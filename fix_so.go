//go:build arm64

package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ptLoad is the PT_LOAD program-header type. The remaining ELF constants and
// the elfLayout helper live in so_rebuild.go (same package).
const ptLoad = 1

// FixOneSo repairs a raw memory dump of a native library so static analysis
// tools (IDA/Ghidra/objdump) can load it. A dump built from /proc/<pid>/maps
// places each segment's bytes at (vaddr - moduleBase) in the output buffer,
// which does not match the on-disk file layout the original ELF header
// describes.
//
// The preferred fix reconstructs a full section header table from the dynamic
// segment (see RebuildSoSections), which restores .dynsym/.dynstr, relocation,
// hash and version sections so IDA recognizes symbols, imports and relocations.
// If that can't run (e.g. no PT_DYNAMIC), it falls back to a minimal fix: patch
// every PT_LOAD segment's p_offset to equal p_vaddr and p_filesz up to p_memsz,
// then zero the section header table (which was never part of the memory image)
// so tools at least load the file via its program headers.
func FixOneSo(soPath, outPath string, injected []InjectedSym) error {
	data, err := os.ReadFile(soPath)
	if err != nil {
		return fmt.Errorf("read so: %w", err)
	}

	if len(data) < 16 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return fmt.Errorf("not a valid ELF file")
	}
	if data[4] != 1 && data[4] != 2 {
		return fmt.Errorf("unsupported EI_CLASS=%d (want ELF32 or ELF64)", data[4])
	}

	// Preferred path: rebuild the section header table from the dynamic segment.
	if rebuilt, rerr := RebuildSoSections(data, injected); rerr == nil {
		if werr := os.WriteFile(outPath, rebuilt, 0644); werr != nil {
			return fmt.Errorf("write out: %w", werr)
		}
		if n, cerr := SelfCheckSo(rebuilt); cerr == nil {
			log.Printf("[fixso] %s: rebuilt section headers, %d dynamic symbols readable", filepath.Base(outPath), n)
		} else {
			log.Printf("[fixso] %s: rebuilt section headers, but self-check couldn't read symbols: %v", filepath.Base(outPath), cerr)
		}
		return nil
	} else {
		log.Printf("[fixso] section rebuild unavailable for %s (%v); falling back to header-only fix", filepath.Base(soPath), rerr)
	}

	// Fallback: normalize p_offset and zero out the section header table,
	// class-aware so both ELF32 and ELF64 dumps still load via program headers.
	l := elfLayout{is64: data[4] == 2}
	if len(data) < l.ehdrSize() {
		return fmt.Errorf("truncated ELF header")
	}
	phoff := l.phoff(data)
	phentsize := l.phentsize(data)
	phnum := l.phnum(data)
	if phentsize == 0 {
		phentsize = l.phdrSize()
	}
	if phoff == 0 || phnum == 0 {
		return fmt.Errorf("no program headers")
	}

	var fixed int
	for i := 0; i < phnum; i++ {
		off := int(phoff) + i*phentsize
		if off+l.phdrSize() > len(data) {
			break
		}
		ph := data[off:]
		if l.pType(ph) != ptLoad {
			continue
		}
		vaddr := l.pVaddr(ph)
		filesz := l.pFilesz(ph)
		memsz := l.pMemsz(ph)
		l.setPOffset(ph, vaddr)
		if memsz > filesz {
			l.setPFilesz(ph, memsz)
		}
		fixed++
	}

	if fixed == 0 {
		return fmt.Errorf("no PT_LOAD segments found")
	}

	l.setShoff(data, 0)
	l.setShnum(data, 0)
	l.setShstrndx(data, 0)

	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return fmt.Errorf("write out: %w", err)
	}
	return nil
}

// FixSoDirectory scans dir for dumped .so files and writes fixed copies to
// a "fix" subdirectory, mirroring FixDexDirectory's layout.
//
// injected symbols are module-relative, so they are only valid for one library.
// symbolsTarget names that library (the module stem from a
// jni_symbols_<stem>.txt file); symbols are injected only into the .so whose
// name matches it, so the other dumped libraries aren't polluted with names at
// offsets that mean nothing in their address space. An empty symbolsTarget with
// a non-empty injected set means the origin couldn't be determined (e.g. a
// hand-written map): fall back to injecting into every .so.
func FixSoDirectory(dir string, injected []InjectedSym, symbolsTarget string) error {
	fixDir := filepath.Join(dir, "fix")
	if err := os.MkdirAll(fixDir, 0755); err != nil {
		return fmt.Errorf("failed to create fix dir %s: %w", fixDir, err)
	}

	var count, injectedInto int
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == fixDir {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".so") {
			return nil
		}

		// Route the symbol map only to its own library.
		var syms []InjectedSym
		if len(injected) > 0 && (symbolsTarget == "" || soMatchesModule(name, symbolsTarget)) {
			syms = injected
		}

		outPath := filepath.Join(fixDir, strings.TrimSuffix(name, ".so")+"_fix.so")
		if err := FixOneSo(path, outPath, syms); err != nil {
			fmt.Fprintf(os.Stdout, "[!] Fix failed for %s: %v\n", path, err)
			return nil
		}
		if len(syms) > 0 {
			injectedInto++
			log.Printf("[+] Injected %d symbol(s) into %s", len(syms), name)
		}
		fmt.Fprintf(os.Stdout, "[+] Wrote %s\n", outPath)
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no .so files found in %s", dir)
	}
	if len(injected) > 0 && symbolsTarget != "" && injectedInto == 0 {
		log.Printf("[!] Symbol map targets module %q but no matching .so was found in %s; no symbols injected", symbolsTarget, dir)
	}
	log.Printf("[+] Fixed %d .so file(s)", count)
	return nil
}

// soMatchesModule reports whether a dumped .so file belongs to module stem.
// dumpso names files so_<pid>_<base>_<size>_<stem>.so, and JNI symbol maps are
// jni_symbols_<stem>.txt, so the stems are compared after sanitizing; a plain
// <stem>.so (a user-renamed file) matches too.
func soMatchesModule(soFileName, stem string) bool {
	base := sanitizeSoName(soFileName)
	return base == stem || strings.HasSuffix(base, "_"+stem)
}

// parseSymbolFile reads an "offset name" map (one entry per line, blank lines
// and '#' comments ignored) for fixso --symbols. The offset is a hex module
// offset (with or without a 0x prefix); everything after it up to whitespace is
// the symbol name. Typically produced by the JNI RegisterNatives capture.
func parseSymbolFile(path string) ([]InjectedSym, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var syms []InjectedSym
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hexStr := strings.TrimPrefix(strings.TrimPrefix(fields[0], "0x"), "0X")
		off, err := strconv.ParseUint(hexStr, 16, 64)
		if err != nil {
			log.Printf("[!] symbols %s:%d: skipping line, bad hex offset %q", filepath.Base(path), lineNo+1, fields[0])
			continue
		}
		syms = append(syms, InjectedSym{Name: fields[1], Value: off})
	}
	return syms, nil
}

// moduleStemFromSymbolsFile extracts the module stem from a JNI symbols file
// named jni_symbols_<stem>.txt (as written by the dump stage), so fixso can
// inject those symbols only into the matching .so. Returns "" for any other
// filename, letting the caller fall back to injecting into every library.
func moduleStemFromSymbolsFile(path string) string {
	base := filepath.Base(path)
	const prefix = "jni_symbols_"
	if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, ".txt") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(base, prefix), ".txt")
}
