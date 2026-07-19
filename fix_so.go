//go:build arm64

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	elf64HeaderSize = 64
	elf64PhdrSize   = 56
	ptLoad          = 1
)

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
func FixOneSo(soPath, outPath string) error {
	data, err := os.ReadFile(soPath)
	if err != nil {
		return fmt.Errorf("read so: %w", err)
	}

	if len(data) < elf64HeaderSize || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return fmt.Errorf("not a valid ELF file")
	}
	if data[4] != 2 {
		return fmt.Errorf("only ELF64 is supported (EI_CLASS=%d)", data[4])
	}

	// Preferred path: rebuild the section header table from the dynamic segment.
	if rebuilt, rerr := RebuildSoSections(data); rerr == nil {
		if werr := os.WriteFile(outPath, rebuilt, 0644); werr != nil {
			return fmt.Errorf("write out: %w", werr)
		}
		return nil
	} else {
		log.Printf("[fixso] section rebuild unavailable for %s (%v); falling back to header-only fix", filepath.Base(soPath), rerr)
	}

	// Fallback: normalize p_offset and zero out the section header table.
	phoff := binary.LittleEndian.Uint64(data[32:40])
	phentsize := binary.LittleEndian.Uint16(data[54:56])
	phnum := binary.LittleEndian.Uint16(data[56:58])
	if phoff == 0 || phnum == 0 {
		return fmt.Errorf("no program headers")
	}

	var fixed int
	for i := 0; i < int(phnum); i++ {
		off := int(phoff) + i*int(phentsize)
		if off+elf64PhdrSize > len(data) {
			break
		}
		if binary.LittleEndian.Uint32(data[off:off+4]) != ptLoad {
			continue
		}

		vaddr := binary.LittleEndian.Uint64(data[off+16 : off+24])
		filesz := binary.LittleEndian.Uint64(data[off+32 : off+40])
		memsz := binary.LittleEndian.Uint64(data[off+40 : off+48])

		binary.LittleEndian.PutUint64(data[off+8:off+16], vaddr)
		if memsz > filesz {
			binary.LittleEndian.PutUint64(data[off+32:off+40], memsz)
		}
		fixed++
	}

	if fixed == 0 {
		return fmt.Errorf("no PT_LOAD segments found")
	}

	binary.LittleEndian.PutUint64(data[40:48], 0) // e_shoff
	binary.LittleEndian.PutUint16(data[60:62], 0) // e_shnum
	binary.LittleEndian.PutUint16(data[62:64], 0) // e_shstrndx

	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return fmt.Errorf("write out: %w", err)
	}
	return nil
}

// FixSoDirectory scans dir for dumped .so files and writes fixed copies to
// a "fix" subdirectory, mirroring FixDexDirectory's layout.
func FixSoDirectory(dir string) error {
	fixDir := filepath.Join(dir, "fix")
	if err := os.MkdirAll(fixDir, 0755); err != nil {
		return fmt.Errorf("failed to create fix dir %s: %w", fixDir, err)
	}

	var count int
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

		outPath := filepath.Join(fixDir, strings.TrimSuffix(name, ".so")+"_fix.so")
		if err := FixOneSo(path, outPath); err != nil {
			fmt.Fprintf(os.Stdout, "[!] Fix failed for %s: %v\n", path, err)
			return nil
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
	log.Printf("[+] Fixed %d .so file(s)", count)
	return nil
}
