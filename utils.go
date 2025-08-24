package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func ByteToString(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(bytes.TrimSpace(bytes.Trim(ba, "\x00")))
}

func CheckConfig(targetStr string) bool {
	file, err := os.Open("/proc/config.gz")
	if err != nil {
		return false
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return false
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)
	target := []byte(targetStr)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), target) {
			// fmt.Println(scanner.Text())
			return true
		}
	}
	return false
}

func FindBTFAssets() string {
	var utsname syscall.Utsname
	err := syscall.Uname(&utsname)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	btfFile := "a12-5.10-arm64_min.btf"
	if strings.Contains(ByteToString(utsname.Release[:]), "rockchip") {
		btfFile = "rock5b-5.10-arm64_min.btf"
	}
	fmt.Printf("Load btf_file=%s\n", btfFile)
	return btfFile
}

// LookupUIDByPackageName tries to resolve Android UID by package name.
// It first parses /data/system/packages.list, and falls back to
// `cmd package list packages -U` and `dumpsys package <pkg>`.
func LookupUIDByPackageName(pkg string) (uint32, error) {
	// 1) Try packages.list (requires root). Format: "<pkg> <uid> ..."
	if f, err := os.Open("/data/system/packages.list"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == pkg {
				if uid64, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
					return uint32(uid64), nil
				}
			}
		}
	}

	// 2) Fallback: cmd package list packages -U (Android 10+)
	if out, err := exec.Command("/system/bin/sh", "-c", "cmd package list packages -U").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			// Example: "package:com.foo uid:10080"
			if !strings.HasPrefix(line, "package:") || !strings.Contains(line, "uid:") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			pkgPart := strings.TrimPrefix(parts[0], "package:")
			if pkgPart != pkg {
				continue
			}
			for _, p := range parts[1:] {
				if strings.HasPrefix(p, "uid:") {
					if uid64, err := strconv.ParseUint(strings.TrimPrefix(p, "uid:"), 10, 32); err == nil {
						return uint32(uid64), nil
					}
				}
			}
		}
	}

	// 3) Fallback: dumpsys package <pkg>
	if out, err := exec.Command("/system/bin/sh", "-c", fmt.Sprintf("dumpsys package %s | grep -m1 userId=", pkg)).Output(); err == nil {
		// Example: "userId=10080" or other placement
		s := strings.TrimSpace(string(out))
		if i := strings.Index(s, "userId="); i >= 0 {
			s2 := s[i+len("userId="):]
			// trim trailing non-digits
			j := 0
			for j < len(s2) && s2[j] >= '0' && s2[j] <= '9' {
				j++
			}
			if j > 0 {
				if uid64, err := strconv.ParseUint(s2[:j], 10, 32); err == nil {
					return uint32(uid64), nil
				}
			}
		}
	}

	return 0, fmt.Errorf("failed to resolve uid for package %q", pkg)
}

// LookupPackagesByUID returns package names that use the given UID.
// Preferred source: /data/system/packages.list; fallback to `cmd package list packages -U`.
func LookupPackagesByUID(uid uint32) ([]string, error) {
	var pkgs []string
	// 1) packages.list
	if f, err := os.Open("/data/system/packages.list"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if u64, err := strconv.ParseUint(fields[1], 10, 32); err == nil && uint32(u64) == uid {
					pkgs = append(pkgs, fields[0])
				}
			}
		}
		if len(pkgs) > 0 {
			return pkgs, nil
		}
	}

	// 2) cmd package list packages -U
	if out, err := exec.Command("/system/bin/sh", "-c", "cmd package list packages -U").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			// Example: "package:com.foo uid:10080"
			if !strings.HasPrefix(line, "package:") || !strings.Contains(line, "uid:") {
				continue
			}
			parts := strings.Fields(line)
			var pkgName string
			var uidStr string
			for _, p := range parts {
				if strings.HasPrefix(p, "package:") {
					pkgName = strings.TrimPrefix(p, "package:")
				} else if strings.HasPrefix(p, "uid:") {
					uidStr = strings.TrimPrefix(p, "uid:")
				}
			}
			if pkgName == "" || uidStr == "" {
				continue
			}
			if u64, err := strconv.ParseUint(uidStr, 10, 32); err == nil && uint32(u64) == uid {
				pkgs = append(pkgs, pkgName)
			}
		}
		if len(pkgs) > 0 {
			return pkgs, nil
		}
	}

	return nil, fmt.Errorf("no packages found for uid %d", uid)
}

// pmPathsForPackage returns install APK paths reported by `pm path <pkg>`.
func pmPathsForPackage(pkg string) ([]string, error) {
	out, err := exec.Command("/system/bin/sh", "-c", fmt.Sprintf("pm path %s", pkg)).Output()
	if err != nil {
		return nil, fmt.Errorf("pm path failed for %s: %w", pkg, err)
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Lines look like: "package:/data/app/.../base.apk"
		if strings.HasPrefix(line, "package:") {
			p := strings.TrimPrefix(line, "package:")
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no package paths reported for %s", pkg)
	}
	return paths, nil
}

// RemoveOatDirsForPackage finds the install dir(s) of pkg and removes their oat/ folders.
func RemoveOatDirsForPackage(pkg string) {
	paths, err := pmPathsForPackage(pkg)
	if err != nil {
		log.Printf("[oat-clean] pm path error for %s: %v", pkg, err)
		return
	}
	seen := make(map[string]struct{})
	for _, p := range paths {
		baseDir := filepath.Dir(p) // directory containing base.apk/splits
		if baseDir == "/" || baseDir == "" {
			continue
		}
		oatDir := filepath.Join(baseDir, "oat")
		if _, ok := seen[oatDir]; ok {
			continue
		}
		seen[oatDir] = struct{}{}
		if st, statErr := os.Stat(oatDir); statErr == nil && st.IsDir() {
			if err := os.RemoveAll(oatDir); err != nil {
				log.Printf("[oat-clean] failed to remove %s: %v", oatDir, err)
			} else {
				log.Printf("[oat-clean] removed %s", oatDir)
			}
		} else {
			log.Printf("[oat-clean] skip, not found: %s", oatDir)
		}
	}
}

// RemoveOatDirsByUID resolves packages for uid and removes oat/ for each.
func RemoveOatDirsByUID(uid uint32) {
	pkgs, err := LookupPackagesByUID(uid)
	if err != nil {
		log.Printf("[oat-clean] resolve packages by uid %d failed: %v", uid, err)
		return
	}
	for _, pkg := range pkgs {
		RemoveOatDirsForPackage(pkg)
	}
}

func findPatternUAddrs(path string, pattern []byte) ([]uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open elf failed: %w", err)
	}
	defer f.Close()

	addrs := make([]uint64, 0)
	seen := make(map[uint64]struct{})

	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
			continue
		}
		rs := p.Open()
		if rs == nil {
			continue
		}
		data, err := io.ReadAll(rs)
		if err != nil {
			return nil, fmt.Errorf("read segment failed: %w", err)
		}
		// 多次查找，允许重叠匹配
		for off := 0; off <= len(data)-len(pattern); {
			idx := bytes.Index(data[off:], pattern)
			if idx < 0 {
				break
			}
			segOff := off + idx
			uaddr := p.Vaddr + uint64(segOff)
			if _, ok := seen[uaddr]; !ok {
				seen[uaddr] = struct{}{}
				addrs = append(addrs, uaddr)
			}
			off = segOff + 1 // 继续向后查找
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("pattern not found")
	}
	return addrs, nil
}

func parseLibArt(path string) map[string]uint64 {
	f, err := elf.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	symMap := make(map[string]uint64)

	scan := func(syms []elf.Symbol) {
		for _, sym := range syms {
			name := sym.Name
			if (strings.Contains(name, "3art") && strings.Contains(name, "11interpreter") && strings.Contains(name, "7Execute")) ||
				name == "ExecuteNterpImpl" ||
				(strings.Contains(name, "3art") && strings.Contains(name, "8verifier") && strings.Contains(name, "13ClassVerifier") && strings.Contains(name, "11VerifyClass")) {
				symMap[name] = sym.Value
			}
		}
	}

	if syms, err := f.Symbols(); err == nil {
		scan(syms)
	} else {
		log.Printf("Failed to read symbols: %v", err)
	}

	if dynSyms, err := f.DynamicSymbols(); err == nil {
		before := len(symMap)
		scan(dynSyms)
		_ = before
	} else {
		log.Printf("Failed to read dynamic symbols: %v", err)
	}

	return symMap
}

// FindArtOffsets locates target offsets in libart:
// - art::interpreter::Execute
// - ExecuteNterpImpl (by symbol, or by byte signature fallback)
// - art::verifier::ClassVerifier::VerifyClass
func FindArtOffsets(libArtPath string) (offsetExecute, offsetExecuteNterp, offsetVerifyClass uint64, err error) {
	symMap := parseLibArt(libArtPath)

	for name, off := range symMap {
		// art::interpreter::Execute
		if offsetExecute == 0 && strings.Contains(name, "3art") && strings.Contains(name, "11interpreter") && strings.Contains(name, "7Execute") {
			offsetExecute = off
			continue
		}
		// ExecuteNterpImpl
		if offsetExecuteNterp == 0 && name == "ExecuteNterpImpl" {
			offsetExecuteNterp = off
			continue
		}
		// art::verifier::ClassVerifier::VerifyClass
		if offsetVerifyClass == 0 && strings.Contains(name, "3art") && strings.Contains(name, "8verifier") && strings.Contains(name, "13ClassVerifier") && strings.Contains(name, "11VerifyClass") {
			offsetVerifyClass = off
			continue
		}
	}

	// If ExecuteNterpImpl symbol is missing, try locating by byte signature
	if offsetExecuteNterp == 0 {
		nterpSig := []byte{
			0xF0, 0x0B, 0x40, 0xD1,
			0x1F, 0x02, 0x40, 0xB9,
			0xFF, 0x83, 0x02, 0xD1,
			0xE8, 0x27, 0x00, 0x6D,
			0xEA, 0x2F, 0x01, 0x6D,
			0xEC, 0x37, 0x02, 0x6D,
			0xEE, 0x3F, 0x03, 0x6D,
			0xF3, 0x53, 0x04, 0xA9,
			0xF5, 0x5B, 0x05, 0xA9,
			0xF7, 0x63, 0x06, 0xA9,
			0xF9, 0x6B, 0x07, 0xA9,
			0xFB, 0x73, 0x08, 0xA9,
			0xFD, 0x7B, 0x09, 0xA9,
			0x16, 0x08, 0x40, 0xF9,
		}
		if addrs, ferr := findPatternUAddrs(libArtPath, nterpSig); ferr == nil && len(addrs) > 0 {
			offsetExecuteNterp = addrs[0]
			if len(addrs) > 1 {
				log.Printf("[!] ExecuteNterpImpl signature matched %d sites; using first: 0x%x", len(addrs), offsetExecuteNterp)
			} else {
				log.Printf("[+] ExecuteNterpImpl found by signature at 0x%x", offsetExecuteNterp)
			}
		} else {
			if ferr != nil {
				log.Printf("[-] ExecuteNterpImpl not found by symbol or signature: %v", ferr)
			} else {
				log.Printf("[-] ExecuteNterpImpl not found by symbol or signature")
			}
		}
	}

	if offsetExecute == 0 || offsetExecuteNterp == 0 || offsetVerifyClass == 0 {
		return 0, 0, 0, fmt.Errorf("failed to parse libart.so offsets (Execute=%x, Nterp=%x, VerifyClass=%x)",
			offsetExecute, offsetExecuteNterp, offsetVerifyClass)
	}
	return offsetExecute, offsetExecuteNterp, offsetVerifyClass, nil
}
