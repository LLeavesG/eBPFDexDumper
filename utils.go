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

// findStringInELF finds the virtual address of a string in ELF file
func findStringInELF(path string, target string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open elf failed: %w", err)
	}
	defer f.Close()

	targetBytes := []byte(target)
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		rs := p.Open()
		if rs == nil {
			continue
		}
		data, err := io.ReadAll(rs)
		if err != nil {
			continue
		}
		idx := bytes.Index(data, targetBytes)
		if idx >= 0 {
			return p.Vaddr + uint64(idx), nil
		}
	}
	return 0, fmt.Errorf("string %q not found", target)
}

// findExecuteByInterpretingString finds art::interpreter::Execute by searching for
// "Interpreting " string reference. The Execute function has 6 parameters and
// uses W5 register early in its body (TBNZ W5, #0, ...).
func findExecuteByInterpretingString(path string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open elf failed: %w", err)
	}
	defer f.Close()

	// Find "Interpreting " string address
	strAddr, err := findStringInELF(path, "Interpreting ")
	if err != nil {
		return 0, fmt.Errorf("failed to find 'Interpreting ' string: %w", err)
	}
	log.Printf("[+] Found 'Interpreting ' string at 0x%x", strAddr)

	// Read code segment
	var codeData []byte
	var codeVaddr uint64
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && (p.Flags&elf.PF_X) != 0 {
			rs := p.Open()
			if rs == nil {
				continue
			}
			data, err := io.ReadAll(rs)
			if err != nil {
				continue
			}
			codeData = data
			codeVaddr = p.Vaddr
			break
		}
	}
	if codeData == nil {
		return 0, fmt.Errorf("code segment not found")
	}

	// Find all ADRP/ADD or ADR sequences that reference strAddr
	var refAddrs []uint64
	for i := 0; i < len(codeData)-8; i += 4 {
		pc := codeVaddr + uint64(i)
		inst := uint32(codeData[i]) | uint32(codeData[i+1])<<8 | uint32(codeData[i+2])<<16 | uint32(codeData[i+3])<<24

		// Check for ADRP instruction (page-relative address)
		if (inst & 0x9F000000) == 0x90000000 {
			// Decode ADRP: immhi(19bit) | immlo(2bit) -> page offset
			immlo := (inst >> 29) & 0x3
			immhi := (inst >> 5) & 0x7FFFF
			imm := int64((immhi<<2)|immlo) << 12
			if (imm & (1 << 32)) != 0 {
				imm |= ^int64(0) << 33
			}
			pageAddr := (pc &^ 0xFFF) + uint64(imm)

			// Check next instruction for ADD
			if i+4 < len(codeData)-4 {
				nextInst := uint32(codeData[i+4]) | uint32(codeData[i+5])<<8 | uint32(codeData[i+6])<<16 | uint32(codeData[i+7])<<24
				// ADD Xd, Xn, #imm12
				if (nextInst & 0xFFC00000) == 0x91000000 {
					imm12 := (nextInst >> 10) & 0xFFF
					targetAddr := pageAddr + uint64(imm12)
					if targetAddr == strAddr {
						refAddrs = append(refAddrs, pc)
					}
				}
			}
		}

		// Check for ADR instruction (PC-relative)
		if (inst & 0x9F000000) == 0x10000000 {
			immlo := (inst >> 29) & 0x3
			immhi := (inst >> 5) & 0x7FFFF
			imm := int64((immhi << 2) | immlo)
			if (imm & (1 << 20)) != 0 {
				imm |= ^int64(0) << 21
			}
			targetAddr := pc + uint64(imm)
			if targetAddr == strAddr {
				refAddrs = append(refAddrs, pc)
			}
		}
	}

	if len(refAddrs) == 0 {
		return 0, fmt.Errorf("no code references to 'Interpreting ' string found")
	}
	log.Printf("[+] Found %d references to 'Interpreting ' string", len(refAddrs))

	// For each reference, find function entry and check if it uses 6 parameters
	for _, refAddr := range refAddrs {
		funcAddr := findFunctionEntry(codeData, codeVaddr, refAddr)
		if funcAddr == 0 {
			continue
		}

		// Check if function uses W5 (6th parameter) with TBNZ/TBZ early
		if has6thParam := checkFor6thParameter(codeData, codeVaddr, funcAddr); has6thParam {
			log.Printf("[+] Execute function found at 0x%x (6 parameters, uses W5)", funcAddr)
			return funcAddr, nil
		}
	}

	return 0, fmt.Errorf("Execute function not found (no 6-parameter function found)")
}

// findFunctionEntry searches backward from refAddr to find function entry
func findFunctionEntry(codeData []byte, codeVaddr, refAddr uint64) uint64 {
	if refAddr < codeVaddr {
		return 0
	}
	startOff := int(refAddr - codeVaddr)

	// Search backward up to 0x2000 bytes for function prologue
	maxSearch := 0x2000
	if startOff < maxSearch {
		maxSearch = startOff
	}

	for off := startOff; off >= startOff-maxSearch && off >= 0; off -= 4 {
		inst := uint32(codeData[off]) | uint32(codeData[off+1])<<8 | uint32(codeData[off+2])<<16 | uint32(codeData[off+3])<<24

		// Check for SUB SP, SP, #imm (function prologue)
		// SUB SP, SP, #imm: 0xD1000000 | (imm12 << 10) | (SP << 5) | SP
		// Encoding: 1101000100 | imm12(12) | Rn(5) | Rd(5), Rn=Rd=SP(31)
		if (inst & 0xFFC003FF) == 0xD10003FF {
			// Verify it's a reasonable stack allocation
			imm12 := (inst >> 10) & 0xFFF
			if imm12 >= 0x20 && imm12 <= 0x400 {
				return codeVaddr + uint64(off)
			}
		}

		// Check for STP X29, X30, [SP, #-imm]! (alternative prologue)
		// STP with pre-index: 101010011 | imm7 | Rt2 | Rn | Rt
		if (inst & 0xFFC07FFF) == 0xA9807BFD {
			return codeVaddr + uint64(off)
		}
	}

	return 0
}

// checkFor6thParameter checks if function uses W5/X5 (6th parameter) within first ~200 bytes
func checkFor6thParameter(codeData []byte, codeVaddr, funcAddr uint64) bool {
	if funcAddr < codeVaddr {
		return false
	}
	startOff := int(funcAddr - codeVaddr)

	// Check first 200 bytes of function for TBNZ/TBZ W5, #bit, label
	checkLen := 200
	if startOff+checkLen > len(codeData) {
		checkLen = len(codeData) - startOff
	}

	for off := startOff; off < startOff+checkLen; off += 4 {
		inst := uint32(codeData[off]) | uint32(codeData[off+1])<<8 | uint32(codeData[off+2])<<16 | uint32(codeData[off+3])<<24

		// TBNZ: 0x37000000 | (b5 << 31) | (b40 << 19) | (imm14 << 5) | Rt
		// TBZ:  0x36000000 | (b5 << 31) | (b40 << 19) | (imm14 << 5) | Rt
		// For W5 (32-bit), b5=0, Rt=5
		if (inst&0x7F000000) == 0x36000000 || (inst&0x7F000000) == 0x37000000 {
			rt := inst & 0x1F
			b5 := (inst >> 31) & 1
			if rt == 5 && b5 == 0 { // W5 register
				return true
			}
		}
	}

	return false
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
// manualExecuteOffset and manualNterpOffset are optional manual overrides (use 0 to auto-detect)
func FindArtOffsets(libArtPath string, manualExecuteOffset, manualNterpOffset uint64) (offsetExecute, offsetExecuteNterp, offsetVerifyClass uint64, err error) {
	// Use manual offsets if provided
	if manualExecuteOffset != 0 {
		offsetExecute = manualExecuteOffset
		log.Printf("[+] Using manual Execute offset: 0x%x", offsetExecute)
	}
	if manualNterpOffset != 0 {
		offsetExecuteNterp = manualNterpOffset
		log.Printf("[+] Using manual ExecuteNterpImpl offset: 0x%x", offsetExecuteNterp)
	}

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

		// FIXED: REMOVE VerifyClass
		// art::verifier::ClassVerifier::VerifyClass
		if offsetVerifyClass == 0 && strings.Contains(name, "3art") && strings.Contains(name, "8verifier") && strings.Contains(name, "13ClassVerifier") && strings.Contains(name, "11VerifyClass") {
			offsetVerifyClass = off
			continue
		}
	}

	// If Execute symbol is missing, try locating by "Interpreting " string reference
	if offsetExecute == 0 {
		if addr, ferr := findExecuteByInterpretingString(libArtPath); ferr == nil {
			offsetExecute = addr
			log.Printf("[+] Execute found by 'Interpreting ' string at 0x%x", offsetExecute)
		} else {
			log.Printf("[-] Execute not found by symbol or string reference: %v", ferr)
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
