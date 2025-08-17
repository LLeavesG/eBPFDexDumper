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
	btf_file := "a12-5.10-arm64_min.btf"
	if strings.Contains(ByteToString(utsname.Release[:]), "rockchip") {
		btf_file = "rock5b-5.10-arm64_min.btf"
	}
	fmt.Printf("Load btf_file=%s\n", btf_file)
	return btf_file
}

func findPatternUaddrs(path string, pattern []byte) ([]uint64, error) {
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

func parse_libart(path string) map[string]uint64 {
	f, err := elf.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	symMap := make(map[string]uint64)

	scan := func(syms []elf.Symbol) {
		for _, sym := range syms {
			name := sym.Name

			// 需要的三类：Execute / ExecuteNterpImpl / VerifyClass
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

	log.Printf("[+] collected symbols: %d (including target funcs and nterp_op_invoke_*)", len(symMap))
	return symMap
}
