//go:build arm64

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/adler32"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// jsonRepairRecord mirrors MethodCodeRecord for reading from JSON
type jsonRepairRecord struct {
	Name      string `json:"name"`
	MethodIdx uint32 `json:"method_idx"`
	CodeHex   string `json:"code"`
}

// FixDexDirectory scans an output directory, pairs dex and code.json, and writes *_fix.dex
func FixDexDirectory(outputDir string) error {
	// regex like: dex_<begin>_<size>_code.json
	re := regexp.MustCompile(`^dex_([0-9a-fA-F]+)_([0-9a-fA-F]+)_code\.json$`)

	// map key is base "dex_<begin>_<size>", value is json path
	pairs := make(map[string]string)

	err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		m := re.FindStringSubmatch(name)
		if len(m) == 3 {
			base := fmt.Sprintf("dex_%s_%s", m[1], m[2])
			pairs[base] = path
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(pairs) == 0 {
		return fmt.Errorf("no dex_*_code.json found in %s", outputDir)
	}
	// make fix dir in outputDir
	fixDir := filepath.Join(outputDir, "fix")
	if err := os.MkdirAll(fixDir, 0755); err != nil {
		return fmt.Errorf("failed to create fix dir %s: %w", fixDir, err)
	}

	// Change to fix dir for output

	for base, jsonPath := range pairs {
		dexPath := filepath.Join(outputDir, base+".dex")
		if _, err := os.Stat(dexPath); err != nil {
			// no matching dex, skip
			continue
		}
		// 输出到 fix 子目录
		outPath := filepath.Join(fixDir, base+"_fix.dex")
		if err := FixOneDex(dexPath, jsonPath, outPath); err != nil {
			fmt.Fprintf(os.Stdout, "[!] Fix failed for %s: %v\n", dexPath, err)
		} else {
			fmt.Fprintf(os.Stdout, "[+] Wrote %s\n", outPath)
		}
	}
	return nil
}

// FixOneDex applies JSON code patches into a single dex file and writes to outPath
func FixOneDex(dexPath, jsonPath, outPath string) error {
	dexBytes, err := os.ReadFile(dexPath)
	if err != nil {
		return fmt.Errorf("read dex: %w", err)
	}

	parser, err := NewDexParser(dexBytes)
	if err != nil {
		return fmt.Errorf("parse dex: %w", err)
	}

	method2off, err := buildMethodCodeOffMap(parser)
	if err != nil {
		return fmt.Errorf("build method map: %w", err)
	}

	f, err := os.Open(jsonPath)
	if err != nil {
		return fmt.Errorf("open json: %w", err)
	}
	defer f.Close()

	var records []jsonRepairRecord
	dec := json.NewDecoder(f)
	if err := dec.Decode(&records); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	// log.Printf("Read %d records from %v\n", len(records), method2off)
	var applied, skipped, mismatched int
	for _, r := range records {

		codeOff, ok := method2off[r.MethodIdx]
		// log.Printf("Patching name %s method_idx %d, code_off 0x%X\n", r.Name, r.MethodIdx, codeOff)
		if !ok || codeOff == 0 {
			skipped++
			continue
		}
		// Get code header insns_size
		if int(codeOff)+0x10 > len(dexBytes) {
			skipped++
			continue
		}
		insnsUnits := le32(dexBytes[int(codeOff)+0x0c:])
		expLen := int(insnsUnits) * 2

		codeBytes, err := hex.DecodeString(r.CodeHex)
		if err != nil {
			skipped++
			continue
		}
		// Only patch up to min length; track mismatch
		writeLen := expLen
		if len(codeBytes) < writeLen {
			writeLen = len(codeBytes)
		}
		if int(codeOff)+0x10+writeLen > len(dexBytes) {
			skipped++
			continue
		}
		if writeLen != len(codeBytes) || writeLen != expLen {
			mismatched++
		}
		copy(dexBytes[int(codeOff)+0x10:int(codeOff)+0x10+writeLen], codeBytes[:writeLen])
		applied++
	}

	// Recalculate signature and checksum
	recalcDexHeader(dexBytes)

	if err := os.WriteFile(outPath, dexBytes, 0644); err != nil {
		return fmt.Errorf("write out: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Applied: %d, Skipped: %d, LengthMismatch: %d for %s\n", applied, skipped, mismatched, filepath.Base(dexPath))
	return nil
}

// buildMethodCodeOffMap walks class_data to map method_idx -> code_off
func buildMethodCodeOffMap(p *DexParser) (map[uint32]uint32, error) {
	res := make(map[uint32]uint32)
	// class_def_item is 32 bytes
	const classDefSize = 32
	for i := uint32(0); i < p.header.ClassDefsSize; i++ {
		off := int(p.header.ClassDefsOff + i*classDefSize)
		if off+classDefSize > len(p.data) {
			return nil, fmt.Errorf("class_def OOB")
		}
		classDataOff := le32(p.data[off+24:])
		if classDataOff == 0 {
			continue
		}
		// parse class_data_item
		pos := int(classDataOff)
		// four uleb128 counts
		sfs, pos := readULEB128(p.data, pos)
		if pos < 0 {
			return nil, fmt.Errorf("uleb read error")
		}
		ifs, pos := readULEB128(p.data, pos)
		if pos < 0 {
			return nil, fmt.Errorf("uleb read error")
		}
		dms, pos := readULEB128(p.data, pos)
		if pos < 0 {
			return nil, fmt.Errorf("uleb read error")
		}
		vms, pos := readULEB128(p.data, pos)
		if pos < 0 {
			return nil, fmt.Errorf("uleb read error")
		}

		// skip static_fields
		for j := uint32(0); j < sfs; j++ {
			// field_idx_diff, access_flags
			_, pos = readULEB128(p.data, pos)
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			_, pos = readULEB128(p.data, pos)
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
		}
		// skip instance_fields
		for j := uint32(0); j < ifs; j++ {
			_, pos = readULEB128(p.data, pos)
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			_, pos = readULEB128(p.data, pos)
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
		}
		// direct_methods
		var lastMethod uint32
		for j := uint32(0); j < dms; j++ {
			diff, np := readULEB128(p.data, pos)
			pos = np
			lastMethod += diff
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			_, pos = readULEB128(p.data, pos) // access_flags
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			codeOff, np3 := readULEB128(p.data, pos)
			pos = np3
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			res[lastMethod] = codeOff
		}
		// virtual_methods
		lastMethod = 0
		for j := uint32(0); j < vms; j++ {
			diff, np := readULEB128(p.data, pos)
			pos = np
			lastMethod += diff
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			_, pos = readULEB128(p.data, pos) // access_flags
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			codeOff, np3 := readULEB128(p.data, pos)
			pos = np3
			if pos < 0 {
				return nil, fmt.Errorf("uleb error")
			}
			res[lastMethod] = codeOff
		}
	}
	return res, nil
}

// readULEB128 reads ULEB128 from data at pos, returns value and new pos (or -1 on error)
func readULEB128(data []byte, pos int) (uint32, int) {
	var result uint32
	var shift uint
	for {
		if pos >= len(data) {
			return 0, -1
		}
		b := data[pos]
		pos++
		result |= uint32(b&0x7f) << shift
		if (b & 0x80) == 0 {
			break
		}
		shift += 7
		if shift > 28 { // sanity
			return 0, -1
		}
	}
	return result, pos
}

// helper little-endian readers
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// recalcDexHeader recomputes SHA-1 signature and Adler32 checksum
func recalcDexHeader(dex []byte) {
	if len(dex) < 32 {
		return
	}
	// signature: sha1 of bytes from offset 32 to EOF
	sig := sha1.Sum(dex[32:])
	copy(dex[12:32], sig[:])
	// checksum: adler32 of bytes from offset 12 to EOF
	sum := adler32.Checksum(dex[12:])
	dex[8] = byte(sum)
	dex[9] = byte(sum >> 8)
	dex[10] = byte(sum >> 16)
	dex[11] = byte(sum >> 24)
}
