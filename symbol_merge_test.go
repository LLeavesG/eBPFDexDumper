package main

import (
	"debug/elf"
	"encoding/binary"
	"path/filepath"
	"testing"
)

func soWithDynamicSegment() []byte {
	data := make([]byte, 1024)
	copy(data, minimalSo())
	binary.LittleEndian.PutUint16(data[56:], 2)
	binary.LittleEndian.PutUint32(data[68:], 5) // readable/executable LOAD
	binary.LittleEndian.PutUint64(data[96:], 1024)
	binary.LittleEndian.PutUint64(data[104:], 1024)
	binary.LittleEndian.PutUint32(data[120:], 2) // PT_DYNAMIC
	binary.LittleEndian.PutUint64(data[136:], 256)
	binary.LittleEndian.PutUint64(data[152:], 16)
	binary.LittleEndian.PutUint64(data[160:], 16)
	return data
}

func TestNestedSoRepairPreservesJniSymbolRouting(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"libtarget", "libother"} {
		writeTestFile(t, filepath.Join(dir, "nested", name+".so"), soWithDynamicSegment())
	}
	syms := []InjectedSym{{Name: "nativeMethod", Value: 128}}
	if err := FixSoDirectory(dir, syms, "libtarget"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"libtarget", "libother"} {
		f, err := elf.Open(filepath.Join(dir, "fix", "nested", name+"_fix.so"))
		if err != nil {
			t.Fatal(err)
		}
		symbols, err := f.Symbols()
		f.Close()
		if name == "libother" {
			if err == nil && len(symbols) > 0 {
				t.Fatal("JNI symbols injected into an unrelated library")
			}
			continue
		}
		if err != nil || len(symbols) != 1 || symbols[0].Name != "nativeMethod" || symbols[0].Value != 128 {
			t.Fatalf("target JNI symbols lost: %+v, %v", symbols, err)
		}
	}
}
