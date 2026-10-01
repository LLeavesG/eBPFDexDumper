package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func minimalDex() []byte {
	var b bytes.Buffer
	h := DexHeader{Magic: [8]byte{'d', 'e', 'x', '\n', '0', '3', '5', 0}, FileSize: 112, HeaderSize: 112, EndianTag: 0x12345678}
	if err := binary.Write(&b, binary.LittleEndian, h); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func TestFixDexDirectoryNestedPairs(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"a", "b"} {
		writeTestFile(t, filepath.Join(dir, sub, "dex_1_70.dex"), minimalDex())
		writeTestFile(t, filepath.Join(dir, sub, "dex_1_70_code.json"), []byte("[]"))
	}
	if err := FixDexDirectory(dir); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"a", "b"} {
		if _, err := os.Stat(filepath.Join(dir, "fix", sub, "dex_1_70_fix.dex")); err != nil {
			t.Fatalf("missing repaired %s: %v", sub, err)
		}
	}
}

func TestFixDexDirectoryReportsFailures(t *testing.T) {
	for _, mode := range []string{"missing dex", "bad dex", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "dex_1_70_code.json"), []byte("[]"))
			if mode != "missing dex" {
				writeTestFile(t, filepath.Join(dir, "dex_1_70.dex"), []byte("broken"))
			}
			if mode == "mixed" {
				writeTestFile(t, filepath.Join(dir, "dex_2_70.dex"), minimalDex())
				writeTestFile(t, filepath.Join(dir, "dex_2_70_code.json"), []byte("[]"))
			}
			if err := FixDexDirectory(dir); err == nil {
				t.Fatal("repair reported success despite failed input")
			}
			if mode == "mixed" {
				if _, err := os.Stat(filepath.Join(dir, "fix", "dex_2_70_fix.dex")); err != nil {
					t.Fatal("valid file was not repaired", err)
				}
			}
		})
	}
}

func TestFixOneDexPatchesInstructionsAndChecksums(t *testing.T) {
	data := append(minimalDex(), make([]byte, 84)...)
	binary.LittleEndian.PutUint32(data[32:], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[96:], 1) // class_defs_size
	binary.LittleEndian.PutUint32(data[100:], 112)
	binary.LittleEndian.PutUint32(data[112+24:], 144)   // class_data_off
	copy(data[144:], []byte{0, 0, 1, 0, 0, 0, 0xb0, 1}) // method 0 has code_off=176
	binary.LittleEndian.PutUint32(data[176+12:], 2)     // insns_size
	dir := t.TempDir()
	in, codes, out := filepath.Join(dir, "in.dex"), filepath.Join(dir, "codes.json"), filepath.Join(dir, "out.dex")
	writeTestFile(t, in, data)
	writeTestFile(t, codes, []byte(`[{"method_idx":0,"code":"12000f00"}]`))
	if err := FixOneDex(in, codes, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[192:], []byte{0x12, 0, 0x0f, 0}) {
		t.Fatalf("wrong patched instructions: %x", got[192:])
	}
	sig := sha1.Sum(got[32:])
	if !bytes.Equal(got[12:32], sig[:]) {
		t.Fatal("wrong SHA-1 signature")
	}
	if binary.LittleEndian.Uint32(got[8:12]) != adler32.Checksum(got[12:]) {
		t.Fatal("wrong Adler-32 checksum")
	}
}

func minimalSo() []byte {
	data := make([]byte, 120)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 3)
	binary.LittleEndian.PutUint16(data[18:], 183)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], 1)
	binary.LittleEndian.PutUint32(data[64:], 1) // PT_LOAD
	binary.LittleEndian.PutUint64(data[64+32:], 120)
	binary.LittleEndian.PutUint64(data[64+40:], 120)
	return data
}

func TestFixSoDirectoryPreservesNestedNames(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"a", "b"} {
		writeTestFile(t, filepath.Join(dir, sub, "libsame.so"), minimalSo())
	}
	if err := FixSoDirectory(dir, nil, ""); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"a", "b"} {
		if _, err := os.Stat(filepath.Join(dir, "fix", sub, "libsame_fix.so")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFixSoDirectoryReportsPartialFailure(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "good.so"), minimalSo())
	writeTestFile(t, filepath.Join(dir, "bad.so"), []byte("broken"))
	if err := FixSoDirectory(dir, nil, ""); err == nil {
		t.Fatal("repair reported success despite corrupt .so")
	}
	if _, err := os.Stat(filepath.Join(dir, "fix", "good_fix.so")); err != nil {
		t.Fatal(err)
	}
}
