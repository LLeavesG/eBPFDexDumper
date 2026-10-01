package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestFixSoHeaderOnlyBothClasses(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		name := "ELF32"
		if is64 {
			name = "ELF64"
		}
		t.Run(name, func(t *testing.T) {
			data := make([]byte, 256)
			copy(data, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
			binary.LittleEndian.PutUint16(data[16:], 3)
			binary.LittleEndian.PutUint32(data[20:], 1)
			if is64 {
				data[4] = 2
				binary.LittleEndian.PutUint16(data[18:], 183)
				binary.LittleEndian.PutUint64(data[32:], 64)
				binary.LittleEndian.PutUint64(data[40:], 0x1000)
				binary.LittleEndian.PutUint16(data[52:], 64)
				binary.LittleEndian.PutUint16(data[54:], 56)
				binary.LittleEndian.PutUint16(data[56:], 1)
				binary.LittleEndian.PutUint32(data[64:], 1)
				binary.LittleEndian.PutUint64(data[72:], 0x1000)
				binary.LittleEndian.PutUint64(data[96:], 120)
				binary.LittleEndian.PutUint64(data[104:], 256)
			} else {
				binary.LittleEndian.PutUint16(data[18:], 40)
				binary.LittleEndian.PutUint32(data[28:], 52)
				binary.LittleEndian.PutUint32(data[32:], 0x1000)
				binary.LittleEndian.PutUint16(data[40:], 52)
				binary.LittleEndian.PutUint16(data[42:], 32)
				binary.LittleEndian.PutUint16(data[44:], 1)
				binary.LittleEndian.PutUint32(data[52:], 1)
				binary.LittleEndian.PutUint32(data[56:], 0x1000)
				binary.LittleEndian.PutUint32(data[68:], 84)
				binary.LittleEndian.PutUint32(data[72:], 256)
			}
			dir := t.TempDir()
			in, out := filepath.Join(dir, "in.so"), filepath.Join(dir, "out.so")
			writeTestFile(t, in, data)
			if err := FixOneSo(in, out); err != nil {
				t.Fatal(err)
			}
			fixed, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := elf.NewFile(bytes.NewReader(fixed))
			if err != nil {
				t.Fatal(err)
			}
			defer parsed.Close()
			if len(parsed.Progs) != 1 || parsed.Progs[0].Off != 0 || parsed.Progs[0].Filesz != 256 || len(parsed.Sections) != 0 {
				t.Fatal("header-only repair did not restore the mapped segment")
			}
		})
	}
}

func TestFixSoRejectsMalformedProgramHeaders(t *testing.T) {
	for _, mode := range []string{"offset overflow", "small stride", "truncated table", "big endian"} {
		t.Run(mode, func(t *testing.T) {
			data := minimalSo()
			switch mode {
			case "offset overflow":
				binary.LittleEndian.PutUint64(data[32:], ^uint64(0))
			case "small stride":
				binary.LittleEndian.PutUint16(data[54:], 1)
			case "truncated table":
				binary.LittleEndian.PutUint16(data[56:], 2)
			case "big endian":
				data[5] = 2
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("malformed ELF panicked: %v", r)
				}
			}()
			dir := t.TempDir()
			in, out := filepath.Join(dir, "in.so"), filepath.Join(dir, "out.so")
			writeTestFile(t, in, data)
			if err := FixOneSo(in, out); err == nil {
				t.Fatal("accepted malformed ELF header")
			}
		})
	}
}

func FuzzDexParser(f *testing.F) {
	f.Add(minimalDex())
	f.Add([]byte("not a DEX"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := NewDexParser(data)
		if err != nil {
			return
		}
		p.GetString(0)
		p.GetTypeDescriptor(0)
		p.GetMethodInfo(0)
		p.getProtoInfo(0)
		p.getParameterTypes(p.header.DataOff)
		buildMethodCodeOffMap(p)
	})
}
