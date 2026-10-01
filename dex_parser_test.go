package main

import (
	"encoding/binary"
	"testing"
)

func TestDexOffsetsDoNotWrap(t *testing.T) {
	for _, kind := range []string{"string", "type", "method", "proto", "parameters"} {
		t.Run(kind, func(t *testing.T) {
			p := &DexParser{data: make([]byte, 112), header: DexHeader{
				StringIdsSize: 1, StringIdsOff: 0xfffffffc,
				TypeIdsSize: 1, TypeIdsOff: 0xfffffffc,
				MethodIdsSize: 1, MethodIdsOff: 0xfffffff8,
				ProtoIdsSize: 1, ProtoIdsOff: 0xfffffff4,
			}}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("malformed offset panicked: %v", r)
				}
			}()
			var err error
			switch kind {
			case "string":
				_, err = p.GetString(0)
			case "type":
				_, err = p.GetTypeDescriptor(0)
			case "method":
				_, err = p.GetMethodInfo(0)
			case "proto":
				_, err = p.getProtoInfo(0)
			case "parameters":
				_, err = p.getParameterTypes(0xfffffffc)
			}
			if err == nil {
				t.Fatal("expected bounds error")
			}
		})
	}
}

func TestULEB128Malformed(t *testing.T) {
	for _, data := range [][]byte{{0x80}, {0x80, 0x80, 0x80, 0x80, 0x10}, {0x80, 0x80, 0x80, 0x80, 0x80, 0}} {
		if _, pos := readULEB128(data, 0); pos != -1 {
			t.Errorf("accepted invalid ULEB128 %x", data)
		}
		p := &DexParser{data: data}
		if _, pos := p.readULEB128(0); pos != -1 {
			t.Errorf("parser accepted invalid ULEB128 %x", data)
		}
	}
	if _, pos := readULEB128([]byte{0}, -1); pos != -1 {
		t.Fatal("accepted negative offset")
	}
	if value, pos := readULEB128([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 0); value != 0xffffffff || pos != 5 {
		t.Fatalf("rejected maximum valid ULEB128: %x %d", value, pos)
	}
}

func TestStringRejectsUnterminatedLength(t *testing.T) {
	// Five continuation bytes followed by a terminator is an invalid length.
	p := &DexParser{data: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0, 0}}
	if _, err := p.readStringData(0); err == nil {
		t.Fatal("accepted invalid string length")
	}
}

func TestDexStringAndMethodSignature(t *testing.T) {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data, 16)
	copy(data[16:], []byte{2, 0xe4, 0xbd, 0xa0, 0xe5, 0xa5, 0xbd, 0})
	p := &DexParser{data: data, header: DexHeader{StringIdsSize: 1}}
	got, err := p.GetString(0)
	if err != nil || got != "你好" {
		t.Fatalf("GetString = %q, %v", got, err)
	}
	info := &MethodInfo{ClassName: "Lcom/example/Foo;", MethodName: "bar", ReturnType: "V", Parameters: []string{"I", "[[Ljava/lang/String;"}}
	if got := info.PrettyMethod(); got != "void com.example.Foo.bar(int, java.lang.String[][])" {
		t.Fatal(got)
	}
}
