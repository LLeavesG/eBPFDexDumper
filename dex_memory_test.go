package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReadMemoryRangeRetriesEveryPage(t *testing.T) {
	source := bytes.Repeat([]byte{0x5a}, 2*dexReadChunkSize+19)
	dst := make([]byte, len(source))
	base := uintptr(0x1000)
	var reads int
	err := readMemoryRange(base, dst, func(address uintptr, buf []byte) error {
		reads++
		if len(buf) > dexReadChunkSize {
			return io.ErrUnexpectedEOF
		}
		offset := int(address - base)
		copy(buf, source[offset:offset+len(buf)])
		return nil
	})
	if err != nil || reads != 4 || !bytes.Equal(dst, source) {
		t.Fatalf("page retry: err=%v reads=%d data matches=%v", err, reads, bytes.Equal(dst, source))
	}
}

func TestReadMemoryRangeRejectsHole(t *testing.T) {
	base := uintptr(0x1000)
	err := readMemoryRange(base, make([]byte, 3*dexReadChunkSize), func(address uintptr, buf []byte) error {
		if len(buf) > dexReadChunkSize || address == base+dexReadChunkSize {
			return io.ErrUnexpectedEOF
		}
		return nil
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("accepted missing page: %v", err)
	}
}

func TestReadDexImageUsesHeaderSizeAndUntaggedAddress(t *testing.T) {
	for _, eventSize := range []uint32{112, 1024} {
		source := append(minimalDex(), bytes.Repeat([]byte{0xa5}, 144)...)
		binary.LittleEndian.PutUint32(source[32:], uint32(len(source)))
		base := uint64(0xab00000000001000)
		image, err := readDexImage(base, eventSize, func(address uintptr, buf []byte) error {
			if address != 0x1000 {
				t.Fatalf("tagged address reached reader: %x", address)
			}
			if len(buf) > len(source) {
				return io.ErrUnexpectedEOF
			}
			copy(buf, source[:len(buf)])
			return nil
		})
		if err != nil || !bytes.Equal(image, source) {
			t.Fatalf("event size %d: image length=%d error=%v", eventSize, len(image), err)
		}
	}
}

func TestReadDexImageRejectsIncompleteImage(t *testing.T) {
	_, err := readDexImage(0x1000, 112, func(address uintptr, buf []byte) error {
		if len(buf) > 36 {
			return io.ErrUnexpectedEOF
		}
		copy(buf, minimalDex())
		return nil
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("accepted truncated image: %v", err)
	}
	for _, size := range []uint32{0, 111, maxDexDumpSize + 1} {
		if _, err := readDexImage(0x1000, size, func(uintptr, []byte) error { t.Fatal("read attempted with invalid size"); return nil }); err == nil {
			t.Fatal("accepted invalid event size", size)
		}
	}
}
