package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	minDexDumpSize   = 0x70
	dexReadChunkSize = 4096
)

// untagAddr clears ART's top-byte address tags before reading process memory.
func untagAddr(addr uint64) uint64 { return addr & 0x00ffffffffffffff }

// readMemoryRange retries a failed contiguous read page by page, requiring
// every page. A byte count alone cannot identify holes in a memory image.
func readMemoryRange(address uintptr, dst []byte, read func(uintptr, []byte) error) error {
	if len(dst) == 0 {
		return nil
	}
	if err := read(address, dst); err == nil {
		return nil
	} else if len(dst) <= dexReadChunkSize {
		return err
	}
	for offset := 0; offset < len(dst); offset += dexReadChunkSize {
		end := offset + dexReadChunkSize
		if end > len(dst) {
			end = len(dst)
		}
		if err := read(address+uintptr(offset), dst[offset:end]); err != nil {
			return fmt.Errorf("memory page at offset %d: %w", offset, err)
		}
	}
	return nil
}

// readDexImage preserves header-based sizing from upstream while refusing to
// publish a partially populated image. Read the header first so a misleading
// event size cannot make us read past the actual file or truncate an extension.
func readDexImage(begin uint64, eventSize uint32, read func(uintptr, []byte) error) ([]byte, error) {
	if eventSize < minDexDumpSize || eventSize > maxDexDumpSize {
		return nil, fmt.Errorf("unreasonable DEX size: %d", eventSize)
	}
	address := uintptr(untagAddr(begin))
	header := make([]byte, 0x24)
	if err := read(address, header); err != nil {
		return nil, fmt.Errorf("read DEX header: %w", err)
	}
	size := eventSize
	if bytes.HasPrefix(header, []byte{'d', 'e', 'x', '\n'}) {
		fileSize := binary.LittleEndian.Uint32(header[0x20:0x24])
		if fileSize >= minDexDumpSize && fileSize <= maxDexDumpSize {
			size = fileSize
		}
	}
	image := make([]byte, size)
	if err := read(address, image); err != nil {
		return nil, err
	}
	return image, nil
}
