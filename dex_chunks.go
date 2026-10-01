package main

import "fmt"

const maxDexDumpSize = 512 * 1024 * 1024

type dexRecvState struct {
	total  uint32
	recv   uint32
	buf    []byte
	ranges []dexByteRange
}

type dexByteRange struct{ start, end uint32 }

func newDexRecvState(total uint32) (*dexRecvState, error) {
	if total == 0 || total > maxDexDumpSize {
		return nil, fmt.Errorf("invalid DEX dump size: %d", total)
	}
	return &dexRecvState{total: total, buf: make([]byte, total)}, nil
}

func (st *dexRecvState) addChunk(offset uint32, payload []byte) (bool, error) {
	end := uint64(offset) + uint64(len(payload))
	if len(payload) == 0 || end > uint64(st.total) {
		return false, fmt.Errorf("DEX chunk out of bounds")
	}
	copy(st.buf[offset:end], payload)
	// Track the union of received ranges. A late final chunk or duplicates do
	// not prove that the earlier bytes arrived.
	current := dexByteRange{offset, uint32(end)}
	merged := make([]dexByteRange, 0, len(st.ranges)+1)
	for _, r := range st.ranges {
		switch {
		case r.end < current.start:
			merged = append(merged, r)
		case current.end < r.start:
			merged = append(merged, current)
			current = r
		default:
			if r.start < current.start {
				current.start = r.start
			}
			if r.end > current.end {
				current.end = r.end
			}
		}
	}
	st.ranges = append(merged, current)
	st.recv = 0
	for _, r := range st.ranges {
		st.recv += r.end - r.start
	}
	return st.recv == st.total, nil
}
