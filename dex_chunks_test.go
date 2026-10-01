package main

import (
	"bytes"
	"testing"
)

func TestDexChunksWaitForGaps(t *testing.T) {
	st, err := newDexRecvState(12)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []uint32{8, 0, 8} {
		done, err := st.addChunk(offset, []byte{byte(offset), 1, 2, 3})
		if err != nil {
			t.Fatal(err)
		}
		if done {
			t.Fatalf("completed with missing bytes 4..8 after chunk at %d", offset)
		}
	}
	done, err := st.addChunk(4, []byte{4, 5, 6, 7})
	if err != nil || !done {
		t.Fatalf("completion = %v, %v", done, err)
	}
	if !bytes.Equal(st.buf, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3}) {
		t.Fatal(st.buf)
	}
}

func TestDexChunksOverlapsAndBounds(t *testing.T) {
	st, _ := newDexRecvState(8)
	for _, chunk := range []struct {
		offset uint32
		data   []byte
	}{{0, []byte{0, 1, 2, 3}}, {2, []byte{2, 3, 4, 5}}, {2, []byte{2, 3, 4, 5}}} {
		if done, err := st.addChunk(chunk.offset, chunk.data); err != nil || done {
			t.Fatalf("premature completion: %v %v", done, err)
		}
	}
	if done, err := st.addChunk(6, []byte{6, 7}); err != nil || !done {
		t.Fatalf("completion: %v %v", done, err)
	}
	for _, offset := range []uint32{8, 0xffffffff} {
		if _, err := st.addChunk(offset, []byte{1}); err == nil {
			t.Fatal("accepted out-of-bounds chunk")
		}
	}
	if _, err := st.addChunk(0, nil); err == nil {
		t.Fatal("accepted empty chunk")
	}
}

func TestDexDumpSizeLimit(t *testing.T) {
	for _, size := range []uint32{0, maxDexDumpSize + 1, 0xffffffff} {
		if _, err := newDexRecvState(size); err == nil {
			t.Fatal("accepted invalid size", size)
		}
	}
}
