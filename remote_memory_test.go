//go:build (linux || android) && cgo

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func requireMemorySyscall(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("process_vm_readv unavailable in this environment: %v", err)
	}
}

func TestReadRemoteMemory(t *testing.T) {
	source := []byte("complete process memory read")
	dst := make([]byte, len(source))
	if err := readRemoteMemory(uint32(os.Getpid()), uintptr(unsafe.Pointer(&source[0])), dst); err != nil {
		requireMemorySyscall(t, err)
		t.Fatal(err)
	}
	runtime.KeepAlive(source)
	if !bytes.Equal(dst, source) {
		t.Fatalf("read %q, want %q", dst, source)
	}
}

func TestRemoteAddressIsNotACgoGoPointer(t *testing.T) {
	// This bit pattern refers to a Go object containing a Go pointer locally.
	// An address in a different process can coincide with exactly this pattern.
	value := 123
	source := &struct{ Pointer *int }{&value}
	dst := make([]byte, unsafe.Sizeof(*source))
	if err := readRemoteMemory(uint32(os.Getpid()), uintptr(unsafe.Pointer(source)), dst); err != nil {
		requireMemorySyscall(t, err)
		t.Fatal(err)
	}
	runtime.KeepAlive(source)
}

func TestReadRemoteMemoryRejectsShortRead(t *testing.T) {
	page := os.Getpagesize()
	mem, err := unix.Mmap(-1, 0, 2*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mem)
	if err := unix.Mprotect(mem[page:], unix.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, len(mem))
	err = readRemoteMemory(uint32(os.Getpid()), uintptr(unsafe.Pointer(&mem[0])), dst)
	requireMemorySyscall(t, err)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short read error = %v", err)
	}
}

func TestReadRemoteMemoryInvalidAddress(t *testing.T) {
	err := readRemoteMemory(uint32(os.Getpid()), 0, make([]byte, 8))
	requireMemorySyscall(t, err)
	if err == nil {
		t.Fatal("accepted unreadable address")
	}
	if err := readRemoteMemory(uint32(os.Getpid()), 0, nil); err != nil {
		t.Fatal("empty read failed", err)
	}
}

func TestCheckRemoteRead(t *testing.T) {
	for _, n := range []int{0, 4, 7} {
		if err := checkRemoteRead(n, 8, nil); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short read of %d accepted: %v", n, err)
		}
	}
	if err := checkRemoteRead(-1, 8, unix.EFAULT); !errors.Is(err, unix.EFAULT) {
		t.Fatal("lost syscall failure", err)
	}
	if err := checkRemoteRead(8, 8, unix.EFAULT); err != nil {
		t.Fatal("successful read incorrectly used stale errno", err)
	}
	if err := readRemoteMemory(uint32(os.Getpid()), 0, nil); err != nil {
		t.Fatal("empty read failed", err)
	}
}
