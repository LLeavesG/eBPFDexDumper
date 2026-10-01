//go:build (linux || android) && cgo

package main

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

// A remote address is an integer, never a pointer into the caller's Go heap.
static ssize_t readRemoteMemoryAddr(pid_t pid, void *dst, size_t len, uintptr_t src) {
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { (void *)src, len };
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}
*/
import "C"

import (
	"fmt"
	"io"
	"unsafe"
)

// readRemoteMemory requires a complete read; truncated structures or DEX files
// must not be interpreted as valid data or committed to the cache/output.
func readRemoteMemory(pid uint32, address uintptr, dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	n, err := C.readRemoteMemoryAddr(C.pid_t(pid), unsafe.Pointer(&dst[0]), C.size_t(len(dst)), C.uintptr_t(address))
	if err := checkRemoteRead(int(n), len(dst), err); err != nil {
		return fmt.Errorf("read process %d memory at 0x%x: %w", pid, address, err)
	}
	return nil
}

func checkRemoteRead(n, want int, readErr error) error {
	if n < 0 {
		return readErr
	}
	if n != want {
		return fmt.Errorf("got %d of %d bytes: %w", n, want, io.ErrUnexpectedEOF)
	}
	return nil
}
