//go:build arm64

package main

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

// src is a remote address taken as a plain integer, not void*: Go's cgo
// pointer checks inspect every unsafe.Pointer argument at call time and, if
// its bit pattern happens to land inside a span this process's own Go heap
// owns, walk it as if it were real Go memory - which panics. A target
// process's address has no relation to our heap, but the check is a dynamic
// numeric coincidence check, not a type-based one, so it can still fire.
// Typing this parameter uintptr_t keeps it out of that check entirely.
static ssize_t readRemoteAddr(pid_t pid, void *dst, size_t len, uintptr_t src) {
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { (void *)src, len };
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}
*/
import "C"

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unsafe"
)

// Safety cap: refuse to allocate/dump a single module larger than this.
const maxSoDumpSize = 512 * 1024 * 1024 // 512MB

// soReadChunkSize is used to retry a failed whole-range read page by page,
// so a single unreadable guard page doesn't sacrifice an entire dump.
const soReadChunkSize = 4096

// soModule describes one candidate native image to dump: either a
// file-backed shared library (spanning all of its mapped segments) or an
// anonymous, self-mapped ELF image (loaders/packers that don't go through
// the normal linker path still need a page starting with the ELF magic).
type soModule struct {
	Name string // library file name, or "anon_<base>" for self-mapped images
	Path string // full path from /proc/<pid>/maps, empty for anonymous modules
	Base uint64
	End  uint64 // exclusive
}

type mapEntry struct {
	start, end uint64
	perms      string
	path       string
}

var mapsLineRe = regexp.MustCompile(`^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwxsp-]{4})\s+[0-9a-fA-F]+\s+\S+\s+\d+\s*(.*)$`)

// matches bionic-style "libfoo.so" as well as glibc-style versioned sonames
// like "libfoo.so.6" or "libfoo.so.1.2".
var soSuffixRe = regexp.MustCompile(`\.so(\.[0-9]+)*$`)

func parseMapEntries(content string) []mapEntry {
	var entries []mapEntry
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		m := mapsLineRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		start, err1 := strconv.ParseUint(m[1], 16, 64)
		end, err2 := strconv.ParseUint(m[2], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		entries = append(entries, mapEntry{start: start, end: end, perms: m[3], path: strings.TrimSpace(m[4])})
	}
	return entries
}

// groupSoModules turns raw /proc/<pid>/maps entries into dumpable modules:
//   - file-backed ".so" mappings are merged by path into one [minStart,maxEnd)
//     span, since the loader maps each PT_LOAD segment of the same file
//     separately (r--/r-x/rw-) but reserves the whole span contiguously
//   - when includeAnon is set, runs of path-less (anonymous) VMAs whose first
//     mapped page starts with the ELF magic are merged the same way; this
//     catches packers that map/decrypt a library manually instead of going
//     through the dynamic linker
//
// A non-empty libFilter narrows file-backed modules to matching paths and,
// since it can't match an anonymous region by name, implicitly disables
// anonymous scanning (the caller asked for one specific library).
func groupSoModules(entries []mapEntry, libFilter string, includeAnon bool, elfMagicAt func(addr uint64) bool) []soModule {
	if libFilter != "" {
		includeAnon = false
	}

	byPath := map[string]*soModule{}
	var order []string

	for _, e := range entries {
		if e.path == "" || !soSuffixRe.MatchString(e.path) {
			continue
		}
		if libFilter != "" && !strings.Contains(e.path, libFilter) {
			continue
		}
		mod, ok := byPath[e.path]
		if !ok {
			mod = &soModule{Name: filepath.Base(e.path), Path: e.path, Base: e.start, End: e.end}
			byPath[e.path] = mod
			order = append(order, e.path)
			continue
		}
		if e.start < mod.Base {
			mod.Base = e.start
		}
		if e.end > mod.End {
			mod.End = e.end
		}
	}

	var mods []soModule
	for _, p := range order {
		mods = append(mods, *byPath[p])
	}

	if includeAnon {
		for i := 0; i < len(entries); {
			e := entries[i]
			if e.path != "" || !strings.Contains(e.perms, "r") || !elfMagicAt(e.start) {
				i++
				continue
			}
			start, end := e.start, e.end
			j := i + 1
			for j < len(entries) && entries[j].path == "" && entries[j].start == end {
				end = entries[j].end
				j++
			}
			mods = append(mods, soModule{Name: fmt.Sprintf("anon_%x", start), Base: start, End: end})
			i = j
		}
	}

	return mods
}

// FindPidsForUID scans /proc for running processes owned by uid.
func FindPidsForUID(uid uint32) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if u, err := strconv.ParseUint(fields[1], 10, 32); err == nil && uint32(u) == uid {
					pids = append(pids, pid)
				}
			}
			break
		}
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("no running process found for uid %d", uid)
	}
	return pids, nil
}

func peekIsElf(pid int, addr uint64) bool {
	buf := make([]byte, 4)
	n := C.readRemoteAddr(C.pid_t(pid), unsafe.Pointer(&buf[0]), C.size_t(len(buf)), C.uintptr_t(addr))
	if int(n) != len(buf) {
		return false
	}
	return bytes.Equal(buf, []byte{0x7f, 'E', 'L', 'F'})
}

// ScanSoModules lists candidate native-library modules mapped into pid.
func ScanSoModules(pid int, libFilter string, includeAnon bool) ([]soModule, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mapsPath, err)
	}

	entries := parseMapEntries(string(data))
	elfMagicAt := func(addr uint64) bool { return peekIsElf(pid, addr) }
	return groupSoModules(entries, libFilter, includeAnon, elfMagicAt), nil
}

// readRemoteRange reads len(buf) bytes at base in pid's memory. If the
// whole-range read fails (a common symptom of a guard/unmapped page
// somewhere inside an otherwise-contiguous module span), it falls back to
// page-sized reads so an unreadable page only costs that page, not the
// whole module. Returns the number of bytes actually populated in buf.
func readRemoteRange(pid int, base uint64, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}

	n := C.readRemoteAddr(C.pid_t(pid), unsafe.Pointer(&buf[0]), C.size_t(len(buf)), C.uintptr_t(base))
	if int(n) == len(buf) {
		return len(buf)
	}

	total := 0
	for off := 0; off < len(buf); off += soReadChunkSize {
		end := off + soReadChunkSize
		if end > len(buf) {
			end = len(buf)
		}
		chunk := buf[off:end]
		cn := C.readRemoteAddr(C.pid_t(pid), unsafe.Pointer(&chunk[0]), C.size_t(len(chunk)), C.uintptr_t(base)+C.uintptr_t(off))
		if int(cn) == len(chunk) {
			total += len(chunk)
		}
	}
	return total
}

func sanitizeSoName(name string) string {
	name = strings.TrimSuffix(name, ".so")
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

// DumpSoModules reads each module's full mapped span from pid's memory and
// writes it as a raw file under outDir. Returns the paths written.
func DumpSoModules(pid int, mods []soModule, outDir string) []string {
	var written []string
	for _, m := range mods {
		size := m.End - m.Base
		if size == 0 {
			continue
		}
		if size > maxSoDumpSize {
			log.Printf("[so-dump] skip %s: size %d exceeds safety cap %d", m.Name, size, maxSoDumpSize)
			continue
		}

		buf := make([]byte, size)
		got := readRemoteRange(pid, m.Base, buf)
		if got == 0 {
			log.Printf("[so-dump] failed to read %s (pid=%d, 0x%x-0x%x)", m.Name, pid, m.Base, m.End)
			continue
		}
		if uint64(got) < size {
			log.Printf("[so-dump] partial read for %s: %d/%d bytes captured", m.Name, got, size)
		}

		fname := fmt.Sprintf("%s/so_%d_%x_%x_%s.so", outDir, pid, m.Base, size, sanitizeSoName(m.Name))
		if err := os.WriteFile(fname, buf, 0644); err != nil {
			log.Printf("[so-dump] write failed for %s: %v", fname, err)
			continue
		}
		log.Printf("[so-dump] saved %s (size=%d)", fname, size)
		written = append(written, fname)
	}
	return written
}
