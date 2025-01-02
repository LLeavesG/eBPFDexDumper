//go:build arm64

package main

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

ssize_t readRemoteMem(pid_t pid, void *dst, size_t len, void *src) {
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { src, len };
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}
*/
import "C"
import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type dexDumpHeader struct {
	Pid   uint32
	Begin uint64
	Size  uint32
}

var outputPath string

func parseEvent(record perf.Record, obj bpfObjects) {

	if record.LostSamples != 0 {
		log.Printf("\033[91mperf event ring buffer full, lost %d samples\033[00m", record.LostSamples)
		return
	}
	buf := bytes.NewBuffer(record.RawSample)

	// dexDumpHeader event
	// save begin and size info
	dexDumpHeader := dexDumpHeader{}
	if err := binary.Read(buf, binary.LittleEndian, &dexDumpHeader); err != nil {
		log.Printf("Read failed: %s", err)
		return
	}

	// log.Printf("dexDumpHeader:  Pid: %d Begin: %x size: %x \n", dexDumpHeader.Pid, dexDumpHeader.Begin, dexDumpHeader.Size)

	// use process_vm_readv to read the dex file
	dexData := make([]byte, dexDumpHeader.Size)
	nread, _ := C.readRemoteMem(
		C.pid_t(dexDumpHeader.Pid),
		unsafe.Pointer(&dexData[0]),
		C.size_t(len(dexData)),
		unsafe.Pointer(uintptr(dexDumpHeader.Begin)),
	)
	if nread < 0 {
		log.Printf("process_vm_readv failed")
		// retry
		time.Sleep(1 * time.Second)
		nread, _ = C.readRemoteMem(
			C.pid_t(dexDumpHeader.Pid),
			unsafe.Pointer(&dexData[0]),
			C.size_t(len(dexData)),
			unsafe.Pointer(uintptr(dexDumpHeader.Begin)),
		)
		if nread < 0 {
			log.Printf("process_vm_readv failed again")
			log.Printf("process_vm_readv failed at Begin: %08x Size: %-10d", dexDumpHeader.Begin, dexDumpHeader.Size)
			obj.bpfMaps.DexFileCacheMap.Delete(uint64(dexDumpHeader.Begin))
			return
		}
	}

	// write to file
	fileName := fmt.Sprintf("%s/dex_%x.dex", outputPath, dexDumpHeader.Begin)
	f, err := os.Create(fileName)
	if err != nil {
		log.Printf("Create file failed: %v", err)
		return
	}
	defer f.Close()

	_, err = f.Write(dexData)
	if err != nil {
		log.Printf("Write dexData failed: %v", err)
		return
	}
	log.Printf("Dex file saved to %s, size %-10d\n", fileName, nread)

}

func parse_libart(path string) (uint64, uint64, uint64) {
	f, err := elf.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var offsetExecute uint64
	var offsetExecuteNterp uint64
	var offsetVerifyClass uint64

	// 遍历所有符号
	syms, err := f.Symbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sym := range syms {
		// art::interpreter::Execute
		if strings.Contains(sym.Name, "3art") && strings.Contains(sym.Name, "11interpreter") && strings.Contains(sym.Name, "7Execute") {
			offsetExecute = sym.Value
		}
		// ExecuteNterpImpl
		if sym.Name == "ExecuteNterpImpl" {
			offsetExecuteNterp = sym.Value

		}
		// art::verifier::ClassVerifier::VerifyClass
		if strings.Contains(sym.Name, "3art") && strings.Contains(sym.Name, "8verifier") && strings.Contains(sym.Name, "13ClassVerifier") && strings.Contains(sym.Name, "11VerifyClass") {
			offsetVerifyClass = sym.Value
		}
	}
	log.Printf("[+] offsetExecute: %x offsetExecuteNterp: %x offsetVerifyClass: %x\n", offsetExecute, offsetExecuteNterp, offsetVerifyClass)
	return offsetExecute, offsetExecuteNterp, offsetVerifyClass
}

func main() {
	log.SetFlags(2)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	var offsetExecute uint64
	var offsetExecuteNterp uint64
	var offsetVerifyClass uint64

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("RemoveMemlock failed: ", err)
	}

	// Load the eBPF program.
	obj := bpfObjects{}
	//opt := perf.ReaderOptions{}
	if err := loadBpfObjects(&obj, nil); err != nil {
		log.Fatal("loadBpfObjects failed: ", err)
	}
	defer obj.Close()

	// args from command line

	bpfConfig := bpfConfigT{}
	const mapKey uint32 = 0

	if len(os.Args) < 7 {
		fmt.Printf("Usage: %s <uid> <pathToLibart> <offsetExecute(hex)> <offsetExecuteNterpImpl(hex)> <offsetVerifyClass(hex)> <outputPath>\n", os.Args[0])
		fmt.Printf("Example ( if Auto get offset ): %s 10244 /apex/com.android.art/lib64/libart.so 0 0 0 /data/local/tmp/dexfile\n", os.Args[0])
		fmt.Printf("Example (if get offset failed): %s 10244 /apex/com.android.art/lib64/libart.so 0x473E48 0x200090 0x3D9F18 /data/local/tmp/dexfile\n", os.Args[0])
		os.Exit(1)
	}

	uidStr := os.Args[1]
	libArtPath := os.Args[2]

	outputPath = os.Args[6]

	uidValue, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		log.Fatalf("Failed to parse uid: %v", err)
	}

	bpfConfig.Uid = uint32(uidValue)
	bpfConfig.Pid = 0

	if err := obj.bpfMaps.ConfigMap.Put(mapKey, bpfConfig); err != nil {
		log.Fatal("Failed to put config: ", err)
	}
	log.Printf("Filtering on uid %d", bpfConfig.Uid)

	offsetExecute, offsetExecuteNterp, offsetVerifyClass = parse_libart(libArtPath)

	if offsetExecute == 0 || offsetExecuteNterp == 0 || offsetVerifyClass == 0 {
		log.Fatalf("Failed to parse libart.so , need give the offset", err)
		offsetExecuteStr := os.Args[3]
		offsetNterpStr := os.Args[4]
		offsetVerifyClassStr := os.Args[5]

		offsetExecute, err = strconv.ParseUint(offsetExecuteStr, 0, 64)
		offsetExecuteNterp, err = strconv.ParseUint(offsetNterpStr, 0, 64)
		offsetVerifyClass, err = strconv.ParseUint(offsetVerifyClassStr, 0, 64)
		if offsetExecute <= 0 || offsetExecuteNterp <= 0 || offsetVerifyClass <= 0 {
			log.Fatalf("Failed to get offset, you give %x %x %x", offsetExecute, offsetExecuteNterp, offsetVerifyClass)
		}
	}

	libArtEx, err := link.OpenExecutable(libArtPath)
	if err != nil {
		log.Fatal("link.OpenExecutable failed: ", err)
	}

	executeLink, err := libArtEx.Uprobe(
		"Execute",
		obj.UprobeLibartExecute,
		&link.UprobeOptions{Address: offsetExecute, Offset: 0},
	)
	if err != nil {
		log.Fatal("Uprobe Execute failed: ", err)
	}
	defer executeLink.Close()

	executeNterpImplLink, err := libArtEx.Uprobe(
		"ExecuteNterpImpl",
		obj.UprobeLibartExecuteNterpImpl,
		&link.UprobeOptions{Address: offsetExecuteNterp, Offset: 0},
	)
	if err != nil {
		log.Fatal("Uprobe ExecuteNterpImpl failed: ", err)
	}
	defer executeNterpImplLink.Close()

	verifyClassLink, err := libArtEx.Uprobe(
		"VerifyClass",
		obj.UprobeLibartVerifyClass,

		&link.UprobeOptions{Address: offsetVerifyClass, Offset: 0},
	)
	if err != nil {
		log.Fatal("Uprobe VerifyClass failed: ", err)
	}
	defer verifyClassLink.Close()

	ropt := perf.ReaderOptions{}
	rd, err := perf.NewReaderWithOptions(obj.Events, os.Getpagesize()*12, ropt)
	if err != nil {
		log.Fatal("perf.NewReader failed: ", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		log.Println("Stopping")
		if err := rd.Close(); err != nil {
			log.Fatal("perf.Reader.Close failed: ", err)

		}
		os.Exit(0)

	}()

	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatal("perf.Reader.Read failed: ", err)
		}
		go parseEvent(record, obj)
	}

}
