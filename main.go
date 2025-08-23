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
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type dexDumpHeader = bpfDexEventDataT
type methodEventHeader = bpfMethodEventDataT

var outputPath string

type DexDumper struct {
	manager    *manager.Manager
	libArtPath string
	uid        uint32

	mu             sync.RWMutex                 // 新增：缓存读写锁
	methodSigCache map[uint64]map[uint32]string // 新增：Begin -> (methodIndex -> signature)
}

// Asset 简单的资产文件加载函数
func Asset(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func SetupManagerOptions() (manager.Options, error) {
	// 对于没有开启 CONFIG_DEBUG_INFO_BTF 的加载额外的 btf.Spec
	btfFile := ""
	bpfManagerOptions := manager.Options{}

	if !CheckConfig("CONFIG_DEBUG_INFO_BTF=y") {
		btfFile = FindBTFAssets()
	}

	if btfFile != "" {
		// 尝试从系统路径加载 BTF 文件
		var byteBuf []byte
		var err error

		// 首先尝试从 assets 目录加载
		byteBuf, err = Asset("assets/" + btfFile)
		if err != nil {
			// 如果 assets 目录不存在，尝试直接从文件系统加载
			byteBuf, err = Asset(btfFile)
			if err != nil {
				log.Printf("Warning: Failed to load BTF file %s: %v", btfFile, err)
				// 如果 BTF 文件加载失败，使用基本配置
				return manager.Options{
					RLimit: &unix.Rlimit{
						Cur: unix.RLIM_INFINITY,
						Max: unix.RLIM_INFINITY,
					},
				}, nil
			}
		}

		spec, err := btf.LoadSpecFromReader(bytes.NewReader(byteBuf))
		if err != nil {
			log.Printf("Warning: Failed to parse BTF spec: %v", err)
			return manager.Options{
				RLimit: &unix.Rlimit{
					Cur: unix.RLIM_INFINITY,
					Max: unix.RLIM_INFINITY,
				},
			}, nil
		}

		bpfManagerOptions = manager.Options{
			DefaultKProbeMaxActive: 512,
			VerifierOptions: ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogSize:     2097152,
					KernelTypes: spec,
				},
			},
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
		}
	} else {
		bpfManagerOptions = manager.Options{
			DefaultKProbeMaxActive: 512,
			VerifierOptions: ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogSize: 2097152,
				},
			},
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
		}
	}
	return bpfManagerOptions, nil
}

func (dd *DexDumper) setupManager() error {
	symMap := parse_libart(dd.libArtPath)

	var offsetExecute uint64
	var offsetExecuteNterp uint64
	var offsetVerifyClass uint64

	for name, off := range symMap {
		// art::interpreter::Execute
		if offsetExecute == 0 && strings.Contains(name, "3art") && strings.Contains(name, "11interpreter") && strings.Contains(name, "7Execute") {
			offsetExecute = off
			continue
		}
		// ExecuteNterpImpl
		if offsetExecuteNterp == 0 && name == "ExecuteNterpImpl" {
			offsetExecuteNterp = off
			continue
		}
		// art::verifier::ClassVerifier::VerifyClass
		if offsetVerifyClass == 0 && strings.Contains(name, "3art") && strings.Contains(name, "8verifier") && strings.Contains(name, "13ClassVerifier") && strings.Contains(name, "11VerifyClass") {
			offsetVerifyClass = off
			continue
		}
	}

	if offsetExecute == 0 || offsetExecuteNterp == 0 || offsetVerifyClass == 0 {
		return fmt.Errorf("failed to parse libart.so offsets (Execute=%x, Nterp=%x, VerifyClass=%x)",
			offsetExecute, offsetExecuteNterp, offsetVerifyClass)
	}

	// 查找所有匹配的指令序列
	pattern := []byte{0x03, 0x0C, 0x40, 0xF9, 0x5F, 0x00, 0x03, 0xEB}
	patternUaddrs, err := findPatternUaddrs(dd.libArtPath, pattern)
	if err != nil {
		log.Printf("[-] pattern scan error: %v", err)
	} else {
		log.Printf("[+] found %d pattern sites", len(patternUaddrs))
	}

	probes := []*manager.Probe{
		{
			UID:              "execute",
			EbpfFuncName:     "uprobe_libart_execute",
			Section:          "uprobe/libart_execute",
			BinaryPath:       dd.libArtPath,
			UAddress:         offsetExecute,
			AttachToFuncName: "Execute",
		},
		{
			UID:              "executeNterp",
			EbpfFuncName:     "uprobe_libart_executeNterpImpl",
			Section:          "uprobe/libart_executeNterpImpl",
			BinaryPath:       dd.libArtPath,
			UAddress:         offsetExecuteNterp,
			AttachToFuncName: "ExecuteNterpImpl",
		},
		// {
		// 	UID:              "verifyClass",
		// 	EbpfFuncName:     "uprobe_libart_verifyClass",
		// 	Section:          "uprobe/libart_verifyClass",
		// 	BinaryPath:       dd.libArtPath,
		// 	UAddress:         offsetVerifyClass,
		// 	AttachToFuncName: "VerifyClass",
		// },
	}

	// 为每个匹配位置追加一个 uprobe（使用绝对偏移 UAddress）
	for i, addr := range patternUaddrs {
		probes = append(probes, &manager.Probe{
			UID:              fmt.Sprintf("pattern_check_%d", i),
			EbpfFuncName:     "uprobe_libart_nterpOpInvoke",
			Section:          "uprobe/libart_nterpOpInvoke",
			BinaryPath:       dd.libArtPath,
			UAddress:         addr,
			AttachToFuncName: fmt.Sprintf("nterp_op_invoke_%d", i),
		})
	}

	dd.manager = &manager.Manager{
		Probes: probes,
		RingbufMaps: []*manager.RingbufMap{
			{
				Map: manager.Map{
					Name: "events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleDexEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "method_events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleMethodEventRingBuf,
				},
			},
		},
	}

	log.Printf("[+] offsetExecute: %x offsetExecuteNterp: %x offsetVerifyClass: %x",
		offsetExecute, offsetExecuteNterp, offsetVerifyClass)
	return nil
}

// Start 启动 DexDumper
func (dd *DexDumper) Start(ctx context.Context) error {
	// setup manager
	if err := dd.setupManager(); err != nil {
		return fmt.Errorf("failed to setup manager: %v", err)
	}

	// init manager with BPF bytecode
	options, err := SetupManagerOptions()
	if err != nil {
		return fmt.Errorf("failed to setup manager options: %v", err)
	}

	if err := dd.manager.InitWithOptions(bytes.NewReader(_BpfBytes), options); err != nil {
		return fmt.Errorf("failed to init manager: %v", err)
	}

	// config filter map
	configMap, found, err := dd.manager.GetMap("config_map")
	if err != nil {
		return fmt.Errorf("failed to get config map: %v", err)
	}
	if !found {
		return fmt.Errorf("config map not found")
	}

	config := bpfConfigT{
		Uid: dd.uid,
		Pid: 0,
	}

	if err := configMap.Put(uint32(0), config); err != nil {
		return fmt.Errorf("failed to put config: %v", err)
	}

	log.Printf("Filtering on uid %d", dd.uid)

	// start manager
	if err := dd.manager.Start(); err != nil {
		return fmt.Errorf("failed to start manager: %v", err)
	}

	log.Printf("eBPF DexDumper started successfully")

	// 等待停止信号
	<-ctx.Done()

	return nil
}

// Stop 停止 DexDumper
func (dd *DexDumper) Stop() error {
	if dd.manager != nil {
		return dd.manager.Stop(manager.CleanAll)
	}
	return nil
}

func NewDexDumper(libArtPath string, uid uint32, outputDir string) *DexDumper {
	outputPath = outputDir

	return &DexDumper{
		libArtPath:     libArtPath,
		uid:            uid,
		methodSigCache: make(map[uint64]map[uint32]string), // 新增：初始化缓存
	}
}

// handleDexEventRingBuf 处理 Dex 文件事件 (RingBuffer版本)
func (dd *DexDumper) handleDexEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	buf := bytes.NewBuffer(data)
	dexHeader := dexDumpHeader{}
	if err := binary.Read(buf, binary.LittleEndian, &dexHeader); err != nil {
		log.Printf("Read dex event failed: %s", err)
		return
	}

	// 读取 dex 文件数据
	dexData := make([]byte, dexHeader.Size)
	nread, _ := C.readRemoteMem(
		C.pid_t(dexHeader.Pid),
		unsafe.Pointer(&dexData[0]),
		C.size_t(len(dexData)),
		unsafe.Pointer(uintptr(dexHeader.Begin)),
	)
	if nread < 0 {
		log.Printf("process_vm_readv failed")
		// retry
		time.Sleep(1 * time.Second)
		nread, _ = C.readRemoteMem(
			C.pid_t(dexHeader.Pid),
			unsafe.Pointer(&dexData[0]),
			C.size_t(len(dexData)),
			unsafe.Pointer(uintptr(dexHeader.Begin)),
		)
		if nread < 0 {
			log.Printf("process_vm_readv failed again at Begin: %08x Size: %-10d", dexHeader.Begin, dexHeader.Size)

			// 删除缓存项
			dexCacheMap, found, err := dd.manager.GetMap("dexFileCache_map")
			if err == nil && found {
				dexCacheMap.Delete(uint64(dexHeader.Begin))
			}
			return
		}
	}

	err := dexCache.AddDexFile(dexHeader.Begin, dexData)
	if err != nil {
		log.Printf("Failed to add dex file to cache: %v", err)
	}

	fileName := fmt.Sprintf("%s/dex_%x.dex", outputPath, dexHeader.Begin)
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

func (dd *DexDumper) handleMethodEventRingBuf(CPU int, data []byte, perfMap *manager.RingbufMap, manager *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(methodEventHeader{})) {
		log.Printf("Method event data too short: %d bytes", len(data))
		return
	}

	buf := bytes.NewBuffer(data)
	methodHeader := methodEventHeader{}
	if err := binary.Read(buf, binary.LittleEndian, &methodHeader); err != nil {
		log.Printf("Read method event failed: %s", err)
		return
	}

	// Read bytecode if present
	var bytecode []byte
	if methodHeader.CodeitemSize > 0 {
		expectedSize := int(unsafe.Sizeof(methodHeader)) + int(methodHeader.CodeitemSize)
		if len(data) >= expectedSize {
			bytecode = data[unsafe.Sizeof(methodHeader):expectedSize]
			log.Printf("Method 0x%x: Read %d bytes of bytecode", methodHeader.ArtMethodPtr, len(bytecode))
		} else {
			log.Printf("Method event data size mismatch: expected %d, got %d", expectedSize, len(data))
		}
	}

	parser := dexCache.GetParser(methodHeader.Begin)
	if parser == nil {
		// log.Printf("Method event: dex file not cached yet, begin=0x%x", methodHeader.Begin)
		return
	}

	var signature string
	dd.mu.RLock()
	if mm, ok := dd.methodSigCache[methodHeader.Begin]; ok {
		if sig, ok2 := mm[methodHeader.MethodIndex]; ok2 {
			signature = sig
		}
	}
	dd.mu.RUnlock()

	if signature == "" {
		methodInfo, err := parser.GetMethodInfo(methodHeader.MethodIndex)
		if err != nil {
			log.Printf("Failed to get method info for index %d: %v", methodHeader.MethodIndex, err)
			return
		}
		signature = methodInfo.PrettyMethod()

		dd.mu.Lock()
		if _, ok := dd.methodSigCache[methodHeader.Begin]; !ok {
			dd.methodSigCache[methodHeader.Begin] = make(map[uint32]string)
		}
		dd.methodSigCache[methodHeader.Begin][methodHeader.MethodIndex] = signature
		dd.mu.Unlock()

	}

	if methodHeader.CodeitemSize > 0 {
		log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x, bytecode_size=%d)",
			signature,
			methodHeader.Pid,
			methodHeader.Begin,
			methodHeader.MethodIndex,
			methodHeader.ArtMethodPtr,
			methodHeader.CodeitemSize)
	} else {
		log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x)",
			signature,
			methodHeader.Pid,
			methodHeader.Begin,
			methodHeader.MethodIndex,
			methodHeader.ArtMethodPtr)
	}
}

func main() {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	// 命令行参数解析
	if len(os.Args) < 7 {
		fmt.Printf("Usage: %s <uid> <pathToLibart> <offsetExecute(hex)> <offsetExecuteNterpImpl(hex)> <offsetVerifyClass(hex)> <outputPath>\n", os.Args[0])
		fmt.Printf("Example ( if Auto get offset ): %s 10244 /apex/com.android.art/lib64/libart.so 0 0 0 /data/local/tmp/dexfile\n", os.Args[0])
		fmt.Printf("Example (if get offset failed): %s 10244 /apex/com.android.art/lib64/libart.so 0x473E48 0x200090 0x3D9F18 /data/local/tmp/dexfile\n", os.Args[0])
		os.Exit(1)
	}

	uidStr := os.Args[1]
	libArtPath := os.Args[2]
	outputDir := os.Args[6]

	uidValue, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		log.Fatalf("Failed to parse uid: %v", err)
	}

	dumper := NewDexDumper(libArtPath, uint32(uidValue), outputDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, unix.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received stop signal, shutting down...")
		cancel()
	}()

	if err := dumper.Start(ctx); err != nil {
		log.Fatalf("Failed to start dumper: %v", err)
	}

	if err := dumper.Stop(); err != nil {
		log.Printf("Failed to stop dumper cleanly: %v", err)
	}

	log.Println("DexDumper stopped")
}
