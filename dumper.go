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
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type dexDumpHeader = bpfDexEventDataT
type methodEventHeader = bpfMethodEventDataT

var outputPath string

// 方法事件处理任务
type methodTask struct {
	data []byte
}

type DexDumper struct {
	manager       *manager.Manager
	libArtPath    string
	uid           uint32
	trace         bool
	autoFix       bool
	executeOffset uint64
	nterpOffset   uint64

	// 使用sync.Map减少锁竞争
	methodSigCache sync.Map // key: uint64(begin<<32|methodIndex), value: string

	// 记录dex文件大小，便于生成文件名 dex<begin>_<size>_code.json
	dexSizesMu sync.RWMutex
	dexSizes   map[uint64]uint32 // Begin -> Size

	// 方法记录使用sync.Map + 原子操作
	methodRecordsMu sync.Mutex
	methodRecords   map[uint64][]MethodCodeRecord // Begin -> records

	// 分片接收状态：在Go侧重组eBPF分片
	pendingDexMu sync.Mutex
	pendingDex   map[uint64]*dexRecvState // Begin -> state

	// Worker pool for parallel method event processing
	methodTaskChan chan methodTask
	workerWg       sync.WaitGroup
	stopped        atomic.Bool
}

// JSON导出条目
type MethodCodeRecord struct {
	Name      string `json:"name"`
	MethodIdx uint32 `json:"method_idx"`
	CodeHex   string `json:"code"`
}

//go:embed assets/*.btf
var embeddedAssets embed.FS

// Asset 从内置资源或文件系统加载
func Asset(filename string) ([]byte, error) {
	// Try embedded assets first (support both with and without assets/ prefix)
	if data, err := embeddedAssets.ReadFile(filename); err == nil {
		return data, nil
	}
	if !strings.HasPrefix(filename, "assets/") {
		if data, err := embeddedAssets.ReadFile("assets/" + filename); err == nil {
			return data, nil
		}
	}
	// Fallback to disk for dev/use outside embedding
	return ioutil.ReadFile(filename)
}

func SetupManagerOptions() (manager.Options, error) {
	btfFile := ""
	bpfManagerOptions := manager.Options{}

	if !CheckConfig("CONFIG_DEBUG_INFO_BTF=y") {
		btfFile = FindBTFAssets()
	}

	if btfFile != "" {
		var byteBuf []byte
		var err error

		byteBuf, err = Asset("assets/" + btfFile)
		if err != nil {
			byteBuf, err = Asset(btfFile)
			if err != nil {
				log.Printf("Warning: Failed to load BTF file %s: %v", btfFile, err)
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
		log.Printf("[+] Loaded BTF spec from %s", btfFile)
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
	offsetExecute, offsetExecuteNterp, offsetVerifyClass, err := FindArtOffsets(dd.libArtPath, dd.executeOffset, dd.nterpOffset)
	if err != nil {
		return err
	}

	// offsets are validated inside FindArtOffsets

	// 查找所有匹配的指令序列
	pattern := []byte{0x03, 0x0C, 0x40, 0xF9, 0x5F, 0x00, 0x03, 0xEB}
	patternUAddrs, err := findPatternUAddrs(dd.libArtPath, pattern)
	if err != nil {
		log.Printf("[-] pattern scan error: %v", err)
	} else {
		log.Printf("[+] found nterp_op_invoke_* %d pattern", len(patternUAddrs))
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

	for i, addr := range patternUAddrs {
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
			{
				Map: manager.Map{
					Name: "dex_chunks",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleDexChunkEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "read_failures",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleReadFailureEventRingBuf,
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

	log.Printf("[+] Filtering on uid %d", dd.uid)

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
	log.Printf("Stopping eBPF DexDumper")

	// 标记停止，阻止新事件进入
	dd.stopped.Store(true)

	// 先停止 manager，确保不再有新事件
	if dd.manager != nil {
		if err := dd.manager.Stop(manager.CleanAll); err != nil {
			log.Printf("Manager stop error: %v", err)
		}
	}

	// 然后关闭 worker pool
	close(dd.methodTaskChan)
	dd.workerWg.Wait()

	dd.flushJSON()

	// 自动修复DEX文件
	if dd.autoFix {
		log.Printf("[+] Auto-fixing DEX files...")
		if err := FixDexDirectory(outputPath); err != nil {
			log.Printf("[!] Auto-fix failed: %v", err)
		}
	}
	return nil
}

const numWorkers = 4 // 并行处理 worker 数量

func NewDexDumper(libArtPath string, uid uint32, outputDir string, trace, autoFix bool, executeOffset, nterpOffset uint64) *DexDumper {
	outputPath = outputDir

	dd := &DexDumper{
		libArtPath:     libArtPath,
		uid:            uid,
		trace:          trace,
		autoFix:        autoFix,
		executeOffset:  executeOffset,
		nterpOffset:    nterpOffset,
		dexSizes:       make(map[uint64]uint32),
		methodRecords:  make(map[uint64][]MethodCodeRecord),
		pendingDex:     make(map[uint64]*dexRecvState),
		methodTaskChan: make(chan methodTask, 4096), // 缓冲通道
	}

	// 启动 worker pool
	for i := 0; i < numWorkers; i++ {
		dd.workerWg.Add(1)
		go dd.methodWorker()
	}

	return dd
}

// methodWorker 并行处理方法事件
func (dd *DexDumper) methodWorker() {
	defer dd.workerWg.Done()
	for task := range dd.methodTaskChan {
		dd.processMethodEvent(task.data)
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

	// 保存 dex 文件大小，供JSON导出文件名使用
	dd.dexSizesMu.Lock()
	dd.dexSizes[dexHeader.Begin] = dexHeader.Size
	dd.dexSizesMu.Unlock()

	// eBPF层已开始分片发送，此处不再 process_vm_readv。
	// 仅记录大小等元信息，等待 dex_chunks 重组完成。
}

func (dd *DexDumper) handleMethodEventRingBuf(CPU int, data []byte, perfMap *manager.RingbufMap, manager *manager.Manager) {
	if dd.stopped.Load() || len(data) < int(unsafe.Sizeof(methodEventHeader{})) {
		return
	}
	// 复制数据并分发到 worker pool
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	select {
	case dd.methodTaskChan <- methodTask{data: dataCopy}:
	default:
		// 通道满时直接处理，避免阻塞 ringbuf
		dd.processMethodEvent(dataCopy)
	}
}

// processMethodEvent 实际处理方法事件
func (dd *DexDumper) processMethodEvent(data []byte) {
	buf := bytes.NewBuffer(data)
	methodHeader := methodEventHeader{}
	if err := binary.Read(buf, binary.LittleEndian, &methodHeader); err != nil {
		return
	}

	// Read bytecode if present
	var bytecode []byte
	if methodHeader.CodeitemSize > 0 {
		bytecode = make([]byte, methodHeader.CodeitemSize)
		if err := binary.Read(buf, binary.LittleEndian, &bytecode); err != nil {
			return
		}
	}

	parser := dexCache.GetParser(methodHeader.Begin)

	var methodName string

	if parser == nil {
		// 当没有dex缓存时，使用方法idx作为methodName
		methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
	} else {
		// 使用sync.Map无锁查询缓存
		cacheKey := (methodHeader.Begin << 20) | uint64(methodHeader.MethodIndex)
		if cached, ok := dd.methodSigCache.Load(cacheKey); ok {
			methodName = cached.(string)
		} else {
			methodInfo, err := parser.GetMethodInfo(methodHeader.MethodIndex)
			if err != nil {
				methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
			} else {
				methodName = methodInfo.PrettyMethod()
				// 存入缓存
				dd.methodSigCache.Store(cacheKey, methodName)
			}
		}
	}

	if methodHeader.CodeitemSize > 0 {
		if dd.trace {
			log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x, bytecode_size=%d)",
				methodName,
				methodHeader.Pid,
				methodHeader.Begin,
				methodHeader.MethodIndex,
				methodHeader.ArtMethodPtr,
				methodHeader.CodeitemSize)
		}

		// 记录到每个dex的JSON导出缓存
		if len(bytecode) > 0 {
			rec := MethodCodeRecord{
				Name:      methodName,
				MethodIdx: methodHeader.MethodIndex,
				CodeHex:   hex.EncodeToString(bytecode),
			}
			dd.methodRecordsMu.Lock()
			dd.methodRecords[methodHeader.Begin] = append(dd.methodRecords[methodHeader.Begin], rec)
			dd.methodRecordsMu.Unlock()
		}
	} else {
		if dd.trace {
			log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x)",
				methodName,
				methodHeader.Pid,
				methodHeader.Begin,
				methodHeader.MethodIndex,
				methodHeader.ArtMethodPtr)
		}
	}
}

func (dd *DexDumper) flushJSON() {
	dd.methodRecordsMu.Lock()
	records := dd.methodRecords
	dd.methodRecords = make(map[uint64][]MethodCodeRecord)
	dd.methodRecordsMu.Unlock()

	dd.dexSizesMu.RLock()
	sizes := make(map[uint64]uint32, len(dd.dexSizes))
	for k, v := range dd.dexSizes {
		sizes[k] = v
	}
	dd.dexSizesMu.RUnlock()

	for begin, recs := range records {
		if len(recs) == 0 {
			continue
		}

		size := sizes[begin]
		if size == 0 {
			if p := dexCache.GetParser(begin); p != nil {
				size = p.header.FileSize
			}
		}

		fileName := fmt.Sprintf("%s/dex_%x_%x_code.json", outputPath, begin, size)
		f, err := os.Create(fileName)
		if err != nil {
			log.Printf("Create JSON file failed: %v", err)
			continue
		}

		// 使用bufio提升写入性能
		writer := bufio.NewWriter(f)
		enc := json.NewEncoder(writer)
		enc.SetIndent("", "  ")
		if err := enc.Encode(recs); err != nil {
			log.Printf("Write JSON failed: %v", err)
		} else {
			writer.Flush()
			log.Printf("Saved code records to %s (%d entries)", fileName, len(recs))
		}
		f.Close()
	}
}

// 接收状态结构：重组 eBPF 分片
type dexRecvState struct {
	total uint32
	recv  uint32
	buf   []byte
}

func (dd *DexDumper) handleDexChunkEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfDexChunkEventT{})) {
		log.Printf("Dex chunk event too short: %d bytes", len(data))
		return
	}

	buf := bytes.NewBuffer(data)
	hdr := bpfDexChunkEventT{}
	if err := binary.Read(buf, binary.LittleEndian, &hdr); err != nil {
		log.Printf("Read dex chunk header failed: %s", err)
		return
	}

	payload := make([]byte, hdr.DataLen)
	if hdr.DataLen > 0 {
		if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
			log.Printf("Read dex chunk payload failed: %s", err)
			return
		}
	}

	begin := hdr.Begin
	dd.pendingDexMu.Lock()
	st, ok := dd.pendingDex[begin]
	if !ok {
		// init new state
		st = &dexRecvState{total: hdr.Size, buf: make([]byte, hdr.Size)}
		dd.pendingDex[begin] = st
		// record size for later JSON name
		dd.dexSizesMu.Lock()
		dd.dexSizes[begin] = hdr.Size
		dd.dexSizesMu.Unlock()
	}
	// bounds check
	if uint64(hdr.Offset)+uint64(hdr.DataLen) <= uint64(len(st.buf)) {
		copy(st.buf[hdr.Offset:uint32(hdr.Offset)+hdr.DataLen], payload)
		// update received length conservatively; allow duplicates
		if st.recv < hdr.Offset+hdr.DataLen {
			st.recv = hdr.Offset + hdr.DataLen
		}
	}

	// completed?
	if st.recv >= st.total {
		dataCopy := st.buf
		// finalize
		delete(dd.pendingDex, begin)
		dd.pendingDexMu.Unlock()

		if err := dexCache.AddDexFile(begin, dataCopy); err != nil {
			log.Printf("Failed to add dex file to cache: %v", err)
		}

		fileName := fmt.Sprintf("%s/dex_%x_%x.dex", outputPath, begin, hdr.Size)
		f, err := os.Create(fileName)
		if err != nil {
			log.Printf("Create file failed: %v", err)
			return
		}
		defer f.Close()
		if _, err := f.Write(dataCopy); err != nil {
			log.Printf("Write dexData failed: %v", err)
			return
		}
		log.Printf("Dex file saved to %s, size %d", fileName, len(dataCopy))
		return
	}
	dd.pendingDexMu.Unlock()
}

func (dd *DexDumper) handleReadFailureEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfDexReadFailureT{})) {
		log.Printf("Read failure event too short: %d bytes", len(data))
		return
	}

	buf := bytes.NewBuffer(data)
	failureEvt := bpfDexReadFailureT{}
	if err := binary.Read(buf, binary.LittleEndian, &failureEvt); err != nil {
		log.Printf("Read failure event failed: %s", err)
		return
	}

	// log.Printf("eBPF read failed at offset %d for dex 0x%x (pid=%d), using readRemoteMem fallback",
	// 	failureEvt.FailedOffset, failureEvt.Begin, failureEvt.Pid)

	dd.readRemoteDexFallback(failureEvt.Begin, failureEvt.Pid, failureEvt.Size, failureEvt.FailedOffset)
}

func (dd *DexDumper) readRemoteDexFallback(begin uint64, pid uint32, totalSize uint32, startOffset uint32) {
	buf := make([]byte, totalSize)

	ret := C.readRemoteMem(C.pid_t(pid), unsafe.Pointer(&buf[0]), C.size_t(totalSize),
		unsafe.Pointer(uintptr(begin)))

	if ret < 0 {
		log.Printf("readRemoteMem failed for dex 0x%x: %d", begin, ret)
		return
	}

	readSize := uint32(ret)
	if readSize != totalSize {
		log.Printf("readRemoteMem partial read: expected %d, got %d", totalSize, readSize)
		buf = buf[:readSize]
	}

	dd.pendingDexMu.Lock()
	delete(dd.pendingDex, begin)
	dd.pendingDexMu.Unlock()

	dd.dexSizesMu.Lock()
	dd.dexSizes[begin] = totalSize
	dd.dexSizesMu.Unlock()

	if err := dexCache.AddDexFile(begin, buf); err != nil {
		log.Printf("Failed to add dex file to cache: %v", err)
	}

	fileName := fmt.Sprintf("%s/dex_%x_%x.dex", outputPath, begin, totalSize)
	f, err := os.Create(fileName)
	if err != nil {
		log.Printf("Create file failed: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		log.Printf("Write dexData failed: %v", err)
		return
	}
	log.Printf("Dex file saved to %s (fallback readRemoteMem), size %d", fileName, len(buf))
}
