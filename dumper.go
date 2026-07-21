//go:build arm64

package main

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

// Remote address is uintptr_t, not void*: Go's cgocheck can panic if a remote
// bit-pattern coincides with a local heap span when passed as unsafe.Pointer.
ssize_t readRemoteMem(pid_t pid, void *dst, size_t len, uintptr_t src) {
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { (void *)src, len };
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

int readRemoteErrno(void) { return errno; }
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
	"path/filepath"
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
	executeOffset         uint64
	nterpOffset           uint64
	registerNativesOffset uint64

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

	// JNI RegisterNatives capture: names for dynamically-registered native
	// methods, resolved to module offsets and written out at Stop.
	jniMu      sync.Mutex
	jniMethods []jniMethod
}

// jniMethod is one captured RegisterNatives entry. fnPtr is an absolute runtime
// address, later resolved to a module-relative offset when symbols are written.
type jniMethod struct {
	pid   uint32
	fnPtr uint64
	name  string
	sig   string
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

	// RegisterNatives hook for JNI name recovery (best-effort: skipped when the
	// offset can't be located in libart — stripped builds fall back to string xref).
	if regNativesOff := FindRegisterNativesOffset(dd.libArtPath, dd.registerNativesOffset); regNativesOff != 0 {
		probes = append(probes, &manager.Probe{
			UID:              "registerNatives",
			EbpfFuncName:     "uprobe_libart_registerNatives",
			Section:          "uprobe/libart_registerNatives",
			BinaryPath:       dd.libArtPath,
			UAddress:         regNativesOff,
			AttachToFuncName: "RegisterNatives",
		})
		log.Printf("[+] JNI RegisterNatives hook enabled (libart offset 0x%x)", regNativesOff)
	} else {
		log.Printf("[-] RegisterNatives offset not found in libart; JNI name recovery disabled")
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
			{
				Map: manager.Map{
					Name: "jni_events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleJniEventRingBuf,
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
	dd.writeJniSymbols()

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

func NewDexDumper(libArtPath string, uid uint32, outputDir string, trace, autoFix bool, executeOffset, nterpOffset, registerNativesOffset uint64) *DexDumper {
	outputPath = outputDir

	dd := &DexDumper{
		libArtPath:            libArtPath,
		uid:                   uid,
		trace:                 trace,
		autoFix:               autoFix,
		executeOffset:         executeOffset,
		nterpOffset:           nterpOffset,
		registerNativesOffset: registerNativesOffset,
		dexSizes:              make(map[uint64]uint32),
		methodRecords:         make(map[uint64][]MethodCodeRecord),
		pendingDex:            make(map[uint64]*dexRecvState),
		methodTaskChan:        make(chan methodTask, 4096), // 缓冲通道
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

// 接收状态：重组 eBPF 分片。用合并后的覆盖区间判断是否收齐，
// 不能用 max(offset+len)：乱序时最后一片先到会误判完成并留下中间空洞。
type dexRecvState struct {
	total  uint32
	buf    []byte
	ranges [][2]uint32 // merged [start, end) byte ranges received
}

// mergeDexRange inserts [start, end) into a sorted, non-overlapping interval list.
func mergeDexRange(ranges [][2]uint32, start, end uint32) [][2]uint32 {
	if start >= end {
		return ranges
	}
	out := make([][2]uint32, 0, len(ranges)+1)
	inserted := false
	for _, r := range ranges {
		if r[1] < start {
			out = append(out, r)
			continue
		}
		if r[0] > end {
			if !inserted {
				out = append(out, [2]uint32{start, end})
				inserted = true
			}
			out = append(out, r)
			continue
		}
		// Overlap or abut: grow the new interval and drop r.
		if r[0] < start {
			start = r[0]
		}
		if r[1] > end {
			end = r[1]
		}
	}
	if !inserted {
		out = append(out, [2]uint32{start, end})
	}
	return out
}

func dexRangesComplete(ranges [][2]uint32, total uint32) bool {
	return total > 0 && len(ranges) == 1 && ranges[0][0] == 0 && ranges[0][1] >= total
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
	// Fallback may have already assembled a complete DEX; ignore late chunks.
	if dexCache.GetParser(begin) != nil {
		return
	}

	dd.pendingDexMu.Lock()
	st, ok := dd.pendingDex[begin]
	if !ok {
		st = &dexRecvState{total: hdr.Size, buf: make([]byte, hdr.Size)}
		dd.pendingDex[begin] = st
		dd.dexSizesMu.Lock()
		dd.dexSizes[begin] = hdr.Size
		dd.dexSizesMu.Unlock()
	}
	if uint64(hdr.Offset)+uint64(hdr.DataLen) <= uint64(len(st.buf)) && hdr.DataLen > 0 {
		copy(st.buf[hdr.Offset:uint32(hdr.Offset)+hdr.DataLen], payload)
		st.ranges = mergeDexRange(st.ranges, hdr.Offset, hdr.Offset+hdr.DataLen)
	}

	if !dexRangesComplete(st.ranges, st.total) {
		dd.pendingDexMu.Unlock()
		return
	}

	dataCopy := append([]byte(nil), st.buf...)
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
}

// handleJniEventRingBuf receives one RegisterNatives entry and records it for
// later resolution to a module offset.
func (dd *DexDumper) handleJniEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfJniMethodEventT{})) {
		return
	}
	evt := bpfJniMethodEventT{}
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &evt); err != nil {
		return
	}
	name := goCStr(evt.Name[:])
	if name == "" {
		return
	}
	dd.jniMu.Lock()
	dd.jniMethods = append(dd.jniMethods, jniMethod{pid: evt.Pid, fnPtr: evt.FnPtr, name: name, sig: goCStr(evt.Sig[:])})
	dd.jniMu.Unlock()
}

// goCStr converts a NUL-terminated int8 buffer (as generated for eBPF char[]
// event fields) to a Go string.
func goCStr(b []int8) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(b[i])
	}
	return string(out)
}

// writeJniSymbols resolves each captured JNI function pointer to the module that
// owns it (via that process's /proc/<pid>/maps) and writes per-module
// "offset name" files ready for `fixso --symbols`, plus a raw capture. Called at
// Stop; a no-op if nothing was captured.
func (dd *DexDumper) writeJniSymbols() {
	dd.jniMu.Lock()
	methods := append([]jniMethod(nil), dd.jniMethods...)
	dd.jniMu.Unlock()
	if len(methods) == 0 {
		return
	}

	modCache := map[uint32][]soModule{}
	getMods := func(pid uint32) []soModule {
		if m, ok := modCache[pid]; ok {
			return m
		}
		var mods []soModule
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)); err == nil {
			mods = groupSoModules(parseMapEntries(string(data)), "", true, true, func(a uint64) bool { return peekIsElf(int(pid), a) })
		}
		modCache[pid] = mods
		return mods
	}

	perMod := map[string]*bytes.Buffer{}
	raw := &bytes.Buffer{}
	seen := map[string]bool{}
	for _, m := range methods {
		key := fmt.Sprintf("%d_%x", m.pid, m.fnPtr)
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(raw, "%d 0x%x %s %s\n", m.pid, m.fnPtr, m.name, m.sig)
		for _, mod := range getMods(m.pid) {
			if m.fnPtr >= mod.Base && m.fnPtr < mod.End {
				b := perMod[mod.Name]
				if b == nil {
					b = &bytes.Buffer{}
					perMod[mod.Name] = b
				}
				fmt.Fprintf(b, "0x%x %s\n", m.fnPtr-mod.Base, m.name)
				break
			}
		}
	}

	_ = os.WriteFile(filepath.Join(outputPath, "jni_symbols_raw.txt"), raw.Bytes(), 0644)
	for name, b := range perMod {
		_ = os.WriteFile(filepath.Join(outputPath, "jni_symbols_"+sanitizeSoName(name)+".txt"), b.Bytes(), 0644)
	}
	log.Printf("[+] Captured %d JNI method(s) across %d module(s); wrote jni_symbols_*.txt under %s (feed to: fixso --symbols)", len(seen), len(perMod), outputPath)
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

	log.Printf("[dex-fallback] eBPF read miss at offset %d for dex 0x%x (pid=%d size=%d), trying process_vm_readv",
		failureEvt.FailedOffset, failureEvt.Begin, failureEvt.Pid, failureEvt.Size)

	dd.readRemoteDexFallback(failureEvt.Begin, failureEvt.Pid, failureEvt.Size, failureEvt.FailedOffset)
}

// untagAddr clears TBI/PAC-style top-byte tags used by ART pointers.
func untagAddr(addr uint64) uint64 {
	return addr & 0x00ffffffffffffff
}

const (
	maxDexDumpSize  = 512 * 1024 * 1024
	minDexDumpSize  = 0x70
	dexReadChunkSize = 4096
)

// readRemoteDexRange reads len(buf) bytes at base from pid. Tries one contiguous
// process_vm_readv first; on failure falls back to page-sized reads so a single
// unreadable hole does not abandon the whole DEX.
// Named distinctly from so_dumper.readRemoteRange (same package, different C helper).
func readRemoteDexRange(pid int, base uint64, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	n := C.readRemoteMem(C.pid_t(pid), unsafe.Pointer(&buf[0]), C.size_t(len(buf)), C.uintptr_t(base))
	if int(n) == len(buf) {
		return len(buf)
	}

	total := 0
	for off := 0; off < len(buf); off += dexReadChunkSize {
		end := off + dexReadChunkSize
		if end > len(buf) {
			end = len(buf)
		}
		chunk := buf[off:end]
		cn := C.readRemoteMem(C.pid_t(pid), unsafe.Pointer(&chunk[0]), C.size_t(len(chunk)), C.uintptr_t(base)+C.uintptr_t(off))
		if int(cn) == len(chunk) {
			total += len(chunk)
		}
	}
	return total
}

func (dd *DexDumper) readRemoteDexFallback(begin uint64, pid uint32, totalSize uint32, startOffset uint32) {
	begin = untagAddr(begin)
	if totalSize < minDexDumpSize || totalSize > maxDexDumpSize {
		log.Printf("readRemoteMem skip dex 0x%x: unreasonable size %d (pid=%d)", begin, totalSize, pid)
		return
	}
	if dexCache.GetParser(begin) != nil {
		return // already dumped/cached
	}

	buf := make([]byte, totalSize)
	got := readRemoteDexRange(int(pid), begin, buf)
	if got == 0 {
		errno := C.readRemoteErrno()
		log.Printf("readRemoteMem failed for dex 0x%x: got=0 errno=%d (%s) pid=%d size=%d off=%d",
			begin, int(errno), unix.Errno(errno).Error(), pid, totalSize, startOffset)
		return
	}
	if uint32(got) < totalSize {
		log.Printf("readRemoteMem partial for dex 0x%x: %d/%d bytes (pid=%d)", begin, got, totalSize, pid)
	}

	// Prefer the on-disk/header file_size once we have a valid DEX header, so
	// dumped length matches what tools expect ("大小不对" cases).
	outSize := uint32(got)
	if got >= 0x24 && bytes.HasPrefix(buf, []byte{'d', 'e', 'x', '\n'}) {
		hdrSize := binary.LittleEndian.Uint32(buf[0x20:0x24])
		if hdrSize >= minDexDumpSize && hdrSize <= maxDexDumpSize {
			if hdrSize <= uint32(got) {
				outSize = hdrSize
				buf = buf[:hdrSize]
			} else if hdrSize != totalSize && hdrSize <= maxDexDumpSize {
				// Header claims more than the event size; try to extend.
				bigger := make([]byte, hdrSize)
				copy(bigger, buf[:got])
				extra := readRemoteDexRange(int(pid), begin+uint64(got), bigger[got:])
				if uint32(got+extra) >= hdrSize {
					buf = bigger
					outSize = hdrSize
					log.Printf("[dex-fallback] resized dump 0x%x to header file_size %d", begin, hdrSize)
				}
			}
		}
	} else if got >= 4 {
		log.Printf("[dex-fallback] warning: dex 0x%x missing magic after read (first4=%x)", begin, buf[:4])
	}

	dd.pendingDexMu.Lock()
	delete(dd.pendingDex, begin)
	dd.pendingDexMu.Unlock()

	dd.dexSizesMu.Lock()
	dd.dexSizes[begin] = outSize
	dd.dexSizesMu.Unlock()

	if err := dexCache.AddDexFile(begin, buf); err != nil {
		log.Printf("Failed to add dex file to cache: %v", err)
	}

	fileName := fmt.Sprintf("%s/dex_%x_%x.dex", outputPath, begin, outSize)
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
