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
	manager       *manager.Manager
	libArtPath    string
	uid           uint32
	trace         bool
	executeOffset uint64
	nterpOffset   uint64

	mu             sync.RWMutex                 // 读写锁，保护内部缓存
	methodSigCache map[uint64]map[uint32]string // Begin -> (methodIndex -> signature)

	// 记录dex文件大小，便于生成文件名 dex<begin>_<size>_code.json
	dexSizes      map[uint64]uint32             // Begin -> Size
	methodRecords map[uint64][]MethodCodeRecord // Begin -> records

	// 分片接收状态：在Go侧重组eBPF分片
	pendingDex map[uint64]*dexRecvState // Begin -> state
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
	dd.flushJSON()
	if dd.manager != nil {
		return dd.manager.Stop(manager.CleanAll)
	}
	return nil
}

func NewDexDumper(libArtPath string, uid uint32, outputDir string, trace bool, executeOffset, nterpOffset uint64) *DexDumper {
	outputPath = outputDir

	return &DexDumper{
		libArtPath:     libArtPath,
		uid:            uid,
		trace:          trace,
		executeOffset:  executeOffset,
		nterpOffset:    nterpOffset,
		methodSigCache: make(map[uint64]map[uint32]string),
		dexSizes:       make(map[uint64]uint32),
		methodRecords:  make(map[uint64][]MethodCodeRecord),
		pendingDex:     make(map[uint64]*dexRecvState),
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
	dd.mu.Lock()
	dd.dexSizes[dexHeader.Begin] = dexHeader.Size
	dd.mu.Unlock()

	// eBPF层已开始分片发送，此处不再 process_vm_readv。
	// 仅记录大小等元信息，等待 dex_chunks 重组完成。
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
		bytecode = make([]byte, methodHeader.CodeitemSize)
		if err := binary.Read(buf, binary.LittleEndian, &bytecode); err != nil {
			log.Printf("Read method bytecode failed: %s", err)
			return
		}
	}

	parser := dexCache.GetParser(methodHeader.Begin)

	var signature string
	var methodName string

	if parser == nil {
		// log.Printf("Method event: dex file not cached yet, begin=0x%x", methodHeader.Begin)
		// 当没有dex缓存时，使用方法idx作为methodName
		methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
	} else {
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
				// 即使获取方法信息失败，也使用方法idx作为fallback
				methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
			} else {
				signature = methodInfo.PrettyMethod()
				methodName = signature

				dd.mu.Lock()
				if _, ok := dd.methodSigCache[methodHeader.Begin]; !ok {
					dd.methodSigCache[methodHeader.Begin] = make(map[uint32]string)
				}
				dd.methodSigCache[methodHeader.Begin][methodHeader.MethodIndex] = signature
				dd.mu.Unlock()
			}
		} else {
			methodName = signature
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
			dd.mu.Lock()
			dd.methodRecords[methodHeader.Begin] = append(dd.methodRecords[methodHeader.Begin], rec)
			dd.mu.Unlock()
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
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	for begin, records := range dd.methodRecords {
		if len(records) == 0 {
			continue
		}

		size := dd.dexSizes[begin]
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
		defer f.Close()

		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(records); err != nil {
			log.Printf("Write JSON failed: %v", err)
		} else {
			log.Printf("Saved code records to %s (%d entries)", fileName, len(records))
		}
	}
}

// 接收状态结构：重组 eBPF 分片
type dexRecvState struct {
	total uint32
	recv  uint32
	buf   []byte
}

// 处理 eBPF 侧发来的 DEX 分片事件
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
	dd.mu.Lock()
	st, ok := dd.pendingDex[begin]
	if !ok {
		// init new state
		st = &dexRecvState{total: hdr.Size, buf: make([]byte, hdr.Size)}
		dd.pendingDex[begin] = st
		// record size for later JSON name
		dd.dexSizes[begin] = hdr.Size
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
		dd.mu.Unlock()

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
	dd.mu.Unlock()
}
