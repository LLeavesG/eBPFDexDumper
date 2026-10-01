//go:build arm64

package main

import (
	"fmt"
	"log"
	"sync"
	"unsafe"
)

// ArtMethod结构定义 (基于Android ART运行时)
type ArtMethod struct {
	DeclaringClass uint32  // 0x00: GcRoot<mirror::Class> declaring_class_
	AccessFlags    uint32  // 0x04: std::atomic<std::uint32_t> access_flags_
	DexMethodIndex uint32  // 0x08: uint32_t dex_method_index_ (关键字段)
	MethodIndex    uint16  // 0x0C: uint16_t method_index_
	HotnessCount   uint16  // 0x0E: uint16_t hotness_count_ (union with imt_index_)
	Data           uintptr // 0x10: void* data_ (PtrSizedFields)
	EntryPoint     uintptr // 0x18: void* entry_point_from_quick_compiled_code_
}

// Dex文件缓存
type DexFileCache struct {
	mu      sync.RWMutex
	parsers map[uint64]*DexParser
}

var dexCache = &DexFileCache{
	parsers: make(map[uint64]*DexParser),
}

// 添加Dex文件到缓存
func (cache *DexFileCache) AddDexFile(begin uint64, data []byte) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	parser, err := NewDexParser(data)
	if err != nil {
		return fmt.Errorf("failed to create dex parser: %v", err)
	}

	cache.parsers[begin] = parser
	log.Printf("Added dex file to cache: begin=0x%x, size=%d", begin, len(data))
	return nil
}

// 从缓存获取Dex解析器
func (cache *DexFileCache) GetParser(begin uint64) *DexParser {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	return cache.parsers[begin]
}

// 从远程进程内存读取ArtMethod结构
func readArtMethodFromRemote(pid uint32, artMethodPtr uintptr) (*ArtMethod, error) {
	artMethodData := make([]byte, unsafe.Sizeof(ArtMethod{}))

	if err := readRemoteMemory(pid, artMethodPtr, artMethodData); err != nil {
		return nil, fmt.Errorf("failed to read ArtMethod from remote process: %w", err)
	}

	// 解析ArtMethod结构
	artMethod := (*ArtMethod)(unsafe.Pointer(&artMethodData[0]))
	return artMethod, nil
}

// 从ArtMethod获取DexFile指针
func getDexFileFromArtMethod(pid uint32, artMethod *ArtMethod) (uint64, error) {
	// declaring_class_是GcRoot<mirror::Class>，需要先解引用获取实际的Class指针
	var classPtr uintptr
	if err := readRemoteMemory(pid, uintptr(artMethod.DeclaringClass), unsafe.Slice((*byte)(unsafe.Pointer(&classPtr)), unsafe.Sizeof(classPtr))); err != nil {
		return 0, fmt.Errorf("failed to read declaring class pointer: %w", err)
	}

	// 从class对象获取dex_cache (Class对象+0x10偏移)
	var dexCachePtr uintptr
	if err := readRemoteMemory(pid, classPtr+0x10, unsafe.Slice((*byte)(unsafe.Pointer(&dexCachePtr)), unsafe.Sizeof(dexCachePtr))); err != nil {
		return 0, fmt.Errorf("failed to read dex_cache pointer: %w", err)
	}

	// 从dex_cache获取dex_file
	var dexFilePtr uintptr
	if err := readRemoteMemory(pid, dexCachePtr+0x10, unsafe.Slice((*byte)(unsafe.Pointer(&dexFilePtr)), unsafe.Sizeof(dexFilePtr))); err != nil {
		return 0, fmt.Errorf("failed to read dex_file pointer: %w", err)
	}

	// 从dex_file获取begin地址
	var begin uint64
	if err := readRemoteMemory(pid, dexFilePtr+0x8, unsafe.Slice((*byte)(unsafe.Pointer(&begin)), unsafe.Sizeof(begin))); err != nil {
		return 0, fmt.Errorf("failed to read dex file begin address: %w", err)
	}

	return begin, nil
}

// 通过ArtMethod获取方法签名 (实现prettyMethod功能)
func PrettyMethodFromArtMethod(pid uint32, artMethodPtr uintptr) (string, error) {
	// 读取ArtMethod结构
	artMethod, err := readArtMethodFromRemote(pid, artMethodPtr)
	if err != nil {
		return "", fmt.Errorf("failed to read ArtMethod: %v", err)
	}

	// 获取DexFile的begin地址
	dexFileBegin, err := getDexFileFromArtMethod(pid, artMethod)
	if err != nil {
		return "", fmt.Errorf("failed to get dex file: %v", err)
	}

	// 从缓存获取Dex解析器
	parser := dexCache.GetParser(dexFileBegin)
	if parser == nil {
		return "", fmt.Errorf("dex file not found in cache: begin=0x%x", dexFileBegin)
	}

	// 获取方法信息
	methodInfo, err := parser.GetMethodInfo(artMethod.DexMethodIndex)
	if err != nil {
		return "", fmt.Errorf("failed to get method info: %v", err)
	}

	// 返回格式化的方法签名
	return methodInfo.PrettyMethod(), nil
}

// 辅助函数：从shadow frame获取ArtMethod指针
func getArtMethodFromShadowFrame(pid uint32, shadowFramePtr uintptr) (uintptr, error) {
	var artMethodPtr uintptr

	if err := readRemoteMemory(pid, shadowFramePtr+8, unsafe.Slice((*byte)(unsafe.Pointer(&artMethodPtr)), unsafe.Sizeof(artMethodPtr))); err != nil {
		return 0, fmt.Errorf("failed to read ArtMethod pointer from shadow frame: %w", err)
	}

	return artMethodPtr, nil
}

// 扩展的事件数据结构，包含方法信息
type MethodEventData struct {
	Begin           uint64
	Pid             uint32
	Size            uint32
	ArtMethodPtr    uint64
	MethodIndex     uint32
	MethodSignature [256]byte // 方法签名字符串
}
