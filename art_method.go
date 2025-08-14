//go:build arm64

package main

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

extern ssize_t readRemoteMem(pid_t pid, void *dst, size_t len, void *src);
*/
import "C"

import (
	"fmt"
	"log"
	"sync"
	"unsafe"
)

// ArtMethod结构定义 (基于Android ART运行时)
type ArtMethod struct {
	DeclaringClass  uint32 // 0x00: GcRoot<mirror::Class> declaring_class_
	AccessFlags     uint32 // 0x04: std::atomic<std::uint32_t> access_flags_
	DexMethodIndex  uint32 // 0x08: uint32_t dex_method_index_ (关键字段)
	MethodIndex     uint16 // 0x0C: uint16_t method_index_
	HotnessCount    uint16 // 0x0E: uint16_t hotness_count_ (union with imt_index_)
	Data            uintptr // 0x10: void* data_ (PtrSizedFields)
	EntryPoint      uintptr // 0x18: void* entry_point_from_quick_compiled_code_
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
	
	nread, _ := C.readRemoteMem(
		C.pid_t(pid),
		unsafe.Pointer(&artMethodData[0]),
		C.size_t(len(artMethodData)),
		unsafe.Pointer(artMethodPtr),
	)
	
	if nread < 0 {
		return nil, fmt.Errorf("failed to read ArtMethod from remote process")
	}
	
	// 解析ArtMethod结构
	artMethod := (*ArtMethod)(unsafe.Pointer(&artMethodData[0]))
	return artMethod, nil
}

// 从ArtMethod获取DexFile指针
func getDexFileFromArtMethod(pid uint32, artMethod *ArtMethod) (uint64, error) {
	// declaring_class_是GcRoot<mirror::Class>，需要先解引用获取实际的Class指针
	var classPtr uintptr
	nread, _ := C.readRemoteMem(
		C.pid_t(pid),
		unsafe.Pointer(&classPtr),
		C.size_t(unsafe.Sizeof(classPtr)),
		unsafe.Pointer(uintptr(artMethod.DeclaringClass)),
	)
	
	if nread < 0 {
		return 0, fmt.Errorf("failed to read declaring class pointer")
	}
	
	// 从class对象获取dex_cache (Class对象+0x10偏移)
	var dexCachePtr uintptr
	nread, _ = C.readRemoteMem(
		C.pid_t(pid),
		unsafe.Pointer(&dexCachePtr),
		C.size_t(unsafe.Sizeof(dexCachePtr)),
		unsafe.Pointer(classPtr+0x10),
	)
	
	if nread < 0 {
		return 0, fmt.Errorf("failed to read dex_cache pointer")
	}
	
	// 从dex_cache获取dex_file
	var dexFilePtr uintptr
	nread, _ = C.readRemoteMem(
		C.pid_t(pid),
		unsafe.Pointer(&dexFilePtr),
		C.size_t(unsafe.Sizeof(dexFilePtr)),
		unsafe.Pointer(dexCachePtr+0x10),
	)
	
	if nread < 0 {
		return 0, fmt.Errorf("failed to read dex_file pointer")
	}
	
	// 从dex_file获取begin地址
	var begin uint64
	nread, _ = C.readRemoteMem(
		C.pid_t(pid),
		unsafe.Pointer(&begin),
		C.size_t(unsafe.Sizeof(begin)),
		unsafe.Pointer(dexFilePtr+0x8),
	)
	
	if nread < 0 {
		return 0, fmt.Errorf("failed to read dex file begin address")
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
	
	nread, _ := C.readRemoteMem(
		C.pid_t(pid),
		unsafe.Pointer(&artMethodPtr),
		C.size_t(unsafe.Sizeof(artMethodPtr)),
		unsafe.Pointer(shadowFramePtr+8),
	)
	
	if nread < 0 {
		return 0, fmt.Errorf("failed to read ArtMethod pointer from shadow frame")
	}
	
	return artMethodPtr, nil
}

// 扩展的事件数据结构，包含方法信息
type MethodEventData struct {
	Begin         uint64
	Pid           uint32
	Size          uint32
	ArtMethodPtr  uint64
	MethodIndex   uint32
	MethodSignature [256]byte // 方法签名字符串
}