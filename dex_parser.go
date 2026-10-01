package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"
)

// Dex文件格式常量
const (
	DexFileMagic = 0x0A786564
	// CompactDexMagic is "cdex" — ART's CompactDex. Such files use a compressed
	// CodeItem layout and shared data, so they need a cdex->dex conversion
	// before standard DEX tooling can read them.
	CompactDexMagic = 0x78656463

	// String类型定义（保留以备后用）
	TypeByte   = 0x00
	TypeShort  = 0x02
	TypeChar   = 0x03
	TypeInt    = 0x04
	TypeLong   = 0x06
	TypeFloat  = 0x10
	TypeDouble = 0x11
	TypeString = 0x17
	TypeType   = 0x18
	TypeField  = 0x19
	TypeMethod = 0x1a
	TypeEnum   = 0x1b
	TypeArray  = 0x1c
	TypeClass  = 0x1f
	TypeNull   = 0x1e
	TypeVoid   = 0x56
)

// Dex文件头结构
type DexHeader struct {
	Magic         [8]byte
	Checksum      uint32
	Signature     [20]byte
	FileSize      uint32
	HeaderSize    uint32
	EndianTag     uint32
	LinkSize      uint32
	LinkOff       uint32
	MapOff        uint32
	StringIdsSize uint32
	StringIdsOff  uint32
	TypeIdsSize   uint32
	TypeIdsOff    uint32
	ProtoIdsSize  uint32
	ProtoIdsOff   uint32
	FieldIdsSize  uint32
	FieldIdsOff   uint32
	MethodIdsSize uint32
	MethodIdsOff  uint32
	ClassDefsSize uint32
	ClassDefsOff  uint32
	DataSize      uint32
	DataOff       uint32
}

// String ID项
type StringIdItem struct {
	StringDataOff uint32
}

// Type ID项
type TypeIdItem struct {
	DescriptorIdx uint32
}

// Method ID项
type MethodIdItem struct {
	ClassIdx uint16
	ProtoIdx uint16
	NameIdx  uint32
}

// Proto ID项
type ProtoIdItem struct {
	ShortyIdx     uint32
	ReturnTypeIdx uint32
	ParametersOff uint32
}

// Type List结构
type TypeList struct {
	Size uint32
	List []TypeItem
}

type TypeItem struct {
	TypeIdx uint16
}

// DexFile解析器
type DexParser struct {
	data   []byte
	header DexHeader
}

// 创建新的Dex解析器
func NewDexParser(data []byte) (*DexParser, error) {
	if len(data) < int(unsafe.Sizeof(DexHeader{})) {
		return nil, fmt.Errorf("dex file too small")
	}

	parser := &DexParser{data: data}

	// 解析头部
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &parser.header)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dex header: %v", err)
	}

	// 验证魔数
	magic := binary.LittleEndian.Uint32(parser.header.Magic[:4])
	if magic == CompactDexMagic {
		return nil, fmt.Errorf("CompactDex (cdex) detected: this tool emits standard DEX; a cdex->dex conversion is needed first (e.g. vdexExtractor) — see README")
	}
	if magic != DexFileMagic {
		return nil, fmt.Errorf("invalid dex magic: %x", magic)
	}

	return parser, nil
}

// dataRange checks offsets in 64 bits before slicing so damaged uint32 table
// offsets and counts cannot wrap around into apparently valid file positions.
func (p *DexParser) dataRange(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(p.data)) || size > uint64(len(p.data))-offset {
		return nil, fmt.Errorf("dex data range out of bounds: offset=%d size=%d", offset, size)
	}
	return p.data[offset : offset+size], nil
}

// 读取字符串
func (p *DexParser) GetString(stringIdx uint32) (string, error) {
	if stringIdx >= p.header.StringIdsSize {
		return "", fmt.Errorf("string index out of bounds: %d", stringIdx)
	}

	// 获取string_id_item
	item, err := p.dataRange(uint64(p.header.StringIdsOff)+uint64(stringIdx)*4, 4)
	if err != nil {
		return "", fmt.Errorf("string id: %w", err)
	}
	stringDataOff := binary.LittleEndian.Uint32(item)

	// 读取字符串数据
	return p.readStringData(stringDataOff)
}

// 读取字符串数据
//
// DEX 的 string_data_item 为: uleb128 编码的 utf16_size(UTF-16 代码单元数，
// 并非字节数)，后跟以 0x00 结尾的 MUTF-8 字节序列。字符串的实际字节长度并不等于
// utf16_size —— 非 ASCII 字符的 MUTF-8 编码会占用多个字节，若按 utf16_size 截取
// 字节会把类名/方法名截断。因此这里扫描到 NUL 结束符来确定真实长度;MUTF-8 把真正
// 的 NUL 编码成 0xC0 0x80，所以 0x00 字节一定是字符串结束标志。
func (p *DexParser) readStringData(offset uint32) (string, error) {
	if int(offset) >= len(p.data) {
		return "", fmt.Errorf("string data offset out of bounds")
	}

	// 跳过 uleb128 的 utf16_size 前缀(仅是长度提示，不代表字节数)
	pos := int(offset)
	_, pos = p.readULEB128(pos)
	if pos < 0 {
		return "", fmt.Errorf("invalid string length ULEB128")
	}

	// 从 pos 扫描到 NUL 结束符，得到实际字节长度
	end := pos
	for end < len(p.data) && p.data[end] != 0x00 {
		end++
	}
	if end >= len(p.data) {
		return "", fmt.Errorf("string data not NUL-terminated")
	}

	return string(p.data[pos:end]), nil
}

// 读取ULEB128
func (p *DexParser) readULEB128(offset int) (uint32, int) {
	return readULEB128(p.data, offset)
}

// 获取类型描述符
func (p *DexParser) GetTypeDescriptor(typeIdx uint32) (string, error) {
	if typeIdx >= p.header.TypeIdsSize {
		return "", fmt.Errorf("type index out of bounds: %d", typeIdx)
	}

	// 获取type_id_item
	item, err := p.dataRange(uint64(p.header.TypeIdsOff)+uint64(typeIdx)*4, 4)
	if err != nil {
		return "", fmt.Errorf("type id: %w", err)
	}
	descriptorIdx := binary.LittleEndian.Uint32(item)

	return p.GetString(descriptorIdx)
}

// 获取方法信息
func (p *DexParser) GetMethodInfo(methodIdx uint32) (*MethodInfo, error) {
	if methodIdx >= p.header.MethodIdsSize {
		return nil, fmt.Errorf("method index out of bounds: %d", methodIdx)
	}

	// 获取method_id_item
	item, err := p.dataRange(uint64(p.header.MethodIdsOff)+uint64(methodIdx)*8, 8)
	if err != nil {
		return nil, fmt.Errorf("method id: %w", err)
	}
	classIdx := binary.LittleEndian.Uint16(item[:2])
	protoIdx := binary.LittleEndian.Uint16(item[2:4])
	nameIdx := binary.LittleEndian.Uint32(item[4:8])

	// 获取类名
	className, err := p.GetTypeDescriptor(uint32(classIdx))
	if err != nil {
		return nil, fmt.Errorf("failed to get class name: %v", err)
	}

	// 获取方法名
	methodName, err := p.GetString(nameIdx)
	if err != nil {
		return nil, fmt.Errorf("failed to get method name: %v", err)
	}

	// 获取原型信息
	proto, err := p.getProtoInfo(uint32(protoIdx))
	if err != nil {
		return nil, fmt.Errorf("failed to get proto info: %v", err)
	}

	return &MethodInfo{
		ClassName:  className,
		MethodName: methodName,
		ReturnType: proto.ReturnType,
		Parameters: proto.Parameters,
	}, nil
}

// 方法信息结构
type MethodInfo struct {
	ClassName  string
	MethodName string
	ReturnType string
	Parameters []string
}

// 原型信息结构
type ProtoInfo struct {
	ReturnType string
	Parameters []string
}

// 获取原型信息
func (p *DexParser) getProtoInfo(protoIdx uint32) (*ProtoInfo, error) {
	if protoIdx >= p.header.ProtoIdsSize {
		return nil, fmt.Errorf("proto index out of bounds: %d", protoIdx)
	}

	// 获取proto_id_item
	item, err := p.dataRange(uint64(p.header.ProtoIdsOff)+uint64(protoIdx)*12, 12)
	if err != nil {
		return nil, fmt.Errorf("proto id: %w", err)
	}
	returnTypeIdx := binary.LittleEndian.Uint32(item[4:8])
	parametersOff := binary.LittleEndian.Uint32(item[8:12])

	// 获取返回类型
	returnType, err := p.GetTypeDescriptor(returnTypeIdx)
	if err != nil {
		return nil, fmt.Errorf("failed to get return type: %v", err)
	}

	var parameters []string
	if parametersOff != 0 {
		parameters, err = p.getParameterTypes(parametersOff)
		if err != nil {
			return nil, fmt.Errorf("failed to get parameter types: %v", err)
		}
	}

	return &ProtoInfo{
		ReturnType: returnType,
		Parameters: parameters,
	}, nil
}

// 获取参数类型列表
func (p *DexParser) getParameterTypes(offset uint32) ([]string, error) {
	header, err := p.dataRange(uint64(offset), 4)
	if err != nil {
		return nil, fmt.Errorf("type list size: %w", err)
	}
	size := binary.LittleEndian.Uint32(header)
	items, err := p.dataRange(uint64(offset)+4, uint64(size)*2)
	if err != nil {
		return nil, fmt.Errorf("type list items: %w", err)
	}
	var parameters []string

	for i := uint32(0); i < size; i++ {
		typeIdx := binary.LittleEndian.Uint16(items[uint64(i)*2 : uint64(i)*2+2])
		typeDesc, err := p.GetTypeDescriptor(uint32(typeIdx))
		if err != nil {
			return nil, fmt.Errorf("failed to get parameter type: %v", err)
		}

		parameters = append(parameters, typeDesc)
	}

	return parameters, nil
}

// 格式化方法签名 (实现prettyMethod功能) - 优化版本使用strings.Builder
func (info *MethodInfo) PrettyMethod() string {
	var sb strings.Builder
	sb.Grow(128) // 预分配空间减少扩容

	// 格式化返回类型
	formatTypeToBuilder(&sb, info.ReturnType)
	sb.WriteByte(' ')

	// 格式化类名 (将L开头的类型转换为Java格式)
	className := info.ClassName
	if len(className) > 2 && className[0] == 'L' && className[len(className)-1] == ';' {
		for i := 1; i < len(className)-1; i++ {
			if className[i] == '/' {
				sb.WriteByte('.')
			} else {
				sb.WriteByte(className[i])
			}
		}
	} else {
		sb.WriteString(className)
	}

	sb.WriteByte('.')
	sb.WriteString(info.MethodName)
	sb.WriteByte('(')

	// 格式化参数列表
	for i, param := range info.Parameters {
		if i > 0 {
			sb.WriteString(", ")
		}
		formatTypeToBuilder(&sb, param)
	}

	sb.WriteByte(')')
	return sb.String()
}

// formatTypeToBuilder 格式化类型描述符到Builder - 高性能版本
func formatTypeToBuilder(sb *strings.Builder, typeDesc string) {
	switch typeDesc {
	case "V":
		sb.WriteString("void")
		return
	case "Z":
		sb.WriteString("boolean")
		return
	case "B":
		sb.WriteString("byte")
		return
	case "S":
		sb.WriteString("short")
		return
	case "C":
		sb.WriteString("char")
		return
	case "I":
		sb.WriteString("int")
		return
	case "J":
		sb.WriteString("long")
		return
	case "F":
		sb.WriteString("float")
		return
	case "D":
		sb.WriteString("double")
		return
	}

	// 数组类型
	if len(typeDesc) > 0 && typeDesc[0] == '[' {
		formatTypeToBuilder(sb, typeDesc[1:])
		sb.WriteString("[]")
		return
	}

	// 对象类型
	if len(typeDesc) > 2 && typeDesc[0] == 'L' && typeDesc[len(typeDesc)-1] == ';' {
		for i := 1; i < len(typeDesc)-1; i++ {
			if typeDesc[i] == '/' {
				sb.WriteByte('.')
			} else {
				sb.WriteByte(typeDesc[i])
			}
		}
		return
	}

	sb.WriteString(typeDesc)
}

// 格式化类型描述符为Java类型 (保留兼容性)
func formatType(typeDesc string) string {
	var sb strings.Builder
	formatTypeToBuilder(&sb, typeDesc)
	return sb.String()
}
