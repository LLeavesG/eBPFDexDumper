//go:build arm64

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
	Magic        [8]byte
	Checksum     uint32
	Signature    [20]byte
	FileSize     uint32
	HeaderSize   uint32
	EndianTag    uint32
	LinkSize     uint32
	LinkOff      uint32
	MapOff       uint32
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
	ShortyIdx      uint32
	ReturnTypeIdx  uint32
	ParametersOff  uint32
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
    if magic != DexFileMagic {
        return nil, fmt.Errorf("invalid dex magic: %x", magic)
    }
	
	return parser, nil
}

// 读取字符串
func (p *DexParser) GetString(stringIdx uint32) (string, error) {
	if stringIdx >= p.header.StringIdsSize {
		return "", fmt.Errorf("string index out of bounds: %d", stringIdx)
	}
	
	// 获取string_id_item
	stringIdOffset := p.header.StringIdsOff + stringIdx*4
	if int(stringIdOffset+4) > len(p.data) {
		return "", fmt.Errorf("string id offset out of bounds")
	}
	
	stringDataOff := binary.LittleEndian.Uint32(p.data[stringIdOffset:stringIdOffset+4])
	
	// 读取字符串数据
	return p.readStringData(stringDataOff)
}

// 读取字符串数据
func (p *DexParser) readStringData(offset uint32) (string, error) {
	if int(offset) >= len(p.data) {
		return "", fmt.Errorf("string data offset out of bounds")
	}
	
	// 读取ULEB128长度
	pos := int(offset)
	length, newPos := p.readULEB128(pos)
	pos = newPos
	
	if pos+int(length) > len(p.data) {
		return "", fmt.Errorf("string data out of bounds")
	}
	
	return string(p.data[pos:pos+int(length)]), nil
}

// 读取ULEB128
func (p *DexParser) readULEB128(offset int) (uint32, int) {
	var result uint32
	var shift uint
	pos := offset
	
	for {
		if pos >= len(p.data) {
			break
		}
		
		b := p.data[pos]
		pos++
		
		result |= uint32(b&0x7f) << shift
		if (b & 0x80) == 0 {
			break
		}
		shift += 7
	}
	
	return result, pos
}

// 获取类型描述符
func (p *DexParser) GetTypeDescriptor(typeIdx uint32) (string, error) {
	if typeIdx >= p.header.TypeIdsSize {
		return "", fmt.Errorf("type index out of bounds: %d", typeIdx)
	}
	
	// 获取type_id_item
	typeIdOffset := p.header.TypeIdsOff + typeIdx*4
	if int(typeIdOffset+4) > len(p.data) {
		return "", fmt.Errorf("type id offset out of bounds")
	}
	
	descriptorIdx := binary.LittleEndian.Uint32(p.data[typeIdOffset:typeIdOffset+4])
	
	return p.GetString(descriptorIdx)
}

// 获取方法信息
func (p *DexParser) GetMethodInfo(methodIdx uint32) (*MethodInfo, error) {
	if methodIdx >= p.header.MethodIdsSize {
		return nil, fmt.Errorf("method index out of bounds: %d", methodIdx)
	}
	
	// 获取method_id_item
	methodIdOffset := p.header.MethodIdsOff + methodIdx*8
	if int(methodIdOffset+8) > len(p.data) {
		return nil, fmt.Errorf("method id offset out of bounds")
	}
	
	classIdx := binary.LittleEndian.Uint16(p.data[methodIdOffset:methodIdOffset+2])
	protoIdx := binary.LittleEndian.Uint16(p.data[methodIdOffset+2:methodIdOffset+4])
	nameIdx := binary.LittleEndian.Uint32(p.data[methodIdOffset+4:methodIdOffset+8])
	
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
		ClassName:    className,
		MethodName:   methodName,
		ReturnType:   proto.ReturnType,
		Parameters:   proto.Parameters,
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
	protoIdOffset := p.header.ProtoIdsOff + protoIdx*12
	if int(protoIdOffset+12) > len(p.data) {
		return nil, fmt.Errorf("proto id offset out of bounds")
	}
	
	_ = binary.LittleEndian.Uint32(p.data[protoIdOffset:protoIdOffset+4]) // shortyIdx (unused)
	returnTypeIdx := binary.LittleEndian.Uint32(p.data[protoIdOffset+4:protoIdOffset+8])
	parametersOff := binary.LittleEndian.Uint32(p.data[protoIdOffset+8:protoIdOffset+12])
	
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
	if int(offset) >= len(p.data) {
		return nil, fmt.Errorf("parameter types offset out of bounds")
	}
	
	// 读取type_list
	if int(offset+4) > len(p.data) {
		return nil, fmt.Errorf("type list size out of bounds")
	}
	
	size := binary.LittleEndian.Uint32(p.data[offset:offset+4])
	var parameters []string
	
	for i := uint32(0); i < size; i++ {
		typeItemOffset := offset + 4 + i*2
		if int(typeItemOffset+2) > len(p.data) {
			return nil, fmt.Errorf("type item offset out of bounds")
		}
		
		typeIdx := binary.LittleEndian.Uint16(p.data[typeItemOffset:typeItemOffset+2])
		typeDesc, err := p.GetTypeDescriptor(uint32(typeIdx))
		if err != nil {
			return nil, fmt.Errorf("failed to get parameter type: %v", err)
		}
		
		parameters = append(parameters, typeDesc)
	}
	
	return parameters, nil
}

// 格式化方法签名 (实现prettyMethod功能)
func (info *MethodInfo) PrettyMethod() string {
	// 格式化类名 (将L开头的类型转换为Java格式)
	className := info.ClassName
	if len(className) > 0 && className[0] == 'L' && className[len(className)-1] == ';' {
		className = className[1 : len(className)-1]
		className = strings.ReplaceAll(className, "/", ".")
	}
	
	// 格式化返回类型
	returnType := formatType(info.ReturnType)
	
	// 格式化参数列表
	var paramStrs []string
	for _, param := range info.Parameters {
		paramStrs = append(paramStrs, formatType(param))
	}
	
	// 组装方法签名
	return fmt.Sprintf("%s %s.%s(%s)", 
		returnType, 
		className, 
		info.MethodName, 
		strings.Join(paramStrs, ", "))
}

// 格式化类型描述符为Java类型
func formatType(typeDesc string) string {
	switch typeDesc {
	case "V":
		return "void"
	case "Z":
		return "boolean"
	case "B":
		return "byte"
	case "S":
		return "short"
	case "C":
		return "char"
	case "I":
		return "int"
	case "J":
		return "long"
	case "F":
		return "float"
	case "D":
		return "double"
	}
	
	// 数组类型
	if len(typeDesc) > 0 && typeDesc[0] == '[' {
		elementType := formatType(typeDesc[1:])
		return elementType + "[]"
	}
	
	// 对象类型
	if len(typeDesc) > 0 && typeDesc[0] == 'L' && typeDesc[len(typeDesc)-1] == ';' {
		className := typeDesc[1 : len(typeDesc)-1]
		className = strings.ReplaceAll(className, "/", ".")
		return className
	}
	
	return typeDesc
}
