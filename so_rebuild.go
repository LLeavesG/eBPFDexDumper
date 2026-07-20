//go:build arm64

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
)

// program header type (ptLoad lives in fix_so.go)
const ptDynamic = 2

// section header types
const (
	shtNull        = 0
	shtProgbits    = 1
	shtSymtab      = 2
	shtStrtab      = 3
	shtRela        = 4
	shtHash        = 5
	shtDynamic     = 6
	shtNobits      = 8
	shtRel         = 9
	shtDynsym      = 11
	shtInitArray   = 14
	shtFiniArray   = 15
	shtRelr        = 19
	shtAndroidRel  = 0x60000001
	shtAndroidRela = 0x60000002
	shtAndroidRelr = 0x6fffff00
	shtGnuHash     = 0x6ffffff6
	shtGnuVerdef   = 0x6ffffffd
	shtGnuVerneed  = 0x6ffffffe
	shtGnuVersym   = 0x6fffffff
)

// section header flags
const (
	shfWrite    = 0x1
	shfAlloc    = 0x2
	shfExec     = 0x4
	shfInfoLink = 0x40
)

// dynamic tags
const (
	dtNull          = 0
	dtPltrelsz      = 2
	dtPltgot        = 3
	dtHash          = 4
	dtStrtab        = 5
	dtSymtab        = 6
	dtRela          = 7
	dtRelasz        = 8
	dtStrsz         = 10
	dtSyment        = 11
	dtInit          = 12
	dtFini          = 13
	dtRel           = 17
	dtRelsz         = 18
	dtPltrel        = 20
	dtJmprel        = 23
	dtInitArray     = 25
	dtFiniArray     = 26
	dtInitArraySz   = 27
	dtFiniArraySz   = 28
	dtRelr          = 36
	dtRelrsz        = 35
	dtAndroidRel    = 0x6000000f
	dtAndroidRelsz  = 0x60000010
	dtAndroidRela   = 0x60000011
	dtAndroidRelasz = 0x60000012
	dtAndroidRelr   = 0x6fffe000
	dtAndroidRelrsz = 0x6fffe001
	dtGnuHash       = 0x6ffffef5
	dtVersym        = 0x6ffffff0
	dtVerdef        = 0x6ffffffc
	dtVerdefnum     = 0x6ffffffd
	dtVerneed       = 0x6ffffffe
	dtVerneednum    = 0x6fffffff
)

var le = binary.LittleEndian

// elfLayout abstracts the byte-level differences between ELF32 and ELF64 so the
// rebuild logic can be written once. All accessors take a slice positioned at
// the start of the relevant structure (or the whole file, for the header) and
// return class-normalized uint64s.
type elfLayout struct{ is64 bool }

func (l elfLayout) ehdrSize() int { return pick(l.is64, 64, 52) }
func (l elfLayout) phdrSize() int { return pick(l.is64, 56, 32) }
func (l elfLayout) shdrSize() int { return pick(l.is64, 64, 40) }
func (l elfLayout) dynSize() int  { return pick(l.is64, 16, 8) }
func (l elfLayout) symSize() int  { return pick(l.is64, 24, 16) }
func (l elfLayout) word() uint64  { return uint64(pick(l.is64, 8, 4)) }

func pick(is64 bool, a, b int) int {
	if is64 {
		return a
	}
	return b
}

// readAddr reads a class-sized (8- or 4-byte) field at the given per-class offset.
func (l elfLayout) readAddr(b []byte, off64, off32 int) uint64 {
	if l.is64 {
		return le.Uint64(b[off64 : off64+8])
	}
	return uint64(le.Uint32(b[off32 : off32+4]))
}

func (l elfLayout) putAddr(b []byte, off64, off32 int, v uint64) {
	if l.is64 {
		le.PutUint64(b[off64:off64+8], v)
	} else {
		le.PutUint32(b[off32:off32+4], uint32(v))
	}
}

// ELF header accessors
func (l elfLayout) phoff(d []byte) uint64 { return l.readAddr(d, 32, 28) }
func (l elfLayout) phentsize(d []byte) int {
	return int(le.Uint16(d[pick(l.is64, 54, 42):]))
}
func (l elfLayout) phnum(d []byte) int          { return int(le.Uint16(d[pick(l.is64, 56, 44):])) }
func (l elfLayout) setShoff(d []byte, v uint64) { l.putAddr(d, 40, 32, v) }
func (l elfLayout) setShentsize(d []byte, v uint16) {
	le.PutUint16(d[pick(l.is64, 58, 46):], v)
}
func (l elfLayout) setShnum(d []byte, v uint16)    { le.PutUint16(d[pick(l.is64, 60, 48):], v) }
func (l elfLayout) setShstrndx(d []byte, v uint16) { le.PutUint16(d[pick(l.is64, 62, 50):], v) }

// Program header accessors (b positioned at a phdr entry)
func (l elfLayout) pType(b []byte) uint32 { return le.Uint32(b[0:4]) }
func (l elfLayout) pFlags(b []byte) uint32 {
	if l.is64 {
		return le.Uint32(b[4:8])
	}
	return le.Uint32(b[24:28])
}
func (l elfLayout) pVaddr(b []byte) uint64        { return l.readAddr(b, 16, 8) }
func (l elfLayout) pFilesz(b []byte) uint64       { return l.readAddr(b, 32, 16) }
func (l elfLayout) pMemsz(b []byte) uint64        { return l.readAddr(b, 40, 20) }
func (l elfLayout) setPOffset(b []byte, v uint64) { l.putAddr(b, 8, 4, v) }
func (l elfLayout) setPFilesz(b []byte, v uint64) { l.putAddr(b, 32, 16, v) }

// Dynamic entry accessors (b positioned at a dyn entry)
func (l elfLayout) dTag(b []byte) int64 {
	if l.is64 {
		return int64(le.Uint64(b[0:8]))
	}
	return int64(int32(le.Uint32(b[0:4])))
}
func (l elfLayout) dVal(b []byte) uint64 { return l.readAddr(b, 8, 4) }

// Symbol accessors (b positioned at a sym entry). NB: ELF32 and ELF64 order
// their fields differently, so these are not simple width swaps.
func (l elfLayout) symValue(b []byte) uint64 {
	if l.is64 {
		return le.Uint64(b[8:16])
	}
	return uint64(le.Uint32(b[4:8]))
}
func (l elfLayout) symInfo(b []byte) byte {
	if l.is64 {
		return b[4]
	}
	return b[12]
}
func (l elfLayout) symShndxOff() int { return pick(l.is64, 6, 14) }
func (l elfLayout) symShndx(b []byte) uint16 {
	return le.Uint16(b[l.symShndxOff():])
}
func (l elfLayout) setSymShndx(b []byte, v uint16) { le.PutUint16(b[l.symShndxOff():], v) }

// putShdr writes one section header entry in the right class layout.
func (l elfLayout) putShdr(b []byte, name, typ uint32, flags, addr, off, size uint64, link, info uint32, align, entsize uint64) {
	le.PutUint32(b[0:4], name)
	le.PutUint32(b[4:8], typ)
	if l.is64 {
		le.PutUint64(b[8:16], flags)
		le.PutUint64(b[16:24], addr)
		le.PutUint64(b[24:32], off)
		le.PutUint64(b[32:40], size)
		le.PutUint32(b[40:44], link)
		le.PutUint32(b[44:48], info)
		le.PutUint64(b[48:56], align)
		le.PutUint64(b[56:64], entsize)
	} else {
		le.PutUint32(b[8:12], uint32(flags))
		le.PutUint32(b[12:16], uint32(addr))
		le.PutUint32(b[16:20], uint32(off))
		le.PutUint32(b[20:24], uint32(size))
		le.PutUint32(b[24:28], link)
		le.PutUint32(b[28:32], info)
		le.PutUint32(b[32:36], uint32(align))
		le.PutUint32(b[36:40], uint32(entsize))
	}
}

// putSym writes one symbol table entry in the right class layout. NB: ELF32 and
// ELF64 order the fields differently.
func (l elfLayout) putSym(b []byte, name uint32, value, size uint64, info, other byte, shndx uint16) {
	if l.is64 {
		le.PutUint32(b[0:4], name)
		b[4] = info
		b[5] = other
		le.PutUint16(b[6:8], shndx)
		le.PutUint64(b[8:16], value)
		le.PutUint64(b[16:24], size)
	} else {
		le.PutUint32(b[0:4], name)
		le.PutUint32(b[4:8], uint32(value))
		le.PutUint32(b[8:12], uint32(size))
		b[12] = info
		b[13] = other
		le.PutUint16(b[14:16], shndx)
	}
}

// secDesc is a work-in-progress section header, with link/info kept as names
// until the final index assignment.
type secDesc struct {
	name     string
	typ      uint32
	flags    uint64
	addr     uint64
	size     uint64
	hasSize  bool // true if size is known precisely (don't overwrite via neighbor calc)
	linkName string
	infoName string
	info     uint32
	entsize  uint64
	align    uint64
	fileData []byte // non-alloc appended section payload (.symtab/.strtab); offset set at emit
	fileOff  uint64
}

type loadSeg struct {
	vaddr, filesz, memsz uint64
	flags                uint32
}

// InjectedSym is a caller-supplied symbol (e.g. a recovered JNI function name
// at a known offset) to write into a real .symtab so IDA/Ghidra show the name.
type InjectedSym struct {
	Name  string
	Value uint64 // offset within the module
}

// sectionIndexOf returns the index of the allocatable section whose address
// range contains value, or 0 (SHN_UNDEF) if none does.
func sectionIndexOf(value uint64, secs []secDesc) uint16 {
	for i, s := range secs {
		if s.flags&shfAlloc == 0 || s.size == 0 {
			continue
		}
		if value >= s.addr && value < s.addr+s.size {
			return uint16(i)
		}
	}
	return 0
}

// RebuildSoSections takes a memory image of an ELF shared object (ELF32 or
// ELF64, little-endian) as produced by dumping [base,end) from process memory
// (bytes live at file offset == virtual address) and returns a copy with
// p_offset normalized and a freshly reconstructed section header table
// appended, so tools like IDA recognize it.
//
// The whole reconstruction is driven by the PT_DYNAMIC segment, which survives
// in a memory dump: DT_SYMTAB/STRTAB/HASH/GNU_HASH/REL/RELA/RELR/JMPREL/PLTGOT/
// VERSYM/VERDEF/VERNEED/INIT_ARRAY/FINI_ARRAY give the addresses (and often the
// sizes) of the corresponding sections. Sections whose size isn't directly
// known are sized from the next section's start after sorting by address.
func RebuildSoSections(image []byte, injected []InjectedSym) ([]byte, error) {
	data := make([]byte, len(image))
	copy(data, image)

	if len(data) < 16 {
		return nil, fmt.Errorf("image too small")
	}
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("not an ELF image")
	}
	if data[4] != 1 && data[4] != 2 {
		return nil, fmt.Errorf("unsupported EI_CLASS=%d", data[4])
	}
	if data[5] != 1 {
		return nil, fmt.Errorf("only little-endian images supported (EI_DATA=%d)", data[5])
	}
	l := elfLayout{is64: data[4] == 2}
	if len(data) < l.ehdrSize() {
		return nil, fmt.Errorf("image smaller than ELF header")
	}

	phoff := l.phoff(data)
	phentsize := l.phentsize(data)
	phnum := l.phnum(data)
	if phentsize == 0 {
		phentsize = l.phdrSize()
	}
	if phoff == 0 || phnum == 0 {
		return nil, fmt.Errorf("no program headers")
	}

	// Parse program headers: normalize p_offset=p_vaddr, collect LOADs + DYNAMIC.
	var loads []loadSeg
	var dynAddr, dynSize uint64
	for i := 0; i < phnum; i++ {
		off := int(phoff) + i*phentsize
		if off+l.phdrSize() > len(data) {
			break
		}
		ph := data[off:]
		pType := l.pType(ph)
		pFlags := l.pFlags(ph)
		pVaddr := l.pVaddr(ph)
		pFilesz := l.pFilesz(ph)
		pMemsz := l.pMemsz(ph)

		// memory image: file offset equals virtual address
		l.setPOffset(ph, pVaddr)

		switch pType {
		case ptLoad:
			loads = append(loads, loadSeg{vaddr: pVaddr, filesz: pFilesz, memsz: pMemsz, flags: pFlags})
			if pMemsz > pFilesz {
				// in a memory image the whole segment is present
				l.setPFilesz(ph, pMemsz)
			}
		case ptDynamic:
			dynAddr = pVaddr
			dynSize = pMemsz
		}
	}
	if dynAddr == 0 {
		return nil, fmt.Errorf("no PT_DYNAMIC segment; cannot rebuild sections")
	}
	if len(loads) == 0 {
		return nil, fmt.Errorf("no PT_LOAD segments")
	}

	var minVaddr, maxVaddr uint64 = ^uint64(0), 0
	var loadFileEnd uint64 // highest vaddr backed by file bytes (end of .data, before .bss)
	for _, seg := range loads {
		if seg.vaddr < minVaddr {
			minVaddr = seg.vaddr
		}
		if seg.vaddr+seg.memsz > maxVaddr {
			maxVaddr = seg.vaddr + seg.memsz
		}
		if end := seg.vaddr + seg.filesz; end > loadFileEnd {
			loadFileEnd = end
		}
	}

	// Parse the dynamic segment (singleton tags only; NEEDED etc. are irrelevant).
	dyn := map[int64]uint64{}
	dynEnt := l.dynSize()
	for off := int(dynAddr); off+dynEnt <= len(data) && off+dynEnt <= int(dynAddr)+int(dynSize); off += dynEnt {
		tag := l.dTag(data[off:])
		val := l.dVal(data[off:])
		if tag == dtNull {
			break
		}
		dyn[tag] = val
	}

	get := func(tag int64) (uint64, bool) { v, ok := dyn[tag]; return v, ok }

	// Determine dynamic symbol count (needed for .dynsym / .gnu.version sizes).
	symcount := 0
	if h, ok := get(dtHash); ok && int(h)+8 <= len(data) {
		// SysV hash: nchain (at +4) == number of symbol table entries
		nchain := le.Uint32(data[int(h)+4 : int(h)+8])
		symcount = int(nchain)
	} else if gh, ok := get(dtGnuHash); ok {
		symcount = gnuHashSymCount(l, data, int(gh))
	}

	symEnt := uint64(l.symSize())
	relaEnt := uint64(pick(l.is64, 24, 12))
	relEnt := uint64(pick(l.is64, 16, 8))

	var secs []secDesc
	secs = append(secs, secDesc{name: ""}) // index 0 is always the NULL section

	strtabAddr, hasStrtab := get(dtStrtab)
	strsz, _ := get(dtStrsz)

	if gh, ok := get(dtGnuHash); ok {
		secs = append(secs, secDesc{name: ".gnu.hash", typ: shtGnuHash, flags: shfAlloc, addr: gh, linkName: ".dynsym", align: l.word()})
	}
	if h, ok := get(dtHash); ok {
		secs = append(secs, secDesc{name: ".hash", typ: shtHash, flags: shfAlloc, addr: h, linkName: ".dynsym", entsize: 4, align: l.word()})
	}
	if sym, ok := get(dtSymtab); ok {
		syment, ok2 := get(dtSyment)
		if !ok2 || syment == 0 {
			syment = symEnt
		}
		d := secDesc{name: ".dynsym", typ: shtDynsym, flags: shfAlloc, addr: sym, linkName: ".dynstr", entsize: syment, align: l.word()}
		if symcount > 0 {
			d.size = uint64(symcount) * syment
			d.hasSize = true
		}
		d.info = uint32(countLocalSyms(l, data, int(sym), symcount))
		secs = append(secs, d)
	}
	if hasStrtab {
		d := secDesc{name: ".dynstr", typ: shtStrtab, flags: shfAlloc, addr: strtabAddr, align: 1}
		if strsz > 0 {
			d.size = strsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if vs, ok := get(dtVersym); ok {
		d := secDesc{name: ".gnu.version", typ: shtGnuVersym, flags: shfAlloc, addr: vs, linkName: ".dynsym", entsize: 2, align: 2}
		if symcount > 0 {
			d.size = uint64(symcount) * 2
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if vd, ok := get(dtVerdef); ok {
		d := secDesc{name: ".gnu.version_d", typ: shtGnuVerdef, flags: shfAlloc, addr: vd, linkName: ".dynstr", align: l.word()}
		if cnt, ok2 := get(dtVerdefnum); ok2 {
			d.info = uint32(cnt)
		}
		secs = append(secs, d)
	}
	if vn, ok := get(dtVerneed); ok {
		d := secDesc{name: ".gnu.version_r", typ: shtGnuVerneed, flags: shfAlloc, addr: vn, linkName: ".dynstr", align: l.word()}
		if cnt, ok2 := get(dtVerneednum); ok2 {
			d.info = uint32(cnt)
		}
		secs = append(secs, d)
	}
	if rela, ok := get(dtRela); ok {
		relasz, _ := get(dtRelasz)
		d := secDesc{name: ".rela.dyn", typ: shtRela, flags: shfAlloc, addr: rela, linkName: ".dynsym", entsize: relaEnt, align: l.word()}
		if relasz > 0 {
			d.size = relasz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if rel, ok := get(dtRel); ok {
		relsz, _ := get(dtRelsz)
		d := secDesc{name: ".rel.dyn", typ: shtRel, flags: shfAlloc, addr: rel, linkName: ".dynsym", entsize: relEnt, align: l.word()}
		if relsz > 0 {
			d.size = relsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if relr, ok := get(dtRelr); ok {
		relrsz, _ := get(dtRelrsz)
		d := secDesc{name: ".relr.dyn", typ: shtRelr, flags: shfAlloc, addr: relr, entsize: l.word(), align: l.word()}
		if relrsz > 0 {
			d.size = relrsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	// Android packed relocations (common in Android hardeners and older NDK
	// output). The payload stays packed (APS2 stream for REL/RELA, bitmap for
	// RELR); we only anchor a correctly typed section header at it so IDA and
	// readelf decode it. These tags are mutually exclusive with the standard
	// DT_REL/DT_RELA/DT_RELR above, so no section name collides in practice.
	if ar, ok := get(dtAndroidRela); ok {
		arsz, _ := get(dtAndroidRelasz)
		d := secDesc{name: ".rela.dyn", typ: shtAndroidRela, flags: shfAlloc, addr: ar, linkName: ".dynsym", align: l.word()}
		if arsz > 0 {
			d.size = arsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if ar, ok := get(dtAndroidRel); ok {
		arsz, _ := get(dtAndroidRelsz)
		d := secDesc{name: ".rel.dyn", typ: shtAndroidRel, flags: shfAlloc, addr: ar, linkName: ".dynsym", align: l.word()}
		if arsz > 0 {
			d.size = arsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if ar, ok := get(dtAndroidRelr); ok {
		arsz, _ := get(dtAndroidRelrsz)
		d := secDesc{name: ".relr.dyn", typ: shtAndroidRelr, flags: shfAlloc, addr: ar, entsize: l.word(), align: l.word()}
		if arsz > 0 {
			d.size = arsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	// .rela.plt / .rel.plt — the JMPREL table; its form (REL vs RELA) follows
	// DT_PLTREL (defaulting to the arch norm: RELA on 64-bit, REL on 32-bit).
	pltIsRela := l.is64
	if pr, ok := get(dtPltrel); ok {
		pltIsRela = pr == uint64(dtRela)
	}
	pltRelEnt := relEnt
	if pltIsRela {
		pltRelEnt = relaEnt
	}
	if jmp, ok := get(dtJmprel); ok {
		pltrelsz, _ := get(dtPltrelsz)
		name, typ := ".rel.plt", uint32(shtRel)
		if pltIsRela {
			name, typ = ".rela.plt", shtRela
		}
		d := secDesc{name: name, typ: typ, flags: shfAlloc | shfInfoLink, addr: jmp, linkName: ".dynsym", infoName: ".got.plt", entsize: pltRelEnt, align: l.word()}
		if pltrelsz > 0 {
			d.size = pltrelsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if ini, ok := get(dtInit); ok {
		secs = append(secs, secDesc{name: ".init", typ: shtProgbits, flags: shfAlloc | shfExec, addr: ini, align: 4})
	}
	// .plt starts right after the JMPREL table; its exact size is arch-dependent,
	// so the neighbor-based pass finalizes it from the next section's start.
	if jmp, ok := get(dtJmprel); ok {
		pltrelsz, _ := get(dtPltrelsz)
		pltAddr := (jmp + pltrelsz + 0xf) &^ 0xf
		secs = append(secs, secDesc{name: ".plt", typ: shtProgbits, flags: shfAlloc | shfExec, addr: pltAddr, entsize: 16, align: 16})
	}
	// .text: seeded just past .plt (or .init); size computed from neighbors.
	textStart := uint64(0)
	if v, ok := get(dtInit); ok {
		textStart = v
	}
	if jmp, ok := get(dtJmprel); ok {
		pltrelsz, _ := get(dtPltrelsz)
		textStart = (jmp + pltrelsz + 0xf) &^ 0xf
	}
	if textStart != 0 {
		secs = append(secs, secDesc{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: textStart + 0x40, align: l.word()})
	}
	if ia, ok := get(dtInitArray); ok {
		iasz, _ := get(dtInitArraySz)
		d := secDesc{name: ".init_array", typ: shtInitArray, flags: shfWrite | shfAlloc, addr: ia, entsize: l.word(), align: l.word()}
		if iasz > 0 {
			d.size = iasz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if fa, ok := get(dtFiniArray); ok {
		fasz, _ := get(dtFiniArraySz)
		d := secDesc{name: ".fini_array", typ: shtFiniArray, flags: shfWrite | shfAlloc, addr: fa, entsize: l.word(), align: l.word()}
		if fasz > 0 {
			d.size = fasz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	secs = append(secs, secDesc{name: ".dynamic", typ: shtDynamic, flags: shfWrite | shfAlloc, addr: dynAddr, size: dynSize, hasSize: true, linkName: ".dynstr", entsize: uint64(dynEnt), align: l.word()})
	// .got.plt (DT_PLTGOT): standard layout is 3 reserved GOT slots followed by
	// one slot per PLT relocation, so its size is (3 + pltRelCount) * wordsize.
	var gotPltEnd uint64
	if got, ok := get(dtPltgot); ok {
		d := secDesc{name: ".got.plt", typ: shtProgbits, flags: shfWrite | shfAlloc, addr: got, entsize: l.word(), align: l.word()}
		if pltrelsz, ok2 := get(dtPltrelsz); ok2 && pltrelsz > 0 && pltRelEnt > 0 {
			d.size = (3 + pltrelsz/pltRelEnt) * l.word()
			d.hasSize = true
			gotPltEnd = got + d.size
		}
		secs = append(secs, d)
	}
	// .data: from the end of .got.plt up to the file-backed load end.
	// .bss: the memsz-beyond-filesz tail.
	if gotPltEnd > 0 && gotPltEnd < loadFileEnd {
		secs = append(secs, secDesc{name: ".data", typ: shtProgbits, flags: shfWrite | shfAlloc, addr: gotPltEnd, align: l.word()})
	}
	if maxVaddr > loadFileEnd {
		secs = append(secs, secDesc{name: ".bss", typ: shtNobits, flags: shfWrite | shfAlloc, addr: loadFileEnd, size: maxVaddr - loadFileEnd, hasSize: true, align: l.word()})
	}

	// Sort allocatable sections by address (NULL stays at index 0).
	body := secs[1:]
	sort.SliceStable(body, func(i, j int) bool { return body[i].addr < body[j].addr })

	// Neighbor-based size pass: any section without a precise size grows to the
	// next section's start; precise sizes are clamped only if they'd overlap.
	for i := 0; i < len(body); i++ {
		var next uint64
		if i+1 < len(body) {
			next = body[i+1].addr
		} else {
			next = loadFileEnd
			if body[i].typ == shtNobits {
				next = maxVaddr
			}
		}
		if next <= body[i].addr {
			continue
		}
		gap := next - body[i].addr
		if !body[i].hasSize {
			body[i].size = gap
		} else if body[i].size > gap {
			body[i].size = gap
		}
	}

	// Reassemble: NULL + sorted allocatable sections + injected .symtab/.strtab
	// + .shstrtab.
	secs = append([]secDesc{secs[0]}, body...)

	// Injected symbols become a real .symtab/.strtab appended at the end of the
	// file (non-alloc), so tools display caller-supplied names such as recovered
	// JNI functions. st_shndx points at the rebuilt section containing the value.
	if len(injected) > 0 {
		symSz := l.symSize()
		strtab := []byte{0}
		symtab := make([]byte, (len(injected)+1)*symSz) // entry 0 is the null symbol
		for i, s := range injected {
			nameOff := uint32(len(strtab))
			strtab = append(strtab, []byte(s.Name)...)
			strtab = append(strtab, 0)
			l.putSym(symtab[(i+1)*symSz:], nameOff, s.Value, 0, 0x12, 0, sectionIndexOf(s.Value, secs)) // STB_GLOBAL|STT_FUNC
		}
		secs = append(secs,
			secDesc{name: ".symtab", typ: shtSymtab, entsize: uint64(symSz), align: l.word(), fileData: symtab, linkName: ".strtab", info: 1},
			secDesc{name: ".strtab", typ: shtStrtab, align: 1, fileData: strtab},
		)
	}

	shstrtabIdx := len(secs)
	secs = append(secs, secDesc{name: ".shstrtab", typ: shtStrtab, align: 1})

	// Build the section header string table.
	shstrtab := []byte{0}
	nameOff := map[string]uint32{"": 0}
	for _, s := range secs {
		if s.name == "" {
			continue
		}
		if _, ok := nameOff[s.name]; ok {
			continue
		}
		nameOff[s.name] = uint32(len(shstrtab))
		shstrtab = append(shstrtab, []byte(s.name)...)
		shstrtab = append(shstrtab, 0)
	}

	// name -> index for link/info resolution
	idxOf := map[string]uint32{}
	for i, s := range secs {
		if s.name != "" {
			idxOf[s.name] = uint32(i)
		}
	}

	// The original st_shndx values in .dynsym point at the (now-gone) original
	// section layout; remap each defined symbol to the rebuilt section that
	// contains its address so the indexes are valid again.
	if symAddr, ok := get(dtSymtab); ok && symcount > 0 {
		remapSymShndx(l, data, int(symAddr), symcount, secs)
	}

	// Lay out appended data at end of file: [non-alloc section payloads]
	// [.shstrtab][shdr table]. Non-alloc sections (.symtab/.strtab) carry their
	// bytes in fileData and get their file offset assigned here.
	for i := range secs {
		if secs[i].fileData == nil {
			continue
		}
		for secs[i].align > 1 && uint64(len(data))%secs[i].align != 0 {
			data = append(data, 0)
		}
		secs[i].fileOff = uint64(len(data))
		data = append(data, secs[i].fileData...)
	}
	shstrtabOff := uint64(len(data))
	data = append(data, shstrtab...)
	for len(data)%int(l.word()) != 0 { // align shdr table to class word size
		data = append(data, 0)
	}
	shoff := uint64(len(data))

	shdrSize := l.shdrSize()
	shtable := make([]byte, len(secs)*shdrSize)
	for i, s := range secs {
		b := shtable[i*shdrSize : (i+1)*shdrSize]
		var shName uint32
		if s.name != "" {
			shName = nameOff[s.name]
		}
		var shOffset, shAddr, shSize uint64 = 0, 0, s.size
		switch {
		case s.name == "":
			// NULL section: all zero
		case s.name == ".shstrtab":
			shOffset = shstrtabOff
			shSize = uint64(len(shstrtab))
		case s.fileData != nil:
			// non-alloc appended section (.symtab/.strtab): lives in the file
			// only, no memory address
			shOffset = s.fileOff
			shSize = uint64(len(s.fileData))
		default:
			shAddr = s.addr
			shOffset = s.addr // memory image: offset == addr
		}
		var link uint32
		if s.linkName != "" {
			link = idxOf[s.linkName]
		}
		info := s.info
		if s.infoName != "" {
			info = idxOf[s.infoName]
		}
		l.putShdr(b, shName, s.typ, s.flags, shAddr, shOffset, shSize, link, info, s.align, s.entsize)
	}
	data = append(data, shtable...)

	// Patch the ELF header to point at the rebuilt table.
	l.setShoff(data, shoff)
	l.setShentsize(data, uint16(shdrSize))
	l.setShnum(data, uint16(len(secs)))
	l.setShstrndx(data, uint16(shstrtabIdx))

	return data, nil
}

// SelfCheckSo parses rebuilt ELF bytes the way IDA/BFD would — strictly, via
// the section header table — and returns how many dynamic symbols are
// readable, as a confidence signal that the rebuild is loadable and useful.
func SelfCheckSo(data []byte) (int, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	syms, err := f.DynamicSymbols()
	if err != nil {
		return 0, err
	}
	return len(syms), nil
}

// remapSymShndx rewrites each defined .dynsym entry's st_shndx to the rebuilt
// allocatable section whose address range contains the symbol's value. UND (0)
// and reserved (>=0xff00, e.g. SHN_ABS) entries are left untouched.
func remapSymShndx(l elfLayout, data []byte, off, count int, secs []secDesc) {
	symSize := l.symSize()
	for i := 0; i < count; i++ {
		o := off + i*symSize
		if o+symSize > len(data) {
			break
		}
		b := data[o:]
		shndx := l.symShndx(b)
		if shndx == 0 || shndx >= 0xff00 {
			continue
		}
		value := l.symValue(b)
		for si, s := range secs {
			if s.flags&shfAlloc == 0 || s.size == 0 {
				continue
			}
			if value >= s.addr && value < s.addr+s.size {
				l.setSymShndx(b, uint16(si))
				break
			}
		}
	}
}

// gnuHashSymCount derives the dynamic symbol count from a DT_GNU_HASH table,
// which (unlike DT_HASH) has no explicit symbol count: walk the hash chain of
// the highest-indexed bucket until its terminator bit is set. The bloom filter
// is word-sized (4 bytes on ELF32, 8 on ELF64); buckets and the chain array are
// always 32-bit.
func gnuHashSymCount(l elfLayout, data []byte, off int) int {
	if off+16 > len(data) {
		return 0
	}
	nbuckets := int(le.Uint32(data[off : off+4]))
	symoffset := int(le.Uint32(data[off+4 : off+8]))
	bloomSize := int(le.Uint32(data[off+8 : off+12]))
	if nbuckets == 0 {
		return symoffset
	}
	bucketsOff := off + 16 + bloomSize*int(l.word())
	chainBase := bucketsOff + nbuckets*4
	if chainBase > len(data) {
		return 0
	}
	maxSym := 0
	for i := 0; i < nbuckets; i++ {
		o := bucketsOff + i*4
		if o+4 > len(data) {
			break
		}
		b := int(le.Uint32(data[o : o+4]))
		if b > maxSym {
			maxSym = b
		}
	}
	if maxSym < symoffset {
		return symoffset
	}
	sym := maxSym
	for {
		o := chainBase + (sym-symoffset)*4
		if o+4 > len(data) || o < chainBase {
			break
		}
		h := le.Uint32(data[o : o+4])
		if h&1 != 0 {
			break
		}
		sym++
	}
	return sym + 1
}

// countLocalSyms counts leading STB_LOCAL entries (st_info>>4 == 0) to seed
// .dynsym sh_info. Best-effort; IDA doesn't depend on it being exact.
func countLocalSyms(l elfLayout, data []byte, off, count int) int {
	if count <= 0 {
		return 1
	}
	symSize := l.symSize()
	locals := 0
	for i := 0; i < count; i++ {
		o := off + i*symSize
		if o+symSize > len(data) {
			break
		}
		if l.symInfo(data[o:])>>4 == 0 { // STB_LOCAL
			locals++
		} else {
			break
		}
	}
	if locals == 0 {
		return 1
	}
	return locals
}
