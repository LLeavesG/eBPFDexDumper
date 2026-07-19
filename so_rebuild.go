//go:build arm64

package main

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// ELF64 structure sizes (elf64HeaderSize/elf64PhdrSize live in fix_so.go).
const (
	elf64ShdrSize = 64
	elf64DynSize  = 16
	elf64SymSize  = 24
)

// program header type (ptLoad lives in fix_so.go)
const ptDynamic = 2

// section header types
const (
	shtNull       = 0
	shtProgbits   = 1
	shtStrtab     = 3
	shtRela       = 4
	shtHash       = 5
	shtDynamic    = 6
	shtNobits     = 8
	shtDynsym     = 11
	shtInitArray  = 14
	shtFiniArray  = 15
	shtRelr       = 19
	shtGnuHash    = 0x6ffffff6
	shtGnuVerdef  = 0x6ffffffd
	shtGnuVerneed = 0x6ffffffe
	shtGnuVersym  = 0x6fffffff
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
	dtNull        = 0
	dtPltrelsz    = 2
	dtPltgot      = 3
	dtHash        = 4
	dtStrtab      = 5
	dtSymtab      = 6
	dtRela        = 7
	dtRelasz      = 8
	dtStrsz       = 10
	dtSyment      = 11
	dtInit        = 12
	dtFini        = 13
	dtJmprel      = 23
	dtInitArray   = 25
	dtFiniArray   = 26
	dtInitArraySz = 27
	dtFiniArraySz = 28
	dtRelr        = 36
	dtRelrsz      = 35
	dtGnuHash     = 0x6ffffef5
	dtVersym      = 0x6ffffff0
	dtVerdef      = 0x6ffffffc
	dtVerdefnum   = 0x6ffffffd
	dtVerneed     = 0x6ffffffe
	dtVerneednum  = 0x6fffffff
)

var le = binary.LittleEndian

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
}

type loadSeg struct {
	vaddr, filesz, memsz uint64
	flags                uint32
}

// RebuildSoSections takes a memory image of an ELF64 shared object (as produced
// by dumping [base,end) from process memory, i.e. bytes live at file offset ==
// virtual address) and returns a copy with p_offset normalized and a freshly
// reconstructed section header table appended, so tools like IDA recognize it.
//
// The whole reconstruction is driven by the PT_DYNAMIC segment, which survives
// in a memory dump: DT_SYMTAB/STRTAB/HASH/GNU_HASH/RELA/RELR/JMPREL/PLTGOT/
// VERSYM/VERDEF/VERNEED/INIT_ARRAY/FINI_ARRAY give the addresses (and often the
// sizes) of the corresponding sections. Sections whose size isn't directly
// known are sized from the next section's start after sorting by address.
func RebuildSoSections(image []byte) ([]byte, error) {
	data := make([]byte, len(image))
	copy(data, image)

	if len(data) < elf64HeaderSize {
		return nil, fmt.Errorf("image too small")
	}
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("not an ELF image")
	}
	if data[4] != 2 {
		return nil, fmt.Errorf("only ELF64 supported")
	}

	phoff := le.Uint64(data[32:40])
	phentsize := int(le.Uint16(data[54:56]))
	phnum := int(le.Uint16(data[56:58]))
	if phentsize == 0 {
		phentsize = elf64PhdrSize
	}
	if phoff == 0 || phnum == 0 {
		return nil, fmt.Errorf("no program headers")
	}

	// Parse program headers: normalize p_offset=p_vaddr, collect LOADs + DYNAMIC.
	var loads []loadSeg
	var dynAddr, dynSize uint64
	for i := 0; i < phnum; i++ {
		off := int(phoff) + i*phentsize
		if off+elf64PhdrSize > len(data) {
			break
		}
		pType := le.Uint32(data[off : off+4])
		pFlags := le.Uint32(data[off+4 : off+8])
		pVaddr := le.Uint64(data[off+16 : off+24])
		pFilesz := le.Uint64(data[off+32 : off+40])
		pMemsz := le.Uint64(data[off+40 : off+48])

		// memory image: file offset equals virtual address
		le.PutUint64(data[off+8:off+16], pVaddr)

		switch pType {
		case ptLoad:
			loads = append(loads, loadSeg{vaddr: pVaddr, filesz: pFilesz, memsz: pMemsz, flags: pFlags})
			if pMemsz > pFilesz {
				// in a memory image the whole segment is present
				le.PutUint64(data[off+32:off+40], pMemsz)
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
	for _, l := range loads {
		if l.vaddr < minVaddr {
			minVaddr = l.vaddr
		}
		if l.vaddr+l.memsz > maxVaddr {
			maxVaddr = l.vaddr + l.memsz
		}
		if end := l.vaddr + l.filesz; end > loadFileEnd {
			loadFileEnd = end
		}
	}

	// Parse the dynamic segment (singleton tags only; NEEDED etc. are irrelevant).
	dyn := map[int64]uint64{}
	for off := int(dynAddr); off+elf64DynSize <= len(data) && off+elf64DynSize <= int(dynAddr+dynSize); off += elf64DynSize {
		tag := int64(le.Uint64(data[off : off+8]))
		val := le.Uint64(data[off+8 : off+16])
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
		symcount = gnuHashSymCount(data, int(gh))
	}

	var secs []secDesc
	secs = append(secs, secDesc{name: ""}) // index 0 is always the NULL section

	strtabAddr, hasStrtab := get(dtStrtab)
	strsz, _ := get(dtStrsz)

	if gh, ok := get(dtGnuHash); ok {
		secs = append(secs, secDesc{name: ".gnu.hash", typ: shtGnuHash, flags: shfAlloc, addr: gh, linkName: ".dynsym", align: 8})
	}
	if h, ok := get(dtHash); ok {
		secs = append(secs, secDesc{name: ".hash", typ: shtHash, flags: shfAlloc, addr: h, linkName: ".dynsym", entsize: 4, align: 8})
	}
	if sym, ok := get(dtSymtab); ok {
		syment, ok2 := get(dtSyment)
		if !ok2 || syment == 0 {
			syment = elf64SymSize
		}
		d := secDesc{name: ".dynsym", typ: shtDynsym, flags: shfAlloc, addr: sym, linkName: ".dynstr", entsize: syment, align: 8}
		if symcount > 0 {
			d.size = uint64(symcount) * syment
			d.hasSize = true
		}
		d.info = uint32(countLocalSyms(data, int(sym), symcount))
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
		d := secDesc{name: ".gnu.version_d", typ: shtGnuVerdef, flags: shfAlloc, addr: vd, linkName: ".dynstr", align: 8}
		if cnt, ok2 := get(dtVerdefnum); ok2 {
			d.info = uint32(cnt)
		}
		secs = append(secs, d)
	}
	if vn, ok := get(dtVerneed); ok {
		d := secDesc{name: ".gnu.version_r", typ: shtGnuVerneed, flags: shfAlloc, addr: vn, linkName: ".dynstr", align: 8}
		if cnt, ok2 := get(dtVerneednum); ok2 {
			d.info = uint32(cnt)
		}
		secs = append(secs, d)
	}
	if rela, ok := get(dtRela); ok {
		relasz, _ := get(dtRelasz)
		d := secDesc{name: ".rela.dyn", typ: shtRela, flags: shfAlloc, addr: rela, linkName: ".dynsym", entsize: 0x18, align: 8}
		if relasz > 0 {
			d.size = relasz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if relr, ok := get(dtRelr); ok {
		relrsz, _ := get(dtRelrsz)
		d := secDesc{name: ".relr.dyn", typ: shtRelr, flags: shfAlloc, addr: relr, entsize: 8, align: 8}
		if relrsz > 0 {
			d.size = relrsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if jmp, ok := get(dtJmprel); ok {
		pltrelsz, _ := get(dtPltrelsz)
		d := secDesc{name: ".rela.plt", typ: shtRela, flags: shfAlloc | shfInfoLink, addr: jmp, linkName: ".dynsym", infoName: ".got.plt", entsize: 0x18, align: 8}
		if pltrelsz > 0 {
			d.size = pltrelsz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if ini, ok := get(dtInit); ok {
		secs = append(secs, secDesc{name: ".init", typ: shtProgbits, flags: shfAlloc | shfExec, addr: ini, align: 4})
	}
	// .plt starts right after .rela.plt; its exact size is arch-dependent, so
	// the neighbor-based pass finalizes it from the next section's start.
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
		secs = append(secs, secDesc{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: textStart + 0x40, align: 8})
	}
	if ia, ok := get(dtInitArray); ok {
		iasz, _ := get(dtInitArraySz)
		d := secDesc{name: ".init_array", typ: shtInitArray, flags: shfWrite | shfAlloc, addr: ia, entsize: 8, align: 8}
		if iasz > 0 {
			d.size = iasz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	if fa, ok := get(dtFiniArray); ok {
		fasz, _ := get(dtFiniArraySz)
		d := secDesc{name: ".fini_array", typ: shtFiniArray, flags: shfWrite | shfAlloc, addr: fa, entsize: 8, align: 8}
		if fasz > 0 {
			d.size = fasz
			d.hasSize = true
		}
		secs = append(secs, d)
	}
	secs = append(secs, secDesc{name: ".dynamic", typ: shtDynamic, flags: shfWrite | shfAlloc, addr: dynAddr, size: dynSize, hasSize: true, linkName: ".dynstr", entsize: 0x10, align: 8})
	// .got.plt (DT_PLTGOT): standard layout is 3 reserved GOT slots followed by
	// one slot per PLT relocation, so its size is (3 + pltRelCount) * 8.
	var gotPltEnd uint64
	if got, ok := get(dtPltgot); ok {
		d := secDesc{name: ".got.plt", typ: shtProgbits, flags: shfWrite | shfAlloc, addr: got, entsize: 8, align: 8}
		if pltrelsz, ok2 := get(dtPltrelsz); ok2 && pltrelsz > 0 {
			d.size = (3 + pltrelsz/0x18) * 8
			d.hasSize = true
			gotPltEnd = got + d.size
		}
		secs = append(secs, d)
	}
	if gotPltEnd > 0 && gotPltEnd < loadFileEnd {
		secs = append(secs, secDesc{name: ".data", typ: shtProgbits, flags: shfWrite | shfAlloc, addr: gotPltEnd, align: 8})
	}
	if maxVaddr > loadFileEnd {
		secs = append(secs, secDesc{name: ".bss", typ: shtNobits, flags: shfWrite | shfAlloc, addr: loadFileEnd, size: maxVaddr - loadFileEnd, hasSize: true, align: 8})
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

	// Reassemble: NULL + sorted allocatable sections + .shstrtab.
	secs = append([]secDesc{secs[0]}, body...)
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
		remapSymShndx(data, int(symAddr), symcount, secs)
	}

	// Lay out appended data at end of file: [.shstrtab][shdr table].
	shstrtabOff := uint64(len(data))
	data = append(data, shstrtab...)
	for len(data)%8 != 0 { // align shdr table
		data = append(data, 0)
	}
	shoff := uint64(len(data))

	shtable := make([]byte, len(secs)*elf64ShdrSize)
	for i, s := range secs {
		b := shtable[i*elf64ShdrSize : (i+1)*elf64ShdrSize]
		var shName uint32
		if s.name != "" {
			shName = nameOff[s.name]
		}
		var shOffset, shAddr, shSize uint64 = 0, 0, s.size
		switch s.name {
		case "":
			// NULL section: all zero
		case ".shstrtab":
			shOffset = shstrtabOff
			shSize = uint64(len(shstrtab))
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
		le.PutUint32(b[0:4], shName)
		le.PutUint32(b[4:8], s.typ)
		le.PutUint64(b[8:16], s.flags)
		le.PutUint64(b[16:24], shAddr)
		le.PutUint64(b[24:32], shOffset)
		le.PutUint64(b[32:40], shSize)
		le.PutUint32(b[40:44], link)
		le.PutUint32(b[44:48], info)
		le.PutUint64(b[48:56], s.align)
		le.PutUint64(b[56:64], s.entsize)
	}
	data = append(data, shtable...)

	// Patch the ELF header to point at the rebuilt table.
	le.PutUint64(data[40:48], shoff)
	le.PutUint16(data[58:60], elf64ShdrSize)
	le.PutUint16(data[60:62], uint16(len(secs)))
	le.PutUint16(data[62:64], uint16(shstrtabIdx))

	return data, nil
}

// remapSymShndx rewrites each defined .dynsym entry's st_shndx to the rebuilt
// allocatable section whose address range contains the symbol's value. UND (0)
// and reserved (>=0xff00, e.g. SHN_ABS) entries are left untouched.
func remapSymShndx(data []byte, off, count int, secs []secDesc) {
	for i := 0; i < count; i++ {
		o := off + i*elf64SymSize
		if o+elf64SymSize > len(data) {
			break
		}
		shndx := le.Uint16(data[o+6 : o+8])
		if shndx == 0 || shndx >= 0xff00 {
			continue
		}
		value := le.Uint64(data[o+8 : o+16])
		for si, s := range secs {
			if s.flags&shfAlloc == 0 || s.size == 0 {
				continue
			}
			if value >= s.addr && value < s.addr+s.size {
				le.PutUint16(data[o+6:o+8], uint16(si))
				break
			}
		}
	}
}

// gnuHashSymCount derives the dynamic symbol count from a DT_GNU_HASH table,
// which (unlike DT_HASH) has no explicit symbol count: walk the hash chain of
// the highest-indexed bucket until its terminator bit is set.
func gnuHashSymCount(data []byte, off int) int {
	if off+16 > len(data) {
		return 0
	}
	nbuckets := int(le.Uint32(data[off : off+4]))
	symoffset := int(le.Uint32(data[off+4 : off+8]))
	bloomSize := int(le.Uint32(data[off+8 : off+12]))
	if nbuckets == 0 {
		return symoffset
	}
	bucketsOff := off + 16 + bloomSize*8
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
func countLocalSyms(data []byte, off, count int) int {
	if count <= 0 {
		return 1
	}
	locals := 0
	for i := 0; i < count; i++ {
		o := off + i*elf64SymSize
		if o+elf64SymSize > len(data) {
			break
		}
		if data[o+4]>>4 == 0 { // STB_LOCAL
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
