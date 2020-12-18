// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Writing Go object files.

package obj

import (
	"bytes"
	"cmd/internal/bio"
	"cmd/internal/goobj"
	"cmd/internal/objabi"
	"fmt"
	"path/filepath"
	"strings"
)

// Entry point of writing new object file.
func WriteObjFile2(ctxt *Link, b *bio.Writer, pkgpath string) {

	debugAsmEmit(ctxt)

	genFuncInfoSyms(ctxt)

	w := writer{
		Writer:  goobj.NewWriter(b),
		ctxt:    ctxt,
		pkgpath: objabi.PathToPrefix(pkgpath),
	}

	start := b.Offset()
	w.init()

	// Header
	// We just reserve the space. We'll fill in the offsets later.
	flags := uint32(0)
	if ctxt.Flag_shared {
		flags |= goobj.ObjFlagShared
	}
	h := goobj.Header{
		Magic:       goobj.Magic,
		Fingerprint: ctxt.Fingerprint,
		Flags:       flags,
	}
	h.Write(w.Writer)

	// String table
	w.StringTable()

	// Autolib
	h.Offsets[goobj.BlkAutolib] = w.Offset()
	for i := range ctxt.Imports {
		ctxt.Imports[i].Write(w.Writer)
	}

	// Package references
	h.Offsets[goobj.BlkPkgIdx] = w.Offset()
	for _, pkg := range w.pkglist {
		w.StringRef(pkg)
	}

	// DWARF file table
	h.Offsets[goobj.BlkDwarfFile] = w.Offset()
	for _, f := range ctxt.PosTable.DebugLinesFileTable() {
		w.StringRef(filepath.ToSlash(f))
	}

	// Symbol definitions
	h.Offsets[goobj.BlkSymdef] = w.Offset()
	for _, s := range ctxt.defs {
		w.Sym(s)
	}

	// Non-pkg symbol definitions
	h.Offsets[goobj.BlkNonpkgdef] = w.Offset()
	for _, s := range ctxt.nonpkgdefs {
		w.Sym(s)
	}

	// Non-pkg symbol references
	h.Offsets[goobj.BlkNonpkgref] = w.Offset()
	for _, s := range ctxt.nonpkgrefs {
		w.Sym(s)
	}

	// Reloc indexes
	h.Offsets[goobj.BlkRelocIdx] = w.Offset()
	nreloc := uint32(0)
	lists := [][]*LSym{ctxt.defs, ctxt.nonpkgdefs}
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(nreloc)
			nreloc += uint32(len(s.R))
		}
	}
	w.Uint32(nreloc)

	// Symbol Info indexes
	h.Offsets[goobj.BlkAuxIdx] = w.Offset()
	naux := uint32(0)
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(naux)
			naux += uint32(nAuxSym(s))
		}
	}
	w.Uint32(naux)

	// Data indexes
	h.Offsets[goobj.BlkDataIdx] = w.Offset()
	dataOff := uint32(0)
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(dataOff)
			dataOff += uint32(len(s.P))
		}
	}
	w.Uint32(dataOff)

	// Relocs
	h.Offsets[goobj.BlkReloc] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			for i := range s.R {
				w.Reloc(&s.R[i])
			}
		}
	}

	// Aux symbol info
	h.Offsets[goobj.BlkAux] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			w.Aux(s)
		}
	}

	// Data
	h.Offsets[goobj.BlkData] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			w.Bytes(s.P)
		}
	}

	// Pcdata
	h.Offsets[goobj.BlkPcdata] = w.Offset()
	for _, s := range ctxt.Text { // iteration order must match genFuncInfoSyms
		if s.Func != nil {
			pc := &s.Func.Pcln
			w.Bytes(pc.Pcsp.P)
			w.Bytes(pc.Pcfile.P)
			w.Bytes(pc.Pcline.P)
			w.Bytes(pc.Pcinline.P)
			for i := range pc.Pcdata {
				w.Bytes(pc.Pcdata[i].P)
			}
		}
	}

	// Fix up block offsets in the header
	end := start + int64(w.Offset())
	b.MustSeek(start, 0)
	h.Write(w.Writer)
	b.MustSeek(end, 0)
}

type writer struct {
	*goobj.Writer
	ctxt    *Link
	pkgpath string   // the package import path (escaped), "" if unknown
	pkglist []string // list of packages referenced, indexed by ctxt.pkgIdx
}

// prepare package index list
func (w *writer) init() {
	w.pkglist = make([]string, len(w.ctxt.pkgIdx)+1)
	w.pkglist[0] = "" // dummy invalid package for index 0
	for pkg, i := range w.ctxt.pkgIdx {
		w.pkglist[i] = pkg
	}
}

func (w *writer) StringTable() {
	w.AddString("")
	for _, p := range w.ctxt.Imports {
		w.AddString(p.Pkg)
	}
	for _, pkg := range w.pkglist {
		w.AddString(pkg)
	}
	w.ctxt.traverseSyms(traverseAll, func(s *LSym) {
		if w.pkgpath != "" {
			s.Name = strings.Replace(s.Name, "\"\".", w.pkgpath+".", -1)
		}
		w.AddString(s.Name)
	})
	w.ctxt.traverseSyms(traverseDefs, func(s *LSym) {
		if s.Type != objabi.STEXT {
			return
		}
		pc := &s.Func.Pcln
		for _, f := range pc.File {
			w.AddString(filepath.ToSlash(f))
		}
		for _, call := range pc.InlTree.nodes {
			f, _ := linkgetlineFromPos(w.ctxt, call.Pos)
			w.AddString(filepath.ToSlash(f))
		}
	})
	for _, f := range w.ctxt.PosTable.DebugLinesFileTable() {
		w.AddString(filepath.ToSlash(f))
	}
}

func (w *writer) Sym(s *LSym) {
	abi := uint16(s.ABI())
	if s.Static() {
		abi = goobj.SymABIstatic
	}
	flag := uint8(0)
	if s.DuplicateOK() {
		flag |= goobj.SymFlagDupok
	}
	if s.Local() {
		flag |= goobj.SymFlagLocal
	}
	if s.MakeTypelink() {
		flag |= goobj.SymFlagTypelink
	}
	if s.Leaf() {
		flag |= goobj.SymFlagLeaf
	}
	if s.NoSplit() {
		flag |= goobj.SymFlagNoSplit
	}
	if s.ReflectMethod() {
		flag |= goobj.SymFlagReflectMethod
	}
	if s.TopFrame() {
		flag |= goobj.SymFlagTopFrame
	}
	if strings.HasPrefix(s.Name, "type.") && s.Name[5] != '.' && s.Type == objabi.SRODATA {
		flag |= goobj.SymFlagGoType
	}
	name := s.Name
	if strings.HasPrefix(name, "gofile..") {
		name = filepath.ToSlash(name)
	}
	var align uint32
	if s.Func != nil {
		align = uint32(s.Func.Align)
	}
	var o goobj.Sym
	o.SetName(name, w.Writer)
	o.SetABI(abi)
	o.SetType(uint8(s.Type))
	o.SetFlag(flag)
	o.SetSiz(uint32(s.Size))
	o.SetAlign(align)
	o.Write(w.Writer)
}

func makeSymRef(s *LSym) goobj.SymRef {
	if s == nil {
		return goobj.SymRef{}
	}
	if s.PkgIdx == 0 || !s.Indexed() {
		fmt.Printf("unindexed symbol reference: %v\n", s)
		panic("unindexed symbol reference")
	}
	return goobj.SymRef{PkgIdx: uint32(s.PkgIdx), SymIdx: uint32(s.SymIdx)}
}

func (w *writer) Reloc(r *Reloc) {
	var o goobj.Reloc
	o.SetOff(r.Off)
	o.SetSiz(r.Siz)
	o.SetType(uint8(r.Type))
	o.SetAdd(r.Add)
	o.SetSym(makeSymRef(r.Sym))
	o.Write(w.Writer)
}

func (w *writer) aux1(typ uint8, rs *LSym) {
	var o goobj.Aux
	o.SetType(typ)
	o.SetSym(makeSymRef(rs))
	o.Write(w.Writer)
}

func (w *writer) Aux(s *LSym) {
	if s.Gotype != nil {
		w.aux1(goobj.AuxGotype, s.Gotype)
	}
	if s.Func != nil {
		w.aux1(goobj.AuxFuncInfo, s.Func.FuncInfoSym)

		for _, d := range s.Func.Pcln.Funcdata {
			w.aux1(goobj.AuxFuncdata, d)
		}

		if s.Func.dwarfInfoSym != nil && s.Func.dwarfInfoSym.Size != 0 {
			w.aux1(goobj.AuxDwarfInfo, s.Func.dwarfInfoSym)
		}
		if s.Func.dwarfLocSym != nil && s.Func.dwarfLocSym.Size != 0 {
			w.aux1(goobj.AuxDwarfLoc, s.Func.dwarfLocSym)
		}
		if s.Func.dwarfRangesSym != nil && s.Func.dwarfRangesSym.Size != 0 {
			w.aux1(goobj.AuxDwarfRanges, s.Func.dwarfRangesSym)
		}
		if s.Func.dwarfDebugLinesSym != nil && s.Func.dwarfDebugLinesSym.Size != 0 {
			w.aux1(goobj.AuxDwarfLines, s.Func.dwarfDebugLinesSym)
		}
	}
}

// return the number of aux symbols s have.
func nAuxSym(s *LSym) int {
	n := 0
	if s.Gotype != nil {
		n++
	}
	if s.Func != nil {
		// FuncInfo is an aux symbol, each Funcdata is an aux symbol
		n += 1 + len(s.Func.Pcln.Funcdata)
		if s.Func.dwarfInfoSym != nil && s.Func.dwarfInfoSym.Size != 0 {
			n++
		}
		if s.Func.dwarfLocSym != nil && s.Func.dwarfLocSym.Size != 0 {
			n++
		}
		if s.Func.dwarfRangesSym != nil && s.Func.dwarfRangesSym.Size != 0 {
			n++
		}
		if s.Func.dwarfDebugLinesSym != nil && s.Func.dwarfDebugLinesSym.Size != 0 {
			n++
		}
	}
	return n
}

// generate symbols for FuncInfo.
func genFuncInfoSyms(ctxt *Link) {
	infosyms := make([]*LSym, 0, len(ctxt.Text))
	var pcdataoff uint32
	var b bytes.Buffer
	symidx := int32(len(ctxt.defs))
	for _, s := range ctxt.Text {
		if s.Func == nil {
			continue
		}
		o := goobj.FuncInfo{
			Args:   uint32(s.Func.Args),
			Locals: uint32(s.Func.Locals),
		}
		pc := &s.Func.Pcln
		o.Pcsp = pcdataoff
		pcdataoff += uint32(len(pc.Pcsp.P))
		o.Pcfile = pcdataoff
		pcdataoff += uint32(len(pc.Pcfile.P))
		o.Pcline = pcdataoff
		pcdataoff += uint32(len(pc.Pcline.P))
		o.Pcinline = pcdataoff
		pcdataoff += uint32(len(pc.Pcinline.P))
		o.Pcdata = make([]uint32, len(pc.Pcdata))
		for i, pcd := range pc.Pcdata {
			o.Pcdata[i] = pcdataoff
			pcdataoff += uint32(len(pcd.P))
		}
		o.PcdataEnd = pcdataoff
		o.Funcdataoff = make([]uint32, len(pc.Funcdataoff))
		for i, x := range pc.Funcdataoff {
			o.Funcdataoff[i] = uint32(x)
		}
		o.File = make([]goobj.SymRef, len(pc.File))
		for i, f := range pc.File {
			fsym := ctxt.Lookup(f)
			o.File[i] = makeSymRef(fsym)
		}
		o.InlTree = make([]goobj.InlTreeNode, len(pc.InlTree.nodes))
		for i, inl := range pc.InlTree.nodes {
			f, l := linkgetlineFromPos(ctxt, inl.Pos)
			fsym := ctxt.Lookup(f)
			o.InlTree[i] = goobj.InlTreeNode{
				Parent:   int32(inl.Parent),
				File:     makeSymRef(fsym),
				Line:     l,
				Func:     makeSymRef(inl.Func),
				ParentPC: inl.ParentPC,
			}
		}

		o.Write(&b)
		isym := &LSym{
			Type:   objabi.SDATA, // for now, I don't think it matters
			PkgIdx: goobj.PkgIdxSelf,
			SymIdx: symidx,
			P:      append([]byte(nil), b.Bytes()...),
		}
		isym.Set(AttrIndexed, true)
		symidx++
		infosyms = append(infosyms, isym)
		s.Func.FuncInfoSym = isym
		b.Reset()

		dwsyms := []*LSym{s.Func.dwarfRangesSym, s.Func.dwarfLocSym, s.Func.dwarfDebugLinesSym, s.Func.dwarfInfoSym}
		for _, s := range dwsyms {
			if s == nil || s.Size == 0 {
				continue
			}
			s.PkgIdx = goobj.PkgIdxSelf
			s.SymIdx = symidx
			s.Set(AttrIndexed, true)
			symidx++
			infosyms = append(infosyms, s)
		}
	}
	ctxt.defs = append(ctxt.defs, infosyms...)
}

// debugDumpAux is a dumper for selected aux symbols.
func writeAuxSymDebug(ctxt *Link, par *LSym, aux *LSym) {
	// Most aux symbols (ex: funcdata) are not interesting--
	// pick out just the DWARF ones for now.
	if aux.Type != objabi.SDWARFLOC &&
		aux.Type != objabi.SDWARFINFO &&
		aux.Type != objabi.SDWARFLINES &&
		aux.Type != objabi.SDWARFRANGE {
		return
	}
	ctxt.writeSymDebugNamed(aux, "aux for "+par.Name)
}

func debugAsmEmit(ctxt *Link) {
	if ctxt.Debugasm > 0 {
		ctxt.traverseSyms(traverseDefs, ctxt.writeSymDebug)
		if ctxt.Debugasm > 1 {
			fn := func(par *LSym, aux *LSym) {
				writeAuxSymDebug(ctxt, par, aux)
			}
			ctxt.traverseAuxSyms(traverseAux, fn)
		}
	}
}
