// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// Go crypto/tls (milestone 6.3): where to probe a Go binary. Go links
// crypto/tls into each binary, so there is no library to probe: the node
// agent reads each exec'd binary's build info for its Go version, finds
// (*Conn).Write and (*Conn).Read by name, and lists their return
// instructions, where the return probes go (6.0: a uretprobe breaks on
// Go's movable stacks). Names come from the symbol table or, in a binary
// stripped with -s, from the function table Go keeps for tracebacks.

// Go versions probed. The probes read arguments from registers by Go's
// internal ABI, which Go does not promise to keep, so a newer Go is
// reported as not visible until it is tested.
const (
	goTLSMinMinor = 21
	goTLSMaxMinor = 26
)

// GoTLSVersions describes the Go versions whose crypto/tls is probed.
var GoTLSVersions = fmt.Sprintf("go1.%d to go1.%d", goTLSMinMinor, goTLSMaxMinor)

const (
	goTLSWrite = "crypto/tls.(*Conn).Write"
	goTLSRead  = "crypto/tls.(*Conn).Read"
)

// goTLSFunc is a function to probe: its entry as a file offset, and its
// return instructions as offsets from the entry.
type goTLSFunc struct {
	Entry uint64
	Rets  []uint64
}

// goTLSBinary is what analysis found in a binary.
type goTLSBinary struct {
	// Go is the binary's Go version; empty: not a Go binary.
	Go string
	// NoTLS: a Go binary without crypto/tls, so nothing to miss.
	NoTLS bool
	// Reason is why a Go binary that has crypto/tls cannot be probed;
	// empty: Write and Read are set.
	Reason      string
	Write, Read goTLSFunc
}

// Probed reports whether the binary's crypto/tls can be probed.
func (b *goTLSBinary) Probed() bool { return b.Go != "" && !b.NoTLS && b.Reason == "" }

// analyzeGoTLS reads a binary for Go crypto/tls. A file that is not ELF
// or not Go is reported as such (Go empty), not as an error.
func analyzeGoTLS(r io.ReaderAt) *goTLSBinary {
	f, err := elf.NewFile(r)
	if err != nil {
		return &goTLSBinary{}
	}
	defer f.Close()
	bi, err := buildinfo.Read(r)
	if err != nil {
		return &goTLSBinary{}
	}
	b := &goTLSBinary{Go: bi.GoVersion}
	write, read, err := goTLSFuncs(f)
	switch {
	case errors.Is(err, errNoGoTLS):
		b.NoTLS = true
		return b
	case err != nil:
		b.Reason = err.Error()
		return b
	}
	minor, ok := goMinor(bi.GoVersion)
	switch {
	case !ok:
		b.Reason = "unrecognised Go version " + strconv.Quote(bi.GoVersion)
		return b
	case minor < goTLSMinMinor:
		b.Reason = fmt.Sprintf("Go older than go1.%d", goTLSMinMinor)
		return b
	case minor > goTLSMaxMinor:
		b.Reason = fmt.Sprintf("Go newer than go1.%d, the last tested", goTLSMaxMinor)
		return b
	}
	for _, fn := range []struct {
		r   *goFuncRange
		out *goTLSFunc
	}{{write, &b.Write}, {read, &b.Read}} {
		gf, err := goTLSProbePoints(f, fn.r)
		if err != nil {
			b.Reason = err.Error()
			return b
		}
		*fn.out = gf
	}
	return b
}

var errNoGoTLS = errors.New("no crypto/tls")

// goMinor is the minor version of a "go1.N[.P]" version, also with a
// pre-release or experiment suffix (go1.26rc1, go1.25.3 X:...).
func goMinor(v string) (int, bool) {
	v, ok := strings.CutPrefix(v, "go1.")
	if !ok {
		return 0, false
	}
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	n, err := strconv.Atoi(v[:end])
	return n, err == nil
}

type goFuncRange struct {
	name       string
	start, end uint64 // virtual addresses
}

// goTLSFuncs finds Write and Read by name: in the symbol table, or else
// in the function table Go keeps for tracebacks, which -s leaves.
func goTLSFuncs(f *elf.File) (write, read *goFuncRange, err error) {
	switch f.Machine {
	case elf.EM_AARCH64, elf.EM_X86_64:
	default:
		return nil, nil, fmt.Errorf("Go on %v is not probed", f.Machine)
	}
	found := map[string]*goFuncRange{}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == goTLSWrite || s.Name == goTLSRead {
				found[s.Name] = &goFuncRange{s.Name, s.Value, s.Value + s.Size}
			}
		}
	}
	if len(found) < 2 {
		tab, err := goFuncTable(f)
		if err != nil {
			if len(found) == 0 {
				return nil, nil, err
			}
		} else {
			for _, name := range []string{goTLSWrite, goTLSRead} {
				if found[name] == nil {
					if fn := tab.LookupFunc(name); fn != nil {
						found[name] = &goFuncRange{name, fn.Entry, fn.End}
					}
				}
			}
		}
	}
	write, read = found[goTLSWrite], found[goTLSRead]
	if write == nil && read == nil {
		return nil, nil, errNoGoTLS
	}
	if write == nil || read == nil {
		return nil, nil, errors.New("crypto/tls without both (*Conn).Write and Read")
	}
	return write, read, nil
}

// goPclnMagic starts the function table of go1.20 and later: the magic,
// two zero bytes, then the instruction quantum and pointer size.
var goPclnMagic = map[elf.Machine][]byte{
	elf.EM_X86_64:  {0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8},
	elf.EM_AARCH64: {0xf1, 0xff, 0xff, 0xff, 0, 0, 4, 8},
}

// goFuncTable reads Go's function table: its section (.gopclntab, or
// .data.rel.ro.gopclntab in a PIE), or, where an external link left no
// section of its own, by its header in the read-only data.
func goFuncTable(f *elf.File) (*gosym.Table, error) {
	var data []byte
	for _, name := range []string{".gopclntab", ".data.rel.ro.gopclntab"} {
		if sec := f.Section(name); sec != nil && sec.Type != elf.SHT_NOBITS {
			d, err := sec.Data()
			if err != nil {
				return nil, fmt.Errorf("read the Go function table: %w", err)
			}
			data = d
			break
		}
	}
	if data == nil {
		magic := goPclnMagic[f.Machine]
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X != 0 || p.Filesz == 0 || p.Filesz > 1<<30 {
				continue
			}
			seg := make([]byte, p.Filesz)
			if _, err := p.ReadAt(seg, 0); err != nil {
				continue
			}
			for off := 0; ; {
				i := bytes.Index(seg[off:], magic)
				if i < 0 {
					break
				}
				// The table is pointer-aligned.
				if (off+i)%8 == 0 {
					data = seg[off+i:]
					break
				}
				off += i + 1
			}
			if data != nil {
				break
			}
		}
	}
	if len(data) < 32 {
		return nil, errors.New("no symbols and no Go function table")
	}
	// Where Go's text starts (runtime.text): the table's header says, but
	// in a PIE may leave it to a relocation; then the .text section's. An
	// external link puts C code first, so .text alone is not enough.
	text := binary.LittleEndian.Uint64(data[24:])
	if text == 0 {
		if sec := f.Section(".text"); sec != nil {
			text = sec.Addr
		}
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text))
	if err != nil {
		return nil, fmt.Errorf("parse the Go function table: %w", err)
	}
	return tab, nil
}

// goTLSProbePoints turns a function's range into a file offset and the
// offsets of its return instructions.
func goTLSProbePoints(f *elf.File, fn *goFuncRange) (goTLSFunc, error) {
	if fn.end <= fn.start || fn.end-fn.start > 1<<20 {
		return goTLSFunc{}, fmt.Errorf("%s: implausible size %d", fn.name, fn.end-fn.start)
	}
	var prog *elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && fn.start >= p.Vaddr && fn.end <= p.Vaddr+p.Filesz {
			prog = p
			break
		}
	}
	if prog == nil {
		return goTLSFunc{}, fmt.Errorf("%s: not in an executable segment", fn.name)
	}
	code := make([]byte, fn.end-fn.start)
	if _, err := prog.ReadAt(code, int64(fn.start-prog.Vaddr)); err != nil {
		return goTLSFunc{}, fmt.Errorf("%s: read: %w", fn.name, err)
	}
	if !goPrologue(f.Machine, code) {
		return goTLSFunc{}, fmt.Errorf("%s: no Go prologue where the function table puts it", fn.name)
	}
	rets, err := goReturns(f.Machine, code)
	if err != nil {
		return goTLSFunc{}, fmt.Errorf("%s: %w", fn.name, err)
	}
	if len(rets) == 0 {
		return goTLSFunc{}, fmt.Errorf("%s: no return instruction", fn.name)
	}
	return goTLSFunc{Entry: fn.start - prog.Vaddr + prog.Off, Rets: rets}, nil
}

// goPrologue checks that code starts as a Go function with a frame does:
// comparing the stack pointer with the goroutine's stack bound. Nothing
// is probed at an offset that does not, since on amd64 a probe inside an
// instruction would corrupt it.
func goPrologue(m elf.Machine, code []byte) bool {
	switch m {
	case elf.EM_AARCH64:
		for off := 0; off+4 <= len(code) && off < 12; off += 4 {
			if binary.LittleEndian.Uint32(code[off:]) == 0xf9400b90 { // ldr x16, [x28, #16]
				return true
			}
		}
	case elf.EM_X86_64:
		// cmp rsp, [r14+16], or for a large frame lea r12, [rsp-n] and
		// cmp r12, [r14+16].
		head := code[:min(len(code), 16)]
		return bytes.Contains(head, []byte{0x49, 0x3b, 0x66, 0x10}) || bytes.Contains(head, []byte{0x4d, 0x3b, 0x66, 0x10})
	}
	return false
}

// goReturns lists the offsets of a function's return instructions. arm64
// instructions are a fixed four bytes; amd64 code is decoded, since a
// return's byte (0xc3) also occurs inside other instructions, where a
// probe would corrupt them.
func goReturns(m elf.Machine, code []byte) ([]uint64, error) {
	var rets []uint64
	switch m {
	case elf.EM_AARCH64:
		for off := 0; off+4 <= len(code); off += 4 {
			if binary.LittleEndian.Uint32(code[off:]) == 0xd65f03c0 { // RET (x30)
				rets = append(rets, uint64(off))
			}
		}
	case elf.EM_X86_64:
		for off := 0; off < len(code); {
			inst, err := x86asm.Decode(code[off:], 64)
			if err != nil {
				// Go pads functions with INT3; anything else undecodable
				// leaves the instruction boundaries unknown.
				if code[off] == 0xcc {
					off++
					continue
				}
				return nil, fmt.Errorf("undecodable instruction at +%#x", off)
			}
			if inst.Op == x86asm.RET {
				rets = append(rets, uint64(off))
			}
			off += inst.Len
		}
	}
	return rets, nil
}
