// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"debug/elf"
	"regexp"
	"strings"
)

// Bundled TLS stacks (milestone 6.4): a TLS library linked into the
// binary rather than loaded as a shared library, so the library probes do
// not see it. Official Node builds link OpenSSL in and export its
// functions, so the same probes go on the binary. Bun links BoringSSL in
// without symbols, and rustls has none to keep: those are reported as not
// visible.

// bundledTLS is what a binary showed of a TLS stack linked into it.
type bundledTLS struct {
	// Stack names it: "OpenSSL 3.5.9, bundled", "Bun's BoringSSL",
	// "rustls 0.23.46".
	Stack string
	// Lib labels its records ("OpenSSL 3.5.9").
	Lib string
	// Reason is why it cannot be probed; empty: Syms holds the file
	// offsets of the OpenSSL functions to probe.
	Reason string
	Syms   map[string]uint64
}

// sslProbeSyms are the OpenSSL (and BoringSSL) functions the library
// probes attach to.
var sslProbeSyms = []string{"SSL_write", "SSL_write_ex", "SSL_read", "SSL_read_ex"}

var (
	opensslBanner = regexp.MustCompile(`^OpenSSL (\d+\.\d+\.\d+[a-z]?)(?:[+-][\w.]+)? +\d{1,2} [A-Z][a-z]{2} \d{4}`)
	rustlsPath    = regexp.MustCompile(`^/rustls-(\d+\.\d+\.\d+)/`)
)

// analyzeBundled looks for a TLS stack linked into f. It returns nil for a
// binary that loads its TLS library (the library probes see it) or shows
// none.
func analyzeBundled(f *elf.File) *bundledTLS {
	if libs, err := f.ImportedLibraries(); err == nil {
		for _, l := range libs {
			if strings.HasPrefix(l, "libssl.") || strings.HasPrefix(l, "libgnutls.") {
				return nil
			}
		}
	}
	syms := definedSSLSyms(f)
	banner, boring, rustls := tlsMarkers(f)
	switch {
	case syms["SSL_write"] != 0 && syms["SSL_read"] != 0:
		lib := "OpenSSL"
		if banner != "" {
			lib = "OpenSSL " + banner
		} else if boring {
			lib = "BoringSSL"
		}
		return &bundledTLS{Stack: lib + ", bundled", Lib: lib, Syms: syms}
	case f.Section(".bun") != nil:
		return &bundledTLS{Stack: "Bun's BoringSSL", Reason: "Bun links BoringSSL in without its symbols"}
	case rustls != "":
		return &bundledTLS{Stack: "rustls " + rustls, Reason: "rustls has no stable symbols to probe"}
	case banner != "":
		return &bundledTLS{Stack: "OpenSSL " + banner + ", linked in", Reason: "linked in without its symbols"}
	case boring:
		return &bundledTLS{Stack: "BoringSSL, linked in", Reason: "linked in without its symbols"}
	}
	return nil
}

// definedSSLSyms finds the OpenSSL functions the binary defines, as file
// offsets.
func definedSSLSyms(f *elf.File) map[string]uint64 {
	want := map[string]bool{}
	for _, s := range sslProbeSyms {
		want[s] = true
	}
	out := map[string]uint64{}
	for _, get := range []func() ([]elf.Symbol, error){f.DynamicSymbols, f.Symbols} {
		syms, err := get()
		if err != nil {
			continue
		}
		for _, s := range syms {
			if !want[s.Name] || out[s.Name] != 0 || s.Section == elf.SHN_UNDEF || s.Value == 0 ||
				elf.ST_TYPE(s.Info) != elf.STT_FUNC {
				continue
			}
			if off, ok := fileOffset(f, s.Value); ok {
				out[s.Name] = off
			}
		}
	}
	return out
}

// fileOffset maps a virtual address in an executable segment to its
// offset in the file.
func fileOffset(f *elf.File, addr uint64) (uint64, bool) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && addr >= p.Vaddr && addr < p.Vaddr+p.Filesz {
			return addr - p.Vaddr + p.Off, true
		}
	}
	return 0, false
}

// maxMarkerScan bounds the read-only data searched for TLS markers.
const maxMarkerScan = 256 << 20

// tlsMarkers searches the read-only data for an OpenSSL version banner
// ("OpenSSL 3.5.9 29 Sep 2026", which libcrypto carries), BoringSSL's
// name, and rustls's crate path, which Rust keeps in panic locations.
func tlsMarkers(f *elf.File) (banner string, boring bool, rustls string) {
	sec := f.Section(".rodata")
	if sec == nil || sec.Type == elf.SHT_NOBITS || sec.Size > maxMarkerScan {
		return "", false, ""
	}
	data, err := sec.Data()
	if err != nil {
		return "", false, ""
	}
	return markersIn(data)
}

func markersIn(data []byte) (banner string, boring bool, rustls string) {
	boring = bytes.Contains(data, []byte("BoringSSL"))
	for off := 0; banner == ""; {
		i := bytes.Index(data[off:], []byte("OpenSSL "))
		if i < 0 {
			break
		}
		off += i
		if m := opensslBanner.FindSubmatch(data[off:min(len(data), off+64)]); m != nil {
			banner = string(m[1])
		}
		off += len("OpenSSL ")
	}
	for off := 0; rustls == ""; {
		i := bytes.Index(data[off:], []byte("/rustls-"))
		if i < 0 {
			break
		}
		off += i
		if m := rustlsPath.FindSubmatch(data[off:min(len(data), off+32)]); m != nil {
			rustls = string(m[1])
		}
		off += len("/rustls-")
	}
	return banner, boring, rustls
}
