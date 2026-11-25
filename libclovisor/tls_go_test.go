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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const goTLSProg = `package main

import (
	"crypto/tls"
	"os"
)

func main() {
	c, err := tls.Dial("tcp", os.Args[1], nil)
	if err == nil {
		c.Write([]byte("x"))
		c.Read(make([]byte, 1))
	}
}
`

// buildGo builds src for goarch, stripped (-s -w) or not.
func buildGo(t *testing.T, src, goarch string, strip bool) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds Go binaries")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module p\n\ngo 1.21\n"), 0o644)
	out := filepath.Join(dir, "bin")
	args := []string{"build", "-o", out}
	if strip {
		args = append(args, "-ldflags=-s -w")
	}
	cmd := exec.Command("go", append(args, ".")...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func analyzeFile(t *testing.T, path string) *goTLSBinary {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return analyzeGoTLS(f)
}

// objdumpRets lists, by go tool objdump, the return instructions of fn
// as offsets from its first instruction.
func objdumpRets(t *testing.T, bin, fn string) []uint64 {
	t.Helper()
	out, err := exec.Command("go", "tool", "objdump", "-s", "^"+regexp.QuoteMeta(fn)+"$", bin).Output()
	if err != nil {
		t.Fatalf("objdump: %v", err)
	}
	var start uint64
	var rets []uint64
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || !strings.HasPrefix(f[1], "0x") {
			continue
		}
		a, _ := strconv.ParseUint(f[1][2:], 16, 64)
		if start == 0 {
			start = a
		}
		if f[3] == "RET" || (len(f) > 4 && f[4] == "RET") {
			rets = append(rets, a-start)
		}
	}
	return rets
}

// Write and Read are found, with their return instructions where go tool
// objdump puts them, on both architectures, stripped or not: -s leaves
// Go's function table.
func TestGoTLSAnalyze(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		plain := buildGo(t, goTLSProg, arch, false)
		b := analyzeFile(t, plain)
		if !b.Probed() || b.Go != runtime.Version() {
			t.Fatalf("%s: %+v", arch, b)
		}
		for _, fn := range []struct {
			name string
			got  goTLSFunc
		}{{goTLSWrite, b.Write}, {goTLSRead, b.Read}} {
			want := objdumpRets(t, plain, fn.name)
			if len(want) == 0 || !equalU64(fn.got.Rets, want) {
				t.Errorf("%s %s: returns %v, objdump %v", arch, fn.name, fn.got.Rets, want)
			}
		}
		// The entry is a file offset: the function's bytes are there.
		f, _ := elf.Open(plain)
		syms, _ := f.Symbols()
		for _, s := range syms {
			if s.Name == goTLSWrite {
				for _, p := range f.Progs {
					if p.Type == elf.PT_LOAD && s.Value >= p.Vaddr && s.Value < p.Vaddr+p.Filesz {
						if want := s.Value - p.Vaddr + p.Off; b.Write.Entry != want {
							t.Errorf("%s: entry %#x, want %#x", arch, b.Write.Entry, want)
						}
					}
				}
			}
		}
		f.Close()

		stripped := analyzeFile(t, buildGo(t, goTLSProg, arch, true))
		if !stripped.Probed() || stripped.Write.Entry != b.Write.Entry || !equalU64(stripped.Read.Rets, b.Read.Rets) {
			t.Errorf("%s stripped: %+v, unstripped %+v", arch, stripped, b)
		}
	}
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A Go binary without crypto/tls has nothing to miss; one of a Go version
// not tested is not visible, and says why; a file that is not Go is not
// reported.
func TestGoTLSNotProbed(t *testing.T) {
	plain := analyzeFile(t, buildGo(t, "package main\n\nfunc main() { println(1) }\n", runtime.GOARCH, false))
	if plain.Go == "" || !plain.NoTLS || plain.Probed() {
		t.Errorf("no crypto/tls: %+v", plain)
	}

	bin := buildGo(t, goTLSProg, runtime.GOARCH, false)
	raw, _ := os.ReadFile(bin)
	v := runtime.Version()
	for _, tc := range []struct{ version, reason string }{
		{"go1.99", "Go newer than go1." + strconv.Itoa(goTLSMaxMinor)},
		{"go1.17", "Go older than go1." + strconv.Itoa(goTLSMinMinor)},
	} {
		// The same binary, its build info naming another version.
		fake := tc.version + "." + strings.Repeat("9", max(len(v)-len(tc.version)-1, 0))
		if len(fake) != len(v) || !bytes.Contains(raw, []byte(v)) {
			t.Fatalf("cannot rewrite %q as %q", v, fake)
		}
		b := analyzeGoTLS(bytes.NewReader(bytes.ReplaceAll(raw, []byte(v), []byte(fake))))
		if b.Probed() || !strings.Contains(b.Reason, tc.reason) {
			t.Errorf("%s: %+v", fake, b)
		}
	}

	if b := analyzeGoTLS(bytes.NewReader([]byte("#!/bin/sh\necho hi\n"))); b.Go != "" || b.Probed() {
		t.Errorf("a script: %+v", b)
	}
	for v, want := range map[string]int{"go1.26.8": 26, "go1.21": 21, "go1.27rc1": 27, "go1.25.3 X:jsonv2": 25} {
		if n, ok := goMinor(v); !ok || n != want {
			t.Errorf("goMinor(%q) = %d %v", v, n, ok)
		}
	}
	if _, ok := goMinor("devel +abc"); ok {
		t.Error("devel parsed")
	}
}

// amd64 returns are found by decoding, not by their byte: 0xc3 inside
// another instruction is not a return.
func TestGoReturnsAMD64(t *testing.T) {
	code := []byte{
		0x48, 0xc7, 0xc0, 0xc3, 0x00, 0x00, 0x00, // mov rax, 0xc3
		0xc3,       // ret
		0xcc, 0xcc, // int3 padding
		0xc3, // ret
	}
	rets, err := goReturns(elf.EM_X86_64, code)
	if err != nil || !equalU64(rets, []uint64{7, 10}) {
		t.Errorf("rets %v err %v", rets, err)
	}
	arm := []byte{0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6} // nop; ret
	if rets, _ := goReturns(elf.EM_AARCH64, arm); !equalU64(rets, []uint64{4}) {
		t.Errorf("arm64 rets %v", rets)
	}
}
