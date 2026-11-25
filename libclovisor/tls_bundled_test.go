// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildC compiles src into a binary, with extra flags.
func buildC(t *testing.T, src string, flags ...string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds C binaries")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.c"), []byte(src), 0o644)
	out := filepath.Join(dir, "bin")
	cmd := exec.Command(cc, append([]string{"-O0", "-o", out, filepath.Join(dir, "main.c")}, flags...)...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cc: %v\n%s", err, b)
	}
	return out
}

func bundledOf(t *testing.T, path string) *bundledTLS {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return analyzeBundled(f)
}

// A binary that defines and exports OpenSSL's functions, as official Node
// builds do, is probed at them, labelled by its version banner; Bun's
// section, rustls's crate path and a banner without symbols are reported
// as not visible; a binary that loads libssl, or shows no stack, is left
// to the library probes.
func TestBundledTLS(t *testing.T) {
	const fns = `
int SSL_write(void *s, const void *b, int n) { return n; }
int SSL_read(void *s, void *b, int n) { return n; }
int SSL_write_ex(void *s, const void *b, unsigned long n, unsigned long *w) { *w = n; return 1; }
`
	const banner = `const char *v = "OpenSSL 3.5.9 29 Sep 2026";
const char *other = "BoringSSL";
`
	node := buildC(t, fns+banner+`int main(void) { return v[0] + other[0]; }`, "-rdynamic")
	b := bundledOf(t, node)
	if b == nil || b.Stack != "OpenSSL 3.5.9, bundled" || b.Lib != "OpenSSL 3.5.9" || b.Reason != "" {
		t.Fatalf("bundled OpenSSL: %+v", b)
	}
	f, _ := elf.Open(node)
	syms, _ := f.DynamicSymbols()
	for _, s := range syms {
		if s.Name == "SSL_write" {
			if want, _ := fileOffset(f, s.Value); b.Syms["SSL_write"] != want || want == 0 {
				t.Errorf("SSL_write at %#x, want %#x", b.Syms["SSL_write"], want)
			}
		}
	}
	f.Close()
	if b.Syms["SSL_read_ex"] != 0 || b.Syms["SSL_write_ex"] == 0 {
		t.Errorf("syms: %v", b.Syms)
	}

	for _, tc := range []struct {
		name, src, stack, reason string
		flags                    []string
	}{
		{"bun", `__attribute__((section(".bun"), used)) static const long bun = 1; const char *b = "BoringSSL"; int main(void) { return b[0]; }`,
			"Bun's BoringSSL", "Bun links BoringSSL in without its symbols", nil},
		{"rustls", `const char *p = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.46/src/conn.rs"; int main(void) { return p[0]; }`,
			"rustls 0.23.46", "rustls has no stable symbols to probe", nil},
		{"static", banner + `int main(void) { return v[0]; }`, "OpenSSL 3.5.9, linked in", "linked in without its symbols", nil},
		{"undefined", `int SSL_write(void *s, const void *b, int n); int main(int c, char **v) { return c > 5 ? SSL_write(0, 0, 0) : 0; }`,
			"", "", []string{"-Wl,--unresolved-symbols=ignore-all"}},
		{"plain", `const char *s = "uses OpenSSL 3 and talks about BoringSL"; int main(void) { return s[0]; }`, "", "", nil},
	} {
		b := bundledOf(t, buildC(t, tc.src, tc.flags...))
		switch {
		case tc.stack == "" && b != nil:
			t.Errorf("%s: %+v", tc.name, b)
		case tc.stack != "" && (b == nil || b.Stack != tc.stack || b.Reason != tc.reason):
			t.Errorf("%s: %+v", tc.name, b)
		}
	}

	// One that loads libssl, even with a banner, is the library probes'.
	if m, _ := filepath.Glob("/usr/lib/*/libssl.so"); len(m) > 0 {
		if b := bundledOf(t, buildC(t, fns+banner+`int main(void) { return v[0]; }`, "-rdynamic", "-Wl,--no-as-needed", "-lssl")); b != nil {
			t.Errorf("loads libssl: %+v", b)
		}
	}
}

func TestTLSMarkers(t *testing.T) {
	for in, want := range map[string]string{
		"OpenSSL 3.5.9 29 Sep 2026":          "3.5.9",
		"xxOpenSSL 1.1.1w  11 Sep 2023\x00":  "1.1.1w",
		"OpenSSL 3.0.13+quic 30 Jan 2024":    "3.0.13",
		"OpenSSL 3 is great; OpenSSL 3.1.2 ": "",
	} {
		if got, _, _ := markersIn([]byte(in)); got != want {
			t.Errorf("%q: banner %q, want %q", in, got, want)
		}
	}
	if _, _, r := markersIn([]byte("x/tokio-rustls-0.26.6/src/a.rs\x00/rustls-0.23.46/src/b.rs")); r != "0.23.46" {
		t.Errorf("rustls %q", r)
	}
}
