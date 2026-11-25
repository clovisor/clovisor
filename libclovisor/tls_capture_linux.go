// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package clovisor

import (
	"debug/elf"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// TLS capture (milestone 6.2): uprobes attached to each process of a run
// whose profile asks for TLS plaintext, on the TLS libraries found on the
// node. The kernel stops each such process at exec until its probes are
// in place (on_tls_exec); the watchdog continues any held longer than
// tlsHoldMax, so a lost event cannot leave one stopped.

const (
	tlsHoldMax  = time.Second
	tlsWatchdog = 250 * time.Millisecond
)

type bpfTLSObjects struct {
	Exec     *ebpf.Program `ebpf:"on_tls_exec"`
	Exit     *ebpf.Program `ebpf:"on_tls_exit"`
	CEntry   *ebpf.Program `ebpf:"tls_c_entry"`
	CReturn  *ebpf.Program `ebpf:"tls_c_return"`
	GoEntry  *ebpf.Program `ebpf:"tls_go_entry"`
	GoReturn *ebpf.Program `ebpf:"tls_go_ret"`
	Capture  *ebpf.Map     `ebpf:"tls_capture"`
	Held     *ebpf.Map     `ebpf:"tls_held"`
	Pids     *ebpf.Map     `ebpf:"tls_pids"`
}

func (o *bpfTLSObjects) Close() {
	for _, c := range []interface{ Close() error }{o.Exec, o.Exit, o.CEntry, o.CReturn, o.GoEntry, o.GoReturn,
		o.Capture, o.Held, o.Pids} {
		if c != nil {
			c.Close()
		}
	}
}

// Library tags in the probes' cookies (agent_audit.c, tls_c_entry).
const (
	tlsLibSSL     = 1
	tlsLibGnuTLS  = 2
	tlsLibBundled = 4 // OpenSSL linked into the binary (milestone 6.4)
)

// tlsFunc is a C TLS function to probe: its direction, and whether its
// count is stored through its 4th argument (the _ex forms).
type tlsFunc struct {
	sym string
	dir uint64 // 1 write, 2 read
	ex  bool
}

var (
	sslFuncs = []tlsFunc{{"SSL_write", 1, false}, {"SSL_write_ex", 1, true}, {"SSL_read", 2, false}, {"SSL_read_ex", 2, true}}
	gnuFuncs = []tlsFunc{{"gnutls_record_send", 1, false}, {"gnutls_record_recv", 2, false}}
)

func tlsCookie(lib uint64, f tlsFunc) uint64 {
	c := lib | f.dir<<8
	if f.ex {
		c |= 1 << 16
	}
	return c
}

// tlsLib is a shared TLS library found on the node, with the functions it
// has.
type tlsLib struct {
	path  string
	ex    *link.Executable
	lib   uint64
	funcs []tlsFunc
}

type tlsCapture struct {
	objs  bpfTLSObjects
	links []link.Link // the exec and exit tracepoints
	libs  []tlsLib

	mu    sync.Mutex
	procs map[uint32]*tlsProc // by process
	// bins caches what analysis found in each binary, by file.
	bins map[exeKey]*tlsBinary
	// programs carries what each exec'd binary with a TLS stack of its own
	// showed (milestones 6.3 and 6.4) to the reader, which sends it on
	// with the events.
	programs chan AuditEvent
	done     chan struct{}
	wg       sync.WaitGroup
}

// tlsProc is one probed process: the library probes, which survive exec,
// and those on the TLS stack its binary carries, which an exec replaces.
type tlsProc struct {
	lib, own []link.Link
}

type exeKey struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

// maxBins bounds the binaries whose analysis is cached.
const maxBins = 1024

// DefaultTLSLibraries are where the TLS libraries are looked for, as the
// node agent sees the filesystem.
var DefaultTLSLibraries = func() []string {
	var out []string
	dirs := []string{"/usr/lib/" + multiarch(), "/lib/" + multiarch(), "/usr/lib64", "/lib64", "/usr/lib", "/usr/local/lib"}
	for _, d := range dirs {
		for _, n := range []string{"libssl.so.3", "libssl.so.1.1", "libgnutls.so.30"} {
			out = append(out, filepath.Join(d, n))
		}
	}
	return out
}

func multiarch() string {
	var u unix.Utsname
	unix.Uname(&u)
	m := unix.ByteSliceToString(u.Machine[:])
	switch m {
	case "x86_64":
		return "x86_64-linux-gnu"
	case "aarch64":
		return "aarch64-linux-gnu"
	}
	return m + "-linux-gnu"
}

func newTLSCapture(spec *ebpf.CollectionSpec, replace map[string]*ebpf.Map, candidates []string) (*tlsCapture, error) {
	c := &tlsCapture{procs: map[uint32]*tlsProc{}, bins: map[exeKey]*tlsBinary{},
		programs: make(chan AuditEvent, 1024), done: make(chan struct{})}
	if err := spec.LoadAndAssign(&c.objs, &ebpf.CollectionOptions{MapReplacements: replace}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load TLS capture programs: %+v", ve)
		}
		return nil, fmt.Errorf("load TLS capture programs: %w", err)
	}
	seen := map[uint64]bool{}
	for _, p := range candidates {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat(real, &st) != nil || seen[st.Ino] {
			continue
		}
		seen[st.Ino] = true
		ex, err := link.OpenExecutable(real)
		if err != nil {
			continue
		}
		lib := tlsLib{path: real, ex: ex, lib: tlsLibSSL}
		funcs := sslFuncs
		if filepath.Base(p) == "libgnutls.so.30" {
			lib.lib, funcs = tlsLibGnuTLS, gnuFuncs
		}
		// Only the functions this version has: a multi link fails whole.
		have := definedSyms(real)
		for _, f := range funcs {
			if have[f.sym] {
				lib.funcs = append(lib.funcs, f)
			}
		}
		if len(lib.funcs) == 0 {
			continue
		}
		c.libs = append(c.libs, lib)
	}
	if len(c.libs) == 0 {
		c.objs.Close()
		return nil, fmt.Errorf("no TLS library found (looked for %d paths)", len(candidates))
	}
	// Probes are attached as uprobe-multi links (kernel 6.6): one per
	// program and library, each detached with one wait on the kernel.
	if ls, err := c.attachC(c.libs[0].ex, c.libs[0].lib, c.libs[0].funcs, nil, uint32(os.Getpid())); err != nil {
		c.Close()
		if errors.Is(err, link.ErrNotSupported) {
			return nil, fmt.Errorf("TLS capture needs uprobe-multi links (Linux 6.6): %w", err)
		}
		return nil, fmt.Errorf("attach TLS probes: %w", err)
	} else {
		for _, l := range ls {
			l.Close()
		}
	}
	for _, p := range []*ebpf.Program{c.objs.Exec, c.objs.Exit} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach TLS tracepoint: %w", err)
		}
		c.links = append(c.links, l)
	}
	c.wg.Add(1)
	go c.watchdog()
	return c, nil
}

// Libraries are the TLS libraries probed.
func (c *tlsCapture) Libraries() []string {
	var out []string
	for _, l := range c.libs {
		out = append(out, l.path)
	}
	return out
}

// setRun turns capture on or off for a run (its policy run's cgroup).
func (c *tlsCapture) setRun(runCg uint64, on bool) error {
	if !on {
		c.objs.Capture.Delete(runCg)
		return nil
	}
	return c.objs.Capture.Put(runCg, uint8(1))
}

// onExec attaches the probes to a process that exec'd in a capturing
// run, then continues it if the kernel stopped it. ev is the exec, as an
// EventTLSProgram to fill in for a binary with a TLS stack of its own.
func (c *tlsCapture) onExec(ev AuditEvent, held bool) {
	pid := ev.PID
	defer func() {
		if held {
			c.objs.Held.Delete(pid)
			unix.Kill(int(pid), unix.SIGCONT)
		}
	}()
	c.mu.Lock()
	p := c.procs[pid]
	if p == nil {
		p = &tlsProc{}
		c.procs[pid] = p
	}
	old, fresh := p.own, p.lib == nil
	p.own = nil
	c.mu.Unlock()
	for _, l := range old { // the binary it ran before this exec
		l.Close()
	}
	var lib []link.Link
	if fresh {
		lib = c.attachLibs(pid)
		if lib == nil {
			lib = []link.Link{} // attached, to nothing
		}
	}
	own, prog := c.attachOwn(pid)
	c.mu.Lock()
	if c.procs[pid] == p {
		if fresh {
			p.lib = lib
		}
		p.own = own
		lib, own = nil, nil
	}
	c.mu.Unlock()
	for _, l := range append(lib, own...) { // it exited meanwhile
		l.Close()
	}
	c.objs.Pids.Put(pid, uint8(1))
	if prog != nil {
		ev.Data = *prog
		select {
		case c.programs <- ev:
		default:
		}
	}
	if syscall.Kill(int(pid), 0) != nil { // gone before it was probed
		c.onExit(pid)
	}
}

func (c *tlsCapture) attachLibs(pid uint32) []link.Link {
	var links []link.Link
	for _, lib := range c.libs {
		ls, err := c.attachC(lib.ex, lib.lib, lib.funcs, nil, pid)
		if err != nil {
			if !errors.Is(err, unix.ESRCH) { // the process is gone
				log.Printf("tls: pid %d: %s: %v", pid, filepath.Base(lib.path), err)
			}
			continue
		}
		links = append(links, ls...)
	}
	return links
}

// attachC attaches the C probes to funcs of ex for pid: by symbol, or at
// addrs (file offsets, one per func) where given. Two links: entries and
// returns.
func (c *tlsCapture) attachC(ex *link.Executable, lib uint64, funcs []tlsFunc, addrs []uint64, pid uint32) ([]link.Link, error) {
	var syms []string
	var cookies []uint64
	for _, f := range funcs {
		cookies = append(cookies, tlsCookie(lib, f))
		if addrs == nil {
			syms = append(syms, f.sym)
		}
	}
	opts := &link.UprobeMultiOptions{Addresses: addrs, Cookies: cookies, PID: pid}
	entry, err := ex.UprobeMulti(syms, c.objs.CEntry, opts)
	if err != nil {
		return nil, err
	}
	ret, err := ex.UretprobeMulti(syms, c.objs.CReturn, opts)
	if err != nil {
		entry.Close()
		return nil, err
	}
	return []link.Link{entry, ret}, nil
}

// definedSyms lists the functions a shared library defines.
func definedSyms(path string) map[string]bool {
	out := map[string]bool{}
	f, err := elf.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	syms, _ := f.DynamicSymbols()
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			out[s.Name] = true
		}
	}
	return out
}

// tlsBinary is what analysis found in one binary: a Go crypto/tls
// (milestone 6.3), or else a TLS stack linked in (6.4).
type tlsBinary struct {
	golang  *goTLSBinary
	bundled *bundledTLS
}

// attachOwn probes the TLS stack the process's binary carries, if any,
// and says what it found; nil: the binary carries none (a Go binary
// without crypto/tls, or one that loads its TLS library).
func (c *tlsCapture) attachOwn(pid uint32) ([]link.Link, *TLSProgramData) {
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	bin, path := c.binary(exe)
	var prog *TLSProgramData
	switch {
	case bin == nil:
		return nil, nil
	case bin.golang != nil && bin.golang.Go != "":
		g := bin.golang
		if g.NoTLS {
			return nil, nil
		}
		prog = &TLSProgramData{Path: path, Stack: g.Go + " crypto/tls", Lib: g.Go, Reason: g.Reason}
	case bin.bundled != nil:
		b := bin.bundled
		prog = &TLSProgramData{Path: path, Stack: b.Stack, Lib: b.Lib, Reason: b.Reason}
	default:
		return nil, nil
	}
	if prog.Reason != "" {
		return nil, prog
	}
	// The binary as this process maps it, whatever its mount namespace.
	ex, err := link.OpenExecutable(exe)
	if err != nil {
		prog.Reason = "open: " + err.Error()
		return nil, prog
	}
	var links []link.Link
	var aerr error
	if g := bin.golang; g != nil && g.Go != "" {
		// Entries, then return instructions as entry probes: a uretprobe
		// breaks on Go's movable stacks. The cookie gives the direction.
		var entries, eCookies, rets, rCookies []uint64
		for _, fn := range []struct {
			f   goTLSFunc
			dir uint64
		}{{g.Write, 1}, {g.Read, 2}} {
			entries, eCookies = append(entries, fn.f.Entry), append(eCookies, fn.dir<<8)
			for _, off := range fn.f.Rets {
				rets, rCookies = append(rets, fn.f.Entry+off), append(rCookies, fn.dir<<8)
			}
		}
		var l link.Link
		if l, aerr = ex.UprobeMulti(nil, c.objs.GoEntry, &link.UprobeMultiOptions{Addresses: entries, Cookies: eCookies, PID: pid}); aerr == nil {
			links = append(links, l)
			if l, aerr = ex.UprobeMulti(nil, c.objs.GoReturn, &link.UprobeMultiOptions{Addresses: rets, Cookies: rCookies, PID: pid}); aerr == nil {
				links = append(links, l)
			}
		}
	} else {
		var funcs []tlsFunc
		var addrs []uint64
		for _, f := range sslFuncs {
			if a := bin.bundled.Syms[f.sym]; a != 0 { // an _ex form this OpenSSL may lack
				funcs, addrs = append(funcs, f), append(addrs, a)
			}
		}
		var ls []link.Link
		if ls, aerr = c.attachC(ex, tlsLibBundled, funcs, addrs, pid); aerr == nil {
			links = ls
		}
	}
	if aerr != nil {
		for _, l := range links {
			l.Close()
		}
		if errors.Is(aerr, unix.ESRCH) {
			return nil, nil // gone
		}
		prog.Reason = "attach: " + aerr.Error()
		return nil, prog
	}
	prog.Probed = true
	return links, prog
}

// binary analyses the binary at exe, once per file.
func (c *tlsCapture) binary(exe string) (*tlsBinary, string) {
	path, _ := os.Readlink(exe)
	f, err := os.Open(exe)
	if err != nil {
		return nil, path
	}
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil {
		return nil, path
	}
	k := exeKey{uint64(st.Dev), st.Ino, st.Size, st.Mtim.Nano()}
	c.mu.Lock()
	bin := c.bins[k]
	c.mu.Unlock()
	if bin != nil {
		return bin, path
	}
	bin = &tlsBinary{golang: analyzeGoTLS(f)}
	if bin.golang.Go == "" {
		if ef, err := elf.NewFile(f); err == nil {
			bin.bundled = analyzeBundled(ef)
		}
	}
	c.mu.Lock()
	if len(c.bins) >= maxBins {
		clear(c.bins)
	}
	c.bins[k] = bin
	c.mu.Unlock()
	return bin, path
}

// onExit detaches a process's probes.
func (c *tlsCapture) onExit(pid uint32) {
	c.mu.Lock()
	p := c.procs[pid]
	delete(c.procs, pid)
	c.mu.Unlock()
	if p != nil {
		for _, l := range append(p.lib, p.own...) {
			l.Close()
		}
	}
	c.objs.Pids.Delete(pid)
}

// watchdog continues processes held at exec for longer than tlsHoldMax:
// their exec event was lost, or attaching stalled.
func (c *tlsCapture) watchdog() {
	defer c.wg.Done()
	t := time.NewTicker(tlsWatchdog)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		var ts unix.Timespec
		unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
		now := uint64(ts.Nano())
		var pid uint32
		var at uint64
		var late []uint32
		it := c.objs.Held.Iterate()
		for it.Next(&pid, &at) {
			if now-at > uint64(tlsHoldMax) {
				late = append(late, pid)
			}
		}
		for _, p := range late {
			c.objs.Held.Delete(p)
			unix.Kill(int(p), unix.SIGCONT)
			log.Printf("tls: pid %d held at exec for over %v without its probes; continued", p, tlsHoldMax)
		}
	}
}

// Close continues every process still held, and detaches everything.
func (c *tlsCapture) Close() {
	select {
	case <-c.done:
		return
	default:
	}
	close(c.done)
	c.wg.Wait()
	var pid uint32
	var at uint64
	it := c.objs.Held.Iterate()
	var held []uint32
	for it.Next(&pid, &at) {
		held = append(held, pid)
	}
	for _, p := range held {
		unix.Kill(int(p), unix.SIGCONT)
	}
	c.mu.Lock()
	for pid, p := range c.procs {
		for _, l := range append(p.lib, p.own...) {
			l.Close()
		}
		delete(c.procs, pid)
	}
	c.mu.Unlock()
	for _, l := range c.links {
		l.Close()
	}
	c.objs.Close()
}

// attachRunning probes the processes already in a run's cgroups: a
// restarted node agent restores a capturing run (milestone 6.6), whose
// processes lost their probes with the previous node agent. They are not
// held; what they send before their probes are in place is not seen.
func (c *tlsCapture) attachRunning(cgroupPath string, runCg uint64) int {
	n := 0
	filepath.WalkDir(cgroupPath, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		var st syscall.Stat_t
		if syscall.Stat(p, &st) != nil {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		if err != nil {
			return nil
		}
		for _, f := range strings.Fields(string(b)) {
			var pid uint32
			if _, err := fmt.Sscan(f, &pid); err != nil {
				continue
			}
			c.mu.Lock()
			_, have := c.procs[pid]
			c.mu.Unlock()
			if have {
				continue
			}
			n++
			c.onExec(AuditEvent{Type: EventTLSProgram, Timestamp: time.Now(), PID: pid, CgroupID: st.Ino, RunCgroupID: runCg}, false)
		}
		return nil
	})
	return n
}

// ContinueStopped continues processes in cgroupPath and below that are
// stopped: a previous node agent may have held them at exec and died
// before continuing them (milestone 6.2). Only for runs that capture.
func ContinueStopped(cgroupPath string) int {
	n := 0
	filepath.WalkDir(cgroupPath, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		if err != nil {
			return nil
		}
		for _, f := range strings.Fields(string(b)) {
			var pid int
			if _, err := fmt.Sscan(f, &pid); err != nil {
				continue
			}
			if st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); procState(st) == 'T' {
				unix.Kill(pid, unix.SIGCONT)
				n++
			}
		}
		return nil
	})
	return n
}

func procState(stat []byte) byte {
	for i := len(stat) - 1; i > 0; i-- {
		if stat[i] == ')' && i+2 < len(stat) {
			return stat[i+2]
		}
	}
	return 0
}
