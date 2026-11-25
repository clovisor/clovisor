// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package clovisor

import (
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
	Exec          *ebpf.Program `ebpf:"on_tls_exec"`
	Exit          *ebpf.Program `ebpf:"on_tls_exit"`
	SSLWrite      *ebpf.Program `ebpf:"tls_ssl_write"`
	SSLWriteEx    *ebpf.Program `ebpf:"tls_ssl_write_ex"`
	SSLWriteRet   *ebpf.Program `ebpf:"tls_ssl_write_ret"`
	SSLWriteExRet *ebpf.Program `ebpf:"tls_ssl_write_ex_ret"`
	SSLRead       *ebpf.Program `ebpf:"tls_ssl_read"`
	SSLReadEx     *ebpf.Program `ebpf:"tls_ssl_read_ex"`
	SSLReadRet    *ebpf.Program `ebpf:"tls_ssl_read_ret"`
	SSLReadExRet  *ebpf.Program `ebpf:"tls_ssl_read_ex_ret"`
	GnuSend       *ebpf.Program `ebpf:"tls_gnutls_send"`
	GnuSendRet    *ebpf.Program `ebpf:"tls_gnutls_send_ret"`
	GnuRecv       *ebpf.Program `ebpf:"tls_gnutls_recv"`
	GnuRecvRet    *ebpf.Program `ebpf:"tls_gnutls_recv_ret"`
	Capture       *ebpf.Map     `ebpf:"tls_capture"`
	Held          *ebpf.Map     `ebpf:"tls_held"`
	Pids          *ebpf.Map     `ebpf:"tls_pids"`
}

func (o *bpfTLSObjects) Close() {
	for _, c := range []interface{ Close() error }{o.Exec, o.Exit, o.SSLWrite, o.SSLWriteEx, o.SSLWriteRet, o.SSLWriteExRet,
		o.SSLRead, o.SSLReadEx, o.SSLReadRet, o.SSLReadExRet, o.GnuSend, o.GnuSendRet, o.GnuRecv, o.GnuRecvRet,
		o.Capture, o.Held, o.Pids} {
		if c != nil {
			c.Close()
		}
	}
}

// tlsProbe is one function of a TLS library to probe, at entry and return.
type tlsProbe struct {
	sym        string
	entry, ret *ebpf.Program
}

type tlsLib struct {
	path   string
	ex     *link.Executable
	probes []tlsProbe
}

type tlsCapture struct {
	objs  bpfTLSObjects
	links []link.Link // the exec and exit tracepoints
	libs  []tlsLib

	mu    sync.Mutex
	procs map[uint32][]link.Link // probes, by process
	done  chan struct{}
	wg    sync.WaitGroup
}

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
	c := &tlsCapture{procs: map[uint32][]link.Link{}, done: make(chan struct{})}
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
		lib := tlsLib{path: real, ex: ex}
		o := &c.objs
		if filepath.Base(p) == "libgnutls.so.30" {
			lib.probes = []tlsProbe{{"gnutls_record_send", o.GnuSend, o.GnuSendRet}, {"gnutls_record_recv", o.GnuRecv, o.GnuRecvRet}}
		} else {
			lib.probes = []tlsProbe{{"SSL_write", o.SSLWrite, o.SSLWriteRet}, {"SSL_write_ex", o.SSLWriteEx, o.SSLWriteExRet},
				{"SSL_read", o.SSLRead, o.SSLReadRet}, {"SSL_read_ex", o.SSLReadEx, o.SSLReadExRet}}
		}
		c.libs = append(c.libs, lib)
	}
	if len(c.libs) == 0 {
		c.objs.Close()
		return nil, fmt.Errorf("no TLS library found (looked for %d paths)", len(candidates))
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
// run, then continues it if the kernel stopped it.
func (c *tlsCapture) onExec(pid uint32, held bool) {
	defer func() {
		if held {
			c.objs.Held.Delete(pid)
			unix.Kill(int(pid), unix.SIGCONT)
		}
	}()
	c.mu.Lock()
	_, have := c.procs[pid]
	c.mu.Unlock()
	if have {
		return
	}
	var links []link.Link
	for _, lib := range c.libs {
		for _, p := range lib.probes {
			for i, prog := range []*ebpf.Program{p.entry, p.ret} {
				var l link.Link
				var err error
				if i == 0 {
					l, err = lib.ex.Uprobe(p.sym, prog, &link.UprobeOptions{PID: int(pid)})
				} else {
					l, err = lib.ex.Uretprobe(p.sym, prog, &link.UprobeOptions{PID: int(pid)})
				}
				if err != nil {
					if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
						continue // a symbol this library lacks, or the process is gone
					}
					log.Printf("tls: pid %d: %s %s: %v", pid, filepath.Base(lib.path), p.sym, err)
					continue
				}
				links = append(links, l)
			}
		}
	}
	c.mu.Lock()
	c.procs[pid] = links
	c.mu.Unlock()
	c.objs.Pids.Put(pid, uint8(1))
	if syscall.Kill(int(pid), 0) != nil { // gone before it was probed
		c.onExit(pid)
	}
}

// onExit detaches a process's probes.
func (c *tlsCapture) onExit(pid uint32) {
	c.mu.Lock()
	links := c.procs[pid]
	delete(c.procs, pid)
	c.mu.Unlock()
	for _, l := range links {
		l.Close()
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
	for p, ls := range c.procs {
		for _, l := range ls {
			l.Close()
		}
		delete(c.procs, p)
	}
	c.mu.Unlock()
	for _, l := range c.links {
		l.Close()
	}
	c.objs.Close()
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
