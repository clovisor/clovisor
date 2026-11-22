// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux
// +build linux

package clovisor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	MaxPathLen   = 256
	maxArgsLen   = 512
	maxCgPathLen = 128
	maxDNSLen    = 1024

	bpfEventExec     = 0
	bpfEventConnect  = 1
	bpfEventRunStart = 2
	bpfEventRunEnd   = 3
	bpfEventDNS      = 4
	bpfEventDrop     = 5

	afInet  = 2
	afInet6 = 10
)

// Wire formats; must match the structs in ebpf/agent_audit.c.
type bpfAuditConfig struct {
	AgentsCgroupID uint64
	AgentsLevel    uint32
	Mode           uint32
	StaleNs        uint64
	TproxyPort     uint16
	DNSPort        uint16
	_              uint32
	Exc            [maxTransparentExceptions]bpfException
	UDPExc         [maxTransparentExceptions]bpfException
}

type bpfException struct {
	IP   [16]byte // network order; IPv4 as ::ffff:a.b.c.d; zero: any loopback
	Port uint16   // host order; 0 ends the list
	_    uint16
	_    uint32
}

type bpfEventHdr struct {
	Type        uint32
	PID         uint32
	TimestampNs uint64
	CgroupID    uint64
	RunCgroupID uint64
}

type bpfExecEvent struct {
	Hdr      bpfEventHdr
	PPID     uint32
	ArgsLen  uint32
	Filename [MaxPathLen]byte
	Args     [maxArgsLen]byte
}

type bpfDNSEvent struct {
	Hdr     bpfEventHdr
	Family  uint16
	_       uint16
	Len     uint32
	OrigLen uint32
	SAddr   [16]byte
	Payload [maxDNSLen]byte
}

type bpfDropEvent struct {
	Hdr      bpfEventHdr
	Family   uint16
	DPort    uint16
	Protocol uint32
	DAddr    [16]byte
	Count    uint32
	Enforced uint32
}

type bpfCgroupEvent struct {
	Hdr  bpfEventHdr
	Path [maxCgPathLen]byte
}

type bpfConnectEvent struct {
	Hdr      bpfEventHdr
	Family   uint16
	DPort    uint16
	Protocol uint32
	DAddr    [16]byte
	Verdict  uint32
	_        uint32
}

type bpfObjects struct {
	ExecProg     *ebpf.Program `ebpf:"on_exec"`
	MkdirProg    *ebpf.Program `ebpf:"on_cgroup_mkdir"`
	RmdirProg    *ebpf.Program `ebpf:"on_cgroup_rmdir"`
	IngressProg  *ebpf.Program `ebpf:"on_ingress"`
	Connect4Prog *ebpf.Program `ebpf:"on_connect4"`
	Connect6Prog *ebpf.Program `ebpf:"on_connect6"`
	Bind4Prog    *ebpf.Program `ebpf:"on_bind4"`
	Bind6Prog    *ebpf.Program `ebpf:"on_bind6"`
	Peer4Prog    *ebpf.Program `ebpf:"on_getpeername4"`
	Peer6Prog    *ebpf.Program `ebpf:"on_getpeername6"`
	SockopsProg  *ebpf.Program `ebpf:"on_sockops"`
	Send4Prog    *ebpf.Program `ebpf:"on_sendmsg4"`
	Send6Prog    *ebpf.Program `ebpf:"on_sendmsg6"`
	Recv4Prog    *ebpf.Program `ebpf:"on_recvmsg4"`
	Recv6Prog    *ebpf.Program `ebpf:"on_recvmsg6"`
	EgressProg   *ebpf.Program `ebpf:"on_egress"`
	ProxyConn4   *ebpf.Program `ebpf:"on_proxy_connect4"`
	ProxyConn6   *ebpf.Program `ebpf:"on_proxy_connect6"`
	Lost         *ebpf.Map     `ebpf:"lost"`
	Suppressed   *ebpf.Map     `ebpf:"suppressed"`
	RunBudget    *ebpf.Map     `ebpf:"run_budget"`
	ProxyRefused *ebpf.Map     `ebpf:"proxy_refused"`
	UDPReported  *ebpf.Map     `ebpf:"udp_reported"`
	DropRate     *ebpf.Map     `ebpf:"drop_rate"`
	SockoptProg  *ebpf.Program `ebpf:"on_getsockopt"`
	Config       *ebpf.Map     `ebpf:"config"`
	Heartbeat    *ebpf.Map     `ebpf:"heartbeat"`
	Events       *ebpf.Map     `ebpf:"events"`
	OrigBySk     *ebpf.Map     `ebpf:"orig_by_sk"`
	RunBySk      *ebpf.Map     `ebpf:"run_by_sk"`
	OrigByTuple  *ebpf.Map     `ebpf:"orig_by_tuple"`
}

func (o *bpfObjects) Close() {
	for _, c := range []interface{ Close() error }{o.ExecProg, o.MkdirProg, o.RmdirProg, o.IngressProg,
		o.Connect4Prog, o.Connect6Prog, o.Bind4Prog, o.Bind6Prog, o.Peer4Prog, o.Peer6Prog, o.SockopsProg, o.SockoptProg, o.Send4Prog, o.Send6Prog, o.Recv4Prog, o.Recv6Prog, o.EgressProg, o.UDPReported, o.DropRate, o.ProxyConn4, o.ProxyConn6, o.Lost, o.Suppressed, o.RunBudget, o.ProxyRefused,
		o.Config, o.Heartbeat, o.Events, o.OrigBySk, o.RunBySk, o.OrigByTuple} {
		if c != nil {
			c.Close()
		}
	}
}

// EBPFReader loads the audit BPF programs, attaches them, and streams
// decoded events from the ring buffer.
type EBPFReader struct {
	objs     bpfObjects
	links    []link.Link
	rd       *ringbuf.Reader
	eventsCh chan AuditEvent
	done     chan struct{}
	wg       sync.WaitGroup
	once     sync.Once

	// Offset that converts CLOCK_BOOTTIME nanoseconds to wall time.
	bootOffset time.Duration

	transparent TransparentOptions
	beatDone    chan struct{}
	// health, if set, must return nil for the heartbeat to be written:
	// the node agent's view of whether the proxy can serve runs.
	health    atomic.Value // func() error
	unhealthy atomic.Bool

	gateMu    sync.Mutex
	gateCg    string
	gateLinks []link.Link
}

// NewEBPFReader loads the BPF object at bpfObjPath, configures it to
// report only tasks under agentsDir (cgroup id agentsCgroupID, at depth
// agentsLevel below the cgroup v2 root), and attaches the programs: the
// exec tracepoint system-wide, the connect hooks to agentsDir. t sets
// the transparent mode (milestone 3.1); the zero value is off.
func NewEBPFReader(bpfObjPath, agentsDir string, agentsCgroupID uint64, agentsLevel uint32, t TransparentOptions) (*EBPFReader, error) {
	if err := t.normalize(); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF spec: %w", err)
	}

	r := &EBPFReader{
		eventsCh:    make(chan AuditEvent, 1000),
		done:        make(chan struct{}),
		transparent: t,
	}

	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	cfg := bpfAuditConfig{AgentsCgroupID: agentsCgroupID, AgentsLevel: agentsLevel,
		Mode:    map[string]uint32{TransparentOff: 0, TransparentAudit: 1, TransparentEnforce: 2}[t.Mode],
		StaleNs: uint64(t.Stale.Nanoseconds()), TproxyPort: t.Port, DNSPort: t.DNSPort}
	for i, x := range t.Exceptions {
		if a := x.Addr(); !a.IsUnspecified() {
			cfg.Exc[i].IP = a.As16() // IPv4 comes out as ::ffff:a.b.c.d
		}
		cfg.Exc[i].Port = x.Port()
	}
	for i, x := range t.UDPExceptions {
		if a := x.Addr(); !a.IsUnspecified() {
			cfg.UDPExc[i].IP = a.As16()
		}
		cfg.UDPExc[i].Port = x.Port()
	}
	if err := r.objs.Config.Put(uint32(0), cfg); err != nil {
		r.Close()
		return nil, fmt.Errorf("failed to write BPF config: %w", err)
	}
	// A heartbeat before any hook can see a connect.
	if err := r.beat(); err != nil {
		r.Close()
		return nil, err
	}

	for _, t := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"sched_process_exec", r.objs.ExecProg},
		{"cgroup_mkdir", r.objs.MkdirProg},
		{"cgroup_rmdir", r.objs.RmdirProg},
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: t.prog})
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("failed to attach %s: %w", t.name, err)
		}
		r.links = append(r.links, l)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{Path: agentsDir, Attach: ebpf.AttachCGroupInetIngress, Program: r.objs.IngressProg})
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("failed to attach ingress to %s: %w", agentsDir, err)
	}
	r.links = append(r.links, l)

	// The connect hooks, and in audit or enforce mode the rest of the
	// transparent set. Enforce pins them, so connects keep failing closed
	// once this process is gone; other modes remove pins a previous
	// enforce left behind.
	on := t.Mode != TransparentOff
	pin := t.Mode == TransparentEnforce
	for _, c := range []struct {
		name string
		cg   string
		typ  ebpf.AttachType
		prog *ebpf.Program
		want bool
	}{
		{"connect4", agentsDir, ebpf.AttachCGroupInet4Connect, r.objs.Connect4Prog, true},
		{"connect6", agentsDir, ebpf.AttachCGroupInet6Connect, r.objs.Connect6Prog, true},
		{"bind4", agentsDir, ebpf.AttachCGroupInet4Bind, r.objs.Bind4Prog, on},
		{"bind6", agentsDir, ebpf.AttachCGroupInet6Bind, r.objs.Bind6Prog, on},
		{"getpeername4", agentsDir, ebpf.AttachCgroupInet4GetPeername, r.objs.Peer4Prog, on},
		{"getpeername6", agentsDir, ebpf.AttachCgroupInet6GetPeername, r.objs.Peer6Prog, on},
		{"sockops", agentsDir, ebpf.AttachCGroupSockOps, r.objs.SockopsProg, on},
		{"sendmsg4", agentsDir, ebpf.AttachCGroupUDP4Sendmsg, r.objs.Send4Prog, on},
		{"sendmsg6", agentsDir, ebpf.AttachCGroupUDP6Sendmsg, r.objs.Send6Prog, on},
		{"recvmsg4", agentsDir, ebpf.AttachCGroupUDP4Recvmsg, r.objs.Recv4Prog, on},
		{"recvmsg6", agentsDir, ebpf.AttachCGroupUDP6Recvmsg, r.objs.Recv6Prog, on},
		// The packet backstop; it acts in enforce only.
		{"egress", agentsDir, ebpf.AttachCGroupInetEgress, r.objs.EgressProg, on},
		// On the root: the proxy runs outside agents/, wherever its
		// operator put it. The program answers only tasks outside runs.
		{"getsockopt", CgroupV2Root, ebpf.AttachCGroupGetsockopt, r.objs.SockoptProg, on},
	} {
		if err := r.cgroupLink(c.name, c.cg, c.typ, c.prog, c.want, pin); err != nil {
			r.Close()
			return nil, err
		}
	}
	if t.Mode != TransparentOff {
		r.beatDone = make(chan struct{})
		go r.heartbeatLoop()
	}

	r.rd, err = ringbuf.NewReader(r.objs.Events)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("failed to open ring buffer: %w", err)
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		r.Close()
		return nil, fmt.Errorf("failed to read CLOCK_BOOTTIME: %w", err)
	}
	r.bootOffset = time.Duration(time.Now().UnixNano() - ts.Nano())

	return r, nil
}

// Start begins reading BPF events.
func (r *EBPFReader) Start() error {
	r.wg.Add(1)
	go r.readLoop()
	return nil
}

func (r *EBPFReader) readLoop() {
	defer r.wg.Done()
	defer close(r.eventsCh)

	for {
		rec, err := r.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		ev, err := r.decode(rec.RawSample)
		if err != nil {
			log.Printf("decode BPF event: %v", err)
			continue
		}

		select {
		case r.eventsCh <- ev:
		case <-r.done:
			return
		}
	}
}

func (r *EBPFReader) decode(raw []byte) (AuditEvent, error) {
	var hdr bpfEventHdr
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &hdr); err != nil {
		return AuditEvent{}, err
	}

	ev := AuditEvent{
		Timestamp:   time.Unix(0, int64(hdr.TimestampNs)).Add(r.bootOffset),
		CgroupID:    hdr.CgroupID,
		RunCgroupID: hdr.RunCgroupID,
		PID:         hdr.PID,
	}

	switch hdr.Type {
	case bpfEventExec:
		var e bpfExecEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		ev.PPID = e.PPID
		ev.Type = EventExec
		ev.Data = ExecData{
			BinaryPath: cString(e.Filename[:]),
			PID:        hdr.PID,
			PPID:       e.PPID,
			Args:       splitArgs(e.Args[:min(int(e.ArgsLen), maxArgsLen)]),
		}

	case bpfEventDNS:
		var e bpfDNSEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		n := min(int(e.Len), maxDNSLen)
		d, err := parseDNSResponse(e.Payload[:n], e.OrigLen > uint32(n))
		if err != nil {
			return AuditEvent{}, fmt.Errorf("dns reply: %w", err)
		}
		server := e.SAddr[:4]
		if e.Family == afInet6 {
			server = e.SAddr[:]
		}
		d.Server = net.IP(append([]byte(nil), server...)).String()
		ev.Type = EventDNS
		ev.Data = d

	case bpfEventDrop:
		var e bpfDropEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		ip := net.IP(append([]byte(nil), e.DAddr[:4]...))
		if e.Family == afInet6 {
			ip = net.IP(append([]byte(nil), e.DAddr[:]...))
		}
		ev.Type = EventDrop
		ev.Data = DropData{DstIP: ip.String(), DstPort: e.DPort, Protocol: ipProtoName(e.Protocol), Count: e.Count, Enforced: e.Enforced != 0}

	case bpfEventRunStart, bpfEventRunEnd:
		var e bpfCgroupEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		ev.Type = EventRunStart
		if hdr.Type == bpfEventRunEnd {
			ev.Type = EventRunEnd
		}
		ev.Data = RunData{CgroupPath: cString(e.Path[:])}

	case bpfEventConnect:
		var e bpfConnectEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		var ip net.IP
		switch e.Family {
		case afInet:
			ip = net.IP(append([]byte(nil), e.DAddr[:4]...))
		case afInet6:
			ip = net.IP(append([]byte(nil), e.DAddr[:]...))
		default:
			return AuditEvent{}, fmt.Errorf("unexpected address family %d", e.Family)
		}
		ev.Type = EventConnect
		ev.Data = ConnectData{DstIP: ip.String(), DstPort: e.DPort, Protocol: protoName(e.Protocol), Verdict: connectVerdicts[e.Verdict]}

	default:
		return AuditEvent{}, fmt.Errorf("unknown event type %d", hdr.Type)
	}

	return ev, nil
}

// Stop detaches the programs and stops the read loop. Safe to call more
// than once.
func (r *EBPFReader) Stop() error {
	r.Close()
	return nil
}

// Events returns the event channel. It is closed when the reader stops.
func (r *EBPFReader) Events() <-chan AuditEvent {
	return r.eventsCh
}

// pinPath is where the link name is pinned.
func (r *EBPFReader) pinPath(name string) string {
	return filepath.Join(r.transparent.PinDir, "transparent-"+name)
}

// cgroupLink attaches prog to cgroup cg, or, if a previous node agent
// pinned a link for name, swaps prog into it atomically, so there is no
// moment with no program, or with two. With want false the link is not
// needed: a pinned one is removed. With pin true it is pinned.
func (r *EBPFReader) cgroupLink(name, cg string, typ ebpf.AttachType, prog *ebpf.Program, want, pin bool) error {
	path := r.pinPath(name)
	if old, err := link.LoadPinnedLink(path, nil); err == nil {
		if want {
			if err := old.Update(prog); err == nil {
				if !pin {
					old.Unpin()
					log.Printf("bpf: %s: removed the pin left by transparent enforce", name)
				}
				r.links = append(r.links, old)
				return nil
			}
		}
		// Not wanted, or from an incompatible build: replace it.
		old.Unpin()
		old.Close()
		if !want {
			log.Printf("bpf: %s: removed the pin left by transparent enforce", name)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("pinned %s: %w", path, err)
	}
	if !want {
		return nil
	}
	l, err := link.AttachCgroup(link.CgroupOptions{Path: cg, Attach: typ, Program: prog})
	if err != nil {
		return fmt.Errorf("failed to attach %s to %s: %w", name, cg, err)
	}
	if pin {
		if err := os.MkdirAll(r.transparent.PinDir, 0o700); err != nil {
			l.Close()
			return err
		}
		if err := l.Pin(path); err != nil {
			l.Close()
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}
	r.links = append(r.links, l)
	return nil
}

// beat records that the node agent is alive (CLOCK_MONOTONIC, which is
// what bpf_ktime_get_ns reads).
func (r *EBPFReader) beat() error {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return err
	}
	if err := r.objs.Heartbeat.Put(uint32(0), uint64(ts.Nano())); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	return nil
}

// SetHealth installs the check the heartbeat depends on. While it
// fails, no heartbeat is written, and in enforce mode connects from runs
// are refused within the stale interval: a clear EPERM rather than
// connections reset by a proxy that is not there.
func (r *EBPFReader) SetHealth(f func() error) { r.health.Store(f) }

func (r *EBPFReader) heartbeatLoop() {
	defer close(r.beatDone)
	tick := time.NewTicker(r.transparent.Stale / 3)
	defer tick.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-tick.C:
			if f, _ := r.health.Load().(func() error); f != nil {
				if err := f(); err != nil {
					if !r.unhealthy.Swap(true) {
						log.Printf("transparent: unhealthy, heartbeat stopped (connects from runs will be refused): %v", err)
					}
					continue
				}
				if r.unhealthy.Swap(false) {
					log.Printf("transparent: healthy again, heartbeat resumed")
				}
			}
			if err := r.beat(); err != nil {
				log.Printf("bpf: %v", err)
			}
		}
	}
}

// Healthy reports whether the last health check passed.
func (r *EBPFReader) Healthy() bool { return !r.unhealthy.Load() }

// LostFor returns and clears a run's missing events: those lost to a full
// ring buffer, and those suppressed because the run spent its event
// budget. It also forgets the run's budget.
func (r *EBPFReader) LostFor(runCg uint64) (lost, suppressed uint64) {
	if runCg == 0 {
		return 0, 0
	}
	take := func(m *ebpf.Map) uint64 {
		var n uint64
		if m == nil || m.Lookup(runCg, &n) != nil {
			return 0
		}
		m.Delete(runCg)
		return n
	}
	if r.objs.RunBudget != nil {
		r.objs.RunBudget.Delete(runCg)
	}
	return take(r.objs.Lost), take(r.objs.Suppressed)
}

// LostTotal is every event lost, and every event suppressed, since the
// program was loaded.
func (r *EBPFReader) LostTotal() (lost, suppressed uint64) {
	if r.objs.Lost != nil {
		r.objs.Lost.Lookup(uint64(0), &lost)
	}
	if r.objs.Suppressed != nil {
		r.objs.Suppressed.Lookup(uint64(0), &suppressed)
	}
	return lost, suppressed
}

// ProxyRefused counts the proxy's connects the gate refused.
func (r *EBPFReader) ProxyRefused() uint64 {
	var n uint64
	if r.objs.ProxyRefused != nil {
		r.objs.ProxyRefused.Lookup(uint32(0), &n)
	}
	return n
}

// GateProxy attaches the proxy's connect gate to cgroup path (relative to
// the cgroup root), replacing any earlier one. An empty path detaches it.
// The caller must make sure the cgroup holds only the proxy: the gate
// applies to everything in it.
func (r *EBPFReader) GateProxy(path string) error {
	r.gateMu.Lock()
	defer r.gateMu.Unlock()
	if path == r.gateCg {
		return nil
	}
	for _, l := range r.gateLinks {
		l.Close()
	}
	r.gateLinks, r.gateCg = nil, ""
	if path == "" {
		return nil
	}
	full := filepath.Join(CgroupV2Root, path)
	for _, c := range []struct {
		typ  ebpf.AttachType
		prog *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, r.objs.ProxyConn4},
		{ebpf.AttachCGroupInet6Connect, r.objs.ProxyConn6},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: full, Attach: c.typ, Program: c.prog})
		if err != nil {
			for _, l := range r.gateLinks {
				l.Close()
			}
			r.gateLinks = nil
			return fmt.Errorf("gate proxy cgroup %s: %w", path, err)
		}
		r.gateLinks = append(r.gateLinks, l)
	}
	r.gateCg = path
	return nil
}

// GatedProxy is the cgroup the proxy gate is attached to, if any.
func (r *EBPFReader) GatedProxy() string {
	r.gateMu.Lock()
	defer r.gateMu.Unlock()
	return r.gateCg
}

// Close releases all resources. Closing the ring buffer reader unblocks
// Read, so the read loop exits promptly. In enforce mode the pinned
// connect hooks stay attached and, with the heartbeat cleared, refuse
// every connect from a run until a node agent starts again.
func (r *EBPFReader) Close() {
	r.once.Do(func() {
		close(r.done)
		if r.beatDone != nil {
			<-r.beatDone
		}
		if r.objs.Heartbeat != nil {
			r.objs.Heartbeat.Put(uint32(0), uint64(0))
		}
		r.GateProxy("")
		for _, l := range r.links {
			l.Close()
		}
		if r.rd != nil {
			r.rd.Close()
			r.wg.Wait()
		}
		r.objs.Close()
	})
}
