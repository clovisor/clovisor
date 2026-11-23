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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/clovisor/clovisor/libclovisor/policy"
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
	bpfEventSocket   = 6
	bpfEventUnix     = 7
	bpfEventExecPath = 8

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

type bpfSocketEvent struct {
	Hdr      bpfEventHdr
	Family   uint16
	Type     uint16
	Protocol uint32
	Op       uint32
	Verdict  uint32
	SkCgroup uint64
}

// bpfLSMObjects are loaded only where BPF LSM is active: on a kernel
// without it, LSM programs do not even load.
type bpfLSMObjects struct {
	SocketCreate  *ebpf.Program `ebpf:"on_lsm_socket_create"`
	SocketConnect *ebpf.Program `ebpf:"on_lsm_socket_connect"`
	SocketSendmsg *ebpf.Program `ebpf:"on_lsm_socket_sendmsg"`
	UnixStream    *ebpf.Program `ebpf:"on_lsm_unix_stream_connect"`
	UnixSend      *ebpf.Program `ebpf:"on_lsm_unix_may_send"`
	Exec          *ebpf.Program `ebpf:"on_lsm_exec"`
	ExecPolicy    *ebpf.Map     `ebpf:"exec_policy"`
	ExecAllow     *ebpf.Map     `ebpf:"exec_allow"`
	ExecSeen      *ebpf.Map     `ebpf:"exec_seen"`
	UnixPolicy    *ebpf.Map     `ebpf:"unix_policy"`
	UnixNode      *ebpf.Map     `ebpf:"unix_node"`
	UnixSeen      *ebpf.Map     `ebpf:"unix_seen"`
}

func (o *bpfLSMObjects) Close() {
	for _, c := range []interface{ Close() error }{o.SocketCreate, o.SocketConnect, o.SocketSendmsg,
		o.UnixStream, o.UnixSend, o.UnixPolicy, o.UnixNode, o.UnixSeen, o.Exec, o.ExecPolicy, o.ExecAllow, o.ExecSeen} {
		if c != nil && !reflect.ValueOf(c).IsNil() {
			c.Close()
		}
	}
}

// Wire formats of exec_policy and exec_allow (agent_audit.c).
const (
	maxExecLayers   = maxKernelExecLayers
	maxExecPrefixes = 4
	execPathBytes   = 256
)

type bpfExecPrefix struct {
	Len uint16
	_   [6]uint8
	B   [execPathBytes]byte
	M   [execPathBytes]byte
}

type bpfExecLayer struct {
	DefaultAllow   uint32
	RequireTrusted uint32
	Enforce        uint32
	NPrefix        uint32
	Pre            [maxExecPrefixes]bpfExecPrefix
}

type bpfExecPolicy struct {
	N uint32
	_ uint32
	L [maxExecLayers]bpfExecLayer
}

type bpfExecKey struct {
	Run   uint64
	Layer uint32
	_     uint32
	Hash  uint64
}

type bpfExecPathEvent struct {
	Hdr     bpfEventHdr
	Path    [execPathBytes]byte
	Len     uint32
	Verdict uint32
	Trusted uint32
	_       uint32
}

// execHash is exec_hash in agent_audit.c: FNV-1a over the zero-padded
// path's little-endian 64-bit words.
func execHash(path string) (uint64, [execPathBytes]byte) {
	var b [execPathBytes]byte
	copy(b[:], path)
	h := uint64(14695981039346656037)
	for j := 0; j < execPathBytes; j += 8 {
		h = (h ^ binary.LittleEndian.Uint64(b[j:])) * 1099511628211
	}
	return h, b
}

// SetExecPolicy gives a run its exec layers (milestone 4.4), replacing any
// earlier ones. No layers: nothing about exec is refused.
func (r *EBPFReader) SetExecPolicy(runCg uint64, layers []policy.ExecLayer) error {
	if r.lsm.ExecPolicy == nil {
		return nil // BPF LSM not in use
	}
	r.ForgetExecPolicy(runCg)
	if len(layers) > maxExecLayers {
		// Fail closed: a layer the kernel cannot hold must not be dropped,
		// so the run gets one that refuses every exec. The run API refuses
		// nested runs that would get here; only clamps can.
		err := fmt.Errorf("at most %d exec layers, got %d: every exec is refused", maxExecLayers, len(layers))
		var p bpfExecPolicy
		p.N = 1
		p.L[0] = bpfExecLayer{Enforce: 1}
		if perr := r.lsm.ExecPolicy.Put(runCg, p); perr != nil {
			return perr
		}
		return err
	}
	if len(layers) == 0 {
		return nil
	}
	var p bpfExecPolicy
	var keys []bpfExecKey
	for i, l := range layers {
		bl := &p.L[i]
		bl.DefaultAllow, bl.RequireTrusted, bl.Enforce = b2u(l.DefaultAllow), b2u(l.RequireTrusted), b2u(l.Enforce)
		if len(l.Prefixes) > maxExecPrefixes {
			return fmt.Errorf("at most %d exec prefixes", maxExecPrefixes)
		}
		for j, pre := range l.Prefixes {
			bl.Pre[j].Len = uint16(len(pre))
			copy(bl.Pre[j].B[:], pre)
			for k := 0; k < len(pre) && k < execPathBytes; k++ {
				bl.Pre[j].M[k] = 0xff
			}
		}
		bl.NPrefix = uint32(len(l.Prefixes))
		for _, path := range l.Exact {
			h, b := execHash(path)
			k := bpfExecKey{Run: runCg, Layer: uint32(i), Hash: h}
			if err := r.lsm.ExecAllow.Put(k, b); err != nil {
				return fmt.Errorf("exec allow %s: %w", path, err)
			}
			keys = append(keys, k)
		}
	}
	p.N = uint32(len(layers))
	r.execMu.Lock()
	r.execKeys[runCg] = keys
	r.execMu.Unlock()
	return r.lsm.ExecPolicy.Put(runCg, p)
}

// ForgetExecPolicy drops a run's exec layers and allow entries.
func (r *EBPFReader) ForgetExecPolicy(runCg uint64) {
	if r.lsm.ExecPolicy == nil {
		return
	}
	r.lsm.ExecPolicy.Delete(runCg)
	r.execMu.Lock()
	keys := r.execKeys[runCg]
	delete(r.execKeys, runCg)
	r.execMu.Unlock()
	for _, k := range keys {
		r.lsm.ExecAllow.Delete(k)
	}
}

func b2u(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// Wire formats of unix_policy (agent_audit.c).
const (
	maxUnixPatterns = 8
	unixPathBytes   = 112
)

type bpfUnixPat struct {
	Len    uint16
	Prefix uint8
	_      [5]uint8
	B      [unixPathBytes]byte
	M      [unixPathBytes]byte // 0xff over the first Len bytes
}

type bpfUnixPolicy struct {
	N       uint32
	Enforce uint32
	P       [maxUnixPatterns]bpfUnixPat
}

type bpfUnixEvent struct {
	Hdr        bpfEventHdr
	Path       [unixPathBytes]byte
	Len        uint32
	Verdict    uint32
	Dgram      uint32
	_          uint32
	PeerCgroup uint64
}

// unixPolicyOf encodes patterns (absolute paths or @names, a trailing *
// for a prefix) for the kernel.
func unixPolicyOf(patterns []string, enforce bool) (bpfUnixPolicy, error) {
	var p bpfUnixPolicy
	if len(patterns) > maxUnixPatterns {
		return p, fmt.Errorf("at most %d unix patterns, got %d", maxUnixPatterns, len(patterns))
	}
	for i, pat := range patterns {
		body, prefix := strings.CutSuffix(pat, "*")
		if len(body) > 108 {
			return p, fmt.Errorf("unix pattern %q is too long", pat)
		}
		p.P[i].Len = uint16(len(body))
		if prefix {
			p.P[i].Prefix = 1
		}
		copy(p.P[i].B[:], body)
		for j := 0; j < len(body); j++ {
			p.P[i].M[j] = 0xff
		}
	}
	p.N = uint32(len(patterns))
	if enforce {
		p.Enforce = 1
	}
	return p, nil
}

// SetUnixPolicy gives a run its effective unix.allow (milestone 4.2).
// enforce says whether the run has an enforcing profile; without one,
// Unix sockets outside the run are reported, not refused.
func (r *EBPFReader) SetUnixPolicy(runCg uint64, patterns []string, enforce bool) error {
	if r.lsm.UnixPolicy == nil {
		return nil // BPF LSM not in use
	}
	p, err := unixPolicyOf(patterns, enforce)
	if err != nil {
		return err
	}
	return r.lsm.UnixPolicy.Put(runCg, p)
}

// ForgetUnixPolicy drops a finished run's entry.
func (r *EBPFReader) ForgetUnixPolicy(runCg uint64) {
	if r.lsm.UnixPolicy != nil {
		r.lsm.UnixPolicy.Delete(runCg)
	}
}

// SetNestedRun marks a nested run's cgroup (milestone 4.6), so the
// kernel looks up per-run policy by it rather than by its top-level run.
// Its policy must be written first.
func (r *EBPFReader) SetNestedRun(cg uint64) error {
	if r.objs.NestedRun == nil {
		return nil
	}
	return r.objs.NestedRun.Put(cg, uint8(1))
}

// ForgetNestedRun drops a finished nested run's mark.
func (r *EBPFReader) ForgetNestedRun(cg uint64) {
	if r.objs.NestedRun != nil {
		r.objs.NestedRun.Delete(cg)
	}
}

// Wire format of run_net (agent_audit.c).
type bpfICMPPrefix struct {
	IP   [16]byte
	Mask [16]byte
}

type bpfNetPolicy struct {
	UDP  [policy.MaxRunUDP]bpfException
	ICMP [policy.MaxRunICMP]bpfICMPPrefix
}

// netPolicyOf encodes a run's UDP and ICMP grant for the kernel.
func netPolicyOf(g policy.NetGrant) (bpfNetPolicy, error) {
	var p bpfNetPolicy
	if len(g.UDP) > len(p.UDP) || len(g.ICMP) > len(p.ICMP) {
		return p, fmt.Errorf("at most %d UDP and %d ICMP entries", len(p.UDP), len(p.ICMP))
	}
	for i, a := range g.UDP {
		p.UDP[i].IP = a.Addr().As16()
		p.UDP[i].Port = a.Port()
	}
	for i, pre := range g.ICMP {
		bits := pre.Bits()
		if pre.Addr().Is4() {
			bits += 96
		}
		ip := pre.Addr().As16()
		for b := 0; b < 16; b++ {
			n := min(max(bits-8*b, 0), 8)
			m := byte(0xff << (8 - n))
			if n == 0 {
				m = 0
			}
			p.ICMP[i].Mask[b] = m
			p.ICMP[i].IP[b] = ip[b] & m
		}
	}
	return p, nil
}

// SetNetPolicy gives a run its UDP and ICMP grant (milestone 4.7). An
// empty grant removes the entry: only the node's exceptions apply.
func (r *EBPFReader) SetNetPolicy(runCg uint64, g policy.NetGrant) error {
	if r.objs.RunNet == nil {
		return nil
	}
	if g.Empty() {
		r.ForgetNetPolicy(runCg)
		return nil
	}
	p, err := netPolicyOf(g)
	if err != nil {
		return err
	}
	return r.objs.RunNet.Put(runCg, p)
}

// ForgetNetPolicy drops a run's UDP and ICMP grant.
func (r *EBPFReader) ForgetNetPolicy(runCg uint64) {
	if r.objs.RunNet != nil {
		r.objs.RunNet.Delete(runCg)
	}
}

// SetUnixNode sets the sockets every run may reach: the run API.
func (r *EBPFReader) SetUnixNode(patterns []string) error {
	if r.lsm.UnixNode == nil {
		return nil
	}
	p, err := unixPolicyOf(patterns, false)
	if err != nil {
		return err
	}
	return r.lsm.UnixNode.Put(uint32(0), p)
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
	NestedRun    *ebpf.Map     `ebpf:"nested_run"`
	RunNet       *ebpf.Map     `ebpf:"run_net"`
}

func (o *bpfObjects) Close() {
	for _, c := range []interface{ Close() error }{o.ExecProg, o.MkdirProg, o.RmdirProg, o.IngressProg,
		o.Connect4Prog, o.Connect6Prog, o.Bind4Prog, o.Bind6Prog, o.Peer4Prog, o.Peer6Prog, o.SockopsProg, o.SockoptProg, o.Send4Prog, o.Send6Prog, o.Recv4Prog, o.Recv6Prog, o.EgressProg, o.UDPReported, o.DropRate, o.ProxyConn4, o.ProxyConn6, o.Lost, o.Suppressed, o.RunBudget, o.ProxyRefused,
		o.Config, o.Heartbeat, o.Events, o.OrigBySk, o.RunBySk, o.OrigByTuple, o.NestedRun, o.RunNet} {
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

	lsm      bpfLSMObjects
	lsmState string // what the socket hooks do, for status
	execMu   sync.Mutex
	execKeys map[uint64][]bpfExecKey // exec_allow entries written, per run
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
		execKeys:    map[uint64][]bpfExecKey{},
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
	if err := r.attachLSM(spec); err != nil {
		r.Close()
		return nil, err
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

	case bpfEventSocket:
		var e bpfSocketEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		ev.Type = EventSocket
		ev.Data = SocketData{Family: socketFamily(e.Family), Type: e.Type, Protocol: e.Protocol,
			Op: []string{"create", "connect", "send"}[min(int(e.Op), 2)], Verdict: connectVerdicts[e.Verdict], SocketCgroup: e.SkCgroup}

	case bpfEventUnix:
		var e bpfUnixEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		ev.Type = EventUnix
		ev.Data = UnixData{Path: string(e.Path[:min(int(e.Len), len(e.Path))]), Verdict: connectVerdicts[e.Verdict],
			Datagram: e.Dgram != 0, PeerCgroup: e.PeerCgroup}

	case bpfEventExecPath:
		var e bpfExecPathEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return AuditEvent{}, err
		}
		ev.Type = EventExecPath
		ev.Data = ExecPathData{Path: string(e.Path[:min(int(e.Len), len(e.Path))]), Trusted: e.Trusted != 0,
			Verdict: connectVerdicts[e.Verdict]}

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

// BPFLSMActive reports whether the kernel runs BPF LSM programs, from
// securityfs's list of active LSMs. Only the list tells: BPF LSM can be
// built in but not active, and then programs attach and never run. As
// root, where securityfs is not mounted (in a container, say), it mounts
// it to read the list.
func BPFLSMActive() bool {
	const lsmList = "/sys/kernel/security/lsm"
	data, err := os.ReadFile(lsmList)
	if errors.Is(err, os.ErrNotExist) && os.Geteuid() == 0 {
		if unix.Mount("securityfs", "/sys/kernel/security", "securityfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "") == nil {
			data, err = os.ReadFile(lsmList)
		}
	}
	if err != nil {
		return false
	}
	for _, m := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if m == "bpf" {
			return true
		}
	}
	return false
}

// lsmNames are the socket hooks (milestones 4.1, 4.3), for pins and status.
var lsmNames = []string{"lsm-socket-create", "lsm-socket-connect", "lsm-socket-sendmsg",
	"lsm-unix-stream-connect", "lsm-unix-may-send", "lsm-exec"}

// attachLSM loads and attaches the socket hooks in audit and enforce, if
// BPF LSM is active; in enforce they are pinned like the cgroup hooks.
// Otherwise it removes pins an earlier enforce left.
func (r *EBPFReader) attachLSM(spec *ebpf.CollectionSpec) error {
	t := r.transparent
	switch {
	case t.Mode == TransparentOff:
		r.lsmState = "off"
	case !BPFLSMActive():
		r.lsmState = "not active: socket families, foreign sockets, Unix sockets and exec are not governed (boot with bpf in lsm=)"
		log.Printf("bpf: BPF LSM is not active; socket families, foreign sockets, Unix sockets and exec are not governed")
	}
	if r.lsmState != "" {
		for _, n := range lsmNames {
			if l, err := link.LoadPinnedLink(r.pinPath(n), nil); err == nil {
				l.Unpin()
				l.Close()
				log.Printf("bpf: %s: removed the pin left by transparent enforce", n)
			}
		}
		return nil
	}
	// The programs share the main object's maps: config, events and the
	// per-run budget.
	replace := map[string]*ebpf.Map{"config": r.objs.Config, "events": r.objs.Events, "lost": r.objs.Lost,
		"suppressed": r.objs.Suppressed, "run_budget": r.objs.RunBudget, "nested_run": r.objs.NestedRun}
	if err := spec.LoadAndAssign(&r.lsm, &ebpf.CollectionOptions{MapReplacements: replace}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load BPF LSM programs: %+v", ve)
		}
		return fmt.Errorf("load BPF LSM programs: %w", err)
	}
	pin := t.Mode == TransparentEnforce
	for i, p := range []*ebpf.Program{r.lsm.SocketCreate, r.lsm.SocketConnect, r.lsm.SocketSendmsg, r.lsm.UnixStream, r.lsm.UnixSend, r.lsm.Exec} {
		name := lsmNames[i]
		// A tracing link cannot take a new program in place, so attach
		// the new one first, then let go of a pinned predecessor: for a
		// moment both run, and both refuse the same things.
		l, err := link.AttachLSM(link.LSMOptions{Program: p})
		if err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		path := r.pinPath(name)
		if old, err := link.LoadPinnedLink(path, nil); err == nil {
			old.Unpin()
			old.Close()
		}
		if pin {
			if err := os.MkdirAll(t.PinDir, 0o700); err != nil {
				l.Close()
				return err
			}
			if err := l.Pin(path); err != nil {
				l.Close()
				return fmt.Errorf("pin %s: %w", name, err)
			}
		}
		r.links = append(r.links, l)
	}
	r.lsmState = map[string]string{TransparentAudit: "audit: refusals recorded, not made",
		TransparentEnforce: "enforce: unusual families, raw sockets, foreign sockets, Unix sockets outside unix.allow, and execs the profile refuses"}[t.Mode]
	return nil
}

// LSMState says what the BPF LSM socket hooks do on this node.
func (r *EBPFReader) LSMState() string { return r.lsmState }

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
		r.lsm.Close()
	})
}
