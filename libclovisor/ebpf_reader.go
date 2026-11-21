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
	"sync"
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

	afInet  = 2
	afInet6 = 10
)

// Wire formats; must match the structs in ebpf/agent_audit.c.
type bpfAuditConfig struct {
	AgentsCgroupID uint64
	AgentsLevel    uint32
	_              uint32
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
}

type bpfObjects struct {
	ExecProg     *ebpf.Program `ebpf:"on_exec"`
	MkdirProg    *ebpf.Program `ebpf:"on_cgroup_mkdir"`
	RmdirProg    *ebpf.Program `ebpf:"on_cgroup_rmdir"`
	IngressProg  *ebpf.Program `ebpf:"on_ingress"`
	Connect4Prog *ebpf.Program `ebpf:"on_connect4"`
	Connect6Prog *ebpf.Program `ebpf:"on_connect6"`
	Config       *ebpf.Map     `ebpf:"config"`
	Events       *ebpf.Map     `ebpf:"events"`
}

func (o *bpfObjects) Close() {
	for _, c := range []interface{ Close() error }{o.ExecProg, o.MkdirProg, o.RmdirProg, o.IngressProg, o.Connect4Prog, o.Connect6Prog, o.Config, o.Events} {
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
}

// NewEBPFReader loads the BPF object at bpfObjPath, configures it to
// report only tasks under agentsDir (cgroup id agentsCgroupID, at depth
// agentsLevel below the cgroup v2 root), and attaches the programs: the
// exec tracepoint system-wide, the connect hooks to agentsDir.
func NewEBPFReader(bpfObjPath, agentsDir string, agentsCgroupID uint64, agentsLevel uint32) (*EBPFReader, error) {
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF spec: %w", err)
	}

	r := &EBPFReader{
		eventsCh: make(chan AuditEvent, 1000),
		done:     make(chan struct{}),
	}

	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	cfg := bpfAuditConfig{AgentsCgroupID: agentsCgroupID, AgentsLevel: agentsLevel}
	if err := r.objs.Config.Put(uint32(0), cfg); err != nil {
		r.Close()
		return nil, fmt.Errorf("failed to write BPF config: %w", err)
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

	for _, c := range []struct {
		name string
		typ  ebpf.AttachType
		prog *ebpf.Program
	}{
		{"connect4", ebpf.AttachCGroupInet4Connect, r.objs.Connect4Prog},
		{"connect6", ebpf.AttachCGroupInet6Connect, r.objs.Connect6Prog},
		{"ingress", ebpf.AttachCGroupInetIngress, r.objs.IngressProg},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: agentsDir, Attach: c.typ, Program: c.prog})
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("failed to attach %s to %s: %w", c.name, agentsDir, err)
		}
		r.links = append(r.links, l)
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
		ev.Data = ConnectData{DstIP: ip.String(), DstPort: e.DPort, Protocol: protoName(e.Protocol)}

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

// Close releases all resources. Closing the ring buffer reader unblocks
// Read, so the read loop exits promptly.
func (r *EBPFReader) Close() {
	r.once.Do(func() {
		close(r.done)
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
