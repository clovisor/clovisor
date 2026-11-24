// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// QUIC by name (milestone 5.6, opt-in with -quic). In transparent enforce
// mode the connect hooks send UDP 443 from a run to this relay. For each
// client address it holds the datagrams until the client's Initial
// packets hold the whole ClientHello, reads the server name, and decides
// it as a CONNECT to that name would be decided. Allowed, it forwards the
// datagrams untouched to the address the name resolves to (never the one
// the run chose) and relays the replies; the kernel makes them appear to
// come from where the run sent. Refused, or unreadable, the client gets a
// CONNECTION_CLOSE saying why, where the relay can write one, and falls
// back to TCP, which is decided as usual.

// Relay defaults.
const (
	DefaultQUICPort = 15443
	// quicHold bounds what is held before the ClientHello is complete:
	// with post-quantum key shares it spans two datagrams (5.0 spikes).
	quicHoldDatagrams = 8
	quicHoldBytes     = 16 << 10
	// quicIdle ends a flow with no traffic either way; QUIC's own idle
	// timeouts are typically 30s, kept alive by PINGs.
	quicIdle = 2 * time.Minute
	// quicRefusedKeep keeps a refused flow, so that retransmitted
	// Initials are not decided and recorded again.
	quicRefusedKeep = 10 * time.Second
	// quicHelloTimeout ends a flow whose ClientHello never completes.
	quicHelloTimeout          = 5 * time.Second
	DefaultMaxQUICFlows       = 4096
	DefaultMaxQUICFlowsPerRun = 256
)

// QUICRelay relays runs' QUIC connections by name.
type QUICRelay struct {
	xp    *ExtProcServer
	conns []*net.UDPConn

	MaxFlows       int
	MaxFlowsPerRun int
	// identify finds the cgroup of a client's socket (SockCgroupUDP).
	identify func(client, server netip.AddrPort) (uint64, error)
	// dial opens the upstream socket for a flow.
	dial func(to netip.AddrPort) (*net.UDPConn, error)
	now  func() time.Time

	mu     sync.Mutex
	flows  map[flowKey]*quicFlow
	perRun map[string]int
	wg     sync.WaitGroup
	done   chan struct{}
}

type flowKey struct {
	ln     int
	client netip.AddrPort
}

type quicFlow struct {
	ln     *net.UDPConn
	client netip.AddrPort
	hello  clientHello
	held   [][]byte
	bytes  int
	start  time.Time
	last   time.Time

	decided bool
	allowed bool
	up      *net.UDPConn
	runID   string
	counted bool // in perRun
}

// NewQUICRelay listens on 127.0.0.1 and ::1 at port. Decisions are
// ext_proc's, so that QUIC and TCP to a name are decided alike.
func NewQUICRelay(xp *ExtProcServer, port uint16) (*QUICRelay, error) {
	r := &QUICRelay{xp: xp, identify: SockCgroupUDP, now: time.Now,
		flows: map[flowKey]*quicFlow{}, perRun: map[string]int{}, done: make(chan struct{}),
		dial: func(to netip.AddrPort) (*net.UDPConn, error) {
			return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
		}}
	for _, a := range []string{"127.0.0.1", "::1"} {
		pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(a), port)))
		if err != nil {
			if a == "::1" && len(r.conns) > 0 {
				continue // no IPv6 loopback
			}
			r.Close()
			return nil, fmt.Errorf("quic relay: %w", err)
		}
		r.conns = append(r.conns, pc)
	}
	return r, nil
}

// Serve relays until Close.
func (r *QUICRelay) Serve() {
	for i, pc := range r.conns {
		r.wg.Add(1)
		go r.serve(i, pc)
	}
	r.wg.Add(1)
	go r.reap()
	r.wg.Wait()
}

// Close stops the relay and its flows.
func (r *QUICRelay) Close() {
	select {
	case <-r.done:
		return
	default:
		close(r.done)
	}
	for _, pc := range r.conns {
		pc.Close()
	}
	r.mu.Lock()
	for k, f := range r.flows {
		r.drop(k, f)
	}
	r.mu.Unlock()
}

func (r *QUICRelay) serve(i int, pc *net.UDPConn) {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, src, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		r.datagram(i, pc, src, append([]byte(nil), buf[:n]...))
	}
}

// drop ends a flow. Called with r.mu held.
func (r *QUICRelay) drop(k flowKey, f *quicFlow) {
	delete(r.flows, k)
	if f.up != nil {
		f.up.Close()
	}
	if f.counted {
		if r.perRun[f.runID]--; r.perRun[f.runID] <= 0 {
			delete(r.perRun, f.runID)
		}
	}
}

func (r *QUICRelay) reap() {
	defer r.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}
		now := r.now()
		r.mu.Lock()
		for k, f := range r.flows {
			switch {
			case f.decided && f.allowed && now.Sub(f.last) > quicIdle,
				f.decided && !f.allowed && now.Sub(f.last) > quicRefusedKeep,
				!f.decided && now.Sub(f.start) > quicHelloTimeout:
				r.drop(k, f)
			}
		}
		r.mu.Unlock()
	}
}

// datagram takes one datagram from a client.
func (r *QUICRelay) datagram(i int, pc *net.UDPConn, src netip.AddrPort, pkt []byte) {
	k := flowKey{i, src}
	r.mu.Lock()
	f := r.flows[k]
	if f == nil {
		if len(r.flows) >= orDefault(r.MaxFlows, DefaultMaxQUICFlows) {
			r.mu.Unlock()
			return // full: dropped, and the client falls back to TCP
		}
		f = &quicFlow{ln: pc, client: src, start: r.now()}
		r.flows[k] = f
	}
	f.last = r.now()
	switch {
	case f.decided && f.allowed:
		up := f.up
		r.mu.Unlock()
		up.Write(pkt)
		return
	case f.decided:
		r.mu.Unlock()
		return
	}
	f.held = append(f.held, pkt)
	f.bytes += len(pkt)
	err := f.hello.add(pkt)
	var name string
	var ech bool
	if err == nil {
		name, ech, err = helloServerName(f.hello.contiguous())
		if errors.Is(err, errHelloIncomplete) {
			if len(f.held) < quicHoldDatagrams && f.bytes < quicHoldBytes {
				r.mu.Unlock()
				return
			}
			err = errors.New("the ClientHello did not complete in the first datagrams")
		}
	}
	f.decided = true
	r.mu.Unlock()

	v := r.decide(src, pc.LocalAddr().(*net.UDPAddr).AddrPort(), name, ech, err)
	r.mu.Lock()
	if r.flows[k] != f {
		r.mu.Unlock()
		return
	}
	f.runID = v.runID
	if v.allowed && r.perRun[v.runID] >= orDefault(r.MaxFlowsPerRun, DefaultMaxQUICFlowsPerRun) {
		v.allowed, v.msg = false, "This run has as many QUIC connections open as it may; use TCP."
	}
	if !v.allowed {
		held := f.held
		f.held = nil
		r.mu.Unlock()
		if f.hello.dcid != nil && v.msg != "" && len(held) > 0 {
			pc.WriteToUDPAddrPort(serverClose(&f.hello, v.msg), src)
		}
		return
	}
	up, derr := r.dial(v.upstream)
	if derr != nil {
		f.allowed = false
		r.mu.Unlock()
		log.Printf("quic relay: %s: %v", v.upstream, derr)
		return
	}
	f.allowed, f.up, f.counted = true, up, true
	r.perRun[v.runID]++
	held := f.held
	f.held = nil
	r.mu.Unlock()
	for _, h := range held {
		up.Write(h)
	}
	r.wg.Add(1)
	go r.replies(k, f, up)
}

// replies relays a flow's upstream datagrams back to the client.
func (r *QUICRelay) replies(k flowKey, f *quicFlow, up *net.UDPConn) {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, err := up.Read(buf)
		if err != nil {
			return // closed by reap or Close
		}
		r.mu.Lock()
		f.last = r.now()
		r.mu.Unlock()
		f.ln.WriteToUDPAddrPort(buf[:n], f.client)
	}
}

type quicVerdict struct {
	allowed  bool
	msg      string
	upstream netip.AddrPort
	runID    string
}

// decide identifies the client's run and decides the server name.
func (r *QUICRelay) decide(client, local netip.AddrPort, name string, ech bool, parseErr error) quicVerdict {
	cg, err := r.identify(client, local)
	if err != nil {
		return quicVerdict{msg: "The QUIC relay could not identify which run this connection belongs to."}
	}
	return r.xp.decideQUIC(cg, name, ech, parseErr)
}

// decideQUIC decides a QUIC connection from the run owning cgroup leaf to
// the server name its ClientHello named, and records it as a CONNECT.
// QUIC is let through only where a TLS connection by name would pass
// without termination: a host whose rules need what is sent inside, or
// ask a person, is refused, and the client uses TCP, where that is done.
func (s *ExtProcServer) decideQUIC(leaf uint64, name string, ech bool, parseErr error) quicVerdict {
	host := policy.NormalizeHost(name)
	d := HTTPData{Method: "CONNECT", Host: host, Port: 443, QUIC: true, Transparent: true, SNI: name, Decision: policy.ActionAllow}
	runID, runCg, eff, isRun := s.api.RunFor(leaf)
	if !isRun {
		if p := findRunCgroupPath(s.agentsDir, leaf); p != "" {
			// A run from before this node agent started: unprofiled.
			runID, runCg, isRun = strings.TrimPrefix(p[strings.LastIndex(p, "/")+1:], RunPrefix), leaf, true
		}
	}
	refuse := func(reason, msg string) quicVerdict {
		d.Decision, d.Enforced, d.Reason, d.Message = policy.ActionDeny, true, reason, msg
		s.record(leaf, runCg, runID, d)
		return quicVerdict{msg: msg, runID: runID}
	}
	switch {
	case !isRun:
		return quicVerdict{msg: "This QUIC relay serves governed agent runs only."}
	case parseErr != nil:
		if d.Host == "" {
			d.Host = "(unknown)"
		}
		return refuse("quic: unreadable", "The QUIC relay could not read this connection's server name ("+parseErr.Error()+"); use TCP.")
	case ech:
		return refuse("quic: encrypted client hello",
			"The QUIC connection hides its server name (encrypted ClientHello), so the relay cannot decide it; use TCP.")
	case host == "" || !policy.ValidHostname(host):
		d.Host = "(no server name)"
		return refuse("quic: no server name", "QUIC is relayed by server name, and this connection named none; use TCP.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if why := s.guard(ctx, host, netip.Addr{}); why != "" {
		return refuse("guard: "+why, "Egress to "+host+":443 is refused: "+why+".")
	}
	if eff != nil {
		ed := eff.Decide(policy.Request{Host: host, Port: 443, Phase: policy.PhaseConnect})
		d.Decision, d.Rule, d.Layer, d.WouldDeny, d.Enforced, d.Message = ed.Action, ed.Rule, ed.Layer, ed.WouldDeny, ed.Enforced, ed.Message
		switch {
		case !ed.Allowed() && ed.Enforced:
			s.record(leaf, runCg, runID, d)
			return quicVerdict{msg: ed.Message, runID: runID}
		case ed.Deferred || eff.InspectsContent(host) || eff.GovernsRemoteMCP(host):
			return refuse("quic: needs termination", fmt.Sprintf("Rules for %s need what is sent inside the connection, "+
				"which this node reads only over TCP; QUIC to it is refused.", host))
		case ed.Asks():
			return refuse("quic: ask", fmt.Sprintf("Connections to %s need a person's approval, which is asked over TCP; QUIC to it is refused.", host))
		}
		if d.Decision == policy.ActionAsk {
			d.Decision = policy.ActionAllow
		}
		if ok, wait := s.checkRates(&d, ed, eff, runID, true, true); !ok {
			d.Message += fmt.Sprintf(" (retry in %s)", retryIn(wait))
			s.record(leaf, runCg, runID, d)
			return quicVerdict{msg: d.Message, runID: runID}
		}
	} else {
		d.Reason = "unprofiled run"
	}
	up, ok := s.resolvedAddr(host)
	if !ok {
		return refuse("quic: unresolved", "The QUIC relay could not resolve "+host+"; use TCP.")
	}
	d.Upstream = up.String()
	s.record(leaf, runCg, runID, d)
	return quicVerdict{allowed: true, upstream: up, runID: runID}
}

// resolvedAddr is an address host resolved to when the guard looked,
// IPv4 first: where a relayed QUIC connection goes.
func (s *ExtProcServer) resolvedAddr(host string) (netip.AddrPort, bool) {
	s.cacheMu.Lock()
	r := s.cache[host]
	s.cacheMu.Unlock()
	var v6 netip.Addr
	for _, a := range r.addrs {
		if a.Unmap().Is4() {
			return netip.AddrPortFrom(a.Unmap(), 443), true
		}
		if !v6.IsValid() {
			v6 = a
		}
	}
	if v6.IsValid() {
		return netip.AddrPortFrom(v6, 443), true
	}
	return netip.AddrPort{}, false
}
