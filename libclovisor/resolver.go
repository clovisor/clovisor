// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Resolver is the node's forced DNS resolver (milestone 3.4, design §6.8).
// In transparent audit and enforce mode every DNS query from a run, UDP or
// TCP, to any server, is redirected here by the connect and sendmsg hooks.
//
// It answers only names some rule in the run's effective policy could
// allow, and NXDOMAIN otherwise, so a name outside policy never leaves the
// node: that is what closes DNS tunnelling. In audit mode it answers
// everything and records what enforce would refuse. It strips the ech
// parameter from HTTPS and SVCB answers, so clients send a cleartext SNI
// the transparent listener can route by. It records every query in the
// run's timeline.
type Resolver struct {
	api       *RunAPIServer
	agentsDir string
	enforce   bool
	upstreams []string
	events    chan<- AuditEvent
	dropped   atomic.Uint64
	// lookup finds a client socket's cgroup: SockCgroupUDP or SockCgroup.
	lookupUDP, lookupTCP func(client, server netip.AddrPort) (uint64, error)

	packets []net.PacketConn
	streams []net.Listener
	wg      sync.WaitGroup
}

// resolverTimeout bounds one upstream exchange.
const resolverTimeout = 3 * time.Second

// NewResolver listens on 127.0.0.1 and ::1 (UDP and TCP) at port, and
// forwards allowed queries to upstreams ("ip:port"; the host's resolvers
// if empty). With enforce false it answers every name.
func NewResolver(api *RunAPIServer, agentsDir string, port uint16, upstreams []string, enforce bool, events chan<- AuditEvent) (*Resolver, error) {
	if len(upstreams) == 0 {
		var err error
		if upstreams, err = SystemResolvers("/etc/resolv.conf"); err != nil {
			return nil, err
		}
	}
	r := &Resolver{api: api, agentsDir: agentsDir, enforce: enforce, upstreams: upstreams, events: events,
		lookupUDP: SockCgroupUDP, lookupTCP: SockCgroup}
	for _, host := range []string{"127.0.0.1", "::1"} {
		addr := net.JoinHostPort(host, fmt.Sprint(port))
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			if host == "::1" {
				log.Printf("resolver: no IPv6 loopback (%v); IPv6 DNS from runs will fail", err)
				continue
			}
			r.Close()
			return nil, err
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close()
			r.Close()
			return nil, err
		}
		r.packets = append(r.packets, pc)
		r.streams = append(r.streams, ln)
	}
	return r, nil
}

// SystemResolvers reads the nameservers of a resolv.conf file.
func SystemResolvers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("resolver upstreams: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 && fs[0] == "nameserver" {
			if a, err := netip.ParseAddr(fs[1]); err == nil {
				out = append(out, netip.AddrPortFrom(a.WithZone(""), 53).String())
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolver upstreams: no nameserver in %s", path)
	}
	return out, nil
}

// Serve answers queries until Close.
func (r *Resolver) Serve() {
	for _, pc := range r.packets {
		r.wg.Add(1)
		go r.serveUDP(pc)
	}
	for _, ln := range r.streams {
		r.wg.Add(1)
		go r.serveTCP(ln)
	}
	r.wg.Wait()
}

// Close stops serving.
func (r *Resolver) Close() {
	for _, pc := range r.packets {
		pc.Close()
	}
	for _, ln := range r.streams {
		ln.Close()
	}
}

func (r *Resolver) serveUDP(pc net.PacketConn) {
	defer r.wg.Done()
	server := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		client := from.(*net.UDPAddr).AddrPort()
		go func() {
			if resp := r.answer(q, "udp", client, server); resp != nil {
				pc.WriteTo(resp, from)
			}
		}()
	}
}

func (r *Resolver) serveTCP(ln net.Listener) {
	defer r.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer c.Close()
			client := c.RemoteAddr().(*net.TCPAddr).AddrPort()
			server := c.LocalAddr().(*net.TCPAddr).AddrPort()
			for {
				c.SetDeadline(time.Now().Add(30 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				resp := r.answer(q, "tcp", client, server)
				if resp == nil || writeTCPMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}

func readTCPMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	m := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, m)
	return m, err
}

func writeTCPMsg(w io.Writer, m []byte) error {
	b := make([]byte, 2+len(m))
	binary.BigEndian.PutUint16(b, uint16(len(m)))
	copy(b[2:], m)
	_, err := w.Write(b)
	return err
}

// answer decides one query and returns the reply, or nil to send none.
func (r *Resolver) answer(q []byte, proto string, client, server netip.AddrPort) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return reply(h, nil, dnsmessage.RCodeFormatError, "")
	}
	question := qs[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")

	// The client's socket's cgroup: a claim the client cannot make.
	lookup := r.lookupUDP
	if proto == "tcp" {
		lookup = r.lookupTCP
	}
	runID, runCg, eff, isRun := "", uint64(0), (*policy.Effective)(nil), false
	if cg, err := lookup(client, server); err == nil {
		runID, runCg, eff, isRun = r.api.RunFor(cg)
		if !isRun {
			if p := findRunCgroupPath(r.agentsDir, cg); p != "" {
				runID, runCg, isRun = strings.TrimPrefix(p[strings.LastIndex(p, "/")+1:], RunPrefix), cg, true
			}
		}
	}
	if !isRun {
		// Only runs are sent here; anyone else is not served.
		return reply(h, &question, dnsmessage.RCodeRefused, "")
	}

	d := DNSData{Query: name, QType: dnsTypeName(question.Type), Decision: policy.ActionAllow}
	if eff == nil {
		d.Reason = "unprofiled run"
	} else {
		ed := eff.DecideName(name)
		d.Decision, d.Rule, d.Layer, d.WouldDeny, d.Message = ed.Action, ed.Rule, ed.Layer, ed.WouldDeny, ed.Message
		if !ed.Allowed() && ed.Enforced {
			if r.enforce {
				d.Enforced, d.RCode = true, "NXDomain"
				r.record(runCg, runID, d)
				return reply(h, &question, dnsmessage.RCodeNameError, "Clovisor: "+ed.Message)
			}
			// Transparent audit: answered, recorded as would-deny.
			d.Decision, d.WouldDeny = policy.ActionAllow, append(d.WouldDeny, ed.Layer)
			d.Reason = "transparent audit"
		}
	}

	resp, upstream, err := r.forward(q, proto)
	if err != nil {
		d.RCode, d.Reason = "ServFail", "upstream: "+err.Error()
		r.record(runCg, runID, d)
		return reply(h, &question, dnsmessage.RCodeServerFailure, "")
	}
	resp, d.ECHStripped = stripECH(resp)
	if parsed, err := parseDNSResponse(resp, false); err == nil {
		d.RCode, d.Answers = parsed.RCode, parsed.Answers
	}
	d.Server = upstream
	r.record(runCg, runID, d)
	return resp
}

// forward sends q to the first upstream that answers.
func (r *Resolver) forward(q []byte, proto string) ([]byte, string, error) {
	var last error
	for _, up := range r.upstreams {
		resp, err := exchange(q, proto, up)
		if err == nil {
			return resp, up, nil
		}
		last = err
	}
	return nil, "", last
}

func exchange(q []byte, proto, upstream string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolverTimeout)
	defer cancel()
	var dialer net.Dialer
	c, err := dialer.DialContext(ctx, proto, upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(resolverTimeout))
	if proto == "tcp" {
		if err := writeTCPMsg(c, q); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// A connected UDP socket only hears from upstream; still, match
		// the id, as a resolver must.
		if n >= 2 && buf[0] == q[0] && buf[1] == q[1] {
			return buf[:n], nil
		}
	}
}

func (r *Resolver) record(runCg uint64, runID string, d DNSData) {
	if r.events == nil || runCg == 0 {
		return
	}
	ev := AuditEvent{Type: EventDNS, Timestamp: time.Now(), CgroupID: runCg, RunCgroupID: runCg, Data: d}
	select {
	case r.events <- ev:
	default:
		if n := r.dropped.Add(1); n%100 == 1 {
			log.Printf("resolver: event queue full; %d queries not recorded", n)
		}
	}
}

// EDE info code 15, Blocked (RFC 8914).
const edeBlocked = 15

// reply builds a response with no answers. With text and an EDNS query, it
// carries an Extended DNS Error saying why: the one narration channel DNS
// has (dig prints it as EDE).
func reply(h dnsmessage.Header, q *dnsmessage.Question, rcode dnsmessage.RCode, text string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	b.StartQuestions()
	if q != nil {
		b.Question(*q)
	}
	if text != "" {
		b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		data := make([]byte, 2+len(text))
		binary.BigEndian.PutUint16(data, edeBlocked)
		copy(data[2:], text)
		b.OPTResource(rh, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 15, Data: data}}})
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// DNS types carrying SvcParams (RFC 9460).
const (
	typeSVCB        dnsmessage.Type = 64
	typeHTTPS       dnsmessage.Type = 65
	svcKeyMandatory                 = 0
	svcKeyECH                       = 5
)

// stripECH removes the ech SvcParam from every HTTPS and SVCB record, so
// clients fall back to a cleartext server name (design §6.6). It returns
// the message unchanged if there is nothing to strip or it cannot be
// parsed, and how many records it changed.
func stripECH(m []byte) ([]byte, int) {
	var msg dnsmessage.Message
	if err := msg.Unpack(m); err != nil {
		return m, 0
	}
	n := 0
	for _, sec := range [][]dnsmessage.Resource{msg.Answers, msg.Authorities, msg.Additionals} {
		for i := range sec {
			t := sec[i].Header.Type
			u, ok := sec[i].Body.(*dnsmessage.UnknownResource)
			if !ok || (t != typeSVCB && t != typeHTTPS) {
				continue
			}
			if data, changed := stripSvcParam(u.Data, svcKeyECH); changed {
				sec[i].Body = &dnsmessage.UnknownResource{Type: t, Data: data}
				n++
			}
		}
	}
	if n == 0 {
		return m, 0
	}
	out, err := msg.Pack()
	if err != nil {
		return m, 0
	}
	return out, n
}

// stripSvcParam removes key from SVCB RDATA: priority, an uncompressed
// target name, then key-sorted params. A mandatory list naming key loses
// it too, or the record would be invalid.
func stripSvcParam(rd []byte, key uint16) ([]byte, bool) {
	if len(rd) < 3 {
		return rd, false
	}
	i := 2
	for {
		if i >= len(rd) {
			return rd, false
		}
		l := int(rd[i])
		if l&0xc0 != 0 {
			return rd, false // compression is not allowed here
		}
		i += 1 + l
		if l == 0 {
			break
		}
	}
	out := append([]byte(nil), rd[:i]...)
	changed := false
	for i < len(rd) {
		if i+4 > len(rd) {
			return rd, false
		}
		k := binary.BigEndian.Uint16(rd[i:])
		l := int(binary.BigEndian.Uint16(rd[i+2:]))
		if i+4+l > len(rd) {
			return rd, false
		}
		v := rd[i+4 : i+4+l]
		i += 4 + l
		switch k {
		case key:
			changed = true
			continue
		case svcKeyMandatory:
			var keep []byte
			for j := 0; j+2 <= len(v); j += 2 {
				if binary.BigEndian.Uint16(v[j:]) != key {
					keep = append(keep, v[j:j+2]...)
				} else {
					changed = true
				}
			}
			if len(keep) == 0 {
				continue
			}
			v = keep
		}
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:], k)
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(v)))
		out = append(append(out, hdr[:]...), v...)
	}
	return out, changed
}
