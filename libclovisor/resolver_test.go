// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// svcbData builds SVCB RDATA: priority 1, target ".", then params.
func svcbData(params ...[]byte) []byte {
	b := []byte{0, 1, 0}
	for _, p := range params {
		b = append(b, p...)
	}
	return b
}

func svcParam(key uint16, v []byte) []byte {
	b := make([]byte, 4, 4+len(v))
	binary.BigEndian.PutUint16(b, key)
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	return append(b, v...)
}

var (
	alpnH2  = svcParam(1, []byte{2, 'h', '2'})
	echConf = svcParam(5, []byte{0xfe, 0x0d, 0, 1, 2, 3})
)

// fakeUpstream answers every query with 203.0.113.10, or for HTTPS with a
// record carrying ech. It counts queries.
func fakeUpstream(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var n atomic.Int32
	go func() {
		buf := make([]byte, 4096)
		for {
			l, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			n.Add(1)
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:l])
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
			if q.Type == typeHTTPS {
				b.UnknownResource(rh, dnsmessage.UnknownResource{Type: typeHTTPS, Data: svcbData(svcParam(0, []byte{0, 5}), alpnH2, echConf)})
			} else {
				b.AResource(rh, dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}})
			}
			out, _ := b.Finish()
			pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String(), &n
}

func query(name string, typ dnsmessage.Type, edns bool) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET})
	if edns {
		b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	out, _ := b.Finish()
	return out
}

func newTestResolver(t *testing.T, enforce bool) (*Resolver, chan AuditEvent, *atomic.Int32) {
	t.Helper()
	up, n := fakeUpstream(t)
	cm := &CgroupManager{agents: t.TempDir(), runMap: map[string]string{}}
	api := &RunAPIServer{cm: cm, active: map[string]bool{}, bound: map[string]*boundRun{},
		byCg: map[uint64]*boundRun{}, runByCg: map[uint64]string{}, runCg: map[string]uint64{}}
	p, err := policy.Parse([]byte(xpProfile))
	if err != nil {
		t.Fatal(err)
	}
	// xpProfile's catch-all would allow every name; drop it.
	p.Spec.Egress.Rules = p.Spec.Egress.Rules[:len(p.Spec.Egress.Rules)-1]
	comp, diags := policy.Compile(policy.Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	const cg = 4242
	api.runByCg[cg], api.runCg["testrun"] = "testrun", cg
	b := &boundRun{runID: "testrun", cgroupID: cg, eff: &policy.Effective{Layers: []policy.Layer{{Profile: comp.Profiles[0], Source: "granted"}}}}
	api.bound["testrun"], api.byCg[cg] = b, b
	events := make(chan AuditEvent, 16)
	r := &Resolver{api: api, agentsDir: cm.agents, enforce: enforce, upstreams: []string{up}, events: events}
	// Port 1 is the run's client; anything else is outside any run.
	r.lookupUDP = func(client, _ netip.AddrPort) (uint64, error) {
		if client.Port() == 1 {
			return cg, nil
		}
		return 99, nil
	}
	r.lookupTCP = r.lookupUDP
	return r, events, n
}

var (
	runClient   = netip.MustParseAddrPort("127.0.0.1:1")
	otherClient = netip.MustParseAddrPort("127.0.0.1:2")
	resolverAt  = netip.MustParseAddrPort("127.0.0.1:15053")
)

func parseReply(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestResolverEnforce(t *testing.T) {
	r, events, upstream := newTestResolver(t, true)

	// An allowed name is forwarded and recorded.
	m := parseReply(t, r.answer(query("github.com", dnsmessage.TypeA, false), "udp", runClient, resolverAt))
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || m.Header.ID != 0x1234 {
		t.Fatalf("allowed name: %+v", m)
	}
	d := (<-events).Data.(DNSData)
	if d.Decision != "allow" || d.Rule != "gh" || d.Query != "github.com" || len(d.Addrs()) != 1 || d.Server == "" {
		t.Fatalf("event: %+v", d)
	}

	// A name no rule allows never leaves the node: NXDOMAIN, with the
	// reason as an Extended DNS Error.
	before := upstream.Load()
	m = parseReply(t, r.answer(query("aGVsbG8.x7k2.exfil.example", dnsmessage.TypeTXT, true), "udp", runClient, resolverAt))
	if m.Header.RCode != dnsmessage.RCodeNameError || upstream.Load() != before {
		t.Fatalf("blocked name: rcode %v, upstream queried %d times", m.Header.RCode, upstream.Load()-before)
	}
	var ede string
	for _, a := range m.Additionals {
		if o, ok := a.Body.(*dnsmessage.OPTResource); ok {
			for _, opt := range o.Options {
				if opt.Code == 15 && len(opt.Data) > 2 && binary.BigEndian.Uint16(opt.Data) == edeBlocked {
					ede = string(opt.Data[2:])
				}
			}
		}
	}
	if !strings.Contains(ede, "not resolved") {
		t.Errorf("EDE text: %q", ede)
	}
	if d := (<-events).Data.(DNSData); !d.Enforced || d.RCode != "NXDomain" || d.Decision != "deny" {
		t.Fatalf("blocked event: %+v", d)
	}

	// ECH is removed from HTTPS answers, other parameters kept, and the
	// mandatory list no longer names it.
	m = parseReply(t, r.answer(query("api.github.com", typeHTTPS, false), "udp", runClient, resolverAt))
	if len(m.Answers) != 1 {
		t.Fatalf("HTTPS answer: %+v", m)
	}
	rd := m.Answers[0].Body.(*dnsmessage.UnknownResource).Data
	if !bytes.Equal(rd, svcbData(alpnH2)) {
		t.Fatalf("HTTPS rdata after stripping: %x", rd)
	}
	if d := (<-events).Data.(DNSData); d.ECHStripped != 1 {
		t.Fatalf("ech count: %+v", d)
	}

	// Clients outside any run are not served.
	m = parseReply(t, r.answer(query("github.com", dnsmessage.TypeA, false), "udp", otherClient, resolverAt))
	if m.Header.RCode != dnsmessage.RCodeRefused || len(events) != 0 {
		t.Fatalf("non-run client: %v, %d events", m.Header.RCode, len(events))
	}
	// Garbage gets no answer.
	if r.answer([]byte{1, 2, 3}, "udp", runClient, resolverAt) != nil {
		t.Error("answered garbage")
	}
}

func TestResolverAudit(t *testing.T) {
	r, events, upstream := newTestResolver(t, false)
	m := parseReply(t, r.answer(query("evil.example", dnsmessage.TypeA, false), "udp", runClient, resolverAt))
	if m.Header.RCode != dnsmessage.RCodeSuccess || upstream.Load() != 1 {
		t.Fatalf("audit mode: %v, upstream %d", m.Header.RCode, upstream.Load())
	}
	d := (<-events).Data.(DNSData)
	if d.Enforced || d.Decision != "allow" || len(d.WouldDeny) != 1 || d.Reason != "transparent audit" {
		t.Fatalf("audit event: %+v", d)
	}
}

func TestStripSvcParam(t *testing.T) {
	// Nothing to strip: unchanged.
	if out, ok := stripSvcParam(svcbData(alpnH2), svcKeyECH); ok || !bytes.Equal(out, svcbData(alpnH2)) {
		t.Error("changed a record without ech")
	}
	// ech only in mandatory, with another key: that key stays mandatory.
	in := svcbData(svcParam(0, []byte{0, 1, 0, 5}), alpnH2, echConf)
	want := svcbData(svcParam(0, []byte{0, 1}), alpnH2)
	if out, ok := stripSvcParam(in, svcKeyECH); !ok || !bytes.Equal(out, want) {
		t.Errorf("got %x, want %x", out, want)
	}
	// Malformed: left alone.
	for _, bad := range [][]byte{{0}, {0, 1, 3, 'a'}, append(svcbData(), 0, 5, 0, 9)} {
		if _, ok := stripSvcParam(bad, svcKeyECH); ok {
			t.Errorf("changed malformed %x", bad)
		}
	}
}

func TestSystemResolvers(t *testing.T) {
	f := t.TempDir() + "/resolv.conf"
	os.WriteFile(f, []byte("# c\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\nnameserver bogus\n"), 0o644)
	got, err := SystemResolvers(f)
	if err != nil || strings.Join(got, ",") != "127.0.0.53:53,[fe80::1]:53" {
		t.Fatalf("%v %v", got, err)
	}
	os.WriteFile(f, []byte("search x\n"), 0o644)
	if _, err := SystemResolvers(f); err == nil {
		t.Error("no nameservers accepted")
	}
}
