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
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// RFC 9001 Appendix A.1: the Initial keys for connection id
// 0x8394c8f03e515708.
func TestInitialKeysRFC9001(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	initial := hkdfExtract(quicSaltV1, dcid)
	for label, want := range map[string][3]string{
		"client in": {"1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		"server in": {"cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314"},
	} {
		secret := expandLabel(initial, label, 32)
		got := [3]string{hex.EncodeToString(expandLabel(secret, "quic key", 16)), hex.EncodeToString(expandLabel(secret, "quic iv", 12)),
			hex.EncodeToString(expandLabel(secret, "quic hp", 16))}
		if got != want {
			t.Errorf("%s: %v, want %v", label, got, want)
		}
	}
}

// testHello is a minimal TLS ClientHello naming name, with extra bytes in
// a padding extension (to make it span datagrams) and, if ech, an
// encrypted_client_hello extension.
func testHello(name string, extra int, ech bool) []byte {
	var exts []byte
	ext := func(typ uint16, body []byte) {
		exts = binary.BigEndian.AppendUint16(exts, typ)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(body)))
		exts = append(exts, body...)
	}
	if name != "" {
		sn := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
		sn = append(sn, 0)
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(name)))
		ext(0, append(sn, name...))
	}
	if ech {
		ext(0xfe0d, []byte{0})
	}
	ext(21, make([]byte, extra)) // padding
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = append(body, 0, 2, 0x13, 0x01)    // one cipher suite
	body = append(body, 1, 0)                // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

var testDCID = []byte{1, 2, 3, 4, 5, 6, 7, 8}
var testSCID = []byte{9, 9, 9, 9}

// clientInitials splits hello into CRYPTO frames over datagrams of at
// most per bytes of it, each a client Initial padded to 1200 bytes.
func clientInitials(hello []byte, per int) [][]byte {
	k := newInitialKeys(testDCID, "client in")
	var out [][]byte
	for off := 0; off < len(hello); off += per {
		end := min(off+per, len(hello))
		f := []byte{0x06}
		f = appendVarint(f, uint64(off))
		f = appendVarint(f, uint64(end-off))
		f = append(f, hello[off:end]...)
		pkt := sealInitial(k, testDCID, testSCID, append(f, make([]byte, 1200-len(f)-60)...))
		out = append(out, pkt)
	}
	return out
}

func TestClientHelloName(t *testing.T) {
	// One datagram.
	var c clientHello
	if err := c.add(clientInitials(testHello("api.example.com", 10, false), 4000)[0]); err != nil {
		t.Fatal(err)
	}
	if name, ech, err := helloServerName(c.contiguous()); name != "api.example.com" || ech || err != nil {
		t.Fatalf("one datagram: %q %v %v", name, ech, err)
	}
	// Split over two, as post-quantum key shares make it.
	dgrams := clientInitials(testHello("big.example.com", 1500, true), 1000)
	var c2 clientHello
	c2.add(dgrams[0])
	if _, _, err := helloServerName(c2.contiguous()); err != errHelloIncomplete {
		t.Fatalf("first half: %v", err)
	}
	c2.add(dgrams[1])
	if name, ech, err := helloServerName(c2.contiguous()); name != "big.example.com" || !ech || err != nil {
		t.Fatalf("two datagrams: %q %v %v", name, ech, err)
	}
	// What is refused.
	bad := append([]byte(nil), dgrams[0]...)
	bad[40] ^= 1
	v2 := append([]byte(nil), dgrams[0]...)
	v2[1], v2[2], v2[3], v2[4] = 0x6b, 0x33, 0x43, 0xcf
	for name, pkt := range map[string][]byte{"tampered": bad, "version 2": v2, "short header": {0x40, 1, 2, 3}} {
		var c clientHello
		if err := c.add(pkt); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := helloServerName([]byte{2, 0, 0, 1, 0}); err == nil {
		t.Error("not a ClientHello accepted")
	}
}

// readClose decrypts a server Initial and returns its CONNECTION_CLOSE
// reason.
func readClose(t *testing.T, pkt []byte) string {
	t.Helper()
	k := newInitialKeys(testDCID, "server in")
	p := 6 + int(pkt[5])
	if string(pkt[6:p]) != string(testSCID) {
		t.Fatalf("close not addressed to the client's id")
	}
	p += 1 + int(pkt[p])
	p++ // token length 0
	length := int(binary.BigEndian.Uint16(pkt[p:]) & 0x3fff)
	p += 2
	mask := make([]byte, 16)
	k.hp.Encrypt(mask, pkt[p+4:p+20])
	hdr := append([]byte(nil), pkt[:p+2]...)
	hdr[0] ^= mask[0] & 0x0f
	hdr[p] ^= mask[1]
	hdr[p+1] ^= mask[2]
	pl, err := k.aead.Open(nil, k.nonce(uint64(hdr[p])<<8|uint64(hdr[p+1])), pkt[p+2:p+length], hdr)
	if err != nil {
		t.Fatalf("close does not decrypt: %v", err)
	}
	if pl[0] != 0x1c || pl[1] != 0x02 {
		t.Fatalf("not CONNECTION_REFUSED: %x", pl[:4])
	}
	n, w, _ := quicVarint(pl[3:])
	return string(pl[3+w : 3+w+int(n)])
}

func TestServerClose(t *testing.T) {
	var c clientHello
	c.add(clientInitials(testHello("x.example", 0, false), 4000)[0])
	if got := readClose(t, serverClose(&c, "No rule allows x.example:443.")); got != "No rule allows x.example:443." {
		t.Errorf("reason %q", got)
	}
}

const quicXP = `kind: AgentProfile
metadata: { name: qx }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: plain, to: { fqdn: ["plain.example.com"], ports: [443] }, action: allow }
      - name: paths
        to: { fqdn: ["paths.example.com"] }
        http: { paths: ["/x"] }
        action: allow
      - { name: asked, to: { fqdn: ["asked.example.com"] }, action: ask }
`

func TestQUICRelay(t *testing.T) {
	xp, events, _ := modelFixture(t, quicXP)
	cg := ownCgroupID(t)
	// The upstream: an echo server standing in for the name's address.
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	var mu sync.Mutex
	var got [][]byte
	go func() {
		b := make([]byte, 65536)
		for {
			n, from, err := up.ReadFromUDP(b)
			if err != nil {
				return
			}
			mu.Lock()
			got = append(got, append([]byte(nil), b[:n]...))
			mu.Unlock()
			up.WriteToUDP([]byte("reply"), from)
		}
	}()
	r, err := NewQUICRelay(xp, 0)
	if err != nil {
		t.Fatal(err)
	}
	var dialed []netip.AddrPort
	r.identify = func(client, server netip.AddrPort) (uint64, error) { return cg, nil }
	r.dial = func(to netip.AddrPort) (*net.UDPConn, error) {
		dialed = append(dialed, to)
		return net.DialUDP("udp", nil, up.LocalAddr().(*net.UDPAddr))
	}
	go r.Serve()
	defer r.Close()
	relay := r.conns[0].LocalAddr().(*net.UDPAddr)

	send := func(dgrams [][]byte) ([]byte, error) {
		c, err := net.DialUDP("udp", nil, relay)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for _, d := range dgrams {
			c.Write(d)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 2048)
		n, err := c.Read(b)
		return b[:n], err
	}

	// Allowed: held until the ClientHello is complete, then forwarded
	// untouched to the name's address, and the reply relayed.
	dgrams := clientInitials(testHello("plain.example.com", 1500, false), 1000)
	reply, err := send(dgrams)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("allowed: %q %v", reply, err)
	}
	mu.Lock()
	if len(got) != 2 || !bytes.Equal(got[0], dgrams[0]) || !bytes.Equal(got[1], dgrams[1]) {
		t.Errorf("forwarded %d datagrams, changed: %v", len(got), len(got) == 2 && !bytes.Equal(got[0], dgrams[0]))
	}
	mu.Unlock()
	if len(dialed) != 1 || dialed[0] != netip.MustParseAddrPort("203.0.113.10:443") {
		t.Errorf("dialed %v: want the name's address", dialed)
	}

	// Refused, with the narration in a CONNECTION_CLOSE.
	for host, want := range map[string]string{
		"denied.example.com": "No rule in profile qx allows denied.example.com:443.",
		"paths.example.com":  "Rules for paths.example.com need what is sent inside the connection",
		"asked.example.com":  "need a person's approval, which is asked over TCP",
	} {
		reply, err := send(clientInitials(testHello(host, 0, false), 4000))
		if err != nil {
			t.Fatalf("%s: no close: %v", host, err)
		}
		if reason := readClose(t, reply); !strings.Contains(reason, want) {
			t.Errorf("%s: %q, want %q", host, reason, want)
		}
	}
	if reply, err := send(clientInitials(testHello("hidden.example.com", 0, true), 4000)); err != nil ||
		!strings.Contains(readClose(t, reply), "encrypted ClientHello") {
		t.Errorf("ECH: %v", err)
	}

	var recs []string
	for len(events) > 0 {
		if d, ok := (<-events).Data.(HTTPData); ok && d.QUIC {
			recs = append(recs, d.Host+":"+d.Decision+":"+d.Reason+":"+d.Upstream)
		}
	}
	for _, w := range []string{"plain.example.com:allow::203.0.113.10:443", "denied.example.com:deny::", "paths.example.com:deny:quic: needs termination:",
		"asked.example.com:deny:quic: ask:", "hidden.example.com:deny:quic: encrypted client hello:"} {
		found := false
		for _, r := range recs {
			found = found || r == w
		}
		if !found {
			t.Errorf("records lack %q: %v", w, recs)
		}
	}
}

// A relayed connection is recorded as a CONNECT, so learn drafts a host
// rule and check replays it.
func TestQUICRecorded(t *testing.T) {
	r := newTestRecorder(t)
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		AuditEvent{Type: EventHTTP, Timestamp: at(1), CgroupID: testRunCg, RunCgroupID: testRunCg,
			Data: HTTPData{Method: "CONNECT", Host: "plain.example.com", Port: 443, Decision: "allow", QUIC: true, Upstream: "203.0.113.10:443"}},
		runEv(EventRunEnd, 2, "/agents/run-abc"),
	)
	if p := tl.Summary.Proxied; len(p) != 1 || p[0].Tunnels != 1 {
		t.Fatalf("proxied: %+v", p)
	}
	var note string
	for _, e := range tl.Events {
		if e.Type == "http" {
			note = e.Note
		}
	}
	if note != "QUIC to 203.0.113.10:443" {
		t.Errorf("note %q", note)
	}
}

// check --transparent --quic replays refused UDP 443 by the names the run
// looked up, as the relay would decide it.
func TestCheckQUIC(t *testing.T) {
	end := at(10)
	tl := &RunTimeline{RunID: "r1", StartedAt: at(0), EndedAt: &end, Complete: true, Summary: RunSummary{
		UDPRefusedTo: []Destination{{Proto: "UDP", IP: "203.0.113.10", Port: 443, Count: 2,
			Names: []string{"paths.example.com", "plain.example.com"}}}}}
	cp := compileOne(t, quicXP)
	rep := CheckRunsWith(cp, []*RunTimeline{tl}, CheckOptions{Transparent: true, QUIC: true})
	var allowed, denied []string
	for _, f := range rep.Allowed {
		allowed = append(allowed, f.What+" "+f.Rule)
	}
	for _, f := range rep.Violations {
		denied = append(denied, f.What+" "+f.Message)
	}
	if strings.Join(allowed, ",") != "UDP 203.0.113.10:443 (plain.example.com, QUIC) plain (QUIC relay)" ||
		len(denied) != 1 || !strings.Contains(denied[0], "paths.example.com, QUIC) QUIC is refused where the rule needs termination") {
		t.Errorf("allowed %q\ndenied %q", allowed, denied)
	}
	// Without the relay, UDP 443 is refused like other UDP.
	rep = CheckRunsWith(cp, []*RunTimeline{tl}, CheckOptions{Transparent: true})
	if len(rep.Violations) != 1 || !strings.Contains(rep.Violations[0].Message, "QUIC: clients fall back to TCP") {
		t.Errorf("without -quic: %+v", rep.Violations)
	}
}
