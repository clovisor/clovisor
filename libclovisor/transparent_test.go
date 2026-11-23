// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

func TestTransparentOptions(t *testing.T) {
	var o TransparentOptions
	if err := o.normalize(); err != nil || o.Mode != TransparentOff || o.Port != DefaultTransparentPort || o.PinDir != DefaultBPFPinDir {
		t.Fatalf("defaults: %+v %v", o, err)
	}
	if err := (&TransparentOptions{Mode: "on"}).normalize(); err == nil {
		t.Error("bad mode accepted")
	}
	five := make([]netip.AddrPort, maxTransparentExceptions+1)
	if err := (&TransparentOptions{Exceptions: five}).normalize(); err == nil {
		t.Error("too many exceptions accepted")
	}
	for mode, want := range map[string]policy.DeploymentMode{TransparentOff: policy.ExplicitProxy,
		TransparentAudit: policy.TransparentAudit, TransparentEnforce: policy.Transparent} {
		if got := (TransparentOptions{Mode: mode}).DeploymentMode(); got != want {
			t.Errorf("%s: %s", mode, got)
		}
	}
}

func TestTransparentReceipt(t *testing.T) {
	p, _ := policy.Parse([]byte(xpProfile))
	for mode, want := range map[policy.DeploymentMode]string{
		policy.Transparent:      "Routing     enforced: every TCP connect",
		policy.TransparentAudit: "Routing     advisory, auditing",
		policy.ExplicitProxy:    "Routing     advisory: only traffic sent to the proxy",
	} {
		c, diags := policy.Compile(policy.Options{Mode: mode, Linux: true}, p)
		if len(diags) > 0 {
			t.Fatal(diags)
		}
		var b strings.Builder
		c.WriteReceipt(&b)
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s receipt lacks %q:\n%s", mode, want, b.String())
		}
	}
	if _, diags := policy.Compile(policy.Options{Mode: policy.Transparent}, p); len(diags) == 0 {
		t.Error("transparent mode compiled off Linux")
	}
}

func TestEnvoyBootstrapTransparent(t *testing.T) {
	b, err := EnvoyBootstrap(EnvoyConfig{ProxyListen: netip.MustParseAddrPort("127.0.0.1:18000"),
		ExtProcSocket: "/run/clovisor/extproc.sock", AdminSocket: "/run/clovisor/admin.sock", TransparentPort: 15001})
	if err != nil {
		t.Fatal(err)
	}
	var boot struct {
		BootstrapExtensions []interface{} `json:"bootstrap_extensions"`
		StaticResources     struct {
			Listeners []map[string]interface{} `json:"listeners"`
		} `json:"static_resources"`
	}
	if err := json.Unmarshal(b, &boot); err != nil {
		t.Fatal(err)
	}
	if len(boot.BootstrapExtensions) == 0 {
		t.Error("no internal listener extension")
	}
	names := map[string]map[string]interface{}{}
	for _, l := range boot.StaticResources.Listeners {
		names[l["name"].(string)] = l
	}
	tl, ok := names["transparent"]
	if !ok || names["transparent-connect"] == nil {
		t.Fatalf("listeners: %v", names)
	}
	s, _ := json.Marshal(tl)
	for _, want := range []string{`"address":"127.0.0.1"`, `"address":"::1"`, "original_dst", "tls_inspector", "http_inspector",
		`"continue_on_listener_filters_timeout":true`, `"exact":"15001"`, // the self chain
		"%REQUESTED_SERVER_NAME%:%DOWNSTREAM_LOCAL_PORT%", "%DOWNSTREAM_DIRECT_LOCAL_ADDRESS%", TransparentHTTPRoute} {
		if !strings.Contains(string(s), want) {
			t.Errorf("transparent listener lacks %s", want)
		}
	}
	// Every route strips the headers only Envoy may set before the origin.
	all := string(b)
	if n := strings.Count(all, `"request_headers_to_remove"`); n != 3 {
		t.Errorf("%d route configs strip headers, want 3 (proxy, transparent-connect, transparent http)", n)
	}
	for _, h := range ownHeaders {
		if strings.Count(all, `"`+h+`"`) < 3 {
			t.Errorf("%s not stripped everywhere", h)
		}
	}

	// Without a transparent port, none of it.
	b, _ = EnvoyBootstrap(EnvoyConfig{ProxyListen: netip.MustParseAddrPort("127.0.0.1:18000"),
		ExtProcSocket: "/x", AdminSocket: "/y"})
	if strings.Contains(string(b), "transparent") || strings.Contains(string(b), "bootstrap_extensions") {
		t.Error("transparent listener without a port")
	}
}

func TestExtProcTransparent(t *testing.T) {
	xp, events, c := newTestExtProc(t, true)
	decideReq := func(req *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) (bool, HTTPData) {
		ir := first(xp.onHeaders(context.Background(), req, h)).GetImmediateResponse()
		var d HTTPData
		select {
		case ev := <-events:
			d = ev.Data.(HTTPData)
		default:
		}
		return ir == nil, d
	}
	client := c.src.String() + "," + c.dst.String()

	// TLS tunnelled into the internal listener: CONNECT to the server name.
	inner := map[string]interface{}{"source.address": "envoy://internal_client_address/", "destination.address": "envoy://transparent-connect/"}
	tun := map[string]string{hdrClient: client, hdrConnect: "github.com:443", hdrOrigDst: "203.0.113.10:443", hdrSNI: "github.com"}
	ok, d := decideReq(reqWith(inner, "CONNECT", "github.com:443", "", tun))
	if !ok || !d.Transparent || d.OrigDst != "203.0.113.10:443" || d.SNI != "github.com" || d.AddrMismatch {
		t.Fatalf("transparent CONNECT: %v %+v", ok, d)
	}
	// The client picked an address the name does not resolve to: noted,
	// not refused (Envoy routes by name).
	tun[hdrOrigDst] = "198.51.100.7:443"
	if ok, d = decideReq(reqWith(inner, "CONNECT", "github.com:443", "", tun)); !ok || !d.AddrMismatch {
		t.Fatalf("mismatch: %v %+v", ok, d)
	}

	// Plain HTTP on the transparent route: identity from Envoy's header.
	direct := map[string]interface{}{"source.address": c.src.String(), "destination.address": "203.0.113.20:80",
		"xds.route_name": TransparentHTTPRoute}
	h := map[string]string{hdrClient: client, hdrOrigDst: "203.0.113.20:80"}
	if ok, d = decideReq(reqWith(direct, "GET", "mirror.internal", "/pub/x", h)); !ok || !d.Transparent {
		t.Fatalf("transparent HTTP: %v %+v", ok, d)
	}
	if ok, d = decideReq(reqWith(direct, "GET", "api.github.com", "/admin/users", h)); ok || d.Rule != "no-admin" {
		t.Fatalf("path rule not applied to transparent HTTP: %+v", d)
	}
	// The same headers on the explicit proxy are not trusted: no
	// transparent marking, and identity comes from the socket attributes.
	explicit := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	if ok, d = decideReq(reqWith(explicit, "GET", "mirror.internal", "/pub/x", h)); !ok || d.Transparent {
		t.Fatalf("explicit request with transparent headers: %v %+v", ok, d)
	}
}

func TestRunRecorderTransparentConnects(t *testing.T) {
	r := newTestRecorder(t)
	verdict := func(ms int, ip string, port uint16, v string) AuditEvent {
		ev := connEv(ms, 10, ip, port)
		cd := ev.Data.(ConnectData)
		cd.Verdict = v
		ev.Data = cd
		return ev
	}
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		verdict(1, "203.0.113.10", 443, VerdictRedirect),
		verdict(2, "203.0.113.11", 443, VerdictRefused),
		verdict(3, "127.0.0.1", 3000, "same-run loopback"),
		AuditEvent{Type: EventHTTP, Timestamp: at(4), CgroupID: testRunCg, RunCgroupID: testRunCg,
			Data: HTTPData{Method: "CONNECT", Host: "github.com", Port: 443, Decision: "allow", Transparent: true, OrigDst: "203.0.113.10:443"}},
		runEv(EventRunEnd, 5, "/agents/run-abc"),
	)
	s := tl.Summary
	if s.Redirected != 1 || s.Refused != 1 || s.Connects != 1 || len(s.Destinations) != 1 || s.Destinations[0].IP != "127.0.0.1" {
		t.Fatalf("summary: %+v", s)
	}
	if len(s.Proxied) != 1 || s.Proxied[0].Transparent != 1 {
		t.Fatalf("proxied: %+v", s.Proxied)
	}
	var verdicts []string
	for _, e := range tl.Events {
		if e.Type == "connect" {
			verdicts = append(verdicts, e.Verdict)
		}
	}
	if strings.Join(verdicts, "|") != "redirect|refused: node agent down|same-run loopback" {
		t.Fatalf("connect verdicts: %q", verdicts)
	}
}

func TestRunRecorderUDPAndDrops(t *testing.T) {
	r := newTestRecorder(t)
	udp := connEv(1, 10, "8.8.8.8", 443)
	cd := udp.Data.(ConnectData)
	cd.Protocol, cd.Verdict = "UDP", VerdictUDP
	udp.Data = cd
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		udp,
		AuditEvent{Type: EventDrop, Timestamp: at(2), CgroupID: testRunCg, RunCgroupID: testRunCg,
			Data: DropData{DstIP: "1.1.1.1", Protocol: "ICMP", Count: 3, Enforced: true}},
		AuditEvent{Type: EventDrop, Timestamp: at(3), CgroupID: testRunCg, RunCgroupID: testRunCg,
			Data: DropData{DstIP: "1.1.1.1", Protocol: "ICMP", Count: 2, Enforced: true}},
		runEv(EventRunEnd, 4, "/agents/run-abc"),
	)
	s := tl.Summary
	if s.UDPRefused != 1 || s.Dropped != 5 || s.Connects != 0 || len(s.Destinations) != 0 {
		t.Fatalf("summary: %+v", s)
	}
	drops := 0
	for _, e := range tl.Events {
		if e.Type == "drop" {
			drops++
		}
	}
	if drops != 2 {
		t.Fatalf("%d drop events", drops)
	}
}

func TestRunRecorderLostEvents(t *testing.T) {
	r := newTestRecorder(t)
	lost, suppressed := uint64(7), uint64(0)
	r.LostFor = func(cg uint64) (uint64, uint64) {
		if cg == testRunCg {
			return lost, suppressed
		}
		return 0, 0
	}
	tl := feed(t, r, runEv(EventRunStart, 0, "/agents/run-abc"), runEv(EventRunEnd, 1, "/agents/run-abc"))
	if tl.LostEvents != 7 || tl.Complete {
		t.Fatalf("lost %d, complete %v", tl.LostEvents, tl.Complete)
	}
	lost, suppressed = 0, 3
	tl = feed(t, r, runEv(EventRunStart, 2, "/agents/run-abc"), runEv(EventRunEnd, 3, "/agents/run-abc"))
	if tl.SuppressedEvents != 3 || tl.LostEvents != 0 || tl.Complete {
		t.Fatalf("suppressed %d, lost %d, complete %v", tl.SuppressedEvents, tl.LostEvents, tl.Complete)
	}
	lost, suppressed = 0, 0
	tl = feed(t, r, runEv(EventRunStart, 4, "/agents/run-abc"), runEv(EventRunEnd, 5, "/agents/run-abc"))
	if !tl.Complete {
		t.Fatal("clean run not complete")
	}
}

func TestResolverBindings(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r := &Resolver{now: func() time.Time { return now }}
	r.init()
	ip := netip.MustParseAddr("20.0.0.9")
	r.bind(7, "github.com", []DNSAnswer{{Type: "CNAME", Value: "x"}, {Type: "A", Value: "20.0.0.9", TTL: 30}})
	r.bind(7, "gh.example", []DNSAnswer{{Type: "A", Value: "20.0.0.9", TTL: 3600}})
	if got := r.NamesFor(7, ip); strings.Join(got, ",") != "github.com,gh.example" {
		t.Fatalf("names: %v", got)
	}
	if got := r.NamesFor(8, ip); len(got) != 0 {
		t.Fatalf("another run sees %v", got)
	}
	// A 30 s TTL still binds for the floor of five minutes.
	now = now.Add(4 * time.Minute)
	if got := r.NamesFor(7, netip.MustParseAddr("::ffff:20.0.0.9")); len(got) != 2 {
		t.Fatalf("within the floor (IPv4-mapped lookup): %v", got)
	}
	now = now.Add(2 * time.Minute)
	if got := r.NamesFor(7, ip); strings.Join(got, ",") != "gh.example" {
		t.Fatalf("after the floor: %v", got)
	}
	r.Forget(7)
	if got := r.NamesFor(7, ip); len(got) != 0 {
		t.Fatalf("after Forget: %v", got)
	}
}

const byNameProfile = `kind: AgentProfile
metadata: { name: bn }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: no-lan, to: { cidr: ["10.0.0.0/8"] }, action: deny, message: "No LAN." }
      - { name: gh-ssh, to: { fqdn: ["github.com"], ports: [22] }, action: allow }
      - { name: no-db, to: { fqdn: ["db.example"] }, action: deny, message: "No databases." }
`

func TestExtProcByResolvedName(t *testing.T) {
	xp, events, c := newTestExtProc(t, false)
	p, _ := policy.Parse([]byte(byNameProfile))
	comp, diags := policy.Compile(policy.Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	cg := ownCgroupID(t)
	b := &boundRun{runID: "testrun", cgroupID: cg, eff: &policy.Effective{Layers: []policy.Layer{{Profile: comp.Profiles[0], Source: "granted"}}}}
	xp.api.bound["testrun"], xp.api.byCg[cg] = b, b
	names := map[string][]string{"20.0.0.9": {"github.com"}, "10.1.2.3": {"github.com"}, "20.0.0.10": {"db.example"}}
	xp.Names = func(_ uint64, ip netip.Addr) []string { return names[ip.String()] }

	inner := map[string]interface{}{"source.address": "envoy://internal_client_address/", "destination.address": "envoy://transparent-connect/"}
	tunnel := func(authority string) (bool, HTTPData) {
		h := map[string]string{hdrClient: c.src.String() + "," + c.dst.String(), hdrConnect: authority, hdrOrigDst: authority}
		req, hh := reqWith(inner, "CONNECT", authority, "", h)
		ok := first(xp.onHeaders(context.Background(), req, hh)).GetImmediateResponse() == nil
		return ok, (<-events).Data.(HTTPData)
	}
	if ok, d := tunnel("20.0.0.9:22"); !ok || d.Rule != "gh-ssh" || d.ResolvedName != "github.com" {
		t.Errorf("SSH by resolved name: %v %+v", ok, d)
	}
	if ok, d := tunnel("20.0.0.9:2222"); ok || d.ResolvedName != "" {
		t.Errorf("other port: %v %+v", ok, d)
	}
	if ok, d := tunnel("10.1.2.3:22"); ok || d.Rule != "no-lan" {
		t.Errorf("a rule on the address wins: %v %+v", ok, d)
	}
	if ok, d := tunnel("20.0.0.10:5432"); ok || d.Message != "No databases." || d.ResolvedName != "db.example" {
		t.Errorf("explicit name deny: %v %+v", ok, d)
	}
	if ok, _ := tunnel("20.0.0.11:22"); ok {
		t.Error("an address with no binding allowed")
	}
	// The explicit proxy does not consult bindings: a CONNECT to an IP
	// literal is the client's own choice there.
	outer := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	req, hh := reqWith(outer, "CONNECT", "20.0.0.9:22", "", nil)
	if first(xp.onHeaders(context.Background(), req, hh)).GetImmediateResponse() == nil {
		t.Error("explicit CONNECT to an address allowed by binding")
	}
}
