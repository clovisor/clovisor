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
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// testClient is a real TCP connection, so SockCgroup finds a real socket
// in this test process's cgroup.
type testClient struct {
	src, dst netip.AddrPort
	close    func()
}

func newTestClient(t *testing.T) testClient {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return testClient{
		src:   netip.MustParseAddrPort(c.LocalAddr().String()),
		dst:   netip.MustParseAddrPort(c.RemoteAddr().String()),
		close: func() { c.Close(); ln.Close() },
	}
}

func ownCgroupID(t *testing.T) uint64 {
	t.Helper()
	cg, err := procCgroup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	id, err := GetCgroupID(filepath.Join(CgroupV2Root, cg))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func headersReq(c testClient, method, authority, path string) (*extprocv3.ProcessingRequest, *extprocv3.HttpHeaders) {
	h := &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte(method)},
		{Key: ":authority", RawValue: []byte(authority)},
		{Key: ":path", RawValue: []byte(path)},
	}}}
	attrs, _ := structpb.NewStruct(map[string]interface{}{
		"source.address":      c.src.String(),
		"destination.address": c.dst.String(),
	})
	return &extprocv3.ProcessingRequest{Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": attrs}}, h
}

const xpProfile = `kind: AgentProfile
metadata: { name: xp }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: gh, to: { fqdn: ["github.com"] }, action: allow }
      - { name: no-admin, to: { fqdn: ["api.github.com"] }, http: { paths: ["/admin*"] }, action: deny, message: "No admin endpoints." }
      - { name: api, to: { fqdn: ["api.github.com"] }, http: { methods: [GET] }, action: allow }
      - { name: any-ip, to: { cidr: ["0.0.0.0/0"] }, action: allow }
      - { name: plain, to: { fqdn: ["mirror.internal"], ports: [80] }, http: { paths: ["/pub/*"] }, action: allow }
      - { name: all, to: { fqdn: ["*"] }, action: tag-and-log }
`

func newTestExtProc(t *testing.T, profiled bool) (*ExtProcServer, chan AuditEvent, testClient) {
	t.Helper()
	cm := &CgroupManager{agents: t.TempDir(), runMap: map[string]string{}}
	api := &RunAPIServer{cm: cm, active: map[string]bool{}, bound: map[string]*boundRun{},
		byCg: map[uint64]*boundRun{}, runByCg: map[uint64]string{}, runCg: map[string]uint64{}}
	events := make(chan AuditEvent, 64)
	xp := NewExtProcServer(api, cm.agents, events)
	xp.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "rebind.example" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	c := newTestClient(t)
	t.Cleanup(c.close)
	cg := ownCgroupID(t)
	api.runByCg[cg] = "testrun"
	api.runCg["testrun"] = cg
	if profiled {
		p, _ := policy.Parse([]byte(xpProfile))
		comp, diags := policy.Compile(policy.Options{Linux: true}, p)
		if len(diags) > 0 {
			t.Fatal(diags)
		}
		b := &boundRun{runID: "testrun", cgroupID: cg, eff: &policy.Effective{Layers: []policy.Layer{{Profile: comp.Profiles[0], Source: "granted"}}}}
		api.bound["testrun"], api.byCg[cg] = b, b
	}
	return xp, events, c
}

func decide(t *testing.T, xp *ExtProcServer, c testClient, method, authority, path string) (allowed bool, body map[string]interface{}, hdr map[string]string) {
	t.Helper()
	req, h := headersReq(c, method, authority, path)
	resp, _ := xp.onHeaders(context.Background(), req, h)
	ir := resp.GetImmediateResponse()
	if ir == nil {
		return true, nil, nil
	}
	if ir.GetStatus().GetCode() != 403 {
		t.Fatalf("immediate response %v", ir.GetStatus())
	}
	json.Unmarshal(ir.GetBody(), &body)
	hdr = map[string]string{}
	for _, o := range ir.GetHeaders().GetSetHeaders() {
		hdr[o.GetHeader().GetKey()] = string(o.GetHeader().GetRawValue())
	}
	return false, body, hdr
}

func TestExtProcDecisions(t *testing.T) {
	xp, events, c := newTestExtProc(t, true)
	cases := []struct {
		method, authority, path string
		allowed                 bool
		msg                     string
	}{
		{"CONNECT", "github.com:443", "", true, ""},
		{"CONNECT", "evil.example:443", "", true, ""}, // tag-and-log via "*"
		{"CONNECT", "203.0.113.5:22", "", true, ""},   // cidr on an IP literal
		{"CONNECT", "api.github.com:443", "", false, "needs the request's method or path"},
		{"GET", "mirror.internal", "/pub/file?x=1", true, ""},
		{"GET", "mirror.internal", "/private", true, ""}, // falls through to "*"
		{"CONNECT", "127.0.0.1:19901", "", false, "node-local address"},
		{"CONNECT", "[::1]:22", "", false, "node-local address"},
		{"CONNECT", "169.254.169.254:80", "", false, "node-local address"},
		{"GET", "localhost:8080", "/", false, "node-local name"},
		{"CONNECT", "rebind.example:443", "", false, "resolves to a node-local address"},
		{"CONNECT", "bad:port:x", "", false, "could not parse"},
	}
	for _, tc := range cases {
		allowed, body, hdr := decide(t, xp, c, tc.method, tc.authority, tc.path)
		if allowed != tc.allowed {
			t.Errorf("%s %s%s: allowed=%v, want %v (%v)", tc.method, tc.authority, tc.path, allowed, tc.allowed, body)
			continue
		}
		if !allowed {
			if !strings.Contains(body["message"].(string), tc.msg) || hdr["x-clovisor-denial"] == "" {
				t.Errorf("%s %s: narration %q / %q", tc.method, tc.authority, body["message"], hdr["x-clovisor-denial"])
			}
		}
	}

	// Decisions reach the recorder, with the query string stripped.
	var got []HTTPData
	for len(events) > 0 {
		got = append(got, (<-events).Data.(HTTPData))
	}
	if len(got) != len(cases)-1 { // the unparseable authority is not recorded
		t.Fatalf("%d events for %d decisions", len(got), len(cases))
	}
	if got[1].Decision != policy.ActionTagAndLog || got[4].Path != "/pub/file" || got[3].Reason != "needs termination" {
		t.Errorf("events: %+v", got)
	}
}

func TestExtProcIdentity(t *testing.T) {
	// An unprofiled run is allowed and recorded.
	xp, events, c := newTestExtProc(t, false)
	if allowed, _, _ := decide(t, xp, c, "CONNECT", "anything.example:443", ""); !allowed || len(events) != 1 {
		t.Fatalf("unprofiled run: allowed=%v events=%d", allowed, len(events))
	}
	// A guard still applies to unprofiled runs.
	if allowed, _, _ := decide(t, xp, c, "CONNECT", "127.0.0.1:22", ""); allowed {
		t.Fatal("guard skipped for an unprofiled run")
	}

	// A client outside any run is refused, unless allowed by config.
	delete(xp.api.runByCg, ownCgroupID(t))
	allowed, body, _ := decide(t, xp, c, "CONNECT", "github.com:443", "")
	if allowed || !strings.Contains(body["message"].(string), "governed agent runs only") {
		t.Fatalf("non-run client: allowed=%v %v", allowed, body)
	}
	xp.NonRunAllowed = true
	if allowed, _, _ := decide(t, xp, c, "CONNECT", "github.com:443", ""); !allowed {
		t.Fatal("non-run client refused with NonRunAllowed")
	}

	// A 4-tuple with no socket behind it cannot be attributed: refused.
	req, h := headersReq(testClient{src: netip.MustParseAddrPort("127.0.0.1:1"), dst: c.dst}, "CONNECT", "github.com:443", "")
	if first(xp.onHeaders(context.Background(), req, h)).GetImmediateResponse() == nil {
		t.Fatal("unidentified client allowed")
	}
}

func first(r *extprocv3.ProcessingResponse, _ *remoteMCP) *extprocv3.ProcessingResponse { return r }

func TestEnvoyBootstrap(t *testing.T) {
	b, err := EnvoyBootstrap(EnvoyConfig{ProxyListen: netip.MustParseAddrPort("127.0.0.1:18000"),
		ExtProcSocket: "/run/clovisor/extproc.sock", AdminSocket: "/run/clovisor/envoy-admin.sock"})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"path": "/run/clovisor/envoy-admin.sock"`, `"path": "/run/clovisor/extproc.sock"`,
		`"failure_mode_allow": false`, `"port_value": 18000`, `"connect_matcher"`} {
		if !strings.Contains(s, want) {
			t.Errorf("bootstrap lacks %s", want)
		}
	}
	if strings.Contains(s, "9901") || strings.Contains(s, `"admin": {"address": {"socket_address"`) {
		t.Error("admin on TCP")
	}
	if _, err := EnvoyBootstrap(EnvoyConfig{}); err == nil {
		t.Error("empty config accepted")
	}
}

func TestSplitAuthority(t *testing.T) {
	for in, want := range map[string]string{
		"github.com:443": "github.com/443", "github.com": "github.com/80", "[::1]:22": "::1/22",
		"1.2.3.4:8080": "1.2.3.4/8080",
	} {
		h, p, err := splitAuthority(in, 80)
		if err != nil || h+"/"+strconv.Itoa(int(p)) != want {
			t.Errorf("splitAuthority(%q) = %q %d %v", in, h, p, err)
		}
	}
	for _, bad := range []string{"h:0", "h:99999", "h:x"} {
		if _, _, err := splitAuthority(bad, 80); err == nil {
			t.Errorf("splitAuthority(%q) accepted", bad)
		}
	}
}

// A client in a child cgroup of a run (an MCP server's, a tool call's) is
// the run's: its decisions are filed under the run's own cgroup id, with
// the client's cgroup as the leaf, so they can be attributed to the call.
func TestExtProcChildCgroupAttribution(t *testing.T) {
	xp, events, c := newTestExtProc(t, false)
	own := ownCgroupID(t)
	// Pretend our cgroup is a child of run "testrun", whose own cgroup is 42.
	xp.api.runCg["testrun"] = 42
	if allowed, _, _ := decide(t, xp, c, "CONNECT", "example.com:443", ""); !allowed {
		t.Fatal("child-cgroup client refused")
	}
	ev := <-events
	if ev.RunCgroupID != 42 || ev.CgroupID != own || own == 42 {
		t.Fatalf("filed under %d/%d, want the run's cgroup 42 and the client's %d", ev.RunCgroupID, ev.CgroupID, own)
	}
}

func TestAuthorityRegex(t *testing.T) {
	for _, tc := range []struct {
		pattern, authority string
		want               bool
	}{
		{"api.github.com", "api.github.com:443", true},
		{"api.github.com", "api.github.com:8443", true},
		{"api.github.com", "api.github.com", false},
		{"api.github.com", "apixgithub.com:443", false},
		{"api.github.com", "evil.api.github.com:443", false},
		{"*.example.org", "raw.example.org:443", true},
		{"*.example.org", "a.b.example.org:443", false}, // one label, like the certificate
		{"*.example.org", "example.org:443", false},
		{"*.example.org", "rawxexample.org:443", false},
		{"*.example.org", "[::1].example.org:443", false},
	} {
		if got := regexp.MustCompile(authorityRegex(tc.pattern)).MatchString(tc.authority); got != tc.want {
			t.Errorf("%s vs %s: %v (regex %s)", tc.pattern, tc.authority, got, authorityRegex(tc.pattern))
		}
	}
}

// reqWith builds a request with chosen attributes and extra headers.
func reqWith(attrs map[string]interface{}, method, authority, path string, extra map[string]string) (*extprocv3.ProcessingRequest, *extprocv3.HttpHeaders) {
	hs := []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte(method)},
		{Key: ":authority", RawValue: []byte(authority)},
		{Key: ":path", RawValue: []byte(path)},
	}
	for k, v := range extra {
		hs = append(hs, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	st, _ := structpb.NewStruct(attrs)
	return &extprocv3.ProcessingRequest{Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": st}},
		&extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}}
}

func TestExtProcTermination(t *testing.T) {
	xp, _, c := newTestExtProc(t, true)
	allowed := func(req *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) (bool, string) {
		ir := first(xp.onHeaders(context.Background(), req, h)).GetImmediateResponse()
		if ir == nil {
			return true, ""
		}
		var body map[string]interface{}
		json.Unmarshal(ir.GetBody(), &body)
		return false, body["message"].(string)
	}
	outer := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	innerAttrs := map[string]interface{}{"source.address": "envoy://internal_client_address/", "destination.address": "envoy://mitm-0/"}
	tunnel := map[string]string{hdrClient: c.src.String() + "," + c.dst.String(), hdrConnect: "api.github.com:443"}

	// The CONNECT is let through to termination only on a terminate route.
	outer["xds.route_name"] = TerminateRoutePrefix + "0"
	if ok, msg := allowed(reqWith(outer, "CONNECT", "api.github.com:443", "", nil)); !ok {
		t.Fatalf("terminated CONNECT refused: %s", msg)
	}
	outer["xds.route_name"] = ""
	if ok, msg := allowed(reqWith(outer, "CONNECT", "api.github.com:443", "", nil)); ok || !strings.Contains(msg, "restart Envoy") {
		t.Fatalf("untermined CONNECT: %v %s", ok, msg)
	}

	// Inside the tunnel: method and path decide ("api" allows GET only).
	if ok, msg := allowed(reqWith(innerAttrs, "GET", "api.github.com", "/repos/x", tunnel)); !ok {
		t.Fatalf("inner GET refused: %s", msg)
	}
	if ok, msg := allowed(reqWith(innerAttrs, "GET", "api.github.com", "/admin/users", tunnel)); ok || msg != "No admin endpoints." {
		t.Fatalf("inner path deny: %v %s", ok, msg)
	}
	// Smuggling: a Host other than the tunnel's destination.
	if ok, msg := allowed(reqWith(innerAttrs, "GET", "evil.example", "/", tunnel)); ok || !strings.Contains(msg, "does not match the tunnel's destination") {
		t.Fatalf("smuggled Host: %v %s", ok, msg)
	}
	// Same host, other port.
	if ok, _ := allowed(reqWith(innerAttrs, "GET", "api.github.com:8443", "/repos/x", tunnel)); ok {
		t.Fatal("smuggled port allowed")
	}

	// On the outer hop the identity header is not trusted: a client naming
	// someone else's connection is identified by its own socket.
	spoof := map[string]string{hdrClient: "127.0.0.1:1,127.0.0.1:2"}
	if ok, msg := allowed(reqWith(outer, "CONNECT", "github.com:443", "", spoof)); !ok {
		t.Fatalf("outer request with a spoofed header refused: %s", msg)
	}
	// On the inner hop, a header naming no live socket is refused.
	bad := map[string]string{hdrClient: "127.0.0.1:1,127.0.0.1:2", hdrConnect: "api.github.com:443"}
	if ok, msg := allowed(reqWith(innerAttrs, "GET", "api.github.com", "/repos/x", bad)); ok || !strings.Contains(msg, "could not identify") {
		t.Fatalf("inner request without a live client: %v %s", ok, msg)
	}
}

func TestEnvoyBootstrapTermination(t *testing.T) {
	b, err := EnvoyBootstrap(EnvoyConfig{ProxyListen: netip.MustParseAddrPort("127.0.0.1:18000"),
		ExtProcSocket: "/x.sock", AdminSocket: "/a.sock", UpstreamCA: "/etc/ssl/certs/ca-certificates.crt",
		Terminate: []TerminatedHost{{Pattern: "api.github.com", CertPath: "/t/0.crt", KeyPath: "/t/0.key"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"name": "clovisor-terminate-0"`, `"server_listener_name": "mitm-0"`, `"envoy.bootstrap.internal_listener"`,
		`"filename": "/t/0.crt"`, `"auto_san_validation": true`, `"xds.route_name"`, `"remove": "x-clovisor-client"`,
		`%FILTER_STATE(clovisor.connect:PLAIN)%`} {
		if !strings.Contains(s, want) {
			t.Errorf("bootstrap lacks %s", want)
		}
	}
	if _, err := EnvoyBootstrap(EnvoyConfig{ProxyListen: netip.MustParseAddrPort("127.0.0.1:1"), ExtProcSocket: "/x", AdminSocket: "/a",
		Terminate: []TerminatedHost{{Pattern: "a.com"}}}); err == nil {
		t.Error("termination without an upstream CA accepted")
	}
}
