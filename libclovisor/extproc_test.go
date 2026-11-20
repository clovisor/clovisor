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
      - { name: api, to: { fqdn: ["api.github.com"] }, http: { methods: [GET] }, action: allow }
      - { name: any-ip, to: { cidr: ["0.0.0.0/0"] }, action: allow }
      - { name: plain, to: { fqdn: ["mirror.internal"], ports: [80] }, http: { paths: ["/pub/*"] }, action: allow }
      - { name: all, to: { fqdn: ["*"] }, action: tag-and-log }
`

func newTestExtProc(t *testing.T, profiled bool) (*ExtProcServer, chan AuditEvent, testClient) {
	t.Helper()
	cm := &CgroupManager{agents: t.TempDir(), runMap: map[string]string{}}
	api := &RunAPIServer{cm: cm, active: map[string]bool{}, bound: map[string]*boundRun{},
		byCg: map[uint64]*boundRun{}, runByCg: map[uint64]string{}}
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
	resp := xp.onHeaders(context.Background(), req, h)
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
	if xp.onHeaders(context.Background(), req, h).GetImmediateResponse() == nil {
		t.Fatal("unidentified client allowed")
	}
}

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
