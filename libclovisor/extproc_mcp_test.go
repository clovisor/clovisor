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
	"path/filepath"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

const remoteProfile = `kind: AgentProfile
metadata: { name: rm }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: mcp-host, to: { fqdn: ["mcp.test.internal"] }, action: allow }
      - { name: other, to: { fqdn: ["api.example.com"] }, action: allow }
  mcp:
    default: deny
    servers:
      - name: remote
        match: { fqdn: "mcp.test.internal" }
        tools: { allow: ["search_*", "get_*"], deny: ["delete_*"] }
        pin_tool_definitions: true
    sampling: { action: deny, message: "No sampling from remote servers." }
`

func newRemoteFixture(t *testing.T, pinPath string) (*ExtProcServer, chan AuditEvent, testClient) {
	t.Helper()
	xp, events, c := newTestExtProc(t, false)
	p, _ := policy.Parse([]byte(remoteProfile))
	comp, diags := policy.Compile(policy.Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	cg := ownCgroupID(t)
	b := &boundRun{runID: "testrun", cgroupID: cg, eff: &policy.Effective{Layers: []policy.Layer{{Profile: comp.Profiles[0]}}}}
	xp.api.bound["testrun"], xp.api.byCg[cg] = b, b
	pins, err := OpenPinStore(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	xp.Pins = pins
	return xp, events, c
}

func innerReq(c testClient, host, method string) (*extprocv3.ProcessingRequest, *extprocv3.HttpHeaders) {
	return reqWith(map[string]interface{}{"source.address": "envoy://internal_client_address/", "destination.address": "envoy://mitm-0/"},
		method, host, "/mcp", map[string]string{hdrClient: c.src.String() + "," + c.dst.String(), hdrConnect: host + ":443"})
}

func innerHeaders(xp *ExtProcServer, c testClient, host, method string) (*extprocv3.ProcessingResponse, *remoteMCP) {
	req, h := innerReq(c, host, method)
	resp, st := xp.onHeaders(context.Background(), req, h)
	return resp, st.remoteMCP()
}

func respHeaders(ct string) *extprocv3.HttpHeaders {
	return &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: "content-type", RawValue: []byte(ct)}, {Key: "content-length", RawValue: []byte("123")}}}}
}

func mutated(t *testing.T, r *extprocv3.ProcessingResponse) string {
	t.Helper()
	return string(r.GetResponseBody().GetResponse().GetBodyMutation().GetBody())
}

func toolsResult(id int, desc string, names ...string) string {
	var tools []interface{}
	for _, n := range names {
		tools = append(tools, map[string]interface{}{"name": n, "description": n + desc})
	}
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{"tools": tools}})
	return string(b)
}

func TestRemoteMCP(t *testing.T) {
	pinPath := filepath.Join(t.TempDir(), "pins.json")
	xp, events, c := newRemoteFixture(t, pinPath)

	// Only requests to a governed MCP host get body processing.
	resp, m := innerHeaders(xp, c, "mcp.test.internal", "POST")
	if m == nil || resp.GetModeOverride().GetRequestBodyMode().String() != "STREAMED" || resp.GetModeOverride().GetResponseBodyMode().String() != "STREAMED" {
		t.Fatalf("no mode override for the MCP host: %v", resp.GetModeOverride())
	}
	if _, m2 := innerHeaders(xp, c, "api.example.com", "POST"); m2 != nil {
		t.Fatal("body processing turned on for a host with no MCP rule")
	}

	// Request bodies.
	r := xp.onMCPRequestBody(m, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`))
	ir := r.GetImmediateResponse()
	if ir == nil || ir.GetStatus().GetCode() != 200 || !strings.Contains(string(ir.GetBody()), `"isError":true`) ||
		!strings.Contains(string(ir.GetBody()), "is denied by profile rm") {
		t.Fatalf("denied call: %v", r)
	}
	if r := xp.onMCPRequestBody(m, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_code"}}`)); r.GetImmediateResponse() != nil {
		t.Fatal("allowed call answered in place")
	}
	r = xp.onMCPRequestBody(m, []byte(`[{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_file"}},`+
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_x"}}]`))
	if b := string(r.GetImmediateResponse().GetBody()); !strings.Contains(b, "another request in this batch was denied") || !strings.Contains(b, `"isError":true`) {
		t.Fatalf("batch: %s", b)
	}

	// A JSON tools/list response, delivered in two chunks.
	if r := xp.onMCPRequestBody(m, []byte(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)); r.GetImmediateResponse() != nil {
		t.Fatal("tools/list refused")
	}
	h := xp.onMCPResponseHeaders(m, respHeaders("application/json"))
	if rm := h.GetResponseHeaders().GetResponse().GetHeaderMutation().GetRemoveHeaders(); len(rm) != 1 || rm[0] != "content-length" {
		t.Fatalf("content-length kept: %v", rm)
	}
	body := toolsResult(5, "", "search_code", "delete_repo", "get_file")
	if got := mutated(t, xp.onMCPResponseBody(m, []byte(body[:30]), false)); got != "" {
		t.Fatalf("partial JSON passed on: %q", got)
	}
	got := mutated(t, xp.onMCPResponseBody(m, []byte(body[30:]), true))
	if !strings.Contains(got, "search_code") || !strings.Contains(got, "get_file") || strings.Contains(got, "delete_repo") {
		t.Fatalf("filtered JSON: %s", got)
	}

	// An SSE response: a sampling request (cut out), then the tools/list
	// result (filtered), split across chunks mid-event.
	_, m = innerHeaders(xp, c, "mcp.test.internal", "POST")
	xp.onMCPRequestBody(m, []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`))
	xp.onMCPResponseHeaders(m, respHeaders("text/event-stream"))
	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"method\":\"sampling/createMessage\",\"params\":{}}\n\n" +
		"id: 9\nevent: message\ndata: " + toolsResult(7, "", "search_code", "delete_repo") + "\n\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
	var out strings.Builder
	for i := 0; i < len(stream); i += 37 {
		end := i + 37
		if end > len(stream) {
			end = len(stream)
		}
		out.WriteString(mutated(t, xp.onMCPResponseBody(m, []byte(stream[i:end]), end == len(stream))))
	}
	s := out.String()
	if strings.Contains(s, "sampling/createMessage") || strings.Contains(s, "delete_repo") || !strings.Contains(s, "search_code") ||
		!strings.Contains(s, "id: 9\n") || !strings.Contains(s, "notifications/progress") {
		t.Fatalf("SSE rewrite:\n%s", s)
	}

	// Pinning: the first sight pinned definitions; a changed one is
	// withheld and later calls to it are refused.
	xp2, events2, c2 := newRemoteFixture(t, pinPath)
	_, m = innerHeaders(xp2, c2, "mcp.test.internal", "POST")
	xp2.onMCPRequestBody(m, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	xp2.onMCPResponseHeaders(m, respHeaders("application/json"))
	got = mutated(t, xp2.onMCPResponseBody(m, []byte(toolsResult(1, " (now exfiltrates)", "search_code", "get_file")), true))
	if strings.Contains(got, "search_code") {
		t.Fatalf("drifted tool offered: %s", got)
	}
	r = xp2.onMCPRequestBody(m, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_code"}}`))
	if b := string(r.GetImmediateResponse().GetBody()); !strings.Contains(b, "changed its definition since it was pinned") {
		t.Fatalf("drifted call: %s", b)
	}

	var kinds []string
	for len(events) > 0 {
		d := (<-events).Data
		if md, ok := d.(MCPData); ok {
			kinds = append(kinds, md.Method+" "+md.Name+" "+md.Decision)
		}
	}
	if j := strings.Join(kinds, ";"); !strings.Contains(j, "tools/call delete_repo deny") || !strings.Contains(j, "sampling/createMessage  deny") {
		t.Errorf("mcp events: %s", j)
	}
	var drift bool
	for len(events2) > 0 {
		if md, ok := (<-events2).Data.(MCPData); ok && md.Reason == "tool definition changed since pinned" && md.Method == "tools/list" {
			drift = true
		}
	}
	if !drift {
		t.Error("drift not recorded")
	}
}
