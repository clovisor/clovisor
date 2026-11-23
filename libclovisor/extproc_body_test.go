// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

const contentXP = `kind: AgentProfile
metadata: { name: cx }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: api, to: { fqdn: ["api.example.com"], ports: [80] }, action: allow }
      - { name: other, to: { fqdn: ["other.example.com"], ports: [443] }, action: allow }
      - { name: mcp, to: { fqdn: ["mcp.test.internal"] }, action: allow }
  mcp:
    default: allow
    servers:
      - { name: remote, match: { fqdn: "mcp.test.internal" }, tools: { deny: ["delete_*"] } }
  content:
    - { name: aws-keys, regex: "AKIA[0-9A-Z]{16}", action: deny }
    - { name: tokens, regex: "tok_[a-z0-9]{8}", action: redact }
    - { name: corp, regex: "corp\\.internal", action: tag-and-log, to: { fqdn: ["api.example.com"] } }
`

func contentFixture(t *testing.T, mode string) (*ExtProcServer, chan AuditEvent, testClient) {
	t.Helper()
	xp, events, c := newTestExtProc(t, false)
	doc := contentXP
	if mode != "" {
		doc = strings.Replace(doc, "mode: enforce", "mode: "+mode, 1)
	}
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	comp, diags := policy.Compile(policy.Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	cg := ownCgroupID(t)
	b := &boundRun{runID: "testrun", cgroupID: cg, eff: &policy.Effective{Layers: []policy.Layer{{Profile: comp.Profiles[0]}}}}
	xp.api.bound["testrun"], xp.api.byCg[cg] = b, b
	return xp, events, c
}

// post sends headers then the body in chunks, as Envoy does in streamed
// mode, and returns the last response and what was released upstream.
func post(t *testing.T, xp *ExtProcServer, c testClient, authority, path string, extra map[string]string, chunks ...[]byte) (*extprocv3.ProcessingResponse, []byte, *streamState) {
	t.Helper()
	attrs := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	req, h := reqWith(attrs, "POST", authority, path, extra)
	h.EndOfStream = len(chunks) == 0
	resp, st := xp.onHeaders(context.Background(), req, h)
	if resp.GetImmediateResponse() != nil || len(chunks) == 0 {
		return resp, nil, st
	}
	if st == nil || st.body == nil {
		t.Fatalf("no body held for %s%s: %v", authority, path, resp)
	}
	if m := resp.GetModeOverride().GetRequestBodyMode().String(); m != "STREAMED" {
		t.Fatalf("request body mode %s", m)
	}
	var out []byte
	for i, ch := range chunks {
		_, r := xp.onBody(st, ch, i == len(chunks)-1)
		if r.GetImmediateResponse() != nil {
			return r, nil, st
		}
		got := r.GetRequestBody().GetResponse().GetBodyMutation().GetBody()
		if i < len(chunks)-1 && len(got) != 0 {
			t.Fatalf("chunk %d released before the body was complete: %q", i, got)
		}
		out = append(out, got...)
		resp = r
	}
	return resp, out, st
}

func status(r *extprocv3.ProcessingResponse) (int, string) {
	ir := r.GetImmediateResponse()
	if ir == nil {
		return 0, ""
	}
	var body struct {
		Message string `json:"message"`
	}
	json.Unmarshal(ir.GetBody(), &body)
	return int(ir.GetStatus().GetCode()), body.Message
}

func contentEvents(events chan AuditEvent) []ContentData {
	var out []ContentData
	for {
		select {
		case ev := <-events:
			if ev.Type == EventContent {
				out = append(out, ev.Data.(ContentData))
			}
		default:
			return out
		}
	}
}

func TestExtProcContent(t *testing.T) {
	xp, events, c := contentFixture(t, "")

	// Clean body: held, then released whole and unchanged.
	_, out, st := post(t, xp, c, "api.example.com", "/v1", nil, []byte(`{"a":`), []byte(`"hello"}`))
	if string(out) != `{"a":"hello"}` {
		t.Fatalf("released %q", out)
	}
	st.done(xp)

	// A secret split across chunks is still found, and nothing is sent.
	r, _, st := post(t, xp, c, "api.example.com", "/v1", nil, []byte(`{"k":"AKIAABCDEF`), []byte(`GHIJKLMNOP"}`))
	code, msg := status(r)
	if code != 403 || !strings.Contains(msg, "its body matches content rule aws-keys of profile cx") || strings.Contains(msg, "AKIA") {
		t.Fatalf("deny: %d %q", code, msg)
	}
	st.done(xp)

	// Redaction keeps the length; tag-and-log only records.
	body := `{"t":"tok_abcd1234","h":"x.corp.internal"}`
	_, out, st = post(t, xp, c, "api.example.com", "/v1", map[string]string{"content-length": strconv.Itoa(len(body))}, []byte(body))
	if len(out) != len(body) || !strings.Contains(string(out), `"t":"************"`) || !strings.Contains(string(out), "corp.internal") {
		t.Fatalf("redacted: %q", out)
	}
	st.done(xp)

	// The query string is checked at headers, decoded; redact refuses there.
	r, _, _ = post(t, xp, c, "api.example.com", "/v1?k=AKIA%41BCDEFGHIJKLMNOP", nil)
	if code, _ := status(r); code != 403 {
		t.Fatalf("query secret: %v", r)
	}
	r, _, _ = post(t, xp, c, "api.example.com", "/v1?t=tok_abcd1234", nil)
	if code, msg := status(r); code != 403 || !strings.Contains(msg, "redacted only in a request body") {
		t.Fatalf("query redact: %d %s", code, msg)
	}

	// gzip is decoded to check; it cannot be redacted, so redact refuses.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"t":"tok_abcd1234"}`))
	zw.Close()
	r, _, st = post(t, xp, c, "api.example.com", "/v1", map[string]string{"content-encoding": "gzip"}, gz.Bytes())
	if code, msg := status(r); code != 403 || !strings.Contains(msg, "a compressed body cannot be redacted") {
		t.Fatalf("gzip redact: %d %s", code, msg)
	}
	st.done(xp)
	r, _, _ = post(t, xp, c, "api.example.com", "/v1", map[string]string{"content-encoding": "br"}, []byte("x"))
	if code, _ := status(r); code != 415 {
		t.Fatalf("br: %v", r)
	}

	// Over the cap: refused as it arrives.
	xp.MaxBody = 16
	r, _, st = post(t, xp, c, "api.example.com", "/v1", nil, []byte("0123456789"), []byte("0123456789"))
	if code, msg := status(r); code != 413 || !strings.Contains(msg, "16 bytes") {
		t.Fatalf("too large: %d %s", code, msg)
	}
	st.done(xp)
	xp.MaxBody = 0

	// A host no content rule covers gets no body processing.
	attrs := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	req, h := reqWith(attrs, "POST", "unlisted.example.com", "/", nil)
	if _, st := xp.onHeaders(context.Background(), req, h); st != nil {
		t.Fatal("unlisted host held")
	}

	// Inspected streams are bounded per run, and released when done.
	xp.MaxInspectedPerRun = 1
	_, _, st1 := post(t, xp, c, "api.example.com", "/v1", nil, []byte("a"), []byte("b"))
	r, _, _ = post(t, xp, c, "api.example.com", "/v1", nil, []byte("a"))
	if code, _ := status(r); code != 503 {
		t.Fatalf("per-run limit: %v", r)
	}
	st1.done(xp)
	if _, out, st := post(t, xp, c, "api.example.com", "/v1", nil, []byte("ok")); string(out) != "ok" {
		t.Fatalf("after release: %q", out)
	} else {
		st.done(xp)
	}
	xp.MaxInspectedPerRun = 0
	if xp.insp.open != 0 || xp.insp.held.Load() != 0 {
		t.Errorf("leaked: open %d held %d", xp.insp.open, xp.insp.held.Load())
	}

	evs := contentEvents(events)
	var decisions []string
	for _, e := range evs {
		decisions = append(decisions, e.Where+":"+e.Decision+":"+e.Rule+e.Reason)
	}
	got := strings.Join(decisions, ",")
	for _, want := range []string{"body:deny:aws-keys", "body:redact:", "query string:deny:aws-keys", "query string:deny:tokens",
		"body:deny:tokens", "body:deny:body encoding not checkable", "body:deny:body over the inspection limit", "body:deny:inspection limit"} {
		if !strings.Contains(got, want) {
			t.Errorf("events lack %q: %s", want, got)
		}
	}
	for _, e := range evs {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "AKIA") || strings.Contains(string(b), "tok_") {
			t.Errorf("event records the match: %s", b)
		}
	}
}

func TestExtProcContentAudit(t *testing.T) {
	xp, events, c := contentFixture(t, "audit")
	body := `{"k":"AKIAABCDEFGHIJKLMNOP","t":"tok_abcd1234"}`
	_, out, st := post(t, xp, c, "api.example.com", "/v1", nil, []byte(body))
	if string(out) != body {
		t.Fatalf("audit changed the body: %q", out)
	}
	st.done(xp)
	evs := contentEvents(events)
	if len(evs) != 1 || evs[0].Decision != "allow" || len(evs[0].Hits) != 2 || evs[0].Hits[0].Enforced {
		t.Fatalf("audit events: %+v", evs)
	}
}

func TestExtProcContentMCP(t *testing.T) {
	xp, _, c := contentFixture(t, "")
	in := func(chunks ...[]byte) (*extprocv3.ProcessingResponse, []byte) {
		req, h := innerReq(c, "mcp.test.internal", "POST")
		resp, st := xp.onHeaders(context.Background(), req, h)
		if st.remoteMCP() == nil || st.body == nil {
			t.Fatalf("MCP stream not inspected: %v", resp)
		}
		defer st.done(xp)
		var r *extprocv3.ProcessingResponse
		for i, ch := range chunks {
			_, r = xp.onBody(st, ch, i == len(chunks)-1)
		}
		return r, r.GetRequestBody().GetResponse().GetBodyMutation().GetBody()
	}
	// Content rules apply to tool-call arguments; MCP policy still decides.
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"tok_abcd1234"}}}`
	if _, out := in([]byte(call[:40]), []byte(call[40:])); !strings.Contains(string(out), `"q":"************"`) {
		t.Fatalf("MCP redaction: %q", out)
	}
	r, _ := in([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo"}}`))
	if ir := r.GetImmediateResponse(); ir == nil || !strings.Contains(string(ir.GetBody()), "isError") {
		t.Fatalf("MCP deny after content: %v", r)
	}
	if r, _ := in([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"q":"AKIAABCDEFGHIJKLMNOP"}}}`)); r.GetImmediateResponse().GetStatus().GetCode() != 403 {
		t.Fatalf("MCP secret: %v", r)
	}
}
