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
	"strings"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

const modelXP = `kind: AgentProfile
metadata: { name: mx }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: files
        to: { fqdn: ["api.example.com"], ports: [80] }
        http: { paths: ["/v1/files"] }
        action: allow
      - name: llm
        to: { fqdn: ["api.example.com"], ports: [80, 443] }
        model: { allow: ["claude-sonnet-5-5*", "gpt-5"] }
        action: allow
      - { name: other, to: { fqdn: ["other.example.com"], ports: [80] }, action: allow }
`

func modelFixture(t *testing.T, layers ...string) (*ExtProcServer, chan AuditEvent, testClient) {
	t.Helper()
	xp, events, c := newTestExtProc(t, false)
	var ps []*policy.AgentProfile
	for _, doc := range layers {
		p, err := policy.Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	comp, diags := policy.Compile(policy.Options{Linux: true}, ps...)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	eff := &policy.Effective{}
	for _, cp := range comp.Profiles {
		eff = eff.With(policy.Layer{Profile: cp})
	}
	cg := ownCgroupID(t)
	b := &boundRun{runID: "testrun", cgroupID: cg, eff: eff}
	xp.api.bound["testrun"], xp.api.byCg[cg] = b, b
	return xp, events, c
}

func modelEvents(events chan AuditEvent) []ModelData {
	var out []ModelData
	for {
		select {
		case ev := <-events:
			if ev.Type == EventModel {
				out = append(out, ev.Data.(ModelData))
			}
		default:
			return out
		}
	}
}

func TestBodyModel(t *testing.T) {
	for body, want := range map[string]string{
		`{"model":"gpt-5","messages":[]}`:              "gpt-5|",
		`{"messages":[{"model":"x"}],"model":"gpt-5"}`: "gpt-5|",
		`{"model":"gpt-5"}`:                            "gpt-5|",
		`{"Model":"gpt-5"}`:                            "|",
		`{"messages":[]}`:                              "|",
		`{"model":"a","model":"b"}`:                    `|its body has more than one "model" field`,
		`{"model":7}`:                                  `|its "model" field is not a string`,
		`{"model":""}`:                                 `|its "model" field is empty`,
		`["model","gpt-5"]`:                            "|its body is not a JSON object",
		`--boundary`:                                   "|its body is not a JSON object",
		`{"model":"gpt-5"`:                             "|its body is not valid JSON",
		`{"model":"gpt-5"} {"model":"x"}`:              "|its body holds more than one JSON value",
	} {
		m, why := bodyModel([]byte(body))
		if got := m + "|" + why; got != want {
			t.Errorf("%s: %q, want %q", body, got, want)
		}
	}
	for q, want := range map[string]string{
		"":                       "false||",
		"a=b":                    "false||",
		"model=gpt-5":            "true|gpt-5|",
		"model=a&model=b":        `true||its query string has more than one "model" parameter`,
		"model=":                 `true||its "model" parameter is empty`,
		"model=gpt%2D5&x=1":      "true|gpt-5|",
		"x=%zz&model=claude-x-1": "true||its query string cannot be parsed",
	} {
		m, named, why := queryModel(q)
		if got := strings.Join([]string{map[bool]string{true: "true", false: "false"}[named], m, why}, "|"); got != want {
			t.Errorf("%q: %q, want %q", q, got, want)
		}
	}
}

func TestExtProcModel(t *testing.T) {
	xp, events, c := modelFixture(t, modelXP)
	send := func(path string, extra map[string]string, chunks ...[]byte) (int, string, []byte) {
		t.Helper()
		r, out, st := post(t, xp, c, "api.example.com", path, extra, chunks...)
		st.done(xp)
		code, msg := status(r)
		return code, msg, out
	}

	// An admitted model, split across chunks, is released unchanged.
	body := `{"model":"claude-sonnet-5-5-20261001","messages":[{"role":"user","content":"hi"}]}`
	if code, msg, out := send("/v1/messages", nil, []byte(body[:12]), []byte(body[12:])); code != 0 || string(out) != body {
		t.Fatalf("allowed: %d %s %q", code, msg, out)
	}
	// Another model is refused, narrated with the list.
	code, msg, _ := send("/v1/messages", nil, []byte(`{"model":"claude-opus-5-5","max_tokens":1}`))
	if code != 403 || !strings.Contains(msg, `model "claude-opus-5-5" is not allowed by rule llm of profile mx`) ||
		!strings.Contains(msg, "Allowed: claude-sonnet-5-5*, gpt-5") {
		t.Fatalf("other model: %d %s", code, msg)
	}
	// A body that names none, or is not JSON, is refused.
	if code, msg, _ := send("/v1/messages", nil, []byte(`{"messages":[]}`)); code != 403 || !strings.Contains(msg, `no top-level "model" field`) {
		t.Fatalf("no model: %d %s", code, msg)
	}
	if code, msg, _ := send("/v1/messages", nil, []byte(`{"model":"gpt-5","model":"claude-opus-5-5"}`)); code != 403 || !strings.Contains(msg, "more than one") {
		t.Fatalf("two models: %d %s", code, msg)
	}
	// A request with no body (or an empty one) names no model and passes.
	if code, msg, _ := send("/v1/models", nil); code != 0 {
		t.Fatalf("no body: %d %s", code, msg)
	}
	if code, msg, _ := send("/v1/models", nil, []byte{}); code != 0 {
		t.Fatalf("empty body: %d %s", code, msg)
	}
	// An earlier rule for uploads is not model-checked.
	attrs := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	req, h := reqWith(attrs, "POST", "api.example.com", "/v1/files", nil)
	if r, st := xp.onHeaders(context.Background(), req, h); st != nil || r.GetImmediateResponse() != nil {
		t.Fatalf("files: %v", r)
	}
	// The query string: checked at headers; it names the model for a body
	// with none, and a refusal there sends nothing.
	if code, msg, _ := send("/v1/realtime?model=gpt-4o", nil); code != 403 || !strings.Contains(msg, `model "gpt-4o"`) {
		t.Fatalf("query model: %d %s", code, msg)
	}
	if code, msg, _ := send("/v1/realtime?model=gpt-5", nil, []byte(`{"input":"x"}`)); code != 0 {
		t.Fatalf("query names it: %d %s", code, msg)
	}
	if code, msg, _ := send("/v1/realtime?model=gpt-5", nil, []byte(`{"model":"gpt-4o"}`)); code != 403 {
		t.Fatalf("body contradicts query: %d %s", code, msg)
	}
	// gzip is decoded to read the model; other encodings are refused.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"model":"claude-opus-5-5"}`))
	zw.Close()
	if code, _, _ := send("/v1/messages", map[string]string{"content-encoding": "gzip"}, gz.Bytes()); code != 403 {
		t.Fatalf("gzip: %d", code)
	}
	if code, msg, _ := send("/v1/messages", map[string]string{"content-encoding": "br"}, []byte("x")); code != 415 ||
		!strings.Contains(msg, "for the model it names") {
		t.Fatalf("br: %d %s", code, msg)
	}
	// A host with no model rule gets no body processing.
	req, h = reqWith(attrs, "POST", "other.example.com", "/", nil)
	if _, st := xp.onHeaders(context.Background(), req, h); st != nil {
		t.Fatal("other host held")
	}
	// A CONNECT Envoy does not terminate cannot be checked.
	req, h = reqWith(attrs, "CONNECT", "api.example.com:443", "", nil)
	r, _ := xp.onHeaders(context.Background(), req, h)
	if code, msg := status(r); code != 403 || !strings.Contains(msg, "method, path or model") {
		t.Fatalf("untermined CONNECT: %d %s", code, msg)
	}

	evs := modelEvents(events)
	var got []string
	for _, e := range evs {
		got = append(got, e.Where+":"+e.Model+":"+e.Decision+":"+e.Reason)
	}
	want := []string{
		"body:claude-sonnet-5-5-20261001:allow:", "body:claude-opus-5-5:deny:", "body::deny:no model named",
		`body::deny:its body has more than one "model" field`, "query string:gpt-4o:deny:",
		"query string:gpt-5:allow:", "query string:gpt-5:allow:", "body:gpt-4o:deny:", "body:claude-opus-5-5:deny:",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("events:\n got %v\nwant %v", got, want)
	}
	if evs[1].Rule != "llm" || evs[1].Layer != "mx" || !evs[1].Enforced || evs[0].Rule != "llm" {
		t.Errorf("event fields: %+v %+v", evs[0], evs[1])
	}
	if xp.insp.open != 0 || xp.insp.held.Load() != 0 {
		t.Errorf("leaked: open %d held %d", xp.insp.open, xp.insp.held.Load())
	}
}

// An audit layer's list only records; content rules still apply to a
// model-checked body.
func TestExtProcModelLayers(t *testing.T) {
	audit := strings.NewReplacer("name: mx", "name: ma", "mode: enforce", "mode: audit", `"gpt-5"`, `"gpt-4o"`).Replace(modelXP)
	withContent := modelXP + `  content:
    - { name: keys, regex: "sk-[a-z]{8}", action: redact, to: { fqdn: ["api.example.com"] } }
`
	xp, events, c := modelFixture(t, withContent, audit)
	body := `{"model":"gpt-5","k":"sk-abcdefgh"}`
	r, out, st := post(t, xp, c, "api.example.com", "/v1/chat/completions", nil, []byte(body))
	st.done(xp)
	if code, msg := status(r); code != 0 || string(out) != `{"model":"gpt-5","k":"***********"}` {
		t.Fatalf("layers: %d %s %q", code, msg, out)
	}
	evs := modelEvents(events)
	if len(evs) != 1 || evs[0].Decision != "allow" || len(evs[0].WouldDeny) != 1 || evs[0].WouldDeny[0] != "ma" {
		t.Fatalf("audit layer: %+v", evs)
	}
}
