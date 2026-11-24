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
	"math"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

const budgetXP = `kind: AgentProfile
metadata: { name: bx }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: llm
        to: { fqdn: ["api.example.com"], ports: [80] }
        budget: { tokens: 100000, cost_usd: 1 }
        action: allow
`

const testPrices = `kind: ModelPrices
metadata: { name: test }
spec:
  models:
    - { match: "claude-sonnet-5-5*", input: 3, output: 15, cache_read: 0.3 }
    - { match: "gpt-5", input: 1.25, output: 10, cache_read: 0.125 }
`

func budgetFixture(t *testing.T, layers ...string) (*ExtProcServer, chan AuditEvent, testClient, *CounterStore) {
	t.Helper()
	xp, events, c := modelFixture(t, layers...)
	store, _ := OpenCounterStore("")
	xp.Budgets = NewBudgetLedger(xp.api, store)
	prices, err := policy.ParsePrices([]byte(testPrices))
	if err != nil {
		t.Fatal(err)
	}
	xp.Budgets.Prices = func() *policy.ModelPrices { return prices }
	return xp, events, c, store
}

func respHeadersStatus(status, ct string) *extprocv3.HttpHeaders {
	return &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":status", RawValue: []byte(status)}, {Key: "content-type", RawValue: []byte(ct)}}}}
}

// budgetExchange is one budgeted request and its response.
type budgetExchange struct {
	code     int    // an immediate response's status, or 0
	msg      string // its narration
	sent     []byte // the request body as released upstream
	received []byte // the response body as passed to the client
	removed  []string
	st       *streamState
}

// budgetCall sends a request body and, if it goes upstream, answers it with
// status, content type and response chunks. done: end the stream.
func budgetCall(t *testing.T, xp *ExtProcServer, c testClient, path, body, respStatus, ct string, done bool, chunks ...string) budgetExchange {
	t.Helper()
	attrs := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	req, h := reqWith(attrs, "POST", "api.example.com", path, map[string]string{"accept-encoding": "gzip, br"})
	resp, st := xp.onHeaders(context.Background(), req, h)
	var ex budgetExchange
	if ex.code, ex.msg = status(resp); ex.code != 0 {
		return ex
	}
	ex.removed = resp.GetRequestHeaders().GetResponse().GetHeaderMutation().GetRemoveHeaders()
	ex.st = st
	if st == nil || st.budget == nil {
		t.Fatalf("not followed: %v", resp)
	}
	_, r := xp.onBody(st, []byte(body), true)
	if ex.code, ex.msg = status(r); ex.code != 0 {
		st.done(xp)
		return ex
	}
	ex.sent = r.GetRequestBody().GetResponse().GetBodyMutation().GetBody()
	xp.onBudgetResponseHeaders(st.budget, respHeadersStatus(respStatus, ct))
	for i, ch := range chunks {
		r := xp.onBudgetResponseBody(st.budget, []byte(ch), i == len(chunks)-1 && done)
		if m := r.GetResponseBody().GetResponse().GetBodyMutation(); m != nil {
			ex.received = append(ex.received, m.GetBody()...)
		} else {
			ex.received = append(ex.received, ch...)
		}
	}
	st.done(xp)
	return ex
}

func usageEvents(events chan AuditEvent) []UsageData {
	var out []UsageData
	for {
		select {
		case ev := <-events:
			if ev.Type == EventUsage {
				out = append(out, ev.Data.(UsageData))
			}
		default:
			return out
		}
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestResponseUsage(t *testing.T) {
	for in, want := range map[string]string{
		`{"model":"claude-sonnet-5-5","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100,"cache_creation_input_tokens":7}}`:          "claude-sonnet-5-5 {10 5 100 7} true false",
		`{"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":20,"output_tokens":1}}}`:                                              "claude-x {20 1 0 0} true false",
		`{"type":"message_delta","usage":{"output_tokens":42}}`:                                                                                              " {0 42 0 0} true false",
		`{"model":"gpt-5","choices":[],"usage":{"prompt_tokens":50,"completion_tokens":9,"prompt_tokens_details":{"cached_tokens":20}}}`:                     "gpt-5 {30 9 20 0} true true",
		`{"model":"gpt-5","choices":[{"delta":{}}],"usage":null}`:                                                                                            "gpt-5 {0 0 0 0} false false",
		`{"type":"response.completed","response":{"model":"gpt-5","usage":{"input_tokens":8,"output_tokens":3,"input_tokens_details":{"cached_tokens":2}}}}`: "gpt-5 {6 3 2 0} true false",
		`not json`: " {0 0 0 0} false false",
	} {
		u, m, ok, only := responseUsage([]byte(in))
		got := strings.TrimSpace(strings.Join([]string{m, strings.Trim(strings.ReplaceAll(jsonUsage(u), ",", " "), ""), boolS(ok), boolS(only)}, " "))
		if got != strings.TrimSpace(want) {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
}

func jsonUsage(u policy.Usage) string {
	return "{" + strings.Join([]string{itoa(u.Input), itoa(u.Output), itoa(u.CacheRead), itoa(u.CacheWrite)}, ",") + "}"
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func boolS(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestWithIncludeUsage(t *testing.T) {
	for in, want := range map[string]string{
		`{"model":"gpt-5","stream":true,"messages":[]}`:                  `{"model":"gpt-5","stream":true,"messages":[],"stream_options":{"include_usage":true}}`,
		`{"stream":true,"stream_options":{"include_obfuscation":false}}`: `{"stream":true,"stream_options":{"include_obfuscation":false,"include_usage":true}}`,
		`{"stream":true,"stream_options":{"include_usage":true}}`:        "",
		`{"stream":false}`:                 "",
		`{"model":"gpt-5"}`:                "",
		`{"stream":true,"stream":false}`:   "",
		`[1]`:                              "",
		`{"stream": true , "a\u00e9" : 1}`: `{"stream":true,"aé":1,"stream_options":{"include_usage":true}}`,
	} {
		out, ok := withIncludeUsage([]byte(in))
		switch {
		case want == "" && (ok || string(out) != in):
			t.Errorf("%s changed: %s", in, out)
		case want != "" && (!ok || string(out) != want):
			t.Errorf("%s:\n got %s\nwant %s", in, out, want)
		}
	}
}

func TestExtProcBudget(t *testing.T) {
	xp, events, c, store := budgetFixture(t, budgetXP)
	spend := func() BudgetSpend {
		sp := store.Get("testrun").Spend["bx/llm"]
		if sp == nil {
			return BudgetSpend{}
		}
		return *sp
	}

	// Anthropic, not streamed. Accept-Encoding is removed; Content-Length
	// is kept, since the body cannot change.
	ex := budgetCall(t, xp, c, "/v1/messages", `{"model":"claude-sonnet-5-5","max_tokens":10}`, "200", "application/json", true,
		`{"model":"claude-sonnet-5-5-20261001","content":[],`, `"usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":1000}}`)
	if strings.Join(ex.removed, ",") != "accept-encoding" || ex.code != 0 {
		t.Fatalf("headers: %+v", ex)
	}
	want := (100*3 + 50*15 + 1000*0.3) / 1e6
	if sp := spend(); sp.Tokens != 1150 || !near(sp.CostUSD, want) || sp.Requests != 1 || sp.LimitTokens != 100000 || sp.LimitCost != 1 {
		t.Fatalf("spend after one: %+v", sp)
	}

	// Anthropic, streamed, events split across chunks.
	ex = budgetCall(t, xp, c, "/v1/messages", `{"model":"claude-sonnet-5-5","stream":true}`, "200", "text/event-stream", true,
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5-5\",\"usage\":{\"input_tokens\":200,\"output_tokens\":1}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content",
		"_block_delta\"}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":30}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	if !strings.Contains(string(ex.received), "message_stop") {
		t.Fatalf("stream not passed: %q", ex.received)
	}
	if sp := spend(); sp.Tokens != 1150+230 {
		t.Fatalf("after stream: %+v", sp)
	}

	// OpenAI, streamed, without include_usage: ext_proc sets it, and takes
	// the usage chunk out of what the client receives.
	ex = budgetCall(t, xp, c, "/v1/chat/completions", `{"model":"gpt-5","stream":true,"messages":[]}`, "200", "text/event-stream", true,
		"data: {\"model\":\"gpt-5\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n",
		"data: {\"model\":\"gpt-5\",\"choices\":[],\"usage\":{\"prompt_tokens\":40,\"completion_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":10}}}\n\ndata: [DONE]\n\n")
	if !strings.Contains(string(ex.sent), `"stream_options":{"include_usage":true}`) || !strings.Contains(strings.Join(ex.removed, ","), "content-length") {
		t.Fatalf("include_usage: %q %v", ex.sent, ex.removed)
	}
	if strings.Contains(string(ex.received), "prompt_tokens") || !strings.Contains(string(ex.received), `"content":"hi"`) ||
		!strings.Contains(string(ex.received), "[DONE]") {
		t.Fatalf("client received: %q", ex.received)
	}
	if sp := spend(); sp.Tokens != 1380+45 {
		t.Fatalf("after openai: %+v", sp)
	}

	// The client asked for usage itself: its chunk is left in.
	ex = budgetCall(t, xp, c, "/v1/chat/completions", `{"model":"gpt-5","stream":true,"stream_options":{"include_usage":true}}`, "200", "text/event-stream", true,
		"data: {\"model\":\"gpt-5\",\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n")
	if !strings.Contains(string(ex.received), "prompt_tokens") {
		t.Fatalf("client's usage chunk removed: %q", ex.received)
	}

	// No usage: an estimate, a token per four bytes each way, flagged.
	budgetCall(t, xp, c, "/v1/other", `{"model":"gpt-5","x":"12345678"}`, "200", "application/json", true, `{"ok":true}`)
	// An error with no usage is not charged.
	budgetCall(t, xp, c, "/v1/messages", `{"model":"gpt-5"}`, "529", "application/json", true, `{"error":"overloaded"}`)
	// A response cut off: what was seen is charged, flagged.
	budgetCall(t, xp, c, "/v1/messages", `{"model":"claude-sonnet-5-5","stream":true}`, "200", "text/event-stream", false,
		"data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5-5\",\"usage\":{\"input_tokens\":70,\"output_tokens\":1}}}\n\n")

	// A model the node has no price for, under a cost budget: refused.
	ex = budgetCall(t, xp, c, "/v1/messages", `{"model":"mystery-1"}`, "", "", true)
	if ex.code != 403 || !strings.Contains(ex.msg, `this node has no price for model "mystery-1"`) {
		t.Fatalf("unpriced: %d %s", ex.code, ex.msg)
	}

	evs := usageEvents(events)
	var got []string
	for _, e := range evs {
		got = append(got, strings.Join([]string{e.Model, itoa(e.Usage.Tokens()), boolS(e.Estimated), boolS(e.Partial), boolS(e.Charged), e.Refused}, ":"))
	}
	wantEvs := []string{
		"claude-sonnet-5-5-20261001:1150:false:false:true:", "claude-sonnet-5-5:230:false:false:true:", "gpt-5:45:false:false:true:",
		"gpt-5:2:false:false:true:", "gpt-5:11:true:false:true:", "gpt-5:0:false:false:false:", "claude-sonnet-5-5:71:false:true:true:",
		"mystery-1:0:false:false:false:no price for model",
	}
	if strings.Join(got, ",") != strings.Join(wantEvs, ",") {
		t.Errorf("usage events\n got %v\nwant %v", got, wantEvs)
	}
	sp := spend()
	if sp.Estimated != 1 || sp.Requests != 6 || len(evs[0].Budgets) != 1 || evs[0].Budgets[0].Tokens != 1150 {
		t.Errorf("spend: %+v; first event budgets %+v", sp, evs[0].Budgets)
	}

	// Spent: refused at headers, before any body is sent.
	store.Update("testrun", func(rc *RunCounters) { rc.Spend["bx/llm"].CostUSD = 1 })
	ex = budgetCall(t, xp, c, "/v1/messages", `{"model":"gpt-5"}`, "", "", true)
	if ex.code != 403 || !strings.Contains(ex.msg, "This run has spent the budget of rule llm of profile bx (100000 tokens and $1.00)") {
		t.Fatalf("spent: %d %s", ex.code, ex.msg)
	}
	if xp.insp.open != 0 || xp.insp.held.Load() != 0 {
		t.Errorf("leaked: open %d held %d", xp.insp.open, xp.insp.held.Load())
	}
}

// A nested run's calls are charged to its parent's budget; an audit
// layer's spent budget refuses nothing.
func TestExtProcBudgetNested(t *testing.T) {
	audit := strings.NewReplacer("name: bx", "name: ba", "mode: enforce", "mode: audit", "tokens: 100000", "tokens: 10").Replace(budgetXP)
	xp, _, c, store := budgetFixture(t, budgetXP, audit)
	// testrun (bound to the client's cgroup) is nested in "parent", which
	// holds both layers.
	b := xp.api.bound["testrun"]
	xp.api.bound["parent"] = &boundRun{runID: "parent", eff: b.eff}
	xp.api.active["parent"], xp.api.active["testrun"] = true, true
	xp.api.parentOf = map[string]string{"testrun": "parent"}

	budgetCall(t, xp, c, "/v1/messages", `{"model":"claude-sonnet-5-5"}`, "200", "application/json", true,
		`{"usage":{"input_tokens":10,"output_tokens":10}}`)
	if store.Get("testrun").Spend != nil {
		t.Errorf("charged to the nested run: %+v", store.Get("testrun"))
	}
	p := store.Get("parent").Spend
	if p["bx/llm"] == nil || p["bx/llm"].Tokens != 20 || p["ba/llm"] == nil || p["ba/llm"].Tokens != 20 {
		t.Fatalf("parent spend: %+v", p)
	}
	// ba's 10 tokens are spent, but it only audits: the next request goes.
	attrs := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	req, h := reqWith(attrs, "POST", "api.example.com", "/v1/messages", nil)
	resp, st := xp.onHeaders(context.Background(), req, h)
	if code, _ := status(resp); code != 0 || st == nil {
		t.Fatalf("audit budget refused: %v", resp)
	}
	st.done(xp)
	// bx spent: the parent's budget refuses the nested run, and says whose.
	store.Update("parent", func(rc *RunCounters) { rc.Spend["bx/llm"].Tokens = 100000 })
	resp, _ = xp.onHeaders(context.Background(), req, h)
	if code, msg := status(resp); code != 403 || !strings.Contains(msg, "Run parent and the runs nested in it have spent the budget of rule llm") {
		t.Fatalf("nested refusal: %d %s", code, msg)
	}
}
