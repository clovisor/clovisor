// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Budgets in ext_proc (milestone 5.4). A request a budgeted rule decides,
// with a body, is followed to the end of its response, and the usage the
// provider reports there is charged:
//
//   - Anthropic-shaped: usage.input_tokens and output_tokens, with cache
//     tokens apart; streamed, input in message_start and cumulative output
//     in message_delta.
//   - OpenAI-shaped: usage.prompt_tokens and completion_tokens (chat), or
//     input_tokens and output_tokens (responses), cached tokens apart. A
//     streamed chat completion reports usage only if the request sets
//     stream_options.include_usage, so ext_proc sets it, and removes the
//     usage chunk the client did not ask for from the response.
//
// A response with no usage it can read is charged an estimate, a token
// per four bytes each way, and flagged. The request's Accept-Encoding is
// removed so that responses come uncompressed and can be read.

// budgetModes: the request body held (to read the model and set
// include_usage), the response streamed through and read.
var budgetModes = &filterv3.ProcessingMode{
	RequestHeaderMode:  filterv3.ProcessingMode_SEND,
	RequestBodyMode:    filterv3.ProcessingMode_STREAMED,
	ResponseHeaderMode: filterv3.ProcessingMode_SEND,
	ResponseBodyMode:   filterv3.ProcessingMode_STREAMED,
}

// UsageData is one model call's usage and what it was charged, for the
// run's timeline.
type UsageData struct {
	Host      string
	Port      uint16
	Method    string
	Path      string
	Model     string
	Usage     policy.Usage
	CostUSD   float64
	Priced    bool // the node has a price for the model
	Estimated bool // no usage in the response: estimated from bytes
	Partial   bool // the response did not complete
	Status    int
	Streamed  bool
	Charged   bool // false: an error response without usage, or refused
	Budgets   []BudgetState
	// Refused says why the request was refused before it was sent, by
	// Rule of Layer.
	Refused string
	Rule    string
	Layer   string
}

// budgetStream follows one budgeted request to the end of its response.
type budgetStream struct {
	owners []budgetOwner
	d      HTTPData
	runID  string
	leaf   uint64
	runCg  uint64

	reqModel string
	reqBytes int
	// mayInject: the request could be an OpenAI chat or text completion,
	// so its Content-Length was removed at headers and its body may grow.
	mayInject bool
	injected  bool
	sent      bool // the request went upstream

	status    int
	sse       bool
	readable  bool
	respBytes int
	buf       []byte
	overflow  bool
	max       int

	usage     policy.Usage
	seen      bool // the response reported usage
	respModel string
	done      bool
	complete  bool // the response reached its end
}

// mayInjectUsage reports whether a request to path could be an OpenAI
// chat or text completion, whose streamed response needs include_usage.
func mayInjectUsage(path string) bool {
	return strings.HasSuffix(path, "/completions")
}

// rawUsage is a usage object in any of the shapes read.
type rawUsage struct {
	InputTokens      *int64 `json:"input_tokens"`
	OutputTokens     *int64 `json:"output_tokens"`
	CacheCreation    *int64 `json:"cache_creation_input_tokens"`
	CacheRead        *int64 `json:"cache_read_input_tokens"`
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	PromptDetails    *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

func val(p *int64) int64 {
	if p == nil || *p < 0 {
		return 0
	}
	return *p
}

func (r *rawUsage) usage() policy.Usage {
	switch {
	case r.PromptTokens != nil || r.CompletionTokens != nil:
		// OpenAI chat: cached tokens are part of the prompt's.
		var cached int64
		if r.PromptDetails != nil {
			cached = r.PromptDetails.CachedTokens
		}
		in := val(r.PromptTokens)
		cached = min(max(cached, 0), in)
		return policy.Usage{Input: in - cached, Output: val(r.CompletionTokens), CacheRead: cached}
	case r.InputDetails != nil:
		// OpenAI responses: likewise, with Anthropic's field names.
		in := val(r.InputTokens)
		cached := min(max(r.InputDetails.CachedTokens, 0), in)
		return policy.Usage{Input: in - cached, Output: val(r.OutputTokens), CacheRead: cached}
	default:
		return policy.Usage{Input: val(r.InputTokens), Output: val(r.OutputTokens),
			CacheRead: val(r.CacheRead), CacheWrite: val(r.CacheCreation)}
	}
}

type modelUsage struct {
	Model string    `json:"model"`
	Usage *rawUsage `json:"usage"`
}

// responseUsage reads the usage and model in one response object: a
// whole JSON response, or one streamed event. usageOnly reports an
// OpenAI chunk carrying usage and no choices, the one include_usage adds.
func responseUsage(obj []byte) (u policy.Usage, model string, ok, usageOnly bool) {
	var v struct {
		modelUsage
		Message  *modelUsage       `json:"message"`
		Response *modelUsage       `json:"response"`
		Choices  []json.RawMessage `json:"choices"`
	}
	if json.Unmarshal(obj, &v) != nil {
		return u, "", false, false
	}
	model = v.Model
	for _, mu := range []*modelUsage{&v.modelUsage, v.Message, v.Response} {
		if mu == nil {
			continue
		}
		if model == "" {
			model = mu.Model
		}
		if mu.Usage != nil && !ok {
			u, ok = mu.Usage.usage(), true
		}
	}
	if ok && v.Usage != nil && v.Choices != nil && len(v.Choices) == 0 {
		usageOnly = true
	}
	return u, model, ok, usageOnly
}

func maxUsage(a, b policy.Usage) policy.Usage {
	return policy.Usage{Input: max(a.Input, b.Input), Output: max(a.Output, b.Output),
		CacheRead: max(a.CacheRead, b.CacheRead), CacheWrite: max(a.CacheWrite, b.CacheWrite)}
}

// observe takes one response object's usage. Streamed events report
// cumulative counts, so the largest of each is kept.
func (b *budgetStream) observe(obj []byte) (usageOnly bool) {
	u, model, ok, only := responseUsage(obj)
	if b.respModel == "" && model != "" {
		b.respModel = model
	}
	if ok {
		b.usage = maxUsage(b.usage, u)
		b.seen = true
	}
	return only
}

// sseData returns an SSE event's data, or nil.
func sseData(event []byte) []byte {
	var data [][]byte
	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if d, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			data = append(data, bytes.TrimPrefix(d, []byte(" ")))
		}
	}
	if len(data) == 0 {
		return nil
	}
	return bytes.Join(data, []byte("\n"))
}

// withIncludeUsage sets stream_options.include_usage in a streamed
// request's top-level object, keeping every other key and value as sent.
// It reports false, changing nothing, if the request is not streamed,
// already asks for usage, or cannot be rewritten safely.
func withIncludeUsage(body []byte) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return body, false
	}
	type kv struct {
		key string
		raw json.RawMessage
	}
	var kvs []kv
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return body, false
		}
		k, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return body, false
		}
		if (k == "stream" || k == "stream_options") && seen[k] {
			return body, false
		}
		seen[k] = true
		kvs = append(kvs, kv{k, raw})
	}
	if _, err := dec.Token(); err != nil || dec.More() {
		return body, false
	}
	streamed, at := false, -1
	for i, p := range kvs {
		switch p.key {
		case "stream":
			streamed = string(bytes.TrimSpace(p.raw)) == "true"
		case "stream_options":
			at = i
		}
	}
	if !streamed {
		return body, false
	}
	opts := map[string]json.RawMessage{}
	if at >= 0 {
		if json.Unmarshal(kvs[at].raw, &opts) != nil {
			return body, false
		}
		if string(bytes.TrimSpace(opts["include_usage"])) == "true" {
			return body, false
		}
	}
	opts["include_usage"] = json.RawMessage("true")
	raw, _ := json.Marshal(opts)
	if at >= 0 {
		kvs[at].raw = raw
	} else {
		kvs = append(kvs, kv{"stream_options", raw})
	}
	var out bytes.Buffer
	out.WriteByte('{')
	for i, p := range kvs {
		if i > 0 {
			out.WriteByte(',')
		}
		k, _ := json.Marshal(p.key)
		out.Write(k)
		out.WriteByte(':')
		out.Write(p.raw)
	}
	out.WriteByte('}')
	return out.Bytes(), true
}

// budgetRequestBody is a budgeted request's complete body, as it will be
// sent: it notes the model and size, and sets include_usage where it
// can. It returns the body to send.
func (b *budgetStream) requestBody(body, plain []byte, encoding string) []byte {
	b.reqBytes = len(plain)
	if m, _ := bodyModel(plain); m != policy.ModelMissing {
		b.reqModel = m
	}
	if b.mayInject && encoding == "" {
		if nb, ok := withIncludeUsage(body); ok {
			b.injected = true
			body = nb
		}
	}
	b.sent = true
	return body
}

// unpriced reports an enforced cost budget the request's model has no
// price for, which cannot be kept.
func (s *ExtProcServer) unpricedBudget(b *budgetStream) *budgetOwner {
	if b.reqModel == "" {
		return nil
	}
	if _, ok := s.Budgets.prices().Price(b.reqModel); ok {
		return nil
	}
	for i := range b.owners {
		if b.owners[i].Enforced && b.owners[i].CostUSD > 0 {
			return &b.owners[i]
		}
	}
	return nil
}

func (s *ExtProcServer) onBudgetResponseHeaders(b *budgetStream, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	hm := h.GetHeaders()
	b.status, _ = strconv.Atoi(headerValue(hm, ":status"))
	b.sse = strings.HasPrefix(strings.ToLower(headerValue(hm, "content-type")), "text/event-stream")
	// Accept-Encoding was removed, so a compressed response is unexpected;
	// its usage cannot be read, and it is charged an estimate.
	ce := strings.ToLower(strings.TrimSpace(headerValue(hm, "content-encoding")))
	b.readable = ce == "" || ce == "identity"
	cr := &extprocv3.CommonResponse{}
	if b.injected {
		// The usage chunk ext_proc asked for is taken out again.
		cr.HeaderMutation = &extprocv3.HeaderMutation{RemoveHeaders: []string{"content-length"}}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
		ResponseHeaders: &extprocv3.HeadersResponse{Response: cr}}}
}

func passResponseBody() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{}}}
}

// onBudgetResponseBody reads one response chunk for usage. It passes the
// chunk on as is, unless the usage chunk include_usage added must be
// taken out: then events are passed on whole, as they complete.
func (s *ExtProcServer) onBudgetResponseBody(b *budgetStream, chunk []byte, eos bool) *extprocv3.ProcessingResponse {
	b.respBytes += len(chunk)
	rewrite := b.injected && b.sse && b.readable
	resp := passResponseBody()
	switch {
	case !b.readable:
	case b.sse:
		b.buf = append(b.buf, chunk...)
		var out []byte
		for {
			i, n := sseBoundary(b.buf)
			if i < 0 {
				break
			}
			ev := b.buf[:i+n]
			drop := false
			if data := sseData(ev); data != nil && string(data) != "[DONE]" {
				drop = b.observe(data) && b.injected
			}
			if rewrite && !drop {
				out = append(out, ev...)
			}
			b.buf = b.buf[i+n:]
		}
		if eos {
			if data := sseData(b.buf); data != nil && string(data) != "[DONE]" {
				b.observe(data)
			}
			if rewrite {
				out = append(out, b.buf...)
			}
			b.buf = nil
		}
		if !rewrite && len(b.buf) > b.max {
			b.buf, b.overflow = nil, true // an event larger than any usage chunk
		}
		if rewrite {
			resp = bodyMutation(out)
		}
	default:
		if !b.overflow {
			if len(b.buf)+len(chunk) > b.max {
				b.buf, b.overflow = nil, true
			} else {
				b.buf = append(b.buf, chunk...)
			}
		}
		if eos && !b.overflow {
			b.observe(b.buf)
			b.buf = nil
		}
	}
	if eos {
		b.complete = true
		s.finishBudget(b)
	}
	return resp
}

// finishBudget charges a budgeted request once, when its response ends or
// its stream does.
func (s *ExtProcServer) finishBudget(b *budgetStream) {
	if b == nil || b.done || !b.sent || s.Budgets == nil {
		return
	}
	b.done = true
	u := UsageData{Host: b.d.Host, Port: b.d.Port, Method: b.d.Method, Path: b.d.Path, Status: b.status, Streamed: b.sse,
		Partial: !b.complete, Model: b.respModel}
	if u.Model == "" {
		u.Model = b.reqModel
	}
	switch {
	case b.seen:
		u.Usage = b.usage
	case b.status >= 300:
		// An error with no usage: providers do not bill those.
		s.recordUsage(b, u)
		return
	default:
		u.Estimated = true
		u.Usage = policy.Usage{Input: int64(b.reqBytes+3) / 4, Output: int64(b.respBytes+3) / 4}
	}
	u.Charged = true
	cost := -1.0
	if p, ok := s.Budgets.prices().Price(u.Model); ok {
		cost = u.Usage.Cost(p)
		u.CostUSD, u.Priced = cost, true
	}
	u.Budgets = s.Budgets.charge(b.owners, u.Usage, cost, u.Estimated, b.runID)
	s.recordUsage(b, u)
}

func (s *ExtProcServer) recordUsage(b *budgetStream, u UsageData) {
	if b.runID == "" || b.runCg == 0 || s.events == nil {
		return
	}
	leaf := b.leaf
	if leaf == 0 {
		leaf = b.runCg
	}
	select {
	case s.events <- AuditEvent{Type: EventUsage, Timestamp: time.Now(), CgroupID: leaf, RunCgroupID: b.runCg, Data: u}:
	default:
		s.dropped.Add(1)
	}
}
