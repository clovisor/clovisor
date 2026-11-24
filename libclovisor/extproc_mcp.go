// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Remote MCP (design §8.1, milestone 2.5). A request on a terminated
// connection to a host the run's policy names as an MCP server has its
// JSON-RPC inspected. Envoy sends ext_proc headers only by default; for
// these streams alone ext_proc switches on body processing with a mode
// override, so runs whose policy has no body rule for a destination never
// have their bodies sent (§6.6).

// remoteMCP is the per-stream state of an inspected MCP request.
type remoteMCP struct {
	host  string
	runID string
	runCg uint64
	eff   *policy.Effective
	// ctx is the stream's: a held sampling ask ends with it.
	ctx context.Context

	toolsList map[string]bool // ids of tools/list requests in this POST
	sse       bool
	buf       []byte
}

// mcpDrift remembers, per run and remote host, tools whose definitions
// changed since pinned, so later calls to them are refused too.
type mcpDrift struct {
	mu sync.Mutex
	m  map[string]map[string]bool
}

func (d *mcpDrift) set(key, tool string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]map[string]bool{}
	}
	if d.m[key] == nil {
		d.m[key] = map[string]bool{}
	}
	d.m[key][tool] = true
}

func (d *mcpDrift) has(key, tool string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[key][tool]
}

// mcpModes is the processing mode for inspected MCP streams: streamed
// request bodies, held by ext_proc until complete (buffered mode stalls a
// body above Envoy's buffer limit, 5.0 spikes), and streamed response
// bodies so SSE keeps flowing.
var mcpModes = &filterv3.ProcessingMode{
	RequestHeaderMode:  filterv3.ProcessingMode_SEND,
	RequestBodyMode:    filterv3.ProcessingMode_STREAMED,
	ResponseHeaderMode: filterv3.ProcessingMode_SEND,
	ResponseBodyMode:   filterv3.ProcessingMode_STREAMED,
}

func (s *ExtProcServer) recordMCP(m *remoteMCP, d MCPData) {
	if s.events == nil || m.runCg == 0 {
		return
	}
	select {
	case s.events <- AuditEvent{Type: EventMCP, Timestamp: time.Now(), CgroupID: m.runCg, RunCgroupID: m.runCg, Data: d}:
	default:
		s.dropped.Add(1)
	}
}

func (m *remoteMCP) decide(kind, tool, uri string) policy.EffectiveDecision {
	return m.eff.DecideMCP(policy.MCPRequest{Kind: kind, Server: m.host, Host: m.host, Tool: tool, URI: uri})
}

func (m *remoteMCP) driftKey() string { return m.runID + "/" + m.host }

func continueBody() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{}}}
}

// onMCPRequestBody decides the JSON-RPC requests in a POST. Denied calls
// are answered in place: the server never sees them.
func (s *ExtProcServer) onMCPRequestBody(m *remoteMCP, body []byte) *extprocv3.ProcessingResponse {
	body = bytes.TrimSpace(body)
	batch := len(body) > 0 && body[0] == '['
	var raws []json.RawMessage
	if batch {
		if json.Unmarshal(body, &raws) != nil {
			return continueBody()
		}
	} else {
		raws = []json.RawMessage{body}
	}
	m.toolsList = map[string]bool{}
	var answers [][]byte
	denied := false
	for _, raw := range raws {
		var msg rpcMsg
		if json.Unmarshal(raw, &msg) != nil || !msg.isRequest() {
			answers = append(answers, nil)
			continue
		}
		var answer []byte
		switch msg.Method {
		case "tools/list":
			m.toolsList[string(msg.ID)] = true
		case "tools/call":
			var p struct {
				Name string `json:"name"`
			}
			json.Unmarshal(msg.Params, &p)
			d := m.decide("tool", p.Name, "")
			data := mcpData(m.host, msg.Method, p.Name, d)
			if d.Allowed() && m.eff.Enforcing() && s.drift.has(m.driftKey(), p.Name) {
				d.Action, d.Enforced = policy.ActionDeny, true
				d.Message = "Tool " + p.Name + " on MCP server " + m.host + " changed its definition since it was pinned; " +
					"it stays blocked until an operator re-approves it."
				data = mcpData(m.host, msg.Method, p.Name, d)
				data.Reason = "tool definition changed since pinned"
			}
			s.recordMCP(m, data)
			if !d.Allowed() {
				answer = toolDenied(msg.ID, d.Message)
			}
		case "resources/read":
			var p struct {
				URI string `json:"uri"`
			}
			json.Unmarshal(msg.Params, &p)
			d := m.decide("resource", "", p.URI)
			s.recordMCP(m, mcpData(m.host, msg.Method, p.URI, d))
			if !d.Allowed() {
				answer = rpcError(msg.ID, -32002, d.Message)
			}
		}
		if answer != nil {
			denied = true
		}
		answers = append(answers, answer)
	}
	if !denied {
		return continueBody()
	}

	// Answer the whole POST here. In a batch, requests that were allowed
	// cannot be forwarded alone, so they are refused with a reason.
	var out []byte
	if batch {
		var parts [][]byte
		for i, raw := range raws {
			if answers[i] != nil {
				parts = append(parts, answers[i])
				continue
			}
			var msg rpcMsg
			if json.Unmarshal(raw, &msg) == nil && msg.isRequest() {
				parts = append(parts, rpcError(msg.ID, -32003, "Not forwarded: another request in this batch was denied by policy."))
			}
		}
		out = append(append([]byte("["), bytes.Join(parts, []byte(","))...), ']')
	} else {
		out = answers[0]
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status: &typev3.HttpStatus{Code: typev3.StatusCode_OK},
			Body:   out,
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
				{Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}},
			}},
			Details: "clovisor_mcp_deny",
		},
	}}
}

// onMCPResponseHeaders notes the response type. The body may change
// length, so content-length goes.
func (s *ExtProcServer) onMCPResponseHeaders(m *remoteMCP, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	m.sse = strings.HasPrefix(strings.ToLower(headerValue(h.GetHeaders(), "content-type")), "text/event-stream")
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
		ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{
			HeaderMutation: &extprocv3.HeaderMutation{RemoveHeaders: []string{"content-length"}},
		}},
	}}
}

func bodyMutation(b []byte) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
		ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{
			BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: b}},
		}},
	}}
}

// onMCPResponseBody rewrites a streamed response chunk. JSON responses are
// held until complete; SSE is passed on event by event, since an event
// can be split across chunks.
func (s *ExtProcServer) onMCPResponseBody(m *remoteMCP, chunk []byte, eos bool) *extprocv3.ProcessingResponse {
	m.buf = append(m.buf, chunk...)
	if !m.sse {
		if !eos {
			return bodyMutation(nil)
		}
		out := m.buf
		m.buf = nil
		if len(m.toolsList) > 0 {
			out = s.toolFilterFor(m).apply(out)
		}
		return bodyMutation(out)
	}
	var out []byte
	for {
		i, n := sseBoundary(m.buf)
		if i < 0 {
			break
		}
		out = append(out, s.mcpEvent(m, m.buf[:i+n])...)
		m.buf = m.buf[i+n:]
	}
	if eos {
		out = append(out, m.buf...)
		m.buf = nil
	}
	return bodyMutation(out)
}

// sseBoundary finds the blank line ending the first SSE event.
func sseBoundary(b []byte) (int, int) {
	best, size := -1, 0
	for _, sep := range []string{"\n\n", "\r\n\r\n", "\r\r"} {
		if i := bytes.Index(b, []byte(sep)); i >= 0 && (best < 0 || i < best) {
			best, size = i, len(sep)
		}
	}
	return best, size
}

// mcpEvent rewrites one SSE event: tools/list results are filtered, and
// server-initiated sampling requests are cut out (the sampling inversion,
// §8.4), so the client never runs them.
func (s *ExtProcServer) mcpEvent(m *remoteMCP, ev []byte) []byte {
	var data []string
	var other []string
	for _, line := range strings.Split(strings.TrimRight(string(ev), "\r\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(v, " "))
		} else {
			other = append(other, line)
		}
	}
	if len(data) == 0 {
		return ev
	}
	payload := []byte(strings.Join(data, "\n"))
	var msg rpcMsg
	if json.Unmarshal(payload, &msg) != nil {
		return ev
	}
	switch {
	case msg.Method == "sampling/createMessage" && msg.isRequest():
		d := m.decide("sampling", "", "")
		data := mcpData(m.host, msg.Method, "", d)
		if d.Asks() {
			// sampling: ask (milestone 5.5): held for a person.
			ok, a := s.askSampling(m, d, samplingDetail(msg.Params))
			settleAsk(&data, d, ok, a)
			s.recordMCP(m, data)
			if !ok {
				return nil
			}
			return ev
		}
		s.recordMCP(m, data)
		if !d.Allowed() {
			return nil
		}
		return ev
	case msg.isResponse() && m.toolsList[string(msg.ID)]:
		payload = s.toolFilterFor(m).apply(payload)
	default:
		return ev
	}
	var b strings.Builder
	for _, l := range other {
		b.WriteString(l + "\n")
	}
	b.WriteString("data: " + string(payload) + "\n\n")
	return []byte(b.String())
}

func (s *ExtProcServer) toolFilterFor(m *remoteMCP) toolFilter {
	f := toolFilter{
		decide: func(tool string) policy.EffectiveDecision { return m.decide("tool", tool, "") },
		pins:   s.Pins,
		drift: func(tool string, blocked bool) {
			s.drift.set(m.driftKey(), tool)
			s.recordMCP(m, driftData(m.host, tool, blocked))
		},
	}
	if m.eff.PinsToolDefinitions(nil, m.host) {
		for _, l := range m.eff.Layers {
			if r := l.Profile.MCPServerRule(nil, m.host); r != "" {
				f.pinKey = l.Profile.Name + "/" + r
				break
			}
		}
		f.enforcing = m.eff.Enforcing()
	}
	return f
}
