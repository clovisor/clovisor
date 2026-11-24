// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Request bodies (milestone 5.1). Envoy sends ext_proc headers only; for
// a request that a content rule covers, or to a governed remote MCP
// server, ext_proc switches on streamed request bodies. It holds every
// chunk back (answering each with an empty body), and once the body is
// complete it checks it and releases it whole, redacted, or refuses the
// request. Streamed, because buffered mode stalls a body above Envoy's
// buffer limit and partial mode passes the rest unread (5.0 spikes). The
// cap is ext_proc's own, and a body above it is refused.

// Inspection defaults.
const (
	DefaultMaxBody            = 8 << 20
	DefaultMaxHeldBytes       = 256 << 20
	DefaultMaxInspected       = 4096
	DefaultMaxInspectedPerRun = 256
	// bigBody is the size above which ext_proc extends Envoy's timer
	// before checking a body, which can take longer than its 200 ms.
	bigBody = 1 << 20
	// scanTimeout is what it extends it to; Envoy's max_message_timeout
	// must allow it.
	scanTimeout = 30 * time.Second
)

// ContentData is what the content rules found in one request, for the
// run's timeline. It never holds the matched text.
type ContentData struct {
	Host     string
	Port     uint16
	Method   string
	Path     string
	Where    string // "body" or "query string"
	Bytes    int
	Hits     []ContentHitData
	Decision string // allow, deny or redact
	Enforced bool   // deny: the request was refused; redact: the body was changed
	Rule     string // the rule that refused it
	Layer    string
	Reason   string // a refusal not by a rule: size, encoding, load
	Message  string
}

// ContentHitData is one content rule that matched.
type ContentHitData struct {
	Layer    string
	Rule     string
	Action   string
	Enforced bool
	Count    int
}

// inspectLimits bounds what ext_proc holds at once, node-wide and per
// run, so held bodies and long-lived inspected streams cannot exhaust the
// node agent or Envoy.
type inspectLimits struct {
	mu     sync.Mutex
	open   int
	perRun map[string]int
	held   atomic.Int64
}

// acquire reserves an inspected stream for runID, or says why not.
func (s *ExtProcServer) acquire(runID string) (func(), string) {
	l := &s.insp
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perRun == nil {
		l.perRun = map[string]int{}
	}
	switch {
	case l.open >= orDefault(s.MaxInspected, DefaultMaxInspected):
		return nil, "the proxy is inspecting as many requests as it allows at once"
	case l.perRun[runID] >= orDefault(s.MaxInspectedPerRun, DefaultMaxInspectedPerRun):
		return nil, "this run has as many inspected requests in flight as it may"
	}
	l.open++
	l.perRun[runID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.open--
			if l.perRun[runID]--; l.perRun[runID] <= 0 {
				delete(l.perRun, runID)
			}
			l.mu.Unlock()
		})
	}, ""
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// streamState is what ext_proc keeps for one HTTP stream it inspects.
type streamState struct {
	mcp     *remoteMCP
	body    *heldBody
	budget  *budgetStream
	release func()
}

func (st *streamState) budgetStream() *budgetStream {
	if st == nil {
		return nil
	}
	return st.budget
}

// encodingUnreadable marks a body held only for budgets whose encoding
// cannot be decoded.
const encodingUnreadable = "unreadable"

func (st *streamState) remoteMCP() *remoteMCP {
	if st == nil {
		return nil
	}
	return st.mcp
}

func (st *streamState) done(s *ExtProcServer) {
	if st == nil {
		return
	}
	// A response that ended early is still charged, from what was seen.
	s.finishBudget(st.budget)
	st.budget = nil
	if st.body != nil {
		s.insp.held.Add(-int64(len(st.body.buf)))
		st.body.buf = nil
	}
	if st.release != nil {
		st.release()
	}
}

// heldBody is a request body being collected for inspection.
type heldBody struct {
	d       HTTPData
	runID   string
	runCg   uint64
	leaf    uint64
	eff     *policy.Effective
	content bool // content rules cover this host
	models  []policy.ModelCheck
	// queryModel: the query string named an admitted model.
	queryModel bool
	encoding   string // gzip or deflate, decoded to check; "" plain
	buf        []byte
	max        int
}

// bodyModes is the processing mode for a request whose body is checked
// but whose response is not.
var bodyModes = &filterv3.ProcessingMode{
	RequestHeaderMode:  filterv3.ProcessingMode_SEND,
	RequestBodyMode:    filterv3.ProcessingMode_STREAMED,
	ResponseHeaderMode: filterv3.ProcessingMode_SKIP,
	ResponseBodyMode:   filterv3.ProcessingMode_NONE,
}

func requestBody(b []byte) *extprocv3.ProcessingResponse {
	if b == nil {
		b = []byte{}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
		RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{
			BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: b}}}}}}
}

// bodyEncoding says how a body encoded as ce can be checked: decoded
// (gzip, deflate), as is (none), or not at all.
func bodyEncoding(ce string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ce)) {
	case "", "identity":
		return "", true
	case "gzip", "x-gzip":
		return "gzip", true
	case "deflate":
		return "deflate", true
	}
	return "", false
}

func decodeBody(enc string, b []byte, max int) ([]byte, error) {
	var r io.Reader
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		r = zr
	case "deflate":
		// RFC 9110 deflate is zlib; some clients send raw deflate.
		if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(b))
		}
	default:
		return b, nil
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > max {
		return nil, fmt.Errorf("decoded body is larger than %d bytes", max)
	}
	return out, nil
}

// contentHits converts a verdict's hits for the timeline.
func contentHits(v policy.ContentVerdict) []ContentHitData {
	var out []ContentHitData
	for _, h := range v.Hits {
		out = append(out, ContentHitData{Layer: h.Layer, Rule: h.Rule, Action: h.Action, Enforced: h.Enforced, Count: h.Count})
	}
	return out
}

// checkQuery applies content rules to a request's query string, decoded,
// at headers. Nothing in it can be redacted.
func (s *ExtProcServer) checkQuery(d HTTPData, rawQuery string, eff *policy.Effective, runID string, leaf, runCg uint64) *extprocv3.ProcessingResponse {
	if rawQuery == "" {
		return nil
	}
	data := rawQuery
	if q, err := url.QueryUnescape(rawQuery); err == nil && q != rawQuery {
		data += "\n" + q
	}
	v := eff.ScanContent(d.Host, "query string", []byte(data), false)
	if !v.Matched() {
		return nil
	}
	cd := ContentData{Host: d.Host, Port: d.Port, Method: d.Method, Path: d.Path, Where: "query string", Bytes: len(rawQuery),
		Hits: contentHits(v), Decision: policy.ActionAllow}
	if v.Denied != nil {
		cd.Decision, cd.Enforced, cd.Rule, cd.Layer, cd.Message = policy.ActionDeny, true, v.Denied.Rule, v.Denied.Layer, v.Message
	}
	s.recordContent(leaf, runCg, runID, cd)
	if v.Denied == nil {
		return nil
	}
	d.Decision, d.Enforced, d.Rule, d.Layer, d.Message = policy.ActionDeny, true, v.Denied.Rule, v.Denied.Layer, v.Message
	return s.deny(d, runID)
}

// onBody takes one chunk of a held request body. pre, if set, must be
// sent before resp: it extends Envoy's timer for a large body.
func (s *ExtProcServer) onBody(st *streamState, chunk []byte, eos bool) (pre, resp *extprocv3.ProcessingResponse) {
	b := st.body
	if len(b.buf)+len(chunk) > b.max {
		return nil, s.refuseBody(b, typev3.StatusCode_PayloadTooLarge, "body over the inspection limit",
			fmt.Sprintf("The request body is larger than the %s this proxy checks for content rules, so it was not sent.", sizeString(b.max)))
	}
	if s.insp.held.Add(int64(len(chunk))) > int64(orDefaultInt64(s.MaxHeldBytes, DefaultMaxHeldBytes)) {
		s.insp.held.Add(-int64(len(chunk)))
		return nil, s.refuseBody(b, typev3.StatusCode_ServiceUnavailable, "proxy holding too many bodies",
			"The proxy is holding as many request bodies for inspection as it allows; retry shortly.")
	}
	b.buf = append(b.buf, chunk...)
	if !eos {
		return nil, requestBody(nil)
	}
	if len(b.buf) > bigBody {
		pre = &extprocv3.ProcessingResponse{OverrideMessageTimeout: durationpb.New(scanTimeout)}
	}
	return pre, s.finishBody(st)
}

func orDefaultInt64(v, def int64) int64 {
	if v > 0 {
		return v
	}
	return def
}

func sizeString(n int) string {
	if n%(1<<20) == 0 {
		return strconv.Itoa(n>>20) + " MiB"
	}
	return strconv.Itoa(n) + " bytes"
}

func (s *ExtProcServer) refuseBody(b *heldBody, code typev3.StatusCode, reason, msg string) *extprocv3.ProcessingResponse {
	cd := ContentData{Host: b.d.Host, Port: b.d.Port, Method: b.d.Method, Path: b.d.Path, Where: "body", Bytes: len(b.buf),
		Decision: policy.ActionDeny, Enforced: true, Reason: reason, Message: msg}
	s.recordContent(b.leaf, b.runCg, b.runID, cd)
	d := b.d
	d.Decision, d.Enforced, d.Reason, d.Message = policy.ActionDeny, true, reason, msg
	return s.denyStatus(d, b.runID, code)
}

// finishBody checks a complete body and releases it, changed or not, or
// refuses the request.
func (s *ExtProcServer) finishBody(st *streamState) *extprocv3.ProcessingResponse {
	b := st.body
	body := b.buf
	plain := body
	switch {
	case b.encoding == encodingUnreadable:
		plain = nil
	case b.encoding != "" && (b.content || len(b.models) > 0):
		var err error
		if plain, err = decodeBody(b.encoding, body, b.max); err != nil {
			return s.refuseBody(b, typev3.StatusCode_BadRequest, "body not decodable",
				fmt.Sprintf("The request body, sent as %s, could not be decoded to check it (%v), so it was not sent.", b.encoding, err))
		}
	case b.encoding != "":
		// Budgets alone: decoded only to read the model.
		if p, err := decodeBody(b.encoding, body, b.max); err == nil {
			plain = p
		} else {
			plain = nil
		}
	}
	if len(b.models) > 0 && len(plain) > 0 {
		// An empty body names no model and calls none, as a GET does.
		// One with no model field is let through if the query string
		// named an admitted model; anything unreadable is refused.
		m, why := bodyModel(plain)
		if !(m == policy.ModelMissing && why == "" && b.queryModel) {
			if r := s.checkModel(b.d, b.models, "body", m, why, b.runID, b.leaf, b.runCg); r != nil {
				return r
			}
		}
	}
	if b.content {
		v := b.eff.ScanContent(b.d.Host, "body", plain, b.encoding == "")
		if v.Matched() {
			cd := ContentData{Host: b.d.Host, Port: b.d.Port, Method: b.d.Method, Path: b.d.Path, Where: "body", Bytes: len(plain),
				Hits: contentHits(v), Decision: policy.ActionAllow}
			switch {
			case v.Denied != nil:
				cd.Decision, cd.Enforced, cd.Rule, cd.Layer, cd.Message = policy.ActionDeny, true, v.Denied.Rule, v.Denied.Layer, v.Message
				if b.encoding != "" && v.Denied.Action == policy.ContentActionRedact {
					cd.Message = fmt.Sprintf("The request to %s was not sent: its body, sent as %s, matches content rule %s of profile %s, "+
						"and a compressed body cannot be redacted.", b.d.Host, b.encoding, v.Denied.Rule, v.Denied.Layer)
				}
			case v.Redacts():
				cd.Decision, cd.Enforced = policy.ContentActionRedact, true
			}
			s.recordContent(b.leaf, b.runCg, b.runID, cd)
			if v.Denied != nil {
				d := b.d
				d.Decision, d.Enforced, d.Rule, d.Layer, d.Message = policy.ActionDeny, true, v.Denied.Rule, v.Denied.Layer, cd.Message
				return s.deny(d, b.runID)
			}
			body = v.Redact(body) // same length: Content-Length stays right
		}
	}
	if st.mcp != nil {
		r := s.onMCPRequestBody(st.mcp, body)
		if r.GetImmediateResponse() != nil {
			return r
		}
	}
	if bs := st.budget; bs != nil {
		bs.reqModel = ""
		if m, _ := bodyModel(plain); m != policy.ModelMissing {
			bs.reqModel = m
		}
		if o := s.unpricedBudget(bs); o != nil {
			msg := fmt.Sprintf("The request to %s was not sent: rule %s of profile %s has a cost budget, and this node has no price for model %q.",
				b.d.Host, o.Rule, o.Layer, bs.reqModel)
			st.budget = nil
			s.recordUsage(bs, UsageData{Host: b.d.Host, Port: b.d.Port, Method: b.d.Method, Path: b.d.Path, Model: bs.reqModel,
				Refused: "no price for model", Rule: o.Rule, Layer: o.Layer})
			d := b.d
			d.Decision, d.Enforced, d.Rule, d.Layer, d.Reason, d.Message = policy.ActionDeny, true, o.Rule, o.Layer, "no price for model", msg
			return s.deny(d, b.runID)
		}
		body = bs.requestBody(body, plain, b.encoding)
	}
	return requestBody(body)
}

func (s *ExtProcServer) recordContent(leaf, runCg uint64, runID string, d ContentData) {
	if runID == "" || runCg == 0 || s.events == nil {
		return
	}
	if leaf == 0 {
		leaf = runCg
	}
	select {
	case s.events <- AuditEvent{Type: EventContent, Timestamp: time.Now(), CgroupID: leaf, RunCgroupID: runCg, Data: d}:
	default:
		s.dropped.Add(1)
	}
}
