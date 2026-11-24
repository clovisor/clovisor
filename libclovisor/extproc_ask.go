// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"fmt"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Ask in ext_proc (milestone 5.5). A request an ask rule decides is held:
// ext_proc extends Envoy's timer for the message once, for the whole
// hold (Envoy honours one extension per stream, 5.1), puts the request in
// the node's queue, and answers when it is decided. A client that goes
// away cancels the stream, and the request is settled as abandoned.

// askMargin is added to an ask's timeout when extending Envoy's timer, so
// that ext_proc, not Envoy, answers a request that times out.
const askMargin = 10 * time.Second

// AskData is how an ask was settled, for the run's timeline.
type AskData struct {
	ID     string
	State  string // approved, denied, timed out, abandoned, remembered, not held
	By     string
	Waited time.Duration
}

type extenderKey struct{}

// withExtender gives a stream's handlers a way to extend Envoy's timer for
// the message being answered.
func withExtender(ctx context.Context, f func(time.Duration) error) context.Context {
	return context.WithValue(ctx, extenderKey{}, f)
}

func extend(ctx context.Context, d time.Duration) {
	if f, ok := ctx.Value(extenderKey{}).(func(time.Duration) error); ok {
		f(d)
	}
}

func overrideTimeout(d time.Duration) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{OverrideMessageTimeout: durationpb.New(d)}
}

// ask holds a request for a decision. It returns the status to refuse it
// with, or 0 to let it through; d records the outcome.
func (s *ExtProcServer) ask(ctx context.Context, d *HTTPData, ed policy.EffectiveDecision, runID, what string) typev3.StatusCode {
	hit := ed.AskHits[0]
	if s.Asks == nil {
		d.Decision, d.Enforced, d.Layer, d.Rule, d.Reason = policy.ActionDeny, true, hit.Layer, hit.Rule, "ask: no approval queue"
		d.Message = fmt.Sprintf("%s needs a person's approval (profile %s), and this node agent takes none.", what, hit.Layer)
		return typev3.StatusCode_Forbidden
	}
	timeout, allowOnTimeout := ed.AskTimeout()
	extend(ctx, timeout+askMargin)
	p := PendingAsk{RunID: runID, UID: s.api.ownerOf(runID), Kind: "egress", What: what, Host: policy.NormalizeHost(d.Host),
		Layer: hit.Layer, Rule: hit.Rule, Message: hit.Message}
	r := s.Asks.Ask(ctx, p, timeout, allowOnTimeout)
	d.Ask = &AskData{ID: r.ID, State: r.State, By: r.By, Waited: r.Waited}
	if r.Allowed {
		d.Decision, d.Rule, d.Layer = policy.ActionAllow, hit.Rule, hit.Layer
		d.Reason = "ask: " + r.State
		if r.By != "" {
			d.Reason += " by " + r.By
		}
		return 0
	}
	d.Decision, d.Enforced, d.Layer, d.Rule, d.Reason = policy.ActionDeny, true, hit.Layer, hit.Rule, "ask: "+r.State
	if r.By != "" {
		d.Reason += " by " + r.By
	}
	d.Message = askRefusal(what, hit, r, timeout)
	if r.State == AskRefused {
		return typev3.StatusCode_ServiceUnavailable
	}
	return typev3.StatusCode_Forbidden
}

// askRefusal narrates an ask that did not end in approval.
func askRefusal(what string, hit policy.AskHit, r AskResult, timeout time.Duration) string {
	by := ""
	if hit.Rule != "" {
		by = fmt.Sprintf(" (rule %s of profile %s)", hit.Rule, hit.Layer)
	} else {
		by = fmt.Sprintf(" (profile %s asks about what it does not allow)", hit.Layer)
	}
	switch r.State {
	case AskDenied:
		return fmt.Sprintf("A person declined %s%s.", what, by)
	case AskRemembered:
		return fmt.Sprintf("A person declined requests like %s for this run%s.", what, by)
	case AskTimedOut:
		return fmt.Sprintf("%s needed a person's approval%s, and no one gave it within %s.", what, by, timeout)
	case AskRefused:
		return fmt.Sprintf("%s needs a person's approval%s, but was not held: %s; retry later.", what, by, r.Reason)
	default:
		return fmt.Sprintf("%s needed a person's approval%s; it was %s.", what, by, r.State)
	}
}

// askSampling holds an MCP server's sampling request on a remote MCP
// stream for a decision. It reports whether the client may receive it.
func (s *ExtProcServer) askSampling(m *remoteMCP, d policy.EffectiveDecision, detail string) (bool, *AskData) {
	if s.Asks == nil || m.ctx == nil {
		return false, &AskData{State: "no approval queue"}
	}
	hit := d.AskHits[0]
	timeout, allowOnTimeout := d.AskTimeout()
	extend(m.ctx, timeout+askMargin)
	p := PendingAsk{RunID: m.runID, UID: s.api.ownerOf(m.runID), Kind: "sampling", What: "sampling/createMessage from MCP server " + m.host,
		Host: m.host, Layer: hit.Layer, Rule: hit.Rule, Message: hit.Message, Detail: detail}
	r := s.Asks.Ask(m.ctx, p, timeout, allowOnTimeout)
	return r.Allowed, &AskData{ID: r.ID, State: r.State, By: r.By, Waited: r.Waited}
}

// samplingDetail is the start of a sampling request's params, for whoever
// decides.
func samplingDetail(params []byte) string {
	const max = 400
	if len(params) > max {
		return string(params[:max]) + "…"
	}
	return string(params)
}

// askWhat names a request for whoever decides.
func askWhat(d HTTPData) string {
	if d.Method == "CONNECT" {
		return fmt.Sprintf("CONNECT %s:%d", d.Host, d.Port)
	}
	return fmt.Sprintf("%s %s%s", d.Method, d.Host, d.Path)
}

// askNote is an ask's outcome for the timeline.
func askNote(a *AskData) string {
	if a == nil {
		return ""
	}
	n := "ask " + a.ID + ": " + a.State
	if a.By != "" {
		n += " by " + a.By
	}
	if a.Waited > 0 {
		n += fmt.Sprintf(" after %s", a.Waited.Round(time.Millisecond))
	}
	return n
}

// httpNote is an http event's note for the timeline: QUIC, and an ask.
func httpNote(d HTTPData) string {
	n := askNote(d.Ask)
	if d.QUIC {
		q := "QUIC"
		if d.Upstream != "" {
			q += " to " + d.Upstream
		}
		if n != "" {
			q += "; " + n
		}
		n = q
	}
	return n
}
