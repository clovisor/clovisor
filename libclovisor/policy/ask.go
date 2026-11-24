// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"time"
)

// Ask (milestone 5.5). A request a rule with action ask decides is held
// until a person approves or denies it, or its timeout passes and
// on_timeout decides. A profile in mode ask is enforced, except that what
// its egress default would refuse is asked instead; its explicit deny
// rules still deny. MCP sampling: ask holds a server's request for a
// model completion the same way.

// ActionAsk holds a request for a person's decision; ModeAsk is the mode.
const (
	ActionAsk = "ask"
	ModeAsk   = "ask"
)

// Ask bounds. A held request has no traffic, so Envoy's stream idle
// timeout (5 minutes) must not pass while it waits.
const (
	DefaultAskTimeout = 2 * time.Minute
	MaxAskTimeout     = 4 * time.Minute
)

type compiledAsk struct {
	timeout        time.Duration
	allowOnTimeout bool
}

// Enforcing reports whether the profile's refusals are made, not only
// recorded: mode enforce, or mode ask.
func (cp *CompiledProfile) Enforcing() bool { return cp.Mode == ModeEnforce || cp.Mode == ModeAsk }

// askConfig validates an ask block, falling back to def's values.
func (c *compiler) askConfig(where string, a *Ask, def *compiledAsk) *compiledAsk {
	out := &compiledAsk{timeout: DefaultAskTimeout}
	if def != nil {
		*out = *def
	}
	if a == nil {
		return out
	}
	if a.Timeout != "" {
		d, err := time.ParseDuration(a.Timeout)
		switch {
		case err != nil:
			c.errf(where, "ask.timeout %q is not a duration (e.g. 2m)", a.Timeout)
		case d < time.Second || d > MaxAskTimeout:
			c.errf(where, "ask.timeout must be between 1s and %v: a held request has no traffic, and Envoy ends idle streams after 5 minutes", MaxAskTimeout)
		default:
			out.timeout = d
		}
	}
	switch a.OnTimeout {
	case "":
	case ActionDeny:
		out.allowOnTimeout = false
	case ActionAllow:
		out.allowOnTimeout = true
	default:
		c.errf(where, "ask.on_timeout must be deny or allow, got %q", a.OnTimeout)
	}
	return out
}

func (a *compiledAsk) describe() string {
	then := "deny"
	if a.allowOnTimeout {
		then = "allow"
	}
	return fmt.Sprintf("held for a person's decision (agentctl pending, approve, deny); after %s, %s", a.timeout, then)
}

// AskHit is one enforcing layer's ask on a request.
type AskHit struct {
	Layer          string
	Rule           string // "" for a mode ask profile's default
	Message        string // the rule's message: shown to whoever decides
	Timeout        time.Duration
	AllowOnTimeout bool
}

// Asks reports whether the decision holds the request for a person.
func (d EffectiveDecision) Asks() bool { return len(d.AskHits) > 0 }

// AskTimeout is the shortest timeout of the asks, and what happens then:
// allowed only if every ask allows on timeout.
func (d EffectiveDecision) AskTimeout() (time.Duration, bool) {
	var t time.Duration
	allow := true
	for _, h := range d.AskHits {
		if t == 0 || h.Timeout < t {
			t = h.Timeout
		}
		allow = allow && h.AllowOnTimeout
	}
	return t, allow
}
