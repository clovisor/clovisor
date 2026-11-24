// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Limits (milestone 5.2). A profile's limits block bounds a run as a whole:
// how long it may last, how many connections it may open a minute, and how
// many bytes it may send. A rate-limit egress rule bounds the requests
// that match it. All are counted for the run that holds the layer: a
// nested run inherits its parent's layers, so what it does is charged to
// its parent's counts too, and it can never get a fresh allowance.

// ActionRateLimit allows matching requests up to the rule's rate.
const ActionRateLimit = "rate-limit"

// Rate is a rate-limit rule's allowance: Requests per Per.
type Rate struct {
	Requests int    `yaml:"requests" json:"requests"`
	Per      string `yaml:"per" json:"per"` // a duration: 1s, 1m, 1h
}

// Limit bounds.
const (
	maxRatePer      = 24 * time.Hour
	maxDuration     = 30 * 24 * time.Hour
	minDuration     = time.Second
	maxConnsPerMin  = 1 << 20
	maxRateRequests = 1 << 20
)

// CompiledLimits are a profile's limits, parsed. Zero means no limit.
type CompiledLimits struct {
	ConnectionsPerMin int
	EgressBytes       uint64
	Duration          time.Duration
}

// Any reports whether any limit is set.
func (l CompiledLimits) Any() bool {
	return l.ConnectionsPerMin > 0 || l.EgressBytes > 0 || l.Duration > 0
}

// ParseBytes reads a byte quantity: a plain number, or one with a suffix
// K, M, G, T (powers of 1000) or Ki, Mi, Gi, Ti (powers of 1024).
func ParseBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   uint64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40},
		{"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}}
	mult := uint64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not a positive byte count (e.g. 100Mi, 2G, 500000)", s)
	}
	if n > (1<<63)/mult {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return n * mult, nil
}

func (c *compiler) limits(p *AgentProfile, cp *CompiledProfile) {
	l := p.Spec.Limits
	if l == nil {
		return
	}
	var out CompiledLimits
	if l.ConnectionsPerMin != 0 {
		if l.ConnectionsPerMin < 0 || l.ConnectionsPerMin > maxConnsPerMin {
			c.errf("limits.connections_per_min", "must be between 1 and %d", maxConnsPerMin)
		} else {
			out.ConnectionsPerMin = l.ConnectionsPerMin
			pl := Placement{Rule: "limits/connections_per_min", Tier: "2",
				EnforcedBy: "ext_proc: connections and plain-HTTP requests through the proxy, per minute",
				Notes: []string{fmt.Sprintf("%d a minute, as a token bucket; beyond it, a narrated 429", l.ConnectionsPerMin),
					"shared with the run's nested runs"}}
			if c.opts.Mode == ExplicitProxy {
				pl.Notes = append(pl.Notes, "explicit proxy: connections that bypass the proxy are not counted")
			}
			cp.Placements = append(cp.Placements, pl)
		}
	}
	if l.EgressBytes != "" {
		n, err := ParseBytes(l.EgressBytes)
		switch {
		case err != nil:
			c.errf("limits.egress_bytes", "%v", err)
		case !c.opts.Linux:
			c.errf("limits.egress_bytes", "egress_bytes needs the Linux node agent with cgroup identity: "+
				"only the kernel sees every byte a run sends, tunnels included")
		default:
			out.EgressBytes = n
			cp.Placements = append(cp.Placements, Placement{Rule: "limits/egress_bytes", Tier: "0",
				EnforcedBy: "kernel (cgroup_skb egress), per run; node agent revokes egress",
				Notes: []string{fmt.Sprintf("%d bytes on the wire, headers included, to other hosts and to the proxy and resolver; "+
					"loopback within the node is not counted", n),
					"past it, the run's packets are dropped and its egress revoked",
					"shared with the run's nested runs"}})
		}
	}
	if l.Duration != "" {
		d, err := time.ParseDuration(l.Duration)
		switch {
		case err != nil:
			c.errf("limits.duration", "%q is not a duration (e.g. 30m, 2h)", l.Duration)
		case d < minDuration || d > maxDuration:
			c.errf("limits.duration", "must be between %v and %v", minDuration, maxDuration)
		default:
			out.Duration = d
			notes := []string{"its processes are killed and its nested runs end with it",
				"counted from when the run that holds the profile started"}
			if !c.opts.Linux {
				notes[0] = "credential identity: the run's proxy credential stops working and its nested runs end; " +
					"its processes are not killed (they are in no cgroup)"
			}
			cp.Placements = append(cp.Placements, Placement{Rule: "limits/duration", Tier: "node",
				EnforcedBy: "node agent: ends the run when it has lasted " + d.String(), Notes: notes})
		}
	}
	cp.Limits = out
}

// rate validates a rate-limit rule's rate.
func (c *compiler) rate(where string, r EgressRule) *compiledRate {
	if r.Rate == nil {
		c.errf(where, "a rate-limit rule needs rate: { requests: N, per: 1m }")
		return nil
	}
	per, err := time.ParseDuration(r.Rate.Per)
	switch {
	case err != nil:
		c.errf(where, "rate.per %q is not a duration (e.g. 1m)", r.Rate.Per)
		return nil
	case per < time.Second || per > maxRatePer:
		c.errf(where, "rate.per must be between 1s and %v", maxRatePer)
		return nil
	case r.Rate.Requests < 1 || r.Rate.Requests > maxRateRequests:
		c.errf(where, "rate.requests must be between 1 and %d", maxRateRequests)
		return nil
	}
	return &compiledRate{requests: r.Rate.Requests, per: per}
}

type compiledRate struct {
	requests int
	per      time.Duration
}

// RateHit is a rate-limit rule that matched a request: the request is
// allowed if the rule's allowance has room.
type RateHit struct {
	// Profile is the layer's profile; the allowance is per run holding it.
	Profile  *CompiledProfile
	Layer    string
	Rule     string
	Requests int
	Per      time.Duration
	Message  string
	Enforced bool // the layer is in enforce mode
}

// LayerLimits are one layer's limits, with the profile that holds them.
type LayerLimits struct {
	Profile  *CompiledProfile
	Layer    string
	Enforced bool
	CompiledLimits
}

// Limits lists the layers that set limits.
func (e *Effective) Limits() []LayerLimits {
	var out []LayerLimits
	for _, l := range e.Layers {
		if l.Profile.Limits.Any() {
			out = append(out, LayerLimits{Profile: l.Profile, Layer: l.Profile.Name,
				Enforced: l.Profile.Mode == ModeEnforce, CompiledLimits: l.Profile.Limits})
		}
	}
	return out
}

// Has reports whether cp is one of the layers.
func (e *Effective) Has(cp *CompiledProfile) bool { return e != nil && e.has(cp) }

// RateMessage narrates a refusal by a rate-limit rule.
func (h RateHit) RateMessage(host string) string {
	if h.Message != "" {
		return h.Message
	}
	return fmt.Sprintf("Requests to %s are limited to %d per %s by rule %s of profile %s; retry later.",
		host, h.Requests, h.Per, h.Rule, h.Layer)
}
