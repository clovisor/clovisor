// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
)

// Content rules (milestone 5.1): patterns checked against what a run
// sends in a request body and query string, on destinations whose
// requests the proxy reads (terminated TLS, or plaintext HTTP). A rule
// denies the request, redacts the matches, or records them.
//
// A rule's to: names the hosts it covers. Without it, it covers every host
// the profile allows by name; those hosts are terminated for it, as for
// http rules. Hosts the proxy cannot read (no_terminate, by address, or
// reached only through fqdn "*" or the egress default) are left out, and
// the receipt says so.

// ContentScope narrows a content rule to some hosts.
type ContentScope struct {
	FQDN []string `yaml:"fqdn" json:"fqdn"`
}

// Content limits.
const (
	MaxContentRules = 32
	maxContentRegex = 1024
)

// ContentActionRedact is the redact action, valid in content rules only.
const ContentActionRedact = "redact"

type compiledContent struct {
	name      string
	re        *regexp.Regexp
	action    string
	message   string
	hosts     []hostPattern
	unbounded bool
}

// unboundedRepeat reports whether a pattern has a repetition with no upper
// bound, so one match can run to the end of a body.
func unboundedRepeat(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
		return true
	case syntax.OpRepeat:
		if re.Max < 0 {
			return true
		}
	}
	for _, s := range re.Sub {
		if unboundedRepeat(s) {
			return true
		}
	}
	return false
}

// contentDefaultScope is the hosts a content rule without to: covers: those
// the profile allows by name, and its remote MCP servers. left lists those
// it cannot cover, and why.
func contentDefaultScope(p *AgentProfile) (hosts []string, plain map[string]bool, left []string) {
	seen := map[string]bool{}
	plain = map[string]bool{}
	nonPlain := map[string]bool{}
	add := func(h string, port80 bool) {
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
		if !port80 {
			nonPlain[h] = true
		}
	}
	var star, cidr bool
	var noTerm, raw []string
	seenRaw := map[string]bool{}
	isNoTerm := map[string]bool{}
	for _, r := range p.Spec.Egress.Rules {
		for _, h := range r.To.FQDN {
			if r.NoTerminate && !isNoTerm[h] {
				isNoTerm[h] = true
				noTerm = append(noTerm, h)
			}
		}
	}
	for _, r := range p.Spec.Egress.Rules {
		if r.Action == ActionDeny {
			continue
		}
		if len(r.To.CIDR) > 0 {
			cidr = true
		}
		for _, h := range r.To.FQDN {
			if _, err := parseHost(h); err != nil {
				continue // reported by the egress checks
			}
			switch {
			case h == "*":
				star = true
			case isNoTerm[h]:
			case !mayCarryHTTP(r.To.Ports):
				if !seenRaw[h] {
					seenRaw[h] = true
					raw = append(raw, h)
				}
			default:
				add(h, onlyPort80(r.To.Ports))
			}
		}
	}
	if p.Spec.MCP != nil {
		for _, s := range p.Spec.MCP.Servers {
			if s.Match.FQDN != "" {
				add(s.Match.FQDN, false)
			}
		}
	}
	for _, h := range hosts {
		plain[h] = !nonPlain[h]
	}
	if len(noTerm) > 0 {
		left = append(left, strings.Join(noTerm, ", ")+" (no_terminate)")
	}
	var rawOnly []string
	for _, h := range raw {
		if !seen[h] {
			rawOnly = append(rawOnly, h)
		}
	}
	if len(rawOnly) > 0 {
		left = append(left, strings.Join(rawOnly, ", ")+" (allowed on no HTTP or TLS port)")
	}
	if cidr {
		left = append(left, "destinations allowed by address (cidr)")
	}
	if star {
		left = append(left, `hosts allowed only through fqdn "*"`)
	}
	if p.Spec.Egress.Default == ActionAllow {
		left = append(left, "hosts allowed only by the egress default")
	}
	return hosts, plain, left
}

// mayCarryHTTP: the ports include one usually HTTP or TLS (none listed
// means any port).
func mayCarryHTTP(ports []uint16) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		switch p {
		case 80, 443, 8080, 8443:
			return true
		}
	}
	return false
}

// contentScope is the hosts a rule covers, and whether each is reached on
// port 80 only (plaintext, no termination needed).
func contentScope(p *AgentProfile, r ContentRule) ([]string, map[string]bool) {
	if r.To != nil {
		plain := map[string]bool{}
		for _, h := range r.To.FQDN {
			plain[h] = false
		}
		return r.To.FQDN, plain
	}
	hosts, plain, _ := contentDefaultScope(p)
	return hosts, plain
}

func (c *compiler) content(p *AgentProfile, cp *CompiledProfile) {
	rules := p.Spec.Content
	if len(rules) == 0 {
		return
	}
	if len(rules) > MaxContentRules {
		c.errf("content", "at most %d rules", MaxContentRules)
	}
	_, _, left := contentDefaultScope(p)
	names := map[string]bool{}
	for i, r := range rules {
		where := fmt.Sprintf("content[%d]", i)
		if r.Name != "" {
			where += " (" + r.Name + ")"
		}
		if !nameRE.MatchString(r.Name) {
			c.errf(where, "name %q must be lowercase letters, digits and '-'", r.Name)
		}
		if names[r.Name] {
			c.errf(where, "duplicate content rule name %q", r.Name)
		}
		names[r.Name] = true
		switch r.Action {
		case ActionDeny, ContentActionRedact, ActionTagAndLog:
		case "":
			c.errf(where, "action is required: deny, redact or tag-and-log")
		default:
			c.errf(where, "action must be deny, redact or tag-and-log, got %q", r.Action)
		}
		if r.Message != "" && r.Action != ActionDeny {
			c.errf(where, "message: is only valid with action deny")
		}
		if r.Regex == "" {
			c.errf(where, "regex is required")
			continue
		}
		if len(r.Regex) > maxContentRegex {
			c.errf(where, "regex is longer than %d characters", maxContentRegex)
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			c.errf(where, "regex: %v", err)
			continue
		}
		if re.MatchString("") {
			c.errf(where, "regex %q matches the empty string, so every request", r.Regex)
			continue
		}
		parsed, _ := syntax.Parse(r.Regex, syntax.Perl)
		cc := &compiledContent{name: r.Name, re: re, action: r.Action, message: r.Message,
			unbounded: parsed != nil && unboundedRepeat(parsed)}
		hosts, _ := contentScope(p, r)
		if r.To != nil && len(r.To.FQDN) == 0 {
			c.errf(where, "to: needs fqdn")
		}
		for _, h := range hosts {
			hp, err := parseHost(h)
			if err != nil {
				c.errf(where, "%v", err)
				continue
			}
			cc.hosts = append(cc.hosts, hp)
		}
		cp.content = append(cp.content, cc)
		cp.Placements = append(cp.Placements, c.placeContent(r, cc, hosts, left))
	}
}

func (c *compiler) placeContent(r ContentRule, cc *compiledContent, hosts, left []string) Placement {
	pl := Placement{Rule: "content/" + r.Name, Tier: "2", EnforcedBy: "ext_proc (request body and query string)"}
	if len(hosts) == 0 {
		pl.Notes = append(pl.Notes, "applies to no host: the profile allows none by name")
	} else {
		sorted := append([]string{}, hosts...)
		sort.Strings(sorted)
		pl.Notes = append(pl.Notes, "applies to "+strings.Join(sorted, ", ")+"; terminated: see posture")
	}
	if r.To == nil {
		for _, l := range left {
			pl.Notes = append(pl.Notes, "not applied to "+l+": the proxy does not read those requests")
		}
	}
	switch r.Action {
	case ContentActionRedact:
		pl.Notes = append(pl.Notes, "matches in the body are replaced by * of the same length; a match in the query string refuses the request")
	case ActionTagAndLog:
		pl.Notes = append(pl.Notes, "matches are recorded, nothing is changed")
	}
	if cc.unbounded {
		pl.Notes = append(pl.Notes, "unbounded repetition: one match can run to the end of the body; prefer {m,n}")
	}
	pl.Notes = append(pl.Notes,
		"sees requests as sent: bodies in gzip or deflate are decoded, other encodings refused; a value split up or re-encoded (base64) does not match",
		"bodies over the node's inspection limit are refused; responses are not checked")
	return pl
}

// contentTerminates corrects egress placements once content rules are
// known: a rule whose every host a content rule covers is terminated.
func (c *compiler) contentTerminates(p *AgentProfile, cp *CompiledProfile) {
	if len(cp.content) == 0 {
		return
	}
	const fronting = "not terminated: domain-fronting exposed (design §7.5)"
	covered := func(r EgressRule) bool {
		if len(r.To.FQDN) == 0 {
			return false
		}
		for _, h := range r.To.FQDN {
			ok := false
			for _, cc := range cp.content {
				for _, hp := range cc.hosts {
					if hp.raw == h {
						ok = true
					}
				}
			}
			if !ok {
				return false
			}
		}
		return true
	}
	for _, r := range p.Spec.Egress.Rules {
		if !covered(r) {
			continue
		}
		for i := range cp.Placements {
			if cp.Placements[i].Rule != r.Name {
				continue
			}
			for j, n := range cp.Placements[i].Notes {
				if n == fronting {
					cp.Placements[i].Notes[j] = "terminated for content rules: see posture"
				}
			}
		}
	}
}

func (cc *compiledContent) applies(host string) bool {
	for _, hp := range cc.hosts {
		if hp.match(host) {
			return true
		}
	}
	return false
}

// HasContent reports whether the profile has content rules.
func (cp *CompiledProfile) HasContent() bool { return len(cp.content) > 0 }

// InspectsContent reports whether any layer has a content rule covering
// host, i.e. whether its requests' bodies must be read.
func (e *Effective) InspectsContent(host string) bool {
	host = NormalizeHost(host)
	for _, l := range e.Layers {
		for _, cc := range l.Profile.content {
			if cc.applies(host) {
				return true
			}
		}
	}
	return false
}

// ContentHit is one content rule that matched.
type ContentHit struct {
	Layer  string
	Rule   string
	Action string // deny, redact or tag-and-log
	// Enforced: the layer is in enforce mode, so a deny blocks and a
	// redact changes the body. An audit layer's hit is what it would do.
	Enforced bool
	Count    int
	spans    [][]int
}

// ContentVerdict is what the content rules say about one request part.
type ContentVerdict struct {
	Hits []ContentHit
	// Denied is the first enforced hit that refuses the request: a deny,
	// or a redact where the part cannot be redacted (the query string).
	Denied  *ContentHit
	Message string
}

// Redacts reports whether enforced redactions change the data.
func (v ContentVerdict) Redacts() bool {
	for _, h := range v.Hits {
		if h.Enforced && h.Action == ContentActionRedact {
			return true
		}
	}
	return false
}

// Matched reports whether any rule matched.
func (v ContentVerdict) Matched() bool { return len(v.Hits) > 0 }

// ScanContent checks data sent to host against every layer's content
// rules. what names the part ("body", "query string") for narration;
// redactable says whether redact can change it, or must refuse instead.
func (e *Effective) ScanContent(host, what string, data []byte, redactable bool) ContentVerdict {
	host = NormalizeHost(host)
	var v ContentVerdict
	for _, l := range e.Layers {
		enforce := l.Profile.Mode == ModeEnforce
		for _, cc := range l.Profile.content {
			if !cc.applies(host) {
				continue
			}
			spans := cc.re.FindAllIndex(data, -1)
			if len(spans) == 0 {
				continue
			}
			h := ContentHit{Layer: l.Profile.Name, Rule: cc.name, Action: cc.action, Enforced: enforce, Count: len(spans), spans: spans}
			v.Hits = append(v.Hits, h)
			refuses := cc.action == ActionDeny || (cc.action == ContentActionRedact && !redactable)
			if enforce && refuses && v.Denied == nil {
				hh := h
				v.Denied = &hh
				v.Message = cc.message
				if v.Message == "" {
					v.Message = fmt.Sprintf("The request to %s was not sent: its %s matches content rule %s of profile %s.",
						host, what, cc.name, l.Profile.Name)
					if cc.action == ContentActionRedact {
						v.Message += " Matches are redacted only in a request body."
					}
				}
			}
		}
	}
	return v
}

// Redact returns data with every enforced redact match replaced by '*'
// of the same length, so a Content-Length stays right.
func (v ContentVerdict) Redact(data []byte) []byte {
	if !v.Redacts() {
		return data
	}
	out := append([]byte(nil), data...)
	for _, h := range v.Hits {
		if !h.Enforced || h.Action != ContentActionRedact {
			continue
		}
		for _, s := range h.spans {
			for i := s[0]; i < s[1]; i++ {
				out[i] = '*'
			}
		}
	}
	return out
}
