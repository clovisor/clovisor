// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// hostPattern is a compiled fqdn entry.
type hostPattern struct {
	raw    string
	any    bool   // "*"
	suffix string // "*.example.com" -> ".example.com"
	exact  string
}

var errHostSyntax = "must be a lowercase hostname, \"*.\" followed by one, or \"*\""

func parseHost(s string) (hostPattern, error) {
	hp := hostPattern{raw: s}
	if s == "*" {
		hp.any = true
		return hp, nil
	}
	name := s
	if strings.HasPrefix(s, "*.") {
		name = s[2:]
	}
	if !validHostname(name) {
		return hp, fmt.Errorf("fqdn %q %s", s, errHostSyntax)
	}
	if strings.HasPrefix(s, "*.") {
		hp.suffix = "." + name
	} else {
		hp.exact = name
	}
	return hp, nil
}

// ValidHostname reports whether s can be used as an exact fqdn entry.
func ValidHostname(s string) bool { return validHostname(s) }

func validHostname(s string) bool {
	if s == "" || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// match reports whether host (lowercase, no trailing dot) matches. A
// wildcard covers exactly one extra label, as a wildcard certificate does.
func (hp hostPattern) match(host string) bool {
	switch {
	case hp.any:
		return true
	case hp.exact != "":
		return host == hp.exact
	default:
		if !strings.HasSuffix(host, hp.suffix) {
			return false
		}
		head := strings.TrimSuffix(host, hp.suffix)
		return head != "" && !strings.Contains(head, ".")
	}
}

// glob matches s against a pattern where "*" matches any run of
// characters, including none.
func glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, last)
}

func globAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if glob(p, s) {
			return true
		}
	}
	return false
}

// NormalizeHost lowercases a hostname and strips a trailing dot.
func NormalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// Phase says how much of a request is known when deciding.
type Phase int

const (
	// PhaseConnect: only the destination is known (a CONNECT, a
	// connection, or a Phase 1 audit record).
	PhaseConnect Phase = iota
	// PhaseRequest: an HTTP request with method and path (plain HTTP, or
	// inside a terminated connection).
	PhaseRequest
)

// Request is what an enforcement point knows about an egress attempt.
type Request struct {
	Host   string     // hostname, if the destination was named
	IP     netip.Addr // IP literal destination, if it was not
	Port   uint16
	Method string
	Path   string // without query string
	Phase  Phase
}

// Decision is the engine's answer.
type Decision struct {
	Action  string // allow, deny or tag-and-log
	Rule    string // rule name, or "" for the default
	Message string // narration for a deny (design §7.7)
	// rate is a rate-limit rule's allowance; Action is rate-limit.
	rate *compiledRate
	// models is the deciding rule's model list (milestone 5.3).
	models *compiledModels
	// budget is the deciding rule's budget (milestone 5.4).
	budget *compiledBudget
	// ask is an ask's timeout and what happens then (milestone 5.5).
	ask *compiledAsk
	// Deferred is set at PhaseConnect when the first matching rule needs
	// method or path. The connection is let through to termination, and
	// each request inside it gets its own decision. Offline, it means the
	// outcome depends on paths the audit data does not have.
	Deferred bool
}

// Allowed reports whether the attempt may proceed.
func (d Decision) Allowed() bool { return d.Action != ActionDeny }

func (r *compiledRule) matchesDestination(req Request) bool {
	if len(r.ports) > 0 && !r.ports[req.Port] {
		return false
	}
	if req.Host != "" {
		for _, hp := range r.hosts {
			if hp.match(req.Host) {
				return true
			}
		}
		return false
	}
	if req.IP.IsValid() {
		for _, n := range r.nets {
			if n.Contains(req.IP.Unmap()) {
				return true
			}
		}
	}
	return false
}

func (r *compiledRule) matchesHTTP(req Request) bool {
	if r.http == nil {
		return true
	}
	if len(r.http.Methods) > 0 {
		ok := false
		for _, m := range r.http.Methods {
			if m == req.Method {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return len(r.http.Paths) == 0 || globAny(r.http.Paths, req.Path)
}

// Decide evaluates an egress attempt. Rules are tried in order and the
// first match decides; if none matches, the egress default applies.
func (cp *CompiledProfile) Decide(req Request) Decision {
	req.Host = NormalizeHost(req.Host)
	for _, r := range cp.Rules {
		if !r.matchesDestination(req) {
			continue
		}
		if (r.http != nil || r.models != nil || r.budget != nil) && req.Phase == PhaseConnect {
			// Only an HTTP request can tell whether this rule or a later
			// one decides, or which model it names; the destination is
			// terminated for that.
			return Decision{Action: ActionAllow, Rule: r.Name, Deferred: true}
		}
		if !r.matchesHTTP(req) {
			continue
		}
		return Decision{Action: r.Action, Rule: r.Name, Message: r.Message, rate: r.rate, models: r.models, budget: r.budget, ask: r.ask}
	}
	if cp.Mode == ModeAsk && cp.DefaultAction == ActionDeny {
		return Decision{Action: ActionAsk, Message: cp.defaultMessage(req), ask: cp.askDefault}
	}
	return Decision{Action: cp.DefaultAction, Message: cp.defaultMessage(req)}
}

func (cp *CompiledProfile) defaultMessage(req Request) string {
	if cp.DefaultAction != ActionDeny {
		return ""
	}
	if cp.DefaultMessage != "" {
		return cp.DefaultMessage
	}
	dest := req.Host
	if dest == "" && req.IP.IsValid() {
		dest = req.IP.String()
	}
	what := fmt.Sprintf("%s:%d", dest, req.Port)
	if req.Phase == PhaseRequest {
		what = fmt.Sprintf("%s %s%s", req.Method, dest, req.Path)
	}
	return fmt.Sprintf("No rule in profile %s allows %s.", cp.Name, what)
}

// ExecDecision is the answer for an exec.
type ExecDecision struct {
	Allowed   bool
	Default   bool // no allow entry matched
	Untrusted bool // refused by require_trusted_path
	// Pinned: an exec.allow entry with hashes names the path, so its
	// content decides (milestone 5.7). Mismatch: the content is none of
	// them; NoHash: the content is not known, so nothing is decided.
	Pinned   bool
	Mismatch bool
	NoHash   bool
}

// DecideExec evaluates an exec of an absolute path. Without an exec
// block, every exec is allowed.
func (cp *CompiledProfile) DecideExec(path string) ExecDecision {
	return cp.DecideExecTrusted(path, true)
}

// DecideExecTrusted is DecideExec for a resolved path whose trusted-path
// test came out as trusted (milestone 4.4), as the kernel decides: listed
// passes; else an untrusted file fails under require_trusted_path; else
// the default.
func (cp *CompiledProfile) DecideExecTrusted(path string, trusted bool) ExecDecision {
	return cp.DecideExecHash(path, trusted, "")
}

// DecideExecHash is DecideExecTrusted for a file whose content hashed to
// sum (sha256:<hex>, or "" if not known), as the kernel decides with
// hashes (milestone 5.7): an entry with hashes passes only the content it
// lists, and refuses any other, whatever the default.
func (cp *CompiledProfile) DecideExecHash(path string, trusted bool, sum string) ExecDecision {
	if cp.exec == nil {
		return ExecDecision{Allowed: true, Default: true}
	}
	if sums, ok := cp.exec.hashes[path]; ok {
		if sum == "" {
			return ExecDecision{Pinned: true, NoHash: true}
		}
		for _, h := range sums {
			if FormatExecHash(h) == sum {
				return ExecDecision{Allowed: true, Pinned: true}
			}
		}
		return ExecDecision{Pinned: true, Mismatch: true}
	}
	if cp.exec.allow[path] {
		return ExecDecision{Allowed: true}
	}
	for _, p := range cp.exec.prefixes {
		if strings.HasPrefix(path, p) {
			return ExecDecision{Allowed: true}
		}
	}
	if cp.exec.RequireTrustedPath && !trusted {
		return ExecDecision{Allowed: false, Default: true, Untrusted: true}
	}
	return ExecDecision{Allowed: cp.exec.Default == ActionAllow, Default: true}
}

// ExecLayer is one profile's exec policy as the kernel holds it.
type ExecLayer struct {
	DefaultAllow   bool
	RequireTrusted bool
	Enforce        bool // an enforcing layer refuses; others record
	Exact          []string
	Prefixes       []string // each ends in /
	// Hashes are the SHA-256s an exact path's content may have, for the
	// paths in Exact that list any (milestone 5.7).
	Hashes map[string][][32]byte
}

// ExecLayer returns the profile's exec policy for the kernel, or false
// if it has none.
func (cp *CompiledProfile) ExecLayer() (ExecLayer, bool) {
	if cp.exec == nil {
		return ExecLayer{}, false
	}
	l := ExecLayer{DefaultAllow: cp.exec.Default == ActionAllow, RequireTrusted: cp.exec.RequireTrustedPath,
		Enforce: cp.Enforcing() && !cp.exec.AuditOnly, Prefixes: cp.exec.prefixes}
	for p := range cp.exec.allow {
		l.Exact = append(l.Exact, p)
	}
	if len(cp.exec.hashes) > 0 {
		l.Hashes = cp.exec.hashes
	}
	sort.Strings(l.Exact)
	return l, true
}

// DecideName answers whether a DNS name may be resolved (milestone 3.4):
// allowed if some request to it, on some port, could be allowed at
// connect phase. That is exact under first-match rules: every port a rule
// names is tried, plus one no rule names. A cidr rule does not make a
// name resolvable, since the name is decided before anything is resolved:
// forwarding an unknown name is what DNS tunnelling needs.
func (cp *CompiledProfile) DecideName(name string) Decision {
	ports := map[uint16]bool{}
	for _, r := range cp.Rules {
		for p := range r.ports {
			ports[p] = true
		}
	}
	other := uint16(1)
	for ports[other] {
		other++
	}
	ports[other] = true
	var first Decision
	for p := range ports {
		d := cp.Decide(Request{Host: name, Port: p, Phase: PhaseConnect})
		if d.Action == ActionAsk && d.Rule == "" {
			// Mode ask's default: names are not forwarded on its account.
			d = Decision{Action: ActionDeny}
		}
		if d.Allowed() {
			// The port is not part of a name decision.
			return Decision{Action: d.Action, Rule: d.Rule}
		}
		if first.Action == "" || (first.Rule == "" && d.Rule != "") {
			first = d
		}
	}
	first.Message = fmt.Sprintf("No rule in profile %s allows any connection to %s, so the name is not resolved.", cp.Name, NormalizeHost(name))
	if first.Rule != "" {
		for _, r := range cp.Rules {
			if r.Name == first.Rule && r.Message != "" {
				first.Message = r.Message
			}
		}
	}
	return first
}
