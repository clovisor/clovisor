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
		if r.http != nil && req.Phase == PhaseConnect {
			// Only an HTTP request can tell whether this rule or a later
			// one decides; the destination is terminated for that.
			return Decision{Action: ActionAllow, Rule: r.Name, Deferred: true}
		}
		if !r.matchesHTTP(req) {
			continue
		}
		return Decision{Action: r.Action, Rule: r.Name, Message: r.Message}
	}
	return Decision{Action: cp.DefaultAction, Message: cp.defaultMessage(req)}
}

func (cp *CompiledProfile) defaultMessage(req Request) string {
	if cp.DefaultAction != ActionDeny {
		return ""
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
	Allowed bool
	Default bool // no allow entry matched
}

// DecideExec evaluates an exec of an absolute path. Without an exec
// block, every exec is allowed.
func (cp *CompiledProfile) DecideExec(path string) ExecDecision {
	if cp.exec == nil {
		return ExecDecision{Allowed: true, Default: true}
	}
	if cp.exec.allow[path] {
		return ExecDecision{Allowed: true}
	}
	return ExecDecision{Allowed: cp.exec.Default == ActionAllow, Default: true}
}
