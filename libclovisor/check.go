// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// CheckFinding is one destination or binary seen in the runs, with what
// the profile would do about it.
type CheckFinding struct {
	Kind     string // egress, http, mcp, exec, unverifiable, not-governed
	What     string // "TCP api.github.com:443 (140.82.112.6)", "/usr/bin/curl"
	Decision string // allow, deny, tag-and-log, deferred, or a reason
	Rule     string
	Message  string
	Count    int
	Runs     []string
}

// CheckReport is the outcome of replaying runs against a profile: the
// shadow step of design §7.10, done offline from Phase 1 audit data.
type CheckReport struct {
	Profile    string
	Version    string
	Runs       []string
	Violations []CheckFinding // would be denied
	Allowed    []CheckFinding
	// Unverifiable: allowed at host level, but the deciding rule needs
	// method or path, which audit data does not record.
	Unverifiable []CheckFinding
	// NotGoverned: traffic an explicit proxy never sees (loopback, DNS,
	// other UDP, raw IP connects by non-proxy-aware clients).
	NotGoverned []CheckFinding
}

type findingKey struct{ kind, what string }

// CheckRuns replays the runs' destinations and execs against cp.
func CheckRuns(cp *policy.CompiledProfile, runs []*RunTimeline) *CheckReport {
	rep := &CheckReport{Profile: cp.Name, Version: cp.Profile.ShortVersion()}
	found := map[findingKey]*CheckFinding{}
	var order []findingKey
	add := func(kind, what string, f CheckFinding, runID string, n int) {
		k := findingKey{kind, what}
		cf := found[k]
		if cf == nil {
			f.Kind, f.What = kind, what
			cf = &f
			found[k] = cf
			order = append(order, k)
		}
		cf.Count += n
		for _, r := range cf.Runs {
			if r == runID {
				return
			}
		}
		cf.Runs = append(cf.Runs, runID)
	}

	for _, tl := range runs {
		rep.Runs = append(rep.Runs, tl.RunID)
		l7 := checkL7(cp, tl, add)
		for _, d := range append(append([]Destination{}, tl.Summary.Destinations...), l7...) {
			addr := net.JoinHostPort(d.IP, strconv.Itoa(int(d.Port)))
			if d.IP == "via proxy" {
				addr = "via proxy"
			}
			ip, _ := netip.ParseAddr(d.IP)
			switch {
			case d.Proto == "UDP" && d.Port == 53:
				add("not-governed", d.Proto+" "+addr, CheckFinding{Decision: "DNS: answered locally; Phase 3 forces it"}, tl.RunID, d.Count)
				continue
			case ip.IsLoopback():
				add("not-governed", d.Proto+" "+addr, CheckFinding{Decision: "loopback"}, tl.RunID, d.Count)
				continue
			case d.Proto == "UDP":
				add("not-governed", d.Proto+" "+addr+namesSuffix(d.Names), CheckFinding{Decision: "UDP never reaches an explicit proxy"}, tl.RunID, d.Count)
				continue
			}
			reqs := []policy.Request{}
			labels := []string{}
			for _, n := range d.Names {
				reqs = append(reqs, policy.Request{Host: n, Port: d.Port})
				labels = append(labels, fmt.Sprintf("%s %s:%d (%s)", d.Proto, n, d.Port, d.IP))
			}
			if len(reqs) == 0 {
				reqs = append(reqs, policy.Request{IP: ip, Port: d.Port})
				labels = append(labels, d.Proto+" "+addr)
			}
			for i, req := range reqs {
				dec := cp.Decide(req)
				f := CheckFinding{Decision: dec.Action, Rule: dec.Rule, Message: dec.Message}
				switch {
				case dec.Deferred:
					f.Decision = "deferred"
					add("unverifiable", labels[i], f, tl.RunID, d.Count)
				case !dec.Allowed():
					add("egress-deny", labels[i], f, tl.RunID, d.Count)
				default:
					add("egress-allow", labels[i], f, tl.RunID, d.Count)
				}
			}
		}
		checkMCP(cp, tl, add)
		for _, b := range tl.Summary.Binaries {
			ed := cp.DecideExec(b)
			f := CheckFinding{Decision: policy.ActionAllow}
			if !ed.Default {
				f.Rule = "exec.allow"
			}
			if !ed.Allowed {
				f.Decision = policy.ActionDeny
				f.Message = "not in exec.allow"
			}
			kind := "exec-allow"
			if !ed.Allowed {
				kind = "exec-deny"
			}
			// Each exec event counts; the summary keeps distinct binaries.
			n := 0
			for _, e := range tl.Events {
				if e.Type == "exec" && e.Binary == b {
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			add(kind, b, f, tl.RunID, n)
		}
	}

	for _, k := range order {
		f := *found[k]
		sort.Strings(f.Runs)
		switch k.kind {
		case "egress-deny", "http-deny", "mcp-deny", "exec-deny":
			f.Kind = strings.TrimSuffix(k.kind, "-deny")
			rep.Violations = append(rep.Violations, f)
		case "egress-allow", "http-allow", "mcp-allow", "exec-allow":
			f.Kind = strings.TrimSuffix(k.kind, "-allow")
			rep.Allowed = append(rep.Allowed, f)
		case "unverifiable":
			rep.Unverifiable = append(rep.Unverifiable, f)
		default:
			rep.NotGoverned = append(rep.NotGoverned, f)
		}
	}
	for _, s := range [][]CheckFinding{rep.Violations, rep.Allowed, rep.Unverifiable, rep.NotGoverned} {
		sort.SliceStable(s, func(i, j int) bool {
			if s[i].Kind != s[j].Kind {
				return s[i].Kind < s[j].Kind
			}
			return s[i].What < s[j].What
		})
	}
	return rep
}

func namesSuffix(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return " (" + strings.Join(names, ", ") + ")"
}

// WriteText renders the report for a terminal.
func (rep *CheckReport) WriteText(w io.Writer) error {
	var b strings.Builder
	p := func(format string, a ...interface{}) { fmt.Fprintf(&b, format+"\n", a...) }
	p("Profile %s@%s against %d run(s)", rep.Profile, rep.Version, len(rep.Runs))
	section := func(title string, fs []CheckFinding, detail func(CheckFinding) string) {
		p("")
		p("%s (%d)", title, len(fs))
		for _, f := range fs {
			p("  %-6s %-55s x%-4d %s", f.Kind, f.What, f.Count, detail(f))
		}
	}
	runs := func(f CheckFinding) string {
		if len(rep.Runs) <= 1 {
			return ""
		}
		return fmt.Sprintf(" [%d/%d runs]", len(f.Runs), len(rep.Runs))
	}
	section("Would be denied", rep.Violations, func(f CheckFinding) string {
		rule := "default"
		if f.Rule != "" {
			rule = "rule " + f.Rule
		}
		return rule + ": " + f.Message + runs(f)
	})
	section("Allowed", rep.Allowed, func(f CheckFinding) string {
		if f.Rule == "" {
			return "default" + runs(f)
		}
		return "rule " + f.Rule + runs(f)
	})
	if len(rep.Unverifiable) > 0 {
		section("Depends on method or path, which audit data lacks", rep.Unverifiable, func(f CheckFinding) string {
			return "first matching rule " + f.Rule + runs(f)
		})
	}
	if len(rep.NotGoverned) > 0 {
		section("Not seen by an explicit proxy", rep.NotGoverned, func(f CheckFinding) string { return f.Decision + runs(f) })
	}
	_, err := io.WriteString(w, b.String())
	return err
}

type addFinding func(kind, what string, f CheckFinding, runID string, n int)

func egressFinding(add addFinding, kind, what string, dec policy.Decision, runID string, n int) {
	f := CheckFinding{Decision: dec.Action, Rule: dec.Rule, Message: dec.Message}
	switch {
	case dec.Deferred:
		f.Decision = "deferred"
		add("unverifiable", what, f, runID, n)
	case !dec.Allowed():
		add(kind+"-deny", what, f, runID, n)
	default:
		add(kind+"-allow", what, f, runID, n)
	}
}

// checkL7 replays the requests the proxy recorded by method and path, and
// the tunnels it could not see into. It returns, as destinations for the
// host-level replay, proxied traffic recorded before paths were.
func checkL7(cp *policy.CompiledProfile, tl *RunTimeline, add addFinding) []Destination {
	var legacy []Destination
	for _, p := range tl.Summary.Proxied {
		if p.Connects == 0 && len(p.Paths) == 0 && p.PathsDropped == 0 {
			legacy = append(legacy, proxiedDestinations(&RunTimeline{Summary: RunSummary{Proxied: []ProxiedDest{p}}}, false)...)
			continue
		}
		base := policy.Request{Port: p.Port}
		if ip, err := netip.ParseAddr(p.Host); err == nil {
			base.IP = ip
		} else {
			base.Host = p.Host
		}
		hp := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
		if p.Tunnels > 0 {
			egressFinding(add, "egress", "CONNECT "+hp+" (not terminated)", cp.Decide(base), tl.RunID, p.Tunnels)
		}
		if rest := p.Connects - p.Tunnels; rest > 0 {
			// Terminated (their requests follow) or blocked: only a
			// denial at host level is news.
			if dec := cp.Decide(base); !dec.Deferred && !dec.Allowed() {
				egressFinding(add, "egress", "CONNECT "+hp, dec, tl.RunID, rest)
			}
		}
		for _, u := range p.Paths {
			r := base
			r.Method, r.Path, r.Phase = u.Method, u.Path, policy.PhaseRequest
			egressFinding(add, "http", u.Method+" "+hp+u.Path, cp.Decide(r), tl.RunID, u.Requests)
		}
		if p.PathsDropped > 0 {
			add("unverifiable", hp+" (paths past the per-run cap)", CheckFinding{Decision: "unrecorded"}, tl.RunID, p.PathsDropped)
		}
	}
	return legacy
}

// checkMCP replays the run's MCP operations. A profile with no mcp block,
// or a remote host it does not name, abstains: nothing to report.
func checkMCP(cp *policy.CompiledProfile, tl *RunTimeline, add addFinding) {
	argv := map[string][]string{}
	for _, u := range tl.Summary.MCP {
		if u.Method == "register" {
			argv[u.Server] = strings.Fields(u.Name)
		}
	}
	for _, u := range tl.Summary.MCP {
		r := policy.MCPRequest{Server: u.Server}
		if a, ok := argv[u.Server]; ok {
			r.Argv = a
		} else {
			r.Host = u.Server
		}
		what := u.Server + " " + u.Method
		switch u.Method {
		case "register":
			r.Kind = "server"
		case "tools/call":
			r.Kind, r.Tool = "tool", u.Name
			what += " " + u.Name
		case "resources/read":
			r.Kind, r.URI = "resource", u.Name
			what += " " + u.Name
		case "sampling/createMessage":
			r.Kind = "sampling"
		default:
			continue // tools/list drift: a property of the server, not the profile
		}
		dec, ok := cp.DecideMCP(r)
		if !ok {
			continue
		}
		f := CheckFinding{Decision: dec.Action, Rule: dec.Rule, Message: dec.Message}
		if dec.Allowed() {
			add("mcp-allow", what, f, tl.RunID, u.Calls)
		} else {
			add("mcp-deny", what, f, tl.RunID, u.Calls)
		}
	}
}
