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
	Kind     string // egress, http, model, mcp, exec, dns, udp, unverifiable, not-governed
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
	// Asks would be held for a person's decision (milestone 5.5).
	Asks []CheckFinding
	// NotGoverned: traffic the deployment does not decide (with an
	// explicit proxy: loopback, DNS, other UDP, raw IP connects by
	// non-proxy-aware clients; with transparent mode, same-run loopback).
	NotGoverned []CheckFinding
	// Transparent: replayed as transparent enforce would decide.
	Transparent bool
	// ContentRules names the profile's content rules, which no replay can
	// decide: runs record which rules matched, not what was sent.
	ContentRules []string
	// BudgetRules names the profile's rules with budgets (milestone 5.4),
	// which no replay decides: what a run spent depends on the order of
	// its calls and on the node's prices.
	BudgetRules []string
}

// CheckOptions describe the deployment to replay against.
type CheckOptions struct {
	// Transparent replays as transparent enforce mode decides (milestone
	// 3.6): DNS names against the resolver's rule, and UDP refused unless
	// in UDPAllow. TCP the run reached by a looked-up name is decided by
	// that name, as transparent mode does with the resolver's answers
	// even when the traffic carries no name.
	Transparent bool
	UDPAllow    []netip.AddrPort
}

// httpish are ports whose traffic is assumed TLS or HTTP, so that it
// carries its name. On other ports transparent mode knows a connection by
// its address, and by names the node's resolver answered with it.
var httpish = map[uint16]bool{80: true, 443: true, 8080: true, 8443: true}

type findingKey struct{ kind, what string }

// profileUDP reports whether cp's udp block names ip:port.
func profileUDP(cp *policy.CompiledProfile, ip netip.Addr, port uint16) bool {
	for _, a := range cp.Net.UDP {
		if a.Port() == port && a.Addr() == ip.Unmap() {
			return true
		}
	}
	return false
}

// CheckRuns replays the runs' destinations and execs against cp, for an
// explicit-proxy deployment.
func CheckRuns(cp *policy.CompiledProfile, runs []*RunTimeline) *CheckReport {
	return CheckRunsWith(cp, runs, CheckOptions{})
}

// CheckRunsWith is CheckRuns for the deployment o describes.
func CheckRunsWith(cp *policy.CompiledProfile, runs []*RunTimeline, o CheckOptions) *CheckReport {
	rep := &CheckReport{Profile: cp.Name, Version: cp.Profile.ShortVersion(), Transparent: o.Transparent}
	for _, r := range cp.Profile.Spec.Content {
		rep.ContentRules = append(rep.ContentRules, r.Name)
	}
	for _, r := range cp.Profile.Spec.Egress.Rules {
		if r.Budget != nil {
			rep.BudgetRules = append(rep.BudgetRules, r.Name)
		}
	}
	udpAllowed := func(ip netip.Addr, port uint16) bool {
		for _, a := range o.UDPAllow {
			if a.Port() == port && (a.Addr().Unmap() == ip.Unmap() || (a.Addr().IsUnspecified() && ip.IsLoopback())) {
				return true
			}
		}
		return false
	}
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
		if o.Transparent {
			// The node's resolver answers a name only if some rule could
			// allow a connection to it.
			for _, n := range append(append([]string{}, tl.Summary.DNSNames...), tl.Summary.DNSBlocked...) {
				dec := cp.DecideName(n)
				f := CheckFinding{Decision: dec.Action, Rule: dec.Rule, Message: dec.Message}
				if dec.Allowed() {
					add("dns-allow", n, f, tl.RunID, 1)
				} else {
					f.Message = "NXDOMAIN: " + dec.Message
					add("dns-deny", n, f, tl.RunID, 1)
				}
			}
		}
		dests := append(append([]Destination{}, tl.Summary.Destinations...), l7...)
		if o.Transparent {
			// UDP refused under enforce: it never reached anywhere, and
			// would be refused again.
			dests = append(dests, tl.Summary.UDPRefusedTo...)
		}
		for _, d := range dests {
			addr := net.JoinHostPort(d.IP, strconv.Itoa(int(d.Port)))
			if d.IP == "via proxy" {
				addr = "via proxy"
			}
			ip, _ := netip.ParseAddr(d.IP)
			switch {
			case d.Port == 53 && o.Transparent:
				continue // decided above, by name
			case d.Proto == "UDP" && d.Port == 53:
				add("not-governed", d.Proto+" "+addr, CheckFinding{Decision: "DNS: answered locally; transparent mode forces it"}, tl.RunID, d.Count)
				continue
			case ip.IsLoopback() && o.Transparent:
				add("not-governed", d.Proto+" "+addr, CheckFinding{Decision: "loopback: direct if the run itself listens there; otherwise refused as node-local"}, tl.RunID, d.Count)
				continue
			case ip.IsLoopback():
				add("not-governed", d.Proto+" "+addr, CheckFinding{Decision: "loopback"}, tl.RunID, d.Count)
				continue
			case d.Proto == "UDP" && o.Transparent:
				what := d.Proto + " " + addr + namesSuffix(d.Names)
				if udpAllowed(ip, d.Port) {
					add("udp-allow", what, CheckFinding{Decision: policy.ActionAllow, Rule: "node -udp-allow"}, tl.RunID, d.Count)
				} else if profileUDP(cp, ip, d.Port) {
					add("udp-allow", what, CheckFinding{Decision: policy.ActionAllow, Rule: "udp.allow (where the ceiling grants it too)"}, tl.RunID, d.Count)
				} else {
					msg := "UDP is refused except DNS, the node's -udp-allow and udp.allow"
					if d.Port == 443 {
						msg += "; QUIC: clients fall back to TCP"
					}
					add("udp-deny", what, CheckFinding{Decision: policy.ActionDeny, Message: msg}, tl.RunID, d.Count)
				}
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
				case dec.Action == policy.ActionAsk:
					add("egress-ask", labels[i], f, tl.RunID, d.Count)
				case !dec.Allowed():
					add("egress-deny", labels[i], f, tl.RunID, d.Count)
				default:
					add("egress-allow", labels[i], f, tl.RunID, d.Count)
				}
			}
		}
		checkModels(cp, tl, add)
		checkMCP(cp, tl, add)
		if o.Transparent {
			uid := -1
			if tl.UID != nil {
				uid = *tl.UID
			}
			for _, u := range tl.Summary.Unix {
				what := "unix " + u.Path
				rule := ""
				for _, pat := range cp.UnixAllow {
					if policy.UnixCovers(strings.ReplaceAll(pat, "{uid}", strconv.Itoa(uid)), u.Path) {
						rule = "unix/" + pat
						break
					}
				}
				if rule != "" {
					add("unix-allow", what, CheckFinding{Decision: policy.ActionAllow, Rule: rule}, tl.RunID, 1)
				} else {
					add("unix-deny", what, CheckFinding{Decision: policy.ActionDeny,
						Message: "no unix.allow entry covers it (BPF LSM refuses it under enforce)"}, tl.RunID, 1)
				}
			}
		}
		// The kernel's resolved paths and trust where it reported them, as
		// the exec hook decides; otherwise the requested paths.
		type execSeen struct {
			path    string
			trusted bool
		}
		var execs []execSeen
		if len(tl.Summary.Exec) > 0 {
			for _, e := range tl.Summary.Exec {
				execs = append(execs, execSeen{e.Path, e.Trusted})
			}
		} else {
			for _, b := range tl.Summary.Binaries {
				execs = append(execs, execSeen{b, true})
			}
		}
		for _, x := range execs {
			b := x.path
			ed := cp.DecideExecTrusted(b, x.trusted)
			f := CheckFinding{Decision: policy.ActionAllow}
			if !ed.Default {
				f.Rule = "exec.allow"
			}
			if !ed.Allowed {
				f.Decision = policy.ActionDeny
				f.Message = "not in exec.allow"
				if ed.Untrusted {
					f.Message = "not in exec.allow, and not on a trusted path (require_trusted_path)"
				}
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
		case "egress-deny", "http-deny", "model-deny", "mcp-deny", "exec-deny", "dns-deny", "udp-deny", "unix-deny":
			f.Kind = strings.TrimSuffix(k.kind, "-deny")
			rep.Violations = append(rep.Violations, f)
		case "egress-allow", "http-allow", "model-allow", "mcp-allow", "exec-allow", "dns-allow", "udp-allow", "unix-allow":
			f.Kind = strings.TrimSuffix(k.kind, "-allow")
			rep.Allowed = append(rep.Allowed, f)
		case "unverifiable":
			rep.Unverifiable = append(rep.Unverifiable, f)
		case "egress-ask", "http-ask", "mcp-ask":
			f.Kind = strings.TrimSuffix(k.kind, "-ask")
			rep.Asks = append(rep.Asks, f)
		default:
			rep.NotGoverned = append(rep.NotGoverned, f)
		}
	}
	for _, s := range [][]CheckFinding{rep.Violations, rep.Allowed, rep.Asks, rep.Unverifiable, rep.NotGoverned} {
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
	mode := "an explicit proxy"
	if rep.Transparent {
		mode = "transparent enforce"
	}
	p("Profile %s@%s against %d run(s), as %s would decide", rep.Profile, rep.Version, len(rep.Runs), mode)
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
	if len(rep.Asks) > 0 {
		section("Would be held for a person's decision", rep.Asks, func(f CheckFinding) string {
			rule := "the profile's default (mode ask)"
			if f.Rule != "" {
				rule = "rule " + f.Rule
			}
			return rule + runs(f)
		})
	}
	if len(rep.Unverifiable) > 0 {
		section("Depends on what audit data lacks (method, path or model)", rep.Unverifiable, func(f CheckFinding) string {
			return "first matching rule " + f.Rule + runs(f)
		})
	}
	if len(rep.NotGoverned) > 0 {
		title := "Not seen by an explicit proxy"
		if rep.Transparent {
			title = "Not decided by policy"
		}
		section(title, rep.NotGoverned, func(f CheckFinding) string { return f.Decision + runs(f) })
	}
	if len(rep.ContentRules) > 0 {
		p("")
		p("Content rules (%d) not replayed: runs record which rules matched, not what was sent: %s",
			len(rep.ContentRules), strings.Join(rep.ContentRules, ", "))
	}
	if len(rep.BudgetRules) > 0 {
		p("")
		p("Budgets (%d) not replayed: spending depends on the order of calls and the node's prices; "+
			"agentctl events shows what each run spent: %s", len(rep.BudgetRules), strings.Join(rep.BudgetRules, ", "))
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
	case dec.Action == policy.ActionAsk:
		add(kind+"-ask", what, f, runID, n)
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

// checkModels replays the models the run's requests named (milestone
// 5.3) against the profile's model lists. A request the profile decides
// by a rule with no model list, or denies, is the path replay's to
// report. A request with a body that a model rule would decide, but whose
// model was not recorded (no model rule decided it in the run), cannot be
// replayed.
func checkModels(cp *policy.CompiledProfile, tl *RunTimeline, add addFinding) {
	request := func(host string, port uint16, method, path string) policy.Request {
		r := policy.Request{Port: port, Method: method, Path: path, Phase: policy.PhaseRequest}
		if ip, err := netip.ParseAddr(host); err == nil {
			r.IP = ip
		} else {
			r.Host = host
		}
		return r
	}
	recorded := map[hostPath]bool{}
	for _, u := range tl.Summary.Models {
		recorded[hostPath{policy.NormalizeHost(u.Host) + ":" + strconv.Itoa(int(u.Port)), u.Method, u.Path}] = true
		dec := cp.Decide(request(u.Host, u.Port, u.Method, u.Path))
		if !dec.Allowed() || !dec.ModelChecked() {
			continue
		}
		hp := net.JoinHostPort(u.Host, strconv.Itoa(int(u.Port)))
		what := fmt.Sprintf("%s %s%s model %q", u.Method, hp, u.Path, u.Model)
		if u.Model == "" {
			what = fmt.Sprintf("%s %s%s (no model: %s)", u.Method, hp, u.Path, u.Reason)
		}
		f := CheckFinding{Decision: policy.ActionAllow, Rule: dec.Rule}
		if dec.PermitsModel(u.Model) {
			add("model-allow", what, f, tl.RunID, u.Requests)
			continue
		}
		f.Decision, f.Message = policy.ActionDeny, "not in the rule's model list"
		if u.Model == "" {
			f.Message = "names no model, and the rule has a model list"
		}
		add("model-deny", what, f, tl.RunID, u.Requests)
	}
	for _, p := range tl.Summary.Proxied {
		for _, u := range p.Paths {
			switch u.Method {
			case "POST", "PUT", "PATCH":
			default:
				continue // no body, no model
			}
			if recorded[hostPath{policy.NormalizeHost(p.Host) + ":" + strconv.Itoa(int(p.Port)), u.Method, u.Path}] {
				continue
			}
			dec := cp.Decide(request(p.Host, p.Port, u.Method, u.Path))
			if !dec.Allowed() || !dec.ModelChecked() {
				continue
			}
			hp := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
			add("unverifiable", fmt.Sprintf("%s %s%s (model not recorded)", u.Method, hp, u.Path),
				CheckFinding{Decision: "model not recorded", Rule: dec.Rule}, tl.RunID, u.Requests)
		}
	}
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
		if dec.Action == policy.ActionAsk {
			add("mcp-ask", what, f, tl.RunID, u.Calls)
		} else if dec.Allowed() {
			add("mcp-allow", what, f, tl.RunID, u.Calls)
		} else {
			add("mcp-deny", what, f, tl.RunID, u.Calls)
		}
	}
}
