// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// interpreters are binaries whose exec permission amounts to arbitrary
// code (design §7.6). Matched on basename, versions stripped.
var interpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "fish": true, "busybox": true,
	"python": true, "python3": true, "node": true, "nodejs": true, "deno": true, "bun": true,
	"perl": true, "ruby": true, "php": true, "lua": true, "tclsh": true, "osascript": true,
	"env": true, "xargs": true, "awk": true, "gawk": true,
}

var versionSuffix = regexp.MustCompile(`[0-9.]+$`)

func isInterpreter(path string) bool {
	base := filepath.Base(path)
	if interpreters[base] {
		return true
	}
	return interpreters[versionSuffix.ReplaceAllString(base, "")]
}

// learnedHost is one hostname the runs connected to.
type learnedHost struct {
	name  string
	ports map[uint16]bool
	conns int
	ips   map[string]bool
	runs  map[string]bool
	udp   map[uint16]int // UDP connects to this name, by port (QUIC etc.)
}

// learnedIP is a destination reached without any looked-up name.
type learnedIP struct {
	proto string
	ip    string
	port  uint16
	conns int
	runs  map[string]bool
}

// Draft is a profile drafted from one or more run timelines, plus what
// the reviewer needs to judge it.
type Draft struct {
	Profile policy.AgentProfile

	Runs       []*RunTimeline
	hosts      map[string]*learnedHost // keyed by rule name
	ruleHost   map[string]string       // rule name -> host
	unnamedTCP []*learnedIP            // TCP to an IP with no name: commented-out cidr rules
	local      []*learnedIP            // loopback destinations
	dnsServers map[string]int          // resolver ip:port -> connects
	otherUDP   []*learnedIP            // UDP, not DNS, no name
	lookedUp   []string                // names looked up but never connected to
	badNames   map[string]int          // connected-to names that are not valid fqdn entries
	binaryRuns map[string]map[string]bool

	httpGroups map[string]*httpGroup // http rules, by rule name
	opaque     map[string]bool       // host rules for hosts used through opaque tunnels
	badPaths   []string              // requests no exact path rule can express
	mcpSeen    []*mcpSeen
	mcpRules   []*mcpSeen // parallel to Profile.Spec.MCP.Servers
	mcpNotes   []string

	// Transparent mode (milestone 3.6):
	udpRefused map[destKey]*learnedIP // UDP the node refused
	udpNames   map[destKey][]string
	dnsBlocked map[string]bool // names the node's resolver refused
	mismatch   map[string]int  // host -> connections to an address it does not resolve to
	byAddress  []string        // refused tunnels to an address the run had looked up by name

	unixSeen map[string]map[string]bool // unix.allow entry -> runs (milestone 4.2)

	// Resolved exec paths (milestone 4.4), where the kernel reported them.
	resolved  bool
	untrusted []string // ran from a path failing the trusted-path test
	// Content hashes the kernel recorded, by path (milestone 5.7): only
	// where a profile already pinned the path.
	execHashes   map[string][]string
	execUnpinned []string // pinned paths with more contents than exec.allow holds

	// Models (milestone 5.3), by rule name.
	ruleModels    map[string]*draftModel
	modelsDropped int
}

// LearnProfile drafts an AgentProfile that would allow exactly the
// behaviour seen in runs: TCP to the hostnames they looked up and then
// connected to, and exec of the binaries they ran. Anything that cannot
// be expressed precisely is left out of the profile and reported as a
// comment instead, so the draft never allows more than was seen.
func LearnProfile(name string, runs []*RunTimeline) *Draft {
	d := &Draft{
		Runs:       runs,
		hosts:      map[string]*learnedHost{},
		ruleHost:   map[string]string{},
		dnsServers: map[string]int{},
		binaryRuns: map[string]map[string]bool{},
		badNames:   map[string]int{},
		httpGroups: map[string]*httpGroup{},
		opaque:     map[string]bool{},
		udpRefused: map[destKey]*learnedIP{},
		udpNames:   map[destKey][]string{},
		dnsBlocked: map[string]bool{},
		mismatch:   map[string]int{},
		unixSeen:   map[string]map[string]bool{},
	}
	d.Profile.Kind = "AgentProfile"
	d.Profile.Metadata.Name = name
	d.Profile.Spec.Mode = "audit"
	d.Profile.Spec.Egress.Default = "deny"
	d.Profile.Spec.Exec = &policy.Exec{Default: "deny", RequireTrustedPath: true, Allow: []policy.ExecAllow{}}

	byHost := map[string]*learnedHost{}
	ipDests := map[destKey]*learnedIP{}
	connected := map[string]bool{}
	looked := map[string]bool{}

	untrusted := map[string]bool{}
	hashes := map[string]map[string]bool{}
	for _, tl := range runs {
		// The kernel's resolved paths, where it reported them: what the
		// exec hook compares (/bin/true runs /usr/bin/gnutrue on some
		// hosts). Otherwise the requested paths.
		bins := tl.Summary.Binaries
		if len(tl.Summary.Exec) > 0 {
			d.resolved = true
			bins = nil
			for _, e := range tl.Summary.Exec {
				bins = append(bins, e.Path)
				if !e.Trusted {
					untrusted[e.Path] = true
				}
				if e.Hash != "" {
					if hashes[e.Path] == nil {
						hashes[e.Path] = map[string]bool{}
					}
					hashes[e.Path][e.Hash] = true
				}
			}
		}
		for _, b := range bins {
			if d.binaryRuns[b] == nil {
				d.binaryRuns[b] = map[string]bool{}
			}
			d.binaryRuns[b][tl.RunID] = true
		}
		for _, n := range tl.Summary.DNSNames {
			looked[n] = true
		}
		for _, n := range tl.Summary.DNSBlocked {
			d.dnsBlocked[n] = true
		}
		for _, u := range tl.Summary.Unix {
			// The run's own uid becomes {uid}, so one entry serves every
			// user's socket (/run/user/1000/bus -> /run/user/{uid}/bus).
			pat := u.Path
			if tl.UID != nil {
				pat = strings.ReplaceAll(pat, "/"+strconv.Itoa(*tl.UID)+"/", "/{uid}/")
			}
			if d.unixSeen[pat] == nil {
				d.unixSeen[pat] = map[string]bool{}
			}
			d.unixSeen[pat][tl.RunID] = true
		}
		ipName := map[string]string{}
		for _, e := range tl.Events {
			if e.Type == "dns" {
				for _, a := range e.Answers {
					if a.Type == "A" || a.Type == "AAAA" {
						ipName[a.Value] = e.Query
					}
				}
			}
		}
		for _, p := range tl.Summary.Proxied {
			if p.AddrMismatches > 0 {
				d.mismatch[p.Host] += p.AddrMismatches
			}
			// Refused by address, though the run had resolved a name to
			// it: non-TLS TCP in transparent mode, which an fqdn rule
			// cannot allow.
			if n := ipName[p.Host]; n != "" && p.Denied > 0 {
				d.byAddress = append(d.byAddress, fmt.Sprintf("%s:%d (%s) %s", p.Host, p.Port, n, plural(p.Denied, "time")))
			}
		}
		for _, u := range tl.Summary.UDPRefusedTo {
			k := destKey{u.Proto, u.IP, u.Port}
			li := d.udpRefused[k]
			if li == nil {
				li = &learnedIP{proto: u.Proto, ip: u.IP, port: u.Port, runs: map[string]bool{}}
				d.udpRefused[k] = li
			}
			li.conns += u.Count
			li.runs[tl.RunID] = true
			d.udpNames[k] = append(d.udpNames[k], u.Names...)
		}
		for _, dst := range append(append([]Destination{}, tl.Summary.Destinations...), proxiedDestinations(tl, true)...) {
			if dst.Port == 53 && dst.Proto == "UDP" {
				d.dnsServers[net.JoinHostPort(dst.IP, "53")] += dst.Count
				continue
			}
			if len(dst.Names) == 0 {
				k := destKey{dst.Proto, dst.IP, dst.Port}
				li := ipDests[k]
				if li == nil {
					li = &learnedIP{proto: dst.Proto, ip: dst.IP, port: dst.Port, runs: map[string]bool{}}
					ipDests[k] = li
				}
				li.conns += dst.Count
				li.runs[tl.RunID] = true
				continue
			}
			for _, n := range dst.Names {
				connected[n] = true
				if !policy.ValidHostname(n) {
					// Not expressible as a rule (e.g. "_srv" labels, or
					// bytes no hostname has); reported for review.
					d.badNames[n] += dst.Count
					continue
				}
				h := byHost[n]
				if h == nil {
					h = &learnedHost{name: n, ports: map[uint16]bool{}, ips: map[string]bool{},
						runs: map[string]bool{}, udp: map[uint16]int{}}
					byHost[n] = h
				}
				h.runs[tl.RunID] = true
				h.ips[dst.IP] = true
				if dst.Proto == "UDP" {
					h.udp[dst.Port] += dst.Count
					continue
				}
				h.ports[dst.Port] = true
				h.conns += dst.Count
			}
		}
	}

	// Egress: one rule per hostname reached over TCP, sorted by name.
	hostNames := make([]string, 0, len(byHost))
	for n := range byHost {
		hostNames = append(hostNames, n)
	}
	sort.Strings(hostNames)
	used := map[string]bool{}
	l7 := collectL7(runs)
	for _, n := range hostNames {
		h := byHost[n]
		rn := uniqueRuleName(ruleName(n), used)
		d.hosts[rn] = h
		d.ruleHost[rn] = n
		if len(h.ports) == 0 {
			continue // UDP only: reported, not allowed
		}
		if d.httpRules(rn, n, h, l7[n], used) {
			continue
		}
		if x := l7[n]; x != nil && x.tunnels > 0 {
			d.opaque[rn] = true
		}
		d.Profile.Spec.Egress.Rules = append(d.Profile.Spec.Egress.Rules, policy.EgressRule{
			Name:   rn,
			To:     policy.Destination{FQDN: []string{n}, Ports: sortedPorts(h.ports)},
			Action: "allow",
		})
	}

	for _, li := range ipDests {
		ip := net.ParseIP(li.ip)
		switch {
		case ip != nil && ip.IsLoopback():
			d.local = append(d.local, li)
		case li.proto == "TCP":
			d.unnamedTCP = append(d.unnamedTCP, li)
		default:
			d.otherUDP = append(d.otherUDP, li)
		}
	}
	for _, s := range [][]*learnedIP{d.local, d.unnamedTCP, d.otherUDP} {
		sort.Slice(s, func(i, j int) bool {
			if s[i].ip != s[j].ip {
				return s[i].ip < s[j].ip
			}
			if s[i].port != s[j].port {
				return s[i].port < s[j].port
			}
			return s[i].proto < s[j].proto
		})
	}

	for n := range looked {
		if !connected[n] {
			d.lookedUp = append(d.lookedUp, n)
		}
	}
	sort.Strings(d.lookedUp)

	d.untrusted = sortedSet(untrusted)
	// Exec: every binary seen, absolute paths only.
	bins := make([]string, 0, len(d.binaryRuns))
	for b := range d.binaryRuns {
		bins = append(bins, b)
	}
	sort.Strings(bins)
	d.execHashes = map[string][]string{}
	for _, b := range bins {
		a := policy.ExecAllow{Path: b}
		if isInterpreter(b) {
			a.Note = "interpreter: allows arbitrary code; confinement comes from egress policy"
		}
		sums := sortedSet(hashes[b])
		if len(sums) > policy.MaxExecHashes {
			d.execUnpinned = append(d.execUnpinned, b)
			sums = nil
		}
		if len(sums) == 0 {
			d.Profile.Spec.Exec.Allow = append(d.Profile.Spec.Exec.Allow, a)
			continue
		}
		// Each content seen, one entry each: the draft pins what ran.
		d.execHashes[b] = sums
		for _, h := range sums {
			a.Hash = h
			d.Profile.Spec.Exec.Allow = append(d.Profile.Spec.Exec.Allow, a)
		}
	}
	d.learnModels(runs)
	d.learnMCP(runs)
	return d
}

var nonRuleChars = regexp.MustCompile(`[^a-z0-9]+`)

func ruleName(host string) string {
	n := strings.Trim(nonRuleChars.ReplaceAllString(strings.ToLower(host), "-"), "-")
	if n == "" {
		n = "host"
	}
	return n
}

func uniqueRuleName(n string, used map[string]bool) string {
	cand := n
	for i := 2; used[cand]; i++ {
		cand = fmt.Sprintf("%s-%d", n, i)
	}
	used[cand] = true
	return cand
}

func sortedPorts(m map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// q quotes s as a YAML double-quoted scalar. JSON string syntax is a
// subset of YAML's double-quoted style.
func q(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func portList(ps []uint16) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(int(p))
	}
	return "[" + strings.Join(s, ", ") + "]"
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

func runsNote(runs map[string]bool, total int) string {
	if total <= 1 {
		return ""
	}
	return fmt.Sprintf(", %d/%d runs", len(runs), total)
}

// WriteYAML renders the draft as YAML, with review notes as comments.
func (d *Draft) WriteYAML(w io.Writer, now time.Time) error {
	var b strings.Builder
	p := func(format string, a ...interface{}) { fmt.Fprintf(&b, format+"\n", a...) }
	total := len(d.Runs)

	p("# Draft profile generated by learn mode on %s.", now.UTC().Format(time.RFC3339))
	p("# It allows exactly what was observed; review before enforcing (design §7.10).")
	p("#")
	p("# Source runs:")
	var incomplete []string
	for _, tl := range d.Runs {
		flag := ""
		if !tl.Complete {
			flag = "  [incomplete: events may be missing]"
			incomplete = append(incomplete, tl.RunID)
		}
		cmd := commentSafe(strings.Join(tl.Command, " "))
		if len(cmd) > 60 {
			cmd = cmd[:57] + "..."
		}
		p("#   %s  %s  %s%s", commentSafe(tl.RunID), tl.StartedAt.UTC().Format(time.RFC3339), cmd, flag)
	}
	if len(incomplete) > 0 {
		p("# Incomplete runs may under-report destinations and binaries.")
	}
	p("kind: AgentProfile")
	p("metadata:")
	p("  name: %s", q(d.Profile.Metadata.Name))
	p("spec:")
	p("  mode: %s  # switch to enforce once shadowing shows no violations", d.Profile.Spec.Mode)
	p("")
	p("  egress:")
	p("    default: %s", d.Profile.Spec.Egress.Default)
	if d.modelsDropped > 0 {
		p("    # %s named models past the per-run cap and were not recorded;", plural(d.modelsDropped, "request"))
		p("    # the model lists below may miss what they named.")
	}
	if len(d.Profile.Spec.Egress.Rules) == 0 {
		p("    rules: []")
	} else {
		p("    rules:")
	}
	for _, r := range d.Profile.Spec.Egress.Rules {
		if g := d.httpGroups[r.Name]; g != nil {
			d.writeHTTPRule(p, r, g, total)
			continue
		}
		h := d.hosts[r.Name]
		p("      # %s%s", hostSeen(h), runsNote(h.runs, total))
		if d.opaque[r.Name] {
			p("      # Used through a TLS tunnel the proxy did not terminate, so the paths are")
			p("      # unseen. To learn them, run under an audit profile whose rule for this")
			p("      # host has http: { paths: [\"*\"] }.")
		}
		if n := d.mismatch[h.name]; n > 0 {
			p("      # %s sent to an address %s does not resolve to; transparent mode", plural(n, "connection"), commentSafe(h.name))
			p("      # routed them by name instead.")
		}
		var raw []string
		for _, port := range r.To.Ports {
			if !httpish[port] {
				raw = append(raw, strconv.Itoa(int(port)))
			}
		}
		if len(raw) > 0 {
			var ips []string
			for ip := range h.ips {
				if ip != "via proxy" {
					ips = append(ips, q(hostCIDR(ip)))
				}
			}
			sort.Strings(ips)
			p("      # Port %s: if that traffic is neither TLS nor HTTP, transparent mode matches", strings.Join(raw, ", "))
			p("      # this rule through the run's own lookup of the name via the node. A client")
			p("      # using a hard-coded address needs a cidr rule instead")
			if len(ips) > 0 {
				p("      # (seen: %s).", strings.Join(ips, ", "))
			} else {
				p("      # for the addresses the host uses.")
			}
		}
		d.writeModelComments(p, r)
		p("      - name: %s", q(r.Name))
		p("        to: { fqdn: [%s], ports: %s }", q(r.To.FQDN[0]), portList(r.To.Ports))
		writeModelLine(p, r)
		p("        action: %s", r.Action)
	}

	if len(d.unnamedTCP) > 0 {
		p("")
		p("      # TCP to addresses with no looked-up name. An IP rule is coarse (shared CDN")
		p("      # addresses, design §7.5), so these are left disabled. Prefer finding the")
		p("      # hostname; enable only for protocols with no name on the wire.")
		for _, li := range d.unnamedTCP {
			p("      # - name: %s  # %s%s", q(ruleName("ip-"+li.ip+"-"+strconv.Itoa(int(li.port)))),
				plural(li.conns, "connection"), runsNote(li.runs, total))
			p("      #   to: { cidr: [%s], ports: [%d] }", q(hostCIDR(li.ip)), li.port)
			p("      #   action: allow")
		}
	}

	var udpNamed []string
	for rn, h := range d.hosts {
		for port, n := range h.udp {
			udpNamed = append(udpNamed, fmt.Sprintf("%s:%d (%s, rule %s)", h.name, port, plural(n, "connection"), rn))
		}
	}
	sort.Strings(udpNamed)
	if len(udpNamed) > 0 || len(d.otherUDP) > 0 {
		p("")
		p("      # UDP seen and not allowed. Transparent mode refuses UDP other than DNS and")
		p("      # the node's -udp-allow; QUIC (UDP 443) falls back to TCP (design §6.8).")
		for _, s := range udpNamed {
			p("      #   %s", commentSafe(s))
		}
		for _, li := range d.otherUDP {
			p("      #   %s (%s)", net.JoinHostPort(li.ip, strconv.Itoa(int(li.port))), plural(li.conns, "connection"))
		}
	}
	if len(d.udpRefused) > 0 {
		var ks []destKey
		for k := range d.udpRefused {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool {
			if ks[i].ip != ks[j].ip {
				return ks[i].ip < ks[j].ip
			}
			return ks[i].port < ks[j].port
		})
		p("")
		p("      # UDP the node refused: drafted in the udp block below, which the ceiling")
		p("      # must also grant (or the operator adds it to the node's -udp-allow):")
		for _, k := range ks {
			li := d.udpRefused[k]
			p("      #   %s (%s)", net.JoinHostPort(li.ip, strconv.Itoa(int(li.port))), plural(li.conns, "attempt"))
		}
	}
	if len(d.local) > 0 {
		p("")
		p("      # Loopback destinations, not covered by egress rules:")
		for _, li := range d.local {
			p("      #   %s %s (%s)", li.proto, net.JoinHostPort(li.ip, strconv.Itoa(int(li.port))), plural(li.conns, "connection"))
		}
	}
	if len(d.dnsServers) > 0 {
		servers := make([]string, 0, len(d.dnsServers))
		for s := range d.dnsServers {
			servers = append(servers, s)
		}
		sort.Strings(servers)
		p("")
		p("      # DNS went to %s. In transparent mode the node's resolver answers", strings.Join(servers, ", "))
		p("      # instead, only for names a rule allows; no DNS rule is needed (design §6.8).")
	}
	if len(d.lookedUp) > 0 {
		p("")
		p("      # Looked up but never connected to (not allowed):")
		for _, n := range d.lookedUp {
			p("      #   %s", commentSafe(n))
		}
	}

	if len(d.byAddress) > 0 {
		sort.Strings(d.byAddress)
		p("")
		p("      # Refused TCP to addresses the run had looked up by name: no rule allowed the")
		p("      # name on that port, or the lookup did not go through the node's resolver.")
		for _, s := range d.byAddress {
			p("      #   %s", commentSafe(s))
		}
	}

	if len(d.dnsBlocked) > 0 {
		p("")
		p("      # Looked up but refused by the node's resolver, under the profile in force:")
		for _, n := range sortedSet(d.dnsBlocked) {
			p("      #   %s", commentSafe(n))
		}
	}

	if len(d.badNames) > 0 {
		bad := make([]string, 0, len(d.badNames))
		for n := range d.badNames {
			bad = append(bad, n)
		}
		sort.Strings(bad)
		p("")
		p("      # Connected to by names that are not valid fqdn entries (not allowed):")
		for _, n := range bad {
			p("      #   %s (%s)", commentSafe(n), plural(d.badNames[n], "connection"))
		}
	}

	if len(d.badPaths) > 0 {
		sort.Strings(d.badPaths)
		p("")
		p("      # Requests no exact http rule can express (not allowed):")
		for _, b := range d.badPaths {
			p("      #   %s", commentSafe(b))
		}
	}

	p("")
	p("  exec:")
	p("    default: %s", d.Profile.Spec.Exec.Default)
	p("    require_trusted_path: %t  # design §7.6; exec.allow entries pass regardless", d.Profile.Spec.Exec.RequireTrustedPath)
	if !d.resolved {
		p("    # Paths as requested: where BPF LSM is active, the node agent records the")
		p("    # paths the kernel resolved, which exec policy compares.")
	}
	if len(d.untrusted) > 0 {
		p("    # These ran from locations someone other than root can write (build output,")
		p("    # downloads). They are listed below, so this draft allows them by exact path.")
		p("    # If their names change from run to run (go test, cargo run), allow their")
		p("    # directory instead (path: /dir/*), or, for an agent that runs what it builds,")
		p("    # set default: allow and require_trusted_path: false.")
		for _, u := range d.untrusted {
			p("    #   %s", commentSafe(u))
		}
	}
	if len(d.execUnpinned) > 0 {
		p("    # These were pinned by hash, and ran with more contents than one path may")
		p("    # list (%d), so the draft allows them by path alone:", policy.MaxExecHashes)
		for _, u := range d.execUnpinned {
			p("    #   %s", commentSafe(u))
		}
	}
	p("    # To pin a binary's content, add hash: sha256:<sha256sum of the file> to its")
	p("    # entry; other content at that path is then refused (where BPF LSM is active).")
	if len(d.Profile.Spec.Exec.Allow) == 0 {
		p("    allow: []")
	} else {
		p("    allow:")
	}
	for _, a := range d.Profile.Spec.Exec.Allow {
		line := fmt.Sprintf("      - path: %s", q(a.Path))
		if rn := runsNote(d.binaryRuns[a.Path], total); rn != "" {
			line += "  # " + strings.TrimPrefix(rn, ", ")
		}
		p("%s", line)
		if a.Hash != "" {
			p("        hash: %s", q(a.Hash))
		}
		if a.Note != "" {
			p("        note: %s", q(a.Note))
		}
	}
	d.writeMCP(p, total)
	d.writeUnix(p, total)
	d.writeUDP(p, total)

	_, err := io.WriteString(w, b.String())
	return err
}

// proxiedDestinations turns a run's proxied requests into destinations
// as learn and check see them. With letThrough, requests the proxy
// blocked are left out: learning from them would widen the profile.
func proxiedDestinations(tl *RunTimeline, letThrough bool) []Destination {
	var out []Destination
	for _, p := range tl.Summary.Proxied {
		n := p.Requests
		if letThrough {
			n -= p.Denied
		}
		if n <= 0 {
			continue
		}
		d := Destination{Proto: "TCP", IP: "via proxy", Port: p.Port, Count: n, Names: []string{p.Host}}
		if _, err := netip.ParseAddr(p.Host); err == nil {
			d.IP, d.Names = p.Host, nil
		}
		out = append(out, d)
	}
	return out
}

// hostSeen describes how a learned host was reached.
func hostSeen(h *learnedHost) string {
	var ips []string
	viaProxy := false
	for ip := range h.ips {
		if ip == "via proxy" {
			viaProxy = true
		} else {
			ips = append(ips, ip)
		}
	}
	sort.Strings(ips)
	parts := []string{}
	if len(ips) > 0 {
		parts = append(parts, "to "+strings.Join(ips, ", "))
	}
	if viaProxy {
		parts = append(parts, "through the proxy")
	}
	return plural(h.conns, "connection") + " " + strings.Join(parts, " and ")
}

// commentSafe escapes s for a YAML comment. Command lines, paths and DNS
// names come from the audited run, which controls them: a raw newline
// would end the comment and let the run write YAML into its own draft.
func commentSafe(s string) string {
	quoted := strconv.QuoteToGraphic(s)
	return quoted[1 : len(quoted)-1]
}

func hostCIDR(ip string) string {
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

func setOf(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// writeUnix drafts the unix block: every Unix socket outside the run that
// writeUDP drafts the udp block (milestone 4.7) from the UDP the node
// refused, commented out: a profile's udp.allow works only where the
// ceiling grants the same destination, and UDP carries no name to check.
func (d *Draft) writeUDP(p func(string, ...interface{}), total int) {
	if len(d.udpRefused) == 0 {
		return
	}
	var ks []destKey
	for k := range d.udpRefused {
		if k.port != 53 {
			ks = append(ks, k)
		}
	}
	if len(ks) == 0 {
		return
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].ip != ks[j].ip {
			return ks[i].ip < ks[j].ip
		}
		return ks[i].port < ks[j].port
	})
	p("")
	p("  # UDP the node refused. Uncomment what the agent needs; the ceiling's udp.allow")
	p("  # must grant it too. QUIC (UDP 443) is better left to fall back to TCP.")
	p("  # udp:")
	p("  #   allow:")
	for _, k := range ks {
		li := d.udpRefused[k]
		names := ""
		if ns := sortedSet(setOf(d.udpNames[k])); len(ns) > 0 {
			names = ", " + commentSafe(strings.Join(ns, ", "))
		}
		p("  #     - %s  # %s%s%s", q(net.JoinHostPort(li.ip, strconv.Itoa(int(li.port)))), plural(li.conns, "attempt"), names, runsNote(li.runs, total))
	}
}

// the runs used. Root-equivalent ones are left commented out, since a
// ceiling must permit them.
func (d *Draft) writeUnix(p func(string, ...interface{}), total int) {
	if len(d.unixSeen) == 0 {
		return
	}
	pats := make([]string, 0, len(d.unixSeen))
	for k := range d.unixSeen {
		pats = append(pats, k)
	}
	sort.Strings(pats)
	if len(pats) > 8 {
		p("")
		p("  # More than 8 Unix sockets were used; a profile allows at most 8 entries.")
		p("  # Merge some into prefixes (a trailing *).")
	}
	p("")
	p("  # Unix sockets outside the run that the run used. Transparent enforce refuses")
	p("  # all others where BPF LSM is active; the run's own sockets always work.")
	p("  unix:")
	p("    allow:")
	for _, pat := range pats {
		note := strings.TrimPrefix(runsNote(d.unixSeen[pat], total), ", ")
		if policy.RootSocket(pat) {
			p("      # - %s  # gives root: needs allowRootSockets in the ceiling", q(pat))
			continue
		}
		if b := policy.UnixBypass(pat); strings.Contains(b, "bypassing") {
			p("      # - %s  # %s", q(pat), commentSafe(b))
			continue
		}
		if b := policy.UnixBypass(pat); b != "" {
			p("      # %s:", commentSafe(b))
		}
		if note != "" {
			p("      - %s  # %s", q(pat), note)
		} else {
			p("      - %s", q(pat))
		}
	}
}
