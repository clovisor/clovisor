// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Learning below the host (milestone 2.6). A host whose every request the
// proxy saw by method and path (plain HTTP, or terminated tunnels) gets
// http rules naming exactly those methods and paths. A host used through
// an opaque tunnel, or connected to directly, keeps a host-level rule:
// what was sent inside is unknown, so no path list would be complete.
// MCP servers get a server rule whose tool and resource lists are the
// calls that were let through.

// hostL7 is what the proxy saw of one hostname, across runs.
type hostL7 struct {
	tunnels int // CONNECTs let through without termination
	dropped int // requests past the per-run path cap
	paths   map[methodPath]*pathSeen
}

type methodPath struct{ method, path string }

type pathSeen struct {
	method, path string
	ports        map[uint16]bool
	requests     int
	runs         map[string]bool
}

// httpGroup is one drafted http rule: paths that were used with the same
// methods on the same ports.
type httpGroup struct {
	host        *learnedHost
	paths       []*pathSeen
	dropped     int
	suggestions []string
}

// collectL7 aggregates the requests the proxy let through, by hostname.
// Blocked requests are left out: learning from them would widen the
// profile.
func collectL7(runs []*RunTimeline) map[string]*hostL7 {
	out := map[string]*hostL7{}
	for _, tl := range runs {
		for _, p := range tl.Summary.Proxied {
			n := policy.NormalizeHost(p.Host)
			h := out[n]
			if h == nil {
				h = &hostL7{paths: map[methodPath]*pathSeen{}}
				out[n] = h
			}
			h.tunnels += p.Tunnels
			h.dropped += p.PathsDropped
			for _, u := range p.Paths {
				if u.Requests-u.Denied <= 0 {
					continue
				}
				k := methodPath{u.Method, u.Path}
				ps := h.paths[k]
				if ps == nil {
					ps = &pathSeen{method: u.Method, path: u.Path, ports: map[uint16]bool{}, runs: map[string]bool{}}
					h.paths[k] = ps
				}
				ps.ports[p.Port] = true
				ps.requests += u.Requests - u.Denied
				ps.runs[tl.RunID] = true
			}
		}
	}
	return out
}

var learnMethodRE = regexp.MustCompile(`^[A-Z]+$`)

// expressible reports whether a path can be written as an exact path
// rule: "*" is the glob character and "?" is refused by the compiler.
func expressiblePath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "*?")
}

// httpRules drafts the http rules for host n, if every use of it was
// seen by method and path. It reports whether it did.
func (d *Draft) httpRules(rn, n string, h *learnedHost, l7 *hostL7, used map[string]bool) bool {
	if l7 == nil || l7.tunnels > 0 || len(l7.paths) == 0 {
		return false
	}
	for ip := range h.ips {
		if ip != "via proxy" {
			return false // also connected to directly: unseen requests
		}
	}

	groups := map[string]*httpGroup{}
	var keys []string
	methodsOf := map[string][]string{}
	portsOf := map[string][]uint16{}
	byPath := map[string]map[string]bool{} // path -> methods
	portsByPath := map[string]map[uint16]bool{}
	for _, ps := range l7.paths {
		if !learnMethodRE.MatchString(ps.method) || !expressiblePath(ps.path) {
			d.badPaths = append(d.badPaths, fmt.Sprintf("%s %s %s (%s)", n, ps.method, ps.path, plural(ps.requests, "request")))
			continue
		}
		if byPath[ps.path] == nil {
			byPath[ps.path] = map[string]bool{}
			portsByPath[ps.path] = map[uint16]bool{}
		}
		byPath[ps.path][ps.method] = true
		for p := range ps.ports {
			portsByPath[ps.path][p] = true
		}
	}
	if len(byPath) == 0 {
		return false
	}
	for _, ps := range l7.paths {
		if byPath[ps.path] == nil || !byPath[ps.path][ps.method] {
			continue
		}
		ms := sortedSet(byPath[ps.path])
		ports := sortedPorts(portsByPath[ps.path])
		k := strings.Join(ms, ",") + "|" + portList(ports)
		g := groups[k]
		if g == nil {
			g = &httpGroup{host: h}
			groups[k] = g
			keys = append(keys, k)
			methodsOf[k], portsOf[k] = ms, ports
		}
		g.paths = append(g.paths, ps)
	}
	sort.Strings(keys)

	for i, k := range keys {
		g := groups[k]
		sort.Slice(g.paths, func(a, b int) bool {
			if g.paths[a].path != g.paths[b].path {
				return g.paths[a].path < g.paths[b].path
			}
			return g.paths[a].method < g.paths[b].method
		})
		var paths []string
		for _, ps := range g.paths {
			if len(paths) == 0 || paths[len(paths)-1] != ps.path {
				paths = append(paths, ps.path)
			}
		}
		name := uniqueRuleName(rn+"-"+strings.ToLower(strings.Join(methodsOf[k], "-")), used)
		if i == 0 {
			g.dropped = l7.dropped
		}
		g.suggestions = suggestGlobs(paths)
		d.httpGroups[name] = g
		d.Profile.Spec.Egress.Rules = append(d.Profile.Spec.Egress.Rules, policy.EgressRule{
			Name:   name,
			To:     policy.Destination{FQDN: []string{n}, Ports: portsOf[k]},
			HTTP:   &policy.HTTPMatch{Methods: methodsOf[k], Paths: paths},
			Action: "allow",
		})
	}
	return true
}

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	digitsRE = regexp.MustCompile(`^[0-9]+$`)
	hexRE    = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
)

// idSegment reports whether a path segment looks like an identifier
// rather than a fixed part of an API.
func idSegment(s string) bool {
	return digitsRE.MatchString(s) || uuidRE.MatchString(s) ||
		(hexRE.MatchString(s) && strings.ContainsAny(s, "0123456789"))
}

// suggestGlobs proposes, for review only, globs that would cover several
// learned paths differing in id-like segments. Each one widens the rule:
// "*" also matches "/", so a glob covers deeper paths too.
func suggestGlobs(paths []string) []string {
	cover := map[string]int{}
	for _, p := range paths {
		segs := strings.Split(p, "/")
		changed := false
		for i, s := range segs {
			if idSegment(s) {
				segs[i], changed = "*", true
			}
		}
		if changed {
			cover[strings.Join(segs, "/")]++
		}
	}
	var out []string
	for g, n := range cover {
		if n >= 2 {
			out = append(out, fmt.Sprintf("%s covers %d of these paths", g, n))
		}
	}
	sort.Strings(out)
	return out
}

// mcpSeen is one MCP server the runs used.
type mcpSeen struct {
	server    string // the harness's name, or the host for a remote server
	command   string // a local server's command line
	remote    bool
	refused   bool // every registration was refused
	tools     map[string]int
	resources map[string]int
	denied    map[string]int // tool calls and reads that were blocked
	sampling  int
	drift     map[string]bool
	runs      map[string]bool
}

// collectMCP aggregates MCP use across runs. A server is local when a
// run registered it with the gateway; otherwise it is a remote host.
func collectMCP(runs []*RunTimeline) []*mcpSeen {
	byKey := map[string]*mcpSeen{}
	var order []string
	for _, tl := range runs {
		cmd := map[string]string{}
		registered := map[string]bool{}
		for _, u := range tl.Summary.MCP {
			if u.Method == "register" {
				cmd[u.Server] = u.Name
				if u.Calls-u.Denied > 0 {
					registered[u.Server] = true
				}
			}
		}
		for _, u := range tl.Summary.MCP {
			c, local := cmd[u.Server]
			key := "remote " + u.Server
			if local {
				key = "local " + u.Server + "\x00" + c
			}
			s := byKey[key]
			if s == nil {
				s = &mcpSeen{server: u.Server, command: c, remote: !local, refused: true,
					tools: map[string]int{}, resources: map[string]int{}, denied: map[string]int{},
					drift: map[string]bool{}, runs: map[string]bool{}}
				byKey[key] = s
				order = append(order, key)
			}
			s.runs[tl.RunID] = true
			if !local || registered[u.Server] {
				s.refused = false
			}
			ok := u.Calls - u.Denied
			switch u.Method {
			case "tools/call":
				if ok > 0 {
					s.tools[u.Name] += ok
				}
				if u.Denied > 0 {
					s.denied["tool "+u.Name] += u.Denied
				}
			case "resources/read":
				if ok > 0 {
					s.resources[u.Name] += ok
				}
				if u.Denied > 0 {
					s.denied["resource "+u.Name] += u.Denied
				}
			case "sampling/createMessage":
				s.sampling += u.Calls
			case "tools/list":
				if u.Name != "" {
					s.drift[u.Name] = true
				}
			}
		}
	}
	sort.Strings(order)
	out := make([]*mcpSeen, len(order))
	for i, k := range order {
		out[i] = byKey[k]
	}
	return out
}

// launchers start the program named by a later argument.
var launchers = map[string]bool{
	"npx": true, "uvx": true, "pipx": true, "bunx": true, "pnpm": true, "yarn": true, "npm": true,
	"uv": true, "docker": true, "podman": true,
}

var launcherVerbs = map[string]bool{"run": true, "exec": true, "dlx": true, "x": true, "--": true}

// stdioPattern picks the match.stdio pattern for a server's command line:
// the package or script a launcher starts, else the executable's name.
// The pattern is always one of the arguments (less an @version suffix),
// so it matches the command it was learned from.
func stdioPattern(command string) string {
	argv := strings.Fields(command)
	if len(argv) == 0 {
		return ""
	}
	pick := filepath.Base(argv[0])
	if launchers[pick] || isInterpreter(argv[0]) {
		pick = ""
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "-") || launcherVerbs[a] || strings.Contains(a, "=") {
				continue
			}
			pick = a
			if i := strings.LastIndex(a, "@"); i > 0 {
				pick = a[:i]
			}
			break
		}
	}
	if pick == "" || strings.ContainsAny(pick, "*?[") {
		return ""
	}
	return pick
}

// learnMCP drafts the mcp block: default deny, one server rule per server
// used, allowing exactly the tools called and resources read.
func (d *Draft) learnMCP(runs []*RunTimeline) {
	d.mcpSeen = collectMCP(runs)
	if len(d.mcpSeen) == 0 {
		return
	}
	m := &policy.MCP{Default: "deny"}
	used := map[string]bool{}
	for _, s := range d.mcpSeen {
		if s.refused {
			d.mcpNotes = append(d.mcpNotes, fmt.Sprintf("%s (%s): every registration was refused; not allowed", s.server, s.command))
			continue
		}
		var match policy.MCPMatch
		if s.remote {
			if !policy.ValidHostname(s.server) {
				d.mcpNotes = append(d.mcpNotes, fmt.Sprintf("%s: not a valid hostname for match.fqdn; not allowed", s.server))
				continue
			}
			match.FQDN = policy.NormalizeHost(s.server)
		} else {
			match.Stdio = stdioPattern(s.command)
			if match.Stdio == "" {
				d.mcpNotes = append(d.mcpNotes, fmt.Sprintf("%s (%s): no argument to match the command on; not allowed", s.server, s.command))
				continue
			}
		}
		rule := policy.MCPServer{
			Name:               uniqueRuleName(ruleName(s.server), used),
			Match:              match,
			PinToolDefinitions: true,
		}
		var tools []string
		for t := range s.tools {
			if t == "" || strings.Contains(t, "*") {
				d.mcpNotes = append(d.mcpNotes, fmt.Sprintf("%s: tool %q cannot be listed exactly; not allowed", s.server, t))
				continue
			}
			tools = append(tools, t)
		}
		sort.Strings(tools)
		if len(tools) > 0 {
			rule.Tools = &policy.ToolRules{Allow: tools}
		} else {
			// An empty allow list allows every tool; deny instead.
			rule.Tools = &policy.ToolRules{Deny: []string{"*"}}
		}
		uris := []string{}
		for u := range s.resources {
			if strings.Contains(u, "*") {
				d.mcpNotes = append(d.mcpNotes, fmt.Sprintf("%s: resource %q cannot be listed exactly; not allowed", s.server, u))
				continue
			}
			uris = append(uris, u)
		}
		sort.Strings(uris)
		// No resources block allows every resource: list exactly the
		// ones read, possibly none.
		rule.Resources = &policy.ResourceRules{AllowURI: uris}
		d.mcpRules = append(d.mcpRules, s)
		m.Servers = append(m.Servers, rule)
	}
	d.Profile.Spec.MCP = m
}

func countsNote(m map[string]int) string {
	n := 0
	for _, c := range m {
		n += c
	}
	return plural(n, "call")
}

// writeHTTPRule renders a drafted http rule.
func (d *Draft) writeHTTPRule(p func(string, ...interface{}), r policy.EgressRule, g *httpGroup, total int) {
	reqs := 0
	runs := map[string]bool{}
	for _, ps := range g.paths {
		reqs += ps.requests
		for r := range ps.runs {
			runs[r] = true
		}
	}
	p("      # %s through the proxy, every one seen by method and path%s", plural(reqs, "request"), runsNote(runs, total))
	for _, s := range g.suggestions {
		p("      # A glob would generalize (each widens the rule): %s", commentSafe(s))
	}
	if g.dropped > 0 {
		p("      # %s to further paths were past the per-run cap and not recorded;", plural(g.dropped, "request"))
		p("      # this rule denies them.")
	}
	p("      - name: %s", q(r.Name))
	p("        to: { fqdn: [%s], ports: %s }", q(r.To.FQDN[0]), portList(r.To.Ports))
	ms := make([]string, len(r.HTTP.Methods))
	for i, m := range r.HTTP.Methods {
		ms[i] = q(m)
	}
	p("        http:")
	p("          methods: [%s]", strings.Join(ms, ", "))
	p("          paths:")
	for _, path := range r.HTTP.Paths {
		n := 0
		for _, ps := range g.paths {
			if ps.path == path {
				n += ps.requests
			}
		}
		p("            - %s  # %s", q(path), plural(n, "request"))
	}
	p("        action: %s", r.Action)
}

// writeMCP renders the drafted mcp block.
func (d *Draft) writeMCP(p func(string, ...interface{}), total int) {
	m := d.Profile.Spec.MCP
	if m == nil && len(d.mcpNotes) == 0 {
		return
	}
	p("")
	p("  mcp:")
	if m == nil {
		p("    # MCP servers were used, but none could be drafted:")
		for _, n := range d.mcpNotes {
			p("    #   %s", commentSafe(n))
		}
		return
	}
	p("    default: %s", m.Default)
	p("    servers:")
	for i, r := range m.Servers {
		s := d.mcpRules[i]
		if s.remote {
			p("      # remote server%s", runsNote(s.runs, total))
		} else {
			p("      # local server %s, started as: %s%s", commentSafe(s.server), commentSafe(s.command), runsNote(s.runs, total))
		}
		for _, k := range sortedKeysInt(s.denied) {
			p("      # blocked during learning, not allowed: %s (%s)", commentSafe(k), plural(s.denied[k], "time"))
		}
		for _, t := range sortedSet(s.drift) {
			p("      # tool %s changed its definition since pinned during learning; review it", commentSafe(t))
		}
		if s.sampling > 0 {
			p("      # asked for sampling %s; sampling stays denied", plural(s.sampling, "time"))
		}
		p("      - name: %s", q(r.Name))
		if r.Match.FQDN != "" {
			p("        match: { fqdn: %s }", q(r.Match.FQDN))
		} else {
			p("        match: { stdio: %s }", q(r.Match.Stdio))
		}
		if len(r.Tools.Allow) > 0 {
			p("        tools:")
			p("          allow:  # %s", countsNote(s.tools))
			for _, t := range r.Tools.Allow {
				p("            - %s  # %s", q(t), plural(s.tools[t], "call"))
			}
		} else {
			p("        tools: { deny: [\"*\"] }  # no tool calls were let through")
		}
		if len(r.Resources.AllowURI) > 0 {
			p("        resources:")
			p("          allow_uri:")
			for _, u := range r.Resources.AllowURI {
				p("            - %s  # %s", q(u), plural(s.resources[u], "read"))
			}
		} else {
			p("        resources: { allow_uri: [] }  # none read")
		}
		p("        pin_tool_definitions: %t", r.PinToolDefinitions)
	}
	for _, n := range d.mcpNotes {
		p("    # %s", commentSafe(n))
	}
}

func sortedKeysInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
