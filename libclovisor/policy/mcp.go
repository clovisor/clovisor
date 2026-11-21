// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"path"
	"strings"
)

// MCP decisions (design §8). Each profile layer decides on its own; a
// layer with no mcp block abstains, so a clamp about egress does not
// switch off MCP. Layers combine as for egress: an enforce-mode deny
// blocks, an audit-mode deny is recorded as would-deny.

// matchStdio reports whether a stdio match pattern names the command
// line: an argument equal to it, the same with an "@version" suffix (npx
// and uvx specs), an executable whose basename it is, or a glob.
func matchStdio(pattern string, argv []string) bool {
	for _, a := range argv {
		if a == pattern || strings.HasPrefix(a, pattern+"@") || path.Base(a) == pattern || glob(pattern, a) {
			return true
		}
	}
	return false
}

// mcpServerFor returns the first server rule naming the server: by
// match.fqdn for a remote server (host set), by match.stdio for a local
// one (argv set); or nil.
func mcpServerFor(m *MCP, argv []string, host string) *MCPServer {
	host = NormalizeHost(host)
	for i := range m.Servers {
		s := &m.Servers[i]
		switch {
		case host != "" && s.Match.FQDN != "":
			if hp, err := parseHost(s.Match.FQDN); err == nil && hp.match(host) {
				return s
			}
		case host == "" && s.Match.Stdio != "" && matchStdio(s.Match.Stdio, argv):
			return s
		}
	}
	return nil
}

// MCPServerRule returns the name of the server rule that governs a server
// (a stdio command line, or a remote host) in this profile, or "".
func (cp *CompiledProfile) MCPServerRule(argv []string, host string) string {
	if cp.mcp == nil {
		return ""
	}
	if s := mcpServerFor(cp.mcp, argv, host); s != nil {
		return s.Name
	}
	return ""
}

// PinsToolDefinitions reports whether the server rule governing a server
// asks for tools/list pinning.
func (cp *CompiledProfile) PinsToolDefinitions(argv []string, host string) bool {
	if cp.mcp == nil {
		return false
	}
	s := mcpServerFor(cp.mcp, argv, host)
	return s != nil && s.PinToolDefinitions
}

// MCPRequest is an MCP operation to decide. Kind is "server" (may this
// server be used at all), "tool", "resource" or "sampling".
type MCPRequest struct {
	Kind   string
	Server string   // the harness's name for the server, for messages
	Argv   []string // a local server's command line, which match.stdio matches
	Host   string   // a remote server's hostname, which match.fqdn matches
	Tool   string
	URI    string
}

func (cp *CompiledProfile) decideMCP(r MCPRequest) (Decision, bool) {
	m := cp.mcp
	if m == nil {
		return Decision{}, false // abstain
	}
	s := mcpServerFor(m, r.Argv, r.Host)
	if r.Host != "" && s == nil {
		// A host no server rule names is not MCP to this profile: egress
		// rules alone govern it, so the layer abstains.
		return Decision{}, false
	}
	if r.Kind == "sampling" {
		if m.Sampling != nil && m.Sampling.Action == ActionAllow {
			return Decision{Action: ActionAllow, Rule: "sampling"}, true
		}
		msg := fmt.Sprintf("MCP server %s asked for a model completion (sampling); profile %s does not allow it.", r.Server, cp.Name)
		if m.Sampling != nil && m.Sampling.Message != "" {
			msg = m.Sampling.Message
		}
		return Decision{Action: ActionDeny, Rule: "sampling", Message: msg}, true
	}
	if s == nil {
		if m.Default == ActionAllow {
			return Decision{Action: ActionAllow}, true
		}
		return Decision{Action: ActionDeny, Message: fmt.Sprintf("MCP server %s (%s) is not allowed by profile %s.",
			r.Server, strings.Join(r.Argv, " "), cp.Name)}, true
	}
	switch r.Kind {
	case "tool":
		if s.Tools != nil {
			if globAny(s.Tools.Deny, r.Tool) {
				return Decision{Action: ActionDeny, Rule: s.Name, Message: fmt.Sprintf(
					"Tool %s on MCP server %s is denied by profile %s.", r.Tool, r.Server, cp.Name)}, true
			}
			if len(s.Tools.Allow) > 0 && !globAny(s.Tools.Allow, r.Tool) {
				return Decision{Action: ActionDeny, Rule: s.Name, Message: fmt.Sprintf(
					"Tool %s on MCP server %s is not in profile %s's allow list (%s).", r.Tool, r.Server, cp.Name,
					strings.Join(s.Tools.Allow, ", "))}, true
			}
		}
	case "resource":
		if s.Resources != nil && !globAny(s.Resources.AllowURI, r.URI) {
			return Decision{Action: ActionDeny, Rule: s.Name, Message: fmt.Sprintf(
				"Resource %s on MCP server %s is not allowed by profile %s.", r.URI, r.Server, cp.Name)}, true
		}
	}
	return Decision{Action: ActionAllow, Rule: s.Name}, true
}

// DecideMCP evaluates an MCP operation against every layer.
func (e *Effective) DecideMCP(r MCPRequest) EffectiveDecision {
	out := EffectiveDecision{Decision: Decision{Action: ActionAllow}}
	for _, l := range e.Layers {
		d, ok := l.Profile.decideMCP(r)
		if !ok {
			continue
		}
		if !d.Allowed() {
			if l.Profile.Mode == ModeEnforce {
				return EffectiveDecision{Decision: d, Enforced: true, Layer: l.Profile.Name, WouldDeny: out.WouldDeny}
			}
			out.WouldDeny = append(out.WouldDeny, l.Profile.Name)
			if out.Message == "" {
				out.Message = d.Message
			}
			continue
		}
		if out.Rule == "" {
			out.Rule = d.Rule
		}
	}
	return out
}

// PinsToolDefinitions reports whether any layer asks for pinning.
func (e *Effective) PinsToolDefinitions(argv []string, host string) bool {
	for _, l := range e.Layers {
		if l.Profile.PinsToolDefinitions(argv, host) {
			return true
		}
	}
	return false
}

// GovernsRemoteMCP reports whether any layer names host as a remote MCP
// server, i.e. whether its requests need JSON-RPC inspection.
func (e *Effective) GovernsRemoteMCP(host string) bool {
	for _, l := range e.Layers {
		if l.Profile.MCPServerRule(nil, host) != "" {
			return true
		}
	}
	return false
}

// Enforcing reports whether any layer is in enforce mode, i.e. whether
// a drifted tool definition is blocked rather than only recorded.
func (e *Effective) Enforcing() bool {
	for _, l := range e.Layers {
		if l.Profile.Mode == ModeEnforce {
			return true
		}
	}
	return false
}
