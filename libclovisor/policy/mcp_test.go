// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"strings"
	"testing"
)

const mcpProfile = `
kind: AgentProfile
metadata: { name: mcp-agent }
spec:
  mode: enforce
  egress: { default: deny, rules: [] }
  mcp:
    default: deny
    servers:
      - name: filesystem
        match: { stdio: "@modelcontextprotocol/server-filesystem" }
        tools: { allow: ["read_*", "list_directory"], deny: ["read_secret*"] }
        resources: { allow_uri: ["file:///workspace/*"] }
        pin_tool_definitions: true
      - name: anything
        match: { stdio: "mcp-anything" }
    sampling: { action: deny, message: "No sampling here." }
`

const mcpClamp = `
kind: AgentProfile
metadata: { name: mcp-clamp }
spec:
  mode: audit
  egress: { default: allow, rules: [] }
  mcp:
    default: deny
    servers:
      - name: fs-read-only
        match: { stdio: "@modelcontextprotocol/server-filesystem" }
        tools: { allow: ["list_directory"] }
`

func TestDecideMCP(t *testing.T) {
	c := mustCompile(t, Options{Linux: true}, mcpProfile, mcpClamp)
	grant := &Effective{Layers: []Layer{{Profile: c.Profile("mcp-agent")}}}
	both := grant.With(Layer{Profile: c.Profile("mcp-clamp")})
	fs := []string{"npx", "-y", "@modelcontextprotocol/server-filesystem@1.2.0", "/workspace"}

	cases := []struct {
		e       *Effective
		r       MCPRequest
		allowed bool
		would   int
		msg     string
	}{
		{grant, MCPRequest{Kind: "server", Server: "fs", Argv: fs}, true, 0, ""},
		{grant, MCPRequest{Kind: "server", Server: "x", Argv: []string{"uvx", "mcp-server-fetch"}}, false, 0, "is not allowed by profile mcp-agent"},
		{grant, MCPRequest{Kind: "server", Server: "a", Argv: []string{"/opt/bin/mcp-anything"}}, true, 0, ""}, // basename match
		{grant, MCPRequest{Kind: "tool", Server: "fs", Argv: fs, Tool: "read_file"}, true, 0, ""},
		{grant, MCPRequest{Kind: "tool", Server: "fs", Argv: fs, Tool: "read_secret_file"}, false, 0, "is denied by profile"},
		{grant, MCPRequest{Kind: "tool", Server: "fs", Argv: fs, Tool: "write_file"}, false, 0, "not in profile mcp-agent's allow list"},
		{grant, MCPRequest{Kind: "tool", Server: "a", Argv: []string{"mcp-anything"}, Tool: "whatever"}, true, 0, ""},
		{grant, MCPRequest{Kind: "resource", Server: "fs", Argv: fs, URI: "file:///workspace/a.txt"}, true, 0, ""},
		{grant, MCPRequest{Kind: "resource", Server: "fs", Argv: fs, URI: "file:///etc/passwd"}, false, 0, "Resource file:///etc/passwd"},
		{grant, MCPRequest{Kind: "sampling", Server: "fs", Argv: fs}, false, 0, "No sampling here."},
		// The audit clamp records would-deny but blocks nothing.
		{both, MCPRequest{Kind: "tool", Server: "fs", Argv: fs, Tool: "read_file"}, true, 1, ""},
		{both, MCPRequest{Kind: "tool", Server: "fs", Argv: fs, Tool: "list_directory"}, true, 0, ""},
	}
	for _, tc := range cases {
		d := tc.e.DecideMCP(tc.r)
		if d.Allowed() != tc.allowed || len(d.WouldDeny) != tc.would || (tc.msg != "" && !strings.Contains(d.Message, tc.msg)) {
			t.Errorf("%+v: got %+v", tc.r, d)
		}
	}

	// A layer with no mcp block abstains.
	egressOnly := mustCompile(t, Options{}, `
kind: AgentProfile
metadata: { name: e }
spec: { mode: enforce, egress: { default: deny, rules: [] } }
`).Profile("e")
	e := &Effective{Layers: []Layer{{Profile: egressOnly}}}
	if d := e.DecideMCP(MCPRequest{Kind: "tool", Argv: fs, Tool: "rm_rf"}); !d.Allowed() {
		t.Errorf("egress-only layer decided MCP: %+v", d)
	}
	if !grant.PinsToolDefinitions(fs) || grant.PinsToolDefinitions([]string{"mcp-anything"}) {
		t.Error("pinning lookup wrong")
	}
}
