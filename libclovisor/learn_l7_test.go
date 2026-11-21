// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

func TestRunRecorderPaths(t *testing.T) {
	r := newTestRecorder(t)
	ev := func(ms int, d HTTPData) AuditEvent {
		return AuditEvent{Type: EventHTTP, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, Data: d}
	}
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		ev(1, HTTPData{Method: "CONNECT", Host: "api.github.com", Port: 443, Decision: "allow", Terminated: true}),
		ev(2, HTTPData{Method: "GET", Host: "api.github.com", Port: 443, Path: "/repos/a/b", Decision: "allow"}),
		ev(3, HTTPData{Method: "GET", Host: "api.github.com", Port: 443, Path: "/repos/a/b", Decision: "allow", WouldDeny: []string{"x"}}),
		ev(4, HTTPData{Method: "DELETE", Host: "api.github.com", Port: 443, Path: "/repos/a/b", Decision: "deny", Enforced: true}),
		ev(5, HTTPData{Method: "CONNECT", Host: "pypi.org", Port: 443, Decision: "allow"}),
		runEv(EventRunEnd, 6, "/agents/run-abc"),
	)
	want := []ProxiedDest{
		{Host: "api.github.com", Port: 443, Requests: 4, Denied: 1, WouldDeny: 1, Connects: 1, Paths: []PathUse{
			{Method: "DELETE", Path: "/repos/a/b", Requests: 1, Denied: 1},
			{Method: "GET", Path: "/repos/a/b", Requests: 2, WouldDeny: 1},
		}},
		{Host: "pypi.org", Port: 443, Requests: 1, Connects: 1, Tunnels: 1},
	}
	if !reflect.DeepEqual(tl.Summary.Proxied, want) {
		t.Fatalf("proxied\n got %+v\nwant %+v", tl.Summary.Proxied, want)
	}
}

func l7Runs() []*RunTimeline {
	end := at(100)
	gh := ProxiedDest{Host: "api.github.com", Port: 443, Connects: 2, Paths: []PathUse{
		{Method: "GET", Path: "/repos/a/b/issues/101", Requests: 2},
		{Method: "GET", Path: "/repos/a/b/issues/102", Requests: 1},
		{Method: "GET", Path: "/user", Requests: 1},
		{Method: "POST", Path: "/repos/a/b/issues", Requests: 1},
		{Method: "GET", Path: "/repos/a/b/issues", Requests: 1},
		{Method: "DELETE", Path: "/repos/a/b", Requests: 1, Denied: 1}, // blocked: not learned
		{Method: "GET", Path: "/weird*path", Requests: 1},              // not expressible
	}}
	gh.Requests = gh.Connects + 8
	mcpHost := ProxiedDest{Host: "mcp.test.internal", Port: 443, Connects: 1, Requests: 3, Paths: []PathUse{
		{Method: "POST", Path: "/mcp", Requests: 2},
	}}
	tunnel := ProxiedDest{Host: "pypi.org", Port: 443, Connects: 1, Tunnels: 1, Requests: 1}
	r1 := &RunTimeline{RunID: "r1", Command: []string{"agent"}, StartedAt: at(0), EndedAt: &end, Complete: true,
		Summary: RunSummary{
			Proxied: []ProxiedDest{gh, mcpHost, tunnel},
			MCP: []MCPUse{
				{Server: "github", Method: "register", Name: "npx -y @modelcontextprotocol/server-github@1.2.0", Calls: 1},
				{Server: "github", Method: "tools/call", Name: "search_code", Calls: 3},
				{Server: "github", Method: "tools/call", Name: "delete_repo", Calls: 1, Denied: 1},
				{Server: "github", Method: "resources/read", Name: "repo://a/b/README.md", Calls: 1},
				{Server: "github", Method: "tools/list", Name: "get_file", Calls: 1, WouldDeny: 1}, // drift
				{Server: "shell", Method: "register", Name: "/usr/bin/shell-mcp --root /", Calls: 1, Denied: 1},
				{Server: "mcp.test.internal", Method: "tools/call", Name: "get_file", Calls: 2},
				{Server: "mcp.test.internal", Method: "sampling/createMessage", Calls: 1, Denied: 1},
			},
		}}
	return []*RunTimeline{r1}
}

func TestLearnL7(t *testing.T) {
	runs := l7Runs()
	d := LearnProfile("l7", runs)
	var b strings.Builder
	if err := d.WriteYAML(&b, t0); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	got, err := policy.Parse([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if !reflect.DeepEqual(*got, d.Profile) {
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(d.Profile)
		t.Fatalf("rendered YAML does not round-trip:\n got %s\nwant %s\nexec %#v %#v\n%s", gj, wj, got.Spec.Exec, d.Profile.Spec.Exec, text)
	}

	rules := map[string]policy.EgressRule{}
	for _, r := range got.Spec.Egress.Rules {
		rules[r.Name] = r
	}
	if r := rules["api-github-com-get"]; r.HTTP == nil ||
		!reflect.DeepEqual(r.HTTP.Paths, []string{"/repos/a/b/issues/101", "/repos/a/b/issues/102", "/user"}) {
		t.Errorf("GET rule %+v", r.HTTP)
	}
	// /repos/a/b/issues saw GET and POST: one rule with both methods.
	if r := rules["api-github-com-get-post"]; r.HTTP == nil ||
		!reflect.DeepEqual(r.HTTP.Methods, []string{"GET", "POST"}) || !reflect.DeepEqual(r.HTTP.Paths, []string{"/repos/a/b/issues"}) {
		t.Errorf("GET,POST rule %+v", r.HTTP)
	}
	if r := rules["pypi-org"]; r.HTTP != nil {
		t.Errorf("tunnelled host got paths: %+v", r)
	}
	for _, s := range []string{
		`/repos/a/b/issues/* covers 2 of these paths`,
		`http: { paths: ["*"] }`,
		`api.github.com GET /weird*path`,
		`blocked during learning, not allowed: tool delete_repo`,
		`tool get_file changed its definition`,
		`asked for sampling 1 time`,
		`shell (/usr/bin/shell-mcp --root /): every registration was refused`,
	} {
		if !strings.Contains(text, s) {
			t.Errorf("draft lacks %q:\n%s", s, text)
		}
	}
	if strings.Contains(text, `"DELETE"`) {
		t.Errorf("learned a blocked request:\n%s", text)
	}

	m := got.Spec.MCP
	if m == nil || len(m.Servers) != 2 {
		t.Fatalf("mcp %+v", m)
	}
	gh, remote := m.Servers[0], m.Servers[1]
	if gh.Match.Stdio != "@modelcontextprotocol/server-github" || !reflect.DeepEqual(gh.Tools.Allow, []string{"search_code"}) ||
		!reflect.DeepEqual(gh.Resources.AllowURI, []string{"repo://a/b/README.md"}) || !gh.PinToolDefinitions {
		t.Errorf("local server %+v", gh)
	}
	if remote.Match.FQDN != "mcp.test.internal" || !reflect.DeepEqual(remote.Tools.Allow, []string{"get_file"}) ||
		len(remote.Resources.AllowURI) != 0 {
		t.Errorf("remote server %+v %+v", remote, remote.Resources)
	}

	// Checked against its own runs, the draft allows everything that was
	// let through, decides every path, and denies only what was blocked.
	rep := CheckRuns(compileOne(t, text), runs)
	var viol []string
	for _, f := range rep.Violations {
		viol = append(viol, f.Kind+" "+f.What)
	}
	wantViol := []string{
		"http DELETE api.github.com:443/repos/a/b",
		"http GET api.github.com:443/weird*path",
		"mcp github tools/call delete_repo",
		"mcp mcp.test.internal sampling/createMessage",
		"mcp shell register",
	}
	if !reflect.DeepEqual(viol, wantViol) {
		t.Errorf("violations\n got %q\nwant %q", viol, wantViol)
	}
	var unver []string
	for _, f := range rep.Unverifiable {
		unver = append(unver, f.What)
	}
	if len(unver) != 0 {
		t.Errorf("unverifiable %q", unver)
	}
}

func TestStdioPattern(t *testing.T) {
	for in, want := range map[string]string{
		"npx -y @modelcontextprotocol/server-github@1.2.0": "@modelcontextprotocol/server-github",
		"uvx mcp-server-git --repository .":                "mcp-server-git",
		"python3 -m mcp_server_fetch":                      "mcp_server_fetch",
		"/opt/bin/my-mcp --flag":                           "my-mcp",
		"pnpm dlx some-server@latest":                      "some-server",
		"npx -y":                                           "",
		"node /srv/*.js":                                   "",
	} {
		if got := stdioPattern(in); got != want {
			t.Errorf("stdioPattern(%q) = %q, want %q", in, got, want)
		}
	}
}
