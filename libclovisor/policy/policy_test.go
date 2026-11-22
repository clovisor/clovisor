// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"net/netip"
	"strings"
	"testing"
)

const goodProfile = `
kind: AgentProfile
metadata: { name: research-agent }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: no-admin
        to: { fqdn: ["api.github.com"], ports: [443] }
        http: { paths: ["/admin*"] }
        action: deny
        message: "Admin endpoints are off limits."
      - name: github-api
        to: { fqdn: ["api.github.com"], ports: [443] }
        http: { methods: [GET], paths: ["/repos/*"] }
        action: allow
      - name: github
        to: { fqdn: ["github.com", "*.githubusercontent.com"] }
        action: allow
      - name: plain-mirror
        to: { fqdn: ["mirror.internal"], ports: [80] }
        http: { methods: [GET] }
        action: allow
      - name: payments
        to: { fqdn: ["billing.internal"] }
        no_terminate: true
        action: allow
      - name: no-external-llm
        to: { fqdn: ["api.openai.com"] }
        action: deny
        message: "External LLM APIs aren't permitted here. Use models.internal instead."
      - name: git-ssh
        to: { cidr: ["140.82.112.0/20"], ports: [22] }
        action: allow
      - name: telemetry
        to: { fqdn: ["telemetry.internal"] }
        action: tag-and-log
  exec:
    default: deny
    audit_only: true
    allow:
      - path: /usr/bin/git
      - path: /usr/bin/python3
        note: "interpreter"
  mcp:
    default: deny
    servers:
      - name: github
        match: { fqdn: "mcp.github.internal" }
        tools: { allow: ["search_*"], deny: ["delete_*"] }
        pin_tool_definitions: true
      - name: filesystem
        match: { stdio: "@modelcontextprotocol/server-filesystem" }
        tools: { allow: ["read_file"] }
    sampling: { action: deny, message: "MCP servers may not drive the model." }
`

func mustCompile(t *testing.T, opts Options, docs ...string) *Compiled {
	t.Helper()
	var ps []*AgentProfile
	for _, d := range docs {
		p, err := Parse([]byte(d))
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	c, diags := Compile(opts, ps...)
	if len(diags) > 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	return c
}

func compileErrors(t *testing.T, doc string) string {
	t.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	_, diags := Compile(Options{Linux: true}, p)
	var s []string
	for _, d := range diags {
		s = append(s, d.Error())
	}
	return strings.Join(s, "\n")
}

func TestParseStrict(t *testing.T) {
	if _, err := Parse([]byte("kind: AgentProfile\nmetadata: {name: x}\nspec: {mode: audit, egres: {}}\n")); err == nil ||
		!strings.Contains(err.Error(), "egres") {
		t.Fatalf("misspelt field accepted: %v", err)
	}
	if _, err := Parse([]byte("kind: AgentProfile\n---\nkind: AgentProfile\n")); err == nil {
		t.Fatal("two documents accepted")
	}
	if _, err := Parse([]byte("")); err == nil {
		t.Fatal("empty profile accepted")
	}
}

func TestVersionIgnoresFormatting(t *testing.T) {
	a, _ := Parse([]byte(goodProfile))
	b, _ := Parse([]byte("# a comment\n" + strings.ReplaceAll(goodProfile, "\n\n", "\n")))
	if a.Version() != b.Version() {
		t.Fatal("comments changed the version")
	}
	c, _ := Parse([]byte(strings.Replace(goodProfile, "mode: enforce", "mode: audit", 1)))
	if a.Version() == c.Version() {
		t.Fatal("a content change kept the version")
	}
	if !strings.HasPrefix(a.Version(), "sha256:") || len(a.ShortVersion()) != 19 {
		t.Fatalf("bad version format %q %q", a.Version(), a.ShortVersion())
	}
}

func TestDecide(t *testing.T) {
	cp := mustCompile(t, Options{Linux: true}, goodProfile).Profile("research-agent")
	ip := netip.MustParseAddr
	cases := []struct {
		name string
		req  Request
		want string // action, or "deferred"
		rule string
	}{
		{"connect to a host with http rules defers", Request{Host: "api.github.com", Port: 443}, "deferred", "no-admin"},
		{"first match wins: deny before allow", Request{Host: "api.github.com", Port: 443, Phase: PhaseRequest, Method: "GET", Path: "/admin/x"}, ActionDeny, "no-admin"},
		{"method and path glob", Request{Host: "api.github.com", Port: 443, Phase: PhaseRequest, Method: "GET", Path: "/repos/o/r/issues"}, ActionAllow, "github-api"},
		{"wrong method falls to default", Request{Host: "api.github.com", Port: 443, Phase: PhaseRequest, Method: "POST", Path: "/repos/o/r"}, ActionDeny, ""},
		{"wrong port", Request{Host: "api.github.com", Port: 80, Phase: PhaseRequest, Method: "GET", Path: "/repos/x"}, ActionDeny, ""},
		{"exact host, any port", Request{Host: "GitHub.com.", Port: 22}, ActionAllow, "github"},
		{"wildcard: one label", Request{Host: "raw.githubusercontent.com", Port: 443}, ActionAllow, "github"},
		{"wildcard: not two labels", Request{Host: "a.b.githubusercontent.com", Port: 443}, ActionDeny, ""},
		{"wildcard: not the apex", Request{Host: "githubusercontent.com", Port: 443}, ActionDeny, ""},
		{"deny rule", Request{Host: "api.openai.com", Port: 443}, ActionDeny, "no-external-llm"},
		{"cidr matches an IP literal", Request{IP: ip("140.82.113.4"), Port: 22}, ActionAllow, "git-ssh"},
		{"cidr: other port", Request{IP: ip("140.82.113.4"), Port: 443}, ActionDeny, ""},
		{"cidr never matches a name", Request{Host: "lb.github.com", Port: 22}, ActionDeny, ""},
		{"tag-and-log", Request{Host: "telemetry.internal", Port: 443}, ActionTagAndLog, "telemetry"},
		{"unknown host", Request{Host: "evil.example", Port: 443}, ActionDeny, ""},
	}
	for _, tc := range cases {
		d := cp.Decide(tc.req)
		got := d.Action
		if d.Deferred {
			got = "deferred"
		}
		if got != tc.want || d.Rule != tc.rule {
			t.Errorf("%s: got %s/%q, want %s/%q", tc.name, got, d.Rule, tc.want, tc.rule)
		}
		if got == ActionDeny && d.Message == "" {
			t.Errorf("%s: deny without narration", tc.name)
		}
	}
	d := cp.Decide(Request{Host: "evil.example", Port: 443})
	if d.Message != "No rule in profile research-agent allows evil.example:443." {
		t.Errorf("default narration %q", d.Message)
	}
	d = cp.Decide(Request{Host: "api.openai.com", Port: 443})
	if !strings.Contains(d.Message, "Use models.internal instead") {
		t.Errorf("rule narration %q", d.Message)
	}

	if !cp.DecideExec("/usr/bin/git").Allowed || cp.DecideExec("/tmp/git").Allowed {
		t.Error("exec decisions wrong")
	}
}

func TestPosture(t *testing.T) {
	other := `
kind: AgentProfile
metadata: { name: light-agent }
spec:
  mode: audit
  egress:
    default: deny
    rules:
      - { name: gh, to: { fqdn: ["api.github.com"] }, action: allow }
`
	c := mustCompile(t, Options{Linux: true}, goodProfile, other)
	got := map[string]DestPosture{}
	for _, d := range c.Posture {
		got[d.Dest] = d
	}
	for dest, want := range map[string]string{
		"api.github.com":      PostureTerminate,
		"mirror.internal":     PosturePlaintext,
		"github.com":          PosturePassthrough,
		"billing.internal":    PosturePassthrough,
		"mcp.github.internal": PostureTerminate,
	} {
		if got[dest].Posture != want {
			t.Errorf("%s: posture %q, want %q (%v)", dest, got[dest].Posture, want, got[dest].Why)
		}
	}
	if o := got["api.github.com"].Others; len(o) != 1 || o[0] != "light-agent" {
		t.Errorf("node-wide consequence not reported: %v", o)
	}
}

func TestCompileErrors(t *testing.T) {
	// The §7.3 example: everything Phase 2 cannot enforce must be refused,
	// each naming what would enforce it.
	doc := `
kind: AgentProfile
metadata: { name: research-agent }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: model-endpoints
        to: { fqdn: ["*.inference.internal"] }
        model: { allow: ["claude-opus-5"] }
        budget: { tokens: 500000, cost_usd: 25 }
        action: allow
      - name: package-registries
        to: { fqdn: ["pypi.org"] }
        action: ask
        ask: { timeout: 5m, on_timeout: deny }
      - name: payments-api
        to: { fqdn: ["billing.internal"] }
        no_terminate: true
        action: allow
      - name: billing-paths
        to: { fqdn: ["billing.internal"] }
        http: { paths: ["/invoices/*"] }
        action: allow
      - name: quiet-deny
        to: { fqdn: ["api.openai.com"] }
        action: deny
      - name: ssh-paths
        to: { cidr: ["10.0.0.0/8"] }
        http: { paths: ["/x"] }
        action: allow
      - name: bad-host
        to: { fqdn: ["Bad_Host.example"] }
        action: allow
  exec:
    default: deny
    allow:
      - path: git
      - path: /usr/local/bin/custom-tool
        hash: sha256:ab12
  content:
    - { name: aws-keys, regex: "AKIA[0-9A-Z]{16}", action: deny }
  limits:
    connections_per_min: 120
`
	errs := compileErrors(t, doc)
	for _, want := range []string{
		"model-endpoints): model cannot be enforced yet: it needs model allow-lists with budgets (Phase 5)",
		"model-endpoints): budget cannot be enforced yet",
		"package-registries): action ask cannot be enforced yet: it needs the approval UI (Phase 5)",
		"billing.internal must be terminated for research-agent (billing-paths: http), but research-agent/payments-api asserts no_terminate",
		"quiet-deny): a deny rule needs a message",
		"ssh-paths): http: needs a hostname destination",
		`bad-host): fqdn "Bad_Host.example" must be a lowercase hostname`,
		"exec: exec rules cannot be enforced by this deployment",
		`exec.allow[0]: path "git" must be absolute`,
		"exec.allow[1]: exec hash cannot be enforced yet: it needs IMA hash verification (Phase 4)",
		"spec.content: content cannot be enforced yet",
		"spec.limits: limits cannot be enforced yet",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing diagnostic %q", want)
		}
	}
	if t.Failed() {
		t.Log(errs)
	}

	if e := compileErrors(t, strings.Replace(goodProfile, "default: deny\n    rules:", "default: maybe\n    rules:", 1)); !strings.Contains(e, "egress.default: must be allow or deny") {
		t.Errorf("bad default accepted: %s", e)
	}
	if e := compileErrors(t, strings.Replace(goodProfile, "mode: enforce", "mode: ask", 1)); !strings.Contains(e, "mode ask cannot be enforced yet") {
		t.Errorf("mode ask accepted: %s", e)
	}
	wild := strings.Replace(goodProfile, `fqdn: ["mirror.internal"], ports: [80]`, `fqdn: ["*.internal"]`, 1)
	if e := compileErrors(t, wild); !strings.Contains(e, "*.internal must be terminated") || !strings.Contains(e, "payments asserts no_terminate") {
		t.Errorf("wildcard/no_terminate overlap not caught: %s", e)
	}
	// In audit mode exec rules are fine without audit_only: nothing is enforced.
	audit := strings.Replace(strings.Replace(goodProfile, "mode: enforce", "mode: audit", 1), "    audit_only: true\n", "", 1)
	if e := compileErrors(t, audit); e != "" {
		t.Errorf("audit-mode exec rejected: %s", e)
	}
}

func TestReceipt(t *testing.T) {
	c := mustCompile(t, Options{Linux: true}, goodProfile)
	var b strings.Builder
	if err := c.WriteReceipt(&b); err != nil {
		t.Fatal(err)
	}
	r := b.String()
	for _, want := range []string{
		"Deployment  explicit-proxy on Linux",
		"enforcement-grade",
		"Profile     research-agent@sha256:",
		"github-api",
		"ext_proc (method and path)",
		"not terminated: domain-fronting exposed",
		"exec/git",
		"not enforced until BPF LSM (Phase 4)",
		"local MCP gateway (@modelcontextprotocol/server-filesystem)",
		"tools/list pinned",
		"api.github.com",
		"terminate",
		"billing.internal",
		"no_terminate: research-agent/payments",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("receipt lacks %q", want)
		}
	}
	if t.Failed() {
		t.Log(r)
	}

	c = mustCompile(t, Options{}, goodProfile)
	b.Reset()
	c.WriteReceipt(&b)
	if !strings.Contains(b.String(), "a claim, not enforcement-grade") {
		t.Error("non-Linux receipt does not say identity is a claim")
	}
}

func TestGlob(t *testing.T) {
	for _, tc := range []struct {
		p, s string
		want bool
	}{
		{"/repos/*", "/repos/a/b", true},
		{"/repos/*", "/repo", false},
		{"/a/*/c", "/a/b/x/c", true},
		{"/a/*/c", "/a/b/x/d", false},
		{"create_*", "create_issue", true},
		{"*_repo*", "delete_repository", true},
		{"exact", "exact", true},
		{"*", "", true},
	} {
		if glob(tc.p, tc.s) != tc.want {
			t.Errorf("glob(%q, %q) != %v", tc.p, tc.s, tc.want)
		}
	}
}

func TestDecideName(t *testing.T) {
	p, err := Parse([]byte(`kind: AgentProfile
metadata: { name: n }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: no-ssh, to: { fqdn: ["git.example"], ports: [22] }, action: deny, message: "No SSH." }
      - { name: git, to: { fqdn: ["git.example"], ports: [443] }, action: allow }
      - { name: only-ssh, to: { fqdn: ["ssh.example"], ports: [22] }, action: deny, message: "No SSH here." }
      - { name: api, to: { fqdn: ["*.api.example"] }, http: { paths: ["/v1/*"] }, action: allow }
      - { name: lan, to: { cidr: ["10.0.0.0/8"] }, action: allow }
`))
	if err != nil {
		t.Fatal(err)
	}
	c, diags := Compile(Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	cp := c.Profiles[0]
	for name, want := range map[string]string{
		"git.example":     "git", // denied on 22, allowed on 443
		"GIT.example.":    "git",
		"eu.api.example":  "api", // a path rule: resolvable, decided per request
		"ssh.example":     "",    // only a deny rule and the default
		"evil.example":    "",
		"10.in-addr.arpa": "", // cidr rules do not make names resolvable
		"x.git.example":   "",
	} {
		d := cp.DecideName(name)
		if (want != "") != d.Allowed() || (want != "" && d.Rule != want) {
			t.Errorf("%s: %+v, want rule %q", name, d, want)
		}
	}
	if d := cp.DecideName("ssh.example"); d.Message != "No SSH here." {
		t.Errorf("message from the deciding rule: %q", d.Message)
	}
	if d := cp.DecideName("evil.example"); !strings.Contains(d.Message, "not resolved") {
		t.Errorf("default message: %q", d.Message)
	}
	// Across layers: an audit layer's deny is only recorded.
	ap, err := Parse([]byte("kind: AgentProfile\nmetadata: { name: a }\nspec:\n  mode: audit\n  egress: { default: deny }\n"))
	if err != nil {
		t.Fatal(err)
	}
	audit, diags := Compile(Options{Linux: true}, ap)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	e := &Effective{Layers: []Layer{{Profile: cp}, {Profile: audit.Profiles[0]}}}
	if d := e.DecideName("git.example"); !d.Allowed() || len(d.WouldDeny) != 1 {
		t.Errorf("layers: %+v", d)
	}
	if d := e.DecideName("evil.example"); d.Allowed() || !d.Enforced {
		t.Errorf("enforced deny: %+v", d)
	}
}
