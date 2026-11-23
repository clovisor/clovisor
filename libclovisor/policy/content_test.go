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

const contentProfile = `kind: AgentProfile
metadata: { name: cp }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: api, to: { fqdn: ["api.example.com"], ports: [443] }, action: allow }
      - { name: mirror, to: { fqdn: ["mirror.internal"], ports: [80] }, action: allow }
      - { name: vault, to: { fqdn: ["vault.internal"] }, no_terminate: true, action: allow }
      - { name: lan, to: { cidr: ["10.0.0.0/8"] }, action: allow }
      - { name: ssh, to: { fqdn: ["git.example"], ports: [22] }, action: allow }
      - { name: blocked, to: { fqdn: ["evil.example"] }, action: deny, message: "no" }
  content:
    - { name: aws-keys, regex: "AKIA[0-9A-Z]{16}", action: deny }
    - { name: tokens, regex: "tok_[a-z0-9]{8}", action: redact }
    - { name: corp, regex: "\\.corp\\.internal", action: tag-and-log }
    - { name: only-api, regex: "SECRET-[0-9]+", action: deny, message: "No secrets to the API.", to: { fqdn: ["api.example.com"] } }
`

func compileContent(t *testing.T, doc string, mode string) *CompiledProfile {
	t.Helper()
	if mode != "" {
		doc = strings.Replace(doc, "mode: enforce", "mode: "+mode, 1)
	}
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c, diags := Compile(Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	return c.Profiles[0]
}

func TestContentCompile(t *testing.T) {
	p, _ := Parse([]byte(contentProfile))
	c, diags := Compile(Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	post := map[string]DestPosture{}
	for _, d := range c.Posture {
		post[d.Dest] = d
	}
	// Content rules need the bodies: the named hosts are terminated, port
	// 80 stays plaintext, no_terminate and denied hosts are left alone.
	for dest, want := range map[string]string{
		"api.example.com": PostureTerminate,
		"mirror.internal": PosturePlaintext,
		"vault.internal":  PosturePassthrough,
		"evil.example":    PosturePassthrough,
		"git.example":     PosturePassthrough,
	} {
		if post[dest].Posture != want {
			t.Errorf("%s: %q, want %q (%v)", dest, post[dest].Posture, want, post[dest].Why)
		}
	}
	if !strings.Contains(strings.Join(post["api.example.com"].Why, ","), "cp (content aws-keys)") {
		t.Errorf("why: %v", post["api.example.com"].Why)
	}
	var notes string
	for _, pl := range c.Profiles[0].Placements {
		if pl.Rule == "content/aws-keys" {
			notes = strings.Join(pl.Notes, "\n")
		}
	}
	for _, want := range []string{"applies to api.example.com, mirror.internal", "vault.internal (no_terminate)",
		"destinations allowed by address (cidr)", "git.example (allowed on no HTTP or TLS port)", "responses are not checked"} {
		if !strings.Contains(notes, want) {
			t.Errorf("receipt lacks %q:\n%s", want, notes)
		}
	}

	for _, pl := range c.Profiles[0].Placements {
		if pl.Rule == "api" && strings.Join(pl.Notes, ",") != "terminated for content rules: see posture" {
			t.Errorf("api placement: %v", pl.Notes)
		}
	}
	for doc, want := range map[string]string{
		`{ name: x, regex: "(", action: deny }`:                                   "regex: error parsing regexp",
		`{ name: x, regex: "a*", action: deny }`:                                  "matches the empty string",
		`{ name: x, regex: "a", action: block }`:                                  "action must be deny, redact or tag-and-log",
		`{ name: x, regex: "a", action: redact, message: "m" }`:                   "message: is only valid with action deny",
		`{ name: x, regex: "a", action: deny, to: { fqdn: ["*"] } }`:              `targets fqdn "*"`,
		`{ name: x, regex: "a", action: deny, to: { fqdn: ["vault.internal"] } }`: "vault.internal must be terminated for cp (content x), but cp/vault asserts no_terminate",
	} {
		bad := strings.Replace(contentProfile, `{ name: aws-keys, regex: "AKIA[0-9A-Z]{16}", action: deny }`, doc, 1)
		p, _ := Parse([]byte(bad))
		_, diags := Compile(Options{Linux: true}, p)
		var b strings.Builder
		for _, d := range diags {
			b.WriteString(d.Error() + "\n")
		}
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s: want %q, got:\n%s", doc, want, b.String())
		}
	}
	p, _ = Parse([]byte(strings.Replace(contentProfile, "  content:\n", "      - { name: r, to: { fqdn: [\"a.example\"] }, action: redact }\n  content:\n", 1)))
	if _, diags := Compile(Options{Linux: true}, p); len(diags) == 0 || !strings.Contains(diags[0].Msg, "redact is an action for content rules") {
		t.Errorf("redact egress rule: %v", diags)
	}
	unb := compileContent(t, strings.Replace(contentProfile, `tok_[a-z0-9]{8}`, `tok_[a-z0-9]+`, 1), "")
	found := false
	for _, pl := range unb.Placements {
		if pl.Rule == "content/tokens" && strings.Contains(strings.Join(pl.Notes, " "), "unbounded repetition") {
			found = true
		}
	}
	if !found {
		t.Error("unbounded repetition not noted")
	}
}

func TestScanContent(t *testing.T) {
	cp := compileContent(t, contentProfile, "")
	eff := &Effective{Layers: []Layer{{Profile: cp}}}
	if !eff.InspectsContent("API.example.com.") || !eff.InspectsContent("mirror.internal") || eff.InspectsContent("vault.internal") {
		t.Error("InspectsContent scope")
	}

	body := []byte(`{"a":"tok_abcd1234 and tok_zzzz9999","h":"x.corp.internal"}`)
	v := eff.ScanContent("api.example.com", "body", body, true)
	if v.Denied != nil || !v.Redacts() || len(v.Hits) != 2 {
		t.Fatalf("verdict: %+v", v)
	}
	out := v.Redact(body)
	if len(out) != len(body) || strings.Contains(string(out), "tok_") || !strings.Contains(string(out), "************ and ************") {
		t.Errorf("redacted: %s", out)
	}
	if string(body) == string(out) {
		t.Error("Redact changed its input in place or did nothing")
	}

	v = eff.ScanContent("api.example.com", "body", []byte("key AKIAABCDEFGHIJKLMNOP"), true)
	if v.Denied == nil || v.Denied.Rule != "aws-keys" || !strings.Contains(v.Message, "matches content rule aws-keys of profile cp") ||
		strings.Contains(v.Message, "AKIA") {
		t.Errorf("deny: %+v", v)
	}
	// Scoped to api.example.com: mirror.internal is not covered by it.
	if v := eff.ScanContent("mirror.internal", "body", []byte("SECRET-42"), true); v.Matched() {
		t.Errorf("scoped rule applied elsewhere: %+v", v)
	}
	if v := eff.ScanContent("api.example.com", "body", []byte("SECRET-42"), true); v.Message != "No secrets to the API." {
		t.Errorf("own message: %+v", v)
	}
	// The query string cannot be redacted: redact refuses there.
	v = eff.ScanContent("api.example.com", "query string", []byte("q=tok_abcd1234"), false)
	if v.Denied == nil || !strings.Contains(v.Message, "its query string matches content rule tokens") || !strings.Contains(v.Message, "only in a request body") {
		t.Errorf("query redact: %+v", v)
	}

	// Audit mode: hits recorded, nothing refused or changed.
	audit := &Effective{Layers: []Layer{{Profile: compileContent(t, contentProfile, "audit")}}}
	v = audit.ScanContent("api.example.com", "body", []byte("AKIAABCDEFGHIJKLMNOP tok_abcd1234"), true)
	if v.Denied != nil || v.Redacts() || len(v.Hits) != 2 || v.Hits[0].Enforced {
		t.Errorf("audit: %+v", v)
	}

	// Layers add up: a clamp's rule applies under the granted profile's.
	clamp := compileContent(t, strings.NewReplacer("name: cp", "name: clamp", `"AKIA[0-9A-Z]{16}"`, `"PRIVATE KEY"`).Replace(contentProfile), "")
	both := eff.With(Layer{Profile: clamp})
	if v := both.ScanContent("api.example.com", "body", []byte("-----BEGIN PRIVATE KEY-----"), true); v.Denied == nil || v.Denied.Layer != "clamp" {
		t.Errorf("clamp layer: %+v", v)
	}
}
