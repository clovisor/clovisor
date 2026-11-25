// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"bytes"
	"strings"
	"testing"
)

// The receipt says, per destination, what audit records: requests where
// it is terminated; the name only where it is not, with TLS plaintext for
// the profiles that ask, on a node that probes (milestone 6.5).
func TestPostureVisibility(t *testing.T) {
	docs := []string{`kind: AgentProfile
metadata: { name: coder }
spec:
  mode: audit
  egress:
    default: deny
    rules:
      - { name: gh, to: { fqdn: [api.github.com] }, http: { methods: [GET] }, action: allow }
      - { name: npm, to: { fqdn: [registry.npmjs.org] }, action: allow }
  observe: { tls_plaintext: true }
`, `kind: AgentProfile
metadata: { name: ci }
spec:
  mode: audit
  egress:
    default: deny
    rules:
      - { name: npm, to: { fqdn: [registry.npmjs.org] }, action: allow }
      - { name: pypi, to: { fqdn: [pypi.org] }, action: allow }
`}
	compile := func(o Options) *Compiled {
		var ps []*AgentProfile
		for _, d := range docs {
			p, err := Parse([]byte(d))
			if err != nil {
				t.Fatal(err)
			}
			ps = append(ps, p)
		}
		c, diags := Compile(o, ps...)
		if len(diags) > 0 {
			t.Fatal(diags)
		}
		return c
	}
	vis := func(c *Compiled) map[string]string {
		out := map[string]string{}
		for _, d := range c.Posture {
			out[d.Dest] = d.Visibility
		}
		return out
	}
	v := vis(compile(Options{Linux: true, Uprobes: true}))
	if v["api.github.com"] != "requests" || v["pypi.org"] != "name only" ||
		v["registry.npmjs.org"] != "name; for coder also requests from TLS plaintext, where the client's TLS is probed" {
		t.Errorf("with uprobes: %v", v)
	}
	if v := vis(compile(Options{Linux: true})); !strings.Contains(v["registry.npmjs.org"], "needs the node agent's -uprobes") {
		t.Errorf("without uprobes: %v", v)
	}
	var b bytes.Buffer
	compile(Options{Linux: true, Uprobes: true}).WriteReceipt(&b)
	if !strings.Contains(b.String(), "AUDIT SEES") || !strings.Contains(b.String(), "by address only") {
		t.Errorf("receipt:\n%s", b.String())
	}
}
