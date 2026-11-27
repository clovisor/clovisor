// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build integration

package integration

import (
	"regexp"
	"strings"
	"testing"
)

var sessionRE = regexp.MustCompile(`agentctl: session ([0-9a-f]+) in run ([0-9a-f]+)`)

// testSessions (milestone 7.3): inside a run under profile, a session
// asking for sub gets only what both allow, and a session inside it no
// more; each has a timeline of its own, nested in its parent's. The run
// itself is unchanged. With cgroup identity, a session's credential is
// refused from another run.
func (e *env) testSessions(t *testing.T, profile, sub, prefix string, cgroup bool) {
	curl := func(label, path string) string {
		return `curl -sS -o /dev/null -w "` + label + ` %{http_code}\n" https://origin.test/` + path
	}
	inner := e.script("session-inner", strings.Join([]string{
		curl("session allowed", "allowed"),
		curl("session headers", "headers"), // sub does not allow it
		curl("session secret", "secret"),   // profile does not
		"/it/bin/agentctl session --profile " + profile + " -- " + curl("nested headers", "headers"),
		"",
	}, "\n"))
	out, id := e.agentRun(profile, prefix+curl("run headers", "headers")+
		"; /it/bin/agentctl session --profile "+sub+" -- "+inner+" 2>/tmp/session.err; cat /tmp/session.err")
	expect(t, out, "run headers 200", "session allowed 200", "session headers 403", "session secret 403", "nested headers 403")
	m := sessionRE.FindAllStringSubmatch(out, -1)
	if len(m) != 2 || m[0][2] != id || m[1][2] != m[0][1] {
		t.Fatalf("want a session in run %s and one in that session:\n%s", id, out)
	}
	a, b := m[0][1], m[1][1]
	expect(t, e.timeline(id), `"children": [`, a)
	expect(t, e.timeline(a), `"session": true`, `"parent": "`+id+`"`, `"/allowed"`, `"/headers"`, `"profile": "`+sub+`"`)
	expect(t, e.timeline(b), `"session": true`, `"parent": "`+a+`"`)
	shown, _, _ := e.sh("/it/bin/agentctl events " + a)
	expect(t, shown, "a session in run "+id)
	if !cgroup {
		return
	}

	// Another run presenting the session's credential is refused: the
	// credential counts only from its own run's cgroup.
	hold := e.script("session-hold", `echo "$https_proxy" > /tmp/session-url
while [ ! -f /tmp/session-done ]; do sleep 0.1; done
`)
	steal := e.script("session-steal", `curl -sS -o /dev/null -w "stolen %{http_connect} %{http_code}\n" -x "$(cat /tmp/session-url)" https://origin.test/allowed 2>/dev/null
echo`)
	out, errOut, err := e.sh(`rm -f /tmp/session-url /tmp/session-done
(/it/bin/agentctl run --profile ` + profile + ` -- /it/bin/agentctl session -- ` + hold + ` >/dev/null 2>&1) &
while [ ! -s /tmp/session-url ]; do sleep 0.1; done
/it/bin/agentctl run --profile ` + profile + ` -- ` + steal + `
touch /tmp/session-done; wait`)
	r := runIDRE.FindStringSubmatch(errOut)
	if err != nil || r == nil {
		t.Fatalf("%v\n%s%s", err, out, errOut)
	}
	expect(t, out, "stolen 403 000")
	expect(t, e.timeline(r[1]), "bad session credential")
}
