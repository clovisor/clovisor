// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"strings"
	"testing"
)

// Each destination is reported at the best level anything saw it, the
// least seen first, with what kept it from better.
func TestRunVisibility(t *testing.T) {
	tl := &RunTimeline{
		Policy: &RunPolicy{Layers: []PolicyLayer{{Profile: "p"}, {Profile: "obs", Observe: true}}},
		Summary: RunSummary{
			Proxied: []ProxiedDest{
				{Host: "api.github.com", Port: 443, Requests: 3, Connects: 1, Paths: []PathUse{{Method: "GET", Path: "/a", Requests: 2}}},
				{Host: "registry.npmjs.org", Port: 443, Requests: 2, Connects: 2, Tunnels: 2},
				{Host: "pinned.example.com", Port: 443, Requests: 1, Connects: 1, Tunnels: 1},
				{Host: "evil.example.com", Port: 443, Requests: 1, Connects: 1, Denied: 1},
				{Host: "example.org", Port: 80, Requests: 1, Paths: []PathUse{{Method: "GET", Path: "/", Requests: 1}}},
			},
			TLS: []TLSUse{
				{Host: "registry.npmjs.org", Method: "GET", Path: "/left-pad", Requests: 2},
				{Host: "direct.example.com:8443", Method: "GET", Path: "/x", Requests: 1},
			},
			TLSPrograms: []TLSProgram{{Path: "/usr/bin/claude", Stack: "Bun's BoringSSL", Reason: "r"}},
			Destinations: []Destination{
				{Proto: "TCP", IP: "10.0.0.5", Port: 22, Count: 1, Names: []string{"git.internal"}},
				{Proto: "TCP", IP: "192.0.2.9", Port: 9000, Count: 1},
				{Proto: "UDP", IP: "127.0.0.53", Port: 53, Count: 4},
				{Proto: "UDP", IP: "192.0.2.10", Port: 5000, Count: 1},
				{Proto: "TCP", IP: "198.51.100.1", Port: 8443, Count: 1, Names: []string{"direct.example.com"}},
			},
		}}
	got := map[string]DestVisibility{}
	var order []string
	for _, v := range RunVisibility(tl) {
		k := v.Host + ":" + itoa(int64(v.Port)) + "/" + v.Proto
		got[k] = v
		order = append(order, v.Seen)
	}
	for k, want := range map[string]struct{ seen, why string }{
		"api.github.com:443/tcp":      {SeenRequests, ""},
		"example.org:80/tcp":          {SeenRequests, ""},
		"registry.npmjs.org:443/tcp":  {SeenPlaintext, "requests read from TLS plaintext"},
		"pinned.example.com:443/tcp":  {SeenName, "not visible in /usr/bin/claude (Bun's BoringSSL)"},
		"evil.example.com:443/tcp":    {SeenName, "refused by name"},
		"direct.example.com:8443/tcp": {SeenPlaintext, "not through the proxy"},
		"git.internal:22/tcp":         {SeenAddress, "name is from the run's DNS lookups"},
		"192.0.2.9:9000/tcp":          {SeenAddress, "connected directly"},
		"192.0.2.10:5000/udp":         {SeenAddress, "UDP"},
	} {
		v, ok := got[k]
		if !ok || v.Seen != want.seen || !strings.Contains(v.Why, want.why) {
			t.Errorf("%s: %+v, want %s %q", k, v, want.seen, want.why)
		}
	}
	if len(got) != 9 {
		t.Errorf("%d destinations (DNS listed?): %v", len(got), got)
	}
	if order[0] != SeenAddress || order[len(order)-1] != SeenRequests {
		t.Errorf("not least seen first: %v", order)
	}

	// A run that does not ask for TLS plaintext is told so.
	tl.Policy.Layers = tl.Policy.Layers[:1]
	for _, v := range RunVisibility(tl) {
		if v.Host == "pinned.example.com" && !strings.Contains(v.Why, "does not ask for TLS plaintext") {
			t.Errorf("not observing: %+v", v)
		}
	}
}
