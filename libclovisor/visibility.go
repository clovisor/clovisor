// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// Visibility report (milestone 6.5): per destination a run reached, how
// much of what it did there the node saw. An audit that lists only what
// it saw reads as complete; this says where it was not.

// Visibility levels, best first.
const (
	SeenRequests  = "requests"  // the proxy saw each request: plain HTTP, or terminated TLS
	SeenPlaintext = "plaintext" // requests read from the process's TLS plaintext (uprobes)
	SeenName      = "name"      // only the host: a CONNECT authority or SNI, tunnelled
	SeenAddress   = "address"   // only the address the kernel saw connected to
)

// DestVisibility is how one destination of a run was seen.
type DestVisibility struct {
	Host string `json:"host"` // a name, or an IP where no name was seen
	Port uint16 `json:"port"`
	// Proto is tcp or udp.
	Proto string `json:"proto"`
	Seen  string `json:"seen"`
	// By lists what saw it: proxy, tls-plaintext, kernel.
	By []string `json:"by"`
	// Why says what kept it from a better level; empty at requests.
	Why string `json:"why,omitempty"`
}

// RunVisibility derives the report from a timeline's summary and policy.
func RunVisibility(tl *RunTimeline) []DestVisibility {
	s := &tl.Summary
	observes := false
	if tl.Policy != nil {
		for _, l := range tl.Policy.Layers {
			observes = observes || l.Observe
		}
	}
	// TLS plaintext by host and port: a host without a port is 443's.
	plain := map[string]bool{}
	for _, u := range s.TLS {
		plain[hostPortKey(u.Host, 443)] = true
	}
	var unseen []string // binaries whose own TLS was not probed
	for _, p := range s.TLSPrograms {
		if !p.Probed {
			unseen = append(unseen, p.Path+" ("+p.Stack+")")
		}
	}

	var out []DestVisibility
	have := map[string]bool{}
	for _, p := range s.Proxied {
		k := hostPortKey(p.Host, p.Port)
		have[k] = true
		v := DestVisibility{Host: p.Host, Port: p.Port, Proto: "tcp", By: []string{"proxy"}}
		switch {
		case p.Requests-p.Connects > 0 || len(p.Paths) > 0:
			v.Seen = SeenRequests
		case p.Tunnels == 0 && p.Denied > 0 && p.Denied >= p.Connects:
			v.Seen, v.Why = SeenName, "refused by name: nothing went through"
		case plain[k]:
			v.Seen, v.By = SeenPlaintext, []string{"proxy", "tls-plaintext"}
			v.Why = "tunnelled without termination; requests read from TLS plaintext"
		default:
			v.Seen, v.Why = SeenName, nameWhy(observes, unseen)
		}
		out = append(out, v)
	}
	// Plaintext from processes whose connections the proxy did not see
	// (explicit mode, a client ignoring the proxy).
	for _, u := range s.TLS {
		k := hostPortKey(u.Host, 443)
		if have[k] {
			continue
		}
		have[k] = true
		h, port := splitHostPort(u.Host, 443)
		out = append(out, DestVisibility{Host: h, Port: port, Proto: "tcp", Seen: SeenPlaintext, By: []string{"tls-plaintext", "kernel"},
			Why: "not through the proxy; requests read from TLS plaintext"})
	}
	// Connections only the kernel saw.
	for _, d := range s.Destinations {
		proto := strings.ToLower(d.Proto)
		if proto == "udp" && d.Port == 53 {
			continue // DNS: recorded as lookups
		}
		host := d.IP
		if len(d.Names) > 0 {
			host = d.Names[0]
		}
		if have[hostPortKey(host, d.Port)] || have[hostPortKey(d.IP, d.Port)] {
			continue
		}
		have[hostPortKey(host, d.Port)] = true
		why := "connected directly, not through the proxy: only the address was seen"
		if proto == "udp" {
			why = "UDP: only the address was seen"
		}
		if len(d.Names) > 0 {
			why += " (the name is from the run's DNS lookups)"
		}
		out = append(out, DestVisibility{Host: host, Port: d.Port, Proto: proto, Seen: SeenAddress, By: []string{"kernel"}, Why: why})
	}
	rank := map[string]int{SeenAddress: 0, SeenName: 1, SeenPlaintext: 2, SeenRequests: 3}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank[a.Seen] != rank[b.Seen] {
			return rank[a.Seen] < rank[b.Seen] // the least seen first
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
	return out
}

// nameWhy says why a tunnelled destination was seen by name only.
func nameWhy(observes bool, unseen []string) string {
	why := "tunnelled without termination; "
	switch {
	case !observes:
		return why + "the run's profile does not ask for TLS plaintext (observe.tls_plaintext)"
	case len(unseen) > 0:
		if len(unseen) > 3 {
			unseen = append(unseen[:3], "...")
		}
		return why + "TLS plaintext was asked for, but not visible in " + strings.Join(unseen, ", ")
	}
	return why + "TLS plaintext was asked for, but none was seen for this host (a client whose TLS is not probed, or a node without -uprobes)"
}

func hostPortKey(host string, port uint16) string {
	h, p := splitHostPort(host, port)
	return strings.ToLower(h) + ":" + strconv.Itoa(int(p))
}

// splitHostPort splits "host:port", or returns host with def.
func splitHostPort(host string, def uint16) (string, uint16) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			return h, uint16(n)
		}
	}
	return host, def
}
