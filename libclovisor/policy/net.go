// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"net/netip"
	"sort"
)

// UDP is the udp block (milestone 4.7): UDP destinations, besides DNS,
// that the run may send to. In transparent mode UDP is refused otherwise,
// since it carries no name the proxy could check (design §6.8). Each
// entry is an exact ip:port ([ipv6]:port).
//
// In a profile it says what the agent needs; in a ceiling, what the
// operator lets runs under it have. A run gets what both allow.
type UDP struct {
	Allow []string `yaml:"allow" json:"allow"`
}

// ICMP is the icmp block (milestone 4.7): destinations the run may ping
// (echo requests only), as addresses or prefixes. Like udp, a profile
// asks and a ceiling permits. Ping must use ICMP datagram sockets (the
// unprivileged ping, net.ipv4.ping_group_range): raw sockets stay
// refused.
type ICMP struct {
	Allow []string `yaml:"allow" json:"allow"`
}

// MaxRunUDP and MaxRunICMP match MAX_RUN_UDP and MAX_RUN_ICMP in
// agent_audit.c.
const (
	MaxRunUDP  = 8
	MaxRunICMP = 8
)

// NetGrant is UDP and ICMP a ceiling permits, or a run has.
type NetGrant struct {
	UDP  []netip.AddrPort
	ICMP []netip.Prefix
}

// Empty reports whether the grant allows nothing.
func (g NetGrant) Empty() bool { return len(g.UDP) == 0 && len(g.ICMP) == 0 }

// parseNet validates udp and icmp blocks; errf reports problems at where.
func parseNet(u *UDP, i *ICMP, errf func(where, format string, a ...interface{})) NetGrant {
	var g NetGrant
	if u != nil {
		if len(u.Allow) > MaxRunUDP {
			errf("udp.allow", "at most %d entries", MaxRunUDP)
		}
		for n, s := range u.Allow {
			ap, err := netip.ParseAddrPort(s)
			switch {
			case err != nil:
				errf(fmt.Sprintf("udp.allow[%d]", n), "%q is not ip:port ([ipv6]:port): %v", s, err)
				continue
			case ap.Port() == 0 || ap.Addr().IsUnspecified():
				errf(fmt.Sprintf("udp.allow[%d]", n), "%q: name one address and port", s)
				continue
			case ap.Port() == 53:
				errf(fmt.Sprintf("udp.allow[%d]", n), "%q: DNS always goes to the node's resolver", s)
				continue
			}
			g.UDP = append(g.UDP, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
	}
	if i != nil {
		if len(i.Allow) > MaxRunICMP {
			errf("icmp.allow", "at most %d entries", MaxRunICMP)
		}
		for n, s := range i.Allow {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				a, aerr := netip.ParseAddr(s)
				if aerr != nil {
					errf(fmt.Sprintf("icmp.allow[%d]", n), "%q is not an address or prefix", s)
					continue
				}
				p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			}
			if p.Addr().Is4In6() {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			g.ICMP = append(g.ICMP, p.Masked())
		}
	}
	return g
}

// Intersect is what both grants allow.
func (g NetGrant) Intersect(o NetGrant) NetGrant {
	var out NetGrant
	for _, a := range g.UDP {
		for _, b := range o.UDP {
			if a == b {
				out.UDP = append(out.UDP, a)
			}
		}
	}
	for _, a := range g.ICMP {
		for _, b := range o.ICMP {
			switch {
			case a.Addr().BitLen() != b.Addr().BitLen():
			case a.Bits() >= b.Bits() && b.Contains(a.Addr()):
				out.ICMP = append(out.ICMP, a)
			case b.Bits() > a.Bits() && a.Contains(b.Addr()):
				out.ICMP = append(out.ICMP, b)
			}
		}
	}
	return out.dedup()
}

func (g NetGrant) dedup() NetGrant {
	var out NetGrant
	seenU := map[netip.AddrPort]bool{}
	for _, a := range g.UDP {
		if !seenU[a] {
			seenU[a] = true
			out.UDP = append(out.UDP, a)
		}
	}
	seenI := map[netip.Prefix]bool{}
	for _, p := range g.ICMP {
		if !seenI[p] {
			seenI[p] = true
			out.ICMP = append(out.ICMP, p)
		}
	}
	sort.Slice(out.UDP, func(i, j int) bool { return out.UDP[i].String() < out.UDP[j].String() })
	sort.Slice(out.ICMP, func(i, j int) bool { return out.ICMP[i].String() < out.ICMP[j].String() })
	return out
}

func (c *compiler) net(p *AgentProfile, cp *CompiledProfile) {
	cp.Net = parseNet(p.Spec.UDP, p.Spec.ICMP, c.errf)
	enforced := "cgroup sock_addr hooks and egress backstop"
	if c.opts.Mode != Transparent && c.opts.Mode != TransparentAudit {
		enforced = "not enforced: UDP and ICMP are governed in transparent mode only"
	}
	for _, a := range cp.Net.UDP {
		cp.Placements = append(cp.Placements, Placement{Rule: "udp/" + a.String(), Tier: "0", EnforcedBy: enforced,
			Notes: []string{"needs the ceiling's udp.allow"}})
	}
	icmpBy := "egress backstop (cgroup_skb), per packet"
	if c.opts.Mode != Transparent && c.opts.Mode != TransparentAudit {
		icmpBy = enforced
	}
	for _, a := range cp.Net.ICMP {
		cp.Placements = append(cp.Placements, Placement{Rule: "icmp/" + a.String(), Tier: "0", EnforcedBy: icmpBy,
			Notes: []string{"echo only, from ICMP datagram sockets; needs the ceiling's icmp.allow"}})
	}
}

// Net is the UDP and ICMP the run may use beyond the node's: the
// ceiling's grant intersected with every enforce-mode layer's udp and icmp
// blocks (a layer without them allows none). A run with no enforce layer
// has none: nothing is refused there, only reported.
func (e *Effective) Net() NetGrant {
	g := e.Ceiling
	enforcing := false
	for _, l := range e.Layers {
		if !l.Profile.Enforcing() {
			continue
		}
		enforcing = true
		g = g.Intersect(l.Profile.Net)
	}
	if !enforcing {
		return NetGrant{}
	}
	return g.dedup()
}
