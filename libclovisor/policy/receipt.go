// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// WriteReceipt writes the enforcement receipt (design §7.4): for each
// rule, where it is enforced and what can get around it, then the TLS
// posture of every named destination.
func (c *Compiled) WriteReceipt(w io.Writer) error {
	var b strings.Builder
	p := func(format string, a ...interface{}) { fmt.Fprintf(&b, format+"\n", a...) }

	platform := "Linux"
	identity := "run cgroup of the client socket (sock_diag): enforcement-grade"
	if !c.Options.Linux {
		platform = "not Linux"
		identity = "per-run proxy credential: a claim, not enforcement-grade (design §5.5)"
	}
	p("Deployment  %s on %s", c.Options.Mode, platform)
	p("Identity    %s", identity)
	switch c.Options.Mode {
	case Transparent:
		p("Routing     enforced: every TCP connect from a run reaches the proxy or is refused, UDP")
		p("            other than DNS and the node's UDP exceptions is refused (QUIC included), and")
		p("            all of it while the node agent is down (design §6.5, §6.8). A packet")
		p("            backstop drops what gets past the socket hooks.")
		if c.Options.KernelLSM {
			p("Sockets     only IPv4, IPv6, Unix and netlink sockets; raw and packet sockets refused;")
			p("            network sockets created outside the run refused at connect and send;")
			p("            Unix sockets outside the run refused unless unix.allow names them, for runs")
			p("            with an enforcing profile (BPF LSM). The run API is always reachable.")
		} else {
			p("Sockets     not governed: BPF LSM is not active. Raw sockets need CAP_NET_RAW; their")
			p("            packets off the node are dropped by the backstop. Not covered: Unix")
			p("            sockets to host daemons, sockets passed in from outside the run.")
		}
		p("DNS         every query from a run goes to the node's resolver, which answers only names")
		p("            some rule allows (NXDOMAIN otherwise) and strips ECH from HTTPS records.")
	case TransparentAudit:
		p("Routing     advisory, auditing: connects that bypass the proxy go direct and are")
		p("            recorded with what transparent mode would have done.")
		p("DNS         every query from a run goes to the node's resolver, which answers all of them")
		p("            and records the names enforce would refuse.")
	default:
		p("Routing     advisory: only traffic sent to the proxy is governed. Pair with a")
		p("            sandbox, or transparent mode, to make it binding (design §4.3).")
	}
	p("Narration   on CONNECT, denials reach clients as x-clovisor-denial only; the JSON")
	p("            body arrives on plain HTTP and terminated connections.")

	for _, cp := range c.Profiles {
		p("")
		p("Profile     %s@%s", cp.Name, cp.Profile.ShortVersion())
		switch cp.Mode {
		case ModeAudit:
			p("Mode        audit: nothing is blocked; decisions are logged as would-deny")
		default:
			p("Mode        %s", cp.Mode)
		}
		p("")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "RULE\tTIER\tENFORCED BY\tNOTES")
		for _, pl := range cp.Placements {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", pl.Rule, pl.Tier, pl.EnforcedBy, strings.Join(pl.Notes, "; "))
		}
		tw.Flush()
	}

	if len(c.Posture) > 0 {
		p("")
		p("TLS posture (node-wide: applies to every run on the node, under every profile)")
		p("")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DESTINATION\tPOSTURE\tWHY")
		for _, d := range c.Posture {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", d.Dest, d.Posture, strings.Join(d.Why, ", "))
			if len(d.Others) > 0 {
				fmt.Fprintf(tw, "\t\talso terminated for %s, which need only the hostname\n", strings.Join(d.Others, ", "))
			}
		}
		tw.Flush()
	}
	_, err := io.WriteString(w, b.String())
	return err
}
