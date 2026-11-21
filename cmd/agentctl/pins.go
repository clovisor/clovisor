// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	clovisor "github.com/clovisor/clovisor/libclovisor"
)

// pinsCommand reviews MCP tool pins (design §8.4). A tool whose
// definition changed since it was pinned is blocked in enforce mode
// until approved here.
func pinsCommand(args []string) error {
	sub := "list"
	if len(args) > 0 && args[0] != "--all" {
		sub, args = args[0], args[1:]
	}
	api, err := clovisor.DialRunAPI(socketPath())
	if err != nil {
		return err
	}
	defer api.Close()

	switch sub {
	case "list":
		all := len(args) == 1 && args[0] == "--all"
		if len(args) > 1 || len(args) == 1 && !all {
			return fmt.Errorf("usage: agentctl pins [--all]")
		}
		r, err := api.Pins("", "", all)
		if err != nil {
			return err
		}
		return writePinList(os.Stdout, r.Pins, all)
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: agentctl pins show <server> <tool>")
		}
		r, err := api.Pins(args[0], args[1], true)
		if err != nil {
			return err
		}
		if len(r.Pins) == 0 {
			return fmt.Errorf("no pin for tool %s on %s", args[1], args[0])
		}
		return writePinShow(os.Stdout, r.Pins[0])
	case "approve":
		var server, tool, hash string
		switch {
		case len(args) == 2 && args[1] == "--all":
			server = args[0]
		case len(args) == 3:
			server, tool, hash = args[0], args[1], args[2]
		default:
			return fmt.Errorf("usage: agentctl pins approve <server> (<tool> <hash> | --all)\n" +
				"the hash is the pending one agentctl pins show prints, so only the reviewed definition is approved")
		}
		r, err := api.ApprovePin(server, tool, hash)
		for _, t := range r.Approved {
			fmt.Printf("approved %s on %s\n", t, server)
		}
		if err != nil {
			return err
		}
		fmt.Println("Runs offered the tool from now on can call it; a run that already saw it change keeps it blocked.")
		return nil
	default:
		return fmt.Errorf("unknown pins command %q (list, show, approve)", sub)
	}
}

func writePinList(w io.Writer, pins []clovisor.PinEntry, all bool) error {
	if len(pins) == 0 {
		if all {
			fmt.Fprintln(w, "No tool definitions pinned yet.")
		} else {
			fmt.Fprintln(w, "No tool definitions changed since pinned. (agentctl pins --all lists every pin.)")
		}
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tTOOL\tSTATUS\tPINNED")
	for _, e := range pins {
		p := e.Pin
		status := "pinned " + short(p.Hash)
		if p.Pending != nil {
			status = fmt.Sprintf("CHANGED %s -> %s, seen %s", short(p.Hash), short(p.Pending.Hash), p.Pending.Seen.Local().Format(time.DateTime))
		}
		at := "-"
		if !p.PinnedAt.IsZero() {
			at = p.PinnedAt.Local().Format(time.DateTime)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Server, e.Tool, status, at)
	}
	return tw.Flush()
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func writePinShow(w io.Writer, e clovisor.PinEntry) error {
	p := e.Pin
	fmt.Fprintf(w, "Server  %s\nTool    %s\n", e.Server, e.Tool)
	fmt.Fprintf(w, "\nPinned  %s", short(p.Hash))
	if !p.PinnedAt.IsZero() {
		fmt.Fprintf(w, " at %s", p.PinnedAt.Local().Format(time.RFC3339))
	}
	fmt.Fprintln(w)
	if p.Def == nil {
		fmt.Fprintln(w, "  (definition not kept: pinned by an earlier version)")
	} else {
		fmt.Fprintln(w, indentJSON(p.Def))
	}
	if p.Pending == nil {
		fmt.Fprintln(w, "\nNo changed definition awaits review.")
		return nil
	}
	fmt.Fprintf(w, "\nChanged %s, seen %s\n", short(p.Pending.Hash), p.Pending.Seen.Local().Format(time.RFC3339))
	fmt.Fprintln(w, indentJSON(p.Pending.Def))
	if p.Def != nil {
		if diff := changedFields(p.Def, p.Pending.Def); len(diff) > 0 {
			fmt.Fprintf(w, "\nFields that differ: %v\n", diff)
		}
	}
	fmt.Fprintf(w, "\nTo accept the change: sudo agentctl pins approve %s %s %s\n", e.Server, e.Tool, short(p.Pending.Hash))
	return nil
}

func indentJSON(b []byte) string {
	var out bytes.Buffer
	if json.Indent(&out, b, "  ", "  ") != nil {
		return "  " + string(b)
	}
	return "  " + out.String()
}

// changedFields names the top-level fields of two tool definitions that
// differ: a changed description is the classic tool-poisoning vector.
func changedFields(a, b []byte) []string {
	var ma, mb map[string]json.RawMessage
	if json.Unmarshal(a, &ma) != nil || json.Unmarshal(b, &mb) != nil {
		return nil
	}
	keys := map[string]bool{}
	for k := range ma {
		keys[k] = true
	}
	for k := range mb {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if !bytes.Equal(ma[k], mb[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
