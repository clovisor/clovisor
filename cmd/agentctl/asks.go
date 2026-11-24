// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	clovisor "github.com/clovisor/clovisor/libclovisor"
)

// asksCommand lists and decides requests held by ask rules (milestone
// 5.5).
func asksCommand(command string, args []string) error {
	api, err := clovisor.DialRunAPI(socketPath())
	if err != nil {
		return err
	}
	defer api.Close()
	if command == "pending" {
		all := false
		for _, a := range args {
			if a != "--all" {
				return fmt.Errorf("usage: agentctl pending [--all]")
			}
			all = true
		}
		r, err := api.Pending(all)
		if err != nil {
			return err
		}
		return writePending(os.Stdout, r.Asks, time.Now())
	}
	remember := false
	var ids []string
	for _, a := range args {
		switch {
		case a == "--remember":
			remember = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("usage: agentctl %s [--remember] <id>", command)
		default:
			ids = append(ids, a)
		}
	}
	if len(ids) != 1 {
		return fmt.Errorf("usage: agentctl %s [--remember] <id>", command)
	}
	r, err := api.DecideAsk(ids[0], command == "approve", remember)
	if err != nil {
		return err
	}
	p := r.Asks[0]
	what := map[bool]string{true: "approved", false: "denied"}[command == "approve"]
	if p.State != clovisor.AskApproved && p.State != clovisor.AskDenied {
		fmt.Printf("Request %s was already %s; later requests like it will be %s for run %s\n", p.ID, p.State, what, p.RunID)
		return nil
	}
	fmt.Printf("%s %s: %s (run %s)\n", strings.ToUpper(what[:1])+what[1:], p.ID, p.What, p.RunID)
	if remember {
		fmt.Printf("Later requests like it are %s for the rest of run %s\n", what, p.RunID)
	}
	return nil
}

func writePending(out io.Writer, asks []clovisor.PendingAsk, now time.Time) error {
	if len(asks) == 0 {
		_, err := fmt.Fprintln(out, "No requests awaiting a decision")
		return err
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tRUN\tSTATE\tREQUEST\tPROFILE/RULE\tLEFT")
	for _, p := range asks {
		rule := p.Layer
		if p.Rule != "" {
			rule += "/" + p.Rule
		}
		left := "-"
		state := p.State
		if p.State == clovisor.AskPending {
			left = p.Expires.Sub(now).Round(time.Second).String() + ", then " + p.OnTimeout
		} else if p.By != "" {
			state += " by " + p.By
		}
		if p.Remember {
			state += " (remembered)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.RunID, state, p.What, rule, left)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, p := range asks {
		if p.State != clovisor.AskPending || (p.Message == "" && p.Detail == "") {
			continue
		}
		fmt.Fprintf(out, "\n%s:", p.ID)
		if p.Message != "" {
			fmt.Fprintf(out, " %s", p.Message)
		}
		if p.Detail != "" {
			fmt.Fprintf(out, "\n  %s", p.Detail)
		}
		fmt.Fprintln(out)
	}
	return nil
}
