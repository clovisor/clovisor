// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	clovisor "github.com/clovisor/clovisor/libclovisor"
)

func printUsage() {
	fmt.Println("AgentCtl - Agent Cgroup Control Tool (Phase 1)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  agentctl run <command> [args...]  Run a command in a new agent cgroup")
	fmt.Println("  agentctl events [--json] [run-id] List recorded runs, or show one run's timeline")
	fmt.Println("  agentctl cgroups                  List active cgroups")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  agentctl run -- python3 script.py")
	fmt.Println("  agentctl run -- curl https://example.com")
	fmt.Println()
	fmt.Println("For BPF functionality, run the node-agent daemon as root.")
	fmt.Println()
	fmt.Println("To compile BPF program:")
	fmt.Println("  make bpf")
	fmt.Println()
	fmt.Println("To run the agent:")
	fmt.Println("  sudo make run")
	os.Exit(0)
}

// runCommand runs args in a fresh run cgroup and returns the child's exit
// code. agentctl itself never joins the cgroup: the child is spawned
// directly into it with clone3(CLONE_INTO_CGROUP), so there is no window in
// which it runs under agentctl's cgroup (design §5.2), and the run cgroup
// contains only the governed process tree.
func runCommand(args []string) (code int, err error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("command required")
	}

	cmgr, err := clovisor.NewCgroupManager()
	if err != nil {
		return 0, fmt.Errorf("failed to create cgroup manager: %w", err)
	}

	runID, err := clovisor.NewRunID()
	if err != nil {
		return 0, err
	}

	cgroupPath, cgroupID, err := cmgr.CreateRunCgroup(runID)
	if err != nil {
		return 0, fmt.Errorf("failed to create cgroup: %w", err)
	}
	defer func() {
		if err := cmgr.DestroyRunCgroup(runID); err != nil {
			fmt.Fprintf(os.Stderr, "agentctl: warning: failed to destroy cgroup: %v\n", err)
		}
	}()

	// The node agent reads this when the run cgroup is removed, so the
	// final write (deferred after the destroy, so it runs first) must land
	// before DestroyRunCgroup.
	cwd, _ := os.Getwd()
	meta := clovisor.RunMeta{
		RunID:     runID,
		Command:   args,
		Cwd:       cwd,
		UID:       os.Getuid(),
		StartedAt: time.Now().UTC(),
	}
	writeMeta := func() {
		if err := clovisor.WriteRunMeta(clovisor.DefaultRunSpoolDir, meta); err != nil {
			fmt.Fprintf(os.Stderr, "agentctl: warning: failed to record run metadata: %v\n", err)
		}
	}
	writeMeta()
	defer func() {
		end := time.Now().UTC()
		meta.EndedAt = &end
		if err == nil {
			c := code
			meta.ExitCode = &c
		}
		writeMeta()
	}()

	fmt.Fprintf(os.Stderr, "agentctl: run %s cgroup %s (id %d)\n", runID, cgroupPath, cgroupID)

	cgroupDir, err := os.Open(cgroupPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open cgroup: %w", err)
	}
	defer cgroupDir.Close()

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroupDir.Fd()),
	}

	// Terminal signals (Ctrl-C, Ctrl-\) already reach the child through the
	// foreground process group; agentctl ignores them so it survives to clean
	// up. Signals aimed at agentctl alone are forwarded.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	fwd := make(chan os.Signal, 1)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(fwd)

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start %s: %w", args[0], err)
	}

	go func() {
		for sig := range fwd {
			cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exitErr):
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	default:
		return 0, err
	}
}

func listCgroups() error {
	cmgr, err := clovisor.NewCgroupManager()
	if err != nil {
		return fmt.Errorf("failed to create cgroup manager: %w", err)
	}

	cgroups := cmgr.ListActiveCgroups()

	if len(cgroups) == 0 {
		fmt.Println("No active cgroups found.")
		return nil
	}

	fmt.Printf("%-20s %-50s %-10s\n", "RUN ID", "PATH", "CGROUP ID")
	fmt.Println(strings.Repeat("-", 85))

	for _, cg := range cgroups {
		pathShort := cg.Path
		if len(pathShort) > 50 {
			pathShort = "..." + pathShort[len(pathShort)-47:]
		}
		fmt.Printf("%-20s %-50s %-10d\n", cg.RunID, pathShort, cg.CgroupID)
	}

	return nil
}

// showEvents lists recorded runs, or prints one run's timeline.
func showEvents(argv []string) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	dir := fs.String("dir", clovisor.DefaultRunOutDir, "directory of run timeline files")
	asJSON := fs.Bool("json", false, "print the raw timeline JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return listRuns(*dir)
	}
	runID := strings.TrimPrefix(fs.Arg(0), clovisor.RunPrefix)
	path := clovisor.TimelinePath(*dir, runID)
	if *asJSON {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}
	tl, err := clovisor.ReadRunTimeline(path)
	if err != nil {
		return err
	}
	printTimeline(tl)
	return nil
}

func listRuns(dir string) error {
	paths, err := filepath.Glob(filepath.Join(dir, "run-*.json"))
	if err != nil {
		return err
	}
	var tls []*clovisor.RunTimeline
	for _, p := range paths {
		tl, err := clovisor.ReadRunTimeline(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentctl: skipping %v\n", err)
			continue
		}
		tls = append(tls, tl)
	}
	if len(tls) == 0 {
		fmt.Printf("No recorded runs in %s. Is the node agent running?\n", dir)
		return nil
	}
	sort.Slice(tls, func(i, j int) bool { return tls[i].StartedAt.Before(tls[j].StartedAt) })

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN ID\tSTARTED\tDURATION\tEXIT\tEXECS\tCONNECTS\tCOMPLETE\tCOMMAND")
	for _, tl := range tls {
		dur, exit := "running", "-"
		if tl.EndedAt != nil {
			dur = tl.EndedAt.Sub(tl.StartedAt).Round(time.Millisecond).String()
		}
		if tl.ExitCode != nil {
			exit = strconv.Itoa(*tl.ExitCode)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%t\t%s\n",
			tl.RunID, tl.StartedAt.Local().Format(time.DateTime), dur, exit,
			tl.Summary.Execs, tl.Summary.Connects, tl.Complete, truncate(strings.Join(tl.Command, " "), 50))
	}
	return w.Flush()
}

func printTimeline(tl *clovisor.RunTimeline) {
	fmt.Printf("Run       %s (cgroup %d, %s)\n", tl.RunID, tl.CgroupID, tl.CgroupPath)
	if len(tl.Command) > 0 {
		fmt.Printf("Command   %s\n", strings.Join(tl.Command, " "))
	}
	fmt.Printf("Started   %s\n", tl.StartedAt.Local().Format(time.RFC3339Nano))
	if tl.EndedAt != nil {
		fmt.Printf("Ended     %s (%s)\n", tl.EndedAt.Local().Format(time.RFC3339Nano),
			tl.EndedAt.Sub(tl.StartedAt).Round(time.Millisecond))
	}
	if tl.ExitCode != nil {
		fmt.Printf("Exit      %d\n", *tl.ExitCode)
	}
	if !tl.Complete {
		fmt.Println("Note      incomplete: the node agent did not see the whole run")
	}
	if tl.DroppedEvents > 0 {
		fmt.Printf("Note      %d events past the per-run cap are counted but not listed\n", tl.DroppedEvents)
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "+TIME\tPID\tPPID\tEVENT\tDETAIL")
	for _, e := range tl.Events {
		rel := "+" + e.Time.Sub(tl.StartedAt).Round(time.Microsecond).String()
		pid, ppid := "", ""
		if e.PID != 0 {
			pid = strconv.Itoa(int(e.PID))
		}
		if e.PPID != 0 {
			ppid = strconv.Itoa(int(e.PPID))
		}
		var detail string
		switch e.Type {
		case "exec":
			detail = e.Binary
			if len(e.Args) > 0 {
				b, _ := json.Marshal(e.Args)
				detail += " " + string(b)
			}
		case "connect":
			detail = e.Proto + " " + net.JoinHostPort(e.DstIP, strconv.Itoa(int(e.DstPort)))
		default:
			detail = e.Note
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", rel, pid, ppid, e.Type, detail)
	}
	w.Flush()

	fmt.Printf("\nBinaries (%d)\n", len(tl.Summary.Binaries))
	for _, b := range tl.Summary.Binaries {
		fmt.Printf("  %s\n", b)
	}
	fmt.Printf("Destinations (%d)\n", len(tl.Summary.Destinations))
	for _, d := range tl.Summary.Destinations {
		fmt.Printf("  %-4s %-40s x%d\n", d.Proto, net.JoinHostPort(d.IP, strconv.Itoa(int(d.Port))), d.Count)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
	}

	command := os.Args[1]

	switch command {
	case "run":
		// Pass remaining args to runCommand (skip "--" if present)
		args := os.Args[2:]
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		code, err := runCommand(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(code)
	case "cgroups":
		if err := listCgroups(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "events":
		if err := showEvents(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
	}
}
