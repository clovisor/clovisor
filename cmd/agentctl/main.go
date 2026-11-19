// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	clovisor "github.com/clovisor/clovisor/libclovisor"
)

func printUsage() {
	fmt.Println("AgentCtl - Agent Cgroup Control Tool (Phase 1)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  agentctl run <command> [args...]  Run a command in a new agent cgroup")
	fmt.Println("  agentctl events                   Show captured audit events")
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
func runCommand(args []string) (int, error) {
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

func showEvents() error {
	fmt.Println("Event collection from BPF perf ring buffers not yet implemented.")
	fmt.Println("Run the node-agent daemon to capture events:")
	fmt.Println("  sudo make run")
	return nil
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
		if err := showEvents(); err != nil {
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
