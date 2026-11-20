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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	clovisor "github.com/clovisor/clovisor/libclovisor"
	"github.com/clovisor/clovisor/libclovisor/policy"
)

func printUsage() {
	fmt.Println("AgentCtl - Agent Cgroup Control Tool (Phase 1)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  agentctl run [--profile p] [--no-proxy] [--mcp-config file] [--] <command> [args...]")
	fmt.Println("                                    Run a command as a governed run")
	fmt.Println("  agentctl profiles                 Show which profiles you may request")
	fmt.Println("  agentctl clamp <run-id> <profile> Intersect a profile into a live run (remove-only)")
	fmt.Println("  agentctl revoke <run-id>          Deny all further egress for a live run")
	fmt.Println("  agentctl events [--json] [run-id] List recorded runs, or show one run's timeline")
	fmt.Println("  agentctl learn [-o file] [--name n] (--all | run-id...)")
	fmt.Println("                                    Draft a profile from recorded runs")
	fmt.Println("  agentctl explain profile.yaml...  Compile profiles and print the enforcement receipt")
	fmt.Println("  agentctl check --profile p.yaml (--all | run-id...)")
	fmt.Println("                                    Replay recorded runs against a profile; exit 1 on violations")
	fmt.Println("  agentctl cgroups                  List active cgroups")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  agentctl run -- python3 script.py")
	fmt.Println("  agentctl run -- curl https://example.com")
	fmt.Println()
	fmt.Println("agentctl run needs the node agent (sudo make run); agentctl itself")
	fmt.Println("needs no privileges. Set CLOVISOR_SOCKET to use a non-default socket.")
	os.Exit(0)
}

// shimArg is the hidden subcommand agentctl re-executes itself with to
// park the child until the node agent has moved it into the run.
const shimArg = "__run-shim"

// runShim is the child side of runCommand. It runs only agentctl's own
// code until the parent releases it, then execs the real command in the
// same process, which by then is in the run cgroup.
func runShim(args []string) {
	if len(args) < 2 {
		os.Exit(127)
	}
	release := os.NewFile(3, "release")
	var b [1]byte
	if n, _ := release.Read(b[:]); n != 1 {
		os.Exit(127) // parent gave up before releasing us
	}
	release.Close()
	err := syscall.Exec(args[0], args[1:], os.Environ())
	fmt.Fprintf(os.Stderr, "agentctl: exec %s: %v\n", args[0], err)
	os.Exit(126)
}

// runCommand runs args in a fresh run and returns the child's exit code.
//
// The node agent owns the cgroup. agentctl starts the child as a parked
// shim, has the node agent move it into the run, and only then lets it
// exec the command. So no command code ever runs outside the run (design
// §5.2), and agentctl needs no privileges. clone3(CLONE_INTO_CGROUP)
// would do this in one step but needs root (see libclovisor/run_api.go).
// proxyEnv points a run at the node's proxy. Both spellings are set:
// curl ignores upper-case HTTP_PROXY (the httpoxy mitigation), and some
// tools read only one or the other. Values already in the environment are
// replaced, so an inherited NO_PROXY cannot route around the proxy.
func proxyEnv(env []string, proxy string) []string {
	set := map[string]string{
		"HTTP_PROXY": proxy, "http_proxy": proxy,
		"HTTPS_PROXY": proxy, "https_proxy": proxy,
		"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
	}
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := set[k]; ok {
			continue
		}
		if strings.EqualFold(k, "ALL_PROXY") {
			continue // would send other protocols somewhere else
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+set[k])
	}
	return out
}

// mcpConfig is the common MCP client configuration format
// ({"mcpServers": {name: {...}}}), as read by most harnesses.
type mcpConfig struct {
	MCPServers map[string]map[string]interface{} `json:"mcpServers"`
}

// prepareMCP registers the stdio servers in configPath with the gateway
// and writes a copy of the config pointing them at it. Remote (url)
// entries pass through unchanged: they are ordinary egress. Servers the
// policy refuses are left out, with the reason printed.
func prepareMCP(api *clovisor.RunAPIClient, configPath, proxy string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg mcpConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("%s: %w", configPath, err)
	}
	baseEnv := map[string]string{}
	for _, k := range []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "TERM"} {
		if v, ok := os.LookupEnv(k); ok {
			baseEnv[k] = v
		}
	}
	if proxy != "" {
		for _, kv := range proxyEnv(nil, proxy) {
			k, v, _ := strings.Cut(kv, "=")
			baseEnv[k] = v
		}
	}

	var specs []clovisor.MCPServerSpec
	names := make([]string, 0, len(cfg.MCPServers))
	for n := range cfg.MCPServers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := cfg.MCPServers[name]
		command, _ := entry["command"].(string)
		if command == "" {
			continue // remote server
		}
		path, err := exec.LookPath(command)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentctl: MCP server %s left out: %v\n", name, err)
			delete(cfg.MCPServers, name)
			continue
		}
		if path, err = filepath.Abs(path); err != nil {
			return "", err
		}
		argv := []string{path}
		if args, ok := entry["args"].([]interface{}); ok {
			for _, a := range args {
				s, ok := a.(string)
				if !ok {
					return "", fmt.Errorf("mcp server %s: args must be strings", name)
				}
				argv = append(argv, s)
			}
		}
		env := map[string]string{}
		for k, v := range baseEnv {
			env[k] = v
		}
		if e, ok := entry["env"].(map[string]interface{}); ok {
			for k, v := range e {
				if s, ok := v.(string); ok {
					env[k] = s
				}
			}
		}
		specs = append(specs, clovisor.MCPServerSpec{Name: name, Command: argv, Env: env})
	}

	if len(specs) > 0 {
		resp, err := api.RegisterMCP(specs)
		if err != nil {
			return "", err
		}
		for _, reg := range resp.MCP {
			if reg.Error != "" {
				fmt.Fprintf(os.Stderr, "agentctl: MCP server %s refused: %s\n", reg.Name, reg.Error)
				delete(cfg.MCPServers, reg.Name)
				continue
			}
			note := ""
			if len(reg.WouldDeny) > 0 {
				note = " (would be refused by " + strings.Join(reg.WouldDeny, ", ") + ")"
			}
			fmt.Fprintf(os.Stderr, "agentctl: MCP server %s via %s%s\n", reg.Name, reg.URL, note)
			cfg.MCPServers[reg.Name] = map[string]interface{}{"type": "http", "url": reg.URL}
		}
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "clovisor-mcp-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(append(out, '\n')); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func runCommand(args []string, profile string, noProxy bool, mcpConfigPath string) (int, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("command required")
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return 0, err
	}
	if path, err = filepath.Abs(path); err != nil {
		return 0, err
	}
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}

	api, err := clovisor.DialRunAPI(socketPath())
	if err != nil {
		return 0, err
	}
	// Closing without End makes the node agent end the run: this also
	// covers agentctl dying.
	defer api.Close()

	cwd, _ := os.Getwd()
	run, err := api.Create(args, cwd, profile)
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(os.Stderr, "agentctl: run %s (cgroup id %d), %s\n", run.RunID, run.CgroupID, describePolicy(run.Policy))
	if run.Policy != nil && profile != "" && run.Policy.Layers[0].Profile != profile {
		fmt.Fprintf(os.Stderr, "agentctl: WARNING: %s\n", run.Policy.Reason)
	}

	relR, relW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer relW.Close()

	pidfd := -1
	cmd := exec.Command(self, append([]string{shimArg, path}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{relR}
	cmd.Env = os.Environ()
	if run.Proxy != "" && !noProxy {
		cmd.Env = proxyEnv(cmd.Env, run.Proxy)
		fmt.Fprintf(os.Stderr, "agentctl: egress via %s\n", run.Proxy)
	}
	if mcpConfigPath != "" {
		proxy := run.Proxy
		if noProxy {
			proxy = ""
		}
		rewritten, err := prepareMCP(api, mcpConfigPath, proxy)
		if err != nil {
			relR.Close()
			return 0, err
		}
		defer os.Remove(rewritten)
		cmd.Env = append(cmd.Env, "CLOVISOR_MCP_CONFIG="+rewritten)
		fmt.Fprintf(os.Stderr, "agentctl: MCP config for the harness: $CLOVISOR_MCP_CONFIG (%s)\n", rewritten)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}

	// Terminal signals (Ctrl-C, Ctrl-\) already reach the child through the
	// foreground process group; agentctl ignores them so it survives to
	// report the exit. Signals aimed at agentctl alone are forwarded.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	fwd := make(chan os.Signal, 1)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(fwd)

	if err := cmd.Start(); err != nil {
		relR.Close()
		return 0, fmt.Errorf("failed to start %s: %w", args[0], err)
	}
	relR.Close()

	attachErr := api.Attach(pidfd)
	syscall.Close(pidfd)
	if attachErr != nil {
		relW.Close() // the shim exits without running the command
		cmd.Wait()
		return 0, attachErr
	}
	if _, err := relW.Write([]byte{1}); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("failed to release %s: %w", args[0], err)
	}
	relW.Close()

	go func() {
		for sig := range fwd {
			cmd.Process.Signal(sig)
		}
	}()

	code, err := exitCode(cmd.Wait())
	if err != nil {
		return 0, err
	}
	if err := api.End(&code); err != nil {
		// Most likely the node agent restarted during the run. It removes
		// the run cgroup once empty, but never learns the exit code.
		fmt.Fprintf(os.Stderr, "agentctl: warning: could not report the end of run %s to the node agent "+
			"(restarted?); its timeline will lack the exit code: %v\n", run.RunID, err)
	}
	return code, nil
}

// describePolicy renders a run's policy layers on one line.
func describePolicy(rp *clovisor.RunPolicy) string {
	if rp == nil {
		return "unprofiled (audit only)"
	}
	var parts []string
	for i, l := range rp.Layers {
		s := l.Profile + "@" + l.Version
		if l.Mode == "audit" {
			s += " (audit)"
		}
		if i > 0 {
			s = l.Source + " " + s
		}
		parts = append(parts, s)
	}
	return "profile " + strings.Join(parts, " + ")
}

// runArgs are agentctl run's options.
type runArgs struct {
	profile   string
	noProxy   bool
	mcpConfig string
}

// parseRunArgs splits "[--profile p] [--no-proxy] [--mcp-config f] [--]
// command..." for agentctl run.
func parseRunArgs(args []string) (o runArgs, cmd []string, err error) {
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--no-proxy":
			o.noProxy, args = true, args[1:]
		case a == "--mcp-config":
			if len(args) < 2 {
				return o, nil, fmt.Errorf("--mcp-config needs a file")
			}
			o.mcpConfig, args = args[1], args[2:]
		case strings.HasPrefix(a, "--mcp-config="):
			o.mcpConfig, args = strings.TrimPrefix(a, "--mcp-config="), args[1:]
		case a == "--":
			return o, args[1:], nil
		case a == "--profile" || a == "-profile":
			if len(args) < 2 {
				return o, nil, fmt.Errorf("--profile needs a name")
			}
			o.profile, args = args[1], args[2:]
		case strings.HasPrefix(a, "--profile="):
			o.profile, args = strings.TrimPrefix(a, "--profile="), args[1:]
		default:
			return o, args, nil
		}
	}
	return o, nil, nil
}

func listProfiles() error {
	api, err := clovisor.DialRunAPI(socketPath())
	if err != nil {
		return err
	}
	defer api.Close()
	r, err := api.Profiles()
	if err != nil {
		return err
	}
	fmt.Printf("Ceiling   %s\n", r.Ceiling)
	fmt.Printf("Allowed   %s\n", strings.Join(r.Allow, ", "))
	if r.Default != "" {
		fmt.Printf("Default   %s (granted when you request nothing, or something not allowed)\n", r.Default)
	}
	if r.Clamp != "" {
		fmt.Printf("Clamp     %s (intersected into every grant)\n", r.Clamp)
	}
	return nil
}

// clampRun layers a profile onto a live run, or revokes its egress.
func clampRun(op string, args []string) error {
	if (op == "clamp" && len(args) != 2) || (op == "revoke" && len(args) != 1) {
		if op == "clamp" {
			return fmt.Errorf("usage: agentctl clamp <run-id> <profile>")
		}
		return fmt.Errorf("usage: agentctl revoke <run-id>")
	}
	api, err := clovisor.DialRunAPI(socketPath())
	if err != nil {
		return err
	}
	defer api.Close()
	var r clovisor.RunAPIResponse
	if op == "clamp" {
		r, err = api.Clamp(args[0], args[1])
	} else {
		r, err = api.Revoke(args[0])
	}
	if err != nil {
		return err
	}
	fmt.Printf("run %s now: %s\n", r.RunID, describePolicy(r.Policy))
	return nil
}

func exitCode(err error) (int, error) {
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

func socketPath() string {
	if p := os.Getenv("CLOVISOR_SOCKET"); p != "" {
		return p
	}
	return clovisor.DefaultRunAPISocket
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
			if !os.IsPermission(err) { // other users' runs are private
				fmt.Fprintf(os.Stderr, "agentctl: skipping %v\n", err)
			}
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
	fmt.Fprintln(w, "RUN ID\tSTARTED\tDURATION\tEXIT\tEXECS\tCONNECTS\tDNS\tCOMPLETE\tPROFILE\tCOMMAND")
	for _, tl := range tls {
		dur, exit := "running", "-"
		if tl.EndedAt != nil {
			dur = tl.EndedAt.Sub(tl.StartedAt).Round(time.Millisecond).String()
		}
		if tl.ExitCode != nil {
			exit = strconv.Itoa(*tl.ExitCode)
		}
		prof := "-"
		if tl.Policy != nil {
			prof = tl.Policy.Layers[0].Profile
			if n := len(tl.Policy.Layers); n > 1 {
				prof += fmt.Sprintf("+%d", n-1)
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%t\t%s\t%s\n",
			tl.RunID, tl.StartedAt.Local().Format(time.DateTime), dur, exit,
			tl.Summary.Execs, tl.Summary.Connects, tl.Summary.DNSReplies, tl.Complete, prof, truncate(strings.Join(tl.Command, " "), 50))
	}
	return w.Flush()
}

func printTimeline(tl *clovisor.RunTimeline) {
	fmt.Printf("Run       %s (cgroup %d, %s)\n", tl.RunID, tl.CgroupID, tl.CgroupPath)
	if len(tl.Command) > 0 {
		fmt.Printf("Command   %s\n", strings.Join(tl.Command, " "))
	}
	if tl.Policy == nil {
		fmt.Println("Policy    unprofiled (audit only)")
	} else {
		fmt.Printf("Policy    ceiling %s: %s\n", tl.Policy.Ceiling, tl.Policy.Reason)
		for _, l := range tl.Policy.Layers {
			fmt.Printf("          %s@%s  mode %s  %s at %s\n", l.Profile, l.Version, l.Mode, l.Source, l.At.Local().Format(time.RFC3339))
		}
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
			if e.DstName != "" {
				detail += " (" + e.DstName + ")"
			}
		case "mcp":
			detail = fmt.Sprintf("%s %s %s -> %s", e.MCPServer, e.Method, e.MCPName, e.Decision)
			if e.Decision == "deny" && !e.Enforced {
				detail += " (not enforced)"
			}
			if e.Layer != "" {
				detail += " by " + e.Layer
			}
			if len(e.WouldDeny) > 0 {
				detail += " (would deny: " + strings.Join(e.WouldDeny, ", ") + ")"
			}
			if e.Reason != "" {
				detail += " [" + e.Reason + "]"
			}
		case "http":
			detail = fmt.Sprintf("%s %s%s -> %s", e.Method, net.JoinHostPort(e.DstName, strconv.Itoa(int(e.DstPort))), e.Path, e.Decision)
			if e.Decision == "deny" && !e.Enforced {
				detail += " (not enforced)"
			}
			if e.Rule != "" {
				detail += " rule " + e.Rule
			}
			if e.Layer != "" {
				detail += " by " + e.Layer
			}
			if len(e.WouldDeny) > 0 {
				detail += " (would deny: " + strings.Join(e.WouldDeny, ", ") + ")"
			}
			if e.Reason != "" {
				detail += " [" + e.Reason + "]"
			}
		case "dns":
			detail = fmt.Sprintf("%s %s %s from %s", e.Query, e.QType, e.RCode, e.Server)
			var vals []string
			for _, a := range e.Answers {
				vals = append(vals, a.Value)
			}
			if len(vals) > 0 {
				detail += " -> " + strings.Join(vals, ", ")
			}
			if e.Partial {
				detail += " (reply cut off at capture limit)"
			}
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
	fmt.Printf("DNS names (%d)\n", len(tl.Summary.DNSNames))
	for _, n := range tl.Summary.DNSNames {
		fmt.Printf("  %s\n", n)
	}
	if len(tl.Summary.MCP) > 0 {
		fmt.Printf("MCP (%d)\n", len(tl.Summary.MCP))
		for _, u := range tl.Summary.MCP {
			note := ""
			if u.Denied > 0 {
				note += fmt.Sprintf(" denied %d", u.Denied)
			}
			if u.WouldDeny > 0 {
				note += fmt.Sprintf(" would-deny %d", u.WouldDeny)
			}
			fmt.Printf("  %-12s %-16s %-28s x%-4d%s\n", u.Server, u.Method, u.Name, u.Calls, note)
		}
	}
	if len(tl.Summary.Proxied) > 0 {
		fmt.Printf("Via proxy (%d destinations, %d connections to the proxy)\n", len(tl.Summary.Proxied), tl.Summary.ProxyConnects)
		for _, p := range tl.Summary.Proxied {
			note := ""
			if p.Denied > 0 {
				note += fmt.Sprintf(" denied %d", p.Denied)
			}
			if p.WouldDeny > 0 {
				note += fmt.Sprintf(" would-deny %d", p.WouldDeny)
			}
			fmt.Printf("  %-46s x%-4d%s\n", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))), p.Requests, note)
		}
	}
	fmt.Printf("Destinations (%d)\n", len(tl.Summary.Destinations))
	for _, d := range tl.Summary.Destinations {
		fmt.Printf("  %-4s %-40s x%-4d %s\n", d.Proto, net.JoinHostPort(d.IP, strconv.Itoa(int(d.Port))), d.Count,
			strings.Join(d.Names, ", "))
	}
}

// loadRuns reads the finished runs named by ids, or every finished run
// readable by the caller when all is set, oldest first.
func loadRuns(dir string, all bool, ids []string) ([]*clovisor.RunTimeline, error) {
	var paths []string
	switch {
	case all && len(ids) > 0:
		return nil, fmt.Errorf("give either --all or run ids, not both")
	case all:
		var err error
		if paths, err = filepath.Glob(filepath.Join(dir, "run-*.json")); err != nil {
			return nil, err
		}
	case len(ids) == 0:
		return nil, fmt.Errorf("give run ids, or --all")
	default:
		for _, id := range ids {
			paths = append(paths, clovisor.TimelinePath(dir, strings.TrimPrefix(id, clovisor.RunPrefix)))
		}
	}

	var runs []*clovisor.RunTimeline
	for _, p := range paths {
		tl, err := clovisor.ReadRunTimeline(p)
		if err != nil {
			if all && os.IsPermission(err) {
				continue // another user's run
			}
			return nil, err
		}
		if tl.EndedAt == nil {
			if all {
				continue // still running, or the agent stopped mid-run
			}
			return nil, fmt.Errorf("run %s has not finished", tl.RunID)
		}
		runs = append(runs, tl)
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("no finished runs in %s", dir)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].StartedAt.Before(runs[j].StartedAt) })
	return runs, nil
}

// compileFiles parses and compiles profile files for this deployment,
// printing every diagnostic.
func compileFiles(paths []string, linux bool) (*policy.Compiled, error) {
	var ps []*policy.AgentProfile
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p, err := policy.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		ps = append(ps, p)
	}
	c, diags := policy.Compile(policy.Options{Mode: policy.ExplicitProxy, Linux: linux}, ps...)
	if len(diags) > 0 {
		for _, d := range diags {
			fmt.Fprintf(os.Stderr, "error: %v\n", d)
		}
		return nil, fmt.Errorf("%d compile error(s)", len(diags))
	}
	return c, nil
}

func platformFlag(fs *flag.FlagSet) *string {
	def := "other"
	if runtime.GOOS == "linux" {
		def = "linux"
	}
	return fs.String("platform", def, "deployment platform: linux (cgroup identity) or other (per-run credential)")
}

// explainProfiles prints the enforcement receipt (design §7.4).
func explainProfiles(argv []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	platform := platformFlag(fs)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("give one or more profile files; pass every profile active on a node to see node-wide TLS posture")
	}
	c, err := compileFiles(fs.Args(), *platform == "linux")
	if err != nil {
		return err
	}
	return c.WriteReceipt(os.Stdout)
}

// errViolations makes agentctl check exit 1 without an error message.
var errViolations = errors.New("violations")

// checkProfile replays recorded runs against a profile (design §7.10,
// shadow step, offline).
func checkProfile(argv []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	dir := fs.String("dir", clovisor.DefaultRunOutDir, "directory of run timeline files")
	profile := fs.String("profile", "", "profile file to check against (required)")
	all := fs.Bool("all", false, "check every finished run in -dir")
	platform := platformFlag(fs)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *profile == "" {
		return fmt.Errorf("--profile is required")
	}
	c, err := compileFiles([]string{*profile}, *platform == "linux")
	if err != nil {
		return err
	}
	runs, err := loadRuns(*dir, *all, fs.Args())
	if err != nil {
		return err
	}
	rep := clovisor.CheckRuns(c.Profiles[0], runs)
	if err := rep.WriteText(os.Stdout); err != nil {
		return err
	}
	if len(rep.Violations) > 0 {
		return errViolations
	}
	return nil
}

// learnProfile drafts an AgentProfile from recorded runs.
func learnProfile(argv []string) error {
	fs := flag.NewFlagSet("learn", flag.ContinueOnError)
	dir := fs.String("dir", clovisor.DefaultRunOutDir, "directory of run timeline files")
	name := fs.String("name", "learned-profile", "metadata.name of the drafted profile")
	out := fs.String("o", "", "write the profile here instead of stdout")
	all := fs.Bool("all", false, "learn from every finished run in -dir")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	runs, err := loadRuns(*dir, *all, fs.Args())
	if err != nil {
		return err
	}

	draft := clovisor.LearnProfile(*name, runs)
	if *out == "" {
		return draft.WriteYAML(os.Stdout, time.Now())
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	if err := draft.WriteYAML(f, time.Now()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "agentctl: wrote draft profile from %d run(s) to %s\n", len(runs), *out)
	return nil
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
	if command == shimArg {
		runShim(os.Args[2:])
	}

	switch command {
	case "run":
		// Pass remaining args to runCommand (skip "--" if present)
		o, args, err := parseRunArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		code, err := runCommand(args, o.profile, o.noProxy, o.mcpConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(code)
	case "profiles":
		if err := listProfiles(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "clamp", "revoke":
		if err := clampRun(command, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
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
	case "explain":
		if err := explainProfiles(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "check":
		if err := checkProfile(os.Args[2:]); err != nil {
			if err != errViolations {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(1)
		}
	case "learn":
		if err := learnProfile(os.Args[2:]); err != nil {
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
