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
	"net/netip"
	"net/url"
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
	fmt.Println("agentctl - run and govern agent processes (see docs/operator-guide.md)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  agentctl run [--profile p] [--no-proxy] [--mcp-config file] [--] <command> [args...]")
	fmt.Println("                                    Run a command as a governed run")
	fmt.Println("  agentctl status                   Show the node's enforcement state")
	fmt.Println("  agentctl profiles                 Show which profiles you may request")
	fmt.Println("  agentctl clamp <run-id> <profile> Intersect a profile into a live run (remove-only)")
	fmt.Println("  agentctl revoke <run-id>          Deny all further egress for a live run")
	fmt.Println("  agentctl events [--json] [run-id] List recorded runs, or show one run's timeline")
	fmt.Println("  agentctl learn [-o file] [--name n] (--all | run-id...)")
	fmt.Println("                                    Draft a profile from recorded runs")
	fmt.Println("  agentctl explain [--transparent off|audit|enforce] profile.yaml...")
	fmt.Println("                                    Compile profiles and print the enforcement receipt")
	fmt.Println("  agentctl check --profile p.yaml [--transparent [--udp-allow ip:port,...]] (--all | run-id...)")
	fmt.Println("                                    Replay recorded runs against a profile; exit 1 on violations")
	fmt.Println("  agentctl pins [--all]             List MCP tools whose definitions changed since pinned")
	fmt.Println("  agentctl pins show <server> <tool>")
	fmt.Println("                                    Show a tool's pinned and changed definitions")
	fmt.Println("  agentctl pins approve <server> (<tool> <hash> | --all)")
	fmt.Println("                                    Accept changed definitions as the new pins (root)")
	fmt.Println("  agentctl cgroups                  List active run cgroups (cgroup identity)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  agentctl run -- python3 script.py")
	fmt.Println("  agentctl run -- curl https://example.com")
	fmt.Println()
	fmt.Println("agentctl run needs a running node agent; agentctl itself needs no privileges.")
	fmt.Println("It finds the node agent's socket in a per-user directory if one is running")
	fmt.Println("there, else in the system's; CLOVISOR_SOCKET overrides. Timelines are read")
	fmt.Println("from the matching directory; CLOVISOR_RUNS or --dir overrides.")
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
func prepareMCP(api *clovisor.RunAPIClient, configPath, proxy, bundle, caCert string) (string, error) {
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
		extra := proxyEnv(nil, proxy)
		if bundle != "" {
			extra = trustEnv(extra, bundle, caCert)
		}
		for _, kv := range extra {
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

// trustEnv makes TLS clients in a run trust the node CA, which terminates
// TLS for destinations whose rules need it. These variables replace each
// client's default store, so they name the full bundle (system roots plus
// the node CA); NODE_EXTRA_CA_CERTS adds to Node's store, so it names only
// the node CA.
func trustEnv(env []string, bundle, caCert string) []string {
	set := map[string]string{
		"SSL_CERT_FILE": bundle, "REQUESTS_CA_BUNDLE": bundle, "CURL_CA_BUNDLE": bundle,
		"GIT_SSL_CAINFO": bundle, "NODE_EXTRA_CA_CERTS": caCert,
	}
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := set[k]; !ok {
			out = append(out, kv)
		}
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

// runCommand runs args in a fresh run and returns the child's exit code.
//
// The node agent owns the cgroup. agentctl starts the child as a parked
// shim, has the node agent move it into the run, and only then lets it
// exec the command. So no command code ever runs outside the run (design
// §5.2), and agentctl needs no privileges. clone3(CLONE_INTO_CGROUP)
// would do this in one step but needs root (see libclovisor/run_api.go).
//
// With credential identity there is no cgroup: the command is started
// directly, and the proxy and MCP gateway know it by the secret in the
// proxy settings it inherits.
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
	credential := run.Identity == "credential"
	if credential {
		fmt.Fprintf(os.Stderr, "agentctl: run %s (credential identity: a claim, design §4.3), %s\n", run.RunID, describePolicy(run.Policy))
	} else {
		fmt.Fprintf(os.Stderr, "agentctl: run %s (cgroup id %d), %s\n", run.RunID, run.CgroupID, describePolicy(run.Policy))
	}
	if run.Policy != nil && profile != "" && run.Policy.Layers[0].Profile != profile {
		fmt.Fprintf(os.Stderr, "agentctl: WARNING: %s\n", run.Policy.Reason)
	}

	env := os.Environ()
	if run.Proxy != "" && !noProxy {
		env = proxyEnv(env, run.Proxy)
		fmt.Fprintf(os.Stderr, "agentctl: egress via %s\n", redactProxy(run.Proxy))
		if run.TrustBundle != "" {
			env = trustEnv(env, run.TrustBundle, run.NodeCACert)
		}
	} else if credential && run.Proxy != "" {
		fmt.Fprintf(os.Stderr, "agentctl: WARNING: --no-proxy with credential identity: the proxy will not know this run\n")
	}
	if mcpConfigPath != "" {
		proxy := run.Proxy
		if noProxy {
			proxy = ""
		}
		bundle, caCert := "", ""
		if proxy != "" {
			bundle, caCert = run.TrustBundle, run.NodeCACert
		}
		rewritten, err := prepareMCP(api, mcpConfigPath, proxy, bundle, caCert)
		if err != nil {
			return 0, err
		}
		defer os.Remove(rewritten)
		env = append(env, "CLOVISOR_MCP_CONFIG="+rewritten)
		fmt.Fprintf(os.Stderr, "agentctl: MCP config for the harness: $CLOVISOR_MCP_CONFIG (%s)\n", rewritten)
	}

	// Terminal signals (Ctrl-C, Ctrl-\) already reach the child through the
	// foreground process group; agentctl ignores them so it survives to
	// report the exit. Signals aimed at agentctl alone are forwarded.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	fwd := make(chan os.Signal, 1)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(fwd)

	var cmd *exec.Cmd
	if credential {
		cmd = exec.Command(path, args[1:]...)
		cmd.Args[0] = args[0]
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = env
		if err := cmd.Start(); err != nil {
			return 0, fmt.Errorf("failed to start %s: %w", args[0], err)
		}
	} else if cmd, err = startInRun(api, path, args, env); err != nil {
		return 0, err
	}

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

// redactProxy hides a proxy URL's credential for display.
func redactProxy(p string) string {
	u, err := url.Parse(p)
	if err != nil || u.User == nil {
		return p
	}
	return u.Redacted()
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

// showStatus prints the node's enforcement state.
func showStatus() error {
	api, err := clovisor.DialRunAPI(socketPath())
	if err != nil {
		return err
	}
	defer api.Close()
	s, err := api.Status()
	if err != nil {
		return err
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Printf("Identity      %s\n", s.Identity)
	fmt.Printf("Transparent   %s\n", s.Transparent)
	if s.Transparent != clovisor.TransparentOff {
		h := yes(s.Healthy)
		if !s.Healthy {
			h = "no: " + s.HealthError
			if s.Transparent == clovisor.TransparentEnforce {
				h += " (connects from runs are refused)"
			}
		}
		fmt.Printf("Healthy       %s\n", h)
	}
	envoy := yes(s.EnvoyReady)
	if s.EnvoyPID > 0 {
		envoy += fmt.Sprintf(" (pid %d, cgroup %s)", s.EnvoyPID, s.EnvoyCgroup)
	}
	fmt.Printf("Envoy ready   %s\n", envoy)
	gate := yes(s.ProxyGated)
	if s.ProxyGated {
		gate += fmt.Sprintf(" (%d node-local connects refused)", s.ProxyRefused)
	} else if s.ProxyGateWhy != "" {
		gate += ": " + s.ProxyGateWhy
	}
	fmt.Printf("Proxy gated   %s\n", gate)
	if s.Resolver != "" {
		fmt.Printf("Resolver      forwarding to %s\n", s.Resolver)
	}
	fmt.Printf("Active runs   %d\n", s.ActiveRuns)
	fmt.Printf("Lost events   %d (ring buffer full), %d suppressed (a run over its event budget)\n", s.LostEvents, s.SuppressedEvents)
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

// runsDir is where the node agent the client talks to writes timelines.
func runsDir() string {
	if p := os.Getenv("CLOVISOR_RUNS"); p != "" {
		return p
	}
	return clovisor.ClientDirs().Runs()
}

func socketPath() string {
	if p := os.Getenv("CLOVISOR_SOCKET"); p != "" {
		return p
	}
	return clovisor.ClientDirs().APISocket()
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
	dir := fs.String("dir", runsDir(), "directory of run timeline files")
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
	if strings.HasPrefix(tl.CgroupPath, clovisor.CredentialRunsDir+"/") {
		fmt.Printf("Run       %s (credential identity: no cgroup, no kernel audit)\n", tl.RunID)
	} else {
		fmt.Printf("Run       %s (cgroup %d, %s)\n", tl.RunID, tl.CgroupID, tl.CgroupPath)
	}
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
			if p.Tunnels > 0 {
				note += fmt.Sprintf(" opaque tunnels %d", p.Tunnels)
			}
			fmt.Printf("  %-46s x%-4d%s\n", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))), p.Requests, note)
			for _, u := range p.Paths {
				note := ""
				if u.Denied > 0 {
					note += fmt.Sprintf(" denied %d", u.Denied)
				}
				if u.WouldDeny > 0 {
					note += fmt.Sprintf(" would-deny %d", u.WouldDeny)
				}
				fmt.Printf("    %-7s %-37s x%-4d%s\n", u.Method, truncate(u.Path, 37), u.Requests, note)
			}
			if p.PathsDropped > 0 {
				fmt.Printf("    (%d more requests to paths past the per-run cap of %d)\n", p.PathsDropped, clovisor.MaxPaths)
			}
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
	return compileFilesFor(paths, policy.Options{Mode: policy.ExplicitProxy, Linux: linux})
}

func compileFilesFor(paths []string, opts policy.Options) (*policy.Compiled, error) {
	var ps []*policy.AgentProfile
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p, _, err := policy.ParseDocument(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if p == nil {
			continue // a ProfileCeiling: not part of the receipt
		}
		ps = append(ps, p)
	}
	c, diags := policy.Compile(opts, ps...)
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
	transparent := fs.String("transparent", "off", "the node's transparent mode: off, audit or enforce (Linux)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("give one or more profile files; pass every profile active on a node to see node-wide TLS posture")
	}
	t := clovisor.TransparentOptions{Mode: *transparent}
	mode := t.DeploymentMode()
	if *transparent != clovisor.TransparentOff && mode == policy.ExplicitProxy {
		return fmt.Errorf("--transparent must be off, audit or enforce")
	}
	c, err := compileFilesFor(fs.Args(), policy.Options{Mode: mode, Linux: *platform == "linux"})
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
	dir := fs.String("dir", runsDir(), "directory of run timeline files")
	profile := fs.String("profile", "", "profile file to check against (required)")
	all := fs.Bool("all", false, "check every finished run in -dir")
	transparent := fs.Bool("transparent", false, "replay as transparent enforce mode decides: DNS by name, UDP refused, non-TLS TCP by address")
	udpAllow := fs.String("udp-allow", "", "with --transparent: the node's -udp-allow list (comma-separated ip:port)")
	platform := platformFlag(fs)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *profile == "" {
		return fmt.Errorf("--profile is required")
	}
	opts := clovisor.CheckOptions{Transparent: *transparent}
	for _, f := range strings.Split(*udpAllow, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		a, err := netip.ParseAddrPort(f)
		if err != nil {
			return fmt.Errorf("--udp-allow: %w", err)
		}
		opts.UDPAllow = append(opts.UDPAllow, a)
	}
	c, err := compileFiles([]string{*profile}, *platform == "linux")
	if err != nil {
		return err
	}
	runs, err := loadRuns(*dir, *all, fs.Args())
	if err != nil {
		return err
	}
	rep := clovisor.CheckRunsWith(c.Profiles[0], runs, opts)
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
	dir := fs.String("dir", runsDir(), "directory of run timeline files")
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
	case "status":
		if err := showStatus(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
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
	case "pins":
		if err := pinsCommand(os.Args[2:]); err != nil {
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
