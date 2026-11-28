// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"flag"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	clovisor "github.com/clovisor/clovisor/libclovisor"
	log "github.com/sirupsen/logrus"
)

var (
	identity = flag.String("identity", "", "How runs are known: cgroup (Linux, kernel audit), credential (anywhere, a per-run proxy secret; a claim) "+
		"actor (Agent Substrate Actors, by their mTLS certificates, checked against Substrate) "+
		"or substrate (Actors behind Substrate's egress gateway, which calls ext_proc on -gateway-listen). Default: cgroup on Linux, credential elsewhere")
	rtDir    = flag.String("runtime-dir", "", "Directory for sockets and generated files (default /run/clovisor as root, a per-user directory otherwise)")
	stDir    = flag.String("state-dir", "", "Directory for timelines, the node CA and tool pins (default /var/lib/clovisor as root, a per-user directory otherwise)")
	bpfObj   = flag.String("bpf", "libclovisor/ebpf/agent_audit.o", "Path to the compiled audit BPF object (cgroup identity)")
	agentsCg = flag.String("agents-cgroup", clovisor.AgentsSubdir, "Name of the cgroup, below the cgroup v2 root, that runs live under (cgroup identity)")
	outDir   = flag.String("out", "", "Directory for per-run timeline files (default <state-dir>/runs)")
	socket   = flag.String("socket", "", "Unix socket for the run API used by agentctl (default <runtime-dir>/agent.sock)")
	policies = flag.String("policy-dir", clovisor.DefaultPolicyDir, "Directory of profiles and ceilings, root-owned when run as root; reloaded on SIGHUP")
	proxy    = flag.String("proxy-listen", "", "Enable the explicit proxy: Envoy listen address for runs, e.g. 127.0.0.1:18000")
	extSock  = flag.String("extproc-socket", "", "Unix socket where ext_proc serves Envoy (default <runtime-dir>/extproc.sock)")
	envoyCfg = flag.String("envoy-config", "", "Where to write the generated Envoy bootstrap (default <runtime-dir>/envoy.json)")
	envoyUID = flag.String("envoy-uids", defaultEnvoyUIDs(), "Comma-separated uids or user names Envoy runs as, admitted to ext_proc (root and the node agent's uid always are)")
	nonRun   = flag.Bool("proxy-non-run", false, "Let processes outside any run use the proxy")
	maxBody  = flag.Int("inspect-max-body", clovisor.DefaultMaxBody, "Largest request body, in bytes, the proxy checks for content rules or remote MCP; larger ones are refused")
	mcpAddr  = flag.String("mcp-listen", "", "Enable the local MCP gateway on this loopback address, e.g. 127.0.0.1:18100")
	caDir    = flag.String("ca-dir", "", "Node CA for TLS termination, key readable only by the node agent (default <state-dir>/ca)")
	upCA     = flag.String("envoy-upstream-ca", "", "System trust store as Envoy sees it, to verify origins behind termination (default: the host's)")
	transp   = flag.String("transparent", "off", "Transparent mode (needs -proxy-listen and cgroup identity): off; audit (record what enforce would do); "+
		"enforce (every TCP connect from a run goes to Envoy's transparent listener or is refused, also while the node agent is down)")
	tPort      = flag.Uint("transparent-port", clovisor.DefaultTransparentPort, "Transparent listener port, on 127.0.0.1 and ::1")
	tDNS       = flag.Uint("transparent-dns-port", clovisor.DefaultResolverPort, "Local resolver port, on 127.0.0.1 and ::1, where transparent mode sends runs' DNS")
	udpOK      = flag.String("udp-allow", "", "Comma-separated ip:port UDP destinations runs may reach in transparent mode (0.0.0.0:port: any loopback address); other UDP but DNS is refused")
	dnsUp      = flag.String("dns-upstream", "", "Comma-separated ip:port resolvers the local resolver forwards to (default: the nameservers in /etc/resolv.conf)")
	tStale     = flag.Duration("transparent-stale", clovisor.DefaultHeartbeatStale, "How long after the node agent stops connects are refused")
	uprobes    = flag.Bool("uprobes", false, "Record requests from the TLS plaintext of runs whose profile sets observe.tls_plaintext, through uprobes on OpenSSL, BoringSSL, GnuTLS and Go crypto/tls (cgroup identity; visibility only)")
	uprobeLibs = flag.String("uprobe-libs", "", "Comma-separated TLS libraries to probe with -uprobes (default: libssl and libgnutls in the usual library directories)")
	quic       = flag.Bool("quic", false, "Relay QUIC (UDP 443) from runs by the server name in its Initial, decided as TLS by name is (transparent enforce only); otherwise QUIC is refused and clients use TCP")
	quicP      = flag.Uint("quic-port", clovisor.DefaultQUICPort, "QUIC relay port, on 127.0.0.1 and ::1 (with -quic)")

	// Actor identity (milestone 7.3).
	actorCA     = flag.String("actor-ca", "", "Actor identity: the CA that issues Actors' certificates (PEM)")
	actorCert   = flag.String("actor-proxy-cert", "", "Actor identity: the proxy listener's certificate, which Actors verify (PEM)")
	actorKey    = flag.String("actor-proxy-key", "", "Actor identity: the proxy listener's key (PEM)")
	actorDomain = flag.String("actor-trust-domain", clovisor.DefaultActorTrustDomain, "Actor identity: the SPIFFE trust domain of Actor certificates")
	actorCheck  = flag.Duration("actor-check", clovisor.DefaultActorCheck, "Actor identity: how often live Actors are checked against Substrate, ending the runs of deleted ones")
	subAddr     = flag.String("substrate-api", "", "Actor identity: Substrate's Control API, host:port")
	subCA       = flag.String("substrate-ca", "", "Actor identity: the CA that verifies Substrate's API server (PEM)")
	subName     = flag.String("substrate-server-name", "", "Actor identity: the API server's name in its certificate, if not the address's host")
	subCert     = flag.String("substrate-cert", "", "Actor identity: the node agent's client certificate for Substrate's API (PEM), if it asks for one")
	subKey      = flag.String("substrate-key", "", "Actor identity: the key for -substrate-cert")
	subPlain    = flag.Bool("substrate-insecure", false, "Actor identity: reach Substrate's API in plaintext (tests only)")
	gwListen    = flag.String("gateway-listen", "", "Substrate identity: where ext_proc serves Substrate's egress gateway over TLS, e.g. 0.0.0.0:9443")
	gwCert      = flag.String("gateway-cert", "", "Substrate identity: ext_proc's certificate (PEM), which the gateway verifies; may hold the key too")
	gwKey       = flag.String("gateway-key", "", "Substrate identity: the key for -gateway-cert, if not in it")
	gwCA        = flag.String("gateway-client-ca", "", "Substrate identity: the CA of the gateway's client certificate (PEM)")
	gwPeers     = flag.String("gateway-peers", clovisor.SubstratePeer, "Substrate identity: comma-separated URI names a client certificate must carry one of")
	sbListen    = flag.String("sandbox-listen", "", "Substrate identity: take gVisor sandbox points from Clovisor's sandbox sinks over TLS here, e.g. 0.0.0.0:9444 (the -gateway-cert and -gateway-client-ca serve it)")
	sbPeers     = flag.String("sandbox-peers", clovisor.SandboxSinkPeer, "Substrate identity: comma-separated URI names a sink's client certificate must carry one of")
)

// defaultEnvoyUIDs is the uid of the official Envoy image's user when the
// node agent is root; a user's node agent runs Envoy as that user.
func defaultEnvoyUIDs() string {
	if os.Geteuid() == 0 {
		return "101"
	}
	return ""
}

func dirs() clovisor.Dirs {
	d := clovisor.DefaultDirs()
	if *rtDir != "" {
		d.Runtime = *rtDir
	}
	if *stDir != "" {
		d.State = *stDir
	}
	return d
}

func proxyAddr() netip.AddrPort { return addrFlag("-proxy-listen", *proxy) }

func addrFlag(name, v string) netip.AddrPort {
	if v == "" {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(v)
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	return ap
}

func addrList(name, s string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, f := range splitList(s) {
		out = append(out, addrFlag(name, f))
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// uids parses -envoy-uids: uids, or user names (milestone 7.2: the
// packaged unit names the clovisor-envoy user, whose uid varies).
func uids(s string) []uint32 {
	var out []uint32
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		u, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			usr, lerr := user.Lookup(f)
			if lerr != nil {
				log.Fatalf("-envoy-uids: %q is neither a uid nor a user: %v", f, lerr)
			}
			u, _ = strconv.ParseUint(usr.Uid, 10, 32)
		}
		out = append(out, uint32(u))
	}
	return out
}

func main() {
	flag.Parse()
	log.Info("Clovisor Node Agent starting...")

	// Create and initialize the node agent with BPF audit attached
	agent, err := clovisor.NewNodeAgentFromOptions(clovisor.NodeAgentOptions{
		Identity:        *identity,
		Dirs:            dirs(),
		BPFObjPath:      *bpfObj,
		AgentsCgroup:    *agentsCg,
		OutDir:          *outDir,
		SocketPath:      *socket,
		PolicyDir:       *policies,
		ProxyListen:     proxyAddr(),
		ExtProcSocket:   *extSock,
		EnvoyConfig:     *envoyCfg,
		EnvoyUIDs:       uids(*envoyUID),
		NonRunProxy:     *nonRun,
		MaxInspectBody:  *maxBody,
		MCPListen:       addrFlag("-mcp-listen", *mcpAddr),
		CADir:           *caDir,
		EnvoyUpstreamCA: *upCA,
		Transparent: clovisor.TransparentOptions{Mode: *transp, Port: uint16(*tPort), DNSPort: uint16(*tDNS), Stale: *tStale,
			UDPExceptions: addrList("-udp-allow", *udpOK), QUICPort: quicPort(*quic, *quicP),
			TLSCapture: *uprobes, TLSLibraries: splitList(*uprobeLibs)},
		DNSUpstreams:     splitList(*dnsUp),
		ActorCA:          *actorCA,
		ActorProxyCert:   *actorCert,
		ActorProxyKey:    *actorKey,
		ActorTrustDomain: *actorDomain,
		ActorCheck:       *actorCheck,
		Gateway: clovisor.GatewayTLS{Addr: addrFlag("-gateway-listen", *gwListen), CertFile: *gwCert, KeyFile: *gwKey,
			ClientCA: *gwCA, Peers: splitList(*gwPeers)},
		Sandbox: clovisor.GatewayTLS{Addr: addrFlag("-sandbox-listen", *sbListen), Peers: splitList(*sbPeers)},
		Substrate: clovisor.SubstrateOptions{Addr: *subAddr, CAFile: *subCA, ServerName: *subName,
			CertFile: *subCert, KeyFile: *subKey, Insecure: *subPlain},
	})
	// A policy that does not load is fatal at start: running without it
	// would silently leave runs unprofiled.
	if err != nil {
		log.Fatalf("Failed to create node agent: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Run the agent in a goroutine so we can wait for signals
	done := make(chan error)
	go func() {
		done <- agent.Run()
	}()

	for {
		select {
		case err := <-done:
			log.Infof("Agent finished: %v", err)
			return
		case sig := <-sigChan:
			if sig == syscall.SIGHUP {
				if err := agent.ReloadPolicy(); err != nil {
					log.Errorf("policy reload failed; keeping the policy in force: %v", err)
				}
				continue
			}
			log.Info("Shutdown signal received, stopping node agent...")
			agent.Stop()
			return
		}
	}
}

// quicPort is the relay's port with -quic, else 0 (no relay).
func quicPort(on bool, port uint) uint16 {
	if !on {
		return 0
	}
	return uint16(port)
}
