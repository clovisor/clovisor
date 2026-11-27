// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestActors runs Actor identity end to end (milestone 7.3): Actors,
// played by curl with their certificates, reach the node agent's Envoy
// over mTLS; Substrate's Control API is a fake the test sets Actors in.
// The Actor's template and atespace choose its profile, a suspended
// Actor is refused, and its run is its UID until Substrate deletes it.
func TestActors(t *testing.T) {
	docker := strings.Fields(os.Getenv("DOCKER"))
	if len(docker) == 0 {
		docker = []string{"docker"}
	}
	if _, err := exec.LookPath(docker[0]); err != nil {
		t.Skip("docker not found")
	}
	var tag [4]byte
	rand.Read(tag[:])
	e := &env{t: t, docker: docker, tag: fmt.Sprintf("a%x", tag), dir: t.TempDir()}
	if err := os.Chmod(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.build()
	e.pki()
	e.actorPKI()
	e.startActors()

	put := func(name, uid, template, state string) {
		t.Helper()
		body := fmt.Sprintf(`{"uid":%q,"template":%q,"state":%q}`, uid, template, state)
		if out, errOut, err := e.sh(`curl -sf -X PUT -d '` + body + `' http://127.0.0.1:19001/actors/team/` + name); err != nil {
			t.Fatalf("set Actor %s: %v %s%s", name, err, out, errOut)
		}
	}
	del := func(name string) {
		t.Helper()
		if _, errOut, err := e.sh(`curl -sf -X DELETE http://127.0.0.1:19001/actors/team/` + name); err != nil {
			t.Fatalf("delete Actor %s: %v %s", name, err, errOut)
		}
	}
	// as fetches path as an Actor: the CONNECT's status and the request's.
	as := func(cert, path string, extra ...string) string {
		t.Helper()
		out, _, _ := e.sh(`curl -sS -o /dev/null -w "%{http_connect} %{http_code}" --proxy https://127.0.0.1:18443 ` +
			`--proxy-cacert /it/actors/proxy-ca.crt ` + certArgs(cert) + strings.Join(extra, " ") +
			` --cacert /run/clovisor/ca-bundle.pem https://origin.test/` + path + ` 2>/dev/null`)
		return strings.TrimSpace(out)
	}

	put("r1", "u-r1", "researcher", "RUNNING")
	put("w1", "u-w1", "writer", "RESUMING")

	t.Run("profile-by-template", func(t *testing.T) {
		for _, c := range []struct{ who, path, want string }{
			{"r1", "allowed", "200 200"},
			{"r1", "headers", "200 403"}, // the researchers' ceiling: ac-narrow
			{"w1", "headers", "200 200"}, // the atespace's: ac
			{"w1", "secret", "200 403"},
		} {
			if got := as(c.who, c.path); got != c.want {
				t.Errorf("%s %s: %q, want %q", c.who, c.path, got, c.want)
			}
		}
	})

	t.Run("identity", func(t *testing.T) {
		// No certificate, or one from another CA: no TLS, so no CONNECT.
		for _, cert := range []string{"", "evil"} {
			if got := as(cert, "allowed"); got != "000 000" {
				t.Errorf("certificate %q: %q, want the handshake refused", cert, got)
			}
		}
		// A valid certificate for an Actor Substrate does not have.
		if got := as("ghost", "allowed"); got != "403 000" {
			t.Errorf("unknown Actor: %q", got)
		}
		// A client's own x-forwarded-client-cert is replaced by Envoy's:
		// r1 claiming w1's chain is still r1.
		w1, _ := os.ReadFile(filepath.Join(e.dir, "actors", "w1.crt"))
		forged := `"x-forwarded-client-cert: Chain=\"` + strings.ReplaceAll(url.QueryEscape(string(w1)), "+", "%20") + `\";URI=spiffe://substrate-actor.local/worker-for-actor/team/w1"`
		if got := as("r1", "headers", "--proxy-header "+forged, "-H "+forged); got != "200 403" {
			t.Errorf("r1 with a forged header: %q, want r1's refusal", got)
		}
	})

	t.Run("lifecycle", func(t *testing.T) {
		put("r1", "u-r1", "researcher", "SUSPENDED")
		if got := as("r1", "allowed"); got != "403 000" {
			t.Errorf("suspended: %q", got)
		}
		put("r1", "u-r1", "researcher", "RUNNING") // resumed, perhaps on another Worker
		time.Sleep(1500 * time.Millisecond)        // past a check, which sees it RUNNING again
		if got := as("r1", "allowed"); got != "200 200" {
			t.Errorf("resumed: %q", got)
		}
		del("w1")
		del("r1")
		time.Sleep(2500 * time.Millisecond) // a check ends both runs
		runs := e.actorRuns()
		r1, w1 := runs["team/r1"], runs["team/w1"]
		if len(r1) != 1 || len(w1) != 1 {
			log, _, _ := e.sh("cat /var/log/node-agent.log")
			t.Fatalf("want one run each for r1 (across suspend and resume) and w1, have %v:\n%s", runs, log)
		}
		expect(t, e.timeline(w1[0]), `"uid": "u-w1"`, `"template": "writer"`, `"end_reason": "the Actor was deleted"`, `"/headers"`, `"/secret"`)
		expect(t, e.timeline(r1[0]), `"uid": "u-r1"`, `"template": "researcher"`, "SUSPENDED")
		shown, _, _ := e.sh("/it/bin/agentctl events " + r1[0])
		expect(t, shown, "Agent Substrate Actor team/r1, uid u-r1, template researcher")
	})
}

// certArgs gives curl an Actor's certificate for the proxy, if any.
func certArgs(name string) string {
	if name == "" {
		return ""
	}
	return "--proxy-cert /it/actors/" + name + ".crt --proxy-key /it/actors/" + name + ".key "
}

var actorRunRE = regexp.MustCompile(`run api: run ([0-9a-f]+) for Actor ([a-z0-9-]+/[a-z0-9-]+) \(uid`)

// actorRuns lists the runs the node agent started per Actor.
func (e *env) actorRuns() map[string][]string {
	out, _, _ := e.sh("cat /var/log/node-agent.log")
	runs := map[string][]string{}
	for _, m := range actorRunRE.FindAllStringSubmatch(out, -1) {
		runs[m[2]] = append(runs[m[2]], m[1])
	}
	return runs
}

// actorPKI makes the Actor CA and its Actors' certificates (r1, w1, ghost,
// whom Substrate does not have), one from another CA (evil, claiming r1),
// and the proxy listener's certificate from a CA of its own.
func (e *env) actorPKI() {
	t := e.t
	dir := filepath.Join(e.dir, "actors")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	newCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	write := func(name, typ string, der []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	issue := func(name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl.SerialNumber = big.NewInt(now.UnixNano())
		tmpl.NotBefore, tmpl.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kder, _ := x509.MarshalECPrivateKey(key)
		write(name+".crt", "CERTIFICATE", der)
		write(name+".key", "EC PRIVATE KEY", kder)
	}
	actorCA, actorKey := newCA("Actor CA")
	evilCA, evilKey := newCA("another CA")
	proxyCA, proxyKey := newCA("proxy CA")
	write("ca.crt", "CERTIFICATE", actorCA.Raw)
	write("proxy-ca.crt", "CERTIFICATE", proxyCA.Raw)
	actor := func(name string) *x509.Certificate {
		u, _ := url.Parse("spiffe://substrate-actor.local/worker-for-actor/team/" + name)
		return &x509.Certificate{Subject: pkix.Name{CommonName: name}, URIs: []*url.URL{u},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	}
	for _, n := range []string{"r1", "w1", "ghost"} {
		issue(n, actorCA, actorKey, actor(n))
	}
	issue("evil", evilCA, evilKey, actor("r1"))
	issue("proxy", proxyCA, proxyKey, &x509.Certificate{Subject: pkix.Name{CommonName: "proxy"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
}

// startActors brings up the origin, the agent container with the fake
// Substrate and the node agent with Actor identity, and Envoy.
func (e *env) startActors() {
	t := e.t
	t.Cleanup(e.cleanup)
	e.run("network", "create", e.name("net"))
	e.run("volume", "create", e.name("run"))
	e.startOrigin()
	e.run("run", "-d", "--name", e.name("agent"), "--network", e.name("net"),
		"-v", filepath.Join(e.dir, "bin")+":/it/bin:ro", "-v", filepath.Join(e.dir, "origin", "ca.crt")+":/it/test-ca.crt:ro",
		"-v", filepath.Join(e.dir, "actors")+":/it/actors:ro", "-v", e.name("run")+":/run/clovisor",
		agentImage, "sleep", "infinity")
	if _, errOut, err := e.sh("mkdir -p /etc/clovisor"); err != nil {
		t.Fatal(errOut)
	}
	e.run("cp", "policy-actors", e.name("agent")+":/etc/clovisor/policy")
	if out, errOut, err := e.sh(`set -e
chown -R root:root /etc/clovisor && chmod 755 /etc/clovisor/policy && chmod 644 /etc/clovisor/policy/*
cat /etc/ssl/certs/ca-certificates.crt /it/test-ca.crt > /run/clovisor/upstream.pem`); err != nil {
		t.Fatalf("prepare agent: %v\n%s%s", err, out, errOut)
	}
	e.run("exec", "-d", e.name("agent"), "sh", "-c", "/it/bin/fakesubstrate > /var/log/fakesubstrate.log 2>&1")
	e.run("exec", "-d", e.name("agent"), "sh", "-c",
		"/it/bin/node-agent -identity actor -policy-dir /etc/clovisor/policy -proxy-listen 127.0.0.1:18443 "+
			"-envoy-upstream-ca /run/clovisor/upstream.pem -actor-ca /it/actors/ca.crt "+
			"-actor-proxy-cert /it/actors/proxy.crt -actor-proxy-key /it/actors/proxy.key "+
			"-substrate-api 127.0.0.1:19000 -substrate-insecure -actor-check 1s > /var/log/node-agent.log 2>&1")
	if out, errOut, err := e.sh(`for i in $(seq 50); do [ -S /run/clovisor/agent.sock ] && [ -f /run/clovisor/envoy.json ] && exit 0; sleep 0.1; done
cat /var/log/node-agent.log /var/log/fakesubstrate.log; exit 1`); err != nil {
		t.Fatalf("node agent did not start: %v\n%s%s", err, out, errOut)
	}
	e.run("run", "-d", "--name", e.name("envoy"), "--network", "container:"+e.name("agent"),
		"-v", e.name("run")+":/run/clovisor", EnvoyImage, "-c", "/run/clovisor/envoy.json", "-l", "warn")
	// Up once a connection gets as far as the TLS handshake.
	if out, errOut, err := e.sh(`for i in $(seq 100); do curl -s -o /dev/null https://127.0.0.1:18443/; [ $? -ne 7 ] && exit 0; sleep 0.1; done; exit 1`); err != nil {
		logs, _ := e.dockerCmd("logs", e.name("envoy")).CombinedOutput()
		t.Fatalf("Envoy did not come up: %v\n%s%s\n%s", err, out, errOut, logs)
	}
}
