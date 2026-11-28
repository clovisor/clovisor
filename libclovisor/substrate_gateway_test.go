// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// The gateway's profile reads bodies for content rules on one host.
const gatewayContentProfile = `kind: AgentProfile
metadata: { name: gcx }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: gh, to: { fqdn: ["github.com"], ports: [443] }, action: allow }
      - { name: up, to: { fqdn: ["upload.example"], ports: [443] }, action: allow }
      - { name: hold, to: { fqdn: ["ask.example"], ports: [443] }, action: ask }
  content:
    - { name: keys, regex: "AKIA[0-9A-Z]{16}", action: deny, to: { fqdn: ["upload.example"] } }
`

const gatewayCeilings = `kind: ProfileCeiling
metadata: { name: team }
spec:
  appliesTo: { atespace: team }
  allow: [gcx]
  default: gcx
`

func TestSubstrateGateway(t *testing.T) {
	dir := t.TempDir()
	reg := NewRunRegistry()
	events := make(chan AuditEvent, 256)
	api, err := NewRunAPIServer(filepath.Join(dir, "agent.sock"), nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	api.Events = events
	api.SetPolicy(actorSet(t, gatewayContentProfile, gatewayCeilings))
	go api.Serve()
	defer api.Close()

	f, addr := startFakeControl(t)
	d, err := DialSubstrate(SubstrateOptions{Addr: addr, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	api.EnableActors(d, time.Hour)
	xp := NewExtProcServer(api, "", events)
	xp.Gateway = &SubstrateGateway{}
	xp.Directory = d
	xp.Asks = NewAskQueue() // as the node agent has
	f.set(ActorInfo{ActorRef: ActorRef{"team", "r1"}, UID: "u-r1", Template: "researcher", State: "RUNNING"})

	// What Substrate's Envoy sends on the MITM chain.
	attrs := func(actor, dialed string) map[string]interface{} {
		a := map[string]interface{}{"source.address": "envoy://internal_client_address/", "destination.address": "envoy://mitm_listener/"}
		if actor != "" {
			a[SubstrateActorAttr] = actor
		}
		if dialed != "" {
			a[SubstrateDialedAttr] = dialed
		}
		return a
	}
	r1 := spiffeActor("team", "r1")
	type result struct {
		ok   bool
		code int
		msg  string
		run  string
	}
	send := func(a map[string]interface{}, method, host string, h map[string]string, body bool) result {
		t.Helper()
		req, hh := reqWith(a, method, host, "/x", h)
		hh.EndOfStream = !body
		resp, _ := xp.onHeaders(context.Background(), req, hh)
		ir := resp.GetImmediateResponse()
		if ir == nil {
			return result{ok: true}
		}
		var m map[string]interface{}
		json.Unmarshal(ir.GetBody(), &m)
		msg, _ := m["message"].(string)
		run, _ := m["run"].(string)
		return result{code: int(ir.GetStatus().GetCode()), msg: msg, run: run}
	}

	if r := send(attrs(r1, "140.82.112.3:443"), "GET", "github.com", nil, false); !r.ok {
		t.Fatalf("allowed request refused: %+v", r)
	}
	runID, _, ok := api.ActorRun("u-r1")
	if !ok {
		t.Fatal("no run for the Actor")
	}
	for _, c := range []struct {
		what, host, dialed string
		code               int
		msg                string
	}{
		{"a host its profile denies", "pypi.org", "151.101.0.223:443", 403, ""},
		// The port is the dialed one: the Host's is never checked.
		{"the dialed port, not the Host's", "github.com:443", "140.82.112.3:8443", 403, ""},
		{"no dialed address", "github.com", "", 503, "dialed"},
	} {
		r := send(attrs(r1, c.dialed), "GET", c.host, nil, false)
		if r.ok || r.code != c.code || !strings.Contains(r.msg, c.msg) {
			t.Errorf("%s: %+v", c.what, r)
		}
	}
	if r := send(attrs(r1, "140.82.112.3:443"), "GET", "pypi.org", nil, false); r.run != runID {
		t.Errorf("refusal names run %q, want %q", r.run, runID)
	}

	// Identity is Envoy's attribute only. Clovisor's own headers, which
	// its Envoy writes but Substrate's does not, are the Actor's here.
	forged := map[string]string{hdrXFCC: "x", "x-forwarded-client-cert": "x", "proxy-authorization": "Basic eDp4",
		hdrConnect: "pypi.org:443", hdrClient: "10.0.0.1:1,10.0.0.2:2", hdrOrigDst: "10.9.9.9:443"}
	if r := send(attrs("", "140.82.112.3:443"), "GET", "github.com", forged, false); r.ok || r.code != 403 || !strings.Contains(r.msg, "no Actor identity") {
		t.Errorf("no identity attribute: %+v", r)
	}
	if r := send(attrs(r1, "140.82.112.3:443"), "GET", "github.com", forged, false); !r.ok {
		t.Errorf("Clovisor's headers from the Actor changed the decision: %+v", r)
	}
	for what, id := range map[string]string{
		"an unknown Actor":     spiffeActor("team", "ghost"),
		"another trust domain": "spiffe://cluster.local/worker-for-actor/team/r1",
		"a workload ID":        "spiffe://cluster.local/ns/team/sa/default",
	} {
		if r := send(attrs(id, "140.82.112.3:443"), "GET", "github.com", nil, false); r.ok || r.code != 403 {
			t.Errorf("%s: %+v", what, r)
		}
	}

	// Bodies are not sent to Clovisor: what needs one is refused, and a
	// request with none, or to a host no body rule covers, is not.
	if r := send(attrs(r1, "10.0.0.5:443"), "POST", "upload.example", nil, true); r.ok || r.code != 403 || !strings.Contains(r.msg, "does not send") {
		t.Errorf("body for content rules: %+v", r)
	}
	if r := send(attrs(r1, "10.0.0.5:443"), "GET", "upload.example", nil, false); !r.ok {
		t.Errorf("no body, content rules: %+v", r)
	}
	if r := send(attrs(r1, "140.82.112.3:443"), "POST", "github.com", nil, true); !r.ok {
		t.Errorf("body, no content rules: %+v", r)
	}

	// An ask cannot be held: the gateway waits 2s.
	if r := send(attrs(r1, "10.0.0.6:443"), "GET", "ask.example", nil, false); r.ok || r.code != 403 || !strings.Contains(r.msg, "cannot wait") {
		t.Errorf("ask: %+v", r)
	}

	// Suspended: refused, recorded in its run.
	f.set(ActorInfo{ActorRef: ActorRef{"team", "r1"}, UID: "u-r1", Template: "researcher", State: "SUSPENDED"})
	time.Sleep(InnerActorMaxAge + 100*time.Millisecond)
	if r := send(attrs(r1, "140.82.112.3:443"), "GET", "github.com", nil, false); r.ok || r.run != runID || !strings.Contains(r.msg, "SUSPENDED") {
		t.Errorf("suspended: %+v", r)
	}
	f.remove(ActorRef{"team", "r1"})
	api.checkActors(d)

	rec, err := NewCredentialRunRecorder(filepath.Join(dir, "runs"), reg)
	if err != nil {
		t.Fatal(err)
	}
	var tl *RunTimeline
	for len(events) > 0 {
		got, err := rec.Handle(<-events)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil && got.RunID == runID {
			tl = got
		}
	}
	if tl == nil || tl.Actor == nil || tl.Actor.UID != "u-r1" {
		t.Fatalf("timeline: %+v", tl)
	}
	var sawPort bool
	for _, e := range tl.Events {
		if e.Type == "http" && e.OrigDst == "140.82.112.3:8443" && e.DstPort == 8443 {
			sawPort = true
		}
	}
	if !sawPort {
		t.Error("timeline lacks the request decided on its dialed port")
	}
}

// pemPair issues a certificate and key, as PEM in one file, the way
// Kubernetes pod certificates are written.
func pemPair(t *testing.T, ca *testCA, dir, name string, dns []string, uris []string, eku x509.ExtKeyUsage) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{eku},
		DNSNames: dns}
	for _, u := range uris {
		pu, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, pu)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	b := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})...)
	p := filepath.Join(dir, name+".pem")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGatewayListener(t *testing.T) {
	dir := t.TempDir()
	serving, podid := newTestCA(t, "servicedns"), newTestCA(t, "podidentity")
	caFile := filepath.Join(dir, "podidentity.pem")
	os.WriteFile(caFile, podid.pem, 0o644)
	srv := pemPair(t, serving, dir, "server", []string{"clovisor.clovisor-system.svc"}, nil, x509.ExtKeyUsageServerAuth)

	api, err := NewRunAPIServer(filepath.Join(dir, "agent.sock"), nil, NewRunRegistry())
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	xp := NewExtProcServer(api, "", make(chan AuditEvent, 16))
	xp.Gateway = &SubstrateGateway{}
	if err := xp.ListenGateway(GatewayTLS{Addr: netip.MustParseAddrPort("127.0.0.1:0"), CertFile: srv, ClientCA: caFile}); err != nil {
		t.Fatal(err)
	}
	go xp.Serve()
	defer xp.Close()
	addr := xp.ln.Addr().String()

	call := func(client string, alpn ...bool) error {
		t.Helper()
		roots := x509.NewCertPool()
		roots.AddCert(serving.cert)
		cfg := &tls.Config{RootCAs: roots, ServerName: "clovisor.clovisor-system.svc", MinVersion: tls.VersionTLS13}
		if client != "" {
			c, err := tls.LoadX509KeyPair(client, client)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Certificates = []tls.Certificate{c}
		}
		opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(cfg))}
		if len(alpn) > 0 && !alpn[0] {
			// As Substrate's Envoy cluster: TLS with no ALPN.
			opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(ctx context.Context, a string) (net.Conn, error) {
					return (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", a)
				})}
		}
		conn, err := grpc.NewClient(addr, opts...)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
		if err != nil {
			return err
		}
		req, hh := reqWith(map[string]interface{}{SubstrateDialedAttr: "10.0.0.1:443"}, "GET", "github.com", "/", nil)
		req.Request = &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: hh}
		if err := st.Send(req); err != nil {
			return err
		}
		_, err = st.Recv()
		return err
	}

	egress := pemPair(t, podid, dir, "egress", nil, []string{SubstratePeer}, x509.ExtKeyUsageClientAuth)
	if err := call(egress); err != nil {
		t.Fatalf("Substrate's gateway: %v", err)
	}
	if err := call(egress, false); err != nil {
		t.Fatalf("Substrate's gateway, no ALPN: %v", err)
	}
	other := pemPair(t, podid, dir, "other", nil, []string{"spiffe://cluster.local/ns/team/sa/default"}, x509.ExtKeyUsageClientAuth)
	if err := call(other, false); err == nil {
		t.Error("another workload's certificate was admitted, no ALPN")
	}
	if err := call(other); err == nil {
		t.Error("another workload's certificate was admitted")
	}
	stranger := pemPair(t, newTestCA(t, "stranger"), dir, "stranger", nil, []string{SubstratePeer}, x509.ExtKeyUsageClientAuth)
	if err := call(stranger); err == nil {
		t.Error("a certificate from another CA was admitted")
	}
	if err := call(""); err == nil {
		t.Error("a client with no certificate was admitted")
	}
}
