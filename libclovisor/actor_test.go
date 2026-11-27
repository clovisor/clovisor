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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/clovisor/clovisor/libclovisor/policy"
	"github.com/clovisor/clovisor/libclovisor/substrateapi"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

type leafOpts struct {
	uris     []string
	isCA     bool
	eku      []x509.ExtKeyUsage
	notAfter time.Time
}

// issue returns a leaf's PEM.
func (ca *testCA) issue(t *testing.T, o leafOpts) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if o.eku == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "actor"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: o.notAfter, ExtKeyUsage: o.eku,
		IsCA: o.isCA, BasicConstraintsValid: true}
	if o.isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	for _, u := range o.uris {
		pu, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, pu)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// xfcc is the header Envoy writes, with set_current_client_cert_details
// cert, chain and URI.
func xfcc(leaf []byte, uri string) string {
	// Percent-encoded, spaces as %20, as Envoy writes it.
	enc := strings.ReplaceAll(url.QueryEscape(string(leaf)), "+", "%20")
	return `Hash=abc;Cert="` + enc + `";Chain="` + enc + `";URI=` + uri
}

func spiffeActor(atespace, name string) string {
	return "spiffe://" + DefaultActorTrustDomain + "/worker-for-actor/" + atespace + "/" + name
}

func TestActorVerify(t *testing.T) {
	ca, other := newTestCA(t, "actor CA"), newTestCA(t, "other CA")
	v := &ActorVerifier{Roots: x509.NewCertPool(), TrustDomain: DefaultActorTrustDomain}
	v.Roots.AddCert(ca.cert)
	good := spiffeActor("team", "a1")
	leaf := ca.issue(t, leafOpts{uris: []string{good}})
	if ref, err := v.Verify(xfcc(leaf, good)); err != nil || ref != (ActorRef{"team", "a1"}) {
		t.Fatalf("good certificate: %v %v", ref, err)
	}
	// Envoy may leave base64's '+' unescaped: it must not become a space.
	raw := `Chain="` + strings.ReplaceAll(url.PathEscape(string(leaf)), "%2B", "+") + `"`
	if _, err := (&ActorVerifier{Roots: v.Roots, TrustDomain: DefaultActorTrustDomain}).Verify(raw); err != nil {
		t.Fatalf("chain with a literal '+': %v", err)
	}
	for name, c := range map[string]struct {
		h, want string
	}{
		"none":            {"", "no client certificate"},
		"other CA":        {xfcc(other.issue(t, leafOpts{uris: []string{good}}), good), "not from the Actor CA"},
		"a CA":            {xfcc(ca.issue(t, leafOpts{uris: []string{good}, isCA: true}), good), "a CA certificate"},
		"server only":     {xfcc(ca.issue(t, leafOpts{uris: []string{good}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}), good), "not from the Actor CA"},
		"expired":         {xfcc(ca.issue(t, leafOpts{uris: []string{good}, notAfter: time.Now().Add(-time.Second)}), good), "outside its validity"},
		"two URIs":        {xfcc(ca.issue(t, leafOpts{uris: []string{good, spiffeActor("team", "a2")}}), good), "2 URI names"},
		"no URI":          {xfcc(ca.issue(t, leafOpts{}), ""), "0 URI names"},
		"other domain":    {xfcc(ca.issue(t, leafOpts{uris: []string{"spiffe://evil.example/worker-for-actor/team/a1"}}), ""), "is not spiffe://"},
		"not an actor":    {xfcc(ca.issue(t, leafOpts{uris: []string{"spiffe://" + DefaultActorTrustDomain + "/ns/team/sa/x"}}), ""), "is not spiffe://"},
		"bad name":        {xfcc(ca.issue(t, leafOpts{uris: []string{spiffeActor("team", "A_1")}}), ""), "is not spiffe://"},
		"two elements":    {xfcc(leaf, good) + "," + xfcc(leaf, good), "2 elements"},
		"no certificate":  {"Hash=abc;URI=" + good, "carries no certificate"},
		"garbage in cert": {`Chain="not%20pem"`, "carries no certificate"},
	} {
		if _, err := v.Verify(c.h); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// fakeControl is Substrate's Control API, as far as Clovisor uses it.
type fakeControl struct {
	substrateapi.UnimplementedControlServer
	mu     sync.Mutex
	actors map[ActorRef]ActorInfo
	fail   bool
	calls  atomic.Int32
}

func (f *fakeControl) GetActor(_ context.Context, r *substrateapi.GetActorRequest) (*substrateapi.Actor, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, grpcstatus.Error(codes.Unavailable, "down")
	}
	a, ok := f.actors[ActorRef{r.GetActor().GetAtespace(), r.GetActor().GetName()}]
	if !ok {
		return nil, grpcstatus.Error(codes.NotFound, "no such actor")
	}
	return &substrateapi.Actor{
		Metadata:      &substrateapi.ResourceMetadata{Atespace: a.Atespace, Name: a.Name, Uid: a.UID},
		ActorTemplate: &substrateapi.ObjectRef{Atespace: a.Atespace, Name: a.Template},
		Status:        &substrateapi.ActorStatus{State: substrateapi.ActorState(substrateapi.ActorState_value["ACTOR_STATE_"+a.State])},
	}, nil
}

func (f *fakeControl) set(a ActorInfo) {
	f.mu.Lock()
	f.actors[a.ActorRef] = a
	f.mu.Unlock()
}

func (f *fakeControl) remove(r ActorRef) {
	f.mu.Lock()
	delete(f.actors, r)
	f.mu.Unlock()
}

func startFakeControl(t *testing.T) (*fakeControl, string) {
	t.Helper()
	f := &fakeControl{actors: map[ActorRef]ActorInfo{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	substrateapi.RegisterControlServer(srv, f)
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return f, ln.Addr().String()
}

// The Substrate client, over gRPC: the Actor's UID, template and state,
// NotFound as ErrActorNotFound, answers cached, failures not.
func TestSubstrateDirectory(t *testing.T) {
	f, addr := startFakeControl(t)
	f.set(ActorInfo{ActorRef: ActorRef{"team", "a1"}, UID: "u-1", Template: "researcher", State: "SUSPENDED"})
	dir, err := DialSubstrate(SubstrateOptions{Addr: addr, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := dir.Actor(ctx, ActorRef{"team", "a1"}, 0)
	if err != nil || a.UID != "u-1" || a.Template != "researcher" || a.State != "SUSPENDED" || a.Placed() {
		t.Fatalf("actor: %+v %v", a, err)
	}
	dir.Actor(ctx, ActorRef{"team", "a1"}, time.Hour)
	if n := f.calls.Load(); n != 1 {
		t.Errorf("%d calls for a cached Actor, want 1", n)
	}
	dir.Actor(ctx, ActorRef{"team", "a1"}, 0)
	if n := f.calls.Load(); n != 2 {
		t.Errorf("%d calls after asking afresh, want 2", n)
	}
	if _, err := dir.Actor(ctx, ActorRef{"team", "gone"}, 0); !errors.Is(err, ErrActorNotFound) {
		t.Errorf("missing Actor: %v", err)
	}
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	if _, err := dir.Actor(ctx, ActorRef{"team", "a2"}, time.Hour); err == nil || errors.Is(err, ErrActorNotFound) {
		t.Errorf("API down: %v", err)
	}
	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	f.set(ActorInfo{ActorRef: ActorRef{"team", "a2"}, UID: "u-2", State: "RUNNING"})
	if a, err := dir.Actor(ctx, ActorRef{"team", "a2"}, time.Hour); err != nil || !a.Placed() {
		t.Errorf("a failure was cached: %+v %v", a, err)
	}
	if _, err := DialSubstrate(SubstrateOptions{Addr: addr}); err == nil {
		t.Error("dialled Substrate with neither a CA nor plaintext asked for")
	}
}

const actorCeilings = `kind: ProfileCeiling
metadata: { name: researchers }
spec:
  appliesTo: { atespace: team, actorTemplate: researcher }
  default: narrow
---
kind: ProfileCeiling
metadata: { name: team }
spec:
  appliesTo: { atespace: team }
  default: g
`

// Actor identity through ext_proc: the certificate, then Substrate's view.
// The Actor's template and atespace choose its profile. Its run is its
// UID: across suspend and resume one timeline, and a new UID is a new run.
func TestActorIdentity(t *testing.T) {
	dir := t.TempDir()
	reg := NewRunRegistry()
	events := make(chan AuditEvent, 256)
	api, err := NewRunAPIServer(filepath.Join(dir, "agent.sock"), nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	api.Events = events
	var docs []string
	docs = append(docs, grantProfile, narrowProfile)
	docs = append(docs, strings.Split(actorCeilings, "---\n")...)
	api.SetPolicy(actorSet(t, docs...))
	go api.Serve()
	defer api.Close()

	f, addr := startFakeControl(t)
	d, err := DialSubstrate(SubstrateOptions{Addr: addr, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	api.EnableActors(d, time.Hour) // checked by hand below
	ca := newTestCA(t, "actor CA")
	xp := NewExtProcServer(api, "", events)
	xp.Actors = &ActorVerifier{Roots: x509.NewCertPool(), TrustDomain: DefaultActorTrustDomain}
	xp.Actors.Roots.AddCert(ca.cert)
	xp.Directory = d

	certFor := func(name string) string {
		u := spiffeActor("team", name)
		return xfcc(ca.issue(t, leafOpts{uris: []string{u}}), u)
	}
	r1, w1 := certFor("r1"), certFor("w1")
	f.set(ActorInfo{ActorRef: ActorRef{"team", "r1"}, UID: "u-r1", Template: "researcher", State: "RUNNING"})
	f.set(ActorInfo{ActorRef: ActorRef{"team", "w1"}, UID: "u-w1", Template: "writer", State: "RESUMING"})

	outer := map[string]interface{}{"source.address": "10.0.0.9:40000", "destination.address": "10.0.0.1:18443"}
	inner := map[string]interface{}{"source.address": "envoy://internal_client_address/", "destination.address": "envoy://mitm-0/"}
	type result struct {
		ok   bool
		code int
		msg  string
		run  string
	}
	send := func(attrs map[string]interface{}, method, host string, h map[string]string) result {
		t.Helper()
		req, hh := reqWith(attrs, method, host, "", h)
		resp, _ := xp.onHeaders(context.Background(), req, hh)
		ir := resp.GetImmediateResponse()
		if ir == nil {
			return result{ok: true}
		}
		var body map[string]interface{}
		json.Unmarshal(ir.GetBody(), &body)
		msg, _ := body["message"].(string)
		run, _ := body["run"].(string)
		return result{code: int(ir.GetStatus().GetCode()), msg: msg, run: run}
	}
	connect := func(cert, host string) result {
		return send(outer, "CONNECT", host+":443", map[string]string{"x-forwarded-client-cert": cert})
	}

	// The template's ceiling for r1, the atespace's for w1 (RESUMING is
	// placed, as Substrate says).
	for _, c := range []struct {
		who, cert, host string
		want            bool
	}{
		{"r1", r1, "github.com", true},
		{"r1", r1, "pypi.org", false},
		{"w1", w1, "github.com", true},
		{"w1", w1, "pypi.org", true},
	} {
		if got := connect(c.cert, c.host); got.ok != c.want {
			t.Errorf("%s to %s: %+v", c.who, c.host, got)
		}
	}
	runR1, _, ok := api.ActorRun("u-r1")
	if !ok {
		t.Fatal("no run for r1")
	}
	if r := connect(r1, "pypi.org"); r.run != runR1 {
		t.Errorf("r1's refusal names run %q, want %q", r.run, runR1)
	}

	// Inside a terminated tunnel, the chain Envoy carried from the CONNECT
	// counts, and a client's own header does not.
	if r := send(inner, "GET", "github.com", map[string]string{hdrXFCC: r1, hdrConnect: "github.com:443"}); !r.ok {
		t.Errorf("inner hop with Envoy's chain: %+v", r)
	}
	if r := send(inner, "GET", "github.com", map[string]string{"x-forwarded-client-cert": r1, hdrConnect: "github.com:443"}); r.ok {
		t.Error("inner hop trusted a client x-forwarded-client-cert")
	}

	// Refusals: no certificate, an Actor Substrate lacks, Substrate down.
	if r := connect("", "github.com"); r.ok || r.code != 403 || !strings.Contains(r.msg, "no client certificate") {
		t.Errorf("no certificate: %+v", r)
	}
	if r := connect(certFor("ghost"), "github.com"); r.ok || !strings.Contains(r.msg, "does not exist") {
		t.Errorf("unknown Actor: %+v", r)
	}
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	if r := connect(r1, "github.com"); r.ok || r.code != 503 {
		t.Errorf("Substrate down: %+v", r)
	}
	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()

	// Suspended, refused, in its own timeline; resumed, possibly on
	// another Worker, the same run.
	f.set(ActorInfo{ActorRef: ActorRef{"team", "r1"}, UID: "u-r1", Template: "researcher", State: "SUSPENDED"})
	if r := connect(r1, "github.com"); r.ok || r.run != runR1 || !strings.Contains(r.msg, "SUSPENDED") {
		t.Errorf("suspended: %+v", r)
	}
	api.checkActors(d)
	f.set(ActorInfo{ActorRef: ActorRef{"team", "r1"}, UID: "u-r1", Template: "researcher", State: "RUNNING"})
	connect(r1, "github.com")
	if id, _, _ := api.ActorRun("u-r1"); id != runR1 {
		t.Fatalf("resumed Actor has run %q, want %q", id, runR1)
	}

	// Deleted and created again: the old run ends, the new UID has its own.
	f.set(ActorInfo{ActorRef: ActorRef{"team", "r1"}, UID: "u-r1b", Template: "researcher", State: "RUNNING"})
	connect(r1, "github.com")
	runR1b, _, ok := api.ActorRun("u-r1b")
	if _, _, old := api.ActorRun("u-r1"); !ok || runR1b == runR1 || old {
		t.Fatalf("recreated Actor: new run %q (%v), old run still live %v", runR1b, ok, old)
	}
	// Deleted: its run ends at the next check.
	runW1, _, _ := api.ActorRun("u-w1")
	f.remove(ActorRef{"team", "w1"})
	api.checkActors(d)
	if _, _, ok := api.ActorRun("u-w1"); ok {
		t.Fatal("run of a deleted Actor still live")
	}

	// Runs here come only from Actors.
	rc, err := DialRunAPI(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := rc.Create([]string{"x"}, dir, ""); err == nil || !strings.Contains(err.Error(), "Actors") {
		t.Errorf("create with Actor identity: %v", err)
	}

	rec, err := NewCredentialRunRecorder(filepath.Join(dir, "runs"), reg)
	if err != nil {
		t.Fatal(err)
	}
	tls := map[string]*RunTimeline{}
	for len(events) > 0 {
		got, err := rec.Handle(<-events)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			tls[got.RunID] = got
		}
	}
	tr, tw := tls[runR1], tls[runW1]
	if tr == nil || tw == nil {
		t.Fatalf("finished timelines: %v", tls)
	}
	if tr.Actor == nil || tr.Actor.UID != "u-r1" || tr.Actor.Template != "researcher" || !strings.Contains(tr.EndReason, "created again") {
		t.Errorf("r1's timeline: actor %+v, end %q", tr.Actor, tr.EndReason)
	}
	var suspended bool
	for _, e := range tr.Events {
		if e.Type == "http" && strings.Contains(e.Reason, "SUSPENDED") {
			suspended = true
		}
	}
	if !suspended {
		t.Error("r1's timeline lacks the refusal while it was suspended")
	}
	if !strings.Contains(tw.EndReason, "deleted") || tw.Actor.State != "RESUMING" {
		t.Errorf("w1's timeline: end %q, actor %+v", tw.EndReason, tw.Actor)
	}
}

func actorSet(t *testing.T, docs ...string) *policy.Set {
	t.Helper()
	var ps []*policy.AgentProfile
	var cs []*policy.ProfileCeiling
	for _, d := range docs {
		p, c, err := policy.ParseDocument([]byte(d))
		if err != nil {
			t.Fatal(err)
		}
		if p != nil {
			ps = append(ps, p)
		}
		if c != nil {
			cs = append(cs, c)
		}
	}
	set, diags := policy.NewSet(policy.Options{Actors: true}, ps, cs, nil, nil)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	return set
}
