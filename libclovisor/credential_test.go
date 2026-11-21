// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// Credential identity end to end, without kernel features: the run API
// hands out a proxy URL with the run's secret, ext_proc knows the run by
// it on both hops, and the recorder writes the timeline from the run
// API's own start and end events.
func TestCredentialIdentity(t *testing.T) {
	dir := t.TempDir()
	reg := NewRunRegistry()
	events := make(chan AuditEvent, 64)
	api, err := NewRunAPIServer(filepath.Join(dir, "agent.sock"), nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	api.ProxyURL, api.Events = "http://127.0.0.1:18000", events
	go api.Serve()
	defer api.Close()

	rc, err := DialRunAPI(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	run, err := rc.Create([]string{"agent", "task"}, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(run.Proxy)
	if err != nil || run.Identity != "credential" || run.CgroupID != 0 || u.User == nil {
		t.Fatalf("create: %+v", run)
	}
	if u.User.Username() != RunPrefix+run.RunID || u.Host != "127.0.0.1:18000" {
		t.Fatalf("proxy URL %s", run.Proxy)
	}
	if err := rc.Attach(0); err == nil || !strings.Contains(err.Error(), "credential identity") {
		t.Fatalf("attach with credential identity: %v", err)
	}
	pass, _ := u.User.Password()
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String()))
	if dec, _ := url.PathUnescape(u.User.String()); dec != u.User.Username()+":"+pass {
		t.Fatalf("userinfo %q", u.User.String())
	}

	xp := NewExtProcServer(api, "", events)
	outer := map[string]interface{}{"source.address": "127.0.0.1:40000", "destination.address": "127.0.0.1:18000"}
	allowed := func(attrs map[string]interface{}, method, auth, path string, h map[string]string) (bool, string) {
		req, hh := reqWith(attrs, method, auth, path, h)
		resp, _ := xp.onHeaders(context.Background(), req, hh)
		ir := resp.GetImmediateResponse()
		if ir == nil {
			return true, ""
		}
		var body map[string]interface{}
		json.Unmarshal(ir.GetBody(), &body)
		return false, body["message"].(string)
	}
	if ok, _ := allowed(outer, "CONNECT", "github.com:443", "", map[string]string{"proxy-authorization": basic}); !ok {
		t.Fatal("run's own credential refused")
	}
	for name, h := range map[string]map[string]string{
		"none":         nil,
		"wrong token":  {"proxy-authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(RunPrefix+run.RunID+":nope"))},
		"other run id": {"proxy-authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(RunPrefix+"other:"+pass))},
		// Only Envoy's inner hop may carry the credential in x-clovisor-cred.
		"forged inner header": {hdrCred: basic},
	} {
		if ok, msg := allowed(outer, "CONNECT", "github.com:443", "", h); ok || !strings.Contains(msg, "credential") {
			t.Errorf("%s: allowed=%v %q", name, ok, msg)
		}
		req, hh := reqWith(outer, "CONNECT", "github.com:443", "", h)
		resp, _ := xp.onHeaders(context.Background(), req, hh)
		ir := resp.GetImmediateResponse()
		challenge := ""
		for _, o := range ir.GetHeaders().GetSetHeaders() {
			if o.GetHeader().GetKey() == "proxy-authenticate" {
				challenge = string(o.GetHeader().GetRawValue())
			}
		}
		if ir.GetStatus().GetCode() != 407 || !strings.HasPrefix(challenge, "Basic ") {
			t.Errorf("%s: want a 407 Basic challenge, got %v %q", name, ir.GetStatus().GetCode(), challenge)
		}
	}
	inner := map[string]interface{}{"source.address": "envoy://internal_client_address/", "destination.address": "envoy://mitm-0/"}
	if ok, msg := allowed(inner, "GET", "api.github.com", "/zen", map[string]string{hdrCred: basic, hdrConnect: "api.github.com:443"}); !ok {
		t.Fatalf("inner hop with Envoy's credential refused: %s", msg)
	}
	if ok, _ := allowed(inner, "GET", "api.github.com", "/zen", map[string]string{"proxy-authorization": basic, hdrConnect: "api.github.com:443"}); ok {
		t.Fatal("inner hop trusted a client Proxy-Authorization")
	}

	if err := rc.End(nil); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if ok, _ := allowed(outer, "CONNECT", "github.com:443", "", map[string]string{"proxy-authorization": basic}); ok {
		t.Fatal("credential of an ended run accepted")
	}

	// The recorder writes the run from the run API's events and the
	// proxy's decisions.
	rec, err := NewCredentialRunRecorder(filepath.Join(dir, "runs"), reg)
	if err != nil {
		t.Fatal(err)
	}
	var tl *RunTimeline
	for len(events) > 0 {
		ev := <-events
		got, err := rec.Handle(ev)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			tl = got
		}
	}
	if tl == nil || tl.RunID != run.RunID || !tl.Complete || tl.EndedAt == nil || len(tl.Summary.Proxied) != 2 {
		t.Fatalf("timeline %+v", tl)
	}
}

func TestParseProxyBasic(t *testing.T) {
	enc := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	if u, p, ok := parseProxyBasic(enc("run-abc:tok")); !ok || u != "run-abc" || p != "tok" {
		t.Fatalf("%q %q %v", u, p, ok)
	}
	for _, bad := range []string{"", "-", "Bearer x", "Basic !!!", enc("nocolon")} {
		if _, _, ok := parseProxyBasic(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
