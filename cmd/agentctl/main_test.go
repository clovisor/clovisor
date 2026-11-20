// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRunArgs(t *testing.T) {
	for _, tc := range []struct {
		in      []string
		profile string
		cmd     []string
	}{
		{[]string{"--", "curl", "--profile", "x"}, "", []string{"curl", "--profile", "x"}},
		{[]string{"--profile", "light", "--", "curl"}, "light", []string{"curl"}},
		{[]string{"--profile=light", "curl", "-v"}, "light", []string{"curl", "-v"}},
		{[]string{"curl", "--profile", "x"}, "", []string{"curl", "--profile", "x"}},
	} {
		p, _, cmd, err := parseRunArgs(tc.in)
		if err != nil || p != tc.profile || !reflect.DeepEqual(cmd, tc.cmd) {
			t.Errorf("parseRunArgs(%q) = %q, %q, %v", tc.in, p, cmd, err)
		}
	}
	if _, _, _, err := parseRunArgs([]string{"--profile"}); err == nil {
		t.Error("dangling --profile accepted")
	}
}

func TestProxyEnv(t *testing.T) {
	env := proxyEnv([]string{"PATH=/bin", "no_proxy=*", "HTTPS_PROXY=http://evil", "all_proxy=socks5://x", "HOME=/h"}, "http://127.0.0.1:18000")
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Fatalf("duplicate %s", k)
		}
		got[k] = v
	}
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if got[k] != "http://127.0.0.1:18000" {
			t.Errorf("%s = %q", k, got[k])
		}
	}
	if got["no_proxy"] != "localhost,127.0.0.1,::1" || got["NO_PROXY"] != got["no_proxy"] {
		t.Errorf("no_proxy = %q", got["no_proxy"])
	}
	if _, ok := got["all_proxy"]; ok {
		t.Error("all_proxy kept")
	}
	if got["PATH"] != "/bin" || got["HOME"] != "/h" {
		t.Error("unrelated variables lost")
	}
}
