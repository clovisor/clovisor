// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"reflect"
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
		p, cmd, err := parseRunArgs(tc.in)
		if err != nil || p != tc.profile || !reflect.DeepEqual(cmd, tc.cmd) {
			t.Errorf("parseRunArgs(%q) = %q, %q, %v", tc.in, p, cmd, err)
		}
	}
	if _, _, err := parseRunArgs([]string{"--profile"}); err == nil {
		t.Error("dangling --profile accepted")
	}
}
