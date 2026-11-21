// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"testing"
)

func TestRunRegistry(t *testing.T) {
	r := NewRunRegistry()
	r.Put(RunMeta{RunID: "a", UID: 5})
	code := 2
	r.Update("a", func(m *RunMeta) { m.ExitCode = &code })
	r.Update("missing", func(m *RunMeta) { t.Fatal("updated a missing run") })
	if m, ok := r.Get("a"); !ok || m.UID != 5 || *m.ExitCode != 2 {
		t.Fatalf("got %+v %v", m, ok)
	}
	r.Done("a")
	if _, ok := r.Get("a"); ok {
		t.Fatal("Done did not forget the run")
	}
}
