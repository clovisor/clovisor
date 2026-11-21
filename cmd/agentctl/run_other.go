// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !linux

package main

import (
	"errors"
	"os/exec"

	clovisor "github.com/clovisor/clovisor/libclovisor"
)

func startInRun(api *clovisor.RunAPIClient, path string, args, env []string) (*exec.Cmd, error) {
	return nil, errors.New("the node agent uses cgroup identity, which needs Linux")
}
