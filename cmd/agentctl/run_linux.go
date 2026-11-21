// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	clovisor "github.com/clovisor/clovisor/libclovisor"
)

// startInRun starts args as a parked shim, has the node agent move it
// into the run's cgroup by pidfd, then releases it to exec the command.
func startInRun(api *clovisor.RunAPIClient, path string, args, env []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	relR, relW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer relW.Close()

	pidfd := -1
	cmd := exec.Command(self, append([]string{shimArg, path}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{relR}
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		relR.Close()
		return nil, fmt.Errorf("failed to start %s: %w", args[0], err)
	}
	relR.Close()

	attachErr := api.Attach(pidfd)
	syscall.Close(pidfd)
	if attachErr != nil {
		relW.Close() // the shim exits without running the command
		cmd.Wait()
		return nil, attachErr
	}
	if _, err := relW.Write([]byte{1}); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("failed to release %s: %w", args[0], err)
	}
	return cmd, nil
}
