// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !linux

package clovisor

// readOnlyMount is Linux's only: elsewhere, policy is checked by owner and
// mode alone.
func readOnlyMount(string) bool { return false }
