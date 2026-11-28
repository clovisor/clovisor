// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import "golang.org/x/sys/unix"

// fuseMagic is FUSE's statfs type: a user's daemon serves its files.
const fuseMagic = 0x65735546

// readOnlyMount reports whether path, symlinks followed, is on a
// read-only mount that is not FUSE.
func readOnlyMount(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Flags&unix.ST_RDONLY != 0 && st.Type != fuseMagic
}
