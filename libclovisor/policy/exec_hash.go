// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// MaxExecHashes is how many hashes one exec.allow path may list
// (MAX_EXEC_HASHES in agent_audit.c): enough for a binary across an
// upgrade, or for one per architecture.
const MaxExecHashes = 4

// ParseExecHash reads an exec.allow hash: sha256: and 64 hex digits, as
// sha256sum prints them (milestone 5.7). SHA-256 is what
// bpf_ima_file_hash returns with the kernel's default IMA hash.
func ParseExecHash(s string) ([32]byte, error) {
	var sum [32]byte
	hexs, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return sum, fmt.Errorf("hash %q must be sha256: followed by 64 hex digits", s)
	}
	b, err := hex.DecodeString(hexs)
	if err != nil || len(b) != len(sum) {
		return sum, fmt.Errorf("hash %q must be sha256: followed by 64 hex digits", s)
	}
	copy(sum[:], b)
	return sum, nil
}

// FormatExecHash is ParseExecHash's inverse, in lower case.
func FormatExecHash(sum [32]byte) string {
	return "sha256:" + hex.EncodeToString(sum[:])
}
