// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// PinStore keeps tool definitions across runs (design §8.4), so a server
// that changes a tool after review is caught. A changed definition is
// kept as pending until an operator approves it (agentctl pins approve),
// which makes it the pin.
type PinStore struct {
	path string
	mu   sync.Mutex
	pins map[string]map[string]*Pin // server key (profile/rule) -> tool -> pin
}

// Pin is one tool's pinned definition, and a changed one awaiting review.
type Pin struct {
	Hash     string          `json:"hash"`
	Def      json.RawMessage `json:"def,omitempty"`
	PinnedAt time.Time       `json:"pinned_at,omitempty"`
	Pending  *PinDef         `json:"pending,omitempty"`
}

// PinDef is a definition seen at a time.
type PinDef struct {
	Hash string          `json:"hash"`
	Def  json.RawMessage `json:"def"`
	Seen time.Time       `json:"seen"`
}

// UnmarshalJSON also reads the first format, a bare hash.
func (p *Pin) UnmarshalJSON(b []byte) error {
	var h string
	if json.Unmarshal(b, &h) == nil {
		*p = Pin{Hash: h}
		return nil
	}
	type plain Pin
	return json.Unmarshal(b, (*plain)(p))
}

// OpenPinStore loads (or starts) the store at path.
func OpenPinStore(path string) (*PinStore, error) {
	ps := &PinStore{path: path, pins: map[string]map[string]*Pin{}}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &ps.pins); err != nil {
			return nil, fmt.Errorf("pin store %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return ps, nil
}

// canonicalHash hashes a tool definition independent of key order and
// whitespace.
func canonicalHash(def json.RawMessage) (string, error) {
	b, err := canonicalJSON(def)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(def json.RawMessage) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(def, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v) // map keys are sorted
}

// save writes the store; the caller holds mu.
func (ps *PinStore) save() error {
	data, _ := json.MarshalIndent(ps.pins, "", "  ")
	if err := os.MkdirAll(filepath.Dir(ps.path), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(ps.path, data, 0o600)
}

// Check pins a tool definition on first sight and reports whether it
// differs from the pinned one. A differing definition is kept as pending
// for review.
func (ps *PinStore) Check(server, tool string, def json.RawMessage) (changed bool, err error) {
	h, err := canonicalHash(def)
	if err != nil {
		return false, err
	}
	canon, _ := canonicalJSON(def)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.pins[server] == nil {
		ps.pins[server] = map[string]*Pin{}
	}
	p := ps.pins[server][tool]
	switch {
	case p == nil:
		ps.pins[server][tool] = &Pin{Hash: h, Def: canon, PinnedAt: time.Now().UTC()}
		return false, ps.save()
	case p.Hash == h:
		return false, nil
	case p.Pending == nil || p.Pending.Hash != h:
		p.Pending = &PinDef{Hash: h, Def: canon, Seen: time.Now().UTC()}
		return true, ps.save()
	default:
		return true, nil
	}
}

// PinEntry is one pin, for listing. Pin is a named field, not embedded:
// embedding would promote Pin's UnmarshalJSON and drop Server and Tool.
type PinEntry struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
	Pin    Pin    `json:"pin"`
}

// List returns the pins, servers and tools sorted; with pendingOnly,
// only those with a changed definition awaiting review.
func (ps *PinStore) List(pendingOnly bool) []PinEntry {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	var out []PinEntry
	for server, tools := range ps.pins {
		for tool, p := range tools {
			if pendingOnly && p.Pending == nil {
				continue
			}
			c := *p
			if p.Pending != nil {
				pd := *p.Pending
				c.Pending = &pd
			}
			out = append(out, PinEntry{Server: server, Tool: tool, Pin: c})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// Approve makes a tool's pending definition its pin. With tool "", every
// pending tool of the server is approved. A pin from the first store
// format has no pending definition kept; approving it forgets the pin,
// so the next definition seen is pinned. It returns the tools approved.
func (ps *PinStore) Approve(server, tool, hash string) ([]string, error) {
	if hash != "" && len(hash) < 8 {
		return nil, fmt.Errorf("give at least 8 characters of the reviewed hash")
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	tools := ps.pins[server]
	if tools == nil {
		return nil, fmt.Errorf("no pins for server %q", server)
	}
	var names []string
	if tool != "" {
		if tools[tool] == nil {
			return nil, fmt.Errorf("no pin for tool %q on %s", tool, server)
		}
		names = []string{tool}
	} else {
		for t, p := range tools {
			if p.Pending != nil {
				names = append(names, t)
			}
		}
		sort.Strings(names)
	}
	var done []string
	for _, t := range names {
		p := tools[t]
		switch {
		case p.Pending != nil:
			if hash != "" && !bytes.HasPrefix([]byte(p.Pending.Hash), []byte(hash)) {
				return done, fmt.Errorf("tool %s: pending definition is %s, not %s; review it again", t, p.Pending.Hash[:12], hash)
			}
			*p = Pin{Hash: p.Pending.Hash, Def: p.Pending.Def, PinnedAt: time.Now().UTC()}
		case p.Def == nil:
			delete(tools, t) // first-format pin: re-pin on next sight
		default:
			return done, fmt.Errorf("tool %s on %s has no changed definition to approve", t, server)
		}
		done = append(done, t)
	}
	return done, ps.save()
}
