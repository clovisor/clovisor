// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Package policy is the policy language (design §7): the AgentProfile
// schema, its compiler, the enforcement receipt, and the decision engine
// shared by every enforcement point.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// AgentProfile is a profile (design §7.3, §8.5).
type AgentProfile struct {
	Kind     string   `yaml:"kind" json:"kind"`
	Metadata Metadata `yaml:"metadata" json:"metadata"`
	Spec     Spec     `yaml:"spec" json:"spec"`
}

// Metadata names a profile.
type Metadata struct {
	Name string `yaml:"name" json:"name"`
}

// Spec is the body of a profile.
type Spec struct {
	Mode    string        `yaml:"mode" json:"mode"` // audit | enforce | ask
	Egress  Egress        `yaml:"egress" json:"egress"`
	Exec    *Exec         `yaml:"exec,omitempty" json:"exec,omitempty"`
	MCP     *MCP          `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	Unix    *Unix         `yaml:"unix,omitempty" json:"unix,omitempty"`
	UDP     *UDP          `yaml:"udp,omitempty" json:"udp,omitempty"`
	ICMP    *ICMP         `yaml:"icmp,omitempty" json:"icmp,omitempty"`
	Content []ContentRule `yaml:"content,omitempty" json:"content,omitempty"`
	Limits  *Limits       `yaml:"limits,omitempty" json:"limits,omitempty"`
}

// Egress is the egress block.
type Egress struct {
	Default string       `yaml:"default" json:"default"` // allow | deny
	Rules   []EgressRule `yaml:"rules" json:"rules"`
}

// EgressRule is one egress rule. Rules are evaluated in order; the first
// whose destination and http block match decides.
type EgressRule struct {
	Name        string      `yaml:"name" json:"name"`
	To          Destination `yaml:"to" json:"to"`
	HTTP        *HTTPMatch  `yaml:"http,omitempty" json:"http,omitempty"`
	Model       *ModelMatch `yaml:"model,omitempty" json:"model,omitempty"`
	Budget      *Budget     `yaml:"budget,omitempty" json:"budget,omitempty"`
	Action      string      `yaml:"action" json:"action"`
	Ask         *Ask        `yaml:"ask,omitempty" json:"ask,omitempty"`
	Message     string      `yaml:"message,omitempty" json:"message,omitempty"`
	NoTerminate bool        `yaml:"no_terminate,omitempty" json:"no_terminate,omitempty"`
}

// Destination selects where a rule applies.
type Destination struct {
	// FQDN entries are exact hostnames, "*.suffix" (exactly one more
	// label, like a TLS wildcard certificate), or "*" (any host).
	FQDN []string `yaml:"fqdn,omitempty" json:"fqdn,omitempty"`
	// CIDR entries match connections addressed to an IP literal.
	CIDR []string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	// Ports restricts the rule; empty means any port.
	Ports []uint16 `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// HTTPMatch narrows a rule to methods and paths. Paths are globs where
// "*" matches any run of characters, "/" included; the query string is
// not part of the path.
type HTTPMatch struct {
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
}

// ModelMatch is a model allow-list (body rule).
type ModelMatch struct {
	Allow []string `yaml:"allow" json:"allow"`
}

// Budget is a per-run token or cost budget.
type Budget struct {
	Tokens  int64   `yaml:"tokens,omitempty" json:"tokens,omitempty"`
	CostUSD float64 `yaml:"cost_usd,omitempty" json:"cost_usd,omitempty"`
}

// Ask configures ask-mode approval.
type Ask struct {
	Timeout   string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	OnTimeout string `yaml:"on_timeout,omitempty" json:"on_timeout,omitempty"`
}

// Exec is the exec block (design §7.6).
type Exec struct {
	Default string `yaml:"default" json:"default"`
	// RequireTrustedPath refuses an exec not named in Allow unless the
	// file, and every directory above it, is owned by root and not
	// writable by group or others (milestone 4.4). Off for agents that run
	// what they build; on for agents that only run installed tools.
	RequireTrustedPath bool `yaml:"require_trusted_path,omitempty" json:"require_trusted_path,omitempty"`
	// RequireReadonlyOrigin is the earlier name of RequireTrustedPath,
	// from when the test was a read-only mount (design §7.6).
	RequireReadonlyOrigin bool `yaml:"require_readonly_origin,omitempty" json:"require_readonly_origin,omitempty"`
	// AuditOnly declares that exec rules are observed, not enforced. It is
	// required in mode enforce until a deployment can gate exec (BPF LSM),
	// so that non-enforcement is stated rather than silent (§7.1).
	AuditOnly bool        `yaml:"audit_only,omitempty" json:"audit_only,omitempty"`
	Allow     []ExecAllow `yaml:"allow" json:"allow"`
}

// ExecAllow allows one binary.
type ExecAllow struct {
	Path string `yaml:"path" json:"path"`
	Hash string `yaml:"hash,omitempty" json:"hash,omitempty"`
	Note string `yaml:"note,omitempty" json:"note,omitempty"`
}

// Unix is the unix block (milestone 4.2): the Unix sockets outside the run
// that the run may connect or send to. A run always reaches sockets it
// created itself, and the node agent's run API; everything else is
// refused under transparent enforce, where BPF LSM is active.
//
// Each entry is an absolute path, or an abstract name written @name. A
// trailing * matches any rest; {uid} stands for the run's uid. The path is
// the address the listening socket was bound to.
type Unix struct {
	Allow []string `yaml:"allow" json:"allow"`
}

// MCP is the mcp block (design §8.5).
type MCP struct {
	Default  string      `yaml:"default" json:"default"`
	Servers  []MCPServer `yaml:"servers" json:"servers"`
	Sampling *Sampling   `yaml:"sampling,omitempty" json:"sampling,omitempty"`
}

// MCPServer is policy for one MCP server.
type MCPServer struct {
	Name               string         `yaml:"name" json:"name"`
	Match              MCPMatch       `yaml:"match" json:"match"`
	Tools              *ToolRules     `yaml:"tools,omitempty" json:"tools,omitempty"`
	Resources          *ResourceRules `yaml:"resources,omitempty" json:"resources,omitempty"`
	PinToolDefinitions bool           `yaml:"pin_tool_definitions,omitempty" json:"pin_tool_definitions,omitempty"`
}

// MCPMatch identifies a server: remote by hostname, or local stdio by
// package or command.
type MCPMatch struct {
	FQDN  string `yaml:"fqdn,omitempty" json:"fqdn,omitempty"`
	Stdio string `yaml:"stdio,omitempty" json:"stdio,omitempty"`
}

// ToolRules allows and denies tools by glob. Deny wins.
type ToolRules struct {
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty" json:"deny,omitempty"`
}

// ResourceRules allows resources by URI glob.
type ResourceRules struct {
	AllowURI []string `yaml:"allow_uri,omitempty" json:"allow_uri,omitempty"`
}

// Sampling governs server-initiated model calls.
type Sampling struct {
	Action  string `yaml:"action" json:"action"`
	Message string `yaml:"message,omitempty" json:"message,omitempty"`
}

// ContentRule is a content pattern (milestone 5.1), checked against
// request bodies and query strings. Regex is RE2 syntax (Go regexp).
type ContentRule struct {
	Name   string `yaml:"name" json:"name"`
	Regex  string `yaml:"regex" json:"regex"`
	Action string `yaml:"action" json:"action"` // deny | redact | tag-and-log
	// Message is what the agent is told when a deny refuses a request.
	// Without it, one is generated; it never quotes the match.
	Message string `yaml:"message,omitempty" json:"message,omitempty"`
	// To limits the rule to some hosts; without it, every host the
	// profile allows by name.
	To *ContentScope `yaml:"to,omitempty" json:"to,omitempty"`
}

// Limits are per-run limits (Phase 5).
type Limits struct {
	ConnectionsPerMin int    `yaml:"connections_per_min,omitempty" json:"connections_per_min,omitempty"`
	EgressBytes       string `yaml:"egress_bytes,omitempty" json:"egress_bytes,omitempty"`
	Duration          string `yaml:"duration,omitempty" json:"duration,omitempty"`
}

// Parse decodes one profile. Unknown fields are errors: a misspelt field
// must never be silently ignored.
func Parse(data []byte) (*AgentProfile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p AgentProfile
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("empty profile")
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("a profile file holds exactly one YAML document")
	}
	return &p, nil
}

// Version identifies a profile's content: "sha256:" and the hex digest of
// its canonical JSON form. Comments and formatting do not change it.
func (p *AgentProfile) Version() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ShortVersion is the first 12 hex digits of Version, for display.
func (p *AgentProfile) ShortVersion() string {
	return p.Version()[:7+12]
}
