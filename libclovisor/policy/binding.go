// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProfileCeiling bounds which profiles a workload may run under (design
// §5.6). It is the only object with a selector, and the selector is over
// platform identity, never over anything the run says about itself.
type ProfileCeiling struct {
	Kind     string      `yaml:"kind" json:"kind"`
	Metadata Metadata    `yaml:"metadata" json:"metadata"`
	Spec     CeilingSpec `yaml:"spec" json:"spec"`
}

// CeilingSpec is the body of a ceiling.
type CeilingSpec struct {
	AppliesTo AppliesTo `yaml:"appliesTo" json:"appliesTo"`
	Allow     []string  `yaml:"allow" json:"allow"`
	// Default is granted when the request names nothing, or names a
	// profile not in Allow.
	Default string `yaml:"default,omitempty" json:"default,omitempty"`
	// Clamp is intersected into every grant under this ceiling.
	Clamp string `yaml:"clamp,omitempty" json:"clamp,omitempty"`
}

// AppliesTo selects callers by platform identity. On a host that is the
// caller's uid or groups, from SO_PEERCRED; exactly one field is set.
type AppliesTo struct {
	User  string `yaml:"user,omitempty" json:"user,omitempty"`
	UID   *int   `yaml:"uid,omitempty" json:"uid,omitempty"`
	Group string `yaml:"group,omitempty" json:"group,omitempty"`
	GID   *int   `yaml:"gid,omitempty" json:"gid,omitempty"`
	Any   bool   `yaml:"any,omitempty" json:"any,omitempty"`
	// Kubernetes platform identity (design §5.6); not available to a host
	// node agent.
	Namespace      string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	ServiceAccount string `yaml:"serviceAccount,omitempty" json:"serviceAccount,omitempty"`
}

// ParseDocument decodes one policy file, which holds either an
// AgentProfile or a ProfileCeiling.
func ParseDocument(data []byte) (*AgentProfile, *ProfileCeiling, error) {
	var head struct {
		Kind string `yaml:"kind"`
	}
	if err := yaml.Unmarshal(data, &head); err != nil {
		return nil, nil, err
	}
	switch head.Kind {
	case "AgentProfile":
		p, err := Parse(data)
		return p, nil, err
	case "ProfileCeiling":
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		var c ProfileCeiling
		if err := dec.Decode(&c); err != nil {
			return nil, nil, err
		}
		var extra yaml.Node
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, nil, fmt.Errorf("a policy file holds exactly one YAML document")
		}
		return nil, &c, nil
	default:
		return nil, nil, fmt.Errorf("kind must be AgentProfile or ProfileCeiling, got %q", head.Kind)
	}
}

// Caller is the platform identity of whoever asks for a run.
type Caller struct {
	UID  int
	GIDs []int // primary and supplementary
}

type ceiling struct {
	name  string
	level int // 3 uid, 2 gid, 1 any
	uid   int
	gid   int
	spec  CeilingSpec
}

func (c *ceiling) matches(caller Caller) bool {
	switch c.level {
	case 3:
		return caller.UID == c.uid
	case 2:
		for _, g := range caller.GIDs {
			if g == c.gid {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// Set is the policy a node agent serves: compiled profiles and ceilings.
type Set struct {
	Compiled *Compiled
	ceilings []*ceiling
}

// NewSet compiles profiles and validates ceilings against them. Names in
// appliesTo are resolved with the lookup functions.
func NewSet(opts Options, profiles []*AgentProfile, ceilings []*ProfileCeiling,
	lookupUser, lookupGroup func(string) (int, error)) (*Set, []Diagnostic) {
	compiled, diags := Compile(opts, profiles...)
	have := map[string]bool{}
	for _, p := range profiles {
		have[p.Metadata.Name] = true
	}
	set := &Set{Compiled: compiled}
	seen := map[string]bool{}
	sameSelector := map[string]string{}
	for _, c := range ceilings {
		name := c.Metadata.Name
		errf := func(where, format string, a ...interface{}) {
			diags = append(diags, Diagnostic{Profile: "ceiling " + name, Where: where, Msg: fmt.Sprintf(format, a...)})
		}
		if c.Kind != "ProfileCeiling" {
			errf("kind", "must be ProfileCeiling")
		}
		if !nameRE.MatchString(name) {
			errf("metadata.name", "%q must be lowercase letters, digits and '-'", name)
		}
		if seen[name] {
			errf("metadata.name", "two ceilings are named %q", name)
		}
		seen[name] = true

		a := c.Spec.AppliesTo
		rc := &ceiling{name: name, spec: c.Spec}
		n := 0
		if a.Namespace != "" || a.ServiceAccount != "" {
			errf("spec.appliesTo", "namespace and serviceAccount need Kubernetes identity, which a host node agent does not have")
		}
		if a.User != "" {
			n++
			uid, err := lookupUser(a.User)
			if err != nil {
				errf("spec.appliesTo.user", "%v", err)
			}
			rc.level, rc.uid = 3, uid
		}
		if a.UID != nil {
			n++
			rc.level, rc.uid = 3, *a.UID
		}
		if a.Group != "" {
			n++
			gid, err := lookupGroup(a.Group)
			if err != nil {
				errf("spec.appliesTo.group", "%v", err)
			}
			rc.level, rc.gid = 2, gid
		}
		if a.GID != nil {
			n++
			rc.level, rc.gid = 2, *a.GID
		}
		if a.Any {
			n++
			rc.level = 1
		}
		if n != 1 {
			errf("spec.appliesTo", "needs exactly one of user, uid, group, gid or any")
		}
		key := fmt.Sprintf("%d/%d/%d", rc.level, rc.uid, rc.gid)
		if prev, ok := sameSelector[key]; ok && n == 1 {
			errf("spec.appliesTo", "selects the same callers as ceiling %s", prev)
		}
		sameSelector[key] = name

		if len(c.Spec.Allow) == 0 && c.Spec.Default == "" {
			errf("spec", "grants nothing: set allow, default, or both")
		}
		for _, p := range c.Spec.Allow {
			if !have[p] {
				errf("spec.allow", "no profile named %q", p)
			}
		}
		if c.Spec.Default != "" && !have[c.Spec.Default] {
			errf("spec.default", "no profile named %q", c.Spec.Default)
		}
		if c.Spec.Clamp != "" && !have[c.Spec.Clamp] {
			errf("spec.clamp", "no profile named %q", c.Spec.Clamp)
		}
		set.ceilings = append(set.ceilings, rc)
	}
	if len(diags) > 0 {
		return nil, diags
	}
	sort.SliceStable(set.ceilings, func(i, j int) bool { return set.ceilings[i].level > set.ceilings[j].level })
	return set, nil
}

// Layer is one profile in a run's effective policy.
type Layer struct {
	Profile *CompiledProfile
	Source  string // "granted", "ceiling clamp", or who clamped it and when
}

// Binding is the outcome of resolving a run's profile request.
type Binding struct {
	Requested string
	Ceiling   string
	// Reason explains the grant, notably when the request was refused
	// and the ceiling's default granted instead.
	Reason    string
	Effective *Effective
}

// Granted returns the profile granted (the first layer).
func (b *Binding) Granted() *CompiledProfile { return b.Effective.Layers[0].Profile }

// ErrNoCeiling is returned when no ceiling covers the caller.
var ErrNoCeiling = errors.New("no ceiling covers the caller")

// ceilingFor returns the most specific ceiling covering the caller.
func (s *Set) ceilingFor(c Caller) (*ceiling, error) {
	var best []*ceiling
	for _, rc := range s.ceilings {
		if len(best) > 0 && rc.level < best[0].level {
			break
		}
		if rc.matches(c) {
			best = append(best, rc)
		}
	}
	switch len(best) {
	case 0:
		return nil, ErrNoCeiling
	case 1:
		return best[0], nil
	default:
		var names []string
		for _, b := range best {
			names = append(names, b.name)
		}
		return nil, fmt.Errorf("ceilings %s all cover uid %d through its groups; make one of them more specific",
			strings.Join(names, " and "), c.UID)
	}
}

// Allowed lists what the caller may request: the ceiling's allow list,
// default and clamp.
func (s *Set) Allowed(c Caller) (ceilingName string, allow []string, def, clamp string, err error) {
	rc, err := s.ceilingFor(c)
	if err != nil {
		return "", nil, "", "", err
	}
	return rc.name, rc.spec.Allow, rc.spec.Default, rc.spec.Clamp, nil
}

// Resolve binds a run to a profile (design §5.6). The requested name is
// untrusted; the ceiling comes only from the caller's platform identity.
func (s *Set) Resolve(c Caller, requested string) (*Binding, error) {
	rc, err := s.ceilingFor(c)
	if err != nil {
		if errors.Is(err, ErrNoCeiling) && requested != "" {
			return nil, fmt.Errorf("no ceiling grants profiles to uid %d", c.UID)
		}
		return nil, err
	}
	b := &Binding{Requested: requested, Ceiling: rc.name}
	granted := ""
	allowed := false
	for _, a := range rc.spec.Allow {
		if a == requested {
			allowed = true
		}
	}
	switch {
	case requested != "" && allowed:
		granted = requested
		b.Reason = "requested; allowed by ceiling " + rc.name
	case rc.spec.Default == "":
		if requested == "" {
			return nil, fmt.Errorf("ceiling %s has no default; request one of: %s", rc.name, strings.Join(rc.spec.Allow, ", "))
		}
		return nil, fmt.Errorf("ceiling %s does not allow %q and has no default; allowed: %s",
			rc.name, requested, strings.Join(rc.spec.Allow, ", "))
	case requested == "":
		granted = rc.spec.Default
		b.Reason = "default of ceiling " + rc.name
	default:
		granted = rc.spec.Default
		b.Reason = fmt.Sprintf("requested %q is not allowed by ceiling %s; granted its default", requested, rc.name)
	}
	b.Effective = &Effective{Layers: []Layer{{Profile: s.Compiled.Profile(granted), Source: "granted"}}}
	if rc.spec.Clamp != "" && rc.spec.Clamp != granted {
		b.Effective.Layers = append(b.Effective.Layers, Layer{Profile: s.Compiled.Profile(rc.spec.Clamp), Source: "ceiling clamp"})
	}
	return b, nil
}

// Profile returns a compiled profile by name, for out-of-band clamps.
func (s *Set) Profile(name string) *CompiledProfile { return s.Compiled.Profile(name) }

// Effective is a run's effective policy: the intersection of its layers.
// It is immutable; clamping makes a new one.
type Effective struct {
	Layers []Layer
}

// With returns a copy with one more layer. Adding a layer can only
// remove permissions, which is what makes clamping safe to delegate.
func (e *Effective) With(l Layer) *Effective {
	layers := append(append([]Layer{}, e.Layers...), l)
	return &Effective{Layers: layers}
}

// EffectiveDecision is a decision across all layers.
type EffectiveDecision struct {
	Decision
	// Enforced is set when an enforce-mode layer denied: the attempt is
	// blocked. A deny from an audit-mode layer only lands in WouldDeny.
	Enforced bool
	Layer    string // profile that decided a block
	// WouldDeny names audit-mode layers that would have denied.
	WouldDeny []string
}

// Decide evaluates an egress attempt against every layer. Any
// enforce-mode deny blocks; audit-mode denies are recorded; otherwise the
// attempt is allowed, deferred to request phase if any layer needs it.
func (e *Effective) Decide(req Request) EffectiveDecision {
	return e.decide(func(cp *CompiledProfile) Decision { return cp.Decide(req) })
}

// DecideName is Decide for a DNS name (see CompiledProfile.DecideName).
func (e *Effective) DecideName(name string) EffectiveDecision {
	return e.decide(func(cp *CompiledProfile) Decision { return cp.DecideName(name) })
}

func (e *Effective) decide(decide func(*CompiledProfile) Decision) EffectiveDecision {
	var out EffectiveDecision
	out.Action = ActionAllow
	var deferred bool
	for _, l := range e.Layers {
		d := decide(l.Profile)
		if !d.Allowed() {
			if l.Profile.Mode == ModeEnforce {
				return EffectiveDecision{Decision: d, Enforced: true, Layer: l.Profile.Name, WouldDeny: out.WouldDeny}
			}
			out.WouldDeny = append(out.WouldDeny, l.Profile.Name)
			if out.Message == "" {
				out.Message = d.Message
			}
			continue
		}
		if d.Deferred {
			deferred = true
		}
		if out.Rule == "" {
			out.Rule = d.Rule
		}
		if d.Action == ActionTagAndLog {
			out.Action = ActionTagAndLog
		}
	}
	out.Deferred = deferred
	return out
}

// RevokedProfile is the profile an out-of-band revoke layers onto a run:
// it denies all egress, in enforce mode.
func RevokedProfile() *CompiledProfile {
	p := &AgentProfile{Kind: "AgentProfile", Metadata: Metadata{Name: "revoked"},
		Spec: Spec{Mode: ModeEnforce, Egress: Egress{Default: ActionDeny}}}
	c, diags := Compile(Options{Mode: ExplicitProxy}, p)
	if len(diags) > 0 {
		panic(diags[0])
	}
	cp := c.Profiles[0]
	cp.DefaultMessage = "Egress for this run has been revoked."
	return cp
}
