// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Actions.
const (
	ActionAllow     = "allow"
	ActionDeny      = "deny"
	ActionTagAndLog = "tag-and-log"
)

// Profile modes.
const (
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)

// TLS postures (design §6.6). In explicit-proxy mode "passthrough" is a
// CONNECT tunnel decided on its authority; in transparent mode, SNI.
const (
	PosturePassthrough = "passthrough"
	PostureTerminate   = "terminate"
	PosturePlaintext   = "plaintext"
)

// DeploymentMode is how traffic reaches the proxy (design §4.3).
type DeploymentMode string

const (
	ExplicitProxy DeploymentMode = "explicit-proxy"
	// Transparent redirects every TCP connect from a run to the proxy, or
	// refuses it (design §6.5 rule 1). Linux only.
	Transparent DeploymentMode = "transparent"
	// TransparentAudit records what Transparent would redirect or refuse
	// and lets it go direct: routing is still advisory.
	TransparentAudit DeploymentMode = "transparent-audit"
)

// Options describe the deployment the profiles are compiled for. The
// receipt depends on it: the same rule has different bypass exposure in
// different deployments.
type Options struct {
	Mode DeploymentMode
	// Linux deployments resolve run identity from the client socket's
	// cgroup; others use a per-run proxy credential.
	Linux bool
	// KernelLSM: BPF LSM is active, so transparent mode also governs
	// socket families, raw sockets and sockets made outside the run.
	KernelLSM bool
	// QUIC: transparent enforce relays QUIC by server name (milestone
	// 5.6, node -quic); otherwise UDP 443 is refused like other UDP.
	QUIC bool
	// Uprobes: the node captures TLS plaintext for runs that ask
	// (milestone 6.2, node -uprobes).
	Uprobes bool
	// ExecHash: the kernel's exec hook hashes files (milestone 5.7:
	// bpf_ima_file_hash, Linux 5.18, and the TAI clock, 5.19), so
	// exec.allow hashes are verified where exec is enforceable.
	ExecHash bool
}

// Diagnostic is one compile error.
type Diagnostic struct {
	Profile string
	Where   string // e.g. "egress.rules[2] (github-api)"
	Msg     string
}

func (d Diagnostic) Error() string {
	if d.Where == "" {
		return fmt.Sprintf("%s: %s", d.Profile, d.Msg)
	}
	return fmt.Sprintf("%s: %s: %s", d.Profile, d.Where, d.Msg)
}

// Placement says where a rule is enforced, for the receipt (design §7.4).
type Placement struct {
	Rule       string
	Tier       string // "0", "1", "2", "audit" or "gateway"
	EnforcedBy string
	Notes      []string
}

type compiledRule struct {
	Name    string
	Action  string
	Message string
	hosts   []hostPattern
	nets    []netip.Prefix
	ports   map[uint16]bool
	http    *HTTPMatch
	rate    *compiledRate
	models  *compiledModels
	budget  *compiledBudget
	ask     *compiledAsk
	src     EgressRule
}

type compiledExec struct {
	Exec
	allow    map[string]bool
	hashes   map[string][][32]byte // exact paths whose content must have one of these (milestone 5.7)
	prefixes []string              // allow entries ending in /*, without the *
}

// MaxExecPrefixes matches MAX_EXEC_PREFIXES in agent_audit.c.
const MaxExecPrefixes = 4

// ExecEnforceable says whether this deployment refuses execs: transparent
// mode with BPF LSM.
func (o Options) ExecEnforceable() bool {
	return o.KernelLSM && (o.Mode == Transparent || o.Mode == TransparentAudit)
}

// CompiledProfile is a profile ready for enforcement and explanation.
type CompiledProfile struct {
	Name          string
	Version       string
	Mode          string
	DefaultAction string
	// DefaultMessage, if set, narrates default denies instead of the
	// generated "No rule in profile ... allows ...".
	DefaultMessage string
	Rules          []*compiledRule
	Placements     []Placement
	Profile        *AgentProfile
	// Builtin names a profile the node agent made rather than loaded
	// (BuiltinRevoked, BuiltinLimit); "" for profiles from the policy
	// directory.
	Builtin string

	exec *compiledExec
	mcp  *MCP
	// UnixAllow is the unix block's patterns, validated.
	UnixAllow []string
	// Net is the udp and icmp blocks, validated (milestone 4.7).
	Net NetGrant

	// askDefault is spec.ask, for ask rules, the mode ask default and
	// sampling ask; samplingAsk is sampling's (milestone 5.5).
	askDefault  *compiledAsk
	samplingAsk *compiledAsk

	content []*compiledContent
	// Limits are the limits block, parsed (milestone 5.2).
	Limits CompiledLimits
}

// DestPosture is the TLS posture derived for one destination. Posture is
// node-wide: every run on the node reaching that destination gets it.
type DestPosture struct {
	Dest    string
	Posture string
	Why     []string
	// Others lists profiles that reach the destination without needing
	// termination, but get it anyway because posture is node-wide.
	Others []string
}

// Compiled is the result of compiling the profiles active on a node.
type Compiled struct {
	Options  Options
	Profiles []*CompiledProfile
	Posture  []DestPosture
}

// Profile returns the compiled profile with the given name.
func (c *Compiled) Profile(name string) *CompiledProfile {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p
		}
	}
	return nil
}

var nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
var methodRE = regexp.MustCompile(`^[A-Z]+$`)

// notYet lists features no deployment can enforce yet, and the build
// phase (design §10) that delivers them. Compiling them is an error: a
// rule that looks enforced but is not is worse than no rule (§7.1).
var notYet = map[string]string{
	"action redirect": "transparent mode (Phase 3)",
}

type compiler struct {
	opts  Options
	diags []Diagnostic
	prof  string
}

func (c *compiler) errf(where, format string, a ...interface{}) {
	c.diags = append(c.diags, Diagnostic{Profile: c.prof, Where: where, Msg: fmt.Sprintf(format, a...)})
}

func (c *compiler) unsupported(where, feature string) {
	c.errf(where, "%s cannot be enforced yet: it needs %s", feature, notYet[feature])
}

// Compile validates and compiles the profiles active on one node. It
// returns every error found, not just the first; the result is only
// usable when there are none.
func Compile(opts Options, profiles ...*AgentProfile) (*Compiled, []Diagnostic) {
	c := &compiler{opts: opts}
	out := &Compiled{Options: opts}
	if opts.Mode == "" {
		opts.Mode = ExplicitProxy
		out.Options.Mode = ExplicitProxy
	}
	switch opts.Mode {
	case ExplicitProxy:
	case Transparent, TransparentAudit:
		if !opts.Linux {
			c.prof = "(deployment)"
			c.errf("", "transparent mode needs Linux")
			return nil, c.diags
		}
	default:
		c.prof = "(deployment)"
		c.errf("", "unknown deployment mode %q", opts.Mode)
		return nil, c.diags
	}

	seen := map[string]bool{}
	for _, p := range profiles {
		c.prof = p.Metadata.Name
		if c.prof == "" {
			c.prof = "(unnamed)"
		}
		if seen[p.Metadata.Name] {
			c.errf("metadata.name", "two profiles are named %q", p.Metadata.Name)
		}
		seen[p.Metadata.Name] = true
		if cp := c.profile(p); cp != nil {
			out.Profiles = append(out.Profiles, cp)
		}
	}
	out.Posture = c.posture(profiles)
	if len(c.diags) > 0 {
		return nil, c.diags
	}
	return out, nil
}

func (c *compiler) profile(p *AgentProfile) *CompiledProfile {
	if p.Kind != "AgentProfile" {
		c.errf("kind", "must be AgentProfile, got %q", p.Kind)
	}
	if !nameRE.MatchString(p.Metadata.Name) {
		c.errf("metadata.name", "%q must be lowercase letters, digits and '-', at most 63 characters", p.Metadata.Name)
	}
	cp := &CompiledProfile{
		Name:          p.Metadata.Name,
		Version:       p.Version(),
		Mode:          p.Spec.Mode,
		DefaultAction: p.Spec.Egress.Default,
		Profile:       p,
	}
	switch p.Spec.Mode {
	case ModeAudit, ModeEnforce, ModeAsk:
	case "":
		c.errf("spec.mode", "is required: audit, enforce or ask")
	default:
		c.errf("spec.mode", "must be audit, enforce or ask, got %q", p.Spec.Mode)
	}
	cp.askDefault = c.askConfig("spec.ask", p.Spec.Ask, nil)
	if p.Spec.Mode == ModeAsk && p.Spec.Egress.Default == ActionDeny {
		cp.Placements = append(cp.Placements, Placement{Rule: "(mode ask)", Tier: "2",
			EnforcedBy: "ext_proc: what the egress default would refuse is " + cp.askDefault.describe(),
			Notes: []string{"explicit deny rules still deny; exec, unix, udp and icmp are enforced, since a syscall cannot wait for a person",
				"transparent mode: the resolver does not answer names only the default would ask about; forwarding every name would open DNS tunnelling. Name the hosts in ask rules"}})
	}

	c.egress(p, cp)
	if c.opts.QUIC && c.opts.Mode == Transparent {
		cp.Placements = append(cp.Placements, Placement{Rule: "(quic)", Tier: "0+2",
			EnforcedBy: "connect hooks send UDP 443 to the node's QUIC relay, which decides the Initial's server name as a CONNECT",
			Notes: []string{"allowed only where TLS to the name passes without termination: hosts whose rules need method, path, body or a person get TCP instead",
				"refused: other QUIC versions, encrypted ClientHellos, connection migration; clients fall back to TCP",
				"forwarded to the address the name resolves to, not the one the run chose"}})
	}
	c.exec(p, cp)
	c.observe(p, cp)
	c.mcp(p, cp)
	c.unix(p, cp)
	c.net(p, cp)
	c.content(p, cp)
	c.contentTerminates(p, cp)
	c.limits(p, cp)
	return cp
}

func (c *compiler) egress(p *AgentProfile, cp *CompiledProfile) {
	e := p.Spec.Egress
	switch e.Default {
	case ActionAllow, ActionDeny:
	case "":
		c.errf("egress.default", "is required: allow or deny")
	default:
		c.errf("egress.default", "must be allow or deny, got %q", e.Default)
	}
	cp.Placements = append(cp.Placements, Placement{
		Rule:       "(egress default)",
		Tier:       "2",
		EnforcedBy: "ext_proc: " + e.Default + " what no rule matches",
	})

	names := map[string]bool{}
	for i, r := range e.Rules {
		where := fmt.Sprintf("egress.rules[%d]", i)
		if r.Name != "" {
			where += " (" + r.Name + ")"
		}
		if !nameRE.MatchString(r.Name) {
			c.errf(where, "name %q must be lowercase letters, digits and '-'", r.Name)
		}
		if names[r.Name] {
			c.errf(where, "duplicate rule name %q", r.Name)
		}
		names[r.Name] = true

		cr := &compiledRule{Name: r.Name, Action: r.Action, Message: r.Message, http: r.HTTP, src: r}
		if len(r.To.FQDN) == 0 && len(r.To.CIDR) == 0 {
			c.errf(where, "to: needs fqdn or cidr")
		}
		for _, h := range r.To.FQDN {
			hp, err := parseHost(h)
			if err != nil {
				c.errf(where, "%v", err)
				continue
			}
			cr.hosts = append(cr.hosts, hp)
		}
		for _, s := range r.To.CIDR {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				addr, aerr := netip.ParseAddr(s)
				if aerr != nil {
					c.errf(where, "cidr %q is not a prefix or address", s)
					continue
				}
				pfx = netip.PrefixFrom(addr, addr.BitLen())
			}
			cr.nets = append(cr.nets, pfx.Masked())
		}
		if len(r.To.Ports) > 0 {
			cr.ports = map[uint16]bool{}
			for _, port := range r.To.Ports {
				if port == 0 {
					c.errf(where, "port 0 is not a port")
				}
				cr.ports[port] = true
			}
		}

		switch r.Action {
		case ActionAllow, ActionDeny, ActionTagAndLog:
		case ActionRateLimit:
			cr.rate = c.rate(where, r)
		case ActionAsk:
			cr.ask = c.askConfig(where, r.Ask, cp.askDefault)
		case "redirect":
			c.unsupported(where, "action "+r.Action)
		case ContentActionRedact:
			c.errf(where, "redact is an action for content rules (spec.content), not egress rules")
		case "":
			c.errf(where, "action is required")
		default:
			c.errf(where, "unknown action %q", r.Action)
		}
		if r.Action == ActionDeny && strings.TrimSpace(r.Message) == "" {
			c.errf(where, "a deny rule needs a message: it is what the agent is told (design §7.7)")
		}
		if r.Rate != nil && r.Action != ActionRateLimit {
			c.errf(where, "rate: is only valid with action rate-limit")
		}
		if r.Ask != nil && r.Action != "ask" {
			c.errf(where, "ask: is only valid with action ask")
		}
		if r.Model != nil {
			cr.models = c.model(where, r)
		}
		if r.Budget != nil {
			cr.budget = c.budget(where, r)
		}

		if r.HTTP != nil {
			if len(r.To.CIDR) > 0 {
				c.errf(where, "http: needs a hostname destination; cidr destinations are not known to be HTTP (design §7.4)")
			}
			if len(r.HTTP.Methods) == 0 && len(r.HTTP.Paths) == 0 {
				c.errf(where, "http: is empty")
			}
			for _, m := range r.HTTP.Methods {
				if !methodRE.MatchString(m) {
					c.errf(where, "method %q must be upper case, e.g. GET", m)
				}
			}
			for _, pth := range r.HTTP.Paths {
				if !strings.HasPrefix(pth, "/") && !strings.HasPrefix(pth, "*") {
					c.errf(where, "path %q must start with / or *", pth)
				}
				if strings.Contains(pth, "?") {
					c.errf(where, "path %q: query strings are not matched", pth)
				}
			}
			if r.NoTerminate {
				c.errf(where, "http: rules need termination, but the rule asserts no_terminate (design §6.6)")
			}
		}

		cp.Rules = append(cp.Rules, cr)
		cp.Placements = append(cp.Placements, c.placeEgress(r, cr))
	}
}

func onlyPort80(ports []uint16) bool {
	if len(ports) == 0 {
		return false
	}
	for _, p := range ports {
		if p != 80 {
			return false
		}
	}
	return true
}

func (c *compiler) placeEgress(r EgressRule, cr *compiledRule) Placement {
	pl := Placement{Rule: r.Name, Tier: "2"}
	switch {
	case r.HTTP != nil || r.Model != nil || r.Budget != nil:
		var by []string
		if r.HTTP != nil {
			by = append(by, "method and path")
		}
		if r.Model != nil {
			by = append(by, "body: model field")
		}
		if r.Budget != nil {
			by = append(by, "response: usage")
		}
		pl.EnforcedBy = "ext_proc (" + strings.Join(by, "; ") + ")"
		if onlyPort80(r.To.Ports) {
			pl.Notes = append(pl.Notes, "plaintext HTTP")
		} else {
			pl.Notes = append(pl.Notes, "terminated: see posture")
		}
		if r.Model != nil {
			pl.Notes = append(pl.Notes, modelNotes(r)...)
		}
		if r.Budget != nil {
			pl.Notes = append(pl.Notes, budgetNotes(r)...)
		}
	case len(r.To.FQDN) > 0:
		pl.EnforcedBy = "ext_proc (CONNECT authority or Host)"
	}
	if len(r.To.CIDR) > 0 {
		by := "ext_proc (CONNECT to an IP literal)"
		if pl.EnforcedBy != "" {
			by = pl.EnforcedBy + "; " + by
		}
		pl.EnforcedBy = by
		pl.Notes = append(pl.Notes, "names resolving into the range do not match")
	}
	for _, h := range r.To.FQDN {
		if h == "*" {
			pl.Notes = append(pl.Notes, "matches every host")
		}
	}
	if r.Action != ActionDeny && r.HTTP == nil && r.Model == nil && r.Budget == nil && len(r.To.FQDN) > 0 && !onlyPort80(r.To.Ports) {
		pl.Notes = append(pl.Notes, "not terminated: domain-fronting exposed (design §7.5)")
	}
	if r.Action == ActionTagAndLog {
		pl.Notes = append(pl.Notes, "allowed and tagged in the audit log")
	}
	if r.Action == ActionAsk && cr.ask != nil {
		pl.Notes = append(pl.Notes, cr.ask.describe())
		if r.HTTP == nil && r.Model == nil && r.Budget == nil {
			pl.Notes = append(pl.Notes, "asked once per tunnel; on a terminated host, once per request")
		}
	}
	if r.Action == ActionRateLimit && r.Rate != nil {
		pl.Notes = append(pl.Notes, fmt.Sprintf("allowed up to %d requests per %s, shared with the run's nested runs; beyond it, a narrated 429",
			r.Rate.Requests, r.Rate.Per))
	}
	if (c.opts.Mode == Transparent || c.opts.Mode == TransparentAudit) && len(r.To.FQDN) > 0 && r.Action != ActionDeny && mayCarryRawTCP(r.To.Ports) {
		pl.Notes = append(pl.Notes, "transparent: traffic that is neither TLS nor HTTP (SSH, databases) matches through the run's own lookup of the name via the node; a hard-coded address does not")
	}
	return pl
}

// mayCarryRawTCP: the ports include one not usually TLS or HTTP (none
// listed means every port).
func mayCarryRawTCP(ports []uint16) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		switch p {
		case 80, 443, 8080, 8443:
		default:
			return true
		}
	}
	return false
}

// observe places the observe block (milestone 6.2): visibility only.
func (c *compiler) observe(p *AgentProfile, cp *CompiledProfile) {
	o := p.Spec.Observe
	if o == nil || !o.TLSPlaintext {
		return
	}
	pl := Placement{Rule: "observe/tls-plaintext", Tier: "audit",
		EnforcedBy: "uprobes on OpenSSL, BoringSSL and GnuTLS in the run's processes",
		Notes: []string{"visibility only: requests are recorded, never decided",
			"each TLS call of the run's processes costs a few microseconds, and each exec up to about 15 ms"}}
	switch {
	case !c.opts.Linux:
		pl.EnforcedBy, pl.Notes = "not observed: needs the Linux node agent", nil
	case !c.opts.Uprobes:
		pl.EnforcedBy, pl.Notes = "not observed: needs the node agent's -uprobes", nil
	default:
		pl.Notes = append(pl.Notes, "not seen: statically linked or stripped TLS stacks (Go, Bun, rustls), and forked children that do not exec")
	}
	cp.Placements = append(cp.Placements, pl)
}

// CapturesTLS says whether the profile asks for TLS plaintext.
func (cp *CompiledProfile) CapturesTLS() bool {
	return cp.Profile != nil && cp.Profile.Spec.Observe != nil && cp.Profile.Spec.Observe.TLSPlaintext
}

func (c *compiler) exec(p *AgentProfile, cp *CompiledProfile) {
	e := p.Spec.Exec
	if e == nil {
		return
	}
	switch e.Default {
	case ActionAllow, ActionDeny:
	case "":
		c.errf("exec.default", "is required: allow or deny")
	default:
		c.errf("exec.default", "must be allow or deny, got %q", e.Default)
	}
	if e.RequireReadonlyOrigin {
		e.RequireTrustedPath = true // the earlier name
	}
	enforceable := c.opts.ExecEnforceable()
	if (p.Spec.Mode == ModeEnforce || p.Spec.Mode == ModeAsk) && !e.AuditOnly && !enforceable {
		c.errf("exec", "exec rules cannot be enforced by this deployment: gating exec needs transparent mode with BPF LSM. "+
			"Set exec.audit_only: true to keep them as audit-only, or remove the exec block")
	}
	ce := &compiledExec{Exec: *e, allow: map[string]bool{}, hashes: map[string][][32]byte{}}
	tier, by := "1", "BPF LSM (bprm_check_security), by resolved path"
	var notes []string
	switch {
	case !c.opts.Linux:
		tier, by = "audit", "not observed: needs the Linux node agent"
	case !enforceable:
		tier, by = "audit", "exec events from the node agent"
		notes = append(notes, "not enforced: needs transparent mode with BPF LSM")
	case e.AuditOnly:
		tier = "audit"
		notes = append(notes, "audit_only: refusals recorded, not made")
	}
	hashable := c.opts.Linux && enforceable && c.opts.ExecHash
	byHash := "BPF LSM (bprm_check_security), by resolved path and SHA-256 (bpf_ima_file_hash)"
	if !hashable {
		byHash = by
	}
	cp.Placements = append(cp.Placements, Placement{
		Rule: "exec (default " + e.Default + ")", Tier: tier, EnforcedBy: by, Notes: notes,
	})
	if e.RequireTrustedPath {
		cp.Placements = append(cp.Placements, Placement{
			Rule: "exec/trusted-path", Tier: tier, EnforcedBy: by,
			Notes: append(append([]string{}, notes...), "execs not in exec.allow must come from root-owned paths no one else can write"),
		})
	}
	plain := map[string]bool{} // exact paths listed without a hash
	pinned := map[string]int{} // exact paths listed with one: their placement
	for i, a := range e.Allow {
		where := fmt.Sprintf("exec.allow[%d]", i)
		dir, prefix := strings.CutSuffix(a.Path, "/*")
		switch {
		case prefix && (!path.IsAbs(dir) || path.Clean(dir) != dir || dir == "/"):
			c.errf(where, "prefix %q must be an absolute, clean directory followed by /*", a.Path)
			continue
		case !prefix && (!path.IsAbs(a.Path) || path.Clean(a.Path) != a.Path || strings.Contains(a.Path, "*")):
			c.errf(where, "path %q must be absolute and clean, or a directory followed by /*: a basename matches any file of that name (design §7.6)", a.Path)
			continue
		case len(a.Path) > 255:
			c.errf(where, "path %q is longer than the kernel compares", a.Path)
			continue
		}
		if a.Hash != "" {
			if prefix {
				c.errf(where, "a hash pins one file: %q must be an exact path, not a directory", a.Path)
				continue
			}
			sum, err := ParseExecHash(a.Hash)
			if err != nil {
				c.errf(where, "%v", err)
				continue
			}
			if enforceable && !c.opts.ExecHash && !e.AuditOnly && (p.Spec.Mode == ModeEnforce || p.Spec.Mode == ModeAsk) {
				c.errf(where, "this node's kernel cannot hash files at exec (bpf_ima_file_hash, Linux 5.18; the TAI clock, 5.19), "+
					"so a hash cannot be verified. Set exec.audit_only: true, or remove the hash")
				continue
			}
			if plain[a.Path] {
				c.errf(where, "%s is also listed without a hash, which allows any content", a.Path)
				continue
			}
			if len(ce.hashes[a.Path]) == MaxExecHashes {
				c.errf(where, "at most %d hashes for %s", MaxExecHashes, a.Path)
				continue
			}
			dup := false
			for _, h := range ce.hashes[a.Path] {
				dup = dup || h == sum
			}
			if !dup {
				ce.hashes[a.Path] = append(ce.hashes[a.Path], sum)
			}
			if j, ok := pinned[a.Path]; ok {
				cp.Placements[j].Notes[0] = fmt.Sprintf("content-verified: one of %d SHA-256s", len(ce.hashes[a.Path]))
				continue
			}
			ce.allow[a.Path] = true
			pl := Placement{Rule: "exec/" + path.Base(a.Path), Tier: tier, EnforcedBy: byHash,
				Notes: append([]string{"content-verified: SHA-256"}, notes...)}
			if hashable {
				pl.Notes = append(pl.Notes, "other content at this path is refused, whatever the default; "+
					"hashed at exec, and cached per inode on ext4, xfs, btrfs and tmpfs")
			} else if enforceable {
				pl.Notes = append(pl.Notes, "hash not verified: this kernel cannot hash files at exec")
			} else {
				pl.Notes = append(pl.Notes, "hash not verified: needs transparent mode with BPF LSM")
			}
			if a.Note != "" {
				pl.Notes = append(pl.Notes, a.Note)
			}
			pinned[a.Path] = len(cp.Placements)
			cp.Placements = append(cp.Placements, pl)
			continue
		}
		if !prefix {
			if _, ok := pinned[a.Path]; ok {
				c.errf(where, "%s is also listed with a hash: without one, any content would pass", a.Path)
				continue
			}
			plain[a.Path] = true
		}
		pl := Placement{Rule: "exec/" + path.Base(a.Path), Tier: tier, EnforcedBy: by, Notes: append([]string{"path only"}, notes...)}
		if prefix {
			ce.prefixes = append(ce.prefixes, dir+"/")
			pl.Rule = "exec/" + a.Path
			pl.Notes = append(pl.Notes, "every file below the directory, including ones the run writes there")
		} else {
			ce.allow[a.Path] = true
		}
		if a.Note != "" {
			pl.Notes = append(pl.Notes, a.Note)
		}
		cp.Placements = append(cp.Placements, pl)
	}
	if len(ce.prefixes) > MaxExecPrefixes {
		c.errf("exec.allow", "at most %d directory prefixes (/*)", MaxExecPrefixes)
	}
	cp.exec = ce
}

func (c *compiler) mcp(p *AgentProfile, cp *CompiledProfile) {
	m := p.Spec.MCP
	if m == nil {
		return
	}
	cp.mcp = m
	switch m.Default {
	case ActionAllow, ActionDeny:
	case "":
		c.errf("mcp.default", "is required: allow or deny")
	default:
		c.errf("mcp.default", "must be allow or deny, got %q", m.Default)
	}
	cp.Placements = append(cp.Placements, Placement{
		Rule: "mcp (default " + m.Default + ")", Tier: "2", EnforcedBy: "ext_proc and the local MCP gateway",
		Notes: []string{"applies to listed remote hosts and to servers behind the gateway; other remote MCP traffic is governed by egress rules only"},
	})
	names := map[string]bool{}
	for i, s := range m.Servers {
		where := fmt.Sprintf("mcp.servers[%d]", i)
		if s.Name != "" {
			where += " (" + s.Name + ")"
		}
		if !nameRE.MatchString(s.Name) {
			c.errf(where, "name %q must be lowercase letters, digits and '-'", s.Name)
		}
		if names[s.Name] {
			c.errf(where, "duplicate server name %q", s.Name)
		}
		names[s.Name] = true
		if (s.Match.FQDN == "") == (s.Match.Stdio == "") {
			c.errf(where, "match: needs exactly one of fqdn or stdio")
		}
		if s.Match.FQDN != "" {
			if hp, err := parseHost(s.Match.FQDN); err != nil {
				c.errf(where, "%v", err)
			} else if hp.any {
				c.errf(where, "match.fqdn \"*\" would terminate every host")
			}
		}
		if s.Tools != nil {
			for _, g := range append(append([]string{}, s.Tools.Allow...), s.Tools.Deny...) {
				if g == "" {
					c.errf(where, "empty tool pattern")
				}
			}
		}
		pl := Placement{Rule: "mcp/" + s.Name, Tier: "2"}
		if s.Match.FQDN != "" {
			pl.EnforcedBy = "ext_proc (JSON-RPC on " + s.Match.FQDN + ")"
			pl.Notes = append(pl.Notes, "terminated: see posture")
		} else {
			pl.Tier = "gateway"
			pl.EnforcedBy = "local MCP gateway (" + s.Match.Stdio + ")"
			pl.Notes = append(pl.Notes, "plaintext on loopback; spawning the server directly bypasses the gateway, and exec policy is the backstop (Phase 4)")
		}
		if s.PinToolDefinitions {
			pl.Notes = append(pl.Notes, "tools/list pinned")
		}
		cp.Placements = append(cp.Placements, pl)
	}
	if m.Sampling != nil {
		switch m.Sampling.Action {
		case ActionAllow, ActionDeny:
		case ActionAsk:
			cp.samplingAsk = c.askConfig("mcp.sampling", m.Sampling.Ask, cp.askDefault)
		default:
			c.errf("mcp.sampling", "action must be allow, deny or ask, got %q", m.Sampling.Action)
		}
		if m.Sampling.Ask != nil && m.Sampling.Action != ActionAsk {
			c.errf("mcp.sampling", "ask: is only valid with action ask")
		}
		if m.Sampling.Action == ActionDeny && strings.TrimSpace(m.Sampling.Message) == "" {
			c.errf("mcp.sampling", "a deny needs a message (design §7.7)")
		}
		cp.Placements = append(cp.Placements, Placement{
			Rule: "mcp/sampling", Tier: "2", EnforcedBy: "ext_proc and the local MCP gateway (server-to-client stream)",
			Notes: append([]string{"sampling " + m.Sampling.Action}, samplingAskNote(cp)...),
		})
	}
}

// posture derives the TLS posture of every named destination across all
// profiles (design §6.6), and reports no_terminate conflicts.
func (c *compiler) posture(profiles []*AgentProfile) []DestPosture {
	type dest struct {
		why     []string
		noTerm  []string // "profile/rule"
		users   map[string]bool
		needers map[string]bool
		plain   bool // every rule needing L7 is on port 80 only
		needs   bool
	}
	dests := map[string]*dest{}
	get := func(h string) *dest {
		d := dests[h]
		if d == nil {
			d = &dest{users: map[string]bool{}, needers: map[string]bool{}, plain: true}
			dests[h] = d
		}
		return d
	}
	for _, p := range profiles {
		for _, r := range p.Spec.Egress.Rules {
			for _, h := range r.To.FQDN {
				d := get(h)
				d.users[p.Metadata.Name] = true
				if r.NoTerminate {
					d.noTerm = append(d.noTerm, p.Metadata.Name+"/"+r.Name)
				}
				if r.HTTP != nil || r.Model != nil || r.Budget != nil {
					d.needs = true
					d.needers[p.Metadata.Name] = true
					if !onlyPort80(r.To.Ports) {
						d.plain = false
					}
					var whats []string
					for _, w := range []struct {
						on   bool
						name string
					}{{r.HTTP != nil, "http"}, {r.Model != nil, "model"}, {r.Budget != nil, "budget"}} {
						if w.on {
							whats = append(whats, w.name)
						}
					}
					what := strings.Join(whats, ", ")
					d.why = append(d.why, fmt.Sprintf("%s (%s: %s)", p.Metadata.Name, r.Name, what))
				}
			}
		}
		// Content rules read request bodies (milestone 5.1).
		for _, cr := range p.Spec.Content {
			hosts, plain := contentScope(p, cr)
			for _, h := range hosts {
				d := get(h)
				d.users[p.Metadata.Name] = true
				d.needs = true
				d.needers[p.Metadata.Name] = true
				if !plain[h] {
					d.plain = false
				}
				d.why = append(d.why, fmt.Sprintf("%s (content %s)", p.Metadata.Name, cr.Name))
			}
		}
		if p.Spec.MCP != nil {
			for _, s := range p.Spec.MCP.Servers {
				if s.Match.FQDN == "" {
					continue
				}
				d := get(s.Match.FQDN)
				d.users[p.Metadata.Name] = true
				d.needs = true
				d.plain = false
				d.needers[p.Metadata.Name] = true
				d.why = append(d.why, fmt.Sprintf("%s (mcp %s)", p.Metadata.Name, s.Name))
			}
		}
	}

	keys := make([]string, 0, len(dests))
	for k := range dests {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// no_terminate conflicts, including across a wildcard and a name it covers.
	for _, k := range keys {
		d := dests[k]
		if !d.needs || d.plain {
			continue
		}
		if k == "*" {
			c.prof = "(node)"
			c.errf("posture", "a rule needing termination targets fqdn \"*\"; termination needs a certificate per host")
			continue
		}
		for _, nk := range keys {
			nd := dests[nk]
			if len(nd.noTerm) == 0 || !overlaps(k, nk) {
				continue
			}
			c.prof = "(node)"
			c.errf("posture", "%s must be terminated for %s, but %s asserts no_terminate (design §6.6)",
				k, strings.Join(d.why, ", "), strings.Join(nd.noTerm, ", "))
		}
	}

	var out []DestPosture
	for _, k := range keys {
		d := dests[k]
		dp := DestPosture{Dest: k, Posture: PosturePassthrough}
		switch {
		case d.needs && d.plain:
			dp.Posture = PosturePlaintext
			dp.Why = append([]string{"http rules on port 80 only"}, d.why...)
		case d.needs:
			dp.Posture = PostureTerminate
			dp.Why = d.why
			for u := range d.users {
				if !d.needers[u] {
					dp.Others = append(dp.Others, u)
				}
			}
			sort.Strings(dp.Others)
		case len(d.noTerm) > 0:
			dp.Why = []string{"no_terminate: " + strings.Join(d.noTerm, ", ")}
		default:
			dp.Why = []string{"no rule needs more than the hostname"}
		}
		out = append(out, dp)
	}
	return out
}

// overlaps reports whether two fqdn entries can name the same host.
func overlaps(a, b string) bool {
	if a == b || a == "*" || b == "*" {
		return true
	}
	pa, err1 := parseHost(a)
	pb, err2 := parseHost(b)
	if err1 != nil || err2 != nil {
		return false
	}
	switch {
	case pa.exact != "" && pb.exact == "":
		return pb.match(pa.exact)
	case pb.exact != "" && pa.exact == "":
		return pa.match(pb.exact)
	}
	return false
}

// maxUnixPatterns matches MAX_UNIX_PATTERNS in agent_audit.c; a sun_path
// holds 108 bytes.
const (
	maxUnixPatterns = 8
	maxUnixPath     = 107
)

func (c *compiler) unix(p *AgentProfile, cp *CompiledProfile) {
	u := p.Spec.Unix
	if u == nil {
		return
	}
	if len(u.Allow) > maxUnixPatterns {
		c.errf("unix.allow", "at most %d entries", maxUnixPatterns)
	}
	for i, pat := range u.Allow {
		where := fmt.Sprintf("unix.allow[%d]", i)
		body := strings.TrimSuffix(pat, "*")
		switch {
		case !strings.HasPrefix(pat, "/") && !strings.HasPrefix(pat, "@"):
			c.errf(where, "%q must be an absolute path or an abstract name (@name)", pat)
			continue
		case strings.Contains(body, "*"):
			c.errf(where, "%q: * is allowed only at the end", pat)
			continue
		case len(strings.ReplaceAll(body, "{uid}", "4294967295")) > maxUnixPath:
			c.errf(where, "%q is longer than a Unix socket address", pat)
			continue
		case strings.ContainsAny(strings.ReplaceAll(body, "{uid}", ""), "{}"):
			c.errf(where, "%q: the only placeholder is {uid}", pat)
			continue
		}
		cp.UnixAllow = append(cp.UnixAllow, pat)
		pl := Placement{Rule: "unix/" + pat, Tier: "1", EnforcedBy: "BPF LSM (unix_stream_connect, unix_may_send)"}
		if !c.opts.KernelLSM || (c.opts.Mode != Transparent && c.opts.Mode != TransparentAudit) {
			pl.EnforcedBy = "not enforced: needs transparent mode with BPF LSM"
		}
		if RootSocket(pat) {
			pl.Notes = append(pl.Notes, "gives root: the ceiling must set allowRootSockets")
		}
		if n := UnixBypass(pat); n != "" {
			pl.Notes = append(pl.Notes, n)
		}
		if strings.HasSuffix(pat, "*") {
			pl.Notes = append(pl.Notes, "prefix")
		}
		cp.Placements = append(cp.Placements, pl)
	}
}

// rootSockets are the well-known sockets whose daemons run anything they
// are asked to as root.
var rootSockets = []string{
	"/var/run/docker.sock", "/run/docker.sock",
	"/run/podman/podman.sock", "/var/run/podman/podman.sock",
	"/run/user/{uid}/podman/podman.sock", "/run/user/{uid}/docker.sock",
	"/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
	"/run/crio/crio.sock", "/var/run/crio/crio.sock",
}

// RootSocket reports whether a unix.allow pattern admits a socket that
// gives root.
func RootSocket(pat string) bool {
	for _, r := range rootSockets {
		if UnixCovers(pat, r) || UnixCovers(pat, strings.ReplaceAll(r, "{uid}", "0")) {
			return true
		}
	}
	for _, base := range []string{"docker.sock", "podman.sock", "containerd.sock", "crio.sock"} {
		if strings.HasSuffix(pat, "/"+base) {
			return true
		}
	}
	return false
}

// UnixBypass explains how a unix.allow pattern reaches around other
// controls, or returns "".
func UnixBypass(pat string) string {
	switch {
	case UnixCovers(pat, "/run/systemd/resolve/io.systemd.Resolve"):
		return "systemd-resolved resolves any name for the run, bypassing the node's resolver (DNS tunnelling)"
	case UnixCovers(pat, "/run/dbus/system_bus_socket"), UnixCovers(pat, "/var/run/dbus/system_bus_socket"):
		return "the system bus reaches system services, systemd-resolved's name resolution among them"
	}
	return ""
}

// UnixCovers reports whether pattern a admits everything pattern (or
// path) b does.
func UnixCovers(a, b string) bool {
	if pa, ok := strings.CutSuffix(a, "*"); ok {
		return strings.HasPrefix(strings.TrimSuffix(b, "*"), pa)
	}
	return a == b
}

func samplingAskNote(cp *CompiledProfile) []string {
	if cp.samplingAsk == nil {
		return nil
	}
	return []string{"the server's request is " + cp.samplingAsk.describe()}
}
