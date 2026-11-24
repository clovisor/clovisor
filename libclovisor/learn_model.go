// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"sort"
	"strings"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Learning models (milestone 5.3). A run records the model each request
// named only where a model rule decided it, so models are learnt from
// runs under a profile whose rule for the host has model: { allow: ["*"] }.
// Each drafted rule for such a host gets a model list naming exactly the
// models its requests named and were let through with.

// modelsSeen is what requests on some paths named.
type modelsSeen struct {
	models map[string]int // model -> requests let through
	none   map[string]int // reason no model was read -> requests
}

type hostPath struct {
	host         string
	method, path string
}

// collectModels aggregates the models runs' requests named, by host and
// path. Refused requests are left out, as for paths.
func collectModels(runs []*RunTimeline) (map[hostPath]*modelsSeen, int) {
	out := map[hostPath]*modelsSeen{}
	dropped := 0
	for _, tl := range runs {
		dropped += tl.Summary.ModelsDropped
		for _, u := range tl.Summary.Models {
			n := u.Requests - u.Denied
			if n <= 0 {
				continue
			}
			k := hostPath{policy.NormalizeHost(u.Host), u.Method, u.Path}
			ms := out[k]
			if ms == nil {
				ms = &modelsSeen{models: map[string]int{}, none: map[string]int{}}
				out[k] = ms
			}
			if u.Model == "" {
				ms.none[u.Reason] += n
			} else {
				ms.models[u.Model] += n
			}
		}
	}
	return out, dropped
}

// draftModel is what a drafted rule's model list was learnt from.
type draftModel struct {
	models map[string]int
	none   map[string]int
}

// learnModels gives each drafted egress rule the models its requests
// named.
func (d *Draft) learnModels(runs []*RunTimeline) {
	seen, dropped := collectModels(runs)
	d.modelsDropped = dropped
	if len(seen) == 0 {
		return
	}
	d.ruleModels = map[string]*draftModel{}
	for i := range d.Profile.Spec.Egress.Rules {
		r := &d.Profile.Spec.Egress.Rules[i]
		if len(r.To.FQDN) != 1 {
			continue
		}
		host := policy.NormalizeHost(r.To.FQDN[0])
		dm := &draftModel{models: map[string]int{}, none: map[string]int{}}
		for k, ms := range seen {
			if k.host != host {
				continue
			}
			if g := d.httpGroups[r.Name]; g != nil && !groupHas(g, k.method, k.path) {
				continue
			}
			for m, n := range ms.models {
				dm.models[m] += n
			}
			for why, n := range ms.none {
				dm.none[why] += n
			}
		}
		if len(dm.models) == 0 {
			continue
		}
		models := make([]string, 0, len(dm.models))
		for m := range dm.models {
			if policy.ValidModelPattern(m) && !strings.Contains(m, "*") {
				models = append(models, m)
			}
		}
		sort.Strings(models)
		if len(models) == 0 {
			continue
		}
		r.Model = &policy.ModelMatch{Allow: models}
		d.ruleModels[r.Name] = dm
	}
}

func groupHas(g *httpGroup, method, path string) bool {
	for _, ps := range g.paths {
		if ps.method == method && ps.path == path {
			return true
		}
	}
	return false
}

// writeModelComments explains a drafted model list, above its rule.
func (d *Draft) writeModelComments(p func(string, ...interface{}), r policy.EgressRule) {
	dm := d.ruleModels[r.Name]
	if dm == nil {
		return
	}
	var parts []string
	for _, m := range sortedKeysInt(dm.models) {
		parts = append(parts, commentSafe(m)+" ("+plural(dm.models[m], "request")+")")
	}
	p("      # Models named: %s.", strings.Join(parts, ", "))
	var bad []string
	for _, m := range sortedKeysInt(dm.models) {
		if !policy.ValidModelPattern(m) || strings.Contains(m, "*") {
			bad = append(bad, commentSafe(m))
		}
	}
	if len(bad) > 0 {
		p("      # Left out, as no model entry can name them exactly: %s.", strings.Join(bad, ", "))
	}
	if len(dm.none) > 0 {
		n := 0
		var whys []string
		for _, why := range sortedKeysInt(dm.none) {
			n += dm.none[why]
			whys = append(whys, commentSafe(why))
		}
		p("      # %s on these paths named no model (%s); this rule refuses", plural(n, "request"), strings.Join(whys, "; "))
		p("      # them. If they are needed, give their paths a rule of their own above this one.")
	}
}

// writeModelLine renders a drafted rule's model list.
func writeModelLine(p func(string, ...interface{}), r policy.EgressRule) {
	if r.Model == nil {
		return
	}
	qs := make([]string, len(r.Model.Allow))
	for i, m := range r.Model.Allow {
		qs[i] = q(m)
	}
	p("        model: { allow: [%s] }", strings.Join(qs, ", "))
}
