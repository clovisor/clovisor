// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"strings"
)

// Model allow-lists (milestone 5.3). An egress rule with model: { allow }
// lets a request through only if it names one of the listed models: the
// top-level "model" field of its JSON body, as Anthropic- and
// OpenAI-shaped APIs take it, and a "model" query parameter if there is
// one. A request with a body that names none is refused, since nothing
// says which model it would reach. A request with no body (GET) names no
// model and calls none, so it passes on the rule alone.

// Model list bounds.
const (
	MaxModels      = 64
	maxModelLength = 128
)

// ModelMissing is the model a verdict reports for a body that named none.
const ModelMissing = ""

type compiledModels struct {
	allow []string // lowercased globs
}

// ValidModelPattern reports whether s can be a model.allow entry.
func ValidModelPattern(s string) bool { return validModelPattern(s) }

func validModelPattern(s string) bool {
	if s == "" || len(s) > maxModelLength {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._:/@*", c)) {
			return false
		}
	}
	return true
}

// model validates a rule's model block.
func (c *compiler) model(where string, r EgressRule) *compiledModels {
	m := r.Model
	switch {
	case len(r.To.CIDR) > 0:
		c.errf(where, "model: needs a hostname destination; cidr destinations are not known to be HTTP")
	case r.NoTerminate:
		c.errf(where, "model: reads the request body, which needs termination, but the rule asserts no_terminate (design §6.6)")
	case r.Action == ActionDeny:
		c.errf(where, "model: narrows what a rule lets through; a deny rule lets nothing through")
	}
	if len(m.Allow) == 0 {
		c.errf(where, "model.allow is empty: it would refuse every request with a body; deny the host instead")
		return nil
	}
	if len(m.Allow) > MaxModels {
		c.errf(where, "model.allow: at most %d entries", MaxModels)
	}
	out := &compiledModels{}
	for _, a := range m.Allow {
		if !validModelPattern(a) {
			c.errf(where, "model %q must be letters, digits and -._:/@, with * as a wildcard, at most %d characters", a, maxModelLength)
			continue
		}
		out.allow = append(out.allow, strings.ToLower(a))
	}
	return out
}

func (m *compiledModels) permits(model string) bool {
	return model != ModelMissing && globAny(m.allow, strings.ToLower(model))
}

// modelNotes are the receipt notes for a rule with a model list.
func modelNotes(r EgressRule) []string {
	notes := []string{"models allowed: " + strings.Join(r.Model.Allow, ", "),
		`read from the JSON body's top-level "model" field and a "model" query parameter; ` +
			"a body naming none, or naming it twice, is refused",
		"APIs that name the model in the path (Gemini, Bedrock) or a nested field (batches) are refused: give their paths a rule of their own above this one",
		"requests with no body pass on the rule alone"}
	for _, a := range r.Model.Allow {
		if a == "*" {
			notes = append(notes, `"*" admits any model: it records them, for learn, and still refuses bodies that name none`)
			break
		}
	}
	return notes
}

// ModelCheck is one layer's model list that a request must satisfy.
type ModelCheck struct {
	Layer    string
	Rule     string
	Allow    []string
	Message  string
	Enforced bool // the layer is in enforce mode
	m        *compiledModels
}

// Permits reports whether the check admits model (ModelMissing for a
// body that named none).
func (c ModelCheck) Permits(model string) bool { return c.m.permits(model) }

// ModelVerdict is what the model lists say about one request.
type ModelVerdict struct {
	// Denied is the first enforced check the model fails.
	Denied  *ModelCheck
	Message string
	// WouldDeny names audit layers whose lists the model fails.
	WouldDeny []string
}

// CheckModel applies a decision's model checks to the model a request
// names (ModelMissing if it names none). why, if set, says why none could
// be read ("its body is not JSON", "it names the model twice").
func CheckModel(checks []ModelCheck, host, model, why string) ModelVerdict {
	var v ModelVerdict
	for i := range checks {
		c := checks[i]
		if c.Permits(model) {
			continue
		}
		if !c.Enforced {
			v.WouldDeny = append(v.WouldDeny, c.Layer)
			continue
		}
		if v.Denied == nil {
			v.Denied = &c
			v.Message = c.Message
			if v.Message == "" {
				v.Message = modelMessage(c, host, model, why)
			}
		}
	}
	return v
}

func modelMessage(c ModelCheck, host, model, why string) string {
	list := strings.Join(c.Allow, ", ")
	if model == ModelMissing {
		if why == "" {
			why = `its body has no top-level "model" field`
		}
		return fmt.Sprintf("The request to %s was not sent: %s, and rule %s of profile %s allows only requests that name one of these models: %s.",
			host, why, c.Rule, c.Layer, list)
	}
	return fmt.Sprintf("The request to %s was not sent: model %q is not allowed by rule %s of profile %s. Allowed: %s.",
		host, model, c.Rule, c.Layer, list)
}

// ModelChecked reports whether the deciding rule has a model list.
func (d Decision) ModelChecked() bool { return d.models != nil }

// PermitsModel reports whether the deciding rule admits model; true if it
// has no model list.
func (d Decision) PermitsModel(model string) bool { return d.models == nil || d.models.permits(model) }

// ChecksModels reports whether any layer's model list applies.
func (d EffectiveDecision) ChecksModels() bool { return len(d.Models) > 0 }
