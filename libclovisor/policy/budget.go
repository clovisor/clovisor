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
	"math"
	"strings"

	"gopkg.in/yaml.v3"
)

// Budgets (milestone 5.4). An egress rule's budget bounds the tokens, and
// the cost in US dollars, of the model calls it lets through, per run
// holding the layer: a nested run's calls are charged to its parent's
// budget too, as limits are (5.2). Spending is read from the usage the
// provider reports in each response, streamed or not. Prices come from
// the node's ModelPrices document, never from a profile: a profile is
// what an agent asks for, and must not set its own prices. A request is
// refused once its budget is spent; what is spent by requests already in
// flight can take it past the budget, by at most what they cost.

// maxBudgetTokens bounds budget.tokens.
const maxBudgetTokens = 1 << 50

type compiledBudget struct {
	tokens int64
	cost   float64
}

// budget validates a rule's budget block.
func (c *compiler) budget(where string, r EgressRule) *compiledBudget {
	b := r.Budget
	switch {
	case len(r.To.CIDR) > 0:
		c.errf(where, "budget: needs a hostname destination; cidr destinations are not known to be HTTP")
	case r.NoTerminate:
		c.errf(where, "budget: reads requests and responses, which needs termination, but the rule asserts no_terminate (design §6.6)")
	case r.Action == ActionDeny:
		c.errf(where, "budget: bounds what a rule lets through; a deny rule lets nothing through")
	}
	ok := true
	if b.Tokens < 0 || b.Tokens > maxBudgetTokens {
		c.errf(where, "budget.tokens must be between 1 and %d", int64(maxBudgetTokens))
		ok = false
	}
	if b.CostUSD < 0 || math.IsNaN(b.CostUSD) || math.IsInf(b.CostUSD, 0) {
		c.errf(where, "budget.cost_usd must be a positive amount")
		ok = false
	}
	if ok && b.Tokens == 0 && b.CostUSD == 0 {
		c.errf(where, "budget needs tokens, cost_usd or both")
		ok = false
	}
	if !ok {
		return nil
	}
	return &compiledBudget{tokens: b.Tokens, cost: b.CostUSD}
}

// budgetNotes are the receipt notes for a rule with a budget.
func budgetNotes(r EgressRule) []string {
	var what []string
	if r.Budget.Tokens > 0 {
		what = append(what, fmt.Sprintf("%d tokens", r.Budget.Tokens))
	}
	if r.Budget.CostUSD > 0 {
		what = append(what, fmt.Sprintf("$%.2f at the node's prices", r.Budget.CostUSD))
	}
	notes := []string{"budget: " + strings.Join(what, " and ") + " per run holding the profile, shared with its nested runs",
		"charged from the usage in each response (Anthropic- and OpenAI-shaped, streamed or not); " +
			"a response without usage is charged an estimate, flagged",
		"refused once spent; requests in flight can take it past the budget by what they cost"}
	if r.Budget.CostUSD > 0 {
		notes = append(notes, "a request naming a model the node has no price for is refused")
	}
	return notes
}

// BudgetCheck is one layer's budget that a request is charged to.
type BudgetCheck struct {
	// Profile is the layer's profile; the budget is per run holding it.
	Profile  *CompiledProfile
	Layer    string
	Rule     string
	Tokens   int64   // 0: no token budget
	CostUSD  float64 // 0: no cost budget
	Message  string
	Enforced bool
}

// Key names the budget within its owning run.
func (b BudgetCheck) Key() string { return b.Layer + "/" + b.Rule }

// Spent reports whether tokens and cost have used up the budget.
func (b BudgetCheck) Spent(tokens int64, cost float64) bool {
	return (b.Tokens > 0 && tokens >= b.Tokens) || (b.CostUSD > 0 && cost >= b.CostUSD)
}

// Describe is the budget for narration: "500000 tokens and $25.00".
func (b BudgetCheck) Describe() string {
	var what []string
	if b.Tokens > 0 {
		what = append(what, fmt.Sprintf("%d tokens", b.Tokens))
	}
	if b.CostUSD > 0 {
		what = append(what, fmt.Sprintf("$%.2f", b.CostUSD))
	}
	return strings.Join(what, " and ")
}

// ChargesBudgets reports whether any layer's budget applies.
func (d EffectiveDecision) ChargesBudgets() bool { return len(d.Budgets) > 0 }

// ModelPrices is the node's price list (kind ModelPrices), in US dollars
// per million tokens. The first entry whose pattern matches a model
// prices it.
type ModelPrices struct {
	Kind     string          `yaml:"kind" json:"kind"`
	Metadata Metadata        `yaml:"metadata" json:"metadata"`
	Spec     ModelPricesSpec `yaml:"spec" json:"spec"`
	compiled []compiledPrice
}

// ModelPricesSpec lists prices.
type ModelPricesSpec struct {
	Models []ModelPrice `yaml:"models" json:"models"`
}

// ModelPrice prices models matching a glob. CacheRead and CacheWrite
// price prompt-cache tokens; without them, those are priced as input.
type ModelPrice struct {
	Match      string   `yaml:"match" json:"match"`
	Input      float64  `yaml:"input" json:"input"`
	Output     float64  `yaml:"output" json:"output"`
	CacheRead  *float64 `yaml:"cache_read,omitempty" json:"cache_read,omitempty"`
	CacheWrite *float64 `yaml:"cache_write,omitempty" json:"cache_write,omitempty"`
}

type compiledPrice struct {
	pattern string
	ModelPrice
}

// MaxPrices bounds a price list.
const MaxPrices = 1024

// DocumentKind reads a policy document's kind.
func DocumentKind(data []byte) string {
	var head struct {
		Kind string `yaml:"kind"`
	}
	if yaml.Unmarshal(data, &head) != nil {
		return ""
	}
	return head.Kind
}

// ParsePrices decodes and validates a ModelPrices document.
func ParsePrices(data []byte) (*ModelPrices, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p ModelPrices
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("a policy file holds exactly one YAML document")
	}
	if p.Kind != "ModelPrices" {
		return nil, fmt.Errorf("kind must be ModelPrices, got %q", p.Kind)
	}
	if len(p.Spec.Models) == 0 {
		return nil, fmt.Errorf("spec.models is empty")
	}
	if len(p.Spec.Models) > MaxPrices {
		return nil, fmt.Errorf("spec.models: at most %d entries", MaxPrices)
	}
	bad := func(f float64) bool { return f < 0 || math.IsNaN(f) || math.IsInf(f, 0) }
	for i, m := range p.Spec.Models {
		where := fmt.Sprintf("spec.models[%d]", i)
		if !validModelPattern(m.Match) {
			return nil, fmt.Errorf("%s: match %q must be letters, digits and -._:/@, with * as a wildcard", where, m.Match)
		}
		if bad(m.Input) || bad(m.Output) || (m.CacheRead != nil && bad(*m.CacheRead)) || (m.CacheWrite != nil && bad(*m.CacheWrite)) {
			return nil, fmt.Errorf("%s (%s): prices must be zero or positive dollars per million tokens", where, m.Match)
		}
		p.compiled = append(p.compiled, compiledPrice{pattern: strings.ToLower(m.Match), ModelPrice: m})
	}
	return &p, nil
}

// Price returns the price of model, if the list has one.
func (p *ModelPrices) Price(model string) (ModelPrice, bool) {
	if p == nil || model == "" {
		return ModelPrice{}, false
	}
	m := strings.ToLower(model)
	for _, c := range p.compiled {
		if glob(c.pattern, m) {
			return c.ModelPrice, true
		}
	}
	return ModelPrice{}, false
}

// Usage is the tokens one model call used. Input excludes cache tokens,
// which are counted apart.
type Usage struct {
	Input      int64 `json:"input,omitempty"`
	Output     int64 `json:"output,omitempty"`
	CacheRead  int64 `json:"cache_read,omitempty"`
	CacheWrite int64 `json:"cache_write,omitempty"`
}

// Tokens is every token the call used.
func (u Usage) Tokens() int64 { return u.Input + u.Output + u.CacheRead + u.CacheWrite }

// Cost is what the call cost at price, in US dollars.
func (u Usage) Cost(p ModelPrice) float64 {
	cr, cw := p.Input, p.Input
	if p.CacheRead != nil {
		cr = *p.CacheRead
	}
	if p.CacheWrite != nil {
		cw = *p.CacheWrite
	}
	return (float64(u.Input)*p.Input + float64(u.Output)*p.Output + float64(u.CacheRead)*cr + float64(u.CacheWrite)*cw) / 1e6
}
