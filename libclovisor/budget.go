// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Budgets (milestone 5.4). A rule's budget belongs to the run that holds
// its layer (owner, as for limits), so a nested run's model calls are
// charged to its parent's budget. Spending is kept in the counter store,
// so a node agent restart does not refill a budget.

// BudgetSpend is what one budget's owner has spent.
type BudgetSpend struct {
	Layer     string  `json:"layer"`
	Rule      string  `json:"rule"`
	Tokens    int64   `json:"tokens"`
	CostUSD   float64 `json:"cost_usd"`
	Requests  int     `json:"requests"`
	Estimated int     `json:"estimated,omitempty"` // requests charged an estimate: no usage in the response
	Unpriced  int     `json:"unpriced,omitempty"`  // requests whose model had no price: tokens charged, no cost
	// The budget, as last charged.
	LimitTokens int64   `json:"limit_tokens,omitempty"`
	LimitCost   float64 `json:"limit_cost_usd,omitempty"`
}

// BudgetLedger checks and charges budgets for ext_proc.
type BudgetLedger struct {
	api   *RunAPIServer
	store *CounterStore
	// Prices returns the node's current price list.
	Prices func() *policy.ModelPrices

	mu    sync.Mutex
	noted map[string]map[string]bool // run -> budget hits already recorded
}

// NewBudgetLedger returns a ledger keeping spend in store.
func NewBudgetLedger(api *RunAPIServer, store *CounterStore) *BudgetLedger {
	return &BudgetLedger{api: api, store: store, noted: map[string]map[string]bool{},
		Prices: func() *policy.ModelPrices {
			if set := api.policy.Load(); set != nil {
				return set.Prices
			}
			return nil
		}}
}

func (l *BudgetLedger) prices() *policy.ModelPrices {
	if l == nil || l.Prices == nil {
		return nil
	}
	return l.Prices()
}

// spent returns what owner has spent of b.
func (l *BudgetLedger) spent(owner string, b policy.BudgetCheck) BudgetSpend {
	c := l.store.Get(owner)
	if s := c.Spend[b.Key()]; s != nil {
		return *s
	}
	return BudgetSpend{Layer: b.Layer, Rule: b.Rule}
}

// note records a budget reached on run's metadata, once per run, budget
// and action.
func (l *BudgetLedger) note(runID, owner string, b policy.BudgetCheck, action string) {
	key := b.Key() + "/" + action
	l.mu.Lock()
	if l.noted[runID] == nil {
		l.noted[runID] = map[string]bool{}
	}
	seen := l.noted[runID][key]
	l.noted[runID][key] = true
	l.mu.Unlock()
	if seen || l.api == nil || l.api.reg == nil {
		return
	}
	h := LimitHit{At: time.Now().UTC(), Limit: "budget " + b.Rule, Layer: b.Layer, Value: b.Describe(), Action: action}
	if owner != runID {
		h.Run = owner
	}
	l.api.reg.Update(runID, func(m *RunMeta) { m.Limits = append(append([]LimitHit{}, m.Limits...), h) })
}

// forget drops what the ledger remembers of a run that ended.
func (l *BudgetLedger) forget(runID string) {
	l.mu.Lock()
	delete(l.noted, runID)
	l.mu.Unlock()
}

// budgetOwners pairs each budget check with the run whose budget it is.
type budgetOwner struct {
	policy.BudgetCheck
	owner string
}

func (s *ExtProcServer) budgetOwners(ed policy.EffectiveDecision, eff *policy.Effective, runID string) []budgetOwner {
	chain := s.api.chain(runID)
	if len(chain) == 0 {
		chain = []runLink{{runID: runID, eff: eff}}
	}
	out := make([]budgetOwner, 0, len(ed.Budgets))
	for _, b := range ed.Budgets {
		out = append(out, budgetOwner{BudgetCheck: b, owner: owner(chain, b.Profile)})
	}
	return out
}

// checkBudgets refuses a request whose budget is spent, or records what
// an audit layer would do. It reports whether the request may proceed.
func (s *ExtProcServer) checkBudgets(d *HTTPData, owners []budgetOwner, runID string) bool {
	l := s.Budgets
	if l == nil {
		return true
	}
	for _, b := range owners {
		sp := l.spent(b.owner, b.BudgetCheck)
		if !b.Spent(sp.Tokens, sp.CostUSD) {
			continue
		}
		if !b.Enforced {
			d.WouldDeny = append(d.WouldDeny, b.Layer)
			if d.Reason == "" {
				d.Reason = "audit: budget " + b.Rule
			}
			l.note(runID, b.owner, b.BudgetCheck, "would refuse")
			continue
		}
		msg := b.Message
		if msg == "" {
			who := "This run has"
			if b.owner != runID {
				who = fmt.Sprintf("Run %s and the runs nested in it have", b.owner)
			}
			msg = fmt.Sprintf("%s spent the budget of rule %s of profile %s (%s): %s so far. No more requests are sent under it.",
				who, b.Rule, b.Layer, b.Describe(), spendString(sp))
		}
		d.Decision, d.Enforced, d.Layer, d.Rule, d.Reason, d.Message = policy.ActionDeny, true, b.Layer, b.Rule, "budget", msg
		l.note(runID, b.owner, b.BudgetCheck, "refused")
		return false
	}
	return true
}

func spendString(sp BudgetSpend) string {
	return fmt.Sprintf("%d tokens, $%.4f", sp.Tokens, sp.CostUSD)
}

// charge adds one call's usage to each budget's owner. cost is the call's
// cost, or negative if its model has no price. It returns each budget's
// totals after the charge.
func (l *BudgetLedger) charge(owners []budgetOwner, u policy.Usage, cost float64, estimated bool, runID string) []BudgetState {
	var out []BudgetState
	for _, b := range owners {
		var after BudgetSpend
		l.store.Update(b.owner, func(c *RunCounters) {
			if c.Spend == nil {
				c.Spend = map[string]*BudgetSpend{}
			}
			sp := c.Spend[b.Key()]
			if sp == nil {
				sp = &BudgetSpend{Layer: b.Layer, Rule: b.Rule}
				c.Spend[b.Key()] = sp
			}
			sp.Tokens += u.Tokens()
			sp.Requests++
			if cost >= 0 {
				sp.CostUSD += cost
			} else {
				sp.Unpriced++
			}
			if estimated {
				sp.Estimated++
			}
			sp.LimitTokens, sp.LimitCost = b.Tokens, b.CostUSD
			after = *sp
		})
		st := budgetState(after)
		if b.owner != runID {
			st.Run = b.owner
		}
		out = append(out, st)
		if b.Spent(after.Tokens, after.CostUSD) {
			action := "reached"
			if !b.Enforced {
				action = "would refuse"
			}
			l.note(runID, b.owner, b.BudgetCheck, action)
		}
	}
	return out
}

// BudgetState is a budget's totals, for run metadata and timelines.
type BudgetState struct {
	Layer       string  `json:"layer"`
	Rule        string  `json:"rule"`
	Run         string  `json:"run,omitempty"` // the owning run, when it is not this one
	Tokens      int64   `json:"tokens"`
	CostUSD     float64 `json:"cost_usd"`
	Requests    int     `json:"requests"`
	Estimated   int     `json:"estimated,omitempty"`
	Unpriced    int     `json:"unpriced,omitempty"`
	LimitTokens int64   `json:"limit_tokens,omitempty"`
	LimitCost   float64 `json:"limit_cost_usd,omitempty"`
}

func budgetState(sp BudgetSpend) BudgetState {
	return BudgetState{Layer: sp.Layer, Rule: sp.Rule, Tokens: sp.Tokens, CostUSD: sp.CostUSD, Requests: sp.Requests,
		Estimated: sp.Estimated, Unpriced: sp.Unpriced, LimitTokens: sp.LimitTokens, LimitCost: sp.LimitCost}
}

// ownedBudgets lists what a run spent of the budgets it owns, nested runs
// included, for its metadata when it ends.
func ownedBudgets(c RunCounters) []BudgetState {
	var out []BudgetState
	for _, sp := range c.Spend {
		out = append(out, budgetState(*sp))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Layer+"/"+out[i].Rule < out[j].Layer+"/"+out[j].Rule })
	return out
}
