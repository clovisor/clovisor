// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"encoding/json"
	"net/url"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Model allow-lists (milestone 5.3). A request a model rule decides is
// let through only if it names a model the rule's list admits: the
// top-level "model" field of a JSON body, and a "model" query parameter
// if it has one. The body is held as for content rules (extproc_body.go)
// and checked once complete.

// ModelData is the model one request named and the decision on it, for
// the run's timeline.
type ModelData struct {
	Host      string
	Port      uint16
	Method    string
	Path      string
	Where     string // "body" or "query string"
	Model     string // as named, at most maxRecordedModel bytes; "" if none
	Decision  string // allow or deny
	Enforced  bool
	Rule      string // the rule whose list decided
	Layer     string
	WouldDeny []string
	Reason    string // why no model could be read
	Message   string
}

// maxRecordedModel bounds a model name as recorded: the run chooses it.
const maxRecordedModel = 128

// bodyModel reads the top-level "model" field of a JSON object. It reads
// the keys itself, rather than decoding into a struct, so that a key is
// matched exactly (encoding/json folds case) and a second "model" key,
// which parsers resolve differently, is refused rather than guessed at.
func bodyModel(body []byte) (model, why string) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return policy.ModelMissing, "its body is not a JSON object"
	}
	found := false
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return policy.ModelMissing, "its body is not valid JSON"
		}
		key, _ := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return policy.ModelMissing, "its body is not valid JSON"
		}
		if key != "model" {
			continue
		}
		if found {
			return policy.ModelMissing, `its body has more than one "model" field`
		}
		found = true
		if err := json.Unmarshal(v, &model); err != nil {
			return policy.ModelMissing, `its "model" field is not a string`
		}
		if model == "" {
			return policy.ModelMissing, `its "model" field is empty`
		}
	}
	if _, err := dec.Token(); err != nil {
		return policy.ModelMissing, "its body is not valid JSON"
	}
	if dec.More() {
		return policy.ModelMissing, "its body holds more than one JSON value"
	}
	if !found {
		return policy.ModelMissing, ""
	}
	return model, ""
}

// queryModel reads a "model" query parameter: named reports whether there
// is one, why whether it could not be read.
func queryModel(rawQuery string) (model string, named bool, why string) {
	if rawQuery == "" {
		return "", false, ""
	}
	q, err := url.ParseQuery(rawQuery)
	vs, ok := q["model"]
	switch {
	case err != nil && ok:
		return policy.ModelMissing, true, "its query string cannot be parsed"
	case !ok:
		return "", false, ""
	case len(vs) > 1:
		return policy.ModelMissing, true, `its query string has more than one "model" parameter`
	case vs[0] == "":
		return policy.ModelMissing, true, `its "model" parameter is empty`
	}
	return vs[0], true, ""
}

// checkModel decides a request on the model it named, records it, and
// returns the refusal, or nil to let it through.
func (s *ExtProcServer) checkModel(d HTTPData, checks []policy.ModelCheck, where, model, why, runID string, leaf, runCg uint64) *extprocv3.ProcessingResponse {
	v := policy.CheckModel(checks, d.Host, model, why)
	md := ModelData{Host: d.Host, Port: d.Port, Method: d.Method, Path: d.Path, Where: where, Model: model,
		Decision: policy.ActionAllow, WouldDeny: v.WouldDeny, Reason: why}
	if len(md.Model) > maxRecordedModel {
		md.Model = md.Model[:maxRecordedModel]
	}
	if model == policy.ModelMissing && why == "" {
		md.Reason = "no model named"
	}
	if v.Denied != nil {
		md.Decision, md.Enforced, md.Rule, md.Layer, md.Message = policy.ActionDeny, true, v.Denied.Rule, v.Denied.Layer, v.Message
	} else if len(checks) > 0 {
		md.Rule, md.Layer = checks[0].Rule, checks[0].Layer
	}
	s.recordModel(leaf, runCg, runID, md)
	if v.Denied == nil {
		return nil
	}
	d.Decision, d.Enforced, d.Rule, d.Layer, d.Message = policy.ActionDeny, true, v.Denied.Rule, v.Denied.Layer, v.Message
	return s.deny(d, runID)
}

func (s *ExtProcServer) recordModel(leaf, runCg uint64, runID string, d ModelData) {
	if runID == "" || runCg == 0 || s.events == nil {
		return
	}
	if leaf == 0 {
		leaf = runCg
	}
	select {
	case s.events <- AuditEvent{Type: EventModel, Timestamp: time.Now(), CgroupID: leaf, RunCgroupID: runCg, Data: d}:
	default:
		s.dropped.Add(1)
	}
}
