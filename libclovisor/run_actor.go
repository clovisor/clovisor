// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// DefaultActorCheck is how often live Actor runs are checked against
// Substrate, to end the runs of Actors that are gone.
const DefaultActorCheck = 30 * time.Second

// actorState is Actor identity's part of the run API server.
type actorState struct {
	enabled bool
	byUID   map[string]string    // Actor UID -> run id
	info    map[string]ActorInfo // run id -> the Actor, as last seen
}

// EnableActors makes runs Agent Substrate Actors (milestone 7.3): they are
// made by the proxy on an Actor's first request, not by the run API, and
// end when Substrate no longer has the Actor. dir is checked every check.
func (s *RunAPIServer) EnableActors(dir ActorDirectory, check time.Duration) {
	s.mu.Lock()
	s.actors = actorState{enabled: true, byUID: map[string]string{}, info: map[string]ActorInfo{}}
	s.mu.Unlock()
	if check <= 0 {
		check = DefaultActorCheck
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(check)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.checkActors(dir)
			case <-s.done:
				return
			}
		}
	}()
}

// ActorIdentity reports whether runs are Actors.
func (s *RunAPIServer) ActorIdentity() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actors.enabled
}

// ActorRun returns the live run of an Actor's UID, if it has one.
func (s *RunAPIServer) ActorRun(uid string) (runID string, runCg uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runID, ok = s.actors.byUID[uid]
	return runID, s.runCg[runID], ok
}

// RunForActor returns the run of a placed Actor, starting it on the
// Actor's first request. The Actor's atespace and ActorTemplate choose
// its ceiling, whose default profile it gets: an Actor asks for nothing.
// A run for an older Actor of the same name (deleted and created again,
// so with another UID) is ended first.
func (s *RunAPIServer) RunForActor(a ActorInfo) (runID string, runCg uint64, eff *policy.Effective, err error) {
	s.mu.Lock()
	if id, ok := s.actors.byUID[a.UID]; ok {
		s.actors.info[id] = a
		cg := s.runCg[id]
		if b, ok := s.byCg[cg]; ok {
			eff = b.eff
		}
		s.mu.Unlock()
		return id, cg, eff, nil
	}
	var stale []string
	for id, old := range s.actors.info {
		if old.ActorRef == a.ActorRef {
			stale = append(stale, id)
		}
	}
	s.mu.Unlock()
	for _, id := range stale {
		s.endActorRun(id, "the Actor was deleted and created again (a new UID)")
	}

	var binding *policy.Binding
	if set := s.policy.Load(); set != nil {
		binding, err = set.Resolve(policy.Caller{UID: -1, Atespace: a.Atespace, ActorTemplate: a.Template}, "")
		if errors.Is(err, policy.ErrNoCeiling) {
			binding, err = nil, nil // unprofiled: audit only
		}
		if err != nil {
			return "", 0, nil, err
		}
	}
	if binding != nil {
		eff = binding.Effective
	}
	if runID, err = NewRunID(); err != nil {
		return "", 0, nil, err
	}
	s.mu.Lock()
	if id, ok := s.actors.byUID[a.UID]; ok {
		// Another request started it meanwhile.
		cg := s.runCg[id]
		var e *policy.Effective
		if b, ok := s.byCg[cg]; ok {
			e = b.eff
		}
		s.mu.Unlock()
		return id, cg, e, nil
	}
	s.nextCg++
	runCg = s.nextCg
	s.actors.byUID[a.UID] = runID
	s.actors.info[runID] = a
	s.active[runID] = true
	s.runByCg[runCg] = runID
	s.runCg[runID] = runCg
	if eff != nil {
		// An Actor has no uid: its run is the node agent's user's.
		b := &boundRun{runID: runID, uid: os.Geteuid(), cgroupID: runCg, eff: eff, started: time.Now()}
		s.bound[runID] = b
		s.byCg[runCg] = b
	}
	s.mu.Unlock()
	if s.OnRunStart != nil {
		s.OnRunStart(runID, runCg)
	}
	act := a
	s.reg.Put(RunMeta{RunID: runID, Command: []string{"actor", a.String()}, UID: os.Geteuid(), StartedAt: time.Now().UTC(),
		Policy: runPolicyRecord(binding), Actor: &act})
	s.emit(EventRunStart, runID, runCg)
	granted := "unprofiled"
	if binding != nil {
		g := binding.Effective.Layers[0]
		granted = g.Profile.Name + "@" + g.Profile.Profile.ShortVersion() + " (" + binding.Reason + ")"
	}
	log.Printf("run api: run %s for Actor %s (uid %s, template %s): %s", runID, a, a.UID, a.Template, granted)
	return runID, runCg, eff, nil
}

// checkActors ends the runs of Actors Substrate no longer has, or has
// again under another UID, or is deleting. A suspended Actor keeps its
// run: it comes back with the same UID, on any Worker.
func (s *RunAPIServer) checkActors(dir ActorDirectory) {
	s.mu.Lock()
	live := make(map[string]ActorInfo, len(s.actors.info))
	for id, a := range s.actors.info {
		live[id] = a
	}
	s.mu.Unlock()
	for id, a := range live {
		now, err := dir.Actor(context.Background(), a.ActorRef, 0)
		switch {
		case errors.Is(err, ErrActorNotFound):
			s.endActorRun(id, "the Actor was deleted")
		case err != nil:
			// Substrate's API failed, not the Actor: keep the run.
		case now.UID != a.UID:
			s.endActorRun(id, "the Actor was deleted and created again (a new UID)")
		case now.State == "DELETING":
			s.endActorRun(id, "the Actor is being deleted")
		default:
			s.mu.Lock()
			if _, ok := s.actors.info[id]; ok {
				s.actors.info[id] = now
			}
			s.mu.Unlock()
		}
	}
}

// endActorRun ends an Actor's run, saying why in its metadata.
func (s *RunAPIServer) endActorRun(runID, why string) {
	s.mu.Lock()
	a, ok := s.actors.info[runID]
	if ok {
		delete(s.actors.info, runID)
		delete(s.actors.byUID, a.UID)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	s.reg.Update(runID, func(m *RunMeta) { m.EndReason = why })
	log.Printf("run api: run %s for Actor %s ended: %s", runID, a, why)
	s.endRun(runID, nil)
}

// actorRefuse is why run API ops that make runs are refused with Actor
// identity, or "".
func (s *RunAPIServer) actorRefuse(op string) string {
	if !s.ActorIdentity() {
		return ""
	}
	return fmt.Sprintf("runs here are Agent Substrate Actors, which the proxy knows by their certificates: op %s does not apply", op)
}
