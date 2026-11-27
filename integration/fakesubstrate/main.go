// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// fakesubstrate is Agent Substrate's Control API, as far as Clovisor uses
// it (milestone 7.3): GetActor, over plaintext gRPC, from Actors the test
// sets through a small HTTP interface:
//
//	PUT    /actors/<atespace>/<name>  {"uid": "...", "template": "...", "state": "RUNNING"}
//	DELETE /actors/<atespace>/<name>
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/clovisor/clovisor/libclovisor/substrateapi"
)

type actor struct {
	UID      string `json:"uid"`
	Template string `json:"template"`
	State    string `json:"state"`
}

type server struct {
	substrateapi.UnimplementedControlServer
	mu     sync.Mutex
	actors map[string]actor // atespace/name
}

func (s *server) GetActor(_ context.Context, r *substrateapi.GetActorRequest) (*substrateapi.Actor, error) {
	ns, name := r.GetActor().GetAtespace(), r.GetActor().GetName()
	s.mu.Lock()
	a, ok := s.actors[ns+"/"+name]
	s.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor %s/%s not found", ns, name)
	}
	return &substrateapi.Actor{
		Metadata:      &substrateapi.ResourceMetadata{Atespace: ns, Name: name, Uid: a.UID},
		ActorTemplate: &substrateapi.ObjectRef{Atespace: ns, Name: a.Template},
		Status:        &substrateapi.ActorStatus{State: substrateapi.ActorState(substrateapi.ActorState_value["ACTOR_STATE_"+a.State])},
	}, nil
}

func main() {
	grpcAddr := flag.String("grpc", "127.0.0.1:19000", "Control API address")
	adminAddr := flag.String("admin", "127.0.0.1:19001", "HTTP interface for setting Actors")
	flag.Parse()
	s := &server{actors: map[string]actor{}}
	ln, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	substrateapi.RegisterControlServer(g, s)
	go g.Serve(ln)
	http.HandleFunc("/actors/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/actors/")
		switch r.Method {
		case http.MethodPut:
			var a actor
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.actors[key] = a
			s.mu.Unlock()
		case http.MethodDelete:
			s.mu.Lock()
			delete(s.actors, key)
			s.mu.Unlock()
		default:
			http.Error(w, "PUT or DELETE", http.StatusMethodNotAllowed)
		}
	})
	log.Printf("fakesubstrate: Control on %s, admin on %s", *grpcAddr, *adminAddr)
	log.Fatal(http.ListenAndServe(*adminAddr, nil))
}
