// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func buildReply(t *testing.T, response bool) []byte {
	t.Helper()
	name := dnsmessage.MustNewName("API.Example.com.")
	cname := dnsmessage.MustNewName("edge.cdn.net.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: response, RCode: dnsmessage.RCodeSuccess})
	b.EnableCompression()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.StartQuestions())
	must(b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
	must(b.StartAnswers())
	hdr := func(n dnsmessage.Name) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 60}
	}
	must(b.CNAMEResource(hdr(name), dnsmessage.CNAMEResource{CNAME: cname}))
	must(b.TXTResource(hdr(cname), dnsmessage.TXTResource{TXT: []string{"skip me"}}))
	must(b.AResource(hdr(cname), dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}))
	must(b.AResource(hdr(cname), dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}}))
	msg, err := b.Finish()
	must(err)
	return msg
}

func TestParseDNSResponse(t *testing.T) {
	d, err := parseDNSResponse(buildReply(t, true), false)
	if err != nil {
		t.Fatal(err)
	}
	if d.Query != "api.example.com" || d.QType != "A" || d.RCode != "Success" || d.Partial {
		t.Fatalf("bad header fields: %+v", d)
	}
	want := []DNSAnswer{
		{Name: "api.example.com", Type: "CNAME", Value: "edge.cdn.net", TTL: 60},
		{Name: "edge.cdn.net", Type: "A", Value: "192.0.2.1", TTL: 60},
		{Name: "edge.cdn.net", Type: "A", Value: "192.0.2.2", TTL: 60},
	}
	if !reflect.DeepEqual(d.Answers, want) {
		t.Fatalf("answers %+v, want %+v", d.Answers, want)
	}
	if got := d.Addrs(); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("addrs %v", got)
	}
}

func TestParseDNSResponseRejectsQueries(t *testing.T) {
	if _, err := parseDNSResponse(buildReply(t, false), false); err != errNotResponse {
		t.Fatalf("got %v, want errNotResponse", err)
	}
}

func TestParseDNSResponseTruncatedCapture(t *testing.T) {
	msg := buildReply(t, true)
	cut := msg[:len(msg)-3] // last A record cut off

	if _, err := parseDNSResponse(cut, false); err == nil {
		t.Fatal("expected an error for a cut message not flagged as truncated")
	}
	d, err := parseDNSResponse(cut, true)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Partial || len(d.Addrs()) != 1 || d.Addrs()[0] != "192.0.2.1" {
		t.Fatalf("want the answers before the cut, got %+v", d)
	}
}

func TestRunRecorderLabelsConnectsFromDNS(t *testing.T) {
	r := newTestRecorder(t)
	dns := AuditEvent{Type: EventDNS, Timestamp: at(1), CgroupID: testRunCg, RunCgroupID: testRunCg,
		Data: DNSData{Server: "127.0.0.53", Query: "api.example.com", QType: "A", RCode: "Success",
			Answers: []DNSAnswer{{Name: "api.example.com", Type: "A", Value: "192.0.2.1"}}}}
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		connEv(1, 10, "192.0.2.1", 443), // before the lookup: unlabelled
		dns,
		connEv(2, 10, "192.0.2.1", 443),
		connEv(3, 10, "198.51.100.9", 443), // literal IP
		runEv(EventRunEnd, 4, "/agents/run-abc"),
	)
	if tl.Events[0].DstName != "" || tl.Events[2].DstName != "api.example.com" || tl.Events[3].DstName != "" {
		t.Fatalf("bad labels: %+v", tl.Events)
	}
	if tl.Summary.DNSReplies != 1 || !reflect.DeepEqual(tl.Summary.DNSNames, []string{"api.example.com"}) {
		t.Fatalf("bad dns summary: %+v", tl.Summary)
	}
	want := []Destination{
		{Proto: "TCP", IP: "192.0.2.1", Port: 443, Count: 2, Names: []string{"api.example.com"}},
		{Proto: "TCP", IP: "198.51.100.9", Port: 443, Count: 1},
	}
	if !reflect.DeepEqual(tl.Summary.Destinations, want) {
		t.Fatalf("destinations %+v, want %+v", tl.Summary.Destinations, want)
	}
}
