// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSData is a resolver reply received by a run.
type DNSData struct {
	Server string // resolver address the reply came from
	Query  string // question name, lowercase, no trailing dot
	QType  string // A, AAAA, HTTPS, ...
	RCode  string // NoError, NXDomain, ...
	// Answers holds the A, AAAA and CNAME records, in message order.
	Answers []DNSAnswer
	// Partial is set when the reply was cut off at the capture limit, so
	// later answers may be missing.
	Partial bool
}

// DNSAnswer is one answer record.
type DNSAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"` // address, or CNAME target
	TTL   uint32 `json:"ttl"`
}

// Addrs returns the A and AAAA addresses in the reply.
func (d DNSData) Addrs() []string {
	var out []string
	for _, a := range d.Answers {
		if a.Type == "A" || a.Type == "AAAA" {
			out = append(out, a.Value)
		}
	}
	return out
}

var errNotResponse = errors.New("not a DNS response")

func dnsName(n dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(n.String(), "."))
}

func dnsTypeName(t dnsmessage.Type) string {
	return strings.TrimPrefix(t.String(), "Type")
}

// parseDNSResponse parses a DNS reply. truncated says the capture was cut
// short; a parse error past the question section is then tolerated and
// whatever answers came before it are kept.
func parseDNSResponse(msg []byte, truncated bool) (DNSData, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return DNSData{}, err
	}
	if !h.Response {
		return DNSData{}, errNotResponse
	}
	d := DNSData{RCode: strings.TrimPrefix(h.RCode.String(), "RCode"), Partial: truncated}

	qs, err := p.AllQuestions()
	if err != nil {
		return DNSData{}, fmt.Errorf("bad question section: %w", err)
	}
	if len(qs) > 0 {
		d.Query = dnsName(qs[0].Name)
		d.QType = dnsTypeName(qs[0].Type)
	}

	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			if truncated {
				return d, nil
			}
			return d, fmt.Errorf("bad answer: %w", err)
		}
		ans := DNSAnswer{Name: dnsName(ah.Name), Type: dnsTypeName(ah.Type), TTL: ah.TTL}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return d, tolerate(err, truncated)
			}
			ans.Value = net.IP(r.A[:]).String()
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return d, tolerate(err, truncated)
			}
			ans.Value = net.IP(r.AAAA[:]).String()
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				return d, tolerate(err, truncated)
			}
			ans.Value = dnsName(r.CNAME)
		default:
			if err := p.SkipAnswer(); err != nil {
				return d, tolerate(err, truncated)
			}
			continue
		}
		d.Answers = append(d.Answers, ans)
	}
	return d, nil
}

func tolerate(err error, truncated bool) error {
	if truncated {
		return nil
	}
	return fmt.Errorf("bad answer: %w", err)
}
