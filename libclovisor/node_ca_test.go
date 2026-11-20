// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNodeCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ca.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode %v", fi.Mode().Perm())
	}
	c := ca.Cert
	if !c.IsCA || !c.MaxPathLenZero || c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(c.SubjectKeyId) == 0 {
		t.Errorf("CA profile: isCA=%v pathlen0=%v ku=%v ski=%x", c.IsCA, c.MaxPathLenZero, c.KeyUsage, c.SubjectKeyId)
	}
	// basicConstraints and keyUsage must be critical (RFC 5280; Python 3.13+).
	for _, ext := range c.Extensions {
		id := ext.Id.String()
		if (id == "2.5.29.19" || id == "2.5.29.15") && !ext.Critical {
			t.Errorf("extension %s not critical", id)
		}
	}

	again, err := LoadOrCreateCA(dir)
	if err != nil || !bytes.Equal(again.CertPEM, ca.CertPEM) {
		t.Fatal("CA not reused")
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	for pattern, host := range map[string]string{"api.example.com": "api.example.com", "*.example.org": "raw.example.org"} {
		certPEM, keyPEM, err := ca.Issue(pattern)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(certPEM)
		leaf, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool}); err != nil {
			t.Errorf("%s: %v", pattern, err)
		}
		if !bytes.Equal(leaf.AuthorityKeyId, ca.Cert.SubjectKeyId) || leaf.IsCA || len(keyPEM) == 0 {
			t.Errorf("%s: leaf profile", pattern)
		}
	}

	if bundle, err := ca.TrustBundle(); err == nil {
		if !bytes.HasSuffix(bytes.TrimSpace(bundle), bytes.TrimSpace(ca.CertPEM)) || bytes.Count(bundle, []byte("BEGIN CERTIFICATE")) < 2 {
			t.Error("trust bundle lacks system roots or the node CA")
		}
	}
}
