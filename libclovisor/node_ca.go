// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// NodeCA is the per-node CA the proxy uses to terminate TLS for the
// destinations whose rules need it (design §6.6). Its key never leaves the
// node agent; Envoy only ever gets leaf certificates.
type NodeCA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

const (
	caValidity   = 365 * 24 * time.Hour
	leafValidity = 30 * 24 * time.Hour
)

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func keyID(pub *ecdsa.PublicKey) []byte {
	b, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha1.Sum(b) // RFC 5280 §4.2.1.2 method 1 style identifier
	return sum[:]
}

// LoadOrCreateCA loads the CA from dir (ca.crt, ca.key), creating it on
// first use. The key file is root-only.
func LoadOrCreateCA(dir string) (*NodeCA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	certPEM, err1 := os.ReadFile(certPath)
	keyPEM, err2 := os.ReadFile(keyPath)
	if err1 == nil && err2 == nil {
		ca, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("node CA in %s: %w", dir, err)
		}
		if time.Until(ca.Cert.NotAfter) > leafValidity {
			return ca, nil
		}
		// Too close to expiry to sign leaves that outlive it: rotate.
	} else if !errors.Is(err1, os.ErrNotExist) && err1 != nil {
		return nil, err1
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "Clovisor node CA (" + host + ")", Organization: []string{"Clovisor"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	return parseCA(certPEM, keyPEM)
}

func parseCA(certPEM, keyPEM []byte) (*NodeCA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("bad PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &NodeCA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// Issue signs a leaf for a host pattern ("api.example.com" or
// "*.example.com"), with the extensions strict verifiers require
// (Python 3.13+ rejects leaves without authorityKeyIdentifier).
func (ca *NodeCA) Issue(pattern string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	notAfter := now.Add(leafValidity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: pattern},
		DNSNames:              []string{pattern},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          keyID(&key.PublicKey),
		AuthorityKeyId:        ca.Cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// systemBundles are where distributions keep the system trust store.
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/cert.pem",                  // macOS, BSD
}

// TrustBundle returns the system trust store with the node CA appended.
// SSL_CERT_FILE and friends replace the default store rather than add
// to it, so runs get the whole bundle, not just the node CA.
func (ca *NodeCA) TrustBundle() ([]byte, error) {
	for _, p := range systemBundles {
		if sys, err := os.ReadFile(p); err == nil {
			return bytes.Join([][]byte{bytes.TrimSpace(sys), ca.CertPEM}, []byte("\n")), nil
		}
	}
	return nil, fmt.Errorf("no system CA bundle found (looked in %v)", systemBundles)
}
