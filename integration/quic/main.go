// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Command quictest is the integration tests' QUIC client and server
// (milestone 5.6), a module of its own so that the main module does not
// depend on quic-go.
//
//	quictest server -listen :443 -cert tls.crt -key tls.key
//	quictest get -name other.test [-addr ip:443] [-ca ca.crt] [-x25519]
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "clovisor-it"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: quictest server|get ...")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "server":
		listen := fs.String("listen", ":443", "")
		cert := fs.String("cert", "/origin/tls.crt", "")
		key := fs.String("key", "/origin/tls.key", "")
		fs.Parse(os.Args[2:])
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		var name string
		ln, err := quic.ListenAddr(*listen, &tls.Config{Certificates: []tls.Certificate{c}, NextProtos: []string{alpn},
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { name = h.ServerName; return nil, nil }}, nil)
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				log.Fatal(err)
			}
			sni := name
			go func() {
				s, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				io.Copy(io.Discard, s)
				fmt.Fprintf(s, "quic %s ok from %s", sni, conn.RemoteAddr())
				s.Close()
				time.Sleep(time.Second)
				conn.CloseWithError(0, "")
			}()
		}
	case "get":
		name := fs.String("name", "", "server name")
		addr := fs.String("addr", "", "address to dial (default name:443)")
		ca := fs.String("ca", "/it/test-ca.crt", "")
		x25519 := fs.Bool("x25519", false, "X25519 key share only: a one-datagram ClientHello")
		timeout := fs.Duration("timeout", 5*time.Second, "")
		fs.Parse(os.Args[2:])
		if *addr == "" {
			*addr = *name + ":443"
		}
		roots, _ := x509.SystemCertPool()
		if pem, err := os.ReadFile(*ca); err == nil {
			roots.AppendCertsFromPEM(pem)
		}
		cfg := &tls.Config{ServerName: *name, RootCAs: roots, NextProtos: []string{alpn}}
		if *x25519 {
			cfg.CurvePreferences = []tls.CurveID{tls.X25519}
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		start := time.Now()
		conn, err := quic.DialAddr(ctx, *addr, cfg, nil)
		if err != nil {
			var te *quic.TransportError
			if errors.As(err, &te) {
				fmt.Printf("refused after %s: %s: %s\n", time.Since(start).Round(time.Millisecond), te.ErrorCode, te.ErrorMessage)
			} else {
				fmt.Printf("error after %s: %v\n", time.Since(start).Round(time.Millisecond), err)
			}
			os.Exit(1)
		}
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		s.Close()
		b, err := io.ReadAll(s)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		conn.CloseWithError(0, "")
	default:
		log.Fatal("usage: quictest server|get ...")
	}
}
