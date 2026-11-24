// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// A Go HTTPS client for the Phase 6 spike, in a module of its own so two
// Go versions can build it: requests over HTTP/2, or a timed write loop
// to the sink (-bench).
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	u := flag.String("url", "https://localhost:8443/go", "")
	n := flag.Int("n", 3, "")
	bench := flag.Bool("bench", false, "write -n buffers of -size bytes to localhost:8444")
	size := flag.Int("size", 64, "")
	flag.Parse()
	if *bench {
		c, err := tls.Dial("tcp", "localhost:8444", &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Fatal(err)
		}
		b := bytes.Repeat([]byte("y"), *size)
		t0 := time.Now()
		for i := 0; i < *n; i++ {
			if _, err := c.Write(b); err != nil {
				log.Fatal(err)
			}
		}
		d := time.Since(t0)
		fmt.Printf("writes=%d size=%d per=%v MB/s=%.1f\n", *n, *size, d/time.Duration(*n), float64(*n**size)/d.Seconds()/1e6)
		return
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}}
	for i := 0; i < *n; i++ {
		r, err := cl.Post(fmt.Sprintf("%s/%d", *u, i), "text/plain", strings.NewReader("hello"))
		if err != nil {
			log.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		fmt.Printf("%s", b)
	}
}
