// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Command gotls is the integration tests' Go HTTPS client (milestone
// 6.3): it GETs each URL in turn, over one HTTP/2 connection per host,
// with Go's crypto/tls, and prints each status.
//
//	gotls URL...
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	cl := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, Proxy: nil}}
	for _, u := range os.Args[1:] {
		r, err := cl.Get(u)
		if err != nil {
			fmt.Println("gotls error:", err)
			os.Exit(1)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		fmt.Println("gotls", r.Proto, r.StatusCode)
	}
}
