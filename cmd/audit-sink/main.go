// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	outputDir = flag.String("output", "/var/log/clovisor", "Output directory for audit logs")
)

func main() {
	flag.Parse()

	fmt.Println("Audit Sink - Phase 1")
	fmt.Println("Collects and exports audit events from agent egress tracking")
	fmt.Println()

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Output directory: %s\n", *outputDir)
	fmt.Println()
	fmt.Println("To run the agent with BPF monitoring:")
	fmt.Println("  sudo make run")
	fmt.Println()
	fmt.Println("Or use agentctl for basic operations:")
	fmt.Println("  ./bin/agentctl")
}
