# Copyright (c) Authors of Clovisor
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

.PHONY: all build clean install bpf agentctl audit-sink node-agent run run-agent check format doc

# Compiler and flags
CC = clang
BPF_CFLAGS = -target bpf -g -O2 -Wall -I/usr/include/$(shell uname -m)-linux-gnu

# Directories
BPF_SRC = libclovisor/ebpf/agent_audit.c
BPF_OBJ = libclovisor/ebpf/agent_audit.o

# Go modules
GO = go

all: build

build: bpf agentctl audit-sink node-agent

# Build the BPF program
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CC) $(BPF_CFLAGS) -c $< -o $@
	@echo "Built BPF object: $@"

# Build the agentctl CLI tool
agentctl:
	$(GO) build -o bin/agentctl ./cmd/agentctl

# Build the audit-sink tool
audit-sink:
	$(GO) build -o bin/audit-sink ./cmd/audit-sink

# Build the node agent daemon
node-agent:
	$(GO) build -o bin/node-agent ./cmd/node-agent

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ)
	rm -rf bin/

# Install (copy binaries to /usr/local/bin)
install: build
	cp bin/agentctl bin/audit-sink bin/node-agent /usr/local/bin/

# Run the agent (requires root for BPF)
run: node-agent
	sudo bin/node-agent -bpf $(BPF_OBJ)

# Run a command using agentctl (requires root for cgroup access)
run-agent:
	sudo bin/agentctl run -- $(CMD)


# Generate documentation
doc:
	$(GO) doc ./libclovisor

# Format code
format:
	$(GO) fmt ./...

# Check code. Scoped to the Phase 1 packages. Excluded: the root package
# (legacy, bcc-tagged), libclovisor/libproto (Go plugin sources, built one
# file at a time) and k8s-ctlr (stale client-go API, does not build).
GO_PKGS = ./cmd/... ./libclovisor
check:
	$(GO) vet $(GO_PKGS)
	$(GO) build $(GO_PKGS)
