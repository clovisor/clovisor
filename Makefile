# Copyright (c) Authors of Clovisor
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

.PHONY: all build clean install package package-test bpf agentctl audit-sink node-agent run run-agent run-proxy envoy check cross integration integration-transparent format doc

# Compiler and flags. -mcpu=v3 (kernel 5.1, below the 5.12 floor) is
# clang 19's default; clang 18, Ubuntu 24.04's, defaults to v1, which has
# no 32-bit atomic exchange and fails on_egress.
CC = clang
BPF_ARCH = $(shell uname -m | sed -e s/aarch64/arm64/ -e s/x86_64/x86/)
BPF_CFLAGS = -target bpf -mcpu=v3 -g -O2 -Wall -D__TARGET_ARCH_$(BPF_ARCH) -I/usr/include/$(shell uname -m)-linux-gnu

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
	rm -rf bin/ dist/

# Install (copy binaries to /usr/local/bin)
install: build
	cp bin/agentctl bin/audit-sink bin/node-agent /usr/local/bin/

# Run the agent (requires root for BPF)
run: node-agent
	sudo bin/node-agent -bpf $(BPF_OBJ)

# Run the node agent with the explicit proxy (milestone 2.3), then Envoy
# from the bootstrap it writes. Envoy runs as uid 101 in the image.
PROXY_LISTEN ?= 127.0.0.1:18000
# The Envoy release the integration tests pin.
ENVOY_IMAGE ?= envoyproxy/envoy:v1.39.5

run-proxy: node-agent
	sudo bin/node-agent -bpf $(BPF_OBJ) -proxy-listen $(PROXY_LISTEN)

envoy:
	sudo docker run --rm --network host -v /run/clovisor:/run/clovisor $(ENVOY_IMAGE) -c /run/clovisor/envoy.json

# Run a command as a governed run (needs the node agent; no root needed)
run-agent:
	bin/agentctl run -- $(CMD)


# Debian and RPM packages for this machine's architecture (milestone 7.2),
# in dist/: the BPF object is compiled for it. See packaging/.
PKG_VERSION ?= 0.7.0
PKG_PRERELEASE ?= dev.$(shell git rev-parse --short HEAD)
PKG_ARCH ?= $(shell $(GO) env GOARCH)
NFPM ?= $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.49.0

# Go's temporary build files go in dist/tmp, not /tmp.
package: bpf
	mkdir -p dist/bin dist/tmp
	for c in node-agent agentctl audit-sink; do GOTMPDIR=$(CURDIR)/dist/tmp CGO_ENABLED=0 GOOS=linux GOARCH=$(PKG_ARCH) \
		$(GO) build -trimpath -o dist/bin/$$c ./cmd/$$c || exit 1; done
	for p in deb rpm; do GOTMPDIR=$(CURDIR)/dist/tmp PKG_ARCH=$(PKG_ARCH) PKG_VERSION=$(PKG_VERSION) PKG_PRERELEASE=$(PKG_PRERELEASE) \
		$(NFPM) package -f packaging/nfpm.yaml -p $$p -t dist/ || exit 1; done
	ls -l dist/*.deb dist/*.rpm

# Install the packages in clean Debian and Fedora containers and check what
# they put where (DOCKER="sudo docker" if needed).
DOCKER ?= docker
package-test: package
	$(DOCKER) run --rm -v $(CURDIR):/src:ro debian:bookworm-slim sh /src/packaging/test-install.sh deb
	$(DOCKER) run --rm -v $(CURDIR):/src:ro fedora:43 sh /src/packaging/test-install.sh rpm

# Generate documentation
doc:
	$(GO) doc ./libclovisor

# Format code
format:
	$(GO) fmt ./...

# Check code: the whole module (spikes/ are modules of their own).
GO_PKGS = ./...
check: cross
	$(GO) vet $(GO_PKGS)
	$(GO) build $(GO_PKGS)
	$(GO) test $(GO_PKGS)

# End-to-end tests in Docker against a pinned Envoy (design 2.7). Set
# DOCKER="sudo docker" where the docker CLI needs it.
integration:
	CLOVISOR_IT_ENVOY_IMAGE=$(ENVOY_IMAGE) $(GO) test -tags integration -count=1 -v ./integration/

# Transparent enforce mode end to end (milestone 3.7): a privileged
# container sharing the host's cgroup and PID namespaces, BPF, cgroup v2.
# Linux only; needs clang for the BPF object.
integration-transparent:
	CLOVISOR_IT_TRANSPARENT=1 CLOVISOR_IT_ENVOY_IMAGE=$(ENVOY_IMAGE) $(GO) test -tags integration -count=1 -v -run TestTransparent ./integration/

# The portable pieces (agentctl, the node agent with credential identity,
# ext_proc, the MCP gateway) must keep building without Linux (design §4.3).
cross:
	GOOS=darwin GOARCH=arm64 $(GO) vet $(GO_PKGS)
	GOOS=darwin GOARCH=amd64 $(GO) build $(GO_PKGS)
