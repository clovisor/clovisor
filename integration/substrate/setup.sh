#!/usr/bin/env bash
# Copyright (c) Authors of Clovisor
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
#
# A kind cluster with Agent Substrate for integration/substrate/e2e.sh
# (milestone 7.4): Substrate at SUBSTRATE_REF, with Clovisor's hook patch
# (deploy/substrate/ate-setup-hook-attributes.patch), installed with
# Clovisor as its gateway's additional ext_proc, and its egress and sandbox
# demos.
#
#   integration/substrate/setup.sh            # create, or bring up to date
#   integration/substrate/setup.sh --delete   # delete the cluster and registry
#
# SUBSTRATE_DIR is a Substrate checkout; one is fetched there if it does
# not exist (default dist/substrate-src). KIND_CLUSTER_NAME is the cluster
# (kind). Needs docker with buildx, go, kubectl and curl; ate-setup builds
# Substrate's images with ko and pushes them to kind's registry on :5001.
# About 10 GB of disk.
set -o errexit -o nounset -o pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SUBSTRATE_URL=${SUBSTRATE_URL:-https://github.com/agent-substrate/substrate.git}
SUBSTRATE_REF=${SUBSTRATE_REF:-7319f1afa2ac90c8224117463f13f7bf782f63ac}
SUBSTRATE_DIR=${SUBSTRATE_DIR:-${ROOT}/dist/substrate-src}
PATCH=${ROOT}/deploy/substrate/ate-setup-hook-attributes.patch
HOOK=clovisor-system/clovisor:9443
export KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-kind}
export ATE_INSTALL_KIND=true
CTX=kind-${KIND_CLUSTER_NAME}

log() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31msetup: %s\033[0m\n' "$*" >&2; exit 1; }

for t in docker go kubectl curl; do
  command -v "$t" >/dev/null || die "needs $t"
done

if [[ "${1:-}" == "--delete" ]]; then
  [[ -d "${SUBSTRATE_DIR}" ]] || die "no Substrate checkout at ${SUBSTRATE_DIR}"
  cd "${SUBSTRATE_DIR}"
  log "delete Substrate and the kind cluster ${KIND_CLUSTER_NAME}"
  # The registry's images live in an anonymous volume, which Substrate's
  # script leaves behind (about 0.5 GB a cluster).
  REGVOL=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/registry"}}{{.Name}}{{end}}{{end}}' kind-registry 2>/dev/null || true)
  go run ./cmd/ate-setup delete all >/dev/null 2>&1 || true
  hack/delete-kind-cluster.sh
  if [[ -n "${REGVOL}" ]] && docker volume inspect "${REGVOL}" >/dev/null 2>&1; then
    echo "   the registry's images are left in volume ${REGVOL}: docker volume rm ${REGVOL} to free them"
  fi
  exit 0
fi
[[ $# -eq 0 ]] || die "usage: $0 [--delete]"
docker buildx version >/dev/null 2>&1 || die "needs docker buildx (ate-setup builds with docker buildx build --push)"

log "Substrate at ${SUBSTRATE_REF:0:12} in ${SUBSTRATE_DIR}"
if [[ ! -d "${SUBSTRATE_DIR}/.git" ]]; then
  mkdir -p "${SUBSTRATE_DIR}"
  git -C "${SUBSTRATE_DIR}" init -q
  git -C "${SUBSTRATE_DIR}" remote add origin "${SUBSTRATE_URL}"
fi
if [[ "$(git -C "${SUBSTRATE_DIR}" rev-parse HEAD 2>/dev/null)" != "${SUBSTRATE_REF}" ]]; then
  [[ -z "$(git -C "${SUBSTRATE_DIR}" status --porcelain --untracked-files=no 2>/dev/null)" ]] ||
    die "${SUBSTRATE_DIR} has local changes and is not at ${SUBSTRATE_REF}"
  git -C "${SUBSTRATE_DIR}" fetch -q --depth 1 origin "${SUBSTRATE_REF}"
  git -C "${SUBSTRATE_DIR}" checkout -q --detach FETCH_HEAD
fi
if git -C "${SUBSTRATE_DIR}" apply --check "${PATCH}" 2>/dev/null; then
  git -C "${SUBSTRATE_DIR}" apply "${PATCH}"
  echo "   applied $(basename "${PATCH}")"
elif git -C "${SUBSTRATE_DIR}" apply --check --reverse "${PATCH}" 2>/dev/null; then
  echo "   $(basename "${PATCH}") is applied"
else
  die "$(basename "${PATCH}") applies neither way to ${SUBSTRATE_DIR}"
fi
cd "${SUBSTRATE_DIR}"

if kubectl config get-contexts "${CTX}" >/dev/null 2>&1 && kubectl --context "${CTX}" get nodes >/dev/null 2>&1; then
  log "kind cluster ${KIND_CLUSTER_NAME} is up"
else
  log "create the kind cluster ${KIND_CLUSTER_NAME} and its registry"
  hack/create-kind-cluster.sh
fi

log "install Substrate, with ${HOOK} as the egress gateway's additional ext_proc"
go run ./cmd/ate-setup deploy ate-system --credential-provider='{"name":"k8s.io"}' \
  --ingress-allowed-spiffe-ids=spiffe://cluster.local/ns/ate-system/sa/atenet-client \
  --experimental-additional-egress-extproc-service="${HOOK}"

log "install Substrate's egress demo"
go run ./cmd/ate-setup deploy demo egress

log "install Substrate's sandbox demo (its Actors run what they are sent: the sandbox audit's)"
go run ./cmd/ate-setup deploy demo sandbox

log "install kubectl-ate"
go install ./cmd/kubectl-ate
BIN=$(go env GOBIN)
BIN=${BIN:-$(go env GOPATH)/bin}
command -v kubectl-ate >/dev/null || echo "   kubectl-ate is in ${BIN}: add it to PATH for e2e.sh"

log "check: the gateway calls ${HOOK} with the dialed address"
kubectl --context "${CTX}" -n ate-system get configmap atenet-egress -o jsonpath='{.data.envoy\.yaml}' |
  sed -n '/cluster_name: additional_egress_ext_proc/,/mutation_rules/p' | grep -q "dev.ate.connect.authority" ||
  die "atenet-egress's additional ext_proc does not send the dialed address"
echo "   ready: make substrate-e2e"
