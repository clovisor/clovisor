#!/usr/bin/env bash
# Copyright (c) Authors of Clovisor
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Clovisor beside Agent Substrate's egress gateway, end to end (milestone
# 7.4), on a kind cluster with Substrate installed with
#   --experimental-additional-egress-extproc-service=clovisor-system/clovisor:9443
# and its egress demo (`ate-setup deploy demo egress`). The demo's Actor
# fetches what it is told to; Substrate's EgressPolicy for it allows
# everything, and Clovisor's profile allows less.
#
#   CLOVISOR_IMAGE=localhost:5001/clovisor:<tag> integration/substrate/e2e.sh
#   integration/substrate/e2e.sh --cleanup
#
# integration/substrate/setup.sh makes such a cluster. A run leaves Clovisor
# deployed, granted, and the target running; --cleanup removes them all:
# the clovisor-system and egress-target namespaces, the Actor, and
# Clovisor's grant in Substrate's global access policy. KUBECTL_CONTEXT
# picks the cluster (kind-kind). Needs kubectl, kubectl-ate, curl, and
# python3 with PyYAML.
set -o errexit -o nounset -o pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTX=${KUBECTL_CONTEXT:-kind-kind}
K="kubectl --context ${CTX}"
KATE="kubectl-ate --context ${CTX}"
NS=clovisor-system
ATESPACE=ate-demo-egress
ACTOR=${ACTOR:-clovisor-e2e}
TEMPLATE=egress
TARGET_NS=egress-target
TARGET=whoami.${TARGET_NS}.svc.cluster.local
PEER=spiffe://cluster.local/ns/${NS}/sa/clovisor
WORK=$(mktemp -d "${TMPDIR:-/tmp}/clovisor-e2e.XXXXXX")
PORT=18199

for t in kubectl kubectl-ate curl python3; do
  command -v "$t" >/dev/null || { echo "e2e: needs $t" >&2; exit 1; }
done
python3 -c 'import yaml' 2>/dev/null || { echo "e2e: needs PyYAML (python3 -m pip install pyyaml, or apt install python3-yaml)" >&2; exit 1; }

log()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; PASSED=$((PASSED+1)); }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=$((FAILED+1)); }
PASSED=0 FAILED=0
PF=

stop_proxy() {
  if [[ -n "${PF}" ]]; then kill "${PF}" >/dev/null 2>&1 || true; wait "${PF}" 2>/dev/null || true; fi
  PF=
}
cleanup() {
  stop_proxy
  ${K} -n "${NS}" delete pod clovisor-probe --ignore-not-found --wait=false >/dev/null 2>&1 || true
  ${KATE} delete actor "${ACTOR}" -a "${ATESPACE}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

# grant add|remove: Clovisor as a viewer in Substrate's global access
# policy. The global policy cannot be deleted, only updated.
grant() {
  ${KATE} get access-policy --global -o yaml >"${WORK}/global.yaml" 2>/dev/null || true
  if ! grep -q "^metadata:" "${WORK}/global.yaml"; then
    [[ "$1" == remove ]] && return 0
    printf 'metadata:\n  name: default\nbindings:\n- role: viewer\n  members:\n  - user:%s\n' "${PEER}" >"${WORK}/global-new.yaml"
    ${KATE} create access-policy --global -f "${WORK}/global-new.yaml" >/dev/null
    return
  fi
  python3 - "$1" "${WORK}/global.yaml" "user:${PEER}" >"${WORK}/global-new.yaml" <<'PY'
import sys, yaml
op, path, member = sys.argv[1:4]
doc = yaml.safe_load(open(path)) or {}
bindings = doc.get("bindings") or []
if op == "add":
    for b in bindings:
        if b.get("role") == "viewer":
            b.setdefault("members", [])
            if member not in b["members"]:
                b["members"].append(member)
            break
    else:
        bindings.append({"role": "viewer", "members": [member]})
else:
    for b in bindings:
        b["members"] = [m for m in b.get("members") or [] if m != member]
    bindings = [b for b in bindings if b["members"]]
doc["bindings"] = bindings
yaml.safe_dump(doc, sys.stdout)
PY
  if [[ "$1" == add ]] && grep -q "${PEER}" "${WORK}/global.yaml"; then return; fi
  if [[ "$1" == remove ]] && ! grep -q "${PEER}" "${WORK}/global.yaml"; then return; fi
  ${KATE} update access-policy --global -f "${WORK}/global-new.yaml" >/dev/null
}

if [[ "${1:-}" == "--cleanup" ]]; then
  log "remove Clovisor, its grant, the Actor and the target"
  ${KATE} delete actor "${ACTOR}" -a "${ATESPACE}" >/dev/null 2>&1 || true
  grant remove
  ${KATE} get access-policy --global -o yaml 2>/dev/null | grep -q "${PEER}" && { echo "e2e: ${PEER} is still in the global access policy" >&2; exit 1; }
  ${K} delete namespace "${NS}" "${TARGET_NS}" --ignore-not-found --wait=true --timeout=180s >/dev/null
  info "removed: namespaces ${NS} and ${TARGET_NS}, the Actor ${ATESPACE}/${ACTOR}, ${PEER}'s grant"
  exit 0
fi
[[ $# -eq 0 ]] || { echo "usage: $0 [--cleanup]" >&2; exit 2; }
: "${CLOVISOR_IMAGE:?set CLOVISOR_IMAGE (make substrate-e2e does)}"

# agentctl in Clovisor's pod.
agentctl() { ${K} -n "${NS}" exec deploy/clovisor -- agentctl "$@"; }

# The run Clovisor started for the Actor's UID, from its log.
actor_run() {
  ${K} -n "${NS}" logs deploy/clovisor 2>/dev/null |
    sed -n "s|.*run api: run \([0-9a-f]*\) for Actor ${ATESPACE}/${ACTOR} (uid $1,.*|\1|p" | tail -1
}

actor_uid() {
  ${KATE} get actor "${ACTOR}" -a "${ATESPACE}" -o yaml 2>/dev/null | sed -n 's/^ *uid: *//p' | head -1
}

start_actor() {
  ${KATE} create actor "${ACTOR}" -a "${ATESPACE}" --template "${TEMPLATE}" >/dev/null
  ${KATE} resume actor "${ACTOR}" -a "${ATESPACE}" >/dev/null 2>&1 || true
  # Substrate allows the Actor everything: what is refused is Clovisor's.
  printf 'rules:\n- http: {hostnames: ["*"], ports: {all: {}}}\n- https: {hostnames: ["*"]}\n' |
    ${KATE} create egress-policy "${ACTOR}" -a "${ATESPACE}" -f - >/dev/null 2>&1 || true
  for _ in $(seq 1 60); do
    ${KATE} get actors -a "${ATESPACE}" 2>/dev/null | grep -E "^${ATESPACE} +${ACTOR} " | grep -q ACTOR_STATE_RUNNING && break
    sleep 3
  done
  ${KATE} get actors -a "${ATESPACE}" 2>/dev/null | grep -E "^${ATESPACE} +${ACTOR} " | grep -q ACTOR_STATE_RUNNING || { fail "the Actor did not reach RUNNING"; exit 1; }
  ${KATE} proxy actor "${ACTOR}" "${PORT}:80" -a "${ATESPACE}" >"${WORK}/pf.log" 2>&1 &
  PF=$!
  for _ in $(seq 1 30); do
    curl -s -o /dev/null "http://localhost:${PORT}/readyz" && return 0
    sleep 1
  done
  fail "kubectl-ate proxy did not come up: $(cat "${WORK}/pf.log")"
  exit 1
}

# fetch URL: the Actor GETs URL. CODE and BODY are the origin's answer, or
# the refusal.
fetch() {
  local out
  out=$(curl -s -m 30 -X POST "http://localhost:${PORT}/" -H 'Content-Type: application/json' -d "{\"url\":\"$1\"}" || true)
  CODE=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1] or "{}"); print(d.get("statusCode") or 0)' "${out}" 2>/dev/null || echo 0)
  BODY=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1] or "{}"); print(d.get("body") or d.get("error") or "")' "${out}" 2>/dev/null || echo "")
}

expect() { # expect WHAT CODE [PATTERN]
  if [[ "${CODE}" == "$2" ]] && { [[ -z "${3:-}" ]] || grep -q -- "$3" <<<"${BODY}"; }; then
    pass "$1: ${CODE}"
  else
    fail "$1: ${CODE} ${BODY:0:300}"
  fi
}

log "preflight: Substrate's gateway calls Clovisor"
${K} -n ate-system rollout status deployment/atenet-egress --timeout=180s >/dev/null
${K} -n ate-system get configmap atenet-egress -o jsonpath='{.data.envoy\.yaml}' >"${WORK}/envoy.yaml"
if grep -q 'cluster_name: additional_egress_ext_proc' "${WORK}/envoy.yaml" &&
   grep -q "address: clovisor.${NS}.svc.cluster.local" "${WORK}/envoy.yaml"; then
  pass "atenet-egress has the additional ext_proc, at clovisor.${NS}"
else
  fail "atenet-egress has no additional ext_proc for clovisor.${NS}: install Substrate with --experimental-additional-egress-extproc-service=${NS}/clovisor:9443"
  exit 1
fi
if sed -n '/cluster_name: additional_egress_ext_proc/,/mutation_rules/p' "${WORK}/envoy.yaml" | grep -q "dev.ate.connect.authority"; then
  info "the hook sends the address the Actor dialed"
else
  info "the hook does not send the address the Actor dialed: Clovisor will refuse every request (see deploy/substrate/README.md)"
fi

log "deploy Clovisor (${CLOVISOR_IMAGE})"
${K} create namespace "${NS}" >/dev/null 2>&1 || true
${K} -n "${NS}" create configmap clovisor-policy --from-file="${ROOT}/deploy/substrate/policy" --dry-run=client -o yaml | ${K} apply -f - >/dev/null
sed "s|\${CLOVISOR_IMAGE}|${CLOVISOR_IMAGE}|" "${ROOT}/deploy/substrate/clovisor.yaml" | ${K} apply -f - >/dev/null
${K} -n "${NS}" rollout restart deployment/clovisor >/dev/null
${K} -n "${NS}" rollout status deployment/clovisor --timeout=180s

log "grant Clovisor read access to Actors (a global viewer)"
grant add
${KATE} get access-policy --global -o yaml | grep -q "${PEER}" && pass "${PEER} is a global viewer" || fail "the global access policy lacks ${PEER}"

log "an in-cluster target, and the Actor ${ATESPACE}/${ACTOR}"
${K} create namespace "${TARGET_NS}" >/dev/null 2>&1 || true
${K} -n "${TARGET_NS}" create deployment whoami --image=traefik/whoami >/dev/null 2>&1 || true
${K} -n "${TARGET_NS}" expose deployment whoami --port=80 --target-port=80 >/dev/null 2>&1 || true
${K} -n "${TARGET_NS}" rollout status deployment/whoami --timeout=180s >/dev/null
${KATE} create atespace "${ATESPACE}" >/dev/null 2>&1 || true
${KATE} delete actor "${ACTOR}" -a "${ATESPACE}" >/dev/null 2>&1 || true
start_actor
UID1=$(actor_uid)
info "running, uid ${UID1}"

log "decisions: Substrate allows everything, Clovisor's profile less"
fetch "http://${TARGET}/"
expect "GET ${TARGET}/, allowed by whoami-read" 200 "Hostname: whoami"
fetch "http://${TARGET}/secret"
expect "GET ${TARGET}/secret, refused with no-secret's narration" 403 "off limits for the demo Actor"
fetch "http://${TARGET}/other"
expect "GET ${TARGET}/other, which no rule allows" 403 "No rule in profile egress-demo"
TARGET_IP=$(${K} -n "${TARGET_NS}" get svc whoami -o jsonpath='{.spec.clusterIP}')
fetch "http://${TARGET_IP}/"
expect "GET by address ${TARGET_IP}/, which the rule does not name" 403
# Decided on the port the Actor dialed, before the gateway dials it.
fetch "http://${TARGET}:8080/"
expect "GET ${TARGET}:8080/, a port the rule does not name" 403
fetch "https://example.com/"
if [[ "${CODE}" == 200 ]]; then
  pass "GET https://example.com/, inside TLS Substrate terminates: 200"
  fetch "https://www.iana.org/"
  expect "GET https://www.iana.org/, which no rule allows" 403 "No rule in profile egress-demo"
else
  info "example.com is unreachable from the cluster (${CODE} ${BODY:0:200}): TLS checks skipped"
fi

RUN1=$(actor_run "${UID1}")
[[ -n "${RUN1}" ]] && pass "Clovisor's run ${RUN1} is the Actor (uid ${UID1})" || fail "no run in Clovisor for uid ${UID1}"
agentctl status 2>/dev/null | grep -q "Active runs *1" && pass "agentctl status: one active run" || fail "agentctl status: $(agentctl status 2>&1 | grep -i 'active runs')"

log "lifecycle: the Actor deleted, its run ends, with its timeline"
stop_proxy
${KATE} suspend actor "${ACTOR}" -a "${ATESPACE}" >/dev/null 2>&1 || true
${KATE} delete actor "${ACTOR}" -a "${ATESPACE}" >/dev/null 2>&1 || true
TL=
for _ in $(seq 1 30); do
  if TL=$(agentctl events --json "${RUN1}" 2>/dev/null) && [[ -n "${TL}" ]]; then break; fi
  sleep 3
done
if [[ -n "${TL}" ]]; then
  printf '%s' "${TL}" >"${WORK}/tl.json"
  python3 - "${WORK}/tl.json" >"${WORK}/tl.txt" <<'PY' || true
import json, sys
tl = json.load(open(sys.argv[1]))
a = tl.get("actor") or {}
print("actor", a.get("atespace"), a.get("name"), a.get("uid"), a.get("template"))
print("end", tl.get("end_reason", ""))
for e in tl.get("events", []):
    if e.get("type") == "http":
        print("http", e.get("method"), e.get("dst_name") or e.get("dst_ip"), e.get("dst_port"), e.get("path"),
              e.get("decision"), e.get("rule", ""), e.get("orig_dst", ""))
PY
  sed 's/^/   /' "${WORK}/tl.txt"
  grep -q "^actor ${ATESPACE} ${ACTOR} ${UID1} ${TEMPLATE}" "${WORK}/tl.txt" && pass "the timeline names the Actor, its UID and template" || fail "the timeline's Actor is wrong"
  grep -q "^end .*deleted" "${WORK}/tl.txt" && pass "the run ended because the Actor was deleted" || fail "the run's end reason: $(grep ^end "${WORK}/tl.txt")"
  grep -q "^http GET .* /secret deny no-secret" "${WORK}/tl.txt" && pass "the timeline has the refusal by no-secret" || fail "the timeline lacks the refusal by no-secret"
  grep -q "^http GET ${TARGET} 80 / allow whoami-read ${TARGET_IP}:80" "${WORK}/tl.txt" && pass "the timeline has the allow, with the address the Actor dialed" || fail "the timeline lacks the allow by whoami-read at ${TARGET_IP}:80"
else
  fail "run ${RUN1:-?} has no timeline after the Actor was deleted"
fi

log "only Substrate's gateway can call Clovisor"
${K} apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: clovisor-probe
  namespace: ${NS}
spec:
  serviceAccountName: clovisor
  automountServiceAccountToken: false
  securityContext: { runAsUser: 65532, runAsNonRoot: true }
  containers:
  - name: curl
    image: curlimages/curl:8.17.0
    command: ["sleep", "600"]
    volumeMounts:
    - { name: podidentity, mountPath: /run/podidentity.podcert.ate.dev, readOnly: true }
    - { name: servicedns, mountPath: /run/servicedns.podcert.ate.dev, readOnly: true }
  volumes:
  - name: podidentity
    projected:
      sources:
      - podCertificate: { signerName: podidentity.podcert.ate.dev/identity, keyType: ECDSAP256, credentialBundlePath: credential-bundle.pem }
  - name: servicedns
    projected:
      sources:
      - clusterTrustBundle: { signerName: servicedns.podcert.ate.dev/identity, labelSelector: { matchLabels: { podcert.ate.dev/canarying: live } }, path: trust-bundle.pem }
YAML
${K} -n "${NS}" wait --for=condition=Ready pod/clovisor-probe --timeout=180s >/dev/null
probe() {
  ${K} -n "${NS}" exec clovisor-probe -- curl -sS -o /dev/null -w 'http %{http_code}' --http2 -m 10 \
    --cacert /run/servicedns.podcert.ate.dev/trust-bundle.pem "$@" \
    "https://clovisor.${NS}.svc:9443/envoy.service.ext_proc.v3.ExternalProcessor/Process" 2>&1 || true
}
# Clovisor's own podidentity certificate: the right CA, not atenet-egress.
OUT=$(probe --cert /run/podidentity.podcert.ate.dev/credential-bundle.pem)
grep -qE "^http [1-9]" <<<"${OUT}" && fail "another workload's certificate reached ext_proc: ${OUT}" || pass "another workload's certificate is refused at the handshake (${OUT##*: })"
OUT=$(probe)
grep -qE "^http [1-9]" <<<"${OUT}" && fail "a client with no certificate reached ext_proc: ${OUT}" || pass "a client with no certificate is refused at the handshake (${OUT##*: })"

log "a new Actor of the same name: a new run; Clovisor down: refused"
start_actor
UID2=$(actor_uid)
fetch "http://${TARGET}/"
expect "GET ${TARGET}/ as the new Actor" 200
RUN2=$(actor_run "${UID2}")
[[ -n "${RUN2}" && "${RUN2}" != "${RUN1}" ]] && pass "uid ${UID2} has its own run ${RUN2}" || fail "uid ${UID2}: run '${RUN2}' (the old was ${RUN1})"
POD=$(${K} -n "${NS}" get pod -l app=clovisor -o jsonpath='{.items[0].metadata.name}')
${K} -n "${NS}" scale deployment/clovisor --replicas=0 >/dev/null
${K} -n "${NS}" wait --for=delete pod/"${POD}" --timeout=120s >/dev/null 2>&1 || true
fetch "http://${TARGET}/"
[[ "${CODE}" != 200 ]] && pass "GET ${TARGET}/ with Clovisor down: not sent (${CODE} ${BODY:0:120})" || fail "GET ${TARGET}/ with Clovisor down was sent"
${K} -n "${NS}" scale deployment/clovisor --replicas=1 >/dev/null
${K} -n "${NS}" rollout status deployment/clovisor --timeout=180s >/dev/null
for _ in $(seq 1 20); do
  fetch "http://${TARGET}/"
  [[ "${CODE}" == 200 ]] && break
  sleep 2
done
expect "GET ${TARGET}/ with Clovisor back" 200

log "result: ${PASSED} passed, ${FAILED} failed"
[[ "${FAILED}" == 0 ]]
