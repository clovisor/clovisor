#!/usr/bin/env bash
# Copyright (c) Authors of Clovisor
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
#
# The sandbox sink against real gVisor (milestone 7.5), no cluster: the
# runsc Substrate's default SandboxConfig pins, run as Substrate's workers
# run it (-root <actors>/<actor UID>/runsc-state), with the sink's own
# trace session. A busybox sandbox runs wget every 2 seconds; it is
# checkpointed under one Actor and restored under another, as Substrate
# moves an Actor between Workers.
#
#   integration/substrate/runsc-sink.sh
#
# Needs Linux, sudo (runsc runs as root), docker (for busybox), go, curl,
# python3. Work files go in WORK (default ~/.cache/clovisor/runsc-sink),
# outside the module: runsc leaves root-owned state there.
set -o errexit -o nounset -o pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-${XDG_CACHE_HOME:-${HOME}/.cache}/clovisor/runsc-sink}
# gVisor release 20261102.0, as Substrate's sandboxconfig-gvisor.yaml (v7) pins it.
GVISOR_REL=20261102.0
case "$(uname -m)" in
  aarch64) ARCH=aarch64 SHA=f702ae92ad7a0c4134be34ca23f52966dbb696db0c0f5b8ec439210ab2cd7c6a ;;
  x86_64) ARCH=x86_64 SHA=a1439ffbba7d212e0fde32ea79fa9bb51cbc4c5f6c16af1f047260290b861d42 ;;
  *) echo "runsc-sink: no gVisor for $(uname -m)" >&2; exit 1 ;;
esac
A=0f6c1f8e-2b7a-4c55-9a51-6b1f0c6a7e01
B=9a3d2c41-7e5f-4b19-8c2d-5e4f3a2b1c02
DOCKER=${DOCKER:-docker}

log()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; PASSED=$((PASSED+1)); }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=$((FAILED+1)); }
PASSED=0 FAILED=0

mkdir -p "${WORK}"
cd "${WORK}"
R=${WORK}/gvisor/runsc
if [[ ! -x "${R}" ]]; then
  log "gVisor ${GVISOR_REL} (${ARCH})"
  curl -fsSL -o gvisor.tar.zstd "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_REL}/${ARCH}/gvisor.tar.zstd"
  echo "${SHA}  gvisor.tar.zstd" | sha256sum -c --quiet
  mkdir -p gvisor && zstd -dc gvisor.tar.zstd | tar -x -C gvisor
fi
if [[ ! -d bundle/rootfs/bin ]]; then
  log "a busybox bundle"
  mkdir -p bundle/rootfs
  CID=$(${DOCKER} create busybox:1.37.0)
  ${DOCKER} export "${CID}" | tar -x -C bundle/rootfs
  ${DOCKER} rm "${CID}" >/dev/null
  (cd bundle && "${R}" spec -- /bin/sh -c 'i=0; while true; do i=$((i+1)); wget -q -T1 http://10.1.2.3/$i; sleep 2; done')
  python3 -c "import json; c=json.load(open('bundle/config.json')); c['process']['terminal']=False; json.dump(c, open('bundle/config.json','w'))"
fi
(cd "${ROOT}" && go build -o "${WORK}/sandbox-sink" ./cmd/sandbox-sink)

# A short directory: a Unix socket's path is at most 108 bytes.
SD=$(mktemp -d /tmp/clovisor-sink.XXXXXX)
ACTORS=${WORK}/actors
SINK=
cleanup() {
  for r in "${ACTORS}/${A}/runsc-state" "${ACTORS}/${B}/runsc-state" "${WORK}/other/runsc-state"; do
    for c in c c2 c3; do sudo "${R}" -root "${r}" delete -force "$c" >/dev/null 2>&1 || true; done
  done
  [[ -n "${SINK}" ]] && kill "${SINK}" 2>/dev/null || true
  rm -rf "${SD}"
}
trap cleanup EXIT
sudo rm -rf "${WORK}/ckpt"
mkdir -p "${WORK}/ckpt"

log "the sink, then a sandbox as Actor A's, checkpointed, restored as Actor B's"
"${WORK}/sandbox-sink" -dir "${SD}" -actors-dir "${ACTORS}" >"${WORK}/points.jsonl" 2>"${WORK}/sink.log" &
SINK=$!
for _ in $(seq 1 20); do [[ -S "${SD}/gvisor.sock" && -f "${SD}/session.json" ]] && break; sleep 0.2; done
INIT=--pod-init-config=${SD}/session.json
sudo "${R}" "${INIT}" -root "${ACTORS}/${A}/runsc-state" --network=none run -detach -bundle "${WORK}/bundle" c >/dev/null 2>&1 &&
  pass "a sandbox starts with the sink's trace session" || fail "the sandbox did not start"
sleep 5
sudo "${R}" -root "${ACTORS}/${A}/runsc-state" checkpoint -image-path "${WORK}/ckpt" c >/dev/null 2>&1 &&
  pass "it checkpoints with the sink connected" || fail "checkpoint failed"
sudo "${R}" "${INIT}" -root "${ACTORS}/${B}/runsc-state" --network=none restore -image-path "${WORK}/ckpt" -bundle "${WORK}/bundle" -detach c >/dev/null 2>&1 &&
  pass "it restores, with a new session" || fail "restore failed"
sleep 6
sudo "${R}" -root "${ACTORS}/${B}/runsc-state" delete -force c >/dev/null 2>&1 || true

log "refusals: a runsc that is not an Actor's, and no sink"
OUT=$(sudo "${R}" "${INIT}" -root "${WORK}/other/runsc-state" --network=none run -detach -bundle "${WORK}/bundle" c2 2>&1 || true)
grep -q "cannot init config" <<<"${OUT}" && pass "a sandbox the sink cannot attribute does not start" || fail "an unattributable sandbox started: ${OUT}"
kill "${SINK}"; wait "${SINK}" 2>/dev/null || true; SINK=
OUT=$(sudo "${R}" "${INIT}" -root "${ACTORS}/${A}/runsc-state" --network=none run -detach -bundle "${WORK}/bundle" c3 2>&1 || true)
grep -q "connection refused" <<<"${OUT}" && pass "with the sink down, a sandbox does not start" || fail "a sandbox started with no sink: ${OUT}"

log "what the sink received"
python3 - "${WORK}/points.jsonl" "${A}" "${B}" "$(sha256sum bundle/rootfs/bin/busybox | cut -c1-64)" >"${WORK}/check.txt" <<'PY'
import json, sys
path, a, b, busybox = sys.argv[1:5]
evs = [json.loads(l) for l in open(path)]
def ok(name, cond): print(("PASS " if cond else "FAIL ") + name)
for uid, who in ((a, "A"), (b, "B")):
    # The loop runs wget and sleep, each from busybox.
    ex = [e for e in evs if e["actor_uid"] == uid and e["kind"] == "exec" and e.get("binary") == "/bin/wget"]
    co = [e for e in evs if e["actor_uid"] == uid and e["kind"] == "connect"]
    ok("Actor %s: %d execs of /bin/wget, with argv and busybox's SHA-256" % (who, len(ex)),
       ex and all(e.get("args", [""])[0] == "wget" and e.get("args", [""])[-1].startswith("http://10.1.2.3/") and e.get("sha256") == busybox for e in ex))
    ok("Actor %s: %d TCP connects to 10.1.2.3:80, ENETUNREACH" % (who, len(co)),
       co and all(e.get("proto") == "TCP" and e.get("dst_ip") == "10.1.2.3" and e.get("dst_port") == 80 and e.get("result") == "ENETUNREACH" for e in co))
ok("every event is Actor A's or B's", all(e["actor_uid"] in (a, b) for e in evs))
ok("no points lost", not [e for e in evs if e["kind"] == "lost"])
pa = max(e.get("pid", 0) for e in evs if e["actor_uid"] == a and e["kind"] == "exec")
pb = min(e.get("pid", 0) for e in evs if e["actor_uid"] == b and e["kind"] == "exec")
ok("the restored sandbox's processes continue A's (pid %d, then %d)" % (pa, pb), pb > pa)
PY
while read -r verdict rest; do
  if [[ "${verdict}" == PASS ]]; then pass "${rest}"; else fail "${rest}"; fi
done <"${WORK}/check.txt"
grep -q "refused a sandbox" "${WORK}/sink.log" && pass "the sink logged the refusal" || fail "the sink did not log the refusal"

log "result: ${PASSED} passed, ${FAILED} failed"
[[ "${FAILED}" == 0 ]]
