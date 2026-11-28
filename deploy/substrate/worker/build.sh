#!/usr/bin/env bash
# Copyright (c) Authors of Clovisor
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
#
# A Substrate gVisor worker image that starts each sandbox with Clovisor's
# trace session (milestone 7.5). Substrate passes runsc the flags in its
# image's ko data, internal_flags.json; this adds
#   --pod-init-config=/var/lib/ate/clovisor/session.json
# to create and restore, and changes nothing else. The sandbox sink
# (sandbox-audit.yaml) writes that file and must run on every node the
# image runs on: a sandbox does not start without it.
#
#   deploy/substrate/worker/build.sh BASE_IMAGE OUT_IMAGE
#
# BASE_IMAGE is the WorkerPool's workerImage (Substrate's ateworker-gvisor);
# OUT_IMAGE is pushed. Needs docker and python3.
set -o errexit -o nounset -o pipefail
[[ $# -eq 2 ]] || { echo "usage: $0 BASE_IMAGE OUT_IMAGE" >&2; exit 2; }
BASE=$1 OUT=$2
FLAG=--pod-init-config=/var/lib/ate/clovisor/session.json
WORK=$(mktemp -d "${TMPDIR:-/tmp}/clovisor-worker.XXXXXX")
trap 'rm -rf "${WORK}"' EXIT

docker pull -q "${BASE}" >/dev/null
KD=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "${BASE}" | sed -n 's/^KO_DATA_PATH=//p')
KD=${KD:-/var/run/ko}
CID=$(docker create "${BASE}")
docker cp -L "${CID}:${KD}/internal_flags.json" "${WORK}/base.json" >/dev/null || { docker rm "${CID}" >/dev/null; echo "no ${KD}/internal_flags.json in ${BASE}" >&2; exit 1; }
docker rm "${CID}" >/dev/null

python3 - "${WORK}/base.json" "${FLAG}" >"${WORK}/internal_flags.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
flag = sys.argv[2]
cmds = cfg.setdefault("commands", {})
for c in ("create", "restore"):
    g = cmds.setdefault(c, {}).setdefault("globalFlags", [])
    g[:] = [f for f in g if not f.startswith("--pod-init-config")]
    g.append(flag)
json.dump(cfg, sys.stdout, indent=2)
print()
PY
cat >"${WORK}/Dockerfile" <<DOCKERFILE
FROM ${BASE}
LABEL dev.clovisor.worker-base="${BASE}"
COPY internal_flags.json ${KD}/internal_flags.json
DOCKERFILE
docker build -q -t "${OUT}" "${WORK}" >/dev/null
docker push -q "${OUT}" >/dev/null
echo "${OUT}: ${BASE}, with ${FLAG} on create and restore"
