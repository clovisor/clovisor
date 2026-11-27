#!/bin/sh
# Clovisor package: the user Envoy runs as, and systemd's view of the
# units. Nothing is enabled or started: that is the operator's choice.
set -e
if ! getent passwd clovisor-envoy >/dev/null; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin clovisor-envoy 2>/dev/null ||
    useradd -r -M -d /nonexistent -s /sbin/nologin clovisor-envoy
fi
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
echo "clovisor: installed. Start with: systemctl enable --now clovisor-node-agent clovisor-envoy"
