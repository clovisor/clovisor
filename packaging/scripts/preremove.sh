#!/bin/sh
# Clovisor package: stop the services before their files go.
set -e
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  systemctl disable --now clovisor-envoy.service clovisor-node-agent.service 2>/dev/null || true
fi
