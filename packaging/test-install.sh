#!/bin/sh
# Install Clovisor's package in a clean container and check what it put
# where (milestone 7.2): `make package-test`. $1: deb or rpm. The
# repository is mounted at /src; the packages are in /src/dist.
set -eu
kind=$1
fail() { echo "FAIL: $*" >&2; exit 1; }

case $kind in
deb)
	apt-get update -qq >/dev/null
	apt-get install -y -qq /src/dist/clovisor_*.deb >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "apt install"; }
	;;
rpm)
	dnf install -y -q /src/dist/clovisor-*.rpm >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "dnf install"; }
	;;
*) fail "usage: $0 deb|rpm" ;;
esac
grep -q "systemctl enable --now clovisor-node-agent" /tmp/install.log || fail "postinstall did not run"

for f in /usr/bin/node-agent /usr/bin/agentctl /usr/bin/audit-sink; do
	[ -x "$f" ] || fail "$f missing or not executable"
done
for f in /usr/lib/clovisor/agent_audit.o /usr/lib/systemd/system/clovisor-node-agent.service \
	/usr/lib/systemd/system/clovisor-envoy.service /etc/default/clovisor \
	/etc/clovisor/policy/observe.yaml /etc/clovisor/policy/ceilings.yaml; do
	[ -f "$f" ] || fail "$f missing"
done
# The guide is in the package; slim images skip /usr/share/doc when installing.
case $kind in
deb) dpkg -L clovisor | grep -q /usr/share/doc/clovisor/operator-guide.md || fail "no operator guide in the package" ;;
rpm) rpm -ql clovisor | grep -q /usr/share/doc/clovisor/operator-guide.md || fail "no operator guide in the package" ;;
esac
# The node agent refuses policy anyone but root can write.
[ "$(stat -c %U:%a /etc/clovisor/policy)" = "root:755" ] || fail "policy directory: $(stat -c %U:%a /etc/clovisor/policy)"
getent passwd clovisor-envoy >/dev/null || fail "no clovisor-envoy user"
/usr/bin/node-agent -h 2>&1 | grep -q "envoy-uids" || fail "node-agent does not run"
# The installed policy compiles, as the node agent will.
/usr/bin/agentctl explain /etc/clovisor/policy/observe.yaml >/tmp/explain.log 2>&1 || { cat /tmp/explain.log; fail "explain"; }
grep -q "observe@sha256:" /tmp/explain.log || fail "the receipt names no observe profile"

case $kind in
deb) apt-get remove -y -qq clovisor >/dev/null ;;
rpm) dnf remove -y -q clovisor >/dev/null ;;
esac
[ ! -e /usr/bin/node-agent ] || fail "remove left /usr/bin/node-agent"
echo "ok: $kind package installs, puts each file in place, and removes"
