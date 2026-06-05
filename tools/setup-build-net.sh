#!/bin/bash
# Provision the ISOLATED build network for jkbase build VMs (design §9).
#
# Build VMs run untrusted tenant build code, so — unlike runtime VMs (jkbr0, which
# is NAT'd to the internet) — they get a dedicated bridge with a strict firewall:
# a build VM may reach ONLY the host-side egress proxy on the build gateway, and
# nothing else (no internet directly, no other VMs, no host services). All real
# fetches go through the proxy, which enforces the allowlist + IP pinning.
#
# Idempotent. Run as root before the server (the systemd unit can ExecStartPre
# this); local dev users run it once per boot.
#
#   sudo tools/setup-build-net.sh [BRIDGE] [GATEWAY_CIDR] [PROXY_PORT]
# Defaults: jkbuild0  172.31.0.1/24  3128
set -euo pipefail

BRIDGE="${1:-jkbuild0}"
GW_CIDR="${2:-172.31.0.1/24}"
PROXY_PORT="${3:-3128}"
GW_IP="${GW_CIDR%/*}"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (creates a bridge + iptables rules)" >&2
    exit 1
fi

# 1. Bridge + gateway IP (the egress proxy binds here).
if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add name "$BRIDGE" type bridge
    ip addr add "$GW_CIDR" dev "$BRIDGE"
    ip link set "$BRIDGE" up
    echo "created bridge $BRIDGE ($GW_CIDR)"
else
    ip addr show "$BRIDGE" | grep -q "${GW_IP}/" || ip addr add "$GW_CIDR" dev "$BRIDGE"
    ip link set "$BRIDGE" up
    echo "bridge $BRIDGE already exists"
fi
# Note: deliberately NO ip_forward / MASQUERADE for the build subnet — build VMs
# must not route anywhere; their only path out is the proxy (a host process).

# 2. Firewall. A dedicated JKBUILD chain (flushed + rebuilt each run, so the rules
# are idempotent) gates everything arriving from the build bridge.
iptables -N JKBUILD 2>/dev/null || iptables -F JKBUILD
#   allow → the egress proxy on the gateway, drop everything else to the host.
iptables -A JKBUILD -p tcp -d "$GW_IP" --dport "$PROXY_PORT" -j ACCEPT
iptables -A JKBUILD -j DROP
# Hook host-bound traffic from the build bridge through JKBUILD (insert once).
iptables -C INPUT -i "$BRIDGE" -j JKBUILD 2>/dev/null \
    || iptables -I INPUT 1 -i "$BRIDGE" -j JKBUILD
# Drop ALL forwarding from the build bridge: no internet, no other subnets/VMs.
iptables -C FORWARD -i "$BRIDGE" -j DROP 2>/dev/null \
    || iptables -I FORWARD 1 -i "$BRIDGE" -j DROP

echo "build network ready: VMs on $BRIDGE may reach ONLY ${GW_IP}:${PROXY_PORT} (egress proxy)"
