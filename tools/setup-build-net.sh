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
#   sudo tools/setup-build-net.sh [BRIDGE] [GATEWAY_CIDR] [PROXY_PORT] [PROXY_ANY_PORT]
# Defaults: jkbuild0  172.31.0.1/24  3128  3129
#
# PROXY_ANY_PORT is the SECOND egress proxy — public-any mode (allowlist bypassed,
# SSRF pin retained) — used only by `builder = "dockerfile"` builds, whose FROM/RUN
# need broad egress. Both proxies enforce the IP pin (no private/metadata/control-
# plane), so it only widens the set of PUBLIC hosts a sandboxed VM may reach. This
# script does NOT open that port to the bridge: jkbase-server grants it per-source
# to ONE dockerfile build VM's guest IP at a time (and revokes it when the build
# ends), so a hostile non-dockerfile build can't reach broad egress by ignoring its
# assigned proxy. The arg is informational here; pass the same value to
# `jkbase-server --build-proxy-any-port` to enable the public-any proxy at all.
set -euo pipefail

BRIDGE="${1:-jkbuild0}"
GW_CIDR="${2:-172.31.0.1/24}"
PROXY_PORT="${3:-3128}"
# Default: NO second port (== PROXY_PORT disables it), so the public-any proxy is
# opt-in — a box's egress posture is unchanged unless an operator passes a distinct
# PROXY_ANY_PORT here AND to jkbase-server's --build-proxy-any-port.
PROXY_ANY_PORT="${4:-$PROXY_PORT}"
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
#   allow → the narrow allowlist egress proxy on the gateway (safe for every build),
#   drop everything else to the host. The public-any (dockerfile) proxy is NOT opened
#   here: jkbase-server inserts a per-source ACCEPT for one dockerfile VM's guest IP
#   above this DROP for the life of that build, so broad egress is scoped per-VM.
iptables -A JKBUILD -p tcp -d "$GW_IP" --dport "$PROXY_PORT" -j ACCEPT
iptables -A JKBUILD -j DROP
# Hook host-bound traffic from the build bridge through JKBUILD (insert once).
iptables -C INPUT -i "$BRIDGE" -j JKBUILD 2>/dev/null \
    || iptables -I INPUT 1 -i "$BRIDGE" -j JKBUILD
# Drop ALL forwarding from the build bridge: no internet, no other subnets/VMs.
iptables -C FORWARD -i "$BRIDGE" -j DROP 2>/dev/null \
    || iptables -I FORWARD 1 -i "$BRIDGE" -j DROP

# 3. IPv6: the proxy is IPv4-only, so there is nothing to allow over v6 — disable
# IPv6 on the bridge and drop all v6 from it. (Build VMs also boot ipv6.disable=1
# and their TAPs are bridge-port-isolated, so this is defense in depth against
# any host-side fe80:: link-local path around the IPv4 firewall.)
sysctl -w "net.ipv6.conf.${BRIDGE}.disable_ipv6=1" >/dev/null 2>&1 || true
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N JKBUILD 2>/dev/null || ip6tables -F JKBUILD
    ip6tables -A JKBUILD -j DROP
    ip6tables -C INPUT -i "$BRIDGE" -j JKBUILD 2>/dev/null \
        || ip6tables -I INPUT 1 -i "$BRIDGE" -j JKBUILD
    ip6tables -C FORWARD -i "$BRIDGE" -j DROP 2>/dev/null \
        || ip6tables -I FORWARD 1 -i "$BRIDGE" -j DROP
fi

if [ "$PROXY_ANY_PORT" != "$PROXY_PORT" ]; then
    echo "build network ready: VMs on $BRIDGE may reach ONLY ${GW_IP}:${PROXY_PORT} (allowlist proxy); ${GW_IP}:${PROXY_ANY_PORT} (dockerfile public-any proxy) is granted per-VM by jkbase-server, not opened here"
else
    echo "build network ready: VMs on $BRIDGE may reach ONLY ${GW_IP}:${PROXY_PORT} (egress proxy)"
fi
