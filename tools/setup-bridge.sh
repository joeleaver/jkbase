#!/bin/bash
# Provision the RUNTIME-VM network bridge for jkbase (jkbr0).
#
# Runtime VMs run untrusted tenant app code but — BY DESIGN — get NAT'd egress to the
# PUBLIC internet (unlike build VMs, which are confined to the egress proxy on jkbuild0;
# see tools/setup-build-net.sh). This script creates the bridge, enables forwarding +
# MASQUERADE, opens the FORWARD path for jkbr0 → uplink (+ the established return path),
# and — under the all-tenants-untrusted threat model — DROPS forwarding from jkbr0 to
# host-INTERNAL targets (link-local / cloud-metadata 169.254.169.254 + RFC1918) so a
# hostile app can't pivot off the public internet into the host's network or steal cloud
# instance credentials.
#
# This is the SINGLE SOURCE OF TRUTH for the runtime bridge: provision.sh installs it as
# the systemd ExecStartPre /usr/local/bin/jkbase-bridge.sh, and deploy-server.sh re-syncs
# it to already-provisioned boxes. Idempotent (every rule is `-C`-guarded); run as root.
#
#   sudo tools/setup-bridge.sh [BRIDGE] [GATEWAY_CIDR]
# Defaults: jkbr0  172.16.0.1/24
set -euo pipefail

BRIDGE="${1:-jkbr0}"
GW_CIDR="${2:-172.16.0.1/24}"
GW_IP="${GW_CIDR%/*}"
PREFIX="${GW_CIDR#*/}"
SUBNET="${GW_IP%.*}.0/${PREFIX}" # e.g. 172.16.0.1/24 -> 172.16.0.0/24

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (creates a bridge + iptables rules)" >&2
    exit 1
fi

# 1. Bridge + gateway IP.
if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add name "$BRIDGE" type bridge
    ip addr add "$GW_CIDR" dev "$BRIDGE"
    ip link set "$BRIDGE" up
else
    ip addr show "$BRIDGE" | grep -q "${GW_IP}/" || ip addr add "$GW_CIDR" dev "$BRIDGE"
    ip link set "$BRIDGE" up
fi

echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. NAT + forwarding to the PUBLIC internet via the default-route uplink.
PUB_IFACE=$(ip route show default | awk '{print $5; exit}')
if [ -n "$PUB_IFACE" ]; then
    if ! iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$PUB_IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$PUB_IFACE" -j MASQUERADE
    fi

    # SSRF guard (threat model: all tenants untrusted). Runtime VMs are NAT'd to the
    # public internet, but must NOT reach host-internal targets via the forward path:
    # cloud metadata (169.254.169.254), the rest of link-local, and RFC1918. Insert
    # these DROPs at the TOP of FORWARD so they precede the uplink ACCEPT below.
    # VM → host-gateway (172.16.0.1) is INPUT, not FORWARD, so host services are
    # governed separately; VM ↔ VM on the same bridge is L2-switched and gated by
    # per-TAP port isolation, not here. Loosen the RFC1918 entries ONLY if a
    # deployment legitimately needs private-network egress.
    for net in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        if ! iptables -C FORWARD -i "$BRIDGE" -d "$net" -j DROP 2>/dev/null; then
            iptables -I FORWARD 1 -i "$BRIDGE" -d "$net" -j DROP
        fi
    done

    # MASQUERADE only rewrites the source; whether a packet is forwarded at all is
    # decided by the filter FORWARD chain, whose policy is DROP on any host with
    # Docker/ufw/firewalld/libvirt or our own build-net rules present. Explicitly
    # ACCEPT jkbr0 → uplink plus the established/related return path.
    if ! iptables -C FORWARD -i "$BRIDGE" -o "$PUB_IFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$BRIDGE" -o "$PUB_IFACE" -j ACCEPT
    fi
    if ! iptables -C FORWARD -i "$PUB_IFACE" -o "$BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$PUB_IFACE" -o "$BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    fi
fi

echo "runtime bridge ready: $BRIDGE ($GW_CIDR) NAT'd to ${PUB_IFACE:-<no uplink>}; link-local + RFC1918 forwarding dropped"
