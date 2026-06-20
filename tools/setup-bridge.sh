#!/bin/bash
# Provision the RUNTIME-VM network bridge for jkbase (jkbr0).
#
# Runtime VMs run untrusted tenant app code but — BY DESIGN — get NAT'd egress to the
# PUBLIC internet (unlike build VMs, which are confined to the egress proxy on jkbuild0;
# see tools/setup-build-net.sh). This script creates the bridge, enables forwarding +
# MASQUERADE, opens the FORWARD path for jkbr0 → uplink (+ the established return path),
# and — under the all-tenants-untrusted threat model — DROPS forwarding from jkbr0 to
# link-local / cloud-metadata (169.254.169.254) so a hostile app can't steal cloud
# instance credentials. (RFC1918 egress is left open for apps that need private
# services; cross-tenant VM↔VM is blocked by per-TAP port isolation, not here.)
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
# The host's primary public IPv4 on that uplink — the address *.{domain} resolves to, and
# hence the address guests use to reach the reverse proxy (their own object store via
# storage.{domain}, their api, their own sites). JKRUNFW (below) allows guest→PUB_IP:80,443
# and DROPs every other guest→host destination.
PUB_IP=$(ip -4 -o addr show "$PUB_IFACE" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
if [ -n "$PUB_IFACE" ]; then
    if ! iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$PUB_IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$PUB_IFACE" -j MASQUERADE
    fi

    # SSRF guard (threat model: all tenants untrusted). Runtime VMs are NAT'd to the
    # public internet, but must NOT reach cloud metadata / the rest of link-local via
    # the forward path (169.254.169.254 → instance-credential theft on a cloud host).
    # DROP it at the TOP of FORWARD so it precedes the uplink ACCEPT below. RFC1918
    # egress is deliberately LEFT OPEN so an app that legitimately needs a private-
    # network service (e.g. a managed DB) still works; cross-tenant reach is handled by
    # per-TAP bridge port isolation (VM↔VM, L2) — not here. (VM → host-gateway is
    # INPUT, not FORWARD, so host services are governed separately.) To also fence off
    # RFC1918, add `-d 10.0.0.0/8 -d 172.16.0.0/12 -d 192.168.0.0/16` DROPs here.
    if ! iptables -C FORWARD -i "$BRIDGE" -d 169.254.0.0/16 -j DROP 2>/dev/null; then
        iptables -I FORWARD 1 -i "$BRIDGE" -d 169.254.0.0/16 -j DROP
    fi

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

# IPv6: runtime egress is IPv4-only (no v6 NAT/forwarding), and the metadata DROP above
# is v6-blind — so disable IPv6 on the bridge and DROP all v6 forwarding/input from it,
# closing the v6 SSRF/metadata path. Guests also boot ipv6.disable=1; this is host-side
# defense in depth, mirroring the build bridge (tools/setup-build-net.sh).
sysctl -w "net.ipv6.conf.${BRIDGE}.disable_ipv6=1" >/dev/null 2>&1 || true
if command -v ip6tables >/dev/null 2>&1; then
    if ! ip6tables -C FORWARD -i "$BRIDGE" -j DROP 2>/dev/null; then
        ip6tables -I FORWARD 1 -i "$BRIDGE" -j DROP
    fi
    if ! ip6tables -C INPUT -i "$BRIDGE" -j DROP 2>/dev/null; then
        ip6tables -I INPUT 1 -i "$BRIDGE" -j DROP
    fi
fi

# Guest DNS via a GATEWAY forwarder. Tenant apps need a resolver, but many hosts (OVH,
# for one) block outbound UDP/53 to public resolvers — so guests can't just use
# 1.1.1.1. Instead, expose the host's already-working systemd-resolved on the bridge IP
# (DNSStubListenerExtra) and open ONLY ${GW_IP}:53 from the bridge. Guests do UDP/53 to
# the LOCAL gateway (always allowed) and the host forwards upstream however it can —
# provider-agnostic, and it works for every DNS client (getaddrinfo, c-ares, Go, …),
# not just glibc. The agent points each container's /etc/resolv.conf at ${GW_IP}.
# (A non-systemd-resolved host should run some forwarder on ${GW_IP}:53 instead — the
# only contract is "a resolver answers at the gateway".)
# Host-service isolation. A dedicated JKRUNFW INPUT chain (flushed + rebuilt each run, so
# idempotent) gates EVERYTHING arriving from the runtime bridge to the host. A guest may
# reach ONLY: the gateway DNS forwarder (${GW_IP}:53) and the public reverse proxy
# (${PUB_IP}:80,443 — its own object store via storage.{domain}, its api, its own sites).
# Every other guest→host destination is DROPped — the control API (:9090, now also
# loopback-bound), the object-store backend (:9091, loopback-bound), the gateway on any
# non-DNS port, and any other host service — regardless of whether/how ufw is configured.
# Egress to the internet is FORWARD, not INPUT, so it is untouched (RFC1918 egress stays
# open per the apps-need-private-services decision). -w: jkbase-server edits iptables
# (build per-VM grants) concurrently, so wait for the xtables lock rather than race it.
iptables -w -N JKRUNFW 2>/dev/null || iptables -w -F JKRUNFW
iptables -w -A JKRUNFW -d "$GW_IP" -p udp --dport 53 -j ACCEPT
iptables -w -A JKRUNFW -d "$GW_IP" -p tcp --dport 53 -j ACCEPT
if [ -n "${PUB_IP:-}" ]; then
    iptables -w -A JKRUNFW -d "$PUB_IP" -p tcp -m multiport --dports 80,443 -j ACCEPT
fi
iptables -w -A JKRUNFW -j DROP
iptables -w -C INPUT -i "$BRIDGE" -j JKRUNFW 2>/dev/null \
    || iptables -w -I INPUT 1 -i "$BRIDGE" -j JKRUNFW
# Remove the pre-JKRUNFW standalone :53 ACCEPTs that older versions of this script left in
# INPUT, so a re-synced box doesn't accumulate cruft (JKRUNFW covers guest DNS now).
for proto in udp tcp; do
    while iptables -w -C INPUT -i "$BRIDGE" -d "$GW_IP" -p "$proto" --dport 53 -j ACCEPT 2>/dev/null; do
        iptables -w -D INPUT -i "$BRIDGE" -d "$GW_IP" -p "$proto" --dport 53 -j ACCEPT
    done
done
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    mkdir -p /etc/systemd/resolved.conf.d
    want="# jkbase: answer guest DNS on the runtime bridge gateway (managed by setup-bridge.sh)
[Resolve]
DNSStubListenerExtra=${GW_IP}"
    if [ "$(cat /etc/systemd/resolved.conf.d/jkbase-stub.conf 2>/dev/null)" != "$want" ]; then
        printf '%s\n' "$want" > /etc/systemd/resolved.conf.d/jkbase-stub.conf
    fi
    # At boot systemd-resolved starts before this bridge exists, so its bind to
    # ${GW_IP}:53 would have failed — (re)bind now the bridge is up. Restart only when
    # it isn't already listening there, to avoid needless host-DNS blips.
    if ! ss -ulnH 2>/dev/null | grep -q "${GW_IP}:53"; then
        systemctl try-restart systemd-resolved 2>/dev/null || true
    fi
fi

echo "runtime bridge ready: $BRIDGE ($GW_CIDR) NAT'd to ${PUB_IFACE:-<no uplink>}; link-local/metadata forwarding dropped (RFC1918 egress allowed); guest DNS via ${GW_IP}:53"
