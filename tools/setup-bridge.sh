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
# ALL global IPv4s on that uplink — the proxy binds 0.0.0.0:80/443 (every host IP), and on a
# multi-homed / failover-IP host (the OVH prod target) *.{domain} may resolve to a secondary.
# Guests reach the reverse proxy (their object store via storage.{domain}, their api, their
# own sites) on whichever it is, so JKRUNFW (below) allows guest→each of them and DROPs the
# rest. (head -n1 would silently fence object-store/api/sites on a secondary-IP host.)
PUB_IPS=$(ip -4 -o addr show "$PUB_IFACE" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')
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
# for one) block outbound UDP/53 to public resolvers — so guests can't just use 1.1.1.1.
# Instead, jkbase-server runs an IN-PROCESS DNS forwarder bound on ${GW_IP}:53
# (crates/jkbase-server/src/dns_forwarder.rs); we open ONLY ${GW_IP}:53 from the bridge.
# Guests do UDP/53 to the LOCAL gateway (always allowed) and the forwarder relays to the
# host's own resolver (whatever /etc/resolv.conf lists — e.g. systemd-resolved's
# 127.0.0.53), which reaches upstream however this host can — provider-agnostic, and it
# works for every DNS client (getaddrinfo, c-ares, Go, …), not just glibc. The agent points
# each container's /etc/resolv.conf at ${GW_IP}. Owning the listener (vs systemd-resolved's
# DNSStubListenerExtra, which this script used to configure) makes guest DNS per-guest
# rate-limited, logged, attributable, and lifecycle-bound to the server — the port handoff
# from resolved is at the bottom of this script.
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
# Replies to HOST-initiated flows MUST pass: the reverse proxy + wait_for_agent connect INTO
# each guest on :80, and the guest's return packets are locally destined → INPUT → JKRUNFW.
# Without this the proxy can't serve a single request. This does NOT let a guest open a NEW
# flow to a forbidden host port — only RELATED/ESTABLISHED replies are admitted.
iptables -w -A JKRUNFW -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -w -A JKRUNFW -d "$GW_IP" -p udp --dport 53 -j ACCEPT
iptables -w -A JKRUNFW -d "$GW_IP" -p tcp --dport 53 -j ACCEPT
# Managed-DB P2 §7.6 — the app→DB in-guest leg's HOST gateway. A dedicated project's app VM reaches
# its sibling DB VM host-mediated: its agent dials the gateway on ${GW_IP}:4230 (rhypedb HTTP plane)
# / :4231 (native TCP wire), which authenticates by the source-guard-pinned (unforgeable) source IP
# and splices to the DB VM's agent. Open ONLY those two gateway ports on ${GW_IP}; the gateway does
# the per-project authorization. (Ports must match jkbase-common config DB_GATEWAY_{HTTP,WIRE}_PORT.)
# This is INPUT (guest→local gateway IP), so the FORWARD-chain SSRF/metadata DROP does not touch it.
iptables -w -A JKRUNFW -d "$GW_IP" -p tcp -m multiport --dports 4230,4231 -j ACCEPT
# Defense-in-depth ([R1]): the DB gateway binds ${GW_IP} (a bridge IP, NOT loopback), so on a
# multi-homed host Linux's weak-host model would otherwise deliver an OFF-bridge packet destined to
# ${GW_IP} to INPUT — bypassing the `-i jkbr0`-scoped JKRUNFW above. DROP any such non-bridge packet
# to the gateway ports outright (the load-bearing control is still the gateway's source-IP auth; an
# off-bridge source matches no allocation and is dropped there too). Inserted at INPUT head.
if ! iptables -w -C INPUT ! -i "$BRIDGE" -d "$GW_IP" -p tcp -m multiport --dports 4230,4231 -j DROP 2>/dev/null; then
    iptables -w -I INPUT 1 ! -i "$BRIDGE" -d "$GW_IP" -p tcp -m multiport --dports 4230,4231 -j DROP
fi
# Same weak-host DROP for the DNS forwarder ([R1]): jkbase-server binds ${GW_IP}:53 (a bridge IP,
# NOT loopback), so on a multi-homed host an OFF-bridge packet to ${GW_IP}:53 could reach INPUT and
# bypass the `-i jkbr0`-scoped JKRUNFW — turning the forwarder into an internet-facing open resolver.
# DROP any non-bridge packet to :53 outright (the forwarder also source-checks 172.16.0.0/24
# in-process; this is the firewall belt-and-braces).
for dnsproto in udp tcp; do
    if ! iptables -w -C INPUT ! -i "$BRIDGE" -d "$GW_IP" -p "$dnsproto" --dport 53 -j DROP 2>/dev/null; then
        iptables -w -I INPUT 1 ! -i "$BRIDGE" -d "$GW_IP" -p "$dnsproto" --dport 53 -j DROP
    fi
done
if [ -n "${PUB_IPS// /}" ]; then
    for pub in $PUB_IPS; do
        iptables -w -A JKRUNFW -d "$pub" -p tcp -m multiport --dports 80,443 -j ACCEPT
    done
elif [ -n "$PUB_IFACE" ]; then
    echo "WARNING: no global IPv4 on $PUB_IFACE; guest→proxy (object store / api / own sites) will be DROPped" >&2
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
# Hand ${GW_IP}:53 off from systemd-resolved to jkbase-server's in-process forwarder. Older versions
# of this script exposed systemd-resolved on the bridge IP via a DNSStubListenerExtra drop-in; REMOVE
# it and restart resolved so it RELEASES ${GW_IP}:53 for the forwarder to bind. jkbase-server starts
# right after this ExecStartPre and the forwarder retries the bind briefly, covering any residual
# race. The host's own resolver (systemd-resolved on 127.0.0.53) is untouched — the forwarder relays
# to it. (On a non-systemd-resolved host there was never a drop-in; nothing to undo.)
if [ -f /etc/systemd/resolved.conf.d/jkbase-stub.conf ]; then
    rm -f /etc/systemd/resolved.conf.d/jkbase-stub.conf
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        systemctl try-restart systemd-resolved 2>/dev/null || true
    fi
fi

echo "runtime bridge ready: $BRIDGE ($GW_CIDR) NAT'd to ${PUB_IFACE:-<no uplink>}; link-local/metadata forwarding dropped (RFC1918 egress allowed); guest DNS via ${GW_IP}:53"
