#!/bin/bash
set -euo pipefail

BRIDGE="jkbr0"
BRIDGE_IP="172.16.0.1/24"

# Create bridge if it doesn't exist
if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add name "$BRIDGE" type bridge
    ip addr add "$BRIDGE_IP" dev "$BRIDGE"
    ip link set "$BRIDGE" up
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "Bridge $BRIDGE created with IP $BRIDGE_IP"
else
    echo "Bridge $BRIDGE already exists"
fi
