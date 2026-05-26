#!/bin/bash
set -euo pipefail

TAP_DEV="${1:-tap0}"
TAP_IP="172.16.0.1"
MASK="/24"

# Create tap device
ip tuntap add dev "$TAP_DEV" mode tap
ip addr add "${TAP_IP}${MASK}" dev "$TAP_DEV"
ip link set "$TAP_DEV" up

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "Tap device $TAP_DEV created with IP $TAP_IP"
