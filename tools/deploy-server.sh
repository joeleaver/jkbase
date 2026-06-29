#!/bin/bash
#
# Deploy updated jkbase to a provisioned server
#
# Usage: ./deploy-server.sh <ssh-target>
# Example: ./deploy-server.sh ubuntu@54.39.17.150
#
# Pulls latest code, rebuilds, restarts the service.
#
# NOTE: this does NOT rebake the build toolchain images (rust/node/bun/… .ext4), which
# bake jkbuild-init (the in-VM build driver). After a change to the jkbuild lifecycle or
# a toolchain input, refresh them with tools/rebake-toolchains.sh (it injects the
# build-mirror CA and verifies it landed before swapping) — otherwise the host emits new
# build behaviour the stale baked jkbuild-init ignores.
#

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <ssh-target>"
    echo "Example: $0 ubuntu@54.39.17.150"
    exit 1
fi

TARGET="$1"

echo "=== Deploying jkbase to $TARGET ==="

# Keepalive: the release rebuild streams nothing for minutes (cargo output is
# piped to `tail`), so an idle SSH session can be dropped mid-deploy. Send a
# keepalive every 15s and tolerate a couple of minutes of silence.
ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=8 "$TARGET" 'bash -s' << 'REMOTE'
set -euo pipefail
source "$HOME/.cargo/env"

cd "$HOME/jkbase"

echo "Pulling latest..."
git pull --ff-only

echo "Building jkbase-server + CLI..."
cargo build --release -p jkbase-server -p jkbase-cli 2>&1 | tail -3

echo "Building jkbase-agent (musl)..."
cargo build --release -p jkbase-agent --target x86_64-unknown-linux-musl 2>&1 | tail -3

# Rebuild the runtime rootfs (apko Wolfi userland + chrony + the new agent as
# /sbin/init) so the agent's chrony-based guest clock discipline ships with this
# deploy. The server runs as root via systemd and can't reach the deploy user's
# apko, so we build the artifact here (as the deploy user) and the server consumes
# it. apko isn't a base-OS package; ensure-apko.sh installs just apko if missing
# (idempotent). We use it rather than install-image-tools.sh, which also fetches bun
# and so needs `unzip` — absent on a minimal server box.
export PATH="$HOME/.local/bin:$PATH"
./tools/ensure-apko.sh
echo "Building runtime rootfs (apko Wolfi + chrony + agent)..."
AGENT_BIN="$HOME/jkbase/target/x86_64-unknown-linux-musl/release/jkbase-agent" \
    OUT=/var/jkbase/base-rootfs.ext4 ./tools/build-runtime-rootfs.sh

# Clean stale loop mounts from any previous failed content image builds
echo "Cleaning stale mounts..."
for dev in $(losetup -l -n -O NAME,BACK-FILE 2>/dev/null | grep /var/jkbase/content-images | awk '{print $1}'); do
    mp=$(findmnt -rn -S "$dev" -o TARGET 2>/dev/null || true)
    if [ -n "$mp" ]; then
        sudo umount "$mp" 2>/dev/null || true
        sudo rmdir "$mp" 2>/dev/null || true
    fi
    sudo losetup -d "$dev" 2>/dev/null || true
done

# Ensure the live unit drains VMs cleanly on restart. Firecracker processes are
# children in jkbase.service's cgroup; the default KillMode=control-group SIGTERMs
# them at the same instant as jkbase-server, racing graceful hibernation ("failed
# to pause VM"). A drop-in (idempotent, no ExecStart duplication) fixes already-
# provisioned boxes that predate the provision.sh change.
echo "Refreshing systemd drain settings..."
sudo mkdir -p /etc/systemd/system/jkbase.service.d
sudo tee /etc/systemd/system/jkbase.service.d/10-drain.conf > /dev/null << 'DROPIN'
[Service]
KillMode=mixed
TimeoutStopSec=120
# Runtime-cgroup provisioner (VM re-adoption §1): an additive ExecStartPre so already-provisioned
# boxes whose main unit predates it still create /sys/fs/cgroup/jkbase-runtime before the server
# starts. Idempotent if the main unit (fresh provision) also lists it. The `-` prefix makes it
# NON-essential: the script is installed by the cp below (before this restart), but if a deploy
# aborts in the window between this daemon-reload and that cp, a later restart must not brick on a
# missing ExecStartPre — and the server self-creates the per-id leaf anyway, so a failure here only
# costs upgrade-survival, never startup.
ExecStartPre=-/usr/local/bin/jkbase-runtime-cgroup.sh
DROPIN
sudo systemctl daemon-reload

# Re-sync the ExecStartPre helpers from the repo. provision.sh installs these once;
# without this, edits to the bridge/firewall/cgroup setup never reach an already-
# provisioned box — it keeps running the old /usr/local/bin copies, so a security-
# relevant change (e.g. the per-dockerfile-VM egress scoping, or the runtime-bridge
# link-local/metadata SSRF DROP) silently wouldn't take effect. Re-copied BEFORE the
# restart so the next ExecStartPre runs the current rules. (jkbase-bridge.sh is now a
# maintained standalone script — tools/setup-bridge.sh — carrying the full prod NAT +
# FORWARD rules, so it IS safe to re-sync here, unlike the old dev-only stub.)
echo "Re-syncing ExecStartPre helper scripts..."
sudo cp "$HOME/jkbase/tools/setup-bridge.sh" /usr/local/bin/jkbase-bridge.sh
sudo cp "$HOME/jkbase/tools/setup-build-cgroup.sh" /usr/local/bin/jkbase-build-cgroup.sh
sudo cp "$HOME/jkbase/tools/setup-runtime-cgroup.sh" /usr/local/bin/jkbase-runtime-cgroup.sh
sudo cp "$HOME/jkbase/tools/setup-build-net.sh" /usr/local/bin/jkbase-build-net.sh
sudo chmod +x /usr/local/bin/jkbase-bridge.sh /usr/local/bin/jkbase-build-cgroup.sh /usr/local/bin/jkbase-runtime-cgroup.sh /usr/local/bin/jkbase-build-net.sh

# Socket-activation units (zero-bounce Phase 2): refresh the two public-listener socket units +
# install the wiring drop-in (mirrors 10-drain.conf) so an already-provisioned box gets
# Requires=/After=/Sockets= without a full provision.sh re-run. NEVER `restart` an active socket —
# that drops the listen backlog and re-opens the gap; deploys touch only the service.
echo "Refreshing socket-activation units (Phase 2)..."
sudo cp "$HOME/jkbase/tools/units/jkbase-proxy-http.socket"  /etc/systemd/system/jkbase-proxy-http.socket
sudo cp "$HOME/jkbase/tools/units/jkbase-proxy-https.socket" /etc/systemd/system/jkbase-proxy-https.socket
sudo tee /etc/systemd/system/jkbase.service.d/20-sockets.conf > /dev/null << 'DROPIN'
[Unit]
# NO PartOf= — that would cycle the sockets on a service restart and re-open the gap. Requires=
# propagates stop only socket->service, never service->socket.
Requires=jkbase-proxy-http.socket jkbase-proxy-https.socket
After=jkbase-proxy-http.socket jkbase-proxy-https.socket
[Service]
Sockets=jkbase-proxy-http.socket
Sockets=jkbase-proxy-https.socket
DROPIN
# Lift the listen-backlog ceiling so the units' Backlog=4096 isn't silently clamped during the
# successor's cold-start no-acceptor window (adversarial MED-6).
echo 'net.core.somaxconn = 4096' | sudo tee /etc/sysctl.d/99-jkbase-somaxconn.conf > /dev/null
sudo sysctl -q -w net.core.somaxconn=4096 || true
sudo systemctl daemon-reload   # does NOT drop already-bound sockets
# enable (NOT --now): on the FIRST deploy of this code the old in-process server still holds
# :80/:443, so `start`ing the socket now would EADDRINUSE and (set -e) abort the deploy mid-flight.
# The service's Requires= pulls the sockets up during the restart's start job (after the stop frees
# the ports). FIRST deploy bounces once (old binary predates the sockets); every deploy after is
# gapless. A future socket port-edit also bounces once (must restart the socket).
sudo systemctl enable jkbase-proxy-http.socket jkbase-proxy-https.socket

# Re-scope ufw 80/443 to the public uplink on already-provisioned boxes. provision.sh only
# runs once, so an existing box keeps the broad `ufw allow 80/443` on EVERY interface (incl.
# jkbr0). JKRUNFW (re-synced above, evaluated before ufw) is the load-bearing control; this
# is defense in depth so the broad rule doesn't linger. Idempotent; skips if ufw is inactive.
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    DEPLOY_PUB_IFACE=$(ip route show default | awk '{print $5; exit}')
    if [ -n "$DEPLOY_PUB_IFACE" ]; then
        sudo ufw delete allow 80/tcp 2>/dev/null || true
        sudo ufw delete allow 443/tcp 2>/dev/null || true
        sudo ufw allow in on "$DEPLOY_PUB_IFACE" to any port 80 proto tcp >/dev/null || true
        sudo ufw allow in on "$DEPLOY_PUB_IFACE" to any port 443 proto tcp >/dev/null || true
    fi
fi

# ebtables is required when --build-proxy-any-port is active (the server's L2
# source-guard, ensure_source_guard, fails closed without it). provision.sh installs
# it on fresh boxes; guarantee it here too so deploying this branch to a box
# provisioned before that line can't self-brick at startup.
if ! command -v ebtables >/dev/null 2>&1; then
    echo "Installing ebtables (build source-guard dependency)..."
    sudo apt-get install -y -qq ebtables
fi

# VM re-adoption §8: mark this restart as an UPGRADE so the OUTGOING server leaves its tenant
# VMs running (in the jkbase-runtime cgroup) for the incoming server to re-adopt, instead of
# draining/hibernating them. The incoming server clears the flag once adoption completes; the
# trap removes it if THIS deploy dies before/at the restart, so a crashed deploy can't leave a
# stale flag that makes a later operator `stop` skip the drain. First deploy of this code still
# bounces once (the OLD server predates the flag check); upgrades after that are zero-bounce.
# (Older than 300s ⇒ the server ignores it anyway — belt to the trap's suspenders.)
trap 'sudo rm -f /var/jkbase/.upgrading 2>/dev/null || true' EXIT
{ date +%s; echo "$$"; } | sudo tee /var/jkbase/.upgrading >/dev/null

echo "Restarting service..."
sudo systemctl restart jkbase

sleep 3
sudo systemctl status jkbase --no-pager | head -10

echo ""
echo "Waiting for API..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:9090/health > /dev/null 2>&1; then
        echo "API ready."
        break
    fi
    sleep 1
done

# Deploy www and console if credentials exist
if [ -f "$HOME/.jkbase/credentials" ]; then
    CLI="$HOME/jkbase/target/release/jkbase"

    # Ensure projects exist (ignore conflict errors)
    $CLI project create www --api http://127.0.0.1:9090 2>/dev/null || true
    $CLI project create console --api http://127.0.0.1:9090 2>/dev/null || true

    if [ -d "$HOME/jkbase/sites/www" ]; then
        echo "Deploying www..."
        cd "$HOME/jkbase/sites/www"
        $CLI deploy --api http://127.0.0.1:9090
    fi

    if [ -d "$HOME/jkbase/sites/console" ]; then
        echo "Deploying console..."
        cd "$HOME/jkbase/sites/console"
        $CLI deploy --api http://127.0.0.1:9090
    fi
else
    echo "No credentials found — skipping site deploys."
    echo "Run 'jkbase init <email> --api http://127.0.0.1:9090' first."
fi

echo ""
echo "Deploy complete."
REMOTE
