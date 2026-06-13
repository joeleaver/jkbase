#!/bin/bash
#
# Deploy updated jkbase to a provisioned server
#
# Usage: ./deploy-server.sh <ssh-target>
# Example: ./deploy-server.sh ubuntu@54.39.17.150
#
# Pulls latest code, rebuilds, restarts the service.
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
DROPIN
sudo systemctl daemon-reload

# Re-sync the ExecStartPre helpers from the repo. provision.sh installs these once;
# without this, edits to the bridge/firewall/cgroup setup never reach an already-
# provisioned box — it keeps running the old /usr/local/bin copies, so a security-
# relevant change (e.g. the per-dockerfile-VM egress scoping, or the runtime-bridge
# link-local/RFC1918 SSRF DROP) silently wouldn't take effect. Re-copied BEFORE the
# restart so the next ExecStartPre runs the current rules. (jkbase-bridge.sh is now a
# maintained standalone script — tools/setup-bridge.sh — carrying the full prod NAT +
# FORWARD rules, so it IS safe to re-sync here, unlike the old dev-only stub.)
echo "Re-syncing ExecStartPre helper scripts..."
sudo cp "$HOME/jkbase/tools/setup-bridge.sh" /usr/local/bin/jkbase-bridge.sh
sudo cp "$HOME/jkbase/tools/setup-build-cgroup.sh" /usr/local/bin/jkbase-build-cgroup.sh
sudo cp "$HOME/jkbase/tools/setup-build-net.sh" /usr/local/bin/jkbase-build-net.sh
sudo chmod +x /usr/local/bin/jkbase-bridge.sh /usr/local/bin/jkbase-build-cgroup.sh /usr/local/bin/jkbase-build-net.sh

# ebtables is required when --build-proxy-any-port is active (the server's L2
# source-guard, ensure_source_guard, fails closed without it). provision.sh installs
# it on fresh boxes; guarantee it here too so deploying this branch to a box
# provisioned before that line can't self-brick at startup.
if ! command -v ebtables >/dev/null 2>&1; then
    echo "Installing ebtables (build source-guard dependency)..."
    sudo apt-get install -y -qq ebtables
fi

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
