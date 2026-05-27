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

ssh "$TARGET" 'bash -s' << 'REMOTE'
set -euo pipefail
source "$HOME/.cargo/env"

cd "$HOME/jkbase"

echo "Pulling latest..."
git pull --ff-only

echo "Building jkbase-server + CLI..."
cargo build --release -p jkbase-server -p jkbase-cli 2>&1 | tail -3

echo "Building jkbase-agent (musl)..."
cargo build --release -p jkbase-agent --target x86_64-unknown-linux-musl 2>&1 | tail -3

# Delete base rootfs so it gets rebuilt with the new agent on next start
sudo rm -f /var/jkbase/base-rootfs.ext4

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
