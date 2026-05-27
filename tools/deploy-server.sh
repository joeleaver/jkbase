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

echo "Building jkbase-server..."
cargo build --release -p jkbase-server -p jkbase-cli 2>&1 | tail -3

echo "Building jkbase-agent (musl)..."
cargo build --release -p jkbase-agent --target x86_64-unknown-linux-musl 2>&1 | tail -3

# Delete base rootfs so it gets rebuilt with the new agent on next start
sudo rm -f /var/jkbase/base-rootfs.ext4

echo "Restarting service..."
sudo systemctl restart jkbase

sleep 3
sudo systemctl status jkbase --no-pager | head -15

echo ""
echo "Deploy complete."
REMOTE
