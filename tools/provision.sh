#!/bin/bash
#
# jkbase bare metal server provisioning script
#
# Usage: ./provision.sh <ssh-target>
# Example: ./provision.sh ubuntu@54.39.17.150
#
# Idempotent — safe to re-run for updates.
# Requires: the SSH target has passwordless sudo.
#

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <ssh-target>"
    echo "Example: $0 ubuntu@54.39.17.150"
    exit 1
fi

TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FC_VERSION="1.15.1"
FC_ARCH="x86_64"

echo "=== Provisioning jkbase on $TARGET ==="

# Phase 1: System hardening and dependencies
echo ""
echo "--- Phase 1: System setup ---"
ssh "$TARGET" 'bash -s' << 'REMOTE_SETUP'
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[1/7] Updating packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

echo "[2/7] Installing dependencies..."
sudo apt-get install -y -qq \
    build-essential \
    musl-tools \
    pkg-config \
    libssl-dev \
    git \
    curl \
    ufw \
    fail2ban \
    jq

echo "[3/7] Configuring firewall..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
echo "y" | sudo ufw enable || true
sudo ufw status

echo "[4/7] Hardening SSH..."
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl reload ssh

echo "[5/7] Setting up KVM access..."
sudo usermod -aG kvm "$(whoami)" || true
ls -la /dev/kvm

echo "[6/7] Installing Rust..."
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    echo "Rust already installed: $(rustc --version)"
fi
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-musl
rustup target add wasm32-wasip1

echo "[7/7] Configuring system limits..."
# Allow many open files for VM management
if ! grep -q "jkbase" /etc/security/limits.d/jkbase.conf 2>/dev/null; then
    echo "* soft nofile 65536" | sudo tee /etc/security/limits.d/jkbase.conf
    echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.d/jkbase.conf
fi

echo "System setup complete."
REMOTE_SETUP

# Phase 2: Firecracker
echo ""
echo "--- Phase 2: Firecracker ---"
ssh "$TARGET" "bash -s" << REMOTE_FC
set -euo pipefail

FC_DIR="\$HOME/.firecracker"
mkdir -p "\$FC_DIR"

if [ ! -f "\$FC_DIR/release-v${FC_VERSION}-${FC_ARCH}/firecracker-v${FC_VERSION}-${FC_ARCH}" ]; then
    echo "Downloading Firecracker v${FC_VERSION}..."
    cd "\$FC_DIR"
    curl -sLO "https://github.com/firecracker-microvm/firecracker/releases/download/v${FC_VERSION}/firecracker-v${FC_VERSION}-${FC_ARCH}.tgz"
    tar -xzf "firecracker-v${FC_VERSION}-${FC_ARCH}.tgz"
    rm -f "firecracker-v${FC_VERSION}-${FC_ARCH}.tgz"
    echo "Firecracker installed."
else
    echo "Firecracker v${FC_VERSION} already installed."
fi

if [ ! -f "\$FC_DIR/vmlinux.bin" ]; then
    echo "Downloading kernel image..."
    cd "\$FC_DIR"
    curl -sLO "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${FC_ARCH}/kernels/vmlinux.bin"
    echo "Kernel image downloaded."
else
    echo "Kernel image already present."
fi

echo "Firecracker setup complete."
REMOTE_FC

# Phase 3: Clone and build jkbase
echo ""
echo "--- Phase 3: Build jkbase ---"
ssh "$TARGET" 'bash -s' << 'REMOTE_BUILD'
set -euo pipefail
source "$HOME/.cargo/env"

JKBASE_DIR="$HOME/jkbase"

if [ -d "$JKBASE_DIR/.git" ]; then
    echo "Updating jkbase..."
    cd "$JKBASE_DIR"
    git pull --ff-only
else
    echo "Cloning jkbase..."
    git clone git@github.com:joeleaver/jkhost.git "$JKBASE_DIR"
    cd "$JKBASE_DIR"
fi

echo "Building jkbase-server..."
cargo build --release -p jkbase-server -p jkbase-cli 2>&1 | tail -3

echo "Building jkbase-agent (musl)..."
cargo build --release -p jkbase-agent --target x86_64-unknown-linux-musl 2>&1 | tail -3

echo "Build complete."
ls -lh target/release/jkbase-server target/release/jkbase target/x86_64-unknown-linux-musl/release/jkbase-agent
REMOTE_BUILD

# Phase 4: Setup systemd service and network
echo ""
echo "--- Phase 4: Service setup ---"
ssh "$TARGET" 'bash -s' << 'REMOTE_SERVICE'
set -euo pipefail

JKBASE_DIR="$HOME/jkbase"

# Create data directory
sudo mkdir -p /var/jkbase
sudo chown "$(whoami):$(whoami)" /var/jkbase

# Create bridge setup script
sudo tee /usr/local/bin/jkbase-bridge.sh > /dev/null << 'BRIDGE'
#!/bin/bash
BRIDGE="jkbr0"
if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add name "$BRIDGE" type bridge
    ip addr add 172.16.0.1/24 dev "$BRIDGE"
    ip link set "$BRIDGE" up
    echo 1 > /proc/sys/net/ipv4/ip_forward
fi
BRIDGE
sudo chmod +x /usr/local/bin/jkbase-bridge.sh

# Create systemd service
sudo tee /etc/systemd/system/jkbase.service > /dev/null << SERVICE
[Unit]
Description=jkbase platform server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStartPre=/usr/local/bin/jkbase-bridge.sh
ExecStart=$JKBASE_DIR/target/release/jkbase-server \
    --data-dir /var/jkbase \
    --fc-dir $HOME/.firecracker \
    --agent-bin $JKBASE_DIR/target/x86_64-unknown-linux-musl/release/jkbase-agent \
    --api-port 9090 \
    --proxy-port 80 \
    --domain jkbase.app
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable jkbase

echo "Service installed. Start with: sudo systemctl start jkbase"
echo "Logs: sudo journalctl -u jkbase -f"
REMOTE_SERVICE

echo ""
echo "=== Provisioning complete ==="
echo ""
echo "Next steps:"
echo "  1. Start the service:  ssh $TARGET 'sudo systemctl start jkbase'"
echo "  2. Init the platform:  jkbase init <email> --api http://<server-ip>:9090"
echo "  3. Point DNS:          *.jkbase.app → <server-ip>"
echo ""
