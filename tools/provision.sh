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
    jq \
    iptables \
    busybox-static \
    e2fsprogs \
    flex bison libelf-dev bc libncurses-dev \
    unzip file python3 \
    erofs-utils fsverity

echo "[2b/7] Installing Docker..."
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$(whoami)"
    echo "Docker installed: $(docker --version)"
else
    echo "Docker already installed: $(docker --version)"
fi

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
if ! grep -q "jkbase" /etc/security/limits.d/jkbase.conf 2>/dev/null; then
    echo "* soft nofile 65536" | sudo tee /etc/security/limits.d/jkbase.conf
    echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.d/jkbase.conf
fi

echo "System setup complete."
REMOTE_SETUP

# Phase 2: Firecracker + the guest kernel are set up in Phase 3, AFTER the clone,
# so they reuse the maintained in-repo tooling (tools/fetch-firecracker.sh +
# tools/build-kernel.sh) — one source of truth shared with local dev (tools/dev).
# (The old inline Phase 2 downloaded a 6.1 kernel that CANNOT mount erofs, so the
# B2 layered runtime never worked from a fresh provision; the 6.12 kernel had to
# be placed by hand. Phase 3 now builds the correct 6.12 kernel.)

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

echo "Building jkbuild-init (musl, build-VM PID1)..."
cargo build --release -p jkbuild --bin jkbuild-init --target x86_64-unknown-linux-musl 2>&1 | tail -3

# Firecracker release — shared fetch+verify with local dev (one source of truth).
echo "Fetching Firecracker (shared tools/fetch-firecracker.sh)..."
FC_DIR="$HOME/.firecracker" tools/fetch-firecracker.sh

# Guest kernel: build the 6.12 erofs/overlay/verity kernel the B2 layered runtime
# REQUIRES (the old 6.1 download could not mount erofs). Idempotent: skips if the
# built kernel already has the must-have config symbols. ~10-15 min on first run.
KOUT="$HOME/.firecracker/vmlinux-6.12.92.bin"
KCFG="$HOME/.firecracker/kernel-build/linux-6.12.92/.config"
need_kernel=1
if [ -f "$KOUT" ] && [ -f "$KCFG" ] && \
   grep -q "^CONFIG_EROFS_FS=y" "$KCFG" && grep -q "^CONFIG_OVERLAY_FS=y" "$KCFG"; then
    need_kernel=0
fi
if [ "$need_kernel" = 1 ]; then
    echo "Building the 6.12 guest kernel (erofs/overlay/verity; ~10-15 min)..."
    OUT="$KOUT" tools/build-kernel.sh 2>&1 | tail -5
fi
# Adopt it as vmlinux.bin (the name the server + tests resolve).
ln -sfn "vmlinux-6.12.92.bin" "$HOME/.firecracker/vmlinux.bin"

echo "Build complete."
ls -lh target/release/jkbase-server target/release/jkbase \
    target/x86_64-unknown-linux-musl/release/jkbase-agent \
    target/x86_64-unknown-linux-musl/release/jkbuild-init \
    "$HOME/.firecracker/vmlinux.bin"
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

# Prebuild the runtime VM rootfs (apko Wolfi userland + chrony + the agent as
# /sbin/init) into the data dir. The server runs as root via systemd and can't
# reach the deploy user's apko, so it consumes this prebuilt artifact on first
# start. apko isn't a base-OS package; install it once if missing (idempotent).
export PATH="$HOME/.local/bin:$PATH"
command -v apko >/dev/null || "$JKBASE_DIR/tools/install-image-tools.sh"
echo "Building runtime rootfs (apko Wolfi + chrony + agent)..."
AGENT_BIN="$JKBASE_DIR/target/x86_64-unknown-linux-musl/release/jkbase-agent" \
    OUT=/var/jkbase/base-rootfs.ext4 "$JKBASE_DIR/tools/build-runtime-rootfs.sh"

# Create bridge setup script
sudo tee /usr/local/bin/jkbase-bridge.sh > /dev/null << 'BRIDGE'
#!/bin/bash
BRIDGE="jkbr0"
if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add name "$BRIDGE" type bridge
    ip addr add 172.16.0.1/24 dev "$BRIDGE"
    ip link set "$BRIDGE" up
fi

echo 1 > /proc/sys/net/ipv4/ip_forward

# NAT for VM internet access — detect the default route interface
PUB_IFACE=$(ip route show default | awk '{print $5; exit}')
if [ -n "$PUB_IFACE" ]; then
    if ! iptables -t nat -C POSTROUTING -s 172.16.0.0/24 -o "$PUB_IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -o "$PUB_IFACE" -j MASQUERADE
    fi
fi
BRIDGE
sudo chmod +x /usr/local/bin/jkbase-bridge.sh

# Build cgroup provisioner (ExecStartPre, per-boot). Build VMs run under the jailer
# in leaf cgroups beneath /sys/fs/cgroup/jkbase-build; that parent must exist with
# +cpu +memory +pids delegated or a hostile build's memory.max never applies and it
# can drive HOST OOM (threat model: all tenants untrusted). Install the maintained
# in-repo script (one source of truth, shared with local dev's `tools/dev net`).
sudo cp "$JKBASE_DIR/tools/setup-build-cgroup.sh" /usr/local/bin/jkbase-build-cgroup.sh
sudo chmod +x /usr/local/bin/jkbase-build-cgroup.sh

# Isolated build network provisioner (ExecStartPre, reboot-surviving). Creates the
# jkbuild0 bridge + JKBUILD firewall so build VMs can reach ONLY the egress proxy
# on the build gateway (default-deny; no internet, no other VMs, no NAT). Required
# because the server runs with --build-net (fail-closed: it refuses to start if the
# bridge/rules are missing). Install the maintained script verbatim. Note: this
# deliberately does NOT touch the global net.bridge.bridge-nf-call-iptables sysctl
# — the isolation rests on INPUT-allowlist (L3 local delivery) + FORWARD DROP +
# no-NAT + per-TAP bridge port-isolation + IPv6-disabled-on-bridge, none of which
# need bridge netfilter, so we avoid a system-wide change to the runtime bridge.
sudo cp "$JKBASE_DIR/tools/setup-build-net.sh" /usr/local/bin/jkbase-build-net.sh
sudo chmod +x /usr/local/bin/jkbase-build-net.sh

# Create .env file for secrets if it doesn't exist
if [ ! -f /var/jkbase/.env ]; then
    echo "# jkbase environment" | sudo tee /var/jkbase/.env > /dev/null
    echo "# CLOUDFLARE_API_TOKEN=" | sudo tee -a /var/jkbase/.env > /dev/null
    echo "# CLOUDFLARE_ZONE_ID=" | sudo tee -a /var/jkbase/.env > /dev/null
    echo "# ACME_EMAIL=" | sudo tee -a /var/jkbase/.env > /dev/null
fi

# Create systemd service with TLS
sudo tee /etc/systemd/system/jkbase.service > /dev/null << SERVICE
[Unit]
Description=jkbase platform server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
EnvironmentFile=/var/jkbase/.env
ExecStartPre=/usr/local/bin/jkbase-bridge.sh
ExecStartPre=/usr/local/bin/jkbase-build-cgroup.sh
ExecStartPre=/usr/local/bin/jkbase-build-net.sh
ExecStart=$JKBASE_DIR/target/release/jkbase-server \
    --data-dir /var/jkbase \
    --fc-dir $HOME/.firecracker \
    --agent-bin $JKBASE_DIR/target/x86_64-unknown-linux-musl/release/jkbase-agent \
    --api-port 9090 \
    --proxy-port 80 \
    --domain jkbase.app \
    --tls \
    --https-port 443 \
    --build-net
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
# Firecracker VMs are children in this unit's cgroup. With the default
# KillMode=control-group, "systemctl restart/stop" SIGTERMs every Firecracker
# process at the same instant as jkbase-server, so the orchestrator's graceful
# hibernate races a dying VM and fails with "failed to pause VM". KillMode=mixed
# sends SIGTERM to jkbase-server ONLY; it then pauses+snapshots and kills each
# VM itself before exiting. TimeoutStopSec gives that drain time before SIGKILL.
KillMode=mixed
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable jkbase

# Bake the default build-VM toolchain image if absent (busybox "passthrough", B1).
# select_toolchain reads <data-dir>/toolchains/ with precedence
# {language}.ext4 -> {kind}.ext4 -> default.ext4. Without it, any build with a
# server/function target fails "no toolchain image"; static-only sites are
# unaffected. Built with `mkfs.ext4 -d` (no mount/loop/root-fs-parse, P0-3-safe).
TOOLCHAIN=/var/jkbase/toolchains/default.ext4
if [ ! -f "$TOOLCHAIN" ]; then
    echo "Baking default build toolchain..."
    sudo BUSYBOX=/bin/busybox "$JKBASE_DIR/tools/build-toolchain.sh" "$TOOLCHAIN"
else
    echo "Build toolchain already present: $TOOLCHAIN"
fi

echo "Service installed. Start with: sudo systemctl start jkbase"
echo "Logs: sudo journalctl -u jkbase -f"
REMOTE_SERVICE

echo ""
echo "=== Provisioning complete ==="
echo ""
echo "Next steps:"
echo "  1. Set env vars in /var/jkbase/.env (CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID, ACME_EMAIL)"
echo "  2. Start the service:  ssh $TARGET 'sudo systemctl start jkbase'"
echo "  3. Init the platform:  jkbase init <email> --api http://<server-ip>:9090"
echo "  4. Point DNS:          *.jkbase.app → <server-ip>"
echo ""
