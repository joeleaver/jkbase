#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FC_DIR="$PROJECT_ROOT/.firecracker"
AGENT_BIN="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/jkbase-agent"
ROOTFS="$FC_DIR/jkbase-rootfs.ext4"
MOUNT_DIR=$(mktemp -d)
SIZE_MB=64

if [ ! -f "$AGENT_BIN" ]; then
    echo "Agent binary not found. Build with:"
    echo "  cargo build -p jkbase-agent --target x86_64-unknown-linux-musl --release"
    exit 1
fi

echo "Creating ${SIZE_MB}MB rootfs image..."
dd if=/dev/zero of="$ROOTFS" bs=1M count=$SIZE_MB status=none
mkfs.ext4 -F -q "$ROOTFS"

echo "Mounting and populating rootfs..."
mount -o loop "$ROOTFS" "$MOUNT_DIR"

mkdir -p "$MOUNT_DIR"/{bin,sbin,dev,proc,sys,tmp,srv/www,etc,run}

# The agent binary IS init — runs as PID 1
cp "$AGENT_BIN" "$MOUNT_DIR/sbin/init"
chmod +x "$MOUNT_DIR/sbin/init"

# Sample static site
cat > "$MOUNT_DIR/srv/www/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>jkbase</title></head>
<body>
<h1>Hello from jkbase!</h1>
<p>Served from a Firecracker microVM.</p>
</body>
</html>
HTMLEOF

echo "jkbase-vm" > "$MOUNT_DIR/etc/hostname"

umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"

echo "Rootfs created at: $ROOTFS"
ls -lh "$ROOTFS"
