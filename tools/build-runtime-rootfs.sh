#!/usr/bin/env bash
# Assemble the runtime VM rootfs: an apko Wolfi (glibc) userland + chrony, with the
# jkbase-agent (static musl) injected as /sbin/init (PID 1). chrony lets the agent
# discipline the guest wall clock from the KVM PTP device (refclock PHC /dev/ptp0) —
# the canonical Firecracker time-sync path. This replaces the old single-static-
# binary rootfs, which had no userland and so could not run a time daemon.
#
# Userspace, no mount (mkfs.ext4 -d), no sudo. Mirrors tools/build-image.sh.
#
# Usage:
#   AGENT_BIN=target/x86_64-unknown-linux-musl/release/jkbase-agent \
#     OUT=.firecracker/base-rootfs.ext4 tools/build-runtime-rootfs.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${CONFIG:-$REPO_ROOT/images/apko/run-agent.apko.yaml}"
CHRONY_CONF="${CHRONY_CONF:-$REPO_ROOT/images/apko/chrony.conf}"
OUT="${OUT:-$REPO_ROOT/.firecracker/base-rootfs.ext4}"
AGENT_BIN="${AGENT_BIN:-$REPO_ROOT/target/x86_64-unknown-linux-musl/release/jkbase-agent}"
WORK="${WORK:-$REPO_ROOT/.firecracker/work/runtime-rootfs}"
export PATH="$HOME/.local/bin:$PATH"

command -v apko >/dev/null || {
    echo "apko not found — run tools/install-image-tools.sh" >&2
    exit 1
}
if [ ! -f "$AGENT_BIN" ]; then
    echo "agent binary missing at $AGENT_BIN" >&2
    echo "  build it: cargo build --release -p jkbase-agent --target x86_64-unknown-linux-musl" >&2
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/stage"
STAGE="$WORK/stage"

echo "[runtime-rootfs] apko build $CONFIG"
# Use the committed lockfile when present so the package set is reproducible
# (the Wolfi repo is rolling). Regenerate with:
#   apko lock "$CONFIG" --arch x86_64 --output "${CONFIG%.yaml}.lock.json"
LOCK="${CONFIG%.yaml}.lock.json"
lock_arg=()
[ -f "$LOCK" ] && lock_arg=(--lockfile "$LOCK")
apko build "$CONFIG" jkbase-runtime:latest "$WORK/oci.tar" --arch x86_64 "${lock_arg[@]}" >/dev/null

echo "[runtime-rootfs] extracting rootfs layers"
layers="$(tar xf "$WORK/oci.tar" -O manifest.json | python3 -c \
    'import json,sys; print("\n".join(json.load(sys.stdin)[0]["Layers"]))')"
[ -n "$layers" ] || {
    echo "no layers in apko manifest" >&2
    exit 1
}
for layer in $layers; do
    # Skip device nodes (mknod needs root; the agent mounts devtmpfs at boot) and
    # skip same-owner so non-root extraction doesn't fail on chown.
    tar xf "$WORK/oci.tar" -O "$layer" |
        tar xz -C "$STAGE" --no-same-owner --exclude='dev/*' --exclude='./dev/*'
done

echo "[runtime-rootfs] injecting jkbase-agent (/sbin/init), chrony.conf, mountpoints"
install -Dm0755 "$AGENT_BIN" "$STAGE/sbin/init"
install -Dm0644 "$CHRONY_CONF" "$STAGE/etc/chrony.conf"
# The RO root can't mkdir at boot — pre-create everything the agent mounts/serves.
# (/run/chrony is created by the agent at 0750 once /run tmpfs is mounted.)
mkdir -p "$STAGE"/{proc,sys,dev,tmp,run,srv/www,mnt/data,etc}

echo "[runtime-rootfs] mkfs.ext4 -d (no mount)"
# Wolfi ships /etc/shadow et al. mode 0000; rootless mkfs.ext4 -d can't read them.
# Grant owner read so the userspace populate succeeds (runtime perms are irrelevant
# — the guest agent runs as root).
chmod -R u+rwX "$STAGE"
content_kib="$(du -sk "$STAGE" | cut -f1)"
size_kib=$((content_kib + content_kib / 2 + 32768)) # +50% metadata slack +32MiB headroom
rm -f "$OUT"
mkdir -p "$(dirname "$OUT")"
truncate -s "${size_kib}K" "$OUT"
mkfs.ext4 -F -q -O ^has_journal -d "$STAGE" "$OUT"
echo "[runtime-rootfs] done: $OUT ($(du -h "$OUT" | cut -f1)); init=/sbin/init=jkbase-agent, chrony present"
