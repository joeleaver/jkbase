#!/bin/bash
# Bake a minimal build-VM *toolchain* image: a busybox userland with
# tools/build-runner.sh as /sbin/init (PID 1). This is the B1 "passthrough"
# toolchain — it boots, runs the source's build.sh under the CoW overlay, and
# writes artifacts to the output drive. Richer toolchains (CNB for servers,
# cargo-component for functions) are B2 and reuse this same init contract.
#
# The image is built with `mkfs.ext4 -d` from a staging dir — NO mount, no loop
# device, no root (threat-model P0-3) — and made read-only/world-readable so it
# can be hard-linked into the jail and shared (page-cache-hot) across builds.
#
#   tools/build-toolchain.sh [OUT.ext4]
# Default OUT: .firecracker/toolchains/default.ext4
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUT="${1:-$PROJECT_ROOT/.firecracker/toolchains/default.ext4}"
BUSYBOX="${BUSYBOX:-/usr/bin/busybox}"
RUNNER="$SCRIPT_DIR/build-runner.sh"

if [ ! -x "$BUSYBOX" ]; then
    echo "static busybox not found at $BUSYBOX (set BUSYBOX=...)" >&2
    exit 1
fi
if ! file "$BUSYBOX" | grep -q "statically linked"; then
    echo "WARNING: $BUSYBOX is not statically linked; the guest has no libc" >&2
fi
[ -f "$RUNNER" ] || { echo "missing $RUNNER" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# The toolchain root boots READ-ONLY (the build-runner overlays a writable
# scratch on top). All mount points the runner uses must therefore already
# exist in the image — it cannot mkdir them on the RO root.
mkdir -p "$STAGE"/{bin,sbin,proc,sys,dev,tmp,etc}
mkdir -p "$STAGE"/{scratch,src,out,cache,newroot,work}
cp "$BUSYBOX" "$STAGE/bin/busybox"
chmod 0755 "$STAGE/bin/busybox"

# Applet symlinks the build-runner + a typical build.sh need.
for app in sh ash mount umount mkdir rmdir chroot pivot_root switch_root sync \
           reboot poweroff halt echo cat sleep ls cp mv rm ln test true false \
           env dirname basename printf grep sed awk tar gzip gunzip find xargs \
           chmod chown id head tail wc touch mktemp \
           nc wget ping ip route ifconfig; do
    ln -sf busybox "$STAGE/bin/$app"
done

cp "$RUNNER" "$STAGE/sbin/init"
chmod 0755 "$STAGE/sbin/init"
echo "jkbase-build" > "$STAGE/etc/hostname"

# Size = content + 50% ext4 metadata slack + 8 MiB headroom.
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"   # a prior image is 0444; truncate would fail to reopen it
KIB="$(du -sk "$STAGE" | cut -f1)"
SIZE_KIB=$(( KIB + KIB / 2 + 8192 ))
truncate -s "${SIZE_KIB}K" "$OUT"
mkfs.ext4 -F -q -O ^has_journal -d "$STAGE" "$OUT"
chmod 0444 "$OUT"

echo "toolchain image: $OUT"
ls -lh "$OUT"
