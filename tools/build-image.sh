#!/usr/bin/env bash
# Assemble a build-VM toolchain ext4 from an apko Wolfi image (WS2).
#
# apko gives us a reproducible glibc rootfs (an OCI/docker-archive tar). We then
# inject the bits apko can't: the static musl jkbuild-init as /sbin/init (the
# in-VM lifecycle), the baked bun binary, busybox applet symlinks the lifecycle
# shells out to, and the mountpoint dirs (the root boots read-only, so they must
# pre-exist). Finally mkfs.ext4 -d into the image — userspace, no mount (P0-3),
# matching tools/build-toolchain.sh / build_image.rs.
#
# Usage: tools/build-image.sh [--config images/apko/build-bun.apko.yaml] [--out PATH]
#
# INJECT_BUN=1 (default) bakes the bun binary at /opt/bun/bin/bun (bun toolchain).
# Set INJECT_BUN=0 for toolchains that carry their own runtime — e.g. the dockerfile
# escape-hatch image, whose buildah-built image IS the runtime:
#   INJECT_BUN=0 CONFIG=images/apko/build-dockerfile.apko.yaml \
#     OUT=.firecracker/toolchains/dockerfile.ext4 tools/build-image.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${CONFIG:-$REPO_ROOT/images/apko/build-bun.apko.yaml}"
OUT="${OUT:-$REPO_ROOT/.firecracker/toolchains/bun.ext4}"
WORK="${WORK:-$REPO_ROOT/.firecracker/work/image-$(basename "${OUT%.ext4}")}"
BUN_BIN="${BUN_BIN:-$REPO_ROOT/.firecracker/assets/bun}"
INIT_BIN="${INIT_BIN:-$REPO_ROOT/target/x86_64-unknown-linux-musl/release/jkbuild-init}"
INJECT_BUN="${INJECT_BUN:-1}"
export PATH="$HOME/.local/bin:$PATH"

command -v apko >/dev/null || {
    echo "apko not found — run tools/install-image-tools.sh" >&2
    exit 1
}
if [ "$INJECT_BUN" = "1" ] && [ ! -f "$BUN_BIN" ]; then
    echo "bun binary missing at $BUN_BIN — run tools/install-image-tools.sh" >&2
    exit 1
fi
if [ ! -f "$INIT_BIN" ]; then
    echo "[build-image] building jkbuild-init (musl-static)"
    (cd "$REPO_ROOT" && cargo build -p jkbuild --bin jkbuild-init \
        --target x86_64-unknown-linux-musl --release)
fi

rm -rf "$WORK"
mkdir -p "$WORK/stage"
STAGE="$WORK/stage"

echo "[build-image] apko build $CONFIG"
apko build "$CONFIG" jkbase-toolchain:latest "$WORK/oci.tar" --arch x86_64 >/dev/null

echo "[build-image] extracting rootfs layers"
# docker-archive: manifest.json lists ordered layer tarballs; apply in order.
layers="$(tar xf "$WORK/oci.tar" -O manifest.json | python3 -c \
    'import json,sys; print("\n".join(json.load(sys.stdin)[0]["Layers"]))')"
[ -n "$layers" ] || {
    echo "no layers in apko manifest" >&2
    exit 1
}
for layer in $layers; do
    # Skip device nodes (mknod needs root; jkbuild-init mounts devtmpfs at boot)
    # and skip same-owner so non-root extraction doesn't fail on chown.
    tar xf "$WORK/oci.tar" -O "$layer" |
        tar xz -C "$STAGE" --no-same-owner --exclude='dev/*' --exclude='./dev/*'
done

echo "[build-image] injecting jkbuild-init, mountpoints, busybox applets$([ "$INJECT_BUN" = "1" ] && echo ", bun")"
install -Dm0755 "$INIT_BIN" "$STAGE/sbin/init"
if [ "$INJECT_BUN" = "1" ]; then
    install -Dm0755 "$BUN_BIN" "$STAGE/opt/bun/bin/bun"
fi
# The RO root can't mkdir at boot — pre-create everything the lifecycle mounts.
mkdir -p "$STAGE"/{scratch,src,out,cache,newroot,work,proc,sys,dev,tmp,run,var,bin,sbin}
# Ensure the applets jkbuild-init shells out to resolve to busybox.
bb=""
for cand in usr/bin/busybox bin/busybox usr/sbin/busybox; do
    [ -x "$STAGE/$cand" ] && bb="/$cand" && break
done
if [ -n "$bb" ]; then
    for applet in sh mount umount cp nc reboot sync mkdir cat sed; do
        if [ ! -e "$STAGE/bin/$applet" ]; then ln -sf "$bb" "$STAGE/bin/$applet"; fi
    done
else
    echo "[build-image] WARN: busybox not found in image; lifecycle shell-outs may fail" >&2
fi

echo "[build-image] mkfs.ext4 -d (no mount)"
# Wolfi ships /etc/shadow et al. mode 0000; rootless `mkfs.ext4 -d` can't read
# them. Grant owner read so the userspace populate succeeds — runtime perms are
# irrelevant for a platform-built build toolchain (the guest runs as root).
chmod -R u+rwX "$STAGE"
content_kib="$(du -sk "$STAGE" | cut -f1)"
size_kib=$((content_kib + content_kib / 2 + 65536)) # +50% metadata slack +64MiB headroom
rm -f "$OUT"
mkdir -p "$(dirname "$OUT")"
truncate -s "${size_kib}K" "$OUT"
mkfs.ext4 -F -q -O ^has_journal -d "$STAGE" "$OUT"
chmod 0444 "$OUT"
echo "[build-image] done: $OUT ($(du -h "$OUT" | cut -f1)); init=/sbin/init=jkbuild-init$([ "$INJECT_BUN" = "1" ] && echo ", /opt/bun/bin/bun present")"
