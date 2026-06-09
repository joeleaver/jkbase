#!/usr/bin/env bash
# Build the jkbase Firecracker guest kernel (WS0).
#
# The dev kernel was 4.14, which predates erofs/fs-verity entirely. The B2
# layered runtime needs erofs + overlayfs + fs-verity (composefs's overlayfs
# fs-verity validation landed in 6.6), so we move to a current LTS (6.12).
#
# Baseline = Firecracker's recommended microVM config (virtio/boot/ext4
# essentials) + tools/kernel.config.fragment (our erofs/verity adds), resolved
# with `make olddefconfig`. Produces an uncompressed `vmlinux` ELF, the format
# Firecracker boots (matches the existing .firecracker/vmlinux.bin).
#
# Pinned + reproducible: KVER and the FC baseline URL are fixed; override via env.
# Usage: tools/build-kernel.sh   (or KVER=6.12.92 OUT=/path tools/build-kernel.sh)
set -euo pipefail

KVER="${KVER:-6.12.92}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$REPO_ROOT/.firecracker/kernel-build}"
OUT="${OUT:-$REPO_ROOT/.firecracker/vmlinux-${KVER}.bin}"
FRAG="$REPO_ROOT/tools/kernel.config.fragment"
# sha256 of linux-${KVER}.tar.xz from cdn.kernel.org (pinned for KVER=6.12.92;
# override when bumping KVER). An unverified kernel source is a supply-chain hole.
KERNEL_SHA256="${KERNEL_SHA256:-0fe376b7db3cac4456b38291bee4faa7091cb8befaa6f9870314f5d1282f9e3e}"
# Firecracker's recommended microVM config (6.1 is the newest they publish;
# olddefconfig resolves the delta against the 6.12 source). Pinned to the FC
# release tag we run (not `main`) so the baseline can't drift under us.
FC_CONFIG_URL="${FC_CONFIG_URL:-https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.15.1/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config}"

echo "[build-kernel] KVER=$KVER WORK=$WORK OUT=$OUT"
mkdir -p "$WORK"
cd "$WORK"

tarball="linux-${KVER}.tar.xz"
if [ ! -f "$tarball" ]; then
    echo "[build-kernel] downloading $tarball"
    curl -fSL -o "$tarball" "https://cdn.kernel.org/pub/linux/kernel/v6.x/${tarball}"
fi
# Verify the source tarball (pinned sha; skip only if explicitly cleared).
if [ -n "$KERNEL_SHA256" ]; then
    echo "${KERNEL_SHA256}  ${tarball}" | sha256sum -c - || {
        echo "[build-kernel] ERROR: $tarball sha256 mismatch (corrupt/tampered or KVER bumped without updating KERNEL_SHA256)" >&2
        exit 1
    }
fi
src="linux-${KVER}"
if [ ! -d "$src" ]; then
    echo "[build-kernel] extracting $tarball"
    tar xf "$tarball"
fi
cd "$src"

echo "[build-kernel] fetching Firecracker baseline config"
curl -fSL -o .config "$FC_CONFIG_URL"
echo "[build-kernel] merging $FRAG"
cat "$FRAG" >>.config
make olddefconfig

# Fail loudly if any must-have capability didn't make it into the resolved config.
missing=0
for sym in CONFIG_EROFS_FS CONFIG_OVERLAY_FS CONFIG_FS_VERITY CONFIG_DM_VERITY \
    CONFIG_SQUASHFS CONFIG_VIRTIO_BLK CONFIG_EXT4_FS CONFIG_USER_NS CONFIG_FUSE_FS; do
    if ! grep -q "^${sym}=y" .config; then
        echo "[build-kernel] ERROR: ${sym}=y missing after olddefconfig" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 1

echo "[build-kernel] compiling vmlinux (-j$(nproc))"
make -j"$(nproc)" vmlinux

# Atomic publish: write a temp then rename, so an interrupted/short copy never
# leaves a truncated-but-present vmlinux that a freshness check would trust.
cp -f vmlinux "$OUT.tmp"
mv -f "$OUT.tmp" "$OUT"
echo "[build-kernel] done: $OUT ($(du -h "$OUT" | cut -f1)), linux $KVER"
echo "[build-kernel] to adopt: replace .firecracker/vmlinux.bin after the boot/snapshot revalidation gauntlet (WS0)."
