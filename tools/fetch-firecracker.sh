#!/usr/bin/env bash
# Download + checksum-verify the pinned Firecracker release into the local
# .firecracker dir. Single source of truth shared by `tools/dev assets` (local)
# and `tools/provision.sh` (prod), so the FC version/verification logic lives in
# ONE place. No root.
#
# Usage: [FC_VERSION=1.15.1 FC_ARCH=x86_64 FC_DIR=~/.firecracker] tools/fetch-firecracker.sh
set -euo pipefail

FC_VERSION="${FC_VERSION:-1.15.1}"
FC_ARCH="${FC_ARCH:-x86_64}"
FC_DIR="${FC_DIR:-$(cd "$(dirname "$0")/.." && pwd)/.firecracker}"
RELEASE_DIR="$FC_DIR/release-v${FC_VERSION}-${FC_ARCH}"
FC_BIN="$RELEASE_DIR/firecracker-v${FC_VERSION}-${FC_ARCH}"

if [ -x "$FC_BIN" ]; then
    echo "[fetch-fc] Firecracker v$FC_VERSION already present ($FC_BIN)"
    exit 0
fi

mkdir -p "$FC_DIR"
cd "$FC_DIR"
tgz="firecracker-v${FC_VERSION}-${FC_ARCH}.tgz"
echo "[fetch-fc] downloading $tgz"
curl -fSL -o "$tgz" \
    "https://github.com/firecracker-microvm/firecracker/releases/download/v${FC_VERSION}/${tgz}"
echo "[fetch-fc] extracting"
tar -xzf "$tgz"
rm -f "$tgz"

# Verify the extracted binaries against the SHA256SUMS the release ships (it
# lists ./-relative paths, so verify from inside the release dir). This is the
# integrity check that was downloaded-but-unused before.
if [ -f "$RELEASE_DIR/SHA256SUMS" ]; then
    echo "[fetch-fc] verifying SHA256SUMS"
    ( cd "$RELEASE_DIR" && sha256sum -c --quiet SHA256SUMS ) || {
        echo "[fetch-fc] ERROR: Firecracker release checksum mismatch" >&2
        exit 1
    }
    echo "[fetch-fc] checksums OK"
else
    echo "[fetch-fc] WARNING: no SHA256SUMS in the release — skipping verification" >&2
fi

[ -x "$FC_BIN" ] || { echo "[fetch-fc] ERROR: $FC_BIN missing after extract" >&2; exit 1; }
echo "[fetch-fc] done: $RELEASE_DIR (firecracker + jailer v$FC_VERSION)"
