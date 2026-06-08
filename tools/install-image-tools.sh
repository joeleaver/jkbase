#!/usr/bin/env bash
# Install the pinned image-build tooling for WS2 (apko) + stage the baked Bun
# binary. No Go required — apko/melange ship prebuilt static linux/amd64 binaries.
# Run once on a build/CI host with network egress to GitHub + bun.sh.
#
# Usage: tools/install-image-tools.sh   (override versions/paths via env)
set -euo pipefail

APKO_VER="${APKO_VER:-1.2.16}"
MELANGE_VER="${MELANGE_VER:-0.52.1}" # only needed if/when we package a jkbuild apk
BUN_VER="${BUN_VER:-1.1.45}"         # pinned; the BASELINE build (no AVX2) for CPU-template safety
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
ASSET_DIR="${ASSET_DIR:-$REPO_ROOT/.firecracker/assets}"

mkdir -p "$BIN_DIR" "$ASSET_DIR"

fetch_tool() { # name version url-template
    local name="$1" ver="$2" url="$3"
    if command -v "$name" >/dev/null 2>&1; then
        echo "[install] $name already on PATH ($(command -v "$name"))"
        return
    fi
    echo "[install] $name $ver -> $BIN_DIR"
    local tgz
    tgz="$(mktemp -d)/$name.tar.gz"
    curl -fSL -o "$tgz" "$url"
    tar -xzf "$tgz" -C "$(dirname "$tgz")"
    # chainguard tarballs contain the binary named like `${name}_${ver}_linux_amd64`.
    local found
    found="$(find "$(dirname "$tgz")" -type f -name "${name}*linux_amd64" ! -name '*.tar.gz' | head -1)"
    [ -n "$found" ] || found="$(find "$(dirname "$tgz")" -type f -name "$name" | head -1)"
    install -m755 "$found" "$BIN_DIR/$name"
    echo "[install] $("$BIN_DIR/$name" version 2>/dev/null | head -1 || echo "$name installed")"
}

fetch_tool apko "$APKO_VER" \
    "https://github.com/chainguard-dev/apko/releases/download/v${APKO_VER}/apko_${APKO_VER}_linux_amd64.tar.gz"

# melange is optional for v1 (we inject bun + jkbuild-init in build-image.sh
# rather than packaging an apk). Install it only when MELANGE=1.
if [ "${MELANGE:-0}" = "1" ]; then
    fetch_tool melange "$MELANGE_VER" \
        "https://github.com/chainguard-dev/melange/releases/download/v${MELANGE_VER}/melange_${MELANGE_VER}_linux_amd64.tar.gz"
fi

# Baked Bun binary (baseline = no-AVX2, safe across the Firecracker CPU templates).
bun_zip="$(mktemp -d)/bun.zip"
echo "[install] bun $BUN_VER (baseline) -> $ASSET_DIR/bun"
curl -fSL -o "$bun_zip" \
    "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VER}/bun-linux-x64-baseline.zip"
if [ -n "${BUN_SHA256:-}" ]; then
    echo "${BUN_SHA256}  $bun_zip" | sha256sum -c - || {
        echo "[install] bun sha256 mismatch" >&2
        exit 1
    }
fi
unzip -o -j "$bun_zip" -d "$ASSET_DIR" '*/bun' >/dev/null
chmod 0755 "$ASSET_DIR/bun"
echo "[install] bun staged: $("$ASSET_DIR/bun" --version 2>/dev/null || echo '(version check needs glibc match)')"

# Host layer tooling for tools/build-base-layer.sh (WS4): mkfs.erofs packs the
# shared base/runtime erofs layers; fsverity is best-effort defense-in-depth on
# the host blobs. These are OS packages, not Chainguard tarballs.
if ! command -v mkfs.erofs >/dev/null 2>&1 || ! command -v fsverity >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        echo "[install] erofs-utils + fsverity (host layer tooling) via apt"
        sudo apt-get install -y -q erofs-utils fsverity || \
            echo "[install] WARNING: could not install erofs-utils/fsverity; build-base-layer.sh needs mkfs.erofs" >&2
    else
        echo "[install] NOTE: install erofs-utils (mkfs.erofs) + fsverity for tools/build-base-layer.sh" >&2
    fi
fi

echo "[install] done. apko=$BIN_DIR/apko bun=$ASSET_DIR/bun mkfs.erofs=$(command -v mkfs.erofs || echo MISSING)"
echo "[install] ensure $BIN_DIR is on PATH, then run tools/build-image.sh + tools/build-base-layer.sh"
