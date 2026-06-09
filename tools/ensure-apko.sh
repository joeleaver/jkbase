#!/usr/bin/env bash
# Ensure apko is installed (to ~/.local/bin) — the ONLY image tool the runtime
# rootfs build (tools/build-runtime-rootfs.sh) needs. Unlike tools/install-image-
# tools.sh, this pulls JUST apko: a static binary shipped as a .tar.gz, so it needs
# only curl + tar (no `unzip`, no bun download). That matters on a minimal host —
# install-image-tools.sh aborts on a box without `unzip` because it also fetches the
# bun zip, which a server that only needs to build the runtime rootfs shouldn't pull.
#
# Idempotent: a no-op once apko is on PATH. Override the version via APKO_VER.
set -euo pipefail

APKO_VER="${APKO_VER:-1.2.16}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
export PATH="$BIN_DIR:$PATH"

if command -v apko >/dev/null 2>&1; then
    echo "[ensure-apko] apko already present ($(command -v apko))"
    exit 0
fi

mkdir -p "$BIN_DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "[ensure-apko] installing apko $APKO_VER -> $BIN_DIR"
curl -fSL -o "$tmp/apko.tgz" \
    "https://github.com/chainguard-dev/apko/releases/download/v${APKO_VER}/apko_${APKO_VER}_linux_amd64.tar.gz"
tar -xzf "$tmp/apko.tgz" -C "$tmp"
# Chainguard tarballs name the binary `apko_${ver}_linux_amd64`; fall back to `apko`.
found="$(find "$tmp" -type f -name 'apko*linux_amd64' ! -name '*.tar.gz' | head -1)"
[ -n "$found" ] || found="$(find "$tmp" -type f -name apko | head -1)"
[ -n "$found" ] || { echo "[ensure-apko] apko binary not found in tarball" >&2; exit 1; }
install -m755 "$found" "$BIN_DIR/apko"
echo "[ensure-apko] $("$BIN_DIR/apko" version 2>/dev/null | head -1 || echo 'apko installed')"
