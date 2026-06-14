#!/usr/bin/env bash
# Generate (idempotently) the shared cross-tenant build-mirror CA.
#
# Produces <dir>/ca.key (host-only secret, 0600) + <dir>/ca.crt (public, 0644). The
# CA cert is baked into the build toolchains' trust store (pass BUILD_CA_CERT=<dir>/ca.crt
# to tools/build-image.sh for the bun/node/rust toolchains); the CA KEY is distributed
# host-only to each mirror host's {data_dir}/build-ca/ca.key (like the bun asset /
# baselayers) and NEVER enters any image. One shared CA across dev+prod keeps
# build-on-dev-and-scp working: dev-baked toolchains trust prod's mirror.
#
# This is a thin wrapper over `jkbase-server gen-build-ca`, so the exact same rcgen
# code path generates the CA the server later signs leaves with.
#
# Usage: tools/gen-build-ca.sh [<dir>]   (default: .firecracker/build-ca)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:-$REPO_ROOT/.firecracker/build-ca}"
BIN="${BIN:-$REPO_ROOT/target/release/jkbase-server}"

if [ ! -x "$BIN" ]; then
    echo "[gen-build-ca] building jkbase-server (release)"
    (cd "$REPO_ROOT" && cargo build -p jkbase-server --release --bin jkbase-server)
fi

mkdir -p "$DIR"
"$BIN" gen-build-ca "$DIR"

echo "[gen-build-ca] CA ready in $DIR"
echo "  - bake toolchains:  BUILD_CA_CERT=$DIR/ca.crt INJECT_BUN=... CONFIG=images/apko/build-<lang>.apko.yaml OUT=... tools/build-image.sh"
echo "  - distribute KEY:   scp $DIR/ca.key <host>:{data_dir}/build-ca/ca.key   (0600, host-only — never into an image)"
