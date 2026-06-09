#!/usr/bin/env bash
# Build the shared, content-addressed runtime LAYERS for the layered runtime (WS2/WS4):
#   - base       : minimal Wolfi glibc rootfs from images/apko/run-base.apko.yaml,
#                  shared by every app/language (Bun's binary is NOT here).
#   - bun runtime: just /opt/bun/bin/bun, shared across all apps on a given Bun
#                  version (so a Bun bump never re-ships per deploy — dedup holds).
#
# Each layer becomes a content-addressed erofs blob `sha256-<hex>.erofs` in the
# host layer store, matching the in-VM app-layer exporter (mkfs.erofs -zlz4hc).
# fs-verity is enabled best-effort (defense-in-depth); the load-bearing integrity
# is the recorded sha256, which the host re-verifies before attaching a blob to a
# tenant VM. A `platform.json` records the current base + per-language runtime
# digests so the host can inject them ahead of the per-deploy app layer.
#
# Host tooling (NOT in the VM): apko + erofs-utils (mkfs.erofs) + fsverity-utils.
#   tools/install-image-tools.sh installs them.
#
# Usage: tools/build-base-layer.sh   (override via env: STORE, BASE_CONFIG, BUN_BIN, BUN_VER)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_CONFIG="${BASE_CONFIG:-$REPO_ROOT/images/apko/run-base.apko.yaml}"
NODE_CONFIG="${NODE_CONFIG:-$REPO_ROOT/images/apko/run-node.apko.yaml}"
RUST_CONFIG="${RUST_CONFIG:-$REPO_ROOT/images/apko/run-rust.apko.yaml}"
STORE="${STORE:-$REPO_ROOT/.firecracker/baselayers}"
BUN_BIN="${BUN_BIN:-$REPO_ROOT/.firecracker/assets/bun}"
BUN_VER="${BUN_VER:-1.3.14}"
WORK="${WORK:-$REPO_ROOT/.firecracker/work/base-layer}"
export PATH="$HOME/.local/bin:$PATH"

command -v apko >/dev/null || { echo "apko not found — run tools/install-image-tools.sh" >&2; exit 1; }
command -v mkfs.erofs >/dev/null || { echo "mkfs.erofs not found — apt-get install erofs-utils" >&2; exit 1; }
command -v rsync >/dev/null || { echo "rsync not found — apt-get install rsync (runtime-layer delta)" >&2; exit 1; }
[ -f "$BUN_BIN" ] || { echo "bun binary missing at $BUN_BIN — run tools/install-image-tools.sh" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK" "$STORE"

# pack <stage_dir> <name> -> sets globals PACK_DIGEST PACK_FILE PACK_SIZE PACK_VERITY
pack_layer() {
    local stage="$1" name="$2"
    local tmp="$WORK/$name.erofs"
    # -zlz4hc matches crates/jkbuild/src/export.rs::pack_layer_erofs; --all-root
    # normalizes ownership; -T 0 (mtimes pinned) + --mkfs-time for a reproducible,
    # content-stable blob. Run as root: the trusted base preserves Wolfi's intended
    # perms (some dirs are non-readable to a non-owner), which root can still read.
    sudo mkfs.erofs -zlz4hc --all-root -T 0 --mkfs-time "$tmp" "$stage" >/dev/null
    sudo chown "$(id -u):$(id -g)" "$tmp"
    local hex
    hex="$(sha256sum "$tmp" | cut -d' ' -f1)"
    PACK_DIGEST="sha256:$hex"
    PACK_FILE="sha256-$hex.erofs"
    PACK_SIZE="$(stat -c%s "$tmp")"
    install -Dm0444 "$tmp" "$STORE/$PACK_FILE"
    # fs-verity: defense-in-depth on the host blob; harmless if the store fs lacks
    # the verity feature — the sha256 digest is the actual integrity guarantee.
    if sudo fsverity enable "$STORE/$PACK_FILE" >/dev/null 2>&1; then
        PACK_VERITY=true
    else
        PACK_VERITY=false
    fi
    echo "[layer] $name -> $PACK_FILE ($PACK_SIZE bytes, fs-verity=$PACK_VERITY)"
}

# build_runtime_layer <apko_config> <layer_name> -> sets globals PACK_* via pack_layer.
# Builds the apko rootfs for a per-language runtime, DELTAs it against the shared
# base stage ($BASE_STAGE, set during the base build below) so only files NOT
# byte-identical to base survive (glibc &c. come from the base layer at overlay
# time, not re-shipped), and packs the delta as a content-addressed erofs blob.
build_runtime_layer() {
    local config="$1" name="$2"
    echo "[$name] apko build $config"
    local lock="${config%.yaml}.lock.json"
    local lock_arg=()
    [ -f "$lock" ] && lock_arg=(--lockfile "$lock")
    local oci="$WORK/$name-oci.tar"
    apko build "$config" "jkbase-$name:latest" "$oci" --arch x86_64 "${lock_arg[@]}" >/dev/null
    local full="$WORK/$name-full"
    rm -rf "$full"; mkdir -p "$full"
    local oci_layers
    oci_layers="$(tar xf "$oci" -O manifest.json |
        python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)[0]["Layers"]))')"
    for layer in $oci_layers; do
        tar xf "$oci" -O "$layer" |
            tar xz -C "$full" --no-same-owner --exclude='dev/*' --exclude='./dev/*'
    done
    # Delta against the shared base: rsync skips any file byte-identical to the one
    # under $BASE_STAGE, leaving only this runtime's additions (node + its libs; or
    # just libgcc_s.so.1 for rust). Keeps the base's glibc unduplicated.
    local delta="$WORK/$name-delta"
    rm -rf "$delta"; mkdir -p "$delta"
    rsync -a --compare-dest="$BASE_STAGE/" "$full/" "$delta/"
    # Prune the empty directory skeleton rsync leaves behind (the overlay gets dirs
    # from the base layer); the language files keep their parent dirs (non-empty).
    find "$delta" -type d -empty -delete 2>/dev/null || true
    mkdir -p "$delta" # find may have removed the now-empty root on a no-op delta
    pack_layer "$delta" "$name"
}

# --- base layer (apko run-base → Wolfi rootfs) ---
echo "[base] apko build $BASE_CONFIG"
# Reproducible package set via the committed lockfile when present (rolling Wolfi
# repo otherwise drifts the base-layer digest run to run). Regenerate with:
#   apko lock "$BASE_CONFIG" --arch x86_64 --output "${BASE_CONFIG%.yaml}.lock.json"
BASE_LOCK="${BASE_CONFIG%.yaml}.lock.json"
base_lock_arg=()
[ -f "$BASE_LOCK" ] && base_lock_arg=(--lockfile "$BASE_LOCK")
apko build "$BASE_CONFIG" jkbase-run-base:latest "$WORK/base-oci.tar" --arch x86_64 "${base_lock_arg[@]}" >/dev/null
BASE_STAGE="$WORK/base-stage"
mkdir -p "$BASE_STAGE"
# docker-archive: apply the ordered layer tarballs (skip device nodes — non-root).
base_layers="$(tar xf "$WORK/base-oci.tar" -O manifest.json |
    python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)[0]["Layers"]))')"
for layer in $base_layers; do
    tar xf "$WORK/base-oci.tar" -O "$layer" |
        tar xz -C "$BASE_STAGE" --no-same-owner --exclude='dev/*' --exclude='./dev/*'
done
# Mountpoints the layered runtime composes/pivots into (overlay needs the dirs to
# exist in some layer; the base is the right home for the FHS skeleton + /app + /opt).
mkdir -p "$BASE_STAGE"/{proc,sys,dev,tmp,run,var,etc,app,opt}
pack_layer "$BASE_STAGE" "wolfi-base"
BASE_DIGEST="$PACK_DIGEST"; BASE_FILE="$PACK_FILE"; BASE_SIZE="$PACK_SIZE"; BASE_VERITY="$PACK_VERITY"

# --- bun runtime layer (just the bun binary) ---
echo "[bun] staging /opt/bun/bin/bun (bun $BUN_VER)"
BUN_STAGE="$WORK/bun-stage"
install -Dm0755 "$BUN_BIN" "$BUN_STAGE/opt/bun/bin/bun"
pack_layer "$BUN_STAGE" "bun-$BUN_VER"
BUN_DIGEST="$PACK_DIGEST"; BUN_FILE="$PACK_FILE"; BUN_SIZE="$PACK_SIZE"; BUN_VERITY="$PACK_VERITY"

# --- node runtime layer (node binary + lib closure, delta'd against base) ---
build_runtime_layer "$NODE_CONFIG" "node"
NODE_DIGEST="$PACK_DIGEST"; NODE_FILE="$PACK_FILE"; NODE_SIZE="$PACK_SIZE"; NODE_VERITY="$PACK_VERITY"

# --- rust runtime layer (libgcc_s.so.1, delta'd against base) ---
build_runtime_layer "$RUST_CONFIG" "rust"
RUST_DIGEST="$PACK_DIGEST"; RUST_FILE="$PACK_FILE"; RUST_SIZE="$PACK_SIZE"; RUST_VERITY="$PACK_VERITY"

# --- platform manifest (host reads this to inject base + runtime ahead of the app) ---
# `runtimes` is keyed by the server manifest's stamped `runtime` (= the resolved
# build language: bun/node/rust); compute_layer_plan looks the language up here.
cat > "$STORE/platform.json" <<JSON
{
  "schema": 1,
  "base": {
    "name": "wolfi-base", "role": "base", "media": "erofs",
    "digest": "$BASE_DIGEST", "file": "$BASE_FILE", "size": $BASE_SIZE, "fs_verity": $BASE_VERITY
  },
  "runtimes": {
    "bun": {
      "name": "bun-$BUN_VER", "role": "runtime", "media": "erofs",
      "digest": "$BUN_DIGEST", "file": "$BUN_FILE", "size": $BUN_SIZE, "fs_verity": $BUN_VERITY
    },
    "node": {
      "name": "node", "role": "runtime", "media": "erofs",
      "digest": "$NODE_DIGEST", "file": "$NODE_FILE", "size": $NODE_SIZE, "fs_verity": $NODE_VERITY
    },
    "rust": {
      "name": "rust", "role": "runtime", "media": "erofs",
      "digest": "$RUST_DIGEST", "file": "$RUST_FILE", "size": $RUST_SIZE, "fs_verity": $RUST_VERITY
    }
  }
}
JSON

echo
echo "[done] layer store: $STORE"
echo "  base         $BASE_DIGEST"
echo "  bun-$BUN_VER $BUN_DIGEST"
echo "  node         $NODE_DIGEST ($NODE_SIZE bytes)"
echo "  rust         $RUST_DIGEST ($RUST_SIZE bytes)"
echo "  manifest     $STORE/platform.json"
