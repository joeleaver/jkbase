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
STORE="${STORE:-$REPO_ROOT/.firecracker/baselayers}"
BUN_BIN="${BUN_BIN:-$REPO_ROOT/.firecracker/assets/bun}"
BUN_VER="${BUN_VER:-1.3.14}"
WORK="${WORK:-$REPO_ROOT/.firecracker/work/base-layer}"
export PATH="$HOME/.local/bin:$PATH"

command -v apko >/dev/null || { echo "apko not found — run tools/install-image-tools.sh" >&2; exit 1; }
command -v mkfs.erofs >/dev/null || { echo "mkfs.erofs not found — apt-get install erofs-utils" >&2; exit 1; }
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

# --- platform manifest (host reads this to inject base + runtime ahead of the app) ---
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
    }
  }
}
JSON

echo
echo "[done] layer store: $STORE"
echo "  base       $BASE_DIGEST"
echo "  bun-$BUN_VER $BUN_DIGEST"
echo "  manifest   $STORE/platform.json"
