#!/usr/bin/env bash
# Ship a locally-baked managed-DB engine layer (ONLY=rhypedb tools/build-base-layer.sh) to a
# running host, ADDITIVELY. The companion of deploy-server.sh, which ships the host binary +
# agent rootfs but never the shared erofs layers — and the host has no rhypedb checkout to
# bake one from.
#
#   tools/ship-rhypedb-layer.sh [--dry-run] [--data-dir DIR] <ssh-target>
#
# What it does, in order (any failure stops before the manifest moves):
#   1. locally re-verifies the blob `runtimes.rhypedb` names: sha256 == its content address
#      AND the appended dm-verity tree verifies against the recorded root hash (the guest
#      pins that root, so a mismatch would fail every DB VM closed at boot);
#   2. copies blob + entry to the host and installs the blob root:root 0444 into
#      {data-dir}/baselayers, re-hashing it there;
#   3. swaps ONLY `runtimes.rhypedb` in the host's platform.json (tools/platform-json-swap.py:
#      backup, blob-present + hash check, every other entry asserted unchanged, atomic).
# Nothing restarts. Running projects keep the engine their metadata image pins (the old blob
# stays; the boot GC keeps it while any app or `.db` image references it); each managed-DB
# project picks up the new engine on its next deploy. The report lists them.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STORE="${STORE:-$REPO_ROOT/.firecracker/baselayers}"
DATA_DIR="/var/jkbase"
DRY_RUN=0
TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)  DRY_RUN=1; shift ;;
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        -h|--help)  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)         echo "unknown flag: $1" >&2; exit 1 ;;
        *)          TARGET="$1"; shift ;;
    esac
done
[ -n "$TARGET" ] || { echo "usage: $0 [--dry-run] [--data-dir DIR] <ssh-target>" >&2; exit 1; }
command -v veritysetup >/dev/null || { echo "veritysetup not found — apt-get install cryptsetup-bin" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
read -r FILE HEX ROOT DSIZE < <(python3 - "$STORE/platform.json" "$WORK/rhypedb-entry.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1]))["runtimes"]["rhypedb"]
json.dump(e, open(sys.argv[2], "w"), indent=2)
print(e["file"], e["digest"].removeprefix("sha256:"), e["verity"]["root_hash"], e["verity"]["data_size"])
PY
)
BLOB="$STORE/$FILE"

echo "[ship] local verify $FILE"
[ "$(sha256sum "$BLOB" | cut -d' ' -f1)" = "$HEX" ] || { echo "[ship] $BLOB sha256 != content address" >&2; exit 1; }
veritysetup verify --hash-offset="$DSIZE" "$BLOB" "$BLOB" "$ROOT" \
    || { echo "[ship] $BLOB dm-verity tree does not verify against root $ROOT" >&2; exit 1; }

REMOTE_TMP="$(ssh "$TARGET" mktemp -d)"
cleanup_remote() { ssh "$TARGET" rm -rf "$REMOTE_TMP" >/dev/null 2>&1 || true; }
trap 'rm -rf "$WORK"; cleanup_remote' EXIT
if [ "$DRY_RUN" = 1 ]; then
    scp -q "$WORK/rhypedb-entry.json" "$TARGET:$REMOTE_TMP/"
else
    echo "[ship] copying blob ($(stat -c%s "$BLOB") bytes) → $TARGET"
    scp -q "$BLOB" "$WORK/rhypedb-entry.json" "$REPO_ROOT/tools/platform-json-swap.py" "$TARGET:$REMOTE_TMP/"
fi

ssh "$TARGET" "bash -s" -- "$REMOTE_TMP" "$DATA_DIR" "$FILE" "$HEX" "$DRY_RUN" <<'REMOTE'
set -euo pipefail
TMP="$1" DATA_DIR="$2" FILE="$3" HEX="$4" DRY_RUN="$5"
STORE="$DATA_DIR/baselayers"
sudo test -f "$STORE/platform.json" || { echo "[ship] no $STORE/platform.json on this host" >&2; exit 1; }
CUR="$(sudo python3 -c "import json; print(json.load(open('$STORE/platform.json'))['runtimes'].get('rhypedb', {}).get('digest', '(absent)'))")"
echo "[ship] host runtimes.rhypedb: $CUR → sha256:$HEX"

if [ "$DRY_RUN" = 1 ]; then
    echo "[ship] --dry-run: not installing or swapping"
else
    if sudo test -f "$STORE/$FILE" && [ "$(sudo sha256sum "$STORE/$FILE" | cut -d' ' -f1)" = "$HEX" ]; then
        echo "[ship] blob already in the store"
    else
        sudo install -o root -g root -m0444 "$TMP/$FILE" "$STORE/$FILE"
        [ "$(sudo sha256sum "$STORE/$FILE" | cut -d' ' -f1)" = "$HEX" ] \
            || { sudo rm -f "$STORE/$FILE"; echo "[ship] installed blob hash mismatch — removed" >&2; exit 1; }
        echo "[ship] blob installed"
    fi
    sudo python3 "$TMP/platform-json-swap.py" --backup "$STORE/platform.json" rhypedb "$TMP/rhypedb-entry.json"
fi

# Which projects run a managed DB (they move to the new engine on their next deploy), and a
# heads-up for schemas with vector fields: an ONNX-free engine can't embed @vectorize text.
echo "[ship] managed-DB projects (id · tier · vector fields):"
found=0
for db in $(sudo sh -c "ls -1 '$DATA_DIR'/hosting/*/live/_database.json 2>/dev/null" || true); do
    live="$(dirname "$db")"; id="$(basename "$(dirname "$live")")"; found=1
    tier="$(sudo python3 -c "import json; print(json.load(open('$db')).get('tier') or 'colocated')" 2>/dev/null || echo '?')"
    vec="$(sudo sh -c "grep -l 'Vector<' '$live'/_database/*.rhype 2>/dev/null" >/dev/null && echo yes || echo no)"
    echo "    $id · $tier · $vec"
done
[ "$found" = 1 ] || echo "    (none)"
REMOTE
echo "[ship] done"
