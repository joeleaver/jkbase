#!/usr/bin/env bash
# Rebake build-VM toolchain images IN PLACE on a running box and atomically swap them
# in. The companion to deploy-server.sh, which ships the host binary + agent rootfs but
# deliberately NOT these (toolchains are large and change rarely). Reach for this when
# an in-VM build change (the jkbuild lifecycle → jkbuild-init, baked into every
# toolchain) or a toolchain input actually changes — otherwise the host emits new build
# behaviour the stale baked jkbuild-init ignores.
#
# Each image is rebaked via build-image.sh (which rebuilds jkbuild-init from the repo)
# WITH the build-mirror CA injected. The new image is then VERIFIED to carry that CA
# BEFORE anything is swapped: a language toolchain without it can't fetch dependencies
# through the active `--build-mirror` — the in-VM package manager rejects the mirror's
# TLS and the build dies at fetch. The live image is backed up (.bak-pre-rebake-<ts>),
# then atomically renamed into place. P0-3 holds: build-image.sh mkfs's in userspace,
# never mounting a filesystem.
#
# Run as the deploy user (cargo + apko on PATH); privileged steps use sudo:
#   tools/rebake-toolchains.sh [--data-dir DIR] [--ca PATH] [LANG ...]
#     LANG ∈ {rust node go python dockerfile bun trunk}
#     default = the language toolchains already present in {data-dir}/toolchains
#     bun/trunk need staged assets (BUN_BIN / TRUNK_BIN + RUST_TOOLCHAIN_DIR); a
#     missing asset skips that image with a clear note rather than baking a broken one.
set -euo pipefail

# Self-locate the repo even when piped over ssh stdin (BASH_SOURCE unhelpful there).
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." 2>/dev/null && pwd || true)}"
[ -d "${REPO_ROOT:-}/tools" ] || REPO_ROOT="$HOME/jkbase"
[ -d "$REPO_ROOT/tools" ] || { echo "ERROR: cannot locate repo (set REPO_ROOT=)" >&2; exit 1; }

DATA_DIR="/var/jkbase"
CA=""
LANGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        --ca)       CA="$2"; shift 2 ;;
        -h|--help)  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)         echo "unknown flag: $1" >&2; exit 1 ;;
        *)          LANGS+=("$1"); shift ;;
    esac
done

TC="$DATA_DIR/toolchains"
CA="${CA:-$DATA_DIR/build-ca/ca.crt}"
[ -d "$TC" ] || { echo "ERROR: no toolchains dir at $TC (wrong --data-dir?)" >&2; exit 1; }

# cargo (jkbuild-init build) + apko (image export) must be reachable. A non-interactive
# ssh shell sources neither — the #1 footgun when driving this remotely.
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
export PATH="$HOME/.local/bin:$PATH"
[ -x "$REPO_ROOT/tools/ensure-apko.sh" ] && "$REPO_ROOT/tools/ensure-apko.sh" >/dev/null 2>&1 || true

BUN_BIN="${BUN_BIN:-$REPO_ROOT/.firecracker/assets/bun}"
TRUNK_BIN="${TRUNK_BIN:-$REPO_ROOT/.firecracker/assets/trunk}"

# Default set: the language toolchains already present (refresh what's deployed, never
# silently mint a new one). `default` (busybox passthrough, no jkbuild-init) and
# `jkbuild-function` (functions take no `context`; rebake explicitly if ever needed)
# are excluded from the default sweep.
if [ "${#LANGS[@]}" -eq 0 ]; then
    for f in "$TC"/*.ext4; do
        n="$(basename "$f" .ext4)"
        case "$n" in default|jkbuild-function) continue ;; esac
        LANGS+=("$n")
    done
fi

# The build-mirror CA cert is PUBLIC, but it lives in a root-only dir
# ({data-dir}/build-ca, 0700) the deploy user can't traverse. Copy the cert (only the
# cert — the signing KEY never leaves root) to a user-readable temp so build-image.sh,
# which runs as this user, can bake it in. A language toolchain that can't obtain the
# CA is SKIPPED, never baked CA-less — a CA-less image silently fails EVERY dependency
# fetch through the active `--build-mirror` (the in-VM package manager rejects its TLS).
CA_READABLE=""
if sudo test -f "$CA" 2>/dev/null; then
    CA_READABLE="$(mktemp "${TMPDIR:-/tmp}/jkbase-build-ca.XXXXXX.crt")"
    trap 'rm -f "$CA_READABLE"' EXIT
    sudo cat "$CA" > "$CA_READABLE" && chmod 644 "$CA_READABLE"
else
    echo "WARN: build-mirror CA $CA not found/readable — language toolchains will be SKIPPED (never baked CA-less). Pass --ca or check --data-dir." >&2
fi

# Per-language bake parameters. Sets CONFIG_F / INJECT_BUN_V / INJECT_TRUNK_V / WANT_CA
# and pre-flights any staged-asset requirement (returns 1 → skip this image).
lang_params() {
    local lang="$1"
    INJECT_BUN_V=0; INJECT_TRUNK_V=0; WANT_CA=1
    case "$lang" in
        rust)   CONFIG_F=build-rust.apko.yaml ;;
        node)   CONFIG_F=build-node.apko.yaml ;;
        go)     CONFIG_F=build-go.apko.yaml ;;
        python) CONFIG_F=build-python.apko.yaml ;;
        # buildah pulls its base image through the public-any proxy (3129), not the
        # package mirror, so the dockerfile toolchain needs no mirror CA.
        dockerfile) CONFIG_F=build-dockerfile.apko.yaml; WANT_CA=0 ;;
        bun)    CONFIG_F=build-bun.apko.yaml; INJECT_BUN_V=1
                [ -x "$BUN_BIN" ] || { echo "  SKIP bun: BUN_BIN missing ($BUN_BIN) — stage via tools/install-image-tools.sh or pass BUN_BIN="; return 1; } ;;
        trunk)  CONFIG_F=build-trunk.apko.yaml; INJECT_TRUNK_V=1
                { [ -x "$TRUNK_BIN" ] && [ -n "${RUST_TOOLCHAIN_DIR:-}" ] && [ -d "${RUST_TOOLCHAIN_DIR:-/nonexistent}" ]; } \
                    || { echo "  SKIP trunk: needs TRUNK_BIN ($TRUNK_BIN) + RUST_TOOLCHAIN_DIR (wasm32-unknown-unknown std)"; return 1; } ;;
        *) echo "  SKIP $lang: unknown toolchain"; return 1 ;;
    esac
    [ -f "$REPO_ROOT/images/apko/$CONFIG_F" ] || { echo "  SKIP $lang: $CONFIG_F not in repo"; return 1; }
    return 0
}

TS="$(date +%Y%m%d-%H%M%S)"
declare -A RESULT
echo "[rebake] repo: $(cd "$REPO_ROOT" && git log --oneline -1 2>/dev/null || echo '?')"
echo "[rebake] data-dir=$DATA_DIR  ca=$CA  langs=${LANGS[*]}"

for lang in "${LANGS[@]}"; do
    echo "==== $lang ===="
    if ! lang_params "$lang"; then RESULT[$lang]="skipped"; continue; fi
    live="$TC/$lang.ext4"
    out="$HOME/.rebake-$lang.ext4"
    rm -f "$out"
    ca_env=()
    if [ "$WANT_CA" = 1 ]; then
        if [ -z "$CA_READABLE" ]; then
            echo "  SKIP $lang: build-mirror CA unavailable — refusing to bake a CA-less language toolchain"
            RESULT[$lang]="skipped (no CA)"; continue
        fi
        ca_env=(BUILD_CA_CERT="$CA_READABLE")
    fi
    if ! env INJECT_BUN="$INJECT_BUN_V" INJECT_TRUNK="$INJECT_TRUNK_V" "${ca_env[@]}" \
            CONFIG="$REPO_ROOT/images/apko/$CONFIG_F" OUT="$out" REPO_ROOT="$REPO_ROOT" \
            "$REPO_ROOT/tools/build-image.sh" > "/tmp/rebake-$lang.log" 2>&1; then
        echo "  BAKE FAILED (live untouched) — tail of /tmp/rebake-$lang.log:"; tail -5 "/tmp/rebake-$lang.log"
        RESULT[$lang]="FAIL (bake)"; continue
    fi
    [ -s "$out" ] || { echo "  no output image (live untouched)"; RESULT[$lang]="FAIL (no image)"; continue; }
    # Hard guard: a language toolchain MUST carry the mirror CA before it goes live.
    # (WANT_CA=1 only reaches here with CA_READABLE set — the bake injected it.)
    if [ "$WANT_CA" = 1 ]; then
        if ! sudo debugfs -R "stat /etc/ssl/certs/jkbase-build-ca.crt" "$out" 2>/dev/null | grep -qE "Type|Inode:"; then
            echo "  CA MISSING in new image — REFUSING to swap (live untouched)"
            rm -f "$out"; RESULT[$lang]="FAIL (no CA)"; continue
        fi
        echo "  build-mirror CA present ✓"
    fi
    [ -f "$live" ] && sudo cp -a "$live" "$live.bak-pre-rebake-$TS"
    sudo install -m0444 -o root -g root "$out" "$live"
    rm -f "$out"
    RESULT[$lang]="OK ($(du -h "$live" | cut -f1))"
    echo "  swapped in."
done

echo "==== SUMMARY (rebake $TS) ===="
for lang in "${LANGS[@]}"; do printf '  %-11s %s\n' "$lang" "${RESULT[$lang]:-?}"; done
echo "Restart not required: build VMs open each image RO per build; new builds pick up the swap."
