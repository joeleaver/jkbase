#!/bin/bash
# Bake a `bun.ext4` build-VM toolchain: a glibc userland with Bun + Node + the
# handful of utilities the build-runner and a typical Bun/Node build.sh need,
# with tools/build-runner.sh as /sbin/init (PID 1). This is a B2 "rich"
# toolchain that reuses the exact same init contract as the B1 busybox
# `default.ext4` (see build-toolchain.sh) — it just carries a language runtime.
#
# Selected automatically for a server target whose jkbase.toml declares
#   [servers.<name>] language = "bun"
# via BuildDeps::select_toolchain (`{language}.ext4` -> `bun.ext4`).
#
# WHY Node *and* Bun: Bun runs `bun install` (fast, lockfile-aware) and
# `bun build --compile` (the single-binary artifact we ship), but some frontend
# toolchains — Vite + vite-plugin-solid among them — must run under Node, not
# Bun's baseline build, to resolve their Babel plugins. Shipping both lets a
# build.sh pick the right driver per step.
#
# WHY baseline Bun by default: the build VM's CPU may not expose AVX2. The
# baseline Bun build avoids SIGILL there; it's only unsuitable for *running*
# Vite (which we do under Node anyway). Override with BUN_FLAVOR=x64 for AVX2.
#
# Unlike the busybox toolchain this needs Docker to assemble a glibc rootfs
# (there is no rootless debootstrap path here). `mkfs.ext4 -d` still builds the
# image with NO mount / NO loop / NO root (threat-model P0-3); the image is made
# read-only + world-readable so it hard-links into the jail, page-cache-hot,
# shared across builds.
#
#   tools/build-bun-toolchain.sh [OUT.ext4]
# Default OUT: .firecracker/toolchains/bun.ext4
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUT="${1:-$PROJECT_ROOT/.firecracker/toolchains/bun.ext4}"
RUNNER="$SCRIPT_DIR/build-runner.sh"

BUN_VERSION="${BUN_VERSION:-1.3.9}"
BUN_FLAVOR="${BUN_FLAVOR:-x64-baseline}"   # or "x64" for AVX2 hosts
NODE_IMAGE="${NODE_IMAGE:-node:22-slim}"

command -v docker  >/dev/null || { echo "docker is required to bake the glibc rootfs" >&2; exit 1; }
command -v mkfs.ext4 >/dev/null || { echo "mkfs.ext4 (e2fsprogs) is required" >&2; exit 1; }
[ -f "$RUNNER" ] || { echo "missing $RUNNER" >&2; exit 1; }

STAGE="$(mktemp -d)"
CID=""
cleanup() { [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1 || true; rm -rf "$STAGE"; }
trap cleanup EXIT

echo "[bun-toolchain] building image (node=$NODE_IMAGE bun=$BUN_VERSION/$BUN_FLAVOR)…"
# Assemble the rootfs in a throwaway image: Node base + Bun + the few extra
# tools build-runner.sh (nc/reboot) and a Bun build.sh (ldd/tar/gzip/ca-certs)
# rely on. busybox-static backstops the init-side applets that slim images drop.
docker build -t jkbase-bun-toolchain:latest -f - "$STAGE" >/dev/null <<DOCKERFILE
FROM ${NODE_IMAGE}
RUN apt-get update \\
 && apt-get install -y --no-install-recommends \\
        ca-certificates curl unzip busybox-static tar gzip \\
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-${BUN_FLAVOR}.zip" -o /tmp/bun.zip \\
 && unzip -j /tmp/bun.zip "bun-linux-${BUN_FLAVOR}/bun" -d /usr/local/bin \\
 && chmod 0755 /usr/local/bin/bun \\
 && rm /tmp/bun.zip \\
 && /usr/local/bin/bun --version
DOCKERFILE

echo "[bun-toolchain] exporting rootfs…"
CID="$(docker create jkbase-bun-toolchain:latest /bin/true)"
docker export "$CID" | tar -x -C "$STAGE"

# Install the build-runner as PID 1.
install -m 0755 "$RUNNER" "$STAGE/sbin/init"
echo "jkbase-build" > "$STAGE/etc/hostname"

# Mount points the runner sets up on the READ-ONLY root (it can't mkdir them
# there at boot): the IO drives, the overlay newroot, and the virtual FSes.
mkdir -p "$STAGE"/{scratch,src,out,cache,newroot,work,proc,sys,dev,tmp}

# build-runner.sh calls `nc` (seal probe) and `reboot -f` (the only way the
# firecracker process exits). Back them with busybox if the slim base lacks them.
BB="/bin/busybox"
[ -e "$STAGE$BB" ] || BB="/usr/bin/busybox"
for app in nc reboot poweroff halt pivot_root switch_root; do
    if [ ! -e "$STAGE/bin/$app" ] && [ ! -e "$STAGE/sbin/$app" ] && [ -e "$STAGE$BB" ]; then
        ln -sf "$BB" "$STAGE/sbin/$app"
    fi
done

# Size = content + 50% ext4 metadata slack + 64 MiB headroom (glibc+node+bun is
# a few hundred MB; the slack keeps `mkfs -d` from running out of inodes/blocks).
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
KIB="$(du -sk "$STAGE" | cut -f1)"
SIZE_KIB=$(( KIB + KIB / 2 + 65536 ))
truncate -s "${SIZE_KIB}K" "$OUT"
mkfs.ext4 -F -q -O ^has_journal -d "$STAGE" "$OUT"
chmod 0444 "$OUT"

echo "[bun-toolchain] done."
echo "bun toolchain image: $OUT"
ls -lh "$OUT"
echo "install it where the server reads toolchains, e.g.:"
echo "  cp '$OUT' \"\$DATA_DIR/toolchains/bun.ext4\""
