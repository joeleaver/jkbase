#!/usr/bin/env bash
# Provision the parent cgroup for build VMs (root; per-boot, NOT reboot-surviving).
#
# Build VMs run under the jailer in leaf cgroups beneath /sys/fs/cgroup/jkbase-build;
# that parent must exist with +cpu +memory +pids delegated or a hostile build's
# memory.max never applies and it can drive HOST OOM (threat model: all tenants
# untrusted). The server also does this best-effort at startup, but provisioning it
# explicitly makes it loud and independent of the binary.
#
# Extracted verbatim from the provision.sh systemd ExecStartPre heredoc so local
# dev (tools/dev net) and prod share one source of truth. Best-effort / exit 0:
# a cgroup hiccup must never block the runtime from starting.
set -euo pipefail

WANT="+cpu +memory +pids"
ROOT="${CGROUP_ROOT:-/sys/fs/cgroup}"
PARENT="$ROOT/jkbase-build"

if [ "$(id -u)" -ne 0 ]; then
    echo "[build-cgroup] must run as root (cgroup-v2 delegation)" >&2
    exit 1
fi

# Delegate controllers down from the root so children can receive them.
echo "$WANT" > "$ROOT/cgroup.subtree_control" 2>/dev/null || true
mkdir -p "$PARENT" 2>/dev/null || true
if ! echo "$WANT" > "$PARENT/cgroup.subtree_control" 2>/dev/null; then
    echo "[build-cgroup] WARNING: could not delegate '$WANT' to $PARENT" >&2
fi
have="$(cat "$PARENT/cgroup.subtree_control" 2>/dev/null || true)"
case "$have" in
    *memory*) echo "[build-cgroup] ready ($have)" ;;
    *) echo "[build-cgroup] WARNING: memory controller NOT delegated — build OOM containment is OFF ($have)" >&2 ;;
esac
exit 0
