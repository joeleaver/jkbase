#!/usr/bin/env bash
# Provision the parent cgroup for RUNTIME (tenant) VMs (root; per-boot, NOT reboot-surviving).
#
# Runtime Firecrackers are migrated by jkbase-server into per-project leaf cgroups beneath
# /sys/fs/cgroup/jkbase-runtime right after spawn (vm.rs). Living in this SIBLING cgroup — NOT
# under jkbase.service — is what lets a tenant VM survive `systemctl restart`: KillMode=mixed
# reaps only the service's own cgroup, so the next jkbase-server can RE-ADOPT the survivor
# instead of cold-restoring it (see docs/vm-readoption-design.md §1). The parent must therefore
# exist (and, mirroring jkbase-build, have +cpu +memory +pids delegated so a future per-VM cap
# can apply) before the service starts; the server creates the per-id leaves itself.
#
# Mirrors tools/setup-build-cgroup.sh so local dev (tools/dev) and prod share one source of
# truth. Best-effort / exit 0: a cgroup hiccup must never block the runtime from starting (the
# VM just won't survive an upgrade — it falls back to the cold-restore path).
set -euo pipefail

WANT="+cpu +memory +pids"
ROOT="${CGROUP_ROOT:-/sys/fs/cgroup}"
PARENT="$ROOT/jkbase-runtime"

if [ "$(id -u)" -ne 0 ]; then
    echo "[runtime-cgroup] must run as root (cgroup-v2 delegation)" >&2
    exit 1
fi

# Delegate controllers down from the root so children can receive them.
echo "$WANT" > "$ROOT/cgroup.subtree_control" 2>/dev/null || true
mkdir -p "$PARENT" 2>/dev/null || true
if ! echo "$WANT" > "$PARENT/cgroup.subtree_control" 2>/dev/null; then
    echo "[runtime-cgroup] WARNING: could not delegate '$WANT' to $PARENT" >&2
fi
# The PARENT existing is the load-bearing bit (the server writes leaf cgroup.procs); controllers
# are a nicety. Report readiness on parent existence, not controller delegation.
if [ -d "$PARENT" ]; then
    echo "[runtime-cgroup] ready ($PARENT; subtree_control='$(cat "$PARENT/cgroup.subtree_control" 2>/dev/null || true)')"
else
    echo "[runtime-cgroup] WARNING: $PARENT does not exist — runtime VMs will NOT survive a restart" >&2
fi
exit 0
