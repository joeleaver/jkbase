# Base-image redeploys without bricking projects: content-addressed rootfs + snapshot durability

## Problem

A `jkbase-server` redeploy rebuilds `/var/jkbase/base-rootfs.ext4` (the guest rootfs: Wolfi
userland + chrony + the `jkbase-agent` as `/sbin/init`) **in place** — `build-runtime-rootfs.sh`
does `rm -f $OUT` then recreates it. Hibernation snapshots reference the rootfs **by that fixed
path**. So after a redeploy, a project that was hibernated under the *old* rootfs restores its old
guest RAM against the *new* rootfs bytes (FC lazily mmap-faults rootfs pages for the VM's whole
life). The in-VM agent then faults a changed page and never becomes ready on `:80` → the proxy
wake-loops forever. This bricked the real project **nlnwt** (2026-06-26). A second, compounding bug:
a failed wake leaves the in-memory `vm_states[project]` stuck at `Waking`, so the project can't even
cold-boot to recover without a full service restart.

The same in-place-rewrite poison class also applies to the per-project **metadata image**
(`content-images/{id}.ext4`, attached as `vdb`, carrying secrets + routes) and, more weakly, to the
shared erofs layers.

## Goal & scope

**In scope (this change):** a base-image redeploy must **never brick** a project. A hibernated
project either restores byte-correct against the exact bytes its RAM expects, or — if anything it
depended on changed — **fails open to a clean cold boot** (~4s) and re-snapshots fresh. No project
can get stuck. Self-healing across the first deploy of this change.

**Explicitly NOT in scope (named follow-on arc — see Overboard):**
- **Zero-bounce continuity.** Running VMs are still drained → hibernated → lazily restored on the
  next request after a restart. True "never stops" needs **VM re-adoption across the binary swap**
  (leave jailer/FC alive, reconnect to the API sockets, rebuild `vm_states`). Bigger lift.
- **Proxy/TLS data-plane survival.** `jkbase-server` *is* the TLS terminator; restarting it cuts
  in-flight HTTPS until the new process binds. Needs graceful listener drain + socket hand-off.

So this change delivers **"restartable without bricking, with a ~4s lazy cold-restore,"** not
literal continuity. That distinction is deliberate and load-bearing for ops expectations.

## Design

### 1. Content-address the base rootfs
At startup the server takes the staging artifact at `data_dir/base-rootfs.ext4` (built by the deploy
script in prod, or the local-dev fallback), `sha256`s it, and places it **immutably** at
`data_dir/base-rootfs/<sha256>.ext4` (atomic temp+fsync+rename; `chmod 0444`; skip-if-exists is only
ever trusted for a blob we wrote via rename). `base_rootfs_path` = that CAS path; `base_rootfs_hash`
= the digest. All VM boots use the immutable CAS path. A redeploy with a new agent mints a **new**
hash/blob *alongside* the old one — the old blob stays, so a pre-redeploy snapshot still restores
byte-correct against the bytes its RAM expects.

### 2. Stamp snapshots with what they actually depend on
`SnapshotMeta` gains two `Option` fields (`#[serde(default)]`; the JSON encoding of the `SNAPSHOTS`
redb table makes this forward- **and** backward-compatible — that's load-bearing, do not switch the
table to bincode):
- `base_rootfs_hash` — the rootfs the VM **actually ran** (cold boot = current hash; restore =
  the hash the snapshot restored against), tracked per-running-VM in `PlatformState.vm_rootfs_hashes`
  and stamped at hibernate. **Not** the process's `current` hash — a restored-then-rehibernated VM
  runs the *old* rootfs, and stamping `current` would lie to the viability gate and make GC reap the
  blob the snapshot needs.
- `deployment_version` — `project.current_version` at hibernate. A single check that subsumes the
  metadata image (vdb), the app layer, and the baselayers: if the snapshot's version still equals
  the project's current version, all of those are guaranteed live and coherent.

### 3. Fail-open wake (viability gate + post-restore fallback)
A restore is **viable** iff: `base_rootfs_hash` is `Some`, is a valid 64-hex digest, its CAS blob
exists, **and** `deployment_version == project.current_version`. Otherwise (legacy `None`, missing
blob, version drift) → **skip restore, cold-boot** from current.

If a restore *is* attempted and `restore_from_snapshot` errors → cold-boot (pre-existing). **New:**
if restore succeeds but `wait_for_agent` fails → synchronously **reap** the restored FC
(`kill_and_wait`, i.e. SIGKILL + waitpid — never the `pkill -f firecracker.*{id}` substring idiom,
which would reap a project whose id contains this one), **poison the snapshot** (delete its meta +
files, so a tenant can't engineer hostile RAM to force the expensive restore→timeout→coldboot cycle
on every wake), then cold-boot **reusing the already-held disk fence** (do not re-`fence_data_disk`
→ RWO self-deadlock). Net: a base-image/agent mismatch can never brick; worst case is one cold boot.

### 4. Never leak `Waking` (RAII) + no hot-loop
`Waking` is committed/reset via a **RAII `WakingGuard`** that wraps the *entire* post-`Waking` body.
On drop, if the wake didn't commit to `Running`, it removes the entry — so a client **disconnect /
cancellation** mid-boot (the most common trigger) and every early `?` exit (`get_vm_allocation`,
`setup_tap`, `fence_data_disk`, the boot block) all reset cleanly. The reset is ordered **after** the
awaited disk-fence release so the retry doesn't hit a transient `LeaseHeld`/`RwoUnsafe`. A short
per-project **negative-cache** after a failed wake fast-fails (Retry-After) instead of letting
hostile traffic spin unbounded full-boot attempts. `wait_for_route` waiters bail early when the
driver leaves `Waking` without a route, instead of hanging the full 30s.

### 5. GC, fail-closed, before anything can boot
At startup, **before** any boot-capable loop is spawned and before the listener binds:
1. **Reap orphan VMs** — SIGKILL any `firecracker` process whose `--api-sock` is under our
   `run/` dir (orphans from a prior crash; FC children only die via `kill_on_drop`, so a
   non-graceful exit leaves them faulting their rootfs blob). This re-establishes the
   "zero VMs running" premise the GC reference set depends on.
2. **CAS-ize** the staging rootfs (part 1).
3. **GC** unreferenced CAS blobs. Referenced set = `{current_hash}` ∪ `{every SnapshotMeta`
   `.base_rootfs_hash that is Some + valid-hex}`. If enumerating snapshot metas errors at all →
   **skip every delete this run** (fail-closed; mirrors `reconcile_baselayers_on_boot`). Only ever
   delete regular files named `<64hex>.ext4`; never the `current` symlink. Every deletion is logged.

Over-deletion is itself self-healing (missing blob → non-viable → cold boot), so GC is defense in
depth, not a brick risk — but it's still fail-closed.

### Observability
Each wake emits a structured `wake_outcome`: `restored` / `skipped_legacy` / `skipped_blob_missing`
/ `skipped_version_drift` / `restore_failed_coldboot` / `restore_ok_agent_fail_coldboot` /
`coldboot_fresh`. A spike in cold-boot fallbacks after a deploy is the signal that the deploy staged
a bad/garbage rootfs (e.g. wrong hash) — otherwise invisible because every project still serves 200.

## Migration (first deploy of this change)
Existing prod snapshots have no `base_rootfs_hash` / `deployment_version` (both `None`) → non-viable
→ cold-boot once → re-hibernate stamps the new fields. Self-healing, no manual step. Rollback is
safe: CAS blobs are immutable and old code never GCs them, and old code ignores the unknown JSON
fields.

## Test plan (on-box, real microVM — this box is KVM/jailer-capable)
1. Deploy a tiny project → VM boots → HTTP 200.
2. Graceful drain (SIGTERM) → snapshot stamped with hash + version.
3. **Durability:** rebuild the base rootfs from a *different* agent (new hash; old CAS blob
   retained) + restart → wake the project → it **restores** against the old blob → 200.
4. **Fail-open:** delete the referenced CAS blob (simulate aggressive GC) → wake → **cold-boots** →
   200. And a legacy (`None`) snapshot → cold-boots → 200.
5. **No stuck Waking:** kill a wake mid-boot (disconnect) → next request still boots → 200.
6. **GC:** confirm referenced blobs are kept, unreferenced removed, and a corrupt snapshot-meta row
   aborts the sweep (nothing deleted).

## Deferred (follow-on cards)
VM re-adoption across restart (zero-bounce); proxy socket hand-off; `chattr +i` on CAS blobs;
data-disk geometry/generation stamp in `SnapshotMeta` (only if an online resize path is ever added);
hibernation-snapshot-aware shared-layer GC (subsumed today by the `deployment_version` gate).
