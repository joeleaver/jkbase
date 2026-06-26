# Zero-bounce continuity, phase 1: tenant VM re-adoption across a server restart

**Status:** design (not yet implemented). Decided approach: *re-adopt + scopes* (vs. self-exec
hot-upgrade). Goal of this phase: a `jkbase-server` upgrade/restart **keeps every tenant VM
running** — they are re-adopted by the new process instead of drained→lazily-restored. The proxy
data-plane gap (in-flight connections cut during the swap) is a **separable phase 2** (socket
activation); this doc does not solve it.

## Today (why a restart bounces every VM)

- Runtime Firecrackers are **direct children** of `jkbase-server` (`vm.rs` `VmInstance.process: Child`,
  `kill_on_drop(true)`), in the **service cgroup**. `systemd KillMode=mixed` SIGKILLs that cgroup on
  `systemctl restart`, so the FCs die.
- The shutdown handler (`shutdown_signal`, main.rs:1674) deliberately **hibernates all running VMs**
  on SIGTERM, then exits.
- On the next start the server cold-starts with empty `vm_states`; the first request to each project
  cold-boots / restores it (~4s). The startup `reap_orphan_firecrackers` (added in the rootfs-CAS
  work) actively **kills** any FC that did survive.

So nothing today keeps a VM alive across the restart, and two mechanisms actively tear them down.

## Target behaviour

A restart for an **upgrade** leaves the tenant FCs running; the new process **re-adopts** them
(reconnects, re-fences, rebuilds in-memory state, re-registers routes) within its startup, before it
serves. A genuine **shutdown** still hibernates. A **crash** is handled by the same re-adopt path
(survivors are adopted; this is a robustness bonus over today's "crash → orphan → reap → cold boot").

Single-host only (matches the production posture). A **host reboot** kills all VMs regardless — out
of scope; that path cold-starts. Re-adoption covers *process* restarts, not machine reboots.

## Design

### 1. Make runtime FCs survive the service restart
Run each runtime Firecracker in its **own transient systemd scope** under a dedicated persistent
slice `jkbase-runtime.slice` (provisioned per-boot like `setup-build-cgroup.sh`), e.g. conceptually
`systemd-run --scope --collect --unit=jkbase-vm-<id> --slice=jkbase-runtime.slice -- firecracker
--api-sock <run>/<id>/firecracker.sock …`. Because the scope is a **separate cgroup/unit**, the
service's `KillMode=mixed` no longer reaches it, so the FC outlives `systemctl restart jkbase`.

Consequences for `vm.rs`:
- Runtime FCs must **not** `kill_on_drop` (dropping a `VmInstance` on server exit must not kill a VM
  we intend to re-adopt). Reaping a runtime VM becomes explicit (`systemctl stop` the scope, or
  SIGKILL by verified pid) on hibernate/teardown/orphan.
- `VmInstance` gains an **adopted** form that wraps a verified **pid + socket + client** rather than a
  tokio `Child` (a restarted server never had a `Child` for a surviving FC). Liveness/reap go through
  the pid (+ starttime) and the scope unit instead of `Child::wait`/`kill`.

> Simpler alternative considered: set the service to `KillMode=process` (systemd kills only the main
> pid, not the cgroup) and keep FCs as direct children. Avoids `systemd-run` entirely but weakens
> systemd's stray containment for *build* VMs and everything else in the cgroup. The slice/scope
> approach is preferred for explicit per-VM lifecycle; the exact `systemd-run` invocation needs on-box
> validation (this repo gates such things behind `// VERIFY(...)` markers).

### 2. Persist a re-adoption record per running VM
At commit-to-Running (both `handle_deploy` and `wake_project_inner`), write
`run/<id>/handoff.json` (and remove it on hibernate/teardown/force-stop/self-fence) carrying exactly
what re-adoption needs and cannot re-derive live:
- `fc_pid` + `fc_starttime` (`/proc/<pid>/stat` field 22 — defeats PID reuse, mirrors `LocalLoop`),
- `scope_unit`, `ip`, `tap`, `mac`,
- `loop_dev` + the data-disk `lease_epoch` it was fenced under,
- `base_rootfs_hash`, `deployment_version` (so the adopted VM keeps an honest hibernate stamp),
- the metadata-image + layer paths (for logging / sanity, not re-attach).

The record is the durable source of truth; the new process trusts it only after verifying liveness.

### 3. Re-adopt on startup (replaces the orphan-reap)
`reap_orphan_firecrackers` becomes `adopt_or_reap_runtime_vms`, run synchronously at startup **before**
CAS-GC and before any boot-capable loop / the proxy bind (same ordering invariant as today). For each
`handoff.json`:
1. **Verify survivor:** `fc_pid` alive **and** its `/proc/<pid>/stat` starttime matches the record
   **and** the FC api-sock answers (`FirecrackerClient` probe). Any mismatch ⇒ not a survivor: reap any
   remnant + delete the record; the project is left wakeable (next request cold-boots). This subsumes
   the old orphan reap.
2. **Re-fence WITHOUT disturbing the live disk:** the old process's `flock` lease released on its exit,
   so `lease.acquire(project)` now succeeds with a **fresh monotonic epoch**. Then a NEW
   `DataDisk::adopt_writer(id, token, loop_dev, fc_pid)` path: assert the persisted `loop_dev` is still
   the loop for this project's image and that `fc_pid` is the live writer, and re-pin `writer_pid`
   under the new token — **never** `attach_rwo` (which would `losetup -d` the live device). If the
   lease can't be acquired (LeaseHeld — must not happen single-host) ⇒ **fail safe**: kill the survivor
   + drop to cold-boot, never run a VM unfenced.
3. **Rebuild in-memory state:** construct the adopted `VmInstance`, insert into `vms`,
   `vm_states=Running`, `vm_rootfs_hashes`, `disk_tokens`; `register_active_routes`. The renew loop
   (`disk_fence_loop`) then renews the new token normally; metering continues off the same `fc_pid`
   (`cpu_delta` already resets cleanly on a pid change, so even an edge mismatch is harmless).

### 4. Conditional drain (upgrade vs shutdown)
`shutdown_signal` must distinguish an **upgrade restart** (leave VMs for re-adoption) from a real
**shutdown** (hibernate, as today) — SIGTERM alone can't, since `systemctl stop` and `restart` both
send it. Use an **upgrade flag**: `tools/deploy-server.sh` touches `/var/jkbase/.upgrading` immediately
before `systemctl restart`; `shutdown_signal` skips hibernation iff the flag is present; the new
process clears it once re-adoption completes. Absent flag ⇒ hibernate (safe default for an operator
`stop`). A stale flag (deploy crashed after touching it, before restart) at most causes the next real
shutdown to skip hibernation → those VMs are re-adopted or cold-booted next start: not a brick.

### 5. Deploy flow
`deploy-server.sh`: `touch /var/jkbase/.upgrading` → rebuild → `systemctl restart` (FCs survive in the
slice) → new server re-adopts → clear flag. The agent rootfs rebuild is unchanged; **re-adopted VMs
keep running the OLD agent** until they next hibernate→cold-boot (or are deliberately recycled), which
is exactly the lazy, staggered rollout we want — the new agent reaches a project on its next cold
cycle, never via a forced bounce.

## Threat-model invariants (load-bearing — the review must confirm)
- **Never two writers on a data disk.** Single-host: during the restart gap the old flock is released
  and nothing else attaches (the new server isn't up yet). The survivor keeps its loop fd; the new
  server re-pins the writer under a higher epoch without detaching. A reboot or a non-single-host
  config must NOT silently re-adopt — gate re-adoption on single-host + the liveness+starttime proof,
  and fail safe (kill+cold-boot) on any doubt.
- **No unfenced run.** A VM is only inserted as Running after the lease is re-acquired; failure ⇒ kill
  + cold-boot.
- **PID reuse** is defeated by the starttime pin (same mechanism `LocalLoop` already uses).
- **Isolation otherwise unchanged:** re-adoption touches only lifecycle bookkeeping (lease/loop/pid/
  routes), never the guest, the rootfs, the layers, or seccomp/jailer posture.

## Out of scope (named follow-ups)
- **Phase 2 — proxy/TLS socket hand-off** (systemd socket activation or `SO_REUSEPORT`) so in-flight
  HTTPS isn't cut during the swap. Without it, re-adoption keeps tenant VMs up but clients still see a
  ~1–2s connection-refused window at the proxy during the restart.
- Host-reboot survival (impossible without snapshotting; cold-start path already handles it).
- HA/multi-node re-adoption (a peer could contend the lease during the gap — needs the cluster lease,
  not flock; deferred with the rest of HA).

## Validation plan (next session, before any prod deploy)
- On-box: boot a real VM, `systemctl restart` the (dev) service with the upgrade flag, assert the FC
  PID is unchanged, the disk is re-fenced (new epoch, same loop, same writer), the route is back, and
  the app serves 200 **without** a re-boot — then confirm a *flagless* restart still hibernates.
- Negative: kill the FC during the gap → assert reap + clean cold-boot (no stuck state, no unfenced
  attach). PID-reuse probe. Double-adopt idempotency (re-run startup twice).
- Adversarial multi-agent review of the fence-across-restart path before merge (per repo hardening
  rule for host/guest-seam changes).
