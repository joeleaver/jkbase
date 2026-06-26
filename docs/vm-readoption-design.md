# Zero-bounce continuity, phase 1: tenant VM re-adoption across a server restart

**Status:** design v2 (revised after adversarial review — see "Review outcome" at the end). Not yet
implemented. Decided approach: *re-adopt + a dedicated runtime cgroup* (the review pushed us off
`systemd-run --scope`, see §1). Goal: a `jkbase-server` upgrade/restart **keeps every tenant VM
running** — survivors are re-adopted by the new process instead of drained→lazily-restored. The proxy
data-plane gap (in-flight HTTPS cut during the swap) is a **separable phase 2** (socket activation);
this doc does not solve it. **Single-host only.** A host reboot kills all VMs (out of scope; cold-start
handles it).

## Today (why a restart bounces every VM)

- Runtime Firecrackers are **direct children** of `jkbase-server` (`vm.rs` `VmInstance.process: Child`,
  `kill_on_drop(true)`, vm.rs:75), in the **service cgroup**. `systemd KillMode=mixed`
  (provision.sh:295) SIGKILLs that cgroup on `systemctl restart`, so the FCs die.
- `shutdown_signal` (main.rs:1674) deliberately **hibernates all running VMs** on SIGTERM, then exits.
- **Two** startup reapers actively kill survivors: `rootfs_cas::reap_orphan_firecrackers` (main.rs:1111,
  targeted by `--api-sock` under `run/`) **and** `reap_orphan_firecrackers_on_boot()` (main.rs:1517 →
  1854, a blunt `pkill -9 -f firecracker-v1.15.1-x86_64`).
- On the next start the server cold-starts with empty `vm_states`; the first request to each project
  cold-boots / restores it (~4s).

## Design

### 1. Make runtime FCs survive the restart — a raw `jkbase-runtime` cgroup (NOT `systemd-run --scope`)
**Review pivot:** an on-box check during review confirmed `systemd-run --scope -- firecracker …`
leaves the launcher **resident as a separate pid** (the tokio `Child` would be the wrapper, not FC) —
which silently breaks `vm.rs` `stop()`/`hibernate()`/`pid()` (they'd kill/measure the wrapper while FC
keeps its loop fd) into a **double-writer hazard** and unmetered CPU. So instead mirror the
already-proven **build-VM** pattern (the jailer puts build FCs in the top-level `jkbase-build` cgroup,
outside `jkbase.service`, so they already survive `systemctl restart`):

- Keep spawning firecracker **directly** as a tokio `Child` (so `Child.id()` *is* the FC pid and
  metering/stop/hibernate keep working), but **drop `kill_on_drop`** for runtime FCs (build FCs keep
  it), and immediately migrate the FC pid into a pre-provisioned raw cgroup
  `/sys/fs/cgroup/jkbase-runtime/<id>/cgroup.procs`. A sibling top-level cgroup is **not** in the
  service's cgroup, so `KillMode=mixed` on the service never reaches it.
- Provision the parent `jkbase-runtime` cgroup in the **three** places `jkbase-build` lives, or the
  first restart drops survivors back into the service cgroup → next restart SIGKILLs them: a new
  `tools/setup-runtime-cgroup.sh` (mirroring `setup-build-cgroup.sh`), wired as an `ExecStartPre` in the
  unit (provision.sh:272) and re-synced by `deploy-server.sh` (the :94-97 helper block).
- **Must validate on-box:** FC pid unchanged across `systemctl restart` with a live VM in
  `jkbase-runtime/`; survival across the exact `daemon-reload`-then-`restart` ordering deploy uses.

### 2. Adopted `VmInstance` (no `Child`)
`VmInstance` gains an **adopted** form wrapping a verified `fc_pid` (+ starttime) + socket + client, not
a `Child`. It must re-implement:
- `pid()` → the stored `fc_pid` (else metering's `filter_map(vm.pid())` drops the VM, main.rs:4122).
- `stop()` / `hibernate()` → SIGKILL by `fc_pid` (the scope/cgroup has no wrapper to stop) and **block
  until death is confirmed** by polling `/proc/<fc_pid>` with the starttime pin. This is load-bearing:
  the no-two-FCs-on-one-RWO-disk guarantee (the restore-fallback `stop()`-before-cold-boot at main.rs
  ~3086, and `handle_deploy`/`handle_teardown` `stop()`-before-`detach`) depends on `stop()` returning
  only after the FC is gone. A non-child `process.wait()` is `ECHILD`; `/proc` polling replaces it.
- `Drop` → **no-op** for the adopted variant (it must never kill a VM intended to survive).
- An `adopt()` constructor that **attaches** to the existing `run/<id>/firecracker.sock` (unlike
  `start()`, which unlinks it, vm.rs:49) and does **not** call `setup_tap` (the TAP + its ebtables
  source-guard persist across the restart; `ensure_runtime_source_guard_chain` is non-flushing,
  main.rs:3495).

### 3. Persist a re-adoption record per running VM (`run/<id>/handoff.json`)
Written at commit-to-Running (`handle_deploy` + `wake_project_inner`), **atomically** (temp + `fsync` +
`rename`, mirroring `LocalLoop::write_holder`), with a `schema_version`. Carries:
`fc_pid` + `fc_starttime` (captured from the **same** `/proc/<pid>/stat` read), `ip`, `tap`, `mac`,
`loop_dev` + the data-disk `lease_epoch`, `base_rootfs_hash`, `deployment_version`, the metadata/layer
paths. **Strict parse:** any partial/garbage/`schema`-unknown/`starttime==0` record ⇒ treated as **no
record** (reap + cold-boot) — never the `LocalLoop` "starttime 0 ⇒ PID-only liveness" fallback (that
fallback is what defeats PID reuse; re-adoption must not inherit it). Removed on **every** teardown
path, tied to the same locked section that clears `disk_tokens`: `hibernate_project` (**first**, before
the pause — see §6), `force_stop_and_cleanup`, `self_fence_project`, `handle_teardown`, the redeploy
`old_vm.stop()`, and the wake-abort-on-deleted-project path.

### 4. `adopt_or_reap_runtime_vms` — one reaper, a superset of both old ones
Replaces **both** `rootfs_cas::reap_orphan_firecrackers` (main.rs:1111) **and**
`reap_orphan_firecrackers_on_boot` (main.rs:1517) — the latter's blunt `pkill -9 -f firecracker…` must
be deleted (it would SIGKILL every survivor right after adoption). The new pass:
1. **Enumerate ALL runtime FCs** by `--api-sock` under `run/` (like the old targeted reaper) — not a
   per-`handoff.json` loop. An FC with no valid handoff (crash between spawn and handoff-write; the
   lost `kill_on_drop` start-error backstop) is a true orphan.
2. For each, find its `handoff.json`. **Verify survivor:** `fc_pid` alive **and** `/proc/<pid>/stat`
   field-22 starttime matches the record **and** the **agent HTTP layer answers** (`agent_alive`,
   main.rs:3838 — NOT the bare FC api-sock, which a *paused* FC still answers) **and** the FC socket's
   `SO_PEERCRED` peer pid `== fc_pid`. Any failure ⇒ not a survivor.
3. **Survivor → adopt** (§5). **Non-survivor / no handoff → reap** by verified `fc_pid` (SIGKILL +
   confirm death) and delete only `handoff.json` — **never** the `LocalLoop` `{id}.holder` (leaving the
   holder lets a later `attach_rwo` run its fail-closed preempt; deleting it makes `attach_rwo`
   fail-*open*). Add an explicit cgroup/pid reap on every `VmInstance::start`/`restore_from_snapshot`
   error path to replace the dropped `kill_on_drop` backstop.

### 5. Re-fence without disturbing the live disk (`adopt_writer`)
For a verified survivor:
1. **Re-acquire the lease:** the old process's `flock` released on its exit, so `lease.acquire(project)`
   succeeds with a **fresh monotonic epoch** (epoch+1, `flock_lease.rs:124`).
   - **If `LeaseHeld`:** on single-host this means a **second live `jkbase-server`** legitimately owns
     the disk. **Do NOT adopt and do NOT kill** the survivor — refuse this project and abort startup
     loudly (a second live server is a misconfiguration for an operator to resolve, never for one
     instance to "fix" by SIGKILLing the other's tenant VM). [Review inverted the original "kill on
     LeaseHeld".]
2. **`adopt_writer(id, token, loop_dev, fc_pid)`** — a NEW `LocalLoop` method (not `attach_rwo`, which
   would `losetup -d` the live device; not `set_writer_pid`, which rejects the higher epoch as
   `Fenced`). It must, fail-closed: (a) a **fresh kernel read** that `loop_dev` still backs
   `data-disks/<id>.img` (`losetup -j <img>` / `/sys/block/loopN/loop/backing_file`) **and**
   `fc_pid` actually holds it (`/proc/<fc_pid>/fd/*` → `/dev/loopN`); (b) `fc_pid`+starttime is the live
   writer; then (c) **overwrite** the holder with the new epoch/source + `fc_pid` + its starttime + the
   *unchanged* verified `loop_dev`.
3. **Doubt-after-acquire fail-safe:** if step 2 fails for *any* reason, **release the freshly-acquired
   lease first** (`lease.release`), then kill the survivor + cold-boot. Otherwise the cold-boot path's
   own `lease.acquire` hits `LeaseHeld` against the lease this very process just took (flock conflicts
   across fds within one process — there's a repo test for it) and the project bricks.
4. Only after the lease is held + `adopt_writer` succeeded: insert `vms` (adopted), `vm_states=Running`,
   `vm_rootfs_hashes`, `disk_tokens`; `register_active_routes`. Make the commit-time `set_writer_pid`
   on the *normal* boot paths **fatal** (drop the `let _ =` at main.rs:2534/3199) so the holder is
   always FC-accurate before any handoff is written.

### 6. Startup ordering (two distinct needs — the original "before CAS-GC" was impossible)
`LocalLoop`/`FlockLease`/`PlatformState` are constructed *after* the CAS-GC, so full adoption cannot
precede GC. Split:
- **(a) Before `rootfs_cas::gc()` (main.rs:1133):** a cheap scan of `run/*/handoff.json` unions every
  live survivor's `base_rootfs_hash` into the GC `keep` set. Without it, an upgrade mints a new
  `current_hash` and the survivor's old (snapshot-less) blob is unlinked. *(Review note: this is
  durability-contract/churn hygiene, not a crash — `gc` `unlink`s and the live FC holds the rootfs fd,
  so the inode's bytes are untouched; but the survivor's next hibernate would stamp a missing blob →
  forced cold-boot. Worth doing; not a brick.)*
- **(b) After `PlatformState` is built and before the proxy bind (main.rs:1523) AND before
  `scheduler_loop` (main.rs:1550)** — the only wake-capable paths — run the full
  `adopt_or_reap_runtime_vms` (verify + re-fence + state rebuild), synchronously. Everything else at
  startup (`cleanup_orphans`, `reconcile_orphans_on_boot`, `backfill_domains`) is non-booting and must
  be made survivor-aware (§7).

### 7. Don't let the boot reconcilers undo the adoption
- **`backfill_domains` (main.rs:2149)** unconditionally `vm_states.insert(id, Hibernated)` + flips redb
  `ProjectState` for every wakeable project → it clobbers an adopted `Running` survivor. Downstream,
  the `== Running` filters silently break: metering stops billing (4120), log-shipping stops (3342),
  idle never hibernates it (3285), and a real shutdown's drain skips it (1693). **Fix:** skip any
  project already `Running`/in `vms`; guard the `NeedsRedeploy` flip against a live survivor.
- **`cleanup_orphans` (main.rs:1718)** TCP-probes `:80` and reaps `VmAllocation`+TAP on a 2s miss →
  could sever a momentarily-slow adopted survivor. **Fix:** skip projects adopted `Running` this start
  (adoption already proved liveness via the agent probe).
- **`reconcile_orphans_on_boot`** must likewise skip live survivors.

### 8. Conditional drain (upgrade vs shutdown), hardened flag
`shutdown_signal` hibernates on a real shutdown, leaves VMs on an upgrade. Gate on
`/var/jkbase/.upgrading` written by `deploy-server.sh` immediately before `systemctl restart`. Harden:
the flag carries a **timestamp** (+pid); `shutdown_signal` honors "skip hibernate" only if it is
**fresh** (e.g. < a few minutes) — a stale flag (deploy crashed after touch, before restart) then
correctly falls back to hibernate instead of silently leaking running tenants on the next operator
`stop`. `deploy-server.sh` `trap`s to remove the flag on its own failure; the new server clears it once
adoption completes. **§6 ordering still removes `handoff.json` first on hibernate**, so even a SIGKILL
mid-drain can't resurrect a paused VM.

### 9. Agent protocol skew
§ keeps survivors on the **old** agent; the new server keeps talking to them over unversioned :80
endpoints (`/_jkbase/health`, `/logs?since=`, `/sync`, `/resync-clock`). A deploy that ships a breaking
agent-protocol change AND re-adopts old agents would silently break log-shipping / hibernate-flush /
clock-resync until each survivor cold-cycles. **Fix:** probe an agent protocol version at adopt time;
on skew, **force-recycle** the survivor (hibernate→cold-boot) instead of re-adopting. Operationally, a
protocol-breaking deploy should simply omit the `.upgrading` flag (drain instead of re-adopt).

### 10. Misc
- **Quota gate at adopt:** if `get_quota_status(id).bandwidth_blocked`, hibernate-on-adopt / don't
  register routes, instead of serving an over-quota survivor until the metering loop re-detects it.
- Metering is safe as-is: `SamplerState` is heap-only and `cpu_delta` reseeds on first sight; same
  `fc_pid` ⇒ at most one lost interval, never double-billed.

## Threat-model invariants (load-bearing)
- **Never two writers on a data disk.** Single-host: during the gap the old flock is released and
  nothing else attaches (the new server isn't up). The survivor keeps its loop fd; the new server
  re-pins under a higher epoch via `adopt_writer` **without detaching**, gated by a fresh kernel
  loop-backing read + `fc_pid` fd proof + starttime pin. Adopted `stop()` is synchronous-to-death, so
  no caller `detach`es a loop a live FC still writes. `LeaseHeld` ⇒ refuse + abort (a peer owns it),
  never kill.
- **No unfenced run.** A VM is inserted `Running` only after the lease is held AND `adopt_writer`
  succeeded; any doubt ⇒ release lease, kill, cold-boot.
- **PID reuse** is defeated by the starttime pin (same mechanism `LocalLoop` already uses), captured in
  the same `/proc` read that proves liveness; `SO_PEERCRED` binds the socket probe to `fc_pid`.
- **Guest cannot forge identity:** adoption is keyed entirely by host-written state at host paths the
  guest cannot reach; a guest crashing its own FC only fails its own liveness check → its own project
  cold-boots.

## Out of scope (named follow-ups)
- **Phase 2 — proxy/TLS socket hand-off** (systemd socket activation / `SO_REUSEPORT`). Without it,
  re-adoption keeps tenant VMs up but clients still see a ~1–2s connection-refused window during the
  swap.
- Host-reboot survival; HA/multi-node re-adoption (needs the cluster lease, not flock).

## Validation plan (next session, before any prod deploy)
1. On-box: boot a real VM in `jkbase-runtime/<id>`; `systemctl restart` with the upgrade flag; assert
   **FC pid unchanged**, disk re-fenced (new epoch, same loop, same writer), route back, app serves 200
   **without a reboot**; then a *flagless* restart still hibernates.
2. Negative: kill the FC during the gap → reap + clean cold-boot. Paused-mid-hibernate SIGKILL →
   handoff already gone → treated as orphan → cold-boot (no resurrected paused VM). PID-reuse probe.
   Double-adopt idempotency (run startup twice). A second live server → `LeaseHeld` → refuse+abort, the
   peer's VM untouched.
3. Adversarial multi-agent review of the implemented fence path before merge.

## Review outcome (design v1 → v2)
A 6-dimension adversarial review (+ an independent verify pass per high-severity finding) of v1
returned **"needs rethink."** v2 folds in every CONFIRMED finding:
- **BLOCKER:** the unnamed blunt `reap_orphan_firecrackers_on_boot` pkill (→ §4, deleted/folded).
- **CONFIRMED HIGH:** `backfill_domains` clobbering `Running` (§7); adopted `stop()` must be
  synchronous-to-death + `pid()`/`Drop` re-implemented (§2); the doubt-after-acquire lease self-deadlock
  (§5.3); the inverted `LeaseHeld` fail-safe — refuse, don't kill a live peer's VM (§5.1); the
  paused-FC-resurrection via an api-sock-only liveness probe (→ agent HTTP probe + handoff-removed-first,
  §4/§6/§8); `adopt_or_reap` must be a catch-all superset, not handoff-only (§4); the `systemd-run
  --scope` resident-wrapper hazard (→ raw cgroup, §1).
- **REFUTED / reseverity'd by the verify pass (kept as hardening):** the CAS-GC "crash" claim — `unlink`
  ≠ in-place rewrite, FC holds the rootfs fd, so reaping the blob is non-destructive (→ kept as keep-set
  hygiene, §6a, not a brick); the `adopt_writer` "creates a second writer" claim — it spawns no FC, the
  survivor is already the sole writer (the holder-rewrite *mechanics* in §5.2 are still required); the
  loop-backing "sole corruption barrier" — unreachable single-host once the starttime liveness check is
  implemented (kept as a fresh-kernel-read hardening, §5.2).
- **MEDIUM (folded):** atomic/strict `handoff.json` (§3); `adopt_writer` epoch/holder mechanics (§5.2);
  the 3-point cgroup provisioning wiring (§1); the `.upgrading` stale-flag freshness (§8); agent
  protocol skew (§9); `cleanup_orphans` severing a survivor (§7); over-quota adopt (§10); `SO_PEERCRED`
  socket binding (§4).
