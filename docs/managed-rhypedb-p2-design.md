# Managed RhypeDB — P2: Dedicated DB VM — implementation plan

Status: **PLAN / awaiting review** (2026-07-07). P0 (boot DB in app VM) + P1 (GA) are DONE + live on
prod. This is the grounded P2 plan, mapped against **current** code (the parent design doc
`managed-rhypedb-design.md` §6/§7 line refs are ~2 weeks stale). Threat model unchanged: **all
tenants untrusted**; every new host/guest seam is probed for cross-tenant bypass.

P2 done-state (parent doc §7): *App VM reaches its sibling DB VM; DB VM runs lean (~512–1024 MiB);
noisy-neighbor isolation; rule-cardinality assertion passes.* P2 is the **safety substrate that must
land before any untrusted client (P5)** touches the engine, and it recovers the density the second VM
costs (per-role sizing).

---

## 1. Three findings that reframe the parent design

Ground-truth recon (three parallel code maps, 2026-07-07) changed three load-bearing assumptions:

### F1 — The `project_id:db` composite key is IMPOSSIBLE as written → use **additive identity**
The data-disk + lease providers reject any id containing `:` — allowed bytes are `[A-Za-z0-9._-]`
only (`crates/jkbase-substrate/src/localloop_disk.rs:95`, `ceph_rbd.rs:51`, error `"must be a plain
id"`; the id is used verbatim as `{id}.img` and lease `{scope}.lock/.epoch`). So the parent doc's
`project_id:db` key **fails outright** at the disk fence.

**Decision (recommended): additive identity, App renders to the bare `project_id`.**
Introduce `VmKey { project_id: String, role: VmRole }` where `VmRole ∈ {App, Db}` and a single
render fn:
```
fn vm_id(&self) -> String { match role { App => project_id.clone(), Db => format!("{project_id}.db") } }
```
Because `.` is validator-legal and the **App role renders to the unchanged bare `project_id`**, every
existing redb row (`VM_ALLOCATIONS`, `SNAPSHOTS`), on-disk path (`snapshots/<id>`, `run/<id>`,
`hosting/<id>`), cgroup leaf, disk `{id}.img`, and lease scope stays **byte-identical** — **zero
migration** for the entire existing fleet. The DB VM is purely additive: a new `…​.db` keyspace that
never existed before. **Collision-proof by construction:** `is_valid_project_id` restricts ids to
`[a-z0-9-]` (no `.` — `api.rs:1242`), so a `.db`-suffixed id can NEVER equal a real project id — the
`.` is a namespace escape tenant ids can't reach. No project-name guard needed.

### F2 — Direct intra-project L2 is a rewrite and NOT needed → **host-mediated reach**
Cross-tenant isolation on `jkbr0` is enforced by **L2 bridge port-isolation** (`isolated on`,
`main.rs:4354`), which is *binary per-port* and drops isolated↔isolated **before** any ebtables
ACCEPT runs. There is **no** existing intra-bridge FORWARD-accept and no "isolated-except-peer"
primitive. Opening a *direct* app↔DB L2 path would mean a bridge-VLAN-per-project re-segment or
inverting the isolation model to ebtables-default-drop — a large, cross-tenant-critical rewrite.

**It is unnecessary.** The host↔DB **splice seam already exists and is host-mediated**:
`do_db_query`/`agent_db_request` dials `vm_ip:80` → agent `handle_db_splice` (x-jkbase-db-secret
gate) → `127.0.0.1:4201` (`main.rs:4013-4090`, agent `main.rs:1108-1137`). The host is a
non-isolated bridge endpoint that can reach **every** VM's eth0, so a host-mediated app→DB path
sidesteps port-isolation entirely. The DB reach plane (`db_ingress.rs`) *already* wakes a VM and
dials its agent — today it resolves to the app VM; P2 points it at the DB `VmKey`'s IP.

**Decision (recommended): P2 reach = host-mediated, reusing the splice seam.** The in-guest app
reaches its DB via its *own* agent on loopback, which proxies to the host, which dials the DB VM's
agent. Cost: one host hop on the DB hot path (acceptable; the console/backup plane already pays it).
Direct-L2 for perf is a deferred, separately-designed follow-up — NOT in P2.

### F3 — The DB boot machinery + reach plane are ~80% role-agnostic already
`VmConfig`/`MachineConfig`/`VmInstance::start` are fully role-agnostic (sizing is caller-supplied).
`ContainerSupervisor::start_database`/`db_manifest`/`spawn_server_layered`/health loop, the
`compute_layer_plan` `database` overlay (`layer_plan.rs:350`), the `_database.json` + `_database/`
staging, the data-disk fence + `data_disk_mib_for` (already per-project via `_database.json`), and
the secret-mint + `_db_reach.json` pipeline all carry over. What **bakes co-location**: the
`127.0.0.1:4200/4201` listen (`container_supervisor.rs:104,106`), the shared `/mnt/data`, both
app+DB reach-facts riding one metadata image, and the app's implicit-loopback DB address.

**Net reframe:** P2 is primarily a **VM-lifecycle/bookkeeping** arc (thread `VmKey` through the maps,
tables, paths, reap/re-adopt/metering) + per-role sizing, with reach as an *extension of existing
host-mediated seams*. This is materially lower cross-tenant risk than the parent doc's L2 approach.

---

## 2. Decomposition (three session-sized cards + a config prelude)

### Prelude — `[database]` tier + DB compute knobs (`jkbase-common`)
`DatabaseConfig` (`config.rs:561-581`) has `engine/schema/rules/size` (size = **data disk** only);
**no `tier`, no VM mem/vCPU**. Add:
- `tier: Option<String>` → `DatabaseTier ∈ {Colocated (default), Dedicated}` (reject-unknown,
  mirror `DatabaseEngine`). **Opt-in** — co-located stays the default so the entire GA fleet is
  untouched; a project opts into a sibling VM.
- DB VM compute floor (host-default, not necessarily tenant-set): ~512–1024 MiB / 1 vCPU
  (RhypeDB runs lean with ONNX dropped; +~80 MB only when a `@vectorize` field exists). Surfaced in
  `_database.json` so the host sizes the DB VM.

### P2a — Per-role VM sizing  *(LOW risk, self-contained)*
Today every runtime VM is a hardcoded **3072 MiB / 4 vCPU** at four sites that MUST stay mutually
consistent (mem snapshot won't map otherwise): deploy `main.rs:2872-2873`, wake `main.rs:3487-3488`,
hibernate `SnapshotMeta` `main.rs:3196-3197` (build VM 4096/4 at `main.rs:1501-1502` — untouched).
- Thread a per-`VmKey` size (a `VmSize{vcpu,mem_mib}` resolved from role + `_database.json`) through
  the deploy/wake/hibernate trio. `SnapshotMeta` already carries `vcpu_count`/`mem_size_mib`, so
  restore reads the size back — the consistency invariant is already structurally supported.
- Lean-boot is already proven at the orch layer (512/1 in `layered_runtime_smoke.rs:181`) and DB
  smokes boot a runtime VM at 1024/2 (`build_orchestrator.rs:5648`).
- Ships independently of P2b (also right-sizes app VMs), but its density payoff is realized only
  once a second VM exists.

### P2b — Dedicated DB VM lifecycle (`VmKey` threading)  *(HIGH effort, the core)*
Introduce `VmKey{project_id, role}` and thread it through, **additively** (App renders to bare id):
- **5 in-memory maps** re-keyed `HashMap<VmKey,_>`: `vms`, `vm_states`, `vm_rootfs_hashes`,
  `wake_failures`, `disk_tokens` (`main.rs:844-876`); every get/insert/remove (deploy 2916-2929,
  wake 3700-3711, re-adopt 5190-5194, + ~40 lookup sites) passes a `VmKey`. A project now holds
  **two independent `VmLifecycle` entries**.
- **2 redb tables**: `VM_ALLOCATIONS` (`store.rs:9,733`) + `SNAPSHOTS` (`store.rs:13,834`) keyed by
  the rendered id. App rows unchanged (bare id); DB rows are new `…​.db` keys. `next_free_octet`
  already dedups by `ip`, so a second allocation row per project just consumes the next octet.
- **On-disk paths** all key off the rendered id (`snapshots/<id>`, `run/<id>`+FC sock+`handoff.json`,
  `hosting/<id>`, cgroup `<RUNTIME_CGROUP_PARENT>/<id>`). Re-adoption reconstructs identity from the
  `run/<id>` path segment + `handoff.json` `read_strict` equality (`main.rs:5004`, `handoff.rs:88`)
  → the `…​.db` id must round-trip one path component (it does; no `:`/`/`).
- **reap / force-stop** anchor on the run-dir segment (`reap_firecracker` `main.rs:4610`, pkill
  `/{id}/firecracker\.sock` `main.rs:4618,5272`) → per-`VmKey`.
- **Loops**: idle reaper (`main.rs:3777`), metering (`main.rs:5466`), log shipper (`main.rs:3857`),
  shutdown drain (`main.rs:1948`), reconcile/placement — each enumerates two `VmKey`s per project.
- **Fence:** `fence_data_disk`/`ensure`/`attach_rwo`/`detach` take the rendered id; the DB VM fences
  its **own** RWO disk (`{project_id}.db.img`) — the P0-DB-1 host-never-mounts invariant is inherited
  verbatim. **Blocker retired by F1** (the `.db` suffix is validator-legal).
- **SnapshotMeta.deployment_version gate**: a DB VM's restore-validity is independent of the app
  deploy version → the version gate (`snapshot_restore_decision` `main.rs:3323`) must fork per role
  (DB snapshot is valid across app redeploys as long as the data disk + schema are compatible).

### P2c — Reach: point the DB plane at the DB VM + give the app a path  *(SECURITY-sensitive)*
- **DB reach/query/backup plane → DB `VmKey`.** `db_ingress.rs` wake + `connect_agent`
  (`:242,:271`), `do_db_query`/`agent_db_request`, and the backup relay currently resolve `vm_ip` via
  `wake_project(project_id)` = the app VM. When `tier=Dedicated`, resolve to `wake(VmKey{_,Db})` = the
  DB VM's IP. `DbRelayRegistry` keying + `conn_count` become role-aware.
- **App→DB (new leg):** the DB now binds the DB VM's eth0 (not loopback), gated by the splice
  secret on the app leg too (preserve "no unauthenticated reach"); the app reaches it via its own
  agent → host → DB VM (host-mediated, F2). The app agent needs the DB endpoint injected (no such
  field today — add to the app VM's `_db_reach.json`).
- **Deploy-time cardinality assertion** (parent doc threat #1, adapted): assert exactly one DB
  `VmAllocation` per project and that the DB VM's `{tap,ip,mac}` source-guard rules exist — since we
  are NOT opening L2, the assertion is over the reach seam (one DB VmKey, splice-gated), not an
  ebtables pair-accept.

---

## 3. Landmines (persisted / on-disk / wire — not just a HashMap re-key)

1. **Disk/lease validator forbids `:`** — retired by F1's `.db` suffix; do NOT reintroduce `:`.
2. **redb keyspace** — App keys unchanged (additive), so no migration; but any code that *lists* a
   table and assumes "one row per project" (metering rollup, reconcile) must tolerate the `…​.db` row.
3. **Re-adoption / pkill reconstruct identity from a path segment** — the `…​.db` id must survive one
   path component and `handoff.json` `read_strict` (`project_id == id`); `HandoffRecord.project_id`
   likely needs a `role`/rendered-id field so a DB survivor re-adopts as a DB VM, not an app VM.
4. **Metering/quota semantics** — DB VM CPU/bw/warm-seconds are a *second* pid/tap under the same
   project; usage rows keyed by rendered id keep them separate (bill/display rollup is a product
   choice — see §4).
5. **Single `ProjectState`** (`store.rs:126`) + one `VmLifecycle` assumption — a sibling DB VM has an
   independent lifecycle the current per-project state model can't represent; the DB VM's up/down must
   not clobber the app's `ProjectState`.
6. **Hibernate/restore size consistency** (P2a) — the DB VM's snapshot size must match its restore
   size; keep them both sourced from the same per-role `VmSize`.

## 4. Open decisions for Joe (recommendations inline)

1. **Dedicated: opt-in tier, or default for all `[database]` projects?**
   **Rec: opt-in `[database] tier="dedicated"`.** Co-located stays the default (GA fleet untouched,
   density preserved); a project opts in for noisy-neighbor isolation / the untrusted-client path.
   Parent doc OPEN DECISION 1 favors dedicated-eventually; incremental opt-in is the safe ship and a
   strict superset. (Untrusted-direct-client, P5, will *require* dedicated regardless.)
2. **Identity separator** — `{project_id}.db` (recommended; validator-legal, App unchanged) vs a
   `VmKey` struct serialized elsewhere. Rec: the `.db` render + a `VmKey` type in memory.
3. **Metering rollup** — bill the DB VM as a separate line, or fold into the project's usage? Rec:
   separate rows (visibility), rolled up in console/CLI display.
4. **IP budget** — dedicated consumes a 2nd octet → ~126 dedicated-DB-projects/host (co-located
   projects still 1 octet). Acceptable at current scale; revisit with a /23 or per-host islands if
   dedicated adoption is high. No action for P2 beyond a `log()` when the octet pool crosses a
   threshold.
5. **DB VM compute floor** — 512 vs 1024 MiB / 1 vCPU default. Rec: 1024/1 default (proven boot),
   512/1 as a future lean tier; `@vectorize` schemas may need +.

## 5. Threat-checklist delta vs parent doc §8

- **#1 cross-tenant DB reach** — reframed: since P2 does NOT open L2 (F2), the defense is the
  host-mediated splice seam (splice-secret + eth0-gate, already adversarial-reviewed for the reach
  plane) pointed at the DB VM, NOT an ebtables pair-accept. No new bridge rule = no new L2 bypass
  surface. The cardinality assertion moves to "exactly one splice-gated DB VmKey per project."
- **#6/#7 single-writer / data-disk fencing** — inherited verbatim; the DB VM fences its own RWO
  disk (`{project_id}.db.img`) under the same P0-DB-1/2 invariants.
- **#2 egress** — the DB VM is a runtime VM → inherits the SSRF/metadata DROP + IPv6-off
  (`setup-bridge.sh:66-94`, `main.rs:4371`) automatically; a managed DB needs no outbound except the
  object-store host for backup staging (already default-deny except that).
- **`…​.db` identity collision — CLOSED by construction** — `is_valid_project_id` forbids `.`
  (`api.rs:1242`), so no real project id can equal a `.db`-suffixed one. No guard needed.
- **NEW: DB survivor re-adopts as the wrong role** — `handoff.json` must carry the role so a boot
  re-adoption can't restore a DB VM as an app VM (or vice-versa).

## 6. Grounded file:line index (current, 2026-07-07)
- VM maps + insert/lookup: `crates/jkbase-server/src/main.rs:843-888` (deploy 2916-2929, wake
  3700-3711, re-adopt 5190-5194); `VmInstance` `crates/jkbase-orch/src/vm.rs:39-49`.
- Sizing literals: `main.rs:2872-2873` (deploy), `3487-3488` (wake), `3196-3197` (hibernate meta),
  `1501-1502` (build); `MachineConfig` set `vm.rs:143-146`; `DATA_DISK_MIB` `main.rs:891`,
  `data_disk_mib_for` `main.rs:4819`.
- Allocation: `VmAllocation` `crates/jkbase-control/src/store.rs:139-156`, `allocate_ip`
  `main.rs:950`, `next_free_octet` `main.rs:968`, `slot_identity` `main.rs:4432`, save `store.rs:728`.
- Snapshots: `SnapshotMeta` `store.rs:95-123`, table `store.rs:13`, dir `main.rs:3106`,
  `snapshot_restore_decision` `main.rs:3323`.
- Fence: `fence_data_disk` `main.rs:4710`, `FenceToken` `crates/jkbase-substrate/src/lib.rs:143`,
  plain-id validators `localloop_disk.rs:92-95` / `ceph_rbd.rs:48-51`, disk file
  `localloop_disk.rs:129`, lease files `flock_lease.rs:48-54`.
- Networking: TAP+isolation `main.rs:4328-4396`, `JKRUN_SG` chain+rules `main.rs:4426-4525`,
  no teardown of runtime ebtables (`teardown_tap` `main.rs:4398-4413` is `ip link delete` only),
  bridge/NAT/SSRF/IPv6 `tools/setup-bridge.sh:53-132`, guest IPv6-off `crates/jkbase-orch/src/vm.rs:183`.
- DB boot: `db_manifest` `crates/jkbase-agent/src/container_supervisor.rs:69`, `start_database`
  `:302`, agent wiring `crates/jkbase-agent/src/main.rs:518-546`, ports `main.rs:1072,1175`.
- DB overlay + secrets: `compute_layer_plan` database `crates/jkbase-server/src/layer_plan.rs:350`,
  `RuntimeLayers.database` `crates/jkbase-common/src/layers.rs:50`, `_database.json` write
  `build_orchestrator.rs:2234`, secret mint `crates/jkbase-control/src/auth.rs:113,127` + store
  `store.rs:2009-2070`, `DbReachFacts` `config.rs:178-196`, bake `layer_plan.rs:445-528`,
  agent load `agent/main.rs:178,518`.
- Reach seam: host `do_db_query`/`agent_db_request` `main.rs:4013-4090`, agent `handle_db_splice`
  `agent/main.rs:1096-1137`, `db_ingress.rs:242,271`, `DbRelayRegistry` `db_relay.rs:28`.
- Config: `DatabaseConfig` `crates/jkbase-common/src/config.rs:561-581`, `size_mib` `:657`,
  `database_json` `:807`.
- Re-adoption: `adopt_or_reap_runtime_vms` `main.rs:4980`, `HandoffRecord` `handoff.rs:32`.

---

## 7. Grounded implementation seams (post-recon, 2026-07-07 — build guide)

Three full code recons (map-access inventory + reach plane + build/boot side) pinned the exact
seams. This section is the load-bearing build guide; it supersedes any earlier hand-waving.

### 7.1 The two id "flavors" (the whole threading rule in one line)
- **Base `project_id`** (`foo`) — anything that reads the *deployment / store / routes / quota*:
  `hosting/<id>/live/…`, `store.get_project`, `get_quota_status`, `list_active_domains_for_project`,
  `store.list_projects`, backups (`db-backups/<id>`). The DB VM has **no** `hosting/foo.db/` — it
  reuses the app's `hosting/foo/live/` deployment content.
- **Rendered `vm_id`** (`foo` for App, `foo.db` for Db) — anything that is *per-VM-instance*:
  the 5 in-memory maps, `run/<id>`, `snapshots/<id>`, `content-images/<id>.ext4`, data disk
  `<id>.img` + lease scope, cgroup leaf, FC api-sock, `VmAllocation` row, `handoff.json`.
- `vm_id(project_id, role)`: App→`project_id`, Db→`format!("{project_id}.db")`.
  `split_vm_id(id)`: `id.strip_suffix(".db")` → `(base, Db)` else `(id, App)`. Collision-proof:
  `is_valid_project_id` forbids `.` in real ids, and `foo-db` ends in `-db` not `.db`.

### 7.2 Builders need NO app/DB flag change for the DB VM — they're data-driven (recon B)
`compute_layer_plan` + `build_metadata_image` + the agent DB supervisor already treat "DB-only"
(a tree with `_database.json` + empty `_servers/`) as first-class: empty `_servers/` ⇒ `start_all`
starts nothing; `_layers.json.database=Some` + `_database/schema.rhype` ⇒ agent runs rhypedb-only.
Agent reach side is **loopback-only** (`handle_db_splice`→`127.0.0.1:4201`), so the DB VM's agent
needs **zero IP changes** — it splices to its own loopback given the same `_db_reach.json` secrets.

**Decision — build BOTH images from the SAME canonical `hosting/foo/live/` tree via additive
`_with(…, ImageContent)` variants** (`ImageContent ∈ {All, AppNoDb, DbOnly}`); the bare
`compute_layer_plan`/`build_metadata_image` delegate to `All` so the ~20 existing build-path/test
callers are untouched. Only the deploy path uses the `_with` variants.
- **Colocated app VM** = `All` (today's behavior, unchanged).
- **Dedicated app VM** = `AppNoDb`: app layers + app files, but **skip the rhypedb overlay and skip
  copying `_database.json`/`_database/`** — else the app agent co-locates a SECOND rhypedb → two
  writers / split-brain (FATAL). `_db_reach.json` is orthogonal (gated by the `db_reach` arg), so
  the app VM still gets reach facts (splice secret + the DB VM endpoint) for the app→DB leg.
- **Dedicated DB VM** = `DbOnly`: rhypedb overlay + `_database.json`/`_database/` only; no app
  layers/files/secrets (avoids copying big site trees into the DB image).

`_database.json` stays in `hosting/foo/live/` for BOTH tiers (keyed by base id), so
`check_project_has_database` / `data_disk_mib_for` work unchanged. App-VM `has_disk` when dedicated =
`has_volumes || disk.exists` (NOT `has_database`) — the app isn't forced a disk for a DB it doesn't host.

### 7.3 Reach seams (recon A) — 4 IP-selection sites, all resolve to the app VM today
Redirect to the DB VM's IP (`wake` the `.db` VmKey) when dedicated:
`db_ingress.rs:245` (external `:443` edge) · `do_db_query` `main.rs:4071` · `do_db_backup:3974` ·
`do_db_restore:4175`. Each then dials `(vm_ip, 80)` with `x-jkbase-db-secret`. `DbRelayRegistry`
(`db_relay.rs`) is project-keyed, no IP — but bakes "one warm VM/project"; the warm VM becomes the
DB VM. App→DB leg: bake the DB VM endpoint into the APP VM's `_db_reach.json` (new field), app
reaches it via own-agent→host→DB-VM (host-mediated, F2), splice-gated on the app leg too.

### 7.4 Landmine checklist (must ALL land with the boot — several are data-loss / cross-tenant)
1. **`reconcile_orphans_on_boot` `main.rs:2183`** — `registered` = base ids only; every reap site
   (content-images `.ext4` :2210, **data-disks `.img` :2243 → loop-detach + rm = DB DATA LOSS**,
   `run/snapshots` dirs :2281) must treat a `.db` artifact as registered iff its **base** is (map via
   `split_vm_id`). Without this a clean restart destroys the DB disk.
2. **`handle_teardown` `main.rs:2078`** — reap the sibling `.db` VM too (stop/reap_firecracker[dot-
   escaped]/disk_tokens/`dd.destroy(foo.db)`/`remove_vm_allocation(foo.db)`/teardown its TAP/remove
   `content-images/foo.db.ext4`+`data-disks/foo.db.{img,holder}`+`snapshots/foo.db`+`run/foo.db`),
   else delete leaks the DB VM + disk + IP.
3. **pkill dot-escape** — `reap_firecracker:4618` + `force_stop:5272` build ERE `/{id}/firecracker\.sock`;
   an unescaped `foo.db` matches `fooadb` → **cross-tenant SIGKILL**. Escape `.` in the rendered id.
4. **re-adoption `finish_adoption`/`adopt_one_survivor` `main.rs:5038-5218`** — `id` is the rendered
   path segment; use **base** for `store.get_project`/`get_quota_status`/`list_active_domains`, **skip
   route registration for Db**, keep lease/disk/maps on the rendered id. Assert role==path suffix.
5. **snapshot version-gate fork** — `SnapshotMeta.deployment_version` gate (`snapshot_restore_decision`
   `main.rs:3323`, stamped hibernate :3199 / read wake :3459) is app-deploy-version keyed; a DB VM's
   snapshot is valid across app redeploys → fork the gate per role (DB uses a DB-stable version token,
   e.g. schema/`_database.json` hash, not the app `current_version`).
6. **`HandoffRecord` role** — add `#[serde(default)] role: VmRole` (VmRole default = App). **Do NOT bump
   `SCHEMA_VERSION`** (read_strict rejects a bumped record → would bounce the whole app fleet on the
   P2 rollout); a serde-default field keeps old app records re-adoptable.
7. **DB-VM idle hibernation** — the idle loop (`main.rs:3821`) seeds every Running VM and hibernates on
   proxy silence; app→DB host-mediated queries are invisible to the proxy `ActivityTracker`, so the DB
   VM could scale to zero under an active app. Mirror the `conn_count>0` guard for host-mediated DB
   activity (or couple the DB VM's idle clock to the app VM's).
8. **metering** (`main.rs:5466`) — DB-VM cpu (`running_pids`) + bw (`allocs`) are captured under the
   `foo.db` key but the per-project roll iterates `list_projects()` (base) → dropped. Add a `.db` roll
   (`add_usage("foo.db",…)`); roll up base+`.db` in the usage GET / console (decision #3). Over-quota
   enforcement should hibernate BOTH VMs.
9. **`cleanup_orphans` `main.rs:2032`** — iterates `list_vm_allocations()` (sees the `foo.db` row);
   make the reachability probe / alloc-reap role-aware so a hibernated DB VM's alloc isn't churned.

### 7.5 Cohesion (CI `-D warnings`)
`--all-targets` compiles the lib without test code, so any `VmRole::Db` / `vm_id` / `VmSize` /
`ImageContent::DbOnly` constructed *only in tests* is dead → build fails. Everything above lands in
one reviewed branch; the first compilable unit is foundation + DB-VM boot + the §7.4 teardown/reconcile
safety (a boot that reaps its own disk is worse than no boot). Sub-commits are fine if each compiles
clean (every newly-introduced item used in non-test code by the same commit).

### 7.6 The app→DB in-guest leg (design-lock — the novel seam; NOT yet built)
**Problem.** A jkbase-*hosted* app in a **dedicated** project's app VM must reach its DB (in the
sibling DB VM) on the same `127.0.0.1:4200/4201` its tenant code already uses for the co-located
case, unchanged. The app VM (AppNoDb) has no local rhypedb, and direct app↔DB L2 is closed (F2).

**Mechanism (host-mediated, mirrors the external edge in reverse).** Three parts:
1. **App-agent loopback proxy.** When the app VM is dedicated (a flag in its `_db_reach.json`),
   the agent binds `127.0.0.1:4200` + `:4201` inside the app VM and, per accepted connection, dials
   the host DB-gateway and splices. The tenant's rhypedb-client is byte-for-byte unchanged.
2. **Host DB-gateway.** A NEW host listener on the bridge gateway `172.16.0.1:<DB_GW_PORT>`
   (internal-only; add one iptables ACCEPT for `-i jkbr0 -d 172.16.0.1 --dport <port>`, and confirm
   the SSRF DROP set doesn't cover it). Per connection: read the **peer source IP** → map to project
   via `VM_ALLOCATIONS` (the app VM's alloc row). The L2 source-guard (`install_tap_source_guard`)
   pins {ip,mac}↔TAP↔slot, so **the source IP is an unforgeable project identity** — a guest can only
   ever present its own IP, so it can only ever reach its own DB VM. Then verify the app-presented
   splice secret == that project's secret (defense-in-depth on top of the IP identity), `wake` the
   `{proj}.db` VmKey (reusing `wake_db_reach`/`wake_project`), and splice to the DB VM agent's
   `/_jkbase/db` (the same path the external edge uses).
3. **Wiring/flag.** Add `dedicated: bool` (or a `db_endpoint`) to `DbReachFacts` (serde-default), set
   on the APP VM's image when dedicated so its agent knows to start the loopback proxy. The DB port
   (`<DB_GW_PORT>`) is a constant; the gateway IP is the well-known `172.16.0.1`.

**Isolation argument (for review).** The only new externally-reachable surface is
`172.16.0.1:<port>` on the internal bridge. Its authorization is the *source IP*, which the existing
L2 source-guard makes unspoofable — so cross-tenant reach is structurally impossible (project A's VM
cannot emit project B's source IP). The splice secret is redundant defense. No new L2 path, no
routing-table entry, no internet exposure. Threat-model delta vs §5: same host-mediated splice
seam, authenticated by an already-enforced invariant.

**Why deferred from the P2c-reach commit.** It needs a new host listener + new agent listener +
firewall rule that can only be validated on the FC-capable box (cross-VM splice is not unit-testable)
— so it lands with the on-box e2e (task #20) as one focused, adversarially-reviewed unit. Until then
a dedicated project's DB is reachable via the external reach plane + console (P2c-reach), just not
from a co-hosted app on loopback.

**Not required for a functional dedicated DB v1** — the external reach plane (`jkbase db proxy`
sidecar) + console already reach the DB VM. This leg is the "full-stack-on-jkbase + dedicated DB"
convenience and the on-ramp toward P5's untrusted-client posture.
