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
