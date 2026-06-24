# Managed RhypeDB on jkbase — Design

> Status: design. Target path `docs/managed-rhypedb-design.md`. Companion to `docs/build-subsystem-design.md` and `docs/function-outbound-io-design.md`. **Threat model is load-bearing: ALL tenants AND (in the end-state) all end-users are untrusted.** Every new host/guest or gateway/engine seam below is marked `P0-…`.

## TL;DR

- **Topology: one dedicated RhypeDB instance per project, in its own Firecracker microVM, on its own RWO data disk.** RhypeDB is structurally instance-per-DB (`AppState.db: ArcSwap<Database>` is one schema/one dir — `rhypedb-server/src/lib.rs:114`), and co-tenanting two projects in one process would put cross-tenant authz inside an engine that has none. VM-per-DB is the only posture that holds against hostile end-users.
- **Ship in two products, not one.** **v1 = "managed RhypeDB for your own backend"** (app→DB over loopback/intra-project, no end-user identity) ships now and delivers value. **End-state = Firestore-style direct-from-untrusted-client** is a long pole gated behind a *prerequisite* jkbase Auth build + four in-engine RhypeDB changes.
- **v1 runs the DB co-located in the project's existing app VM** (second supervised process bound to `127.0.0.1:4200`, persisted on the existing RWO disk) — zero new VMs, zero new host/guest seam, near-zero RhypeDB change. The **dedicated DB-VM split** (`project_id:db` composite key + intra-project L2 + per-role sizing) lands at the MVP boundary, before any untrusted client can reach the engine.
- **The single biggest dependency/risk:** **jkbase has no end-user identity system, and RhypeDB has no per-caller authz or rules layer.** The Firestore differentiator (client-side security rules keyed on `uid`/claims) cannot exist until *both* are built — a per-project EdDSA-JWT issuer + offline JWKS on the jkbase side, and a verified-principal hook + default-deny declarative rules evaluator + query governor + WebSocket subs *inside RhypeDB*. The host cannot interpose on any of the last four without parsing the guest's query protocol.
- **Scale-to-zero already fits** — hibernate is Pause+snapshot+SIGKILL with no SIGTERM to the guest (`jkbase-orch/src/vm.rs:243-255`); RhypeDB must (and does claim to) treat Pause as a crash and replay WAL on resume. *Correction to recon:* RhypeDB **does** ship a SIGTERM-flush handler (`rhypedb-server/src/lib.rs:848-879`), but jkbase never delivers SIGTERM on the hibernate path, so the flush path is dead on that route — crash-recovery is the load-bearing one and must be snapshot-fuzzed before prod.
- **The data disk is the one durable thing and it does NOT roll back with code** (RWO disk keyed per-project not per-version; rollback only repoints the `live` symlink — `api.rs:do_rollback`). This is already correct; the guard is RhypeDB's fail-closed schema-shrink refusal on a code-rollback against a forward-migrated disk.
- **DoS is the sharp edge for any untrusted-client tier:** `.limit()`/`k` are uncapped and unindexed predicates fall to a full `scan_all_objects` (`rhypedb-query/src/executor.rs:546-560,1162-1164`); only vector `ef`/pool are clamped (`executor.rs:583,649,662`). A query governor is a **hard gate** before direct clients — it must land in-engine.
- **Reuse the proven object-store product template** (reserved-host short-circuit → owner-scoped `_console` Bearer JSON API hosted on the data service, credential→tenant→current-owner re-bind, fail-closed quota with TTL re-walk, lifecycle reapers, metering loop) for the console DB tab and CLI — but the DB is **stateful per-VM**, so it uses the proxy's on-demand-wake path, not a stateless loopback service.

---

## 1. Product shape

### v1 — "Managed RhypeDB for your own backend" (the shippable MVP)
A managed, scale-to-zero object database, provisioned by one `jkbase.toml` stanza, reachable **only by the tenant's own app/function** (server-side, trusted-by-the-tenant). No end-user identity, no client-side rules. This is "managed Postgres-shaped, but RhypeDB": relationships + native vectors + realtime subs for *your backend*. It is a strict subset and clean upgrade path to the end-state — nothing here is throwaway.

This matches RhypeDB's actual current contract: the data plane is a single trusted caller (`/query` and the TCP listener are explicitly unauthenticated — `lib.rs:805-813`, `lib.rs:1157`), which is exactly correct when the only caller is the tenant's own code inside its own trust domain.

### End-state — Firestore-style direct-from-client
Untrusted browsers/mobile clients talk to the DB directly over `db.{project}.jkbase.app`, authenticated as **end-users** (not the project owner), authorized by **declarative security rules** that reference the authenticated subject and document fields, with realtime subscriptions over WebSocket. This is the headline differentiator and the long pole.

### Deliberately deferred
- **In-process multi-tenancy** — impossible without forking RhypeDB (`AppState.db` is one DB) and an unacceptable blast radius anyway. Rejected permanently.
- **A shared multi-*process* "free tier" supervisor** — see OPEN DECISION 1. Default recommendation: **do not build it**; recover density via per-role VM sizing instead.
- **Raw TCP / binary-protocol ingress to untrusted clients** — the edge is HTTP-only (`hyper http1::serve_connection`, no L4/SNI passthrough). Untrusted clients use HTTP `/query` + WS subs. The binary TCP protocol stays intra-VM/server-side only.
- **wasi:sockets-style direct DB access from WASM functions** — deferred behind the existing function outbound-I/O §8 gate; functions reach the DB the same way the app does (intra-project HTTP).

---

## 2. Architecture

### 2.1 Topology — where the DB runs

| Phase | DB location | App→DB transport | Why |
|---|---|---|---|
| **v1 (P0–P1)** | Second supervised process **inside the project's app VM**, bound `127.0.0.1:4200/4201`, data on a `/mnt/data/rhypedb` volume of the existing RWO disk | loopback (`@rhypedb/client` server-side, unchanged) | Zero new VM/IP/snapshot; **zero new host/guest seam**; loopback-inside-one-VM *is* RhypeDB's single-trusted-caller model. The agent's `ContainerSupervisor` already starts N servers with bind-mounted persistent volumes from `/mnt/data` (`jkbase-agent/src/container_supervisor.rs`). |
| **MVP boundary onward (P2+)** | **Dedicated sibling DB VM** per project (`project_id:db` composite key), own RWO data disk, own allocated octet/tap | intra-project L2 (scoped ebtables FORWARD) or, for untrusted clients, edge `db.` host | Noisy-neighbor isolation; required posture before any untrusted end-user can reach the engine (a compromised app must not share the DB VM with the request-handling tier — though same tenant, the dedicated split is what unlocks per-role sizing + the gateway). |

The boot primitive is already role-agnostic: `VmInstance::start` takes a `VmConfig` with its own rootfs/layers/data-disk/tap/mac/ip (`jkbase-orch/src/vm.rs`). A DB VM is a new `VmConfig` with a rhypedb runtime layer. The blockers for the dedicated split are **bookkeeping** (composite key) and **IP budget** (252 octets/host → two VMs/project halves max projects to ~126; mitigated by per-role sizing).

### 2.2 Isolation & the P0 invariants

- **P0-DB-1 (host never mounts/parses the data disk).** The RWO ext4 disk is preallocated and **read-write-once fenced**: lease-acquire → `attach_rwo` → record the Firecracker PID as the single writer (`main.rs:2696-2802`, `fence_data_disk` `main.rs:3271`). The host moves opaque blobs only (sha256-verified, via `debugfs`, never a mount). RhypeDB owns its LSM/WAL/HNSW files on the guest side. This is inherited unchanged and is the single most important invariant.
- **P0-DB-2 (single writer per data dir, defense-in-depth in-guest).** RhypeDB layers its own `flock(LOCK_EX|NB)` + 128-bit owner-fence token *inside* the already-single-writer disk, fail-closed on overlay/network FS (`rhypedb-storage/src/lock.rs:10-29`). Two writers on one dir corrupt the LSM silently; the host RWO fence + the guest flock are belt-and-suspenders.
- **P0-DB-3 (no cross-tenant L2 reach).** Both runtime TAPs sit on `jkbr0` with **port-isolation ON** (`main.rs:2948-2959`) + per-TAP ebtables source-guard pinning `{MAC, IPv4-src, ARP-src}` (`main.rs:2970-2985`). The dedicated split needs an **intra-project** FORWARD-accept scoped to *exactly the project's two pinned `{tap,ip,mac}` pairs* — never a bare TAP-name or subnet rule. See §9 threat #1.
- **P0-DB-4 (DB VM inherits the runtime egress posture, default-deny outbound).** A persistent DB VM is a runtime VM (KVM + Firecracker seccomp, **not** jailed — same posture as app VMs; the jailer is build-VM-only). It must inherit the runtime SSRF DROP to host/metadata + IPv6-off (`main.rs:2960-2967`). A managed DB has **no legitimate outbound need** except the object-store host for backup staging → default egress-deny except the pinned storage host.
- **P0-DB-5 (gateway/engine trust seam — end-state only).** When untrusted end-users reach the engine, the gateway is the *only* trusted token-verifier; RhypeDB must trust **only** an HMAC-signed internal principal header from the gateway, never a raw client token, and reject any client-supplied principal header at the gateway boundary. See §4.

### 2.3 Connection model

**Two ingress classes, both HTTPS-terminated at `jkbase-proxy` over the wildcard `*.jkbase.app` cert.** The whole edge→agent→app path is HTTP/1.1 today.

- **App→DB (v1, in-project, trusted-by-tenant):**
  - *v1 co-located:* loopback `http://127.0.0.1:4200/query`. Nothing on the bridge can reach it; the agent does not route `:80` to it.
  - *dedicated split:* the app reaches `http://{db_ip}:4200/query` over the intra-project L2 FORWARD-accept. No edge round-trip.
- **Untrusted direct client (end-state):** new **reserved host `db.{project}.jkbase.app`** → mirror the `storage.` short-circuit exactly (`jkbase-proxy/src/lib.rs:289-301` is the template: add `db_addr` to `ProxyConfig`/`SharedState`, branch on `subdomain == "db"`). The DB-gateway service terminates the end-user JWT, then proxies to that project's DB VM via the on-demand-wake path. Custom domains (`db.app.com`) get on-demand HTTP-01 certs.

  **Note:** reserved hosts bypass the per-project VM/quota/wake path, so the gateway must itself resolve host→project, wake the VM, and enforce quota — same as `objectstore_service.rs` does. This is why the DB-gateway is a real service, not a dumb local-forward.

### 2.4 Routing / TLS / realtime-subs transport

- **Routing:** v1 is invisible (loopback). Dedicated/end-state: `db.` reserved-host branch (mirror `storage.`), tenancy resolved credential/JWT→project→current-owner re-bind (the orphaned-key fix, `objectstore_service.rs:486-489`).
- **TLS:** wildcard ACME DNS-01 in memory (`tls.rs:299-367`); custom domains HTTP-01. Unchanged.
- **Realtime subs — the transport gap.** The jkbase edge *already* relays WebSocket end-to-end: `is_upgrade_request` → `relay_upgrade`/`spawn_upgrade_relay` splices client↔backend byte streams with an idle-reap + concurrency cap, preserving `Connection`/`Upgrade` on the 101 (`proxy/src/lib.rs:442-474`; `wsproxy/src/lib.rs`), and the agent runs `.with_upgrades()`. **But RhypeDB has no WebSocket route** — subscriptions are **binary-TCP-only** (`lib.rs:822-831,1157`; confirmed no `upgrade`/`websocket`/`tungstenite` anywhere in `rhypedb-server`). The ARCHITECTURE.md "HTTP+WebSocket gateway" (line 211) is **aspirational/unimplemented**. The raw binary TCP protocol **cannot** traverse the HTTP proxy. So RhypeDB must grow a **WebSocket `/subscribe` upgrade** that bridges to its transport-agnostic change hub (`rhypedb-subscribe`); then subs relay end-to-end unchanged.
  - **P0-DB-6 (sub liveness vs idle reaper).** A long-lived WS sub counts as **one** activity timestamp at open (`proxy/src/lib.rs:323-326` records per request). The per-VM idle reaper (`idle_detection_loop`, 60s poll) must treat an active spliced relay as liveness, or it hibernates a busy-but-quiet subscribed DB mid-stream. Fix: have the wsproxy relay refresh the activity tracker on byte flow, or exclude VMs with active upgrade relays from hibernation.

### 2.5 Scale-to-zero

Hibernate = Firecracker **Pause + Full snapshot + SIGKILL** (`vm.hibernate` `jkbase-orch/src/vm.rs:243-255`; the only pre-pause step is a *log* flush to the shipper, `main.rs:2471-2473`). **No SIGTERM is delivered to the guest.** Wake = `restore_from_snapshot` (paused-load → repoint data drive → resume), triggered on the first request to a hibernated VM.

This is **ideal** for RhypeDB *if* it relies on crash-recovery: the snapshot freezes RAM (memtable + HNSW mmap) and the data disk coherently, and restore thaws both — the DB never "shuts down," it's frozen and thawed. RhypeDB's design assumes "restore from WAL tail on wake" (`ARCHITECTURE.md:69,174-176,226`).

- *Recon correction:* RhypeDB **does** have a clean SIGTERM-flush path (drain → quiesce vectorizer → `storage.flush()` memtable→SST, `lib.rs:848-879`), and the recon "no clean-shutdown hook" claim conflated jkbase's behavior with RhypeDB's. The accurate statement: **jkbase never invokes it on hibernate**, so it is dead on that route. The load-bearing path is crash-recovery-from-Pause, which must be **on-box snapshot/restore fuzzed** (Pause at every WAL/memtable/compaction/vectorize-queue boundary → resume → verify integrity) before the dedicated tier ships. Do **not** add a pre-pause guest RPC unless fuzzing proves crash-recovery insufficient — that would be a new host/guest seam.

### 2.6 Persistent data disk

- The existing RWO disk is exactly the one durable thing a DB needs (`LayerPlan::empty(has_data_disk)` `layer_plan.rs:47-53`; re-fenced each wake, restore PATCHes the drive to the fenced device).
- **Default size `DATA_DISK_MIB = 1024` (`main.rs:820`) is too small for a DB.** Make data-disk size **per-role** via `[database] size`. v1 co-located shares the app VM's disk; dedicated split gets its own sized disk.
- **Disk is a free hard cap:** RhypeDB hits ENOSPC at the boundary — no host dir-walk needed, and the object-store soft-cap overshoot problem does not apply on the *bytes* axis (row/edge/vector counts are a different axis — see §5).

### 2.7 Backups to the object store

RhypeDB restore reads **local paths only** (`std::fs::copy`, `restore.rs:288-303`; no `reqwest`/`ureq`/HTTP/S3 anywhere in restore). **The platform owns blob movement** — this is fine and keeps network off RhypeDB's hot path.

- **Backup:** a metering-loop-adjacent timer calls `GET /admin/backup/stream` (gated by the host-minted `RHYPEDB_ADMIN_TOKEN`) → stage the tar to local disk → push to the **project's own object-store bucket** (reuse the own-bucket `StorageBinding`, `layer_plan.rs:21-28`).
- **Restore:** platform pulls the blob → local disk → sets `RHYPEDB_RESTORE_FROM` on next boot (`lib.rs:67-80`; idempotent across restarts).
- **P0-DB-7 (backup poisoning).** A guest that compromised its VM could write a malformed/oversized backup. Mitigations: size-cap the staged blob against the data-disk quota; restore only into the **same project bucket** (own-bucket binding) so it can never poison another tenant; treat the tar as untrusted input — **no host-side extraction/parse**, hand the blob straight to RhypeDB.

---

## 3. Identity & security rules — the hard part

### 3.1 Is a "jkbase Auth" prerequisite needed? — YES, for the end-state only

**Verdict (verified): no end-user identity system exists.** Every identity primitive in jkbase serves the **platform operator / project owner**, not the tenant app's end-users:
- `Tenant{id,email,password_hash}` + `ApiToken{tenant_id,token_hash}` — the control plane (`jkbase-control/src/auth.rs:8-23`); a "tenant" is the platform customer.
- Git-push token (`jkbg_`), object-store SigV4 access keys (bound to `tenant_id` = the owner, re-bound to the project's current owner per request — `objectstore_service.rs:482-489`), and the `_console` session Bearer — all owner/operator-scoped.
- **No signup/login for a deployed app's own users, no end-user sessions/cookies, no JWT/JWS verification, no OAuth/OIDC anywhere** (zero verification-code matches in either repo).

A Firestore-style rules layer keys on the authenticated *end-user's* subject (`uid` + claims). jkbase has no such concept, no issuer, and no token a DB could validate. **v1 does NOT need this** (app-mediated, single trusted caller). **The end-state cannot ship without it.**

### 3.2 Minimum jkbase Auth surface (offline-verifiable so the DB needs no network on the hot path)

- **Issuer service** (new, control-plane-adjacent, per-project keyed): end-user signup/login (email+password to start; federated OIDC/social import later) → mints a short-lived **EdDSA-signed JWT** `{iss=project, sub=uid, aud=project-db, exp, custom claims}`, signed by a **per-project asymmetric key**.
  - **P0-AUTH-1 (per-project keys).** Keys MUST be per-project. A global signing key lets project A mint project B's tokens. JWKS is published per-project.
- **JWKS publication** per project so the gateway/DB validates offline.
- This is a **platform primitive with value far beyond RhypeDB** (it's "jkbase Auth," reusable by functions/servers). See OPEN DECISION 4 for scope.

### 3.3 Where rules are evaluated — gateway verifies identity, RhypeDB enforces rules

Firestore rules reference **document fields** (`allow read: if resource.data.ownerId == request.auth.uid`), so a pure proxy cannot authorize without parsing the engine's data. Therefore:

- **Identity verification at the DB-gateway:** verify signature / `iss` / `aud` / `exp` / bounded clock-skew against the per-project pubkey, **fail-closed** (attacker-controlled tokens). Extract `{sub, claims}`.
- **Rules enforcement inside RhypeDB:** thread a **verified principal** into `handle_query` / `handle_tcp_connection` / the new WS `/subscribe` and into `ExecContext` (today carries none — `executor.rs:59-72`, confirmed). Add a **default-deny declarative rules evaluator** keyed on type/object/field against the principal.
- **Trust seam (P0-DB-5):** the gateway injects an **HMAC-signed internal principal header** (secret minted/rotated per deploy via the `StorageBinding`-style reserved metadata channel — `layer_plan.rs:568-571`). RhypeDB trusts only that header. Every entrypoint — HTTP `/query`, the **binary TCP handler** (the easy-to-forget one, `lib.rs:1157`), and WS `/subscribe` — must gate on a verified principal and **default-deny if absent**.
- **Admin plane** (`/admin/*`) stays on the static `RHYPEDB_ADMIN_TOKEN`, host-minted per deploy via the reserved channel, never user-visible.

### 3.4 The rules model — lean on RhypeDB's typed schema

RhypeDB's SDL is the source of truth (typed objects, typed relationships, native vectors). Rules should be **schema-aware and declarative**, co-located with or adjacent to `schema.rhype`:
- **Per-type allow/deny** for `read | create | update | delete | subscribe` (subscribe is a first-class op — Firestore lacks a clean analog, and RhypeDB subs are query-pattern-based).
- **Field-level predicates** referencing the principal (`request.auth.uid`, `request.auth.claims.*`) and the object/edge fields (`resource.<field>`), and the *incoming* values on writes (`request.<field>`).
- **Relationship-aware rules** — RhypeDB's first-class edges let rules express "the principal is in `resource.owners`" or "the principal's `org` matches `resource.org`" as a traversal, which the engine can evaluate cheaply (pointer-follow, not a join). This is a genuine advantage over Firestore's `get()`-based cross-document reads.
- **Default-deny.** No rule → no access. The open routes become closed.

---

## 4. Provisioning & lifecycle

### 4.1 `jkbase.toml [database]` schema

```toml
[database]
engine = "rhypedb"        # rejected if unknown — mirror SiteConfig::build_strategy (config.rs rejects unknown build strategies)
schema = "schema.rhype"   # file in the uploaded source tree (same convention as ServerConfig.source)
rules  = "rules.rhype"    # security rules; OPTIONAL — required before exposing untrusted clients
size   = "4GiB"           # per-role data-disk size (default 1GiB is too small)
# tier = "dedicated"      # see OPEN DECISION 1; only "dedicated" if a shared tier is ever built
```

Add `pub database: Option<DatabaseConfig>` to `ProjectConfig` (`config.rs:7-22`) and a typed `DatabaseConfig { engine, schema, rules, size }` that **rejects unknown `engine`** (mirror the build-strategy resolver that rejects unknown values, so `engine = "rhypdb"` fails closed). Emit a host-side `_database.json` sidecar via a `database_json()` method following `routes_json`/`schedules_json` — never written to the on-disk artifact in cleartext where it shouldn't be; credentials ride the reserved channel.

### 4.2 Deploy + schema apply

Deploy path unchanged through the shared tail `activate_deployment` (stage → `deployments/v{N}` → quota gate → atomic `live` symlink swap → reconcile → boot). Two hooks:
- **(a) In `build_metadata_image`:** write `_database.json` + **bake `schema.rhype` (and `rules.rhype`) into the read-only metadata image**, host-authored like `_platform.json` (`layer_plan.rs`). Inject the `RHYPEDB_ADMIN_TOKEN`-class credential via the reserved channel (the `StorageBinding` template, `layer_plan.rs:21-28,568-571`) — never in tenant `process.env`, never user-visible, minted/rotated per deploy.
- **(b) In the agent:** synthesize a supervised RhypeDB entry: `rhypedb-server --data-dir /mnt/data/rhypedb --schema /srv/.../schema.rhype [--rules ...] --listen 127.0.0.1:4200`. Ship `rhypedb-server` as a baked erofs runtime layer (`rhypedb.ext4`, exactly like `trunk.ext4`).

### 4.3 Online migrations without data loss

- **Additive changes are free.** Add a field, reapply the schema → existing objects read the new field as null (`README.md:104-119`). Drive via `POST /admin/reload` (hot, no cold restart, in-place `ArcSwap`) instead of forcing a redeploy.
- **Type changes are an online migration** (`POST /admin/migrations`): double-write → background backfill → cutover, crash-resumable, hot-reloads the live handle on completion (`admin.rs:37-69`; resume watchers re-registered on restart, `lib.rs:798`). The control plane/agent drives this on the running instance.
- **The platform never forces a cold redeploy for a schema change** — that's the whole point of the hot-reload + online-migration surface.

### 4.4 Code rollback vs data

- Rollback only **repoints the `live` symlink** at an older `v{N}` and reboots (`api.rs do_rollback`). The **RWO data disk is keyed per-project, not per-version**, and attaches to whatever version is live → **DB data does NOT roll back with code.** This is already the correct design.
- **P0-DB-8 (rollback-against-forward-migrated-disk guard).** A code rollback to an older `schema.rhype` against a forward-migrated disk must hit RhypeDB's **fail-closed schema-shrink refusal** (`allow_schema_shrink` default off; post-cutover type changes irreversible) — the engine refuses rather than corrupting. Surface this clearly in the CLI/console (rollback may strand the DB at a newer schema; that's safe, not silent corruption).

### 4.5 Quota / metering / DoS caps

- **Bytes-on-disk:** v1 = the disk's fixed size is the cap (ENOSPC). Dedicated: per-role sized disk; meter via host `stat` of the RWO image file (never mount), reusing the object-store fail-closed reservation + TTL re-walk shape if a soft cap is wanted.
- **Row/edge/vector counts** live behind the engine — **the host cannot dir-walk them.** RhypeDB must export per-tenant counters (`/status` extension) for metering.
- **Query DoS** — the sharp edge, see §6.4 and §9 #3. The governor lands in-engine.

---

## 5. Changes required IN RhypeDB (ordered, by crate)

1. **Query resource governor** — `rhypedb-query` (`executor.rs`). Cap `Step::Limit{count}`/`k` (truncate-verbatim today, `executor.rs:546-560`); forbid-or-page unindexed `scan_all_objects`/`scan_type` (uncapped today, `executor.rs:163,190,1162-1164`); add traversal-depth budget, per-request wall-clock + row/byte ceiling. (`ef`/pool already clamped to `MAX_VECTOR_SEARCH_POOL=10_000`, `executor.rs:583,649,662`.) **Highest leverage, cheapest, blocks any untrusted tier; also defense-in-depth for v1 own-app abuse.** Must be in-engine — the host cannot interpose.
2. **Per-instance metering counters** — `rhypedb-server` (`/status` extension): query cost, RSS, sub fan-out, object/edge/vector counts. Feeds platform quota/metering. Needed for any billable tier.
3. **Object-store backup/restore contract** — `rhypedb-server` (`restore.rs`/`admin.rs`): formalize the platform local-staging contract (size cap, idempotent restore sentinel — mostly already present). No engine network code. *(Mostly platform-mediable; minimal RhypeDB change.)*
4. **Crash-recovery-from-Pause hardening + on-box fuzz** — `rhypedb-storage` (`lsm.rs`/`wal.rs`/`restore.rs`): prove WAL replay + HNSW sweep is sound when Paused at every boundary (incl. mid-vectorize-queue, `ARCHITECTURE.md:155,175`). Likely already correct; needs the fuzz harness.
5. **Verified-principal hook** — `rhypedb-server` + `rhypedb-query`: thread a principal into `handle_query` / `handle_tcp_connection` (`lib.rs:222,1157`) and `ExecContext` (`executor.rs:59-72`). **Prereq for #6.** *(End-state.)*
6. **Default-deny declarative security-rules evaluator** — new `rhypedb-rules` crate (or in `rhypedb-query`): per type/object/field/op, principal-aware, schema-aware, relationship-aware. **The Firestore core; large.** *(End-state.)*
7. **WebSocket `/subscribe` transport** — `rhypedb-server`: WS upgrade bridging the transport-agnostic change hub (`rhypedb-subscribe`), same authz gate as #5/#6. Replaces binary-TCP for untrusted clients. *(End-state.)*

Items 1–4 are platform-adjacent or v1-relevant; **5–7 must land inside RhypeDB** because they sit on the query/auth path the host cannot interpose on without parsing the guest protocol.

---

## 6. Changes required IN jkbase (ordered, by crate)

1. **`[database]` config + sidecar** — `jkbase-common` (`config.rs`): `DatabaseConfig` (reject-unknown-engine), `database_json()` emitter.
2. **Bake `rhypedb.ext4` runtime layer + agent supervised-DB synthesis** — build assets + `jkbase-agent` (`container_supervisor.rs`): start RhypeDB as a supervised server on a `/mnt/data/rhypedb` volume, loopback-bound. **(Ships v1.)**
3. **Deploy hooks** — `jkbase-server` (`layer_plan.rs`, `build_metadata_image`): write `_database.json`, bake schema/rules, mint+inject `RHYPEDB_ADMIN_TOKEN`-class credential via the reserved channel; control store mints/rotates per deploy (`jkbase-control/src/store.rs`).
4. **Backup loop** — `jkbase-server`: metering-loop-adjacent timer → `/admin/backup/stream` → stage → push to own bucket; restore staging → `RHYPEDB_RESTORE_FROM`.
5. **Per-role VM sizing** — `jkbase-server` (`main.rs`): make `mem_size_mib`/`vcpu_count`/data-disk-size **per-role** (hardcoded 3072/4 at `main.rs:2515-2516`, 4096/4 at `main.rs:1313-1314`; test path proves 1024/1 boots). DB-VM floor ~512–1024 MiB / 1 vCPU (RhypeDB runs lean with `--no-default-features` dropping ONNX; +~80 MB only when a `@vectorize` field exists). **Recovers most density lost to the second VM.**
6. **Dedicated DB-VM lifecycle (composite key)** — `jkbase-server` (`main.rs`): thread `project_id:db` through `vms`/`vm_states`/`VmAllocation`/snapshot-meta/disk-tokens/routing (all bare-`project_id` today, `main.rs:791-792`). **(MVP boundary.)**
7. **Intra-project L2 FORWARD-accept** — `jkbase-server` (`main.rs` networking): scoped to exactly the project's two pinned `{tap,ip,mac}` pairs (atop port-isolation + source-guard, `main.rs:2948-2985`), with a deploy-time assertion of rule cardinality = one pair/project. **(MVP boundary.)**
8. **`db.` reserved host + DB-gateway service** — `jkbase-proxy` (`lib.rs`, mirror `storage.` at `:289-301`) + new `db_gateway` service (mirror `objectstore_service.rs`): JWT verify, host→project resolve, wake, quota, HMAC principal-header injection. **(End-state.)**
9. **Idle-reaper sub liveness** — `jkbase-proxy`/`jkbase-server`: active upgrade relay = liveness (P0-DB-6).
10. **Console DB tab + CLI `jkbase db`** — `sites/console` + `jkbase-cli`: owner-scoped `_console/projects/{id}/db/...` Bearer JSON API hosted on the DB service (mirror the object browser), CLI thin-proxy injecting the session token + project routing (mirror `jkbase storage`). Reuse RhypeDB's existing migrate/backup/export/codegen logic; the browser cannot use `@rhypedb/client` (TCP-only) so it goes through the HTTP `_console/db` front.
11. **jkbase Auth issuer + per-project JWKS** — new control-adjacent service. **(End-state; largest jkbase-side arc; reusable platform primitive.)**

---

## 7. Phased roadmap

Each phase is a small shippable increment with a crisp done-state. Small atomic commits; branch first; security-relevant seams get adversarial review before merge. **Proper over throwaway:** v1 is a true subset of the end-state, nothing is rebuilt.

| Phase | Scope | Done-state | Unlocks |
|---|---|---|---|
| **P0 — Boot a DB in the app VM** | Config `[database]` + `rhypedb.ext4` layer + agent supervised-DB on loopback + `/mnt/data/rhypedb` volume. RhypeDB change: none (boots on existing `--data-dir`/`--schema`). | `jkbase deploy` of a project with `[database]` boots RhypeDB co-located; the app queries it over loopback; on-box e2e: create→query→relate→similar→HTTP 200. Hibernate→wake survives (WAL crash-recovery). | "Managed RhypeDB for your own backend" — basic. |
| **P1 — Productionize v1** | Cheap query governor (#1) + per-instance counters (#2) + backups to object store (#4 jkbase / #3 rhypedb) + metering (`database_disk_bytes`) + CLI `jkbase db` (apply/query/backup/codegen) + console DB tab (schema viewer + paged object browser via `_console/db`). Crash-recovery-from-Pause fuzz (#4 rhypedb). | A tenant provisions, queries, migrates (additive + type), backs up to their bucket, and browses data in the console. DoS bounded even for own-app abuse. Snapshot/restore fuzz green. | **MVP boundary candidate** — v1 GA as a standalone product (OPEN DECISION 2). |
| **P2 — Dedicated DB VM** | Composite key `project_id:db` (#6) + per-role VM sizing (#5) + intra-project L2 FORWARD-accept (#7) + per-role data-disk size. | App VM reaches its sibling DB VM over scoped L2; DB VM runs at ~512–1024 MiB; noisy-neighbor isolation; rule-cardinality assertion passes. | Noisy-neighbor isolation; the substrate for untrusted-client exposure; density recovered. |
| **P3 — jkbase Auth** | Per-project EdDSA-JWT issuer (signup/login) + per-project JWKS + (later) OIDC import. | An end-user signs up/logs in to a tenant app and receives a short-lived per-project JWT; JWKS verifiable offline. | The identity prerequisite for everything Firestore-shaped (and reusable by functions/servers). |
| **P4 — RhypeDB authz core** | Verified-principal hook (#5) + default-deny rules evaluator (#6) — gating **all** entrypoints incl. TCP. | A query with no verified principal is denied; a rules file gates read/write/subscribe per type/field/principal; adversarial review of the in-engine rules seam passes. | Per-end-user authorization — the differentiator. |
| **P5 — Direct-client + realtime** | WS `/subscribe` (#7) + `db.` reserved host + DB-gateway (JWT verify, wake, HMAC principal header) (#8) + sub-liveness reaper (#9) + console rules editor + Auth tab. | An **untrusted browser** connects to `db.{project}.jkbase.app`, authenticates as an end-user, reads/writes only what rules allow, and gets realtime updates over WS. Full adversarial seam review (§9) green. | **Firestore-style end-state.** |

**MVP boundary:** end of **P1** for the backend-only product; end of **P5** for the Firestore product. Recommendation: ship P1 as GA (it delivers value while the long pole builds), do the dedicated-VM split (P2) before *any* untrusted client touches the engine.

---

## 8. Adversarial threat checklist

| # | Attack on the new seam | Defense |
|---|---|---|
| 1 | **Cross-tenant DB reach** via the intra-project L2 FORWARD-accept | Rule must match **both** src+dst pinned `{MAC,IP}` — never a bare TAP-name or subnet rule (a subnet accept re-opens cross-tenant reach). Rides atop existing port-isolation + source-guard (`main.rs:2948-2985`). **Deploy-time assertion: rule cardinality = exactly one pair per project.** (P0-DB-3) |
| 2 | **Egress/exfil from a compromised DB VM** (gateway/uplink reachable; egress unaffected by port-isolation) | DB VM inherits runtime egress posture: SSRF DROP to host/metadata, IPv6 off (`main.rs:2960-2967`). A managed DB has no legit outbound → **default egress-deny except the pinned object-store host** for backup staging. (P0-DB-4) |
| 3 | **DoS via expensive queries** — uncapped `.limit()`/`k`, unindexed → full `scan_type` | **In-engine query governor (hard gate before any untrusted client):** cap limit/k, page-or-forbid unbounded scans, traversal-depth + wall-clock + row/byte budgets (`executor.rs:546,1162`). v1 risk is contained to the tenant's own VM (no cross-tenant blast radius); end-state risk is a hostile end-user weaponizing it. Host cannot interpose → must be in RhypeDB. |
| 4 | **Rules bypass via the binary TCP path** — `/query`, TCP handler, and WS each independently unauthenticated today | Principal hook gates **every** entrypoint — HTTP `/query` (`lib.rs:222`), the binary TCP handler (`lib.rs:1157`, the easy-to-forget one), and WS `/subscribe`. **Default-deny if no verified principal header.** (P0-DB-5) |
| 5 | **Identity-token forgery** | Gateway verifies sig/`iss`/`aud`/`exp`/skew with the **per-project** pubkey, fail-closed (a global key lets project A forge project B). Gateway→DB HMAC header secret is per-deploy via the reserved channel, never user-visible. **Reject any client-supplied principal header at the gateway boundary.** (P0-AUTH-1, P0-DB-5) |
| 6 | **Single-writer / lock abuse** | RWO disk = one writer/disk (`main.rs:2696`); RhypeDB `flock`+128-bit fence per data-dir (`lock.rs:10-29`). Defended in VM-per-DB. (The rejected shared-process design is where this would bite.) (P0-DB-1/2) |
| 7 | **Data-disk fencing** | RWO-once, host never mounts/parses (`main.rs:2696`, `fence_data_disk:3271`). RhypeDB owns its files; host moves opaque sha256-verified blobs. (P0-DB-1) |
| 8 | **Backup poisoning** | Size-cap the staged blob vs data-disk quota; restore only into the **same** project bucket (own-bucket binding); treat the tar as untrusted — **no host-side extraction/parse**, hand straight to RhypeDB. (P0-DB-7) |
| 9 | **Sub-VM hibernated mid-stream** (long-lived WS = one activity timestamp at open) | Idle reaper treats an active spliced upgrade relay as liveness. (P0-DB-6) |
| 10 | **Code rollback corrupts a forward-migrated disk** | RhypeDB fail-closed schema-shrink refusal (`allow_schema_shrink` off); DB stays at the newer schema rather than corrupting. Surface clearly. (P0-DB-8) |
| 11 | **Pause-without-flush data loss** | Crash-recovery from WAL on resume (RhypeDB claims this; `ARCHITECTURE.md:175`). **On-box snapshot/restore fuzz at every boundary is the gate** — do not ship the dedicated tier until green. |

---

## 9. OPEN DECISIONS for the human

1. **Density vs blast radius — shared free tier?**
   *Either:* dedicated VM-per-DB for **every** DB project (halves host density to ~126/host even with per-role sizing) — *or* build density-cost's **shared multi-process supervisor** (one host-side process fork/exec-ing a rhypedb child per project data-dir) for free/hobby.
   **Recommendation: dedicated VM-per-DB with per-role sizing; do NOT build the shared supervisor.** The shared supervisor is a brand-new host-side process that handles the *untrusted guest's unbounded query protocol* over loopback — a new cross-tenant seam strictly weaker than KVM. The object-store analogy is false: object-store proxies *bounded opaque byte streams*, not a query language. Revisit only if free-tier economics force it, and then **dedicated-tier-only for any untrusted-direct-client project.**

2. **Ship v1 (backend-only) as standalone GA, or hold for the full Firestore story?**
   **Recommendation: ship P1 as GA.** It delivers real value (managed relationships + vectors + subs for your backend) while the multi-quarter identity+rules+governor+WS long pole builds. v1 is a strict subset — no rework.

3. **Direct-client blast radius — allow Firestore mode on any tier, or dedicated-VM-only?**
   **Recommendation: dedicated-VM-only.** A hostile end-user must never reach a shared process; even if a shared tier is built (Decision 1), untrusted-direct-client exposure is restricted to dedicated VMs.

4. **Scope of "jkbase Auth" — full reusable identity platform, or DB-only JWT minter?**
   *Either:* a full identity issuer (signup/login + OIDC/social import + JWKS) as a **platform primitive** reusable by functions/servers/the console — *or* a minimal DB-only JWT minter.
   **This is a platform-strategy call (genuinely the human's), not an architecture forcing function.** Auth is a large arc with value far beyond RhypeDB; building it minimal-then-expanding is fine if the minimal surface is the per-project EdDSA+JWKS core (the expensive, hard-to-change part), with signup-UX/OIDC layered later. Recommend the per-project EdDSA+JWKS core be designed as a platform primitive from day one even if the first consumer is only the DB.

5. **Rules language — adopt a Firestore-rules-like DSL, or a RhypeDB-native schema-embedded rules syntax?**
   *Either:* a familiar Firestore-rules-shaped DSL (lower learning curve, but Firestore's `get()`-based cross-doc reads map awkwardly onto RhypeDB's edge model) — *or* a RhypeDB-native syntax that leans on first-class relationships (`allow read: if request.auth.uid in resource.owners`) co-located in/beside `schema.rhype`.
   **Recommendation: RhypeDB-native, relationship-aware, schema-co-located** — it's the genuine differentiator (cheap pointer-follow rules vs Firestore's join-shaped `get()`), and the typed schema gives static validation Firestore lacks. Mark as the human's call because it's a product-surface commitment that's hard to reverse.

---

### Verified file references (checkable)
- jkbase: routing/reserved-host `crates/jkbase-proxy/src/lib.rs:268-301`, WS relay `:442-474`; VM keys `crates/jkbase-server/src/main.rs:791-792`, IP budget `:879-886`, data-disk size `:820`, per-VM sizing `:1313-1314,2515-2516`, port-isolation+source-guard `:2948-2985`, fence `:2696-2802,3271`; hibernate `crates/jkbase-orch/src/vm.rs:238-262`; config `crates/jkbase-common/src/config.rs:7-22`; reserved-channel injection `crates/jkbase-server/src/layer_plan.rs:21-28,568-571`; object-store template `crates/jkbase-server/src/objectstore_service.rs:99-199,482-489`.
- RhypeDB: open data plane + admin-only auth `crates/rhypedb-server/src/lib.rs:805-813`, `crates/rhypedb-server/src/admin.rs:37-95`; SIGTERM flush (unused on hibernate) `lib.rs:848-879`; no-principal `ExecContext` `crates/rhypedb-query/src/executor.rs:59-72`; uncapped limit/scan `executor.rs:546-560,1162-1164`; vector clamp `executor.rs:583,649,662`; TCP handler no-auth `lib.rs:1157-1216`; single-writer lock `crates/rhypedb-storage/src/lock.rs:10-29`; local-only restore `crates/rhypedb-server/src/restore.rs:288-303`; instance-per-DB `lib.rs:109-114`.

Recommended file path for this document: `/home/joe/dev/jkbase/docs/managed-rhypedb-design.md`.
