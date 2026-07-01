# Managed RhypeDB — backups-to-object-store design (P1)

> Status: design (P1). Companion to `docs/managed-rhypedb-design.md` and
> `docs/managed-rhypedb-tcp-ingress-design.md`. This adds **managed backup + restore** to the
> v1 "managed RhypeDB for your own backend" offering: snapshot a project's co-located RhypeDB to
> platform-owned object storage, list snapshots, and restore one. On-demand (CLI/API) **and**
> nightly-automatic with retention.
>
> **Threat model (load-bearing): all tenants untrusted; the host must NEVER mount or parse a guest
> filesystem, and the RWO data disk is host-write-forbidden.** The managed DB has ZERO data-plane
> auth (loopback-only by design), and its `/admin/*` surface (which includes full data exfil via
> `/admin/backup/stream`) is gated only by a bearer token. Every defense below follows from those
> two facts. This seam gets a full multi-agent adversarial review before merge (project convention).
>
> **Decisions (Joe, 2026-07-01):**
> **(B1)** Backups are **platform-owned** (a separate host-internal object store, never tenant-
> addressable), delivered by a **host-relay pull** — NOT written to the tenant's own bucket. Durable
> (tenant can't delete), off tenant quota, minimal guest secret surface.
> **(B2)** Ship **on-demand + nightly-automatic** with retention (keep the newest N per project).

## Hard constraints (honored throughout)
- **(a) No rhypedb engine change.** We use the existing `GET /admin/backup/stream` (Bearer
  `RHYPEDB_ADMIN_TOKEN`) + `RHYPEDB_RESTORE_FROM` restore-on-boot. Both already exist upstream.
- **(b) All tenants untrusted; host never touches the guest FS / RWO data disk.**
- **(c) The admin token is a reserved credential** — agent-needed, tenant-forbidden.
- **(d) Scale-to-zero holds** (backup/restore run inside the fenced boot window; no second host
  writer attaches the disk).

---

## 1. The rhypedb contract we build on (verified against sibling `/home/joe/dev/rhypedb`)

- **Backup:** `GET /admin/backup/stream` (`rhypedb-server/src/admin.rs:782`) — `Authorization: Bearer
  <RHYPEDB_ADMIN_TOKEN>`; freezes a physical snapshot (SSTs + `wal.log` + `hnsw_*.bin` +
  `schema.rhype` + `MANIFEST.json` written **last**) into a temp dir on the data-dir filesystem and
  streams it back as a **tar**, chunked / never buffered. A failure *after* the 200 begins can only
  **truncate** the body → the consumer **MUST validate the tar end-of-archive marker** before
  trusting a snapshot.
- **Admin gate:** `RHYPEDB_ADMIN_TOKEN` unset → all `/admin/*` return **403**; wrong bearer → 401
  (`admin.rs:75`). Read once at startup from env (`rhypedb-server/src/config.rs:77`).
- **Restore-on-boot:** env `RHYPEDB_RESTORE_FROM=<untarred-snapshot-dir>` (+ `RHYPEDB_RESTORE_FROM_FORCE`)
  → `restore.rs::restore_from_snapshot` runs BEFORE `Database::open`: validates the manifest
  (rejects path-traversal filenames + incomplete sources *before* touching the data dir), clears
  stale data under a single-writer guard, copies load-bearing files, writes a `RESTORE_DONE`
  sentinel LAST. **Idempotent** (a matching sentinel → no-op, preserving post-restore writes) and
  **crash-safe** (an in-progress marker resumes an interrupted restore). Snapshot identity =
  `created_at_ms` + `max_version` (mount-path independent).

Consequence: **restore is always an in-guest operation.** The host ferries only the opaque tar; the
agent untars into `/mnt/data` and rhypedb does the destructive restore under its own single-writer
guard. The host never parses the tar and never writes the guest FS.

---

## 2. Topology & data flow

```
                        BACKUP (host-relay pull)
  scheduler / CLI ─▶ POST /projects/{id}/db/backups (api., owner-scoped)
                        │  records DbBackup{status:Pending}, invokes db_backup_callback
                        ▼
  jkbase-server executor ── connect vm_ip:80 /_jkbase/db-backup  (x-jkbase-db-secret, streaming)
                                        │
                        agent ── GET 127.0.0.1:4200/admin/backup/stream  (Bearer admin_token)
                                        │  streams tar back over the eth0 response body
                        ▼
  host ── stream tar ─▶ platform ObjectStore  {data_dir}/db-backups  (bucket "snapshots",
                        key "{project_id}/{backup_id}.tar")   [NEVER wired to any router]
                        │  validate tar EOF ⇒ flip status Complete(size, manifest) | Failed(delete)

                        RESTORE (host-push, in-guest untar)
  CLI ─▶ POST /projects/{id}/db/restore {backup_id} (owner-scoped; backup_id resolved via catalog)
                        │  invokes db_restore_callback
                        ▼
  jkbase-server executor ── get_object(tar) ─▶ connect vm_ip:80 /_jkbase/db-restore (secret, streaming)
                                        │
                        agent ── untar → /mnt/data/volumes/rhypedb-restore/<id>  (in-guest, bounded)
                                     ── stop rhypedb (supervisor-coordinated)
                                     ── respawn rhypedb with RHYPEDB_RESTORE_FROM=<dir> (+_FORCE)
                                        │  rhypedb restore-on-boot: validate → clear → copy → sentinel
                        ▼            ── 200 ⇒ status recorded
```

The **admin token** and the **splice secret** ride the same host-only reserved channel
(`DbReachFacts` / `_db_reach.json`), written LAST into the per-VM metadata image so a tenant source
file of the same name can't forge it. The token is injected only into rhypedb's `ServerManifest.env`
(the agent's `env_clear()` per-process guarantees it never reaches a tenant process).

---

## 3. Components (by crate)

### 3.1 `jkbase-common`
- `config::DbReachFacts` gains `#[serde(default)] pub admin_token: String` (old images → empty →
  fail-closed: no admin token ⇒ backups disabled, not a crash). `_db_reach.json` unchanged as the
  file; already `_`-prefixed (never static-served) and written LAST (`layer_plan.rs`).

### 3.2 `jkbase-control`
- `auth::generate_rhypedb_admin_token()` — `jkba_` + 32 bytes `OsRng`, base64url (mirrors
  `generate_splice_secret`, distinct self-identifying prefix).
- `store`:
  - `DB_ADMIN_TOKEN` table (`project_id → token`) + `mint / get / delete_db_admin_token` (verbatim
    copy of the `DB_SPLICE` block; overwrite per deploy, purge on teardown).
  - `DB_BACKUPS` (primary, key `backup_id`) + `DB_BACKUPS_BY_PROJECT` (index, key
    `"{project_id}:{backup_id}"`) — mirrors the `DB_ACCESS_KEYS` primary+index split. Register both
    in `Store::open`.
  - `struct DbBackup { backup_id, project_id, tenant_id, created_at_ms, size_bytes, object_key,
    manifest_summary, status }`; `enum BackupStatus { Pending, Complete, Failed }`.
  - `create_db_backup` (cap-checked via the `{project_id}:` index range, primary+index in one txn),
    `list_db_backups`, `get_db_backup(project_id, backup_id)` (scoped via the index key so a tenant
    can't resolve another project's backup by guessing the id), `set_db_backup_status`,
    `delete_db_backup`, `delete_all_db_backups`, `MAX_DB_BACKUPS_PER_PROJECT` (retention bound).
- `api::AppState` gains `db_backup_callback` + `db_restore_callback` (async, server-provided; mirror
  `deploy_callback` / `db_revoke_callback`). Endpoints (registered next to the db-key routes, behind
  the same `require_auth` + owner-scope):
  - `POST /projects/{id}/db/backups` → owner-check → `db_backup_callback` → `{backup_id, status}`.
  - `GET  /projects/{id}/db/backups` → owner-check → `list_db_backups`.
  - `POST /projects/{id}/db/restore` `{backup_id}` → owner-check → resolve backup via catalog (**not**
    a caller-supplied key) → `db_restore_callback` → `{status:"started"}`.
- Teardown (`delete_project` / transfer) also purges `delete_db_admin_token` + `delete_all_db_backups`
  **and** the backup blobs (via a callback to the platform store) — a recreated same-slug project must
  not inherit a prior tenant's snapshots.

### 3.3 `jkbase-server`
- **Platform backup store:** a second `jkbase_objectstore::ObjectStore` rooted at
  `{data_dir}/db-backups`, held on `PlatformState`, **never** merged into
  `ObjectStoreService::into_router()`. Fixed bucket `snapshots`; key `{project_id}/{backup_id}.tar`
  (`project_id` may be <3 chars / hyphen-edged, so it can't be a bucket name — use it as a key
  prefix; `is_valid_project_id`-guard before any join). Writes via `put_object_capped` (streaming,
  size-capped); reads via `get_object`; retention via `list_v2` + `delete_object`.
- **Backup executor** (`db_backups.rs`): resolve the project's running VM IP (LogShipper-style; wake
  if hibernated), connect `vm_ip:80/_jkbase/db-backup` presenting `x-jkbase-db-secret`, **stream** the
  tar response into the platform store, validate the tar trailer, flip status. Invoked by the
  callback (on-demand) and the nightly loop.
- **Restore executor:** `get_object` the tar, connect `vm_ip:80/_jkbase/db-restore`, **stream** the
  tar as the request body, await 200.
- **Nightly loop:** modelled on `scheduler_loop` (`last_run` + `due_since` + catch-up cap + a
  concurrency `Semaphore`); walks managed-DB projects, backs up those due, prunes to
  `MAX_DB_BACKUPS_PER_PROJECT`. Single-host owns all projects today (mirror the scheduler's gating
  comment for future HA).
- **Admin-token mint at deploy:** where `db_reach` is built (`main.rs` ~2734), also
  `mint_db_admin_token(project_id)` and set `DbReachFacts { splice_secret, admin_token }`. Best-effort
  (a mint failure must not fail the deploy — the DB just runs without rotated admin/backups until next
  deploy), matching the splice-secret stance.
- **Lifecycle GC:** add `db-backups` to `handle_teardown` reap + `reconcile_orphans_on_boot`.

### 3.4 `jkbase-agent`
- **Streaming plumbing:** the `/_jkbase/db-backup` + `/_jkbase/db-restore` handlers must NOT use the
  buffered `Full<Bytes>` return / `Limited`+`collect` request path (OOM on a multi-GB tar). Backup:
  forward the loopback `hyper::body::Incoming` straight through as a boxed streaming body. Restore:
  read the request body frame-by-frame to disk (bounded by a size/quota deadline, not the 10 MiB
  `MAX_REQUEST_BODY`).
- **`/_jkbase/db-backup`** (GET): inherits the eth0-loopback drop; constant-time `x-jkbase-db-secret`
  compare (reuse the splice-secret gate); on pass, `GET 127.0.0.1:4200/admin/backup/stream` with the
  `Bearer` admin token (from the reserved channel) and relay the body to the host, streaming. 404 on
  every reject (no managed DB / bad secret / admin token absent).
- **`/_jkbase/db-restore`** (POST): same gate; stream the body into
  `/mnt/data/volumes/rhypedb-restore/<backup_id>` via a **traversal-safe, bounded** tar extractor
  (defence-in-depth atop rhypedb's own manifest validation), then, coordinated with the supervisor so
  the health loop can't race-respawn: stop rhypedb, respawn it with `RHYPEDB_RESTORE_FROM=<dir>`
  (+`_FORCE`) in `ServerManifest.env`, await health, return 200. Old restore-staging dirs are swept.
- **Admin-token inject:** the `_db_reach.json` loader returns the whole `DbReachFacts`; `start_database`
  sets `env: {"RHYPEDB_ADMIN_TOKEN": admin_token}` (was `HashMap::new()`).

### 3.5 `jkbase-cli`
- `DbCommand` gains `Backup`, `Backups`, `Restore { backup_id }` (mirror `DbKeyCommand`: `--project`
  inference + `--api`). Handlers call the control API with the stored Bearer token (mirror
  `run_db_key`). `db backup` polls `db backups` until the row is Complete/Failed (bounded) and prints
  the result; `db restore` prints a destructive-op warning (consider `--force`).

---

## 4. Hard requirements ([R#]) — the adversarial-review checklist

- **[RB1] Admin token is reserved.** Rides `DbReachFacts` / `_db_reach.json` only (host-authored,
  written LAST, tenant-unforgeable). NEVER in `_database.json`, NEVER in any tenant `_servers/*` env,
  filtered from `list_secrets` so a tenant can't shadow/read it. Rotated per deploy; purged on teardown.
- **[RB2] Both new agent endpoints re-use the reach-plane gate:** eth0-loopback drop for `/_jkbase/*`
  (→ 404) + constant-time `x-jkbase-db-secret` compare; every reject path is **404** (never
  403/401/500 — a probing tenant on eth0 must not confirm the endpoint, the DB, or a backup's
  existence).
- **[RB3] Stream, never buffer** on the tar path (agent + host). No `collect()` / `Full<Bytes>`;
  bypass `MAX_REQUEST_BODY` on the restore push but bound it another way (declared size / disk quota).
- **[RB4] The platform `db-backups` store is never routable.** Not merged into `into_router()`; no
  SigV4/console/proxy surface. `is_valid_project_id` guard before any path join; a tenant cannot
  address it via S3/console (it is not under any tenant root). Its bytes are **not** summed by
  `project_storage_bytes` (off tenant quota by construction).
- **[RB5] Restore stays in-guest.** The host never untars and never writes the data-disk FS. The agent
  untars (bounded, traversal-safe); rhypedb's `restore_from_snapshot` re-validates the manifest and
  runs under its single-writer guard.
- **[RB6] Restore takes an opaque `backup_id`, resolved through the per-project catalog** (owner-scoped
  `{project_id}:{backup_id}` index) to a **server-authored** object key. Never accept a caller-supplied
  storage path (else cross-project blob read / traversal).
- **[RB7] Owner-scope on all three endpoints (404, not 403).** Restore re-checks the *current* owner;
  an orphaned backup/token can't be inherited by a recreated same-slug project (teardown purge).
- **[RB8] Two-phase catalog status.** `Pending` → `Complete` only after the tar EOF marker validates; a
  truncated/aborted stream lands `Failed` and its partial object is deleted. Restore refuses any
  non-`Complete` backup.
- **[RB9] Restore respawn is race-free.** The stop→respawn-with-restore-env is coordinated with the
  supervisor health/respawn loop so rhypedb can't be race-respawned without `RHYPEDB_RESTORE_FROM`;
  rhypedb is single-writer, so it must be stopped before the destructive clear.
- **[RB10] The admin token grants full `/admin/*`** (data exfil + compact/migrate) on loopback:4200 —
  it is defence-in-depth on a channel already fenced loopback + eth0 + splice-secret. The DB name
  `rhypedb` stays reserved from tenant routes/servers/sites (existing deploy fence).
- **[RB11] Blob GC on project delete/transfer.** Purge catalog rows AND backup blobs so a deleted
  tenant's DB data does not linger in the platform store.
- **[RB12] Nightly wake-to-backup is bounded.** A `Semaphore` caps concurrent backups; catch-up
  collapses a post-outage backlog to a single fire. (Waking a hibernated DB to back it up trades
  scale-to-zero economics for a durability guarantee — accepted for v1; an incremental/awake-only
  optimization is a later card.)

---

## 5. Deferred (do NOT re-litigate here)
- Point-in-time / incremental backups (v1 is full-snapshot only).
- Cross-region / off-host backup replication (single-host today; rides the HA arc).
- Tenant-visible backup blobs / "bring your own bucket" (rejected in favour of platform-owned, per B1).
- Logical export/import (`/admin/export`) as a portability format — physical snapshot is the v1 path.
- `rhypedb-cli` in the runtime layer (not needed — restore is env-driven restore-on-boot, no CLI).
