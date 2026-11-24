//! Managed-DB control endpoints (owner-scoped): backups + restore ([RB6]/[RB8]), the
//! dedicated-tier drop, the console DB tools (query / schema / status), the owner's
//! `rewrite-covers` pass, and the schema-only redeploy. The server binary provides every
//! transport (backup/restore/query callbacks) — control owns no orch dependency.

use super::*;

/// One catalog row, as surfaced to the owner. Never carries the object-store key or the
/// tenant id — the caller identifies a backup only by its opaque `backup_id`.
#[derive(Serialize)]
struct DbBackupResponse {
    backup_id: String,
    created_at_ms: u64,
    size_bytes: u64,
    status: crate::store::BackupStatus,
    manifest_summary: String,
}

impl From<crate::store::DbBackup> for DbBackupResponse {
    fn from(b: crate::store::DbBackup) -> Self {
        Self {
            backup_id: b.backup_id,
            created_at_ms: b.created_at_ms,
            size_bytes: b.size_bytes,
            status: b.status,
            manifest_summary: b.manifest_summary,
        }
    }
}

#[derive(Deserialize)]
pub(super) struct DropDedicatedDbRequest {
    /// Must equal the project id — a destructive, irreversible op is never one stray request.
    confirm: String,
}

#[derive(Serialize)]
struct DropDedicatedDbResponse {
    dropped: bool,
}

/// `DELETE /projects/{id}/db/dedicated` — irreversibly destroy the project's dedicated-tier DB
/// VM and its data disk (`{id}.db.img`). Owner-scoped; the body must echo the project id. The
/// one way to reclaim a dedicated DB disk short of deleting the project: leaving the dedicated
/// tier keeps it (its data would otherwise be lost to a config edit), and it counts against the
/// storage quota at its full size. Serialized against deploy/build/rollback on the per-project
/// deploy lock; wakes and wake-path boots don't take that lock, so the server-side drop
/// additionally refuses (`Busy` → 409) unless it holds the DB disk's lease and no DB VM
/// wake/hibernate/boot is in flight — it never frees a disk or IP an in-flight boot is using.
///
/// Also clears a recorded `dedicated` deployed tier ([R4]): the data a later tier change would
/// strand is gone, so back-up → drop → redeploy at the new tier → restore is a clean migration.
/// If the live deployment still declares `tier = "dedicated"`, its DB is down until the next
/// deploy boots a fresh, empty one.
pub(super) async fn drop_dedicated_db(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<DropDedicatedDbRequest>,
) -> impl IntoResponse {
    let err = |code: StatusCode, msg: String| (code, Json(ErrorResponse { error: msg }));
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    if req.confirm != id {
        return err(
            StatusCode::BAD_REQUEST,
            format!("refusing to drop: `confirm` must be the project id '{id}'"),
        )
        .into_response();
    }
    let Some(cb) = &state.db_drop_callback else {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "database drop is not available on this server".into(),
        )
        .into_response();
    };
    let Some(_lock) = DeployLockGuard::try_acquire(&state, &id) else {
        return err(
            StatusCode::CONFLICT,
            format!("a deploy, build or rollback of '{id}' is in progress; retry when it finishes"),
        )
        .into_response();
    };
    match cb(id.clone()).await {
        Ok(DbDropOutcome::Busy) => err(
            StatusCode::CONFLICT,
            format!("the database of '{id}' is starting or hibernating; retry in a moment"),
        )
        .into_response(),
        Ok(outcome) => {
            if matches!(state.store.get_deployed_tier(&id), Ok(Some(t)) if t == "dedicated") {
                let _ = state.store.delete_deployed_tier(&id);
            }
            Json(DropDedicatedDbResponse {
                dropped: outcome == DbDropOutcome::Dropped,
            })
            .into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct RestoreRequest {
    backup_id: String,
}

/// `POST /projects/{id}/db/backups` — trigger an on-demand backup of the project's managed
/// DB. Owner-scoped. Records a `Pending` catalog row and fires the server-side executor
/// (host-relay pull → platform store), returning immediately with the new `backup_id`; the
/// caller polls `GET /db/backups` for completion. 400 if the project has no deployed managed
/// DB (no admin token minted yet).
pub(super) async fn trigger_db_backup(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    // A managed DB that has been deployed since backups shipped has a minted admin token;
    // without one there is nothing to back up (or the token needs a redeploy to rotate in).
    match state.store.get_db_admin_token(&id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "project has no managed database, or it has not been redeployed since \
                            backups were enabled (redeploy to enable backups)"
                        .to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    }
    let Some(cb) = state.db_backup_callback.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "backups are not available on this server".to_string(),
            }),
        )
            .into_response();
    };

    // Single-flight: refuse a new backup while one is already in progress, so a tenant can't
    // accumulate concurrent full-DB pulls into off-quota host disk (adversarial-review finding).
    if matches!(state.store.has_active_backup(&id), Ok(true)) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "a backup is already in progress for this project".to_string(),
            }),
        )
            .into_response();
    }

    // Server-authored id + object key ([RB6]) — the caller never supplies a storage path.
    match state.store.create_db_backup_auto(&id, &tenant.id) {
        Ok(row) => {
            let backup_id = row.backup_id.clone();
            info!(project = %id, backup_id = %backup_id, "managed-db backup requested");
            cb(id.clone(), backup_id);
            (StatusCode::ACCEPTED, Json(DbBackupResponse::from(row))).into_response()
        }
        Err(e) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// `GET /projects/{id}/db/backups` — list the project's managed-DB backups (newest first).
/// Owner-scoped. Metadata only; the tar blobs are never exposed here.
pub(super) async fn list_db_backups(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    match state.store.list_db_backups(&id) {
        Ok(rows) => {
            let out: Vec<DbBackupResponse> = rows.into_iter().map(DbBackupResponse::from).collect();
            Json(out).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// `POST /projects/{id}/db/restore` — restore the managed DB from a backup. Owner-scoped.
/// The body carries only an opaque `backup_id`, resolved through the per-project catalog to
/// the server-authored object key ([RB6]) — a caller can never point restore at an arbitrary
/// blob. Refuses a backup that isn't `Complete` ([RB8]). Fires the server-side restore
/// executor (host-push → in-guest untar → rhypedb restore-on-boot).
pub(super) async fn restore_db_backup(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<RestoreRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    let backup = match state.store.get_db_backup(&id, &req.backup_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("backup '{}' not found", req.backup_id),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };
    if backup.status != crate::store::BackupStatus::Complete {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!(
                    "backup '{}' is not restorable (status: {:?})",
                    req.backup_id, backup.status
                ),
            }),
        )
            .into_response();
    }
    let Some(cb) = state.db_restore_callback.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "restore is not available on this server".to_string(),
            }),
        )
            .into_response();
    };
    info!(project = %id, backup_id = %req.backup_id, "managed-db restore requested");
    cb(id.clone(), req.backup_id.clone());
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "started", "backup_id": req.backup_id })),
    )
        .into_response()
}

/// Max query-string length the console DB tools accept (defense-in-depth alongside the router
/// body limit and the agent's own inbound bound). Queries are small; results can be large.
const MAX_DB_QUERY_LEN: usize = 128 * 1024;

#[derive(Deserialize)]
pub struct DbQueryRequest {
    pub query: String,
}

/// Shared tail for the three console DB proxy endpoints: require the query callback, invoke it,
/// and pass the engine's HTTP status + JSON body back VERBATIM (so 400 parse/governor errors
/// reach the UI unchanged). A transport/wake failure becomes a 502 with a JSON error.
async fn db_query_dispatch(
    state: &Arc<AppState>,
    id: String,
    op: DbQueryOp,
) -> axum::response::Response {
    let Some(cb) = state.db_query_callback.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "the database console tools are not available on this server".to_string(),
            }),
        )
            .into_response();
    };
    match cb(id, op).await {
        Ok(res) => {
            let status = StatusCode::from_u16(res.status).unwrap_or(StatusCode::BAD_GATEWAY);
            (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                res.body,
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, Json(ErrorResponse { error: e })).into_response(),
    }
}

/// `POST /projects/{id}/db/query` — run a query against the project's managed DB. Owner-scoped.
/// The query string is forwarded verbatim to the in-VM DB's open loopback `POST /query`; the
/// engine's response (including 400 parse/governor errors) is returned unchanged. Enables the
/// console query tool + data browser.
pub(super) async fn db_query(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<DbQueryRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    if req.query.len() > MAX_DB_QUERY_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: format!("query exceeds {MAX_DB_QUERY_LEN} bytes"),
            }),
        )
            .into_response();
    }
    db_query_dispatch(&state, id, DbQueryOp::Query(req.query)).await
}

/// `GET /projects/{id}/db/schema` — schema introspection for the managed DB (types + fields +
/// the relationship graph + canonical SDL). Owner-scoped. Powers the schema/relationship view.
pub(super) async fn db_schema(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    db_query_dispatch(&state, id, DbQueryOp::Schema).await
}

/// `GET /projects/{id}/db/status` — metering counts (objects/edges/vectors/queries). Owner-scoped.
pub(super) async fn db_status(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    db_query_dispatch(&state, id, DbQueryOp::Status).await
}

/// Max SDL the schema editor accepts.
const MAX_SDL_BYTES: usize = 512 * 1024;

#[derive(Deserialize)]
pub struct DbSchemaRequest {
    pub sdl: String,
}

/// Recursively clone `src` → `dst`, HARD-LINKING regular files (immutable deployment artifacts —
/// mostly large erofs layer blobs) so a schema-only new version doesn't duplicate them on disk;
/// symlinks are recreated, dirs recursed. A caller that wants to CHANGE a file must
/// remove-then-write it (writing through a hard-link would mutate the cloned-from version).
pub(super) fn hardlink_clone_dir(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ft.is_dir() {
            hardlink_clone_dir(&from, &to)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            std::os::unix::fs::symlink(target, &to)?;
        } else if std::fs::hard_link(&from, &to).is_err() {
            // cross-filesystem or EMLINK → fall back to a byte copy.
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Poll the managed DB's `/status` (via the console DB transport) until it returns 200 or the
/// window elapses. Used as the post-redeploy reconcile gate: rhypedb refuses to open on an
/// incompatible schema change and crash-loops, so `/status` never reaches 200 → the caller rolls
/// back. `Ok` if no transport is wired (degraded: no gate) so this never wedges a redeploy.
async fn wait_db_healthy(state: &Arc<AppState>, id: &str) -> Result<(), String> {
    let Some(cb) = state.db_query_callback.clone() else {
        return Ok(());
    };
    let mut last = "database did not respond".to_string();
    for _ in 0..20 {
        match cb(id.to_string(), DbQueryOp::Status).await {
            Ok(res) if res.status == 200 => return Ok(()),
            Ok(res) => last = format!("database returned HTTP {}", res.status),
            Err(e) => last = e,
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Err(last)
}

/// `POST /projects/{id}/db/schema` — apply a new managed-DB schema via a SCHEMA-ONLY REDEPLOY.
/// Owner-scoped. Clones the current deployment (hard-linking the built app layers — no rebuild),
/// swaps in the new `_database/schema.rhype`, activates it (atomic `live` swap + VM reboot), then
/// GATES on DB health: rhypedb reconciles the schema on boot (additive changes apply; a field-type
/// change needs a migration; a drop needs a shrink) and crash-loops on an incompatible change — so
/// if `/status` doesn't come back healthy we ROLL BACK to the prior version and report it. The DB's
/// data disk is untouched by the redeploy.
pub(super) async fn db_schema_apply(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<DbSchemaRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    if req.sdl.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "schema (sdl) must not be empty".to_string(),
            }),
        )
            .into_response();
    }
    if req.sdl.len() > MAX_SDL_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: format!("schema exceeds {MAX_SDL_BYTES} bytes"),
            }),
        )
            .into_response();
    }
    let proj_dir = state.deploy_dir.join(&id);
    // Must already have a live managed DB — this edits an existing schema, it doesn't provision one.
    if !proj_dir.join("live").join("_database.json").exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "project has no managed database; add a [database] section to jkbase.toml \
                        and deploy it first"
                    .to_string(),
            }),
        )
            .into_response();
    }
    // Serialize with deploy/build/rollback (409 on contention) — held for the whole redeploy.
    // Acquire the lock BEFORE reading `current_version`, then re-read the project FRESH under it,
    // so a concurrent deploy that advanced the version can't be clobbered by a stale snapshot
    // (activate_deployment derives v{N} from current_version + history). Mirrors run_build_job's re-read.
    // [adversarial-review: schema-redeploy TOCTOU]
    let _guard = match DeployLockGuard::try_acquire(&state, &id) {
        Some(g) => g,
        None => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "a deploy or rollback is already in progress for this project".to_string(),
                }),
            )
                .into_response();
        }
    };
    let mut project = match state.store.get_project(&id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };
    let Some(prev_version) = project.current_version else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "project has no active deployment".to_string(),
            }),
        )
            .into_response();
    };

    let prev_deploy_path = proj_dir.join("deployments").join(format!("v{prev_version}"));
    // The clone below recreates the tree's symlinks and the SDL write lands under `_database/`:
    // a symlinked `_database` (a tree predating activation's check) would aim that root-privileged
    // remove+write at another tenant's schema. Validate BEFORE cloning, not just at activation.
    if let Err(e) = validate_deployment_tree(&prev_deploy_path) {
        return (
            deploy_error_status(&e),
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }
    let staged = proj_dir.join(format!(".staging-schema-{}", auth::timestamp()));
    let _ = std::fs::remove_dir_all(&staged);
    if let Err(e) = hardlink_clone_dir(&prev_deploy_path, &staged) {
        let _ = std::fs::remove_dir_all(&staged);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("clone current deployment: {e}"),
            }),
        )
            .into_response();
    }
    // Remove-then-write so the new SDL doesn't mutate the prior version through the hard-link.
    let schema_dest = staged.join("_database").join("schema.rhype");
    if let Some(p) = schema_dest.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let _ = std::fs::remove_file(&schema_dest);
    if let Err(e) = std::fs::write(&schema_dest, req.sdl.as_bytes()) {
        let _ = std::fs::remove_dir_all(&staged);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("write schema: {e}"),
            }),
        )
            .into_response();
    }

    // Activate (move → atomic live swap → VM reboot). On failure, clean the stage and map quota.
    let new_version = match activate_deployment(&state, &mut project, &staged).await {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staged);
            return (
                deploy_error_status(&e),
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    // Reconcile gate: rhypedb crash-loops on an incompatible schema → roll back to the prior version.
    if let Err(reason) = wait_db_healthy(&state, &id).await {
        // do_rollback repoints `live` + persists current_version=prev BEFORE its fallible VM-restart
        // callback, so on Err the deployment pointer is still on the prior version — but say so
        // rather than claiming a clean rollback. [adversarial-review: swallowed rollback error]
        let tail = match do_rollback(&state, &mut project, &prev_deploy_path, prev_version).await {
            Ok(()) => format!("rolled back to v{prev_version}."),
            Err(e) if e.downcast_ref::<DeployRefused>().is_some() => format!(
                "rolling back to v{prev_version} was refused ({e}) — the new schema is still live; \
                 roll back or redeploy explicitly."
            ),
            Err(e) => format!(
                "the deployment pointer is back on v{prev_version}, but restarting it reported an \
                 error ({e}) — it will restart on next access, or redeploy to force it."
            ),
        };
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: format!(
                    "the database rejected the new schema ({reason}); {tail} \
                     Additive changes (a new type / a new nullable field) apply cleanly; a field TYPE \
                     change needs a migration and a field/type DROP needs a shrink."
                ),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "version": new_version, "status": "deployed" })),
    )
        .into_response()
}
