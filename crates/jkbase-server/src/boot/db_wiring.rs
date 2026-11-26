//! Managed-DB control callbacks: relay revocation, backups/restores and the console DB tools.

use super::Planes;
use crate::db_backup_store;
use crate::db_ops::{
    DB_BACKUP_MAX_CONCURRENT, DbBackupCtx, DbQueryCtx, do_db_query, run_db_backup, run_db_restore,
};
use jkbase_control::api::AppState;
use jkbase_proxy::db_relay::DbRelayRegistry;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

pub(crate) fn wire_db_callbacks(
    state: &mut AppState,
    planes: &Planes,
    data_dir: &Path,
) -> (Arc<DbRelayRegistry>, DbBackupCtx) {
    // Managed-DB reach-plane live-relay registry — shared with the proxy edge, the idle
    // loop, and the drain. [R5]: the control API force-closes live relays through it when a
    // DB key is revoked or a project is deleted/transferred. Built here (before `state` is
    // sealed into the router) so the revoke callback can reach it.
    let db_relay_registry = jkbase_proxy::db_relay::DbRelayRegistry::new();
    {
        let reg = db_relay_registry.clone();
        state.db_revoke_callback = Some(Arc::new(move |scope| match scope {
            jkbase_control::api::DbRevokeScope::Key(k) => {
                let n = reg.cancel_key(&k);
                if n > 0 {
                    info!(key = %k, count = n, "db key revoked: closed live relays");
                }
            }
            jkbase_control::api::DbRevokeScope::Project(p) => {
                let n = reg.cancel_project(&p);
                if n > 0 {
                    info!(project = %p, count = n, "project teardown: closed live db relays");
                }
            }
        }));
    }

    // Managed-DB backups ([RB*]): the platform-owned blob store + the executor context shared by
    // the on-demand callbacks and the nightly loop. The control API records intent + owner-scopes;
    // execution (VM wake, agent relay, blob store) is server-side here.
    let db_backup_ctx = DbBackupCtx {
        platform: planes.platform.clone(),
        routing: planes.routing.clone(),
        domains: planes.domains.clone(),
        shipper: planes.shipper.clone(),
        store: state.store.clone(),
        backups: Arc::new(db_backup_store::BackupStore::new(data_dir)),
        backup_sem: Arc::new(tokio::sync::Semaphore::new(DB_BACKUP_MAX_CONCURRENT)),
        restoring: Arc::new(std::sync::Mutex::new(HashSet::new())),
    };
    {
        let ctx = db_backup_ctx.clone();
        state.db_backup_callback = Some(Arc::new(move |project_id, backup_id| {
            tokio::spawn(run_db_backup(ctx.clone(), project_id, backup_id));
        }));
    }
    {
        let ctx = db_backup_ctx.clone();
        state.db_restore_callback = Some(Arc::new(move |project_id, backup_id| {
            tokio::spawn(run_db_restore(ctx.clone(), project_id, backup_id));
        }));
    }
    {
        // Console DB tools (query / schema / status / rewrite-covers) — a SYNCHRONOUS proxy (the
        // caller blocks on the result), unlike the fire-and-forget backup/restore callbacks.
        // Captures the wake inputs + store directly, plus the relay registry the rewrite pass
        // holds the DB VM warm through.
        let ctx = DbQueryCtx {
            platform: planes.platform.clone(),
            routing: planes.routing.clone(),
            domains: planes.domains.clone(),
            shipper: planes.shipper.clone(),
            store: state.store.clone(),
            relays: db_relay_registry.clone(),
            rewriting: Arc::new(std::sync::Mutex::new(HashSet::new())),
        };
        let cb: jkbase_control::api::DbQueryCallback = Arc::new(
            move |project_id: String, op: jkbase_control::api::DbQueryOp| {
                let ctx = ctx.clone();
                Box::pin(async move { do_db_query(ctx, project_id, op).await })
            },
        );
        state.db_query_callback = Some(cb);
    }
    (db_relay_registry, db_backup_ctx)
}
