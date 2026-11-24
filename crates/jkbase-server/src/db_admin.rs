//! The owner's admin ops on a managed DB (today: `rewrite-covers`) — host side. Long-running and
//! mutating, so each is single-flight per project, keeps the DB VM warm through a relay-registry
//! hold charged to the owner's warm-VM quota, and is detached from its caller so a hang-up can
//! neither hibernate the VM mid-pass nor free the slot for a stacked rerun. The agent authorizes
//! the one hard-coded engine admin route itself; the host only ever presents the project's own
//! splice secret to the project's own VM.

use super::*;
use crate::db_ops::{DbQueryCtx, agent_db_request, db_splice_secret};

/// Outer deadline on one `rewrite-covers` pass (wake + the whole engine pass). The engine works in
/// batches and is safe to interrupt, and keeps working after the host drops the connection — so
/// on expiry the host only stops WAITING: the agent's own single-flight still refuses a rerun
/// until the engine answers, and a later rerun redoes only what is still stale. Long enough for
/// a large store, bounded so a wedged engine can't pin the keep-warm hold forever.
const DB_REWRITE_COVERS_DEADLINE: Duration = Duration::from_secs(60 * 60);
/// Synthetic akid for the keep-warm hold in the relay registry. Never a real DB key, so a key
/// revocation (`cancel_key`) never targets it; `cancel_project` / `cancel_all` still do.
const DB_ADMIN_HOLD_AKID: &str = "__db_admin_op__";

/// The owner's `rewrite-covers` pass ([`DbQueryOp::RewriteCovers`]). Bounded on every axis:
/// single-flight per project (a second call while one runs is a 409, before any wake; the agent
/// enforces the same per VM, covering a pass the host stopped waiting for), one keep-warm hold in
/// the relay registry registered BEFORE the wake (so a project delete during the wake aborts it —
/// [R5]), and [`DB_REWRITE_COVERS_DEADLINE`] over the whole thing. The project's OWN splice
/// secret + VM are the only target; the agent authorizes the hard-coded admin call with the
/// in-guest token.
///
/// The pass runs in a DETACHED task: the caller hanging up (Ctrl-C, a dropped console tab) must
/// not release the hold — the VM would hibernate mid-pass — or the guard, while the engine is
/// still working. Both last until the agent answers, the deadline passes, or the project is
/// cancelled. The hold keeps the DB VM warm, so its warm time bills to the tenant like any other
/// DB connection: the owner asked for the work.
///
/// [`DbQueryOp::RewriteCovers`]: jkbase_control::api::DbQueryOp::RewriteCovers
pub(crate) async fn do_db_rewrite_covers(
    ctx: &DbQueryCtx,
    project_id: &str,
) -> Result<jkbase_control::api::DbQueryResult, String> {
    let (ctx, project_id) = (ctx.clone(), project_id.to_string());
    tokio::spawn(async move { rewrite_covers_pass(&ctx, &project_id).await })
        .await
        .map_err(|e| format!("rewrite-covers task failed: {e}"))?
}

/// The body of [`do_db_rewrite_covers`], run detached from the caller.
async fn rewrite_covers_pass(
    ctx: &DbQueryCtx,
    project_id: &str,
) -> Result<jkbase_control::api::DbQueryResult, String> {
    let Some(_running) = RewriteInFlight::try_start(&ctx.rewriting, project_id) else {
        return Ok(json_result(
            409,
            "a rewrite-covers pass is already running for this project's database",
        ));
    };
    let secret = db_splice_secret(&ctx.store, project_id)?;
    let (_hold, cancel) = hold_db_vm_warm(&ctx.relays, project_id)?;
    let run = async {
        let ip = wake_db_reach(
            project_id,
            ctx.platform.clone(),
            ctx.routing.clone(),
            ctx.domains.clone(),
            ctx.shipper.clone(),
        )
        .await
        .map_err(|e| format!("wake project: {e:?}"))?;
        agent_db_request(
            &ip,
            "/_jkbase/db/rewrite-covers",
            "POST",
            &secret,
            Vec::new(),
        )
        .await
        .map_err(|e| format!("{e:#}"))
    };
    let res = tokio::select! {
        _ = cancel.cancelled() => {
            return Err("rewrite-covers aborted (project deleted or server shutting down); \
                        rerunning it is safe".to_string());
        }
        r = tokio::time::timeout(DB_REWRITE_COVERS_DEADLINE, run) => r.map_err(|_| {
            "rewrite-covers did not finish within the deadline; the database may still be \
             working on it. Rerunning is safe and redoes only what is still stale — check \
             `cover_peers_sound` in the database status first."
                .to_string()
        })??,
    };
    info!(project = %project_id, status = res.status, "managed-db rewrite-covers finished");
    Ok(rewrite_covers_result(res))
}

/// Map the agent's answer for the operator. The engine's own answer (200 with `ok` true/false +
/// its counters, or its error status) passes through verbatim, as do the agent's own refusals
/// (409 while a pass runs, 501 for an engine without the route). A 404 can only come from the
/// agent itself — no such endpoint (a VM booted before this shipped) or no admin token baked; the
/// host presented the project's current splice secret — so say how to fix it.
fn rewrite_covers_result(
    res: jkbase_control::api::DbQueryResult,
) -> jkbase_control::api::DbQueryResult {
    if res.status == 404 {
        return json_result(
            409,
            "the project's database VM is running an older agent without rewrite-covers; \
             restart or redeploy the project, then retry",
        );
    }
    res
}

fn json_result(status: u16, error: &str) -> jkbase_control::api::DbQueryResult {
    jkbase_control::api::DbQueryResult {
        status,
        body: serde_json::to_vec(&serde_json::json!({ "error": error })).unwrap_or_default(),
    }
}

/// Register the keep-warm hold for an admin op on `project_id`'s DB (keyed by the BASE project, so
/// it keeps a dedicated `{id}.db` VM warm too). No tenant (an owner-driven maintenance op must not
/// be refused by — or count against — the external reach warm-VM quota) and no per-project cap:
/// the hold is already bounded to one per project by the single-flight guard.
fn hold_db_vm_warm(
    relays: &Arc<jkbase_proxy::db_relay::DbRelayRegistry>,
    project_id: &str,
) -> Result<
    (
        jkbase_proxy::db_relay::RelayGuard,
        tokio_util::sync::CancellationToken,
    ),
    String,
> {
    relays
        .try_register(project_id, None, DB_ADMIN_HOLD_AKID, usize::MAX, 0, 0)
        .map_err(|r| format!("could not hold the database VM warm: {r:?}"))
}

/// RAII per-project single-flight slot for `rewrite-covers`; released on drop (any exit path).
struct RewriteInFlight {
    set: Arc<std::sync::Mutex<HashSet<String>>>,
    project_id: String,
}

impl RewriteInFlight {
    fn try_start(set: &Arc<std::sync::Mutex<HashSet<String>>>, project_id: &str) -> Option<Self> {
        let mut running = set.lock().unwrap_or_else(|p| p.into_inner());
        running.insert(project_id.to_string()).then(|| Self {
            set: set.clone(),
            project_id: project_id.to_string(),
        })
    }
}

impl Drop for RewriteInFlight {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.project_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::api::DbQueryResult;

    #[test]
    fn rewrite_covers_is_single_flight_per_project() {
        let set = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let a = RewriteInFlight::try_start(&set, "p1").expect("first pass starts");
        assert!(
            RewriteInFlight::try_start(&set, "p1").is_none(),
            "second is refused"
        );
        let b = RewriteInFlight::try_start(&set, "p2").expect("another project is independent");
        drop(a);
        assert!(
            RewriteInFlight::try_start(&set, "p1").is_some(),
            "slot frees on drop"
        );
        drop(b);
        assert!(set.lock().unwrap().is_empty());
    }

    /// The hold is what keeps the idle loop off the VM (`conn_count > 0`), it is keyed so
    /// `cancel_project` reaches it, and it is gone the moment the op ends.
    #[test]
    fn admin_hold_keeps_the_db_vm_warm_and_is_cancellable() {
        let relays = jkbase_proxy::db_relay::DbRelayRegistry::new();
        let (hold, cancel) = hold_db_vm_warm(&relays, "proj").unwrap();
        assert_eq!(relays.conn_count("proj"), 1);
        assert_eq!(
            relays.cancel_key("some-real-akid"),
            0,
            "key revocation never hits it"
        );
        assert_eq!(relays.cancel_project("proj"), 1);
        assert!(cancel.is_cancelled());
        drop(hold);
        assert_eq!(relays.conn_count("proj"), 0);
    }

    #[test]
    fn rewrite_covers_result_passes_the_engine_through_and_explains_a_stale_agent() {
        let engine = br#"{"ok":true,"objects":3,"cover_peers_sound":true}"#.to_vec();
        let r = rewrite_covers_result(DbQueryResult {
            status: 200,
            body: engine.clone(),
        });
        assert_eq!((r.status, r.body), (200, engine));
        let failed = br#"{"ok":false,"error":"write conflict"}"#.to_vec();
        let r = rewrite_covers_result(DbQueryResult {
            status: 200,
            body: failed.clone(),
        });
        assert_eq!(
            (r.status, r.body),
            (200, failed),
            "engine-level failure is the engine's"
        );
        let r = rewrite_covers_result(DbQueryResult {
            status: 404,
            body: b"not found".to_vec(),
        });
        assert_eq!(r.status, 409);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("restart or redeploy"));
    }
}
