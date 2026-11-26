//! The pre-swap deploy gate: refusals judged against the NEW tree before it goes live (so a
//! refused deploy keeps the old one serving), including the DB tier-flip rule, and the record of
//! which tier a project was last deployed at.

use crate::{
    DEAD_HOST_THRESHOLD, DeployTarget, PlatformState, deploy_target, deployment_has_database,
    deployment_is_dedicated, vm_identity,
};
use anyhow::Result;
use jkbase_control::store::Store;
use std::path::Path;
use tracing::warn;

/// Why a deployment tree must not go live — pure policy over the store + the tree, never touching
/// the running VM. Runs twice: from the control plane's `deploy_precheck_callback` against the NEW
/// tree BEFORE the `live` swap (so a refused version never becomes what the next
/// wake/restart/resume boots), and in [`handle_deploy`] against `live` before teardown.
pub(crate) async fn deploy_refusal(
    plat: &PlatformState,
    project_id: &str,
    deployment_dir: &Path,
) -> Result<()> {
    // HA P3: only the OWNER host may deploy a project. On a single node every project is
    // local (unplaced / owned by this host), so this is a no-op; in a cluster a deploy that
    // reached a non-owner fails closed (retry) rather than booting a second owner.
    {
        let me = plat.host_id.clone();
        let alloc = plat.store.get_vm_allocation(project_id).ok().flatten();
        let hosts = plat.store.list_hosts().unwrap_or_default();
        let now = jkbase_control::auth::timestamp();
        match deploy_target(
            alloc.as_ref(),
            &hosts,
            &me,
            now,
            DEAD_HOST_THRESHOLD.as_secs(),
        ) {
            DeployTarget::Local => {}
            DeployTarget::Remote { host_id, addr } => {
                // The refusal text reaches the tenant: the owner's address stays in the log.
                warn!(project = %project_id, owner = %host_id, addr = ?addr,
                    "deploy reached a non-owner host");
                anyhow::bail!(
                    "project {project_id} is owned by another host; the deploy must run there \
                     (cross-host deploy forwarding not yet wired)"
                )
            }
            DeployTarget::OwnerDead { host_id } => anyhow::bail!(
                "project {project_id}'s owner host {host_id} is down; the reconciler will reassign \
                 it — retry the deploy shortly"
            ),
        }
    }

    // [R4] Refuse an in-place managed-DB TIER FLIP (colocated↔dedicated). Flipping the tier between
    // deploys would strand the existing DB data on the OLD tier's disk (colocated data on the app
    // VM's `{id}.img`; dedicated data on the sibling `{id}.db.img`) and silently start an EMPTY DB
    // (or orphan the sibling DB VM) — apparent total data loss on a config toggle. The tenant
    // migrates explicitly: back up, recreate at the new tier, restore. (First flip of a pre-P2
    // project that never recorded a tier is not caught — dedicated is unreleased, so no such data
    // exists yet.) A store read error fails open, as before.
    let prior = plat.store.get_deployed_tier(project_id).ok().flatten();
    let new_tier = deployment_db_tier(deployment_dir);
    if let Some(msg) = tier_flip_refusal(project_id, prior.as_deref(), new_tier) {
        anyhow::bail!(msg);
    }
    // A dedicated DB's disk outlives its tier record in one case the check above can't see: a
    // record dropped by code that predates keeping it across a no-`[database]` deploy (so
    // dedicated → no DB → co-located slipped through) — the disk is unreachable yet counted
    // against the quota at full size. Detect it from the disk itself. `exists` errors fail open
    // rather than block every deploy on a substrate hiccup. Only a deploy that would CREATE that
    // state is refused: once the project already runs co-located beside the disk (recorded tier
    // `colocated`), refusing its restarts, rollbacks and cold boots protects nothing.
    let db_id = vm_identity::vm_id(project_id, vm_identity::VmRole::Db);
    if new_tier == Some("colocated")
        && prior.as_deref() != Some("colocated")
        && plat.data_disk.exists(&db_id).await.unwrap_or(false)
    {
        anyhow::bail!(
            "project {project_id}: a dedicated-tier managed database from an earlier deploy \
             still holds data on its own disk, and a co-located database would start empty \
             beside it. To keep it, redeploy with `tier = \"dedicated\"` (and back it up \
             before migrating); to discard it, run `jkbase db drop --project {project_id}`, \
             then redeploy."
        );
    }
    Ok(())
}

/// [R4] The refusal message for deploying a tree at managed-DB tier `new_tier` over the recorded
/// `prior` tier, or `None` when it may proceed. `prior` is the last tier the project EVER ran a
/// managed DB at — it survives a deploy that drops `[database]`, since that DB's data stays on its
/// tier's disk — so re-adding the DB at the other tier is refused like a direct flip. A tree with
/// no DB, or a project that never had one (so a plain project newly adding a dedicated DB), is
/// never refused.
pub(crate) fn tier_flip_refusal(
    project_id: &str,
    prior: Option<&str>,
    new_tier: Option<&str>,
) -> Option<String> {
    match (prior, new_tier) {
        (Some(prior), Some(new_tier)) if prior != new_tier => {
            // Leaving `dedicated` has an in-place path: its data sits on its own disk, which
            // `jkbase db drop` discards (clearing this record). A co-located DB shares the app's
            // disk with its volumes, so there is nothing separate to drop.
            let migrate = if prior == "dedicated" {
                format!(
                    "Back up the database (`jkbase db backup`), drop it (`jkbase db drop --project \
                     {project_id}`), redeploy at the new tier, then restore the backup into it."
                )
            } else {
                "Keep `tier = \"colocated\"`, or move it yourself: export your data (e.g. over \
                 `jkbase db proxy`; platform backups do not survive deleting the project), delete \
                 and recreate the project at the new tier, and import it."
                    .to_string()
            };
            Some(format!(
                "project {project_id}: changing the managed-database [database] tier in place \
                 ({prior} → {new_tier}) is not supported — your database's data is still on its \
                 {prior}-tier disk (also after a deploy without [database]), and a {new_tier} \
                 database would start empty beside it. {migrate}"
            ))
        }
        _ => None,
    }
}

/// [R4] Stamp the tier `deployment_dir` runs its managed DB at. A tree with no DB leaves the
/// prior stamp in place (see the commit-to-Running call site in [`handle_deploy`]).
pub(crate) fn record_deployed_tier(store: &Store, project_id: &str, deployment_dir: &Path) {
    if let Some(tier) = deployment_db_tier(deployment_dir) {
        let _ = store.set_deployed_tier(project_id, tier);
    }
}

/// The managed-DB tier (`"dedicated"` / `"colocated"`) a deployment tree declares, or `None` when
/// it declares no managed DB. Same host-baked `_database.json` reads as
/// [`check_project_has_database`] / [`project_is_dedicated`], against any tree (the not-yet-live
/// one, for the pre-swap precheck).
pub(crate) fn deployment_db_tier(deployment_dir: &Path) -> Option<&'static str> {
    if !deployment_has_database(deployment_dir) {
        return None;
    }
    Some(if deployment_is_dedicated(deployment_dir) {
        "dedicated"
    } else {
        "colocated"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_is_dedicated;
    use jkbase_control::store::Store;

    /// [R4] The tier-flip refusal judges the tree being ACTIVATED, not `live`: the control plane
    /// prechecks the new `deployments/v{N}` before swapping `live` to it, so `live` still names
    /// the previous version when the check runs. Judging `live` there would wave every flip
    /// through (prior == live's tier) and the refused tree would go live.
    #[test]
    fn tier_flip_is_judged_against_the_new_tree() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data = std::env::temp_dir().join(format!("jkbase-tierflip-{nanos}"));
        let proj = data.join("hosting").join("p");
        let tree = |v: u64, db: Option<&str>| {
            let dir = proj.join("deployments").join(format!("v{v}"));
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(json) = db {
                std::fs::write(dir.join("_database.json"), json).unwrap();
            }
            dir
        };
        let v1 = tree(1, Some(r#"{"engine":"rhypedb","tier":"dedicated"}"#));
        let v2 = tree(2, Some(r#"{"engine":"rhypedb"}"#));
        let v3 = tree(3, None);
        std::os::unix::fs::symlink(&v1, proj.join("live")).unwrap();

        // `live` (v1) is dedicated; the new tree (v2) is co-located.
        assert!(project_is_dedicated(&data, "p"));
        assert_eq!(deployment_db_tier(&v1), Some("dedicated"));
        assert_eq!(deployment_db_tier(&v2), Some("colocated"));
        assert_eq!(deployment_db_tier(&v3), None);

        // Recorded dedicated → new co-located tree is refused; the message names both tiers.
        let msg = tier_flip_refusal("p", Some("dedicated"), deployment_db_tier(&v2))
            .expect("dedicated → colocated must be refused");
        assert!(msg.contains("dedicated → colocated"), "{msg}");
        assert!(
            tier_flip_refusal("p", Some("colocated"), deployment_db_tier(&v1)).is_some(),
            "colocated → dedicated must be refused"
        );
        // Same tier, no recorded tier, or no DB in the new tree: not a data-stranding flip.
        assert!(tier_flip_refusal("p", Some("dedicated"), deployment_db_tier(&v1)).is_none());
        assert!(tier_flip_refusal("p", None, deployment_db_tier(&v2)).is_none());
        assert!(tier_flip_refusal("p", Some("dedicated"), deployment_db_tier(&v3)).is_none());

        // A deploy that drops `[database]` keeps the stamp (the data is still on its tier's
        // disk), so dedicated → no DB → colocated can't launder past the refusal.
        let store = Store::open(&data.join("db.redb")).unwrap();
        record_deployed_tier(&store, "p", &v1);
        record_deployed_tier(&store, "p", &v3);
        let prior = store.get_deployed_tier("p").unwrap();
        assert_eq!(prior.as_deref(), Some("dedicated"));
        assert!(tier_flip_refusal("p", prior.as_deref(), deployment_db_tier(&v2)).is_some());

        let _ = std::fs::remove_dir_all(&data);
    }
}
