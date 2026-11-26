//! Boot-time reconciliation, run before the proxy serves: settle projects left mid-lifecycle by
//! the previous process, drop base layers no live or restorable VM references, and backfill the
//! domain map so apex/www/console never 404 in the gap.

use crate::{PlatformState, VmLifecycle, layer_plan, vm_identity};
use anyhow::Result;
use jkbase_control::store::{DomainKind, DomainRecord, DomainStatus, ProjectState, Store};
use jkbase_proxy::DomainMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Boot-time sweep for projects deleted but left with artifacts behind (a teardown
/// that failed midway, or a project removed before teardown existed). For every
/// per-project image/dir whose name is NOT a currently registered project, drop the
/// stale artifact. Registered projects are never touched, so live data disks are
/// safe. `builds/` is reaped wholesale by the build reconcile, so it is omitted.
pub(crate) async fn reconcile_orphans_on_boot(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let mut registered: HashSet<String> = match plat.store.list_projects() {
        Ok(ps) => ps.into_iter().map(|p| p.id).collect(),
        Err(_) => return,
    };
    // VM re-adoption §7: treat every re-adopted survivor as protected too (belt-and-suspenders
    // — a survivor is always also `registered`, but this guards the data-disks loop-detach below
    // against ever `losetup -d`'ing a live survivor's loop even if a store read drifted).
    for (id, state) in plat.vm_states.iter() {
        if *state == VmLifecycle::Running {
            registered.insert(id.clone());
        }
    }
    let data_dir = plat.data_dir.clone();
    drop(plat);

    // A dedicated DB VM's artifacts are named by its RENDERED id (`{base}.db.img`,
    // `snapshots/{base}.db`, `run/{base}.db`, `content-images/{base}.db.ext4`) but there is no
    // `{base}.db` project row — the DB VM belongs to its BASE project. Protect a `.db` artifact iff
    // its base is registered (or the DB VM is itself Running, inserted above). WITHOUT this, a clean
    // restart with the DB VM not-yet-woken reaps `{base}.db.img` as an "orphan" — a loop-detach +
    // delete that DESTROYS the tenant's database. (For an app-id artifact `base_project_id` is a
    // no-op, so the check is unchanged for every existing project.)
    let is_registered =
        |id: &str| registered.contains(id) || registered.contains(vm_identity::base_project_id(id));

    // Collect each directory's entries up front: removing files while iterating a
    // live read_dir handle skips entries (the kernel readdir cursor shifts under
    // the deletions), so a single pass would reap only a subset of the orphans.
    // content-images: `{id}.ext4`.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("content-images")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".ext4") else {
                continue;
            };
            if !is_registered(id) {
                let _ = std::fs::remove_file(entry.path());
                info!(project = %id, artifact = "content-images", "reaped orphaned artifact");
            }
        }
    }
    // data-disks: loop-managed `{id}.img` + its `{id}.holder` record (+ legacy
    // `{id}.ext4`). Detach any loop device still bound to an orphan image before
    // removing it, so deleted projects can't leak loop devices that another project
    // would later reuse.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("data-disks")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Orphaned atomic-write temp files (`{id}.holder.tmp.{pid}`) left by a crash
            // mid `write_holder`: always stale (a completed write renames into place), so
            // reap unconditionally — they carry no live identity to match `registered`.
            // Match the EXACT `.holder.tmp.<digits>` suffix, not a substring: a real disk
            // ends in `.img`/`.holder`/`.ext4`, and a project id may itself legally contain
            // `.holder.tmp.`, so a substring check could delete a live disk.
            if name
                .rsplit_once(".holder.tmp.")
                .is_some_and(|(_, pid)| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
            {
                let _ = std::fs::remove_file(entry.path());
                continue;
            }
            let Some(id) = name
                .strip_suffix(".img")
                .or_else(|| name.strip_suffix(".holder"))
                .or_else(|| name.strip_suffix(".ext4"))
            else {
                continue;
            };
            if is_registered(id) {
                continue;
            }
            let path = entry.path();
            if name.ends_with(".img")
                && let Ok(out) = tokio::process::Command::new("losetup")
                    .args(["-j", &path.to_string_lossy()])
                    .output()
                    .await
            {
                for dev in String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|l| l.split(':').next())
                    .filter(|d| !d.is_empty())
                {
                    let _ = tokio::process::Command::new("losetup")
                        .args(["-d", dev])
                        .status()
                        .await;
                }
            }
            let _ = std::fs::remove_file(&path);
            info!(project = %id, artifact = "data-disks", "reaped orphaned artifact");
        }
    }
    // `objectstore/{id}` + `db-backups/{id}`: a deleted project's bucket tree / managed-DB
    // backup blobs ([RB11]). `buildcache/{id}`: its warm build caches + per-target artifact
    // cache. Delete purges them, but a crash-interrupted teardown can leave them — reap so a
    // recreated slug starts clean (it must never inherit the previous tenant's build
    // artifacts) and a deleted tenant's DB data doesn't linger.
    for sub in [
        "hosting",
        "run",
        "snapshots",
        "objectstore",
        "db-backups",
        "buildcache",
    ] {
        let Ok(entries) = std::fs::read_dir(data_dir.join(sub)) else {
            continue;
        };
        let entries: Vec<_> = entries.flatten().collect();
        for entry in entries {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            if !is_registered(&id) {
                let _ = std::fs::remove_dir_all(entry.path());
                info!(project = %id, artifact = %sub, "reaped orphaned dir");
            }
        }
    }
    // git bare repos (build·D push-to-deploy): `git/{id}.git` dirs. Reaps the
    // bare repo (and its credential's pushed objects) when a delete-time cleanup
    // was missed, so a recreated slug can't inherit them.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("git")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".git") else {
                continue;
            };
            if !is_registered(id) {
                let _ = std::fs::remove_dir_all(entry.path());
                info!(project = %id, artifact = "git", "reaped orphaned bare repo");
            }
        }
    }
}

/// Boot-time GC of the shared layer store (`baselayers/`). Base + per-language
/// runtime erofs blobs are content-addressed, dm-verity'd, and shared across ALL
/// projects; they accumulate as the platform's layers are rebuilt (each new base/
/// runtime version adds a `sha256-<hex>.erofs` and `platform.json` is repointed).
/// A blob is LIVE iff the CURRENT `platform.json` names it, OR some registered
/// project's current metadata image still attaches it (its baked `_layerpaths.json`
/// pins the exact base/runtime version that project deployed with — possibly older
/// than `platform.json` if it hasn't redeployed since). Everything else is an
/// unreferenced old version: reap it.
///
/// Runs at boot ONLY — before the proxy/control serve, so no deploy/wake can race
/// (same ordering guarantee as [`reconcile_orphans_on_boot`]); the live set needs no
/// lock. Per-tenant app layers live under each version dir and are already reclaimed
/// with the dir on prune, so only `baselayers/` leaks and only it is swept here.
///
/// FAILS SAFE: if `platform.json` is present but unparseable, or any project's layer
/// map can't be read, the sweep aborts (leak rather than risk reaping a live blob).
pub(crate) async fn reconcile_baselayers_on_boot(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let registered: Vec<String> = match plat.store.list_projects() {
        Ok(ps) => ps.into_iter().map(|p| p.id).collect(),
        Err(_) => return,
    };
    let data_dir = plat.data_dir.clone();
    drop(plat);

    let baselayers = data_dir.join("baselayers");
    if !baselayers.is_dir() {
        return;
    }
    let Some(live) = baselayers_live_set(&data_dir, &registered, layer_plan::try_read_layer_paths)
    else {
        return;
    };

    // Sweep: reap content-addressed blobs (`sha256-<hex>.erofs`) not in the live set.
    // Anything else in baselayers/ (platform.json, verity sidecars) is left untouched.
    let Ok(entries) = std::fs::read_dir(&baselayers) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !layer_plan::is_safe_layer_filename(&name) || live.contains(&name) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => info!(blob = %name, "reaped unreferenced baselayer blob"),
            Err(e) => warn!(blob = %name, error = %e, "failed to reap unreferenced baselayer blob"),
        }
    }
}

/// The LIVE set of `baselayers/` blob filenames the boot GC must never touch, or `None` ⇒ abort
/// the sweep (a manifest or layer map we can't read). `read_paths` is
/// [`layer_plan::try_read_layer_paths`] in production (`Ok(empty)` for an absent image).
///
/// Every VM a project can boot pins its own blobs, so BOTH metadata images count: the app VM's
/// `{id}.ext4` and a dedicated project's sibling DB VM's `{id}.db.ext4`. The DB image is the ONLY
/// referrer of the `rhypedb` runtime layer for a dedicated project (its app VM is built `AppNoDb`),
/// so skipping it reaped the old engine blob on the first host restart after a rhypedb layer swap
/// — and the DB VM's next cold boot / restore then had no engine layer to attach.
pub(crate) fn baselayers_live_set(
    data_dir: &Path,
    registered: &[String],
    read_paths: impl Fn(&Path) -> Result<Vec<PathBuf>>,
) -> Option<HashSet<String>> {
    let baselayers = data_dir.join("baselayers");
    let mut live: HashSet<String> = HashSet::new();

    // (1) Current platform.json base + every runtime are ALWAYS live (the next deploy
    //     and any project mid-deploy use them). baselayers/ existing implies platform.json
    //     should too — the platform-layer build installs the blobs THEN writes the
    //     manifest — so treat absent/unreadable/unparseable IDENTICALLY: abort the sweep
    //     rather than risk reaping the current (or a freshly-baked, not-yet-deployed-onto)
    //     base/runtime when the manifest momentarily isn't there.
    let platform_json = baselayers.join("platform.json");
    let parsed = std::fs::read(&platform_json)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let Some(v) = parsed else {
        warn!("baselayers GC: platform.json missing/unreadable/unparseable; skipping sweep");
        return None;
    };
    if let Some(f) = v
        .get("base")
        .and_then(|b| b.get("file"))
        .and_then(|f| f.as_str())
    {
        live.insert(f.to_string());
    }
    if let Some(rts) = v.get("runtimes").and_then(|r| r.as_object()) {
        for desc in rts.values() {
            if let Some(f) = desc.get("file").and_then(|f| f.as_str()) {
                live.insert(f.to_string());
            }
        }
    }

    // (2) Each registered project's CURRENT metadata images (app VM + dedicated DB VM) pin
    //     the exact base/runtime blobs they attach. If a layer map can't be read, abort the
    //     whole sweep (treating it as "references nothing" could reap a blob it still needs).
    let content_images = data_dir.join("content-images");
    let images = registered.iter().flat_map(|id| {
        [vm_identity::VmRole::App, vm_identity::VmRole::Db]
            .map(|role| content_images.join(format!("{}.ext4", vm_identity::vm_id(id, role))))
    });
    for img in images {
        let paths = match read_paths(&img) {
            Ok(p) => p,
            Err(e) => {
                warn!(image = %img.display(), error = %e, "baselayers GC: cannot read layer paths; skipping sweep");
                return None;
            }
        };
        for p in paths {
            // Match by content-addressed FILENAME, not parent path: the baked paths carry
            // the data_dir spelling AS OF deploy time, so a relocated/re-spelled data_dir
            // would make a live base/runtime's parent lexically != the boot-time baselayers
            // dir and silently drop it from the set. A `sha256-<hex>.erofs` name uniquely
            // identifies its blob regardless of directory; adding app-layer names too is
            // harmless (they never collide with a baselayers blob's content address).
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                live.insert(name.to_string());
            }
        }
    }
    Some(live)
}

/// Reconcile persisted state into the in-memory domain map at startup. Grandfathers
/// each deployed project's primary subdomain and any legacy `project.domains` into
/// the DOMAINS registry as Active (trusted prod data — no re-verification), then
/// loads all Active domains into the map so hosts resolve before traffic arrives.
/// Whether a registered project can actually be woken: it needs EITHER cold-boot
/// content (`hosting/{id}/live`) OR a restorable snapshot (snapshot + mem files
/// present) atop its metadata image (`content-images/{id}.ext4`). When neither holds,
/// its deployable artifacts were removed out-of-band (e.g. an over-aggressive cleanup)
/// and it can only come back via a redeploy — see [`ProjectState::NeedsRedeploy`].
pub(crate) fn project_can_wake(data_dir: &Path, store: &Store, project_id: &str) -> bool {
    if data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .is_dir()
    {
        return true; // can cold-boot from the deployed content
    }
    let content_image = data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"))
        .is_file();
    let snapshot_ok = store
        .get_snapshot_meta(project_id)
        .ok()
        .flatten()
        .map(|m| Path::new(&m.snapshot_path).exists() && Path::new(&m.mem_file_path).exists())
        .unwrap_or(false);
    content_image && snapshot_ok // can restore from snapshot
}

pub(crate) async fn backfill_domains(platform: &Arc<Mutex<PlatformState>>, domain_map: &DomainMap) {
    let active = {
        let mut plat = platform.lock().await;
        // Before anything reads the registry: drop rows a pre-wildcard binary may have
        // left behind across a rollback (proof-less `*` rows, orphaned wildcards).
        match plat.store.purge_invalid_domain_rows() {
            Ok(0) => {}
            Ok(n) => warn!(removed = n, "purged invalid domain rows at boot"),
            Err(e) => tracing::error!(error = %e, "domain-row purge failed"),
        }
        let projects = match plat.store.list_projects() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "failed to list projects");
                return;
            }
        };

        for project in &projects {
            if project.current_version.is_none() {
                continue;
            }
            match project.state {
                ProjectState::Active | ProjectState::Hibernated => {
                    // VM re-adoption §7: a project re-adopted Running this start is ALREADY live
                    // (its survivor VM + routes are up). Do NOT overwrite its state to Hibernated
                    // or flip redb — that silently breaks metering/log-ship/idle-hibernate/drain,
                    // which all filter on `== Running`. Just keep its domains grandfathered.
                    let adopted = plat.vm_states.get(&project.id) == Some(&VmLifecycle::Running)
                        || plat.vms.contains_key(&project.id);
                    // Reconcile a registered project whose deployable artifacts were
                    // removed out-of-band: it would otherwise be registered for wake and
                    // loop the proxy on "starting up" forever. Mark it NeedsRedeploy so
                    // the proxy serves a clear message; still grandfather its domains so
                    // the user gets that message (not a 404). A redeploy clears it.
                    let data_dir = plat.data_dir.clone();
                    if adopted {
                        // live survivor — leave Running + routes intact; grandfather only.
                    } else if !project_can_wake(&data_dir, &plat.store, &project.id) {
                        warn!(
                            project = %project.id,
                            "registered project has no deployable artifacts (content + snapshot gone) — marking needs-redeploy"
                        );
                        let mut p = project.clone();
                        p.state = ProjectState::NeedsRedeploy;
                        let _ = plat.store.update_project(&p);
                        // Drop the dangling snapshot pointer so nothing tries to restore it.
                        let _ = plat.store.remove_snapshot_meta(&project.id);
                    } else {
                        plat.vm_states
                            .insert(project.id.clone(), VmLifecycle::Hibernated);
                        if project.state == ProjectState::Active {
                            let mut p = project.clone();
                            p.state = ProjectState::Hibernated;
                            let _ = plat.store.update_project(&p);
                        }
                        // Clear a stale snapshot pointer (snapshot file gone but content
                        // present) so wake cold-boots cleanly from content instead of
                        // attempting a doomed restore.
                        if let Ok(Some(meta)) = plat.store.get_snapshot_meta(&project.id)
                            && !Path::new(&meta.snapshot_path).exists()
                        {
                            let _ = plat.store.remove_snapshot_meta(&project.id);
                        }
                    }

                    let tenant_id = project.tenant_id.clone().unwrap_or_default();
                    // Grandfather the primary subdomain (host-key == project id).
                    grandfather_domain(&plat.store, &project.id, &project.id, &tenant_id);
                    // Grandfather legacy project.domains (already-trusted aliases).
                    for host in &project.domains {
                        grandfather_domain(&plat.store, host, &project.id, &tenant_id);
                    }
                }
                ProjectState::NeedsRedeploy | ProjectState::Stopped => {
                    // NeedsRedeploy: still grandfather domains so the proxy can serve the
                    // clear "redeploy" message rather than a 404; don't register for wake.
                    if project.state == ProjectState::NeedsRedeploy {
                        let tenant_id = project.tenant_id.clone().unwrap_or_default();
                        grandfather_domain(&plat.store, &project.id, &project.id, &tenant_id);
                        for host in &project.domains {
                            grandfather_domain(&plat.store, host, &project.id, &tenant_id);
                        }
                    }
                }
            }
        }

        plat.store.list_all_domains().unwrap_or_default()
    };

    let mut map = domain_map.write().await;
    let mut count = 0usize;
    for d in active {
        if d.status == DomainStatus::Active {
            map.insert(d.host.clone(), d.target());
            count += 1;
        }
    }
    info!(
        domains = count,
        "domain map built; projects registered for on-demand wake"
    );
}

/// Ensure an Active DomainRecord exists for `host` (idempotent). Used by backfill
/// to migrate pre-registry data without forcing re-verification.
pub(crate) fn grandfather_domain(store: &Store, host: &str, project_id: &str, tenant_id: &str) {
    if matches!(store.get_domain(host), Ok(Some(_))) {
        return;
    }
    // Wildcards postdate the registry, so they are never legacy: a `*.` entry left in
    // a stale `project.domains` cache must NOT come back Active without DNS proof.
    if host.contains('*') {
        return;
    }
    let kind = if host.contains('.') {
        DomainKind::Custom
    } else {
        DomainKind::Subdomain
    };
    let record = DomainRecord {
        host: host.to_string(),
        project_id: project_id.to_string(),
        tenant_id: tenant_id.to_string(),
        site: None,
        kind,
        status: DomainStatus::Active,
        token: String::new(),
        created_at: 0,
        acme_delegation: None,
    };
    let _ = store.claim_domain(&record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::store::{SnapshotMeta, Store};
    use std::collections::HashMap;

    #[test]
    fn project_can_wake_requires_content_or_restorable_snapshot() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("jkbase-cw-{nanos}"));
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let store = Store::open(&root.join("s.redb")).unwrap();
        let snap_meta = |id: &str, sp: PathBuf, mp: PathBuf| SnapshotMeta {
            project_id: id.into(),
            snapshot_path: sp.to_string_lossy().into_owned(),
            mem_file_path: mp.to_string_lossy().into_owned(),
            created_at: 0,
            vcpu_count: 1,
            mem_size_mib: 1024,
            base_rootfs_hash: None,
            deployment_version: None,
        };

        // Nothing on disk, no snapshot → cannot wake.
        assert!(!project_can_wake(&data, &store, "p"));

        // Cold-boot content present (hosting/{id}/live) → can wake.
        std::fs::create_dir_all(data.join("hosting").join("p").join("live")).unwrap();
        assert!(project_can_wake(&data, &store, "p"));

        // Content image + a snapshot whose files BOTH exist → can restore → can wake.
        std::fs::create_dir_all(data.join("content-images")).unwrap();
        std::fs::write(data.join("content-images").join("q.ext4"), b"x").unwrap();
        let qsnap = data.join("snapshots").join("q");
        std::fs::create_dir_all(&qsnap).unwrap();
        std::fs::write(qsnap.join("snapshot"), b"s").unwrap();
        std::fs::write(qsnap.join("mem"), b"m").unwrap();
        store
            .save_snapshot_meta(&snap_meta("q", qsnap.join("snapshot"), qsnap.join("mem")))
            .unwrap();
        assert!(project_can_wake(&data, &store, "q"));

        // nlnwt's failure mode: a content image present but the snapshot files are gone
        // and there's no cold-boot content → CANNOT wake (needs redeploy).
        std::fs::write(data.join("content-images").join("r.ext4"), b"x").unwrap();
        let rsnap = data.join("snapshots").join("r");
        store
            .save_snapshot_meta(&snap_meta("r", rsnap.join("snapshot"), rsnap.join("mem")))
            .unwrap();
        assert!(!project_can_wake(&data, &store, "r"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A rhypedb layer swap repoints `platform.json` at the new engine; the OLD engine blob is
    /// then pinned only by a dedicated project's DB VM image (`{id}.db.ext4`). The boot GC must
    /// keep it live, and an unreadable DB image must abort the sweep like an app image does.
    #[test]
    fn baselayers_live_set_keeps_blobs_pinned_by_dedicated_db_vm_images() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data = std::env::temp_dir().join(format!("jkbase-blgc-{nanos}"));
        let blob = |c: char| format!("sha256-{}.erofs", c.to_string().repeat(64));
        let (base, new_db, old_db, app) = (blob('a'), blob('b'), blob('c'), blob('d'));
        std::fs::create_dir_all(data.join("baselayers")).unwrap();
        std::fs::write(
            data.join("baselayers/platform.json"),
            format!(
                r#"{{"base":{{"file":"{base}"}},"runtimes":{{"rhypedb":{{"file":"{new_db}"}}}}}}"#
            ),
        )
        .unwrap();
        let images = data.join("content-images");
        let pins: HashMap<PathBuf, Vec<PathBuf>> = HashMap::from([
            (
                images.join("p.ext4"),
                vec![PathBuf::from(&base), PathBuf::from(&app)],
            ),
            (
                images.join("p.db.ext4"),
                vec![PathBuf::from(&base), PathBuf::from(&old_db)],
            ),
        ]);
        let registered = vec!["p".to_string(), "q".to_string()];

        let live = baselayers_live_set(&data, &registered, |img| {
            Ok(pins.get(img).cloned().unwrap_or_default())
        })
        .expect("readable manifest + layer maps ⇒ a live set");
        for f in [&base, &new_db, &old_db, &app] {
            assert!(live.contains(f), "{f} must be live: {live:?}");
        }

        // An unreadable DB VM layer map aborts the sweep (never "references nothing").
        let unreadable = images.join("p.db.ext4");
        assert!(
            baselayers_live_set(&data, &registered, |img| {
                if img == unreadable {
                    anyhow::bail!("corrupt")
                }
                Ok(Vec::new())
            })
            .is_none()
        );

        let _ = std::fs::remove_dir_all(&data);
    }
}
