//! The content-addressed base rootfs: build, pin at `base-rootfs/<hash>.ext4`, and GC.

use crate::cli::Args;
use crate::{handoff, rootfs_cas};
use anyhow::Result;
use jkbase_control::store::Store;
use jkbase_orch::rootfs;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Content-address the base rootfs so a redeploy that ships a new agent can never poison a
/// pre-existing hibernation snapshot (incident: nlnwt, 2026-06-26). The staging artifact at
/// `base-rootfs.ext4` is built by the deploy script in prod (apko may not be on the service's
/// PATH) or the local-dev fallback; we hash it and pin it immutably at `base-rootfs/<hash>.ext4`.
/// ORDER IS LOAD-BEARING (see docs/rootfs-cas-snapshot-durability.md): CAS-ize → GC, ALL
/// synchronously here, before any loop that can boot/restore a VM is spawned (the HA
/// reconciler/disk-fence, spawned after this returns) and before the proxy binds. VM re-adoption (§6) changes the
/// premise that this used to depend on: runtime FCs now SURVIVE a restart (they live in the
/// jkbase-runtime cgroup), so we do NOT reap them here — the old blunt pre-GC reaper is gone.
/// Instead the survivors' rootfs blobs are kept out of the sweep (the keep-set scan below), and
/// the full verify/adopt/reap of survivors happens after PlatformState is built (§6b). GC
/// unlinking a still-mapped blob is non-destructive anyway (the FC holds the fd; bytes survive
/// until it closes), and a true orphan is reaped in §6b.
pub(crate) async fn place_and_gc(
    args: &Args,
    data_dir: &Path,
    store: &Store,
) -> Result<(PathBuf, String)> {
    let staging_rootfs = data_dir.join("base-rootfs.ext4");
    rootfs::build_base_rootfs(&args.agent_bin, &staging_rootfs).await?;
    let cas_dir = data_dir.join("base-rootfs");
    let runtime_dir = data_dir.join("run");
    let (base_rootfs_path, base_rootfs_hash) = rootfs_cas::place(&staging_rootfs, &cas_dir)?;
    // FAIL CLOSED: only reap a blob we can PROVE no restorable snapshot references. If we can't
    // enumerate every snapshot's stamped hash, skip all deletes (a partial set would reap a live
    // blob). Over-deletion is self-healing anyway (missing blob ⇒ non-viable restore ⇒ cold boot).
    match store.list_snapshot_metas() {
        Ok(metas) => {
            let mut keep: HashSet<String> = HashSet::new();
            keep.insert(base_rootfs_hash.clone());
            for m in &metas {
                if let Some(h) = &m.base_rootfs_hash
                    && rootfs_cas::is_sha256_hex(h)
                {
                    keep.insert(h.clone());
                }
            }
            // §6a: keep every LIVE survivor's mapped rootfs blob — an upgrade mints a new
            // current_hash, and a survivor that hibernated before this start carries no snapshot
            // yet, so without this union its (old) blob would be reaped and its next hibernate
            // would stamp a missing blob → forced cold-boot. Cheap scan of run/*/handoff.json.
            for rec in handoff::scan(&runtime_dir) {
                if rootfs_cas::is_sha256_hex(&rec.base_rootfs_hash) {
                    keep.insert(rec.base_rootfs_hash.clone());
                }
            }
            match rootfs_cas::gc(&cas_dir, &keep) {
                Ok(removed) if !removed.is_empty() => {
                    info!(
                        count = removed.len(),
                        "GC: reaped unreferenced base-rootfs blobs"
                    )
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "base-rootfs GC failed; skipped (no blobs reaped)"),
            }
        }
        Err(e) => {
            warn!(error = %e, "could not enumerate snapshots; skipping base-rootfs GC (fail closed)")
        }
    }
    Ok((base_rootfs_path, base_rootfs_hash))
}
