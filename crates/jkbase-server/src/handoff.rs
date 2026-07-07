//! Per-running-VM **re-adoption record** (`run/<id>/handoff.json`) — the host-written state
//! that lets a NEW `jkbase-server` re-adopt a tenant Firecracker that SURVIVED the previous
//! process's exit (it lives in the `jkbase-runtime` cgroup, so `systemctl restart` did not
//! reap it) instead of draining → cold-restoring it. See `docs/vm-readoption-design.md` §3.
//!
//! Written at commit-to-Running (deploy + wake), **atomically** (temp + fsync + rename,
//! mirroring `rootfs_cas::place` / `LocalLoop::write_holder`), and removed on EVERY teardown
//! path (hibernate — *first*, before the pause — force-stop, self-fence, teardown, redeploy,
//! wake-abort).
//!
//! **Strict parse is load-bearing:** any partial / garbage / unknown-schema / `fc_starttime==0`
//! record is treated as **no record** (the VM is reaped + cold-booted), NEVER as a lenient
//! "starttime 0 ⇒ PID-only liveness" fallback — that fallback is exactly what defeats PID
//! reuse, and re-adoption must not inherit it. The record carries only what adoption needs;
//! the metadata image + erofs layer paths are re-derived from the deployment on the next
//! wake (fixed paths), so they are deliberately NOT stored here.
//!
//! Keyed entirely by host paths the guest cannot reach, so a guest cannot forge an identity:
//! a guest that crashes its own FC only fails its own liveness check → its own project
//! cold-boots.

use crate::vm_identity::{split_vm_id, VmRole};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Bumped on any incompatible change to [`HandoffRecord`]. A record whose `schema_version`
/// is not exactly this is treated as no record (force recycle + cold boot), so an upgrade
/// that changes the shape can never mis-read an old survivor's record.
pub const SCHEMA_VERSION: u32 = 1;

/// Everything the new process needs to re-adopt one surviving runtime Firecracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffRecord {
    pub schema_version: u32,
    /// The **rendered** VM id (`project_id` for an App VM, `"{project_id}.db"` for a dedicated
    /// DB VM) — equal to the `run/<id>` path segment this record lives under, so `read_strict`
    /// rejects a misplaced/forged file.
    pub project_id: String,
    /// Which of the project's Firecrackers this record describes. `#[serde(default)]` = App, so an
    /// old (pre-P2) record with no `role` field re-adopts as an App VM unchanged — this is why
    /// [`SCHEMA_VERSION`] does NOT bump for the DB-VM work (a bump would reject every in-flight
    /// app survivor and bounce the whole fleet on the P2 rollout).
    #[serde(default)]
    pub role: VmRole,
    /// Firecracker OS pid + its `/proc/<pid>/stat` field-22 start time, captured from the
    /// SAME read so the pid is pinned to one incarnation (PID-reuse-proof).
    pub fc_pid: u32,
    pub fc_starttime: u64,
    pub ip: String,
    pub tap: String,
    pub mac: String,
    /// The loop device backing the data disk + the lease epoch it was fenced at — present
    /// only for projects WITH a data disk (`None` for diskless projects, which skip the
    /// `adopt_writer` re-fence entirely).
    pub loop_dev: Option<String>,
    pub lease_epoch: Option<u64>,
    /// The base-rootfs CAS hash the guest RAM actually maps (kept out of the GC reap set
    /// while the survivor is live — §6a).
    pub base_rootfs_hash: String,
    /// The project's deployed version at commit time — used to detect drift at adopt.
    pub deployment_version: Option<u64>,
}

fn dir(runtime_dir: &Path, id: &str) -> PathBuf {
    runtime_dir.join(id)
}

/// `run/<id>/handoff.json`.
pub fn path(runtime_dir: &Path, id: &str) -> PathBuf {
    dir(runtime_dir, id).join("handoff.json")
}

/// Persist `rec` atomically. The `run/<id>/` dir already exists (created by `VmInstance::start`
/// / `restore_from_snapshot`); a partial write lands at a pid-tagged `.tmp` and is renamed only
/// after fsync, so a crash mid-write never leaves a truncated record a strict read would have
/// to reject anyway.
pub fn write(runtime_dir: &Path, id: &str, rec: &HandoffRecord) -> std::io::Result<()> {
    let d = dir(runtime_dir, id);
    std::fs::create_dir_all(&d)?;
    let body = serde_json::to_vec(rec)?;
    let tmp = d.join(format!("handoff.json.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::fs::write(&tmp, &body)?;
    {
        let f = std::fs::File::open(&tmp)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path(runtime_dir, id))
}

/// Read a record STRICTLY: returns `Some` only for a well-formed record of the current schema
/// whose `fc_starttime` is non-zero and whose `project_id` matches `id` (a misplaced/forged
/// file is rejected). Any read/parse error, schema mismatch, zero start time, or id mismatch
/// ⇒ `None` (the caller reaps + cold-boots).
pub fn read_strict(runtime_dir: &Path, id: &str) -> Option<HandoffRecord> {
    let body = std::fs::read(path(runtime_dir, id)).ok()?;
    let rec: HandoffRecord = serde_json::from_slice(&body).ok()?;
    // `role` must match what the id's `.db` suffix implies, so a record can't restore a DB VM as
    // an app VM (or vice-versa) even if the file were moved between run dirs.
    if rec.schema_version != SCHEMA_VERSION
        || rec.fc_starttime == 0
        || rec.project_id != id
        || split_vm_id(id).1 != rec.role
    {
        return None;
    }
    Some(rec)
}

/// Remove the record (idempotent; absent is fine). Tied to teardown — once gone, a surviving
/// FC for `id` is treated as an orphan and reaped on the next start.
pub fn remove(runtime_dir: &Path, id: &str) {
    let _ = std::fs::remove_file(path(runtime_dir, id));
}

/// Every strictly-valid handoff record under `runtime_dir/*/handoff.json`. Used by the
/// pre-GC keep-set scan (§6a) and the adoption pass (§6b). Cheap: a few small JSON reads.
pub fn scan(runtime_dir: &Path) -> Vec<HandoffRecord> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(runtime_dir) else {
        return out;
    };
    for entry in rd.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if let Some(rec) = read_strict(runtime_dir, &id) {
            out.push(rec);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-handoff-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn rec(id: &str) -> HandoffRecord {
        HandoffRecord {
            schema_version: SCHEMA_VERSION,
            project_id: id.to_string(),
            role: split_vm_id(id).1,
            fc_pid: 4242,
            fc_starttime: 99,
            ip: "172.16.0.2".into(),
            tap: "jktap0".into(),
            mac: "AA:FC:00:00:00:01".into(),
            loop_dev: Some("/dev/loop3".into()),
            lease_epoch: Some(7),
            base_rootfs_hash: "a".repeat(64),
            deployment_version: Some(3),
        }
    }

    #[test]
    fn write_read_remove_round_trips() {
        let rt = tmp("rt");
        write(&rt, "proj", &rec("proj")).unwrap();
        let got = read_strict(&rt, "proj").unwrap();
        assert_eq!(got.fc_pid, 4242);
        assert_eq!(got.loop_dev.as_deref(), Some("/dev/loop3"));
        assert_eq!(got.lease_epoch, Some(7));
        remove(&rt, "proj");
        assert!(read_strict(&rt, "proj").is_none());
        let _ = std::fs::remove_dir_all(&rt);
    }

    #[test]
    fn strict_parse_rejects_bad_records() {
        let rt = tmp("strict");
        // garbage
        std::fs::create_dir_all(rt.join("g")).unwrap();
        std::fs::write(path(&rt, "g"), b"{not json").unwrap();
        assert!(read_strict(&rt, "g").is_none());
        // zero start time ⇒ rejected (never the legacy PID-only fallback)
        let mut z = rec("z");
        z.fc_starttime = 0;
        write(&rt, "z", &z).unwrap();
        assert!(read_strict(&rt, "z").is_none());
        // unknown schema ⇒ rejected
        let mut s = rec("s");
        s.schema_version = SCHEMA_VERSION + 1;
        write(&rt, "s", &s).unwrap();
        assert!(read_strict(&rt, "s").is_none());
        // id mismatch (a record dropped into the wrong dir) ⇒ rejected
        write(&rt, "right", &rec("wrong")).unwrap();
        assert!(read_strict(&rt, "right").is_none());
        // role/id-suffix mismatch: a DB-role record under an App-id dir ⇒ rejected (defends
        // against a survivor being re-adopted as the wrong role).
        let mut wrong_role = rec("appvm");
        wrong_role.role = VmRole::Db;
        write(&rt, "appvm", &wrong_role).unwrap();
        assert!(read_strict(&rt, "appvm").is_none());
        let _ = std::fs::remove_dir_all(&rt);
    }

    #[test]
    fn db_vm_record_round_trips_with_role() {
        let rt = tmp("dbrole");
        // A rendered DB VM id (`{project}.db`) parses to role Db and round-trips.
        write(&rt, "proj.db", &rec("proj.db")).unwrap();
        let got = read_strict(&rt, "proj.db").unwrap();
        assert_eq!(got.role, VmRole::Db);
        assert_eq!(got.project_id, "proj.db");
        let _ = std::fs::remove_dir_all(&rt);
    }

    #[test]
    fn scan_returns_only_valid_records() {
        let rt = tmp("scan");
        write(&rt, "ok1", &rec("ok1")).unwrap();
        write(&rt, "ok2", &rec("ok2")).unwrap();
        let mut bad = rec("bad");
        bad.fc_starttime = 0;
        write(&rt, "bad", &bad).unwrap();
        // a dir with no handoff at all
        std::fs::create_dir_all(rt.join("empty")).unwrap();
        let mut ids: Vec<String> = scan(&rt).into_iter().map(|r| r.project_id).collect();
        ids.sort();
        assert_eq!(ids, vec!["ok1".to_string(), "ok2".to_string()]);
        let _ = std::fs::remove_dir_all(&rt);
    }
}
