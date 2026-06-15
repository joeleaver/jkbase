//! [`LocalLoop`] — the node-local [`DataDiskProvider`]: per-project data disks as
//! ext4 image files bound to loop devices. Advertises [`Caps::NODE_LOCAL_RWO`] —
//! read-write-once is enforced only within a single host, so the factory refuses
//! it as the data-disk backend for a multi-node cluster.
//!
//! **This is the highest-risk role: a false "exclusive" attach is silent
//! multi-writer corruption.** `attach_rwo` therefore gates on a persisted holder
//! record: if a prior writer's process is still alive it REFUSES
//! ([`SubstrateError::RwoUnsafe`]) and the caller must cold-boot; only when the
//! prior writer is gone does it preempt the stale loop binding and attach.
//!
//! The holder PID recorded is the attaching process (the lifecycle owner of the
//! microVM). On the deployed platform Firecracker children are killed with
//! jkbase-server by the systemd cgroup, so "owner dead ⇒ writer dead" holds; the
//! restore-path-fence card refines this to track the Firecracker PID directly.

use crate::{Backend, BlockDevice, Caps, DataDiskProvider, FenceToken, Result, SubstrateError};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

pub struct LocalLoop {
    dir: PathBuf,
}

/// The current read-write-once holder of a disk, persisted beside its image.
struct Holder {
    /// PID of the process that owns the writer (checked for liveness on preempt).
    pid: u32,
    /// Start time of `pid` (jiffies since boot, `/proc/<pid>/stat` field 22) at the
    /// moment the holder was written. Pins the liveness check to the SAME process
    /// incarnation so a recycled PID (the kernel handing `pid` to an unrelated
    /// process) doesn't read as "prior writer still alive" and wedge the disk in
    /// `RwoUnsafe`. `0` means UNKNOWN — a legacy 4-line holder written before this
    /// field existed — and falls back to the PID-only check.
    pid_starttime: u64,
    /// Fence token the holder presented (epoch + issuing source), for diagnostics
    /// and the restore-path fence.
    epoch: u64,
    source_id: String,
    /// The loop device the image is bound to (`/dev/loopN`).
    loop_dev: String,
}

/// Process start time (jiffies since boot) from field 22 of `/proc/<pid>/stat`, or
/// `None` if the process is gone / the stat line is unparseable. Used to detect PID
/// reuse: a recycled PID gets a different start time. The `comm` field (field 2) is
/// parenthesised and may itself contain spaces and `)`, so split the tail AFTER the
/// last `)` — there, field 22 is index 19 (field 3 `state` is index 0).
fn process_starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Liveness with PID-reuse resistance. With a known `expected_starttime` the process
/// counts as alive only if its current start time still matches (same incarnation).
/// `expected_starttime == 0` is a legacy holder with no recorded start time: fall
/// back to the conservative PID-only check (`/proc/<pid>` exists iff the process does).
fn process_alive_with_identity(pid: u32, expected_starttime: u64) -> bool {
    match process_starttime(pid) {
        Some(st) if expected_starttime != 0 => st == expected_starttime,
        Some(_) => true, // legacy holder (unknown start time): PID exists ⇒ alive
        None => false,   // process gone (or /proc unreadable) ⇒ not alive
    }
}

/// Ids become filenames; reject traversal so a disk id can't escape the dir.
fn validate_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(SubstrateError::Backend(format!(
            "invalid data-disk id {id:?} (must be a plain id)"
        )))
    }
}

async fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| SubstrateError::Backend(format!("{cmd}: {e}")))?;
    if !out.status.success() {
        return Err(SubstrateError::Backend(format!(
            "{cmd} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl LocalLoop {
    /// Open (creating if absent) a data-disk provider rooted at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn img_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.img"))
    }
    fn holder_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.holder"))
    }

    fn read_holder(&self, id: &str) -> Option<Holder> {
        let body = std::fs::read_to_string(self.holder_path(id)).ok()?;
        let lines: Vec<&str> = body.lines().collect();
        // Two on-disk layouts, disambiguated by line count: the current 5-line
        // (pid, pid_starttime, epoch, source_id, loop_dev) and the legacy 4-line
        // (pid, epoch, source_id, loop_dev) written before start-time tracking. A
        // legacy record is read with pid_starttime=0 (UNKNOWN), preserving the prior
        // PID-only liveness behaviour for holders already on disk in production.
        match lines.as_slice() {
            [pid, pid_starttime, epoch, source_id, loop_dev] => Some(Holder {
                pid: pid.trim().parse().ok()?,
                // Lenient: a corrupt start time degrades to 0=UNKNOWN (PID-only liveness)
                // rather than failing the whole parse — returning None here would make
                // attach_rwo see "no holder" and SKIP the exclusivity gate (fail-open).
                pid_starttime: pid_starttime.trim().parse().unwrap_or(0),
                epoch: epoch.trim().parse().ok()?,
                source_id: source_id.to_string(),
                loop_dev: loop_dev.to_string(),
            }),
            [pid, epoch, source_id, loop_dev] => Some(Holder {
                pid: pid.trim().parse().ok()?,
                pid_starttime: 0,
                epoch: epoch.trim().parse().ok()?,
                source_id: source_id.to_string(),
                loop_dev: loop_dev.to_string(),
            }),
            _ => None,
        }
    }

    fn write_holder(&self, id: &str, h: &Holder) -> Result<()> {
        // Write atomically (temp + rename) so a crash mid-write never leaves a
        // truncated holder that `read_holder` would parse as "no holder" — which
        // would make the next attach skip the exclusivity/liveness gate. The temp
        // name carries our PID so a crash mid-write leaves a `{id}.holder.tmp.{pid}`
        // that the boot-time orphan sweep reaps.
        let body = format!(
            "{}\n{}\n{}\n{}\n{}",
            h.pid, h.pid_starttime, h.epoch, h.source_id, h.loop_dev
        );
        let dest = self.holder_path(id);
        let tmp = self.dir.join(format!("{id}.holder.tmp.{}", std::process::id()));
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &dest)?;
        Ok(())
    }
}

#[async_trait]
impl DataDiskProvider for LocalLoop {
    async fn ensure(&self, id: &str, size_bytes: u64) -> Result<()> {
        validate_id(id)?;
        let img = self.img_path(id);
        if tokio::fs::try_exists(&img).await.unwrap_or(false) {
            // Idempotent: an existing disk keeps its data; never reformat, and
            // never shrink. (Growing the fs is resize2fs territory — out of scope.)
            return Ok(());
        }
        if let Some(p) = img.parent() {
            tokio::fs::create_dir_all(p).await?;
        }
        // Sparse-allocate then format the FILE directly — mkfs.ext4 on a regular
        // file needs no loop device and no root (so `ensure` stays unprivileged).
        let f = tokio::fs::File::create(&img).await?;
        f.set_len(size_bytes).await?;
        drop(f);
        run("mkfs.ext4", &["-F", "-q", img.to_str().unwrap()]).await?;
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        Ok(tokio::fs::try_exists(self.img_path(id)).await.unwrap_or(false))
    }

    async fn attach_rwo(&self, id: &str, token: &FenceToken) -> Result<BlockDevice> {
        validate_id(id)?;
        let img = self.img_path(id);
        if !tokio::fs::try_exists(&img).await.unwrap_or(false) {
            return Err(SubstrateError::NotFound(id.to_string()));
        }
        // Exclusivity gate. If a prior writer is still alive, REFUSE — the caller
        // must cold-boot rather than risk a second writer on the same disk.
        if let Some(h) = self.read_holder(id) {
            if process_alive_with_identity(h.pid, h.pid_starttime) {
                return Err(SubstrateError::RwoUnsafe {
                    scope: id.to_string(),
                });
            }
            // Prior writer is gone: preempt its (now-stale) loop binding.
            let _ = run("losetup", &["-d", &h.loop_dev]).await;
        }
        // Defensively detach any other stale binding of this image before we rebind.
        if let Ok(out) = run("losetup", &["-j", img.to_str().unwrap()]).await {
            for dev in out.lines().filter_map(|l| l.split(':').next()) {
                if !dev.is_empty() {
                    let _ = run("losetup", &["-d", dev]).await;
                }
            }
        }
        // Bind a fresh loop device read-write.
        let dev = run("losetup", &["--find", "--show", img.to_str().unwrap()])
            .await?
            .trim()
            .to_string();
        let pid = std::process::id();
        self.write_holder(
            id,
            &Holder {
                pid,
                pid_starttime: process_starttime(pid).unwrap_or(0),
                epoch: token.epoch,
                source_id: token.source_id.clone(),
                loop_dev: dev.clone(),
            },
        )?;
        Ok(BlockDevice {
            path: PathBuf::from(dev),
        })
    }

    async fn set_writer_pid(&self, id: &str, token: &FenceToken, pid: u32) -> Result<()> {
        validate_id(id)?;
        // Only the current holder may refine the writer pid; if our token no longer
        // matches the persisted holder we've been fenced.
        match self.read_holder(id) {
            Some(h) if h.epoch == token.epoch && h.source_id == token.source_id => {
                // Re-pin the liveness identity to the NEW pid's incarnation; if it's
                // already gone (None) record 0 so the holder falls back to PID-only.
                let pid_starttime = process_starttime(pid).unwrap_or(0);
                self.write_holder(
                    id,
                    &Holder {
                        pid,
                        pid_starttime,
                        ..h
                    },
                )
            }
            _ => Err(SubstrateError::Fenced { scope: id.to_string() }),
        }
    }

    async fn detach(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        if let Some(h) = self.read_holder(id) {
            let _ = run("losetup", &["-d", &h.loop_dev]).await;
            let _ = std::fs::remove_file(self.holder_path(id));
        }
        Ok(())
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        self.detach(id).await?;
        let _ = std::fs::remove_file(self.img_path(id));
        let _ = std::fs::remove_file(self.holder_path(id));
        Ok(())
    }
}

impl Backend for LocalLoop {
    fn backend_name(&self) -> &str {
        "localloop"
    }
    fn caps(&self) -> Caps {
        Caps::NODE_LOCAL_RWO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-loop-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn token(epoch: u64) -> FenceToken {
        FenceToken {
            scope: "disk".into(),
            epoch,
            holder: "node-a".into(),
            source_id: "src".into(),
        }
    }

    #[test]
    fn process_starttime_reads_self_and_handles_dead() {
        assert!(process_starttime(std::process::id()).is_some_and(|st| st > 0)); // ourselves
        assert_eq!(process_starttime(0), None); // /proc/0 never exists
        assert_eq!(process_starttime(4_000_000_000), None); // implausible PID
    }

    #[test]
    fn liveness_detects_pid_reuse() {
        let me = std::process::id();
        let st = process_starttime(me).unwrap();
        // Same PID + matching start time ⇒ same incarnation ⇒ alive.
        assert!(process_alive_with_identity(me, st));
        // Same PID, DIFFERENT start time ⇒ the PID was recycled ⇒ NOT the prior writer.
        assert!(!process_alive_with_identity(me, st.wrapping_add(1)));
        // Legacy holder (start time 0/UNKNOWN) ⇒ PID-only fallback.
        assert!(process_alive_with_identity(me, 0));
        assert!(!process_alive_with_identity(4_000_000_000, 0));
    }

    #[test]
    fn read_holder_accepts_legacy_4line_format() {
        let p = LocalLoop::open(dir("legacy")).unwrap();
        // A holder written before pid_starttime existed: 4 lines, no start time.
        std::fs::write(p.holder_path("d"), b"1234\n7\nsrc\n/dev/loop3").unwrap();
        let h = p.read_holder("d").unwrap();
        assert_eq!(h.pid, 1234);
        assert_eq!(h.pid_starttime, 0); // UNKNOWN ⇒ PID-only liveness
        assert_eq!(h.epoch, 7);
        assert_eq!(h.source_id, "src");
        assert_eq!(h.loop_dev, "/dev/loop3");
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[test]
    fn invalid_ids_rejected() {
        assert!(validate_id("proj-1_2.dat").is_ok());
        assert!(validate_id("../escape").is_err());
        assert!(validate_id("a/b").is_err());
        assert!(validate_id("").is_err());
    }

    #[tokio::test]
    async fn attach_refuses_while_prior_writer_is_alive() {
        let p = LocalLoop::open(dir("alive")).unwrap();
        // Pretend the disk image exists and is held by a LIVE process (ourselves).
        std::fs::write(p.img_path("d"), b"").unwrap();
        let me = std::process::id();
        p.write_holder(
            "d",
            &Holder {
                pid: me,
                pid_starttime: process_starttime(me).unwrap(),
                epoch: 1,
                source_id: "src".into(),
                loop_dev: "/dev/loopX".into(),
            },
        )
        .unwrap();
        // Must refuse BEFORE touching losetup — exclusivity gate.
        assert!(matches!(
            p.attach_rwo("d", &token(2)).await,
            Err(SubstrateError::RwoUnsafe { .. })
        ));
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[tokio::test]
    async fn set_writer_pid_refines_holder_and_honors_token() {
        let p = LocalLoop::open(dir("setpid")).unwrap();
        std::fs::write(p.img_path("d"), b"").unwrap();
        let me = std::process::id();
        p.write_holder(
            "d",
            &Holder { pid: me, pid_starttime: process_starttime(me).unwrap(), epoch: 7, source_id: "src".into(), loop_dev: "/dev/loopX".into() },
        )
        .unwrap();
        // The current holder refines the writer pid to the (now-known) FC pid.
        p.set_writer_pid("d", &token(7), 4242).await.unwrap();
        assert_eq!(p.read_holder("d").unwrap().pid, 4242);
        // A superseded token can no longer refine — it has been fenced.
        assert!(matches!(
            p.set_writer_pid("d", &token(8), 99).await,
            Err(SubstrateError::Fenced { .. })
        ));
        assert_eq!(p.read_holder("d").unwrap().pid, 4242); // unchanged
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[tokio::test]
    async fn attach_missing_disk_is_not_found() {
        let p = LocalLoop::open(dir("missing")).unwrap();
        assert!(matches!(
            p.attach_rwo("nope", &token(1)).await,
            Err(SubstrateError::NotFound(_))
        ));
        assert_eq!(p.caps(), Caps::NODE_LOCAL_RWO);
        assert_eq!(p.backend_name(), "localloop");
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    /// Full ensure → attach → detach → destroy cycle. Needs root + losetup + mkfs,
    /// so it's ignored by default. Run on a capable box with:
    ///   sudo -E cargo test -p jkbase-substrate --  --ignored loop_full_cycle
    #[tokio::test]
    #[ignore = "needs root + losetup + mkfs.ext4"]
    async fn loop_full_cycle() {
        let p = LocalLoop::open(dir("cycle")).unwrap();
        p.ensure("d", 8 * 1024 * 1024).await.unwrap();
        let dev = p.attach_rwo("d", &token(1)).await.unwrap();
        assert!(dev.path.to_string_lossy().starts_with("/dev/loop"));
        // A second attach while we (a live PID) hold it must refuse.
        assert!(matches!(
            p.attach_rwo("d", &token(2)).await,
            Err(SubstrateError::RwoUnsafe { .. })
        ));
        p.detach("d").await.unwrap();
        // After detach a fresh attach succeeds (holder record cleared).
        let _dev2 = p.attach_rwo("d", &token(3)).await.unwrap();
        p.destroy("d").await.unwrap();
        assert!(!std::path::Path::new(&p.img_path("d")).exists());
        let _ = std::fs::remove_dir_all(&p.dir);
    }
}
