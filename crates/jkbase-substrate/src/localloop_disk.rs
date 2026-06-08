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
    /// Fence token the holder presented (epoch + issuing source), for diagnostics
    /// and the restore-path fence.
    epoch: u64,
    source_id: String,
    /// The loop device the image is bound to (`/dev/loopN`).
    loop_dev: String,
}

/// Linux process liveness without a libc dep: `/proc/<pid>` exists iff the process
/// does. Conservative — treats "can't tell" as alive elsewhere.
fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
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
        let mut lines = body.lines();
        let pid = lines.next()?.trim().parse().ok()?;
        let epoch = lines.next()?.trim().parse().ok()?;
        let source_id = lines.next()?.to_string();
        let loop_dev = lines.next()?.to_string();
        Some(Holder {
            pid,
            epoch,
            source_id,
            loop_dev,
        })
    }

    fn write_holder(&self, id: &str, h: &Holder) -> Result<()> {
        // Write atomically (temp + rename) so a crash mid-write never leaves a
        // truncated holder that `read_holder` would parse as "no holder" — which
        // would make the next attach skip the exclusivity/liveness gate.
        let body = format!("{}\n{}\n{}\n{}", h.pid, h.epoch, h.source_id, h.loop_dev);
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
            if process_alive(h.pid) {
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
        self.write_holder(
            id,
            &Holder {
                pid: std::process::id(),
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
                self.write_holder(id, &Holder { pid, ..h })
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
    fn process_alive_distinguishes_live_from_dead() {
        assert!(process_alive(std::process::id())); // ourselves
        assert!(!process_alive(0)); // /proc/0 never exists
        assert!(!process_alive(4_000_000_000)); // implausible PID
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
        p.write_holder(
            "d",
            &Holder {
                pid: std::process::id(),
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
        p.write_holder(
            "d",
            &Holder { pid: std::process::id(), epoch: 7, source_id: "src".into(), loop_dev: "/dev/loopX".into() },
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
