//! [`CephRbd`] — the cluster-grade R3 [`DataDiskProvider`]: per-project data disks
//! as Ceph RBD images, with **storage-enforced** read-write-once. Unlike the
//! node-local [`LocalLoop`](crate::LocalLoop) (which can only check that a prior
//! writer's *process* is gone on the SAME host), Ceph enforces single-writer in the
//! storage layer itself: `attach_rwo` **blocklists** any prior client at the OSDs —
//! so a superseded writer's in-flight and future I/O is rejected cluster-wide, even
//! if that writer is alive but partitioned on another host. It therefore advertises
//! [`Caps::STORAGE_ENFORCED_RWO`] and the factory accepts it as the data-disk
//! backend for a multi-node cluster.
//!
//! Like [`LocalLoop`], this backend shells out to the host CLIs (`rbd`, `ceph`) —
//! no Rust cloud SDK — so it adds no dependency; the `ceph` feature only gates the
//! module in. The single fence epoch (from the R2 lease) is persisted in the image
//! metadata (`rbd image-meta`); a stale token (older epoch than the recorded
//! holder) is refused with [`SubstrateError::Fenced`], and the live writers to fence
//! are read authoritatively from `rbd status` (the cluster's watcher list).
//!
//! **Highest-risk role: a false "exclusive" attach is silent multi-writer
//! corruption.** The safety argument here is: (1) a stale token never attaches; (2)
//! every live prior watcher is blocklisted BEFORE we map, and if any blocklist fails
//! we refuse ([`SubstrateError::RwoUnsafe`]) rather than risk a second writer.

use crate::{Backend, BlockDevice, Caps, DataDiskProvider, FenceToken, Result, SubstrateError};
use async_trait::async_trait;
use std::path::PathBuf;

/// Metadata keys stamped on the RBD image to record the current RWO holder.
const EPOCH_KEY: &str = "jkbase_epoch";
const HOLDER_KEY: &str = "jkbase_holder";
const SOURCE_KEY: &str = "jkbase_source";

pub struct CephRbd {
    pool: String,
    /// Optional `--conf` path; `None` uses the system default (`/etc/ceph/ceph.conf`).
    conf: Option<String>,
    /// Optional `--id` user; `None` uses the client default (admin).
    user: Option<String>,
}

fn be<E: std::fmt::Display>(e: E) -> SubstrateError {
    SubstrateError::Backend(e.to_string())
}

/// Ids become RBD image names; reject anything that isn't a plain id.
fn validate_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id != "."
        && id != ".."
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(SubstrateError::Backend(format!("invalid data-disk id {id:?} (must be a plain id)")))
    }
}

async fn run(cmd: &str, args: &[String]) -> Result<String> {
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

impl CephRbd {
    /// A provider over `pool`, using the system Ceph config + default (admin) user.
    pub fn new(pool: impl Into<String>) -> Self {
        Self { pool: pool.into(), conf: None, user: None }
    }
    /// Override the ceph config path (`--conf`).
    pub fn with_conf(mut self, conf: impl Into<String>) -> Self {
        self.conf = Some(conf.into());
        self
    }
    /// Override the client id (`--id`).
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// `<pool>/<id>` — the RBD image spec.
    fn spec(&self, id: &str) -> String {
        format!("{}/{}", self.pool, id)
    }

    /// Common `--conf/--id` flags prepended to every rbd/ceph invocation.
    fn base(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(c) = &self.conf {
            v.push("--conf".into());
            v.push(c.clone());
        }
        if let Some(u) = &self.user {
            v.push("--id".into());
            v.push(u.clone());
        }
        v
    }

    async fn rbd(&self, args: &[&str]) -> Result<String> {
        let mut a = self.base();
        a.extend(args.iter().map(|s| s.to_string()));
        run("rbd", &a).await
    }
    async fn ceph(&self, args: &[&str]) -> Result<String> {
        let mut a = self.base();
        a.extend(args.iter().map(|s| s.to_string()));
        run("ceph", &a).await
    }

    async fn image_exists(&self, id: &str) -> bool {
        self.rbd(&["info", &self.spec(id)]).await.is_ok()
    }

    /// The recorded holder epoch, if any (absent key => `None`).
    async fn current_epoch(&self, id: &str) -> Option<u64> {
        self.rbd(&["image-meta", "get", &self.spec(id), EPOCH_KEY])
            .await
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Addresses of every live client currently watching the image (its writers).
    async fn watchers(&self, id: &str) -> Result<Vec<String>> {
        let out = self.rbd(&["status", &self.spec(id)]).await?;
        Ok(out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("watcher="))
            .filter_map(|rest| rest.split_whitespace().next())
            .map(|s| s.to_string())
            .collect())
    }

    /// Devices this host has mapped for the image. Read from the kernel rbd sysfs
    /// (`/sys/bus/rbd/devices/<N>/{pool,name}` → `/dev/rbdN`) rather than parsing
    /// `rbd device list`, whose blank-namespace column makes whitespace splitting
    /// ambiguous.
    async fn mapped_devices(&self, id: &str) -> Result<Vec<String>> {
        let mut devs = Vec::new();
        let mut rd = match tokio::fs::read_dir("/sys/bus/rbd/devices").await {
            Ok(rd) => rd,
            Err(_) => return Ok(devs), // none mapped (or module not loaded)
        };
        while let Some(entry) = rd.next_entry().await? {
            let n = entry.file_name();
            let base = entry.path();
            let pool = tokio::fs::read_to_string(base.join("pool")).await.unwrap_or_default();
            let name = tokio::fs::read_to_string(base.join("name")).await.unwrap_or_default();
            if pool.trim() == self.pool && name.trim() == id {
                devs.push(format!("/dev/rbd{}", n.to_string_lossy()));
            }
        }
        Ok(devs)
    }

    async fn parse_device(&self, map_stdout: &str) -> Option<String> {
        map_stdout
            .lines()
            .rev()
            .map(|l| l.trim())
            .find(|l| l.starts_with("/dev/"))
            .map(|s| s.to_string())
    }
}

#[async_trait]
impl DataDiskProvider for CephRbd {
    async fn ensure(&self, id: &str, size_bytes: u64) -> Result<()> {
        validate_id(id)?;
        if self.image_exists(id).await {
            return Ok(()); // idempotent: never reformat existing data
        }
        // RBD --size is in MiB; round up so we never under-provision.
        let size_mib = size_bytes.div_ceil(1024 * 1024).max(1).to_string();
        self.rbd(&["create", &self.spec(id), "--size", &size_mib, "--image-feature", "exclusive-lock"])
            .await?;
        // Format on first creation only: map -> mkfs.ext4 -> unmap.
        let dev = self
            .parse_device(&self.rbd(&["map", &self.spec(id)]).await?)
            .await
            .ok_or_else(|| be("rbd map returned no device during format"))?;
        let fmt = run("mkfs.ext4", &["-F".into(), "-q".into(), dev.clone()]).await;
        let _ = self.rbd(&["unmap", &dev]).await; // always unmap, even on mkfs failure
        fmt?;
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        Ok(self.image_exists(id).await)
    }

    async fn attach_rwo(&self, id: &str, token: &FenceToken) -> Result<BlockDevice> {
        validate_id(id)?;
        if !self.image_exists(id).await {
            return Err(SubstrateError::NotFound(id.to_string()));
        }
        // Stale-token gate: a strictly newer holder must not be preempted.
        if let Some(e) = self.current_epoch(id).await
            && e > token.epoch
        {
            return Err(SubstrateError::Fenced { scope: id.to_string() });
        }
        // Storage-enforced fence: blocklist EVERY live prior writer before we map,
        // so its I/O is rejected cluster-wide. If we cannot fence one, refuse rather
        // than risk a second writer.
        for addr in self.watchers(id).await? {
            self.ceph(&["osd", "blocklist", "add", &addr]).await.map_err(|e| {
                SubstrateError::RwoUnsafe {
                    scope: format!("{id}: could not blocklist prior writer {addr}: {e}"),
                }
            })?;
        }
        // Drop any STALE mapping this host still has for the image (e.g. a prior
        // holder on this same host that crashed without detaching, now blocklisted)
        // before binding a fresh client — both for crash-recovery and so the new map
        // doesn't collide with a now-fenced local kernel client.
        for stale in self.mapped_devices(id).await? {
            let _ = self.rbd(&["unmap", &stale]).await;
        }
        // Map a fresh client (new address — not blocklisted) and record our hold.
        let dev = self
            .parse_device(&self.rbd(&["map", &self.spec(id)]).await?)
            .await
            .ok_or_else(|| be("rbd map returned no device"))?;
        let epoch = token.epoch.to_string();
        self.rbd(&["image-meta", "set", &self.spec(id), EPOCH_KEY, &epoch]).await?;
        self.rbd(&["image-meta", "set", &self.spec(id), HOLDER_KEY, &token.holder]).await?;
        self.rbd(&["image-meta", "set", &self.spec(id), SOURCE_KEY, &token.source_id]).await?;
        Ok(BlockDevice { path: PathBuf::from(dev) })
    }

    async fn detach(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        // Unmap every device this host has for the image (normally exactly one).
        for dev in self.mapped_devices(id).await? {
            let _ = self.rbd(&["unmap", &dev]).await;
        }
        Ok(())
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        self.detach(id).await?;
        if self.image_exists(id).await {
            self.rbd(&["rm", &self.spec(id)]).await?;
        }
        Ok(())
    }
}

impl Backend for CephRbd {
    fn backend_name(&self) -> &str {
        "ceph-rbd"
    }
    fn caps(&self) -> Caps {
        // Ceph enforces single-writer in the storage layer (exclusive-lock +
        // OSD blocklist), so RWO holds across hosts / a split brain.
        Caps::STORAGE_ENFORCED_RWO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_ids_rejected() {
        assert!(validate_id("proj-1_2.dat").is_ok());
        assert!(validate_id("../escape").is_err());
        assert!(validate_id("a/b").is_err());
        assert!(validate_id("").is_err());
    }

    #[test]
    fn spec_and_caps() {
        let c = CephRbd::new("rbd");
        assert_eq!(c.spec("d1"), "rbd/d1");
        assert_eq!(c.caps(), Caps::STORAGE_ENFORCED_RWO);
        assert_eq!(c.backend_name(), "ceph-rbd");
    }
}
