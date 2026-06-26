//! Firecracker **jailer** integration for build microVMs.
//!
//! Build VMs run hostile, attacker-controlled code, so — unlike the runtime
//! path ([`crate::vm`]) — they are launched under the Firecracker `jailer`,
//! which chroots the VM, drops it to a dedicated non-root uid/gid, applies
//! cgroup-v2 resource limits, enters a fresh PID namespace, and `mknod`s the
//! device nodes inside the jail. This module owns the *pure* path/argv math and
//! the small set of root-side staging helpers; the lifecycle lives in
//! [`crate::build_vm`].
//!
//! Derived from the reviewed hardening spec. Items that can only be confirmed on
//! a real KVM host are marked `// VERIFY(build/jailer):`.

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Everything needed to build the jailer argv for one build VM. Pure data — no
/// I/O happens in here.
pub struct JailerConfig {
    pub jailer_bin: PathBuf,
    /// `--exec-file`: the firecracker binary the jailer chroots and execs.
    pub firecracker_bin: PathBuf,
    /// Sanitized id (`[A-Za-z0-9-]`, ≤64). Use [`sanitize_id`].
    pub id: String,
    pub uid: u32,
    pub gid: u32,
    /// `--chroot-base-dir`. MUST be on the same filesystem as the drive images
    /// (RO images are hard-linked into the jail).
    pub chroot_base: PathBuf,
    /// Root-owned parent cgroup whose ceilings the jailed uid cannot raise.
    pub parent_cgroup: String,
    /// Leaf `--cgroup key=value` writes (belt; the parent ceiling is suspenders).
    pub cgroups: Vec<(String, String)>,
    /// Optional `--resource-limit key=value` (e.g. `fsize`).
    pub resource_limits: Vec<(String, String)>,
    /// `--netns` path. `None` for now → the build VM has no network at all.
    pub netns: Option<PathBuf>,
}

impl JailerConfig {
    /// The ordered jailer arguments (excluding the jailer binary itself, which
    /// is the program passed to `Command::new`). Everything after `--` is
    /// forwarded to firecracker.
    pub fn argv(&self, layout: &JailerLayout) -> Vec<OsString> {
        // VERIFY(build/jailer): v1.15.1 still defaults cgroup-version to 1, so
        // requesting "2" explicitly (below) is mandatory.
        let mut a: Vec<OsString> = vec![
            "--id".into(),
            self.id.as_str().into(),
            "--exec-file".into(),
            self.firecracker_bin.clone().into_os_string(),
            "--uid".into(),
            self.uid.to_string().into(),
            "--gid".into(),
            self.gid.to_string().into(),
            "--chroot-base-dir".into(),
            self.chroot_base.clone().into_os_string(),
            "--cgroup-version".into(),
            "2".into(),
            "--parent-cgroup".into(),
            self.parent_cgroup.as_str().into(),
        ];
        for (k, v) in &self.cgroups {
            a.push("--cgroup".into());
            a.push(format!("{k}={v}").into());
        }
        for (k, v) in &self.resource_limits {
            a.push("--resource-limit".into());
            a.push(format!("{k}={v}").into());
        }
        // NOTE: --new-pid-ns is intentionally omitted. CONFIRMED on box
        // (2026-06-05): it makes jailer FORK firecracker into the new namespace
        // and the jailer parent exits 0 immediately, detaching firecracker —
        // which breaks foreground wait()/kill on the Child handle. The host-pid
        // benefit is marginal for a single-process VMM (a guest fork-bomb
        // consumes GUEST pids, not host pids; host pids are already capped by the
        // pids.max cgroup), and teardown's cgroup.kill guarantees reaping.
        // Re-adding it would require managing firecracker via <root>/<exec>.pid
        // instead of the Child handle.
        if let Some(ns) = &self.netns {
            a.push("--netns".into());
            a.push(ns.clone().into_os_string());
        }
        // Forwarded firecracker args. NOTE: no --daemonize (it would setsid and
        // detach, breaking wait()/kill_on_drop and orphaning the guest); no
        // --no-seccomp / --seccomp-filter (keep the built-in advanced filter).
        a.push("--".into());
        a.push("--api-sock".into());
        a.push(layout.api_sock_arg.into());
        a.push("--boot-timer".into());
        a
    }
}

/// All paths jailer's chroot layout implies, derived purely from
/// `(chroot_base, cgroup_mount, parent_cgroup, id)`. Host-side and guest-side
/// (chroot-relative) paths **diverge** under the jailer, so they are computed in
/// one place.
pub struct JailerLayout {
    /// `<base>/firecracker/<id>` — the whole per-build tree (teardown root).
    pub chroot_id_dir: PathBuf,
    /// `<base>/firecracker/<id>/root` — the chroot.
    pub chroot_root: PathBuf,
    /// Host path to the api socket (the host connects here).
    pub host_socket: PathBuf,
    /// Chroot-relative api-sock arg passed to firecracker.
    pub api_sock_arg: &'static str,
    /// Host path to the log vsock uds (the host log reader connects here).
    pub host_vsock: PathBuf,
    /// Chroot-relative vsock uds arg.
    pub vsock_arg: &'static str,
    /// `<root>/drives` — where drive backing files are staged.
    pub drives_dir: PathBuf,
    /// `<cgroup_mount>/<parent>/<id>` — the leaf cgroup jailer creates.
    pub cgroup_dir: PathBuf,
    /// `<cgroup_mount>/<parent>` — the root-owned ceiling.
    pub parent_cgroup_dir: PathBuf,
}

impl JailerLayout {
    pub fn new(
        chroot_base: &Path,
        cgroup_mount: &Path,
        parent_cgroup: &str,
        exec_basename: &str,
        id: &str,
    ) -> Self {
        // CONFIRMED on box (2026-06-05, jailer v1.15.1): the per-id dir is named
        // after the exec-file *basename* (e.g. "firecracker-v1.15.1-x86_64"), NOT
        // the literal "firecracker". The cgroup leaf, by contrast, is
        // <cgroup_mount>/<parent>/<id> with no exec basename, and is root-owned
        // (so the jailed uid cannot raise its own limits — leaf-only writes are
        // safe, no parent ceiling needed).
        let chroot_id_dir = chroot_base.join(exec_basename).join(id);
        let chroot_root = chroot_id_dir.join("root");
        Self {
            host_socket: chroot_root.join("run/firecracker.socket"),
            api_sock_arg: "run/firecracker.socket",
            host_vsock: chroot_root.join("v.sock"),
            vsock_arg: "v.sock",
            drives_dir: chroot_root.join("drives"),
            cgroup_dir: cgroup_mount.join(parent_cgroup).join(id),
            parent_cgroup_dir: cgroup_mount.join(parent_cgroup),
            chroot_root,
            chroot_id_dir,
        }
    }

    /// Chroot-relative `path_on_host` for a drive backing file in `drives/`.
    pub fn drive_rel(&self, file: &str) -> String {
        format!("drives/{file}")
    }
}

/// Sanitize a build id to `[A-Za-z0-9-]`, length 1..=64. The id becomes a path
/// segment and a cgroup name, so anything else is rejected.
pub fn sanitize_id(id: &str) -> Result<String> {
    let s: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if s.is_empty() || s.len() > 64 {
        bail!("invalid build VM id {id:?}: must be 1..=64 chars of [A-Za-z0-9-]");
    }
    Ok(s)
}

/// Fail unless `a` and `b` live on the same filesystem (`st_dev`). RO images are
/// hard-linked into the jail, which is impossible across filesystems.
pub fn assert_same_fs(a: &Path, b: &Path) -> Result<()> {
    let da = std::fs::metadata(a)
        .with_context(|| format!("stat {}", a.display()))?
        .dev();
    let db = std::fs::metadata(b)
        .with_context(|| format!("stat {}", b.display()))?
        .dev();
    if da != db {
        bail!(
            "{} and {} are on different filesystems; the jailer chroot_base and \
             all drive images must share one fs (e.g. <data_dir>/jailer)",
            a.display(),
            b.display()
        );
    }
    Ok(())
}

/// Hard-link a read-only image into the jail. The image must already be
/// world-readable (`0o444`) — hard links share the source inode's ownership, and
/// the dropped build uid must be able to `open()` it.
pub fn stage_ro(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::hard_link(src, dst).with_context(|| {
        format!(
            "hard-link {} -> {} (must be same filesystem)",
            src.display(),
            dst.display()
        )
    })?;
    Ok(())
}

/// Create a **preallocated** (non-sparse) read-write image and chown it to the
/// build uid/gid. Preallocation (not `truncate`/`set_len`, which are sparse)
/// means guest writes inside the image can never trigger host `ENOSPC` via thin
/// growth.
pub fn stage_rw_prealloc(dst: &Path, size_bytes: u64, uid: u32, gid: u32) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // `fallocate` reserves real blocks. (util-linux; orch runs as root.)
    let status = std::process::Command::new("fallocate")
        .arg("-l")
        .arg(size_bytes.to_string())
        .arg(dst)
        .status()
        .with_context(|| format!("run fallocate for {}", dst.display()))?;
    if !status.success() {
        bail!("fallocate failed for {} ({status})", dst.display());
    }
    // Format as an empty journal-less ext4 so the guest can mount it RW. Safe:
    // the image is empty and host-created — the host never parses guest-written
    // data here (build output is read back out-of-band, never host-mounted).
    let status = std::process::Command::new("mkfs.ext4")
        .args(["-F", "-q", "-O", "^has_journal"])
        .arg(dst)
        .status()
        .with_context(|| format!("run mkfs.ext4 for {}", dst.display()))?;
    if !status.success() {
        bail!("mkfs.ext4 failed for {} ({status})", dst.display());
    }
    chown_to(dst, uid, gid)?;
    Ok(())
}

/// chown a path to `uid:gid` (root-only).
pub fn chown_to(path: &Path, uid: u32, gid: u32) -> Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
        .with_context(|| format!("chown {} to {uid}:{gid}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn argv_is_ordered_and_complete() {
        let layout = JailerLayout::new(
            Path::new("/data/jailer"),
            Path::new("/sys/fs/cgroup"),
            "jkbase-build",
            "firecracker-v1.15.1-x86_64",
            "abc",
        );
        let cfg = JailerConfig {
            jailer_bin: PathBuf::from("/usr/bin/jailer"),
            firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
            id: "abc".to_string(),
            uid: 100000,
            gid: 100000,
            chroot_base: PathBuf::from("/data/jailer"),
            parent_cgroup: "jkbase-build".to_string(),
            cgroups: vec![
                ("pids.max".into(), "512".into()),
                ("memory.max".into(), "3758096384".into()),
                ("memory.swap.max".into(), "0".into()),
                ("cpu.max".into(), "400000 100000".into()),
            ],
            resource_limits: vec![],
            netns: None,
        };
        let expected = os(&[
            "--id",
            "abc",
            "--exec-file",
            "/usr/bin/firecracker",
            "--uid",
            "100000",
            "--gid",
            "100000",
            "--chroot-base-dir",
            "/data/jailer",
            "--cgroup-version",
            "2",
            "--parent-cgroup",
            "jkbase-build",
            "--cgroup",
            "pids.max=512",
            "--cgroup",
            "memory.max=3758096384",
            "--cgroup",
            "memory.swap.max=0",
            "--cgroup",
            "cpu.max=400000 100000",
            "--",
            "--api-sock",
            "run/firecracker.socket",
            "--boot-timer",
        ]);
        assert_eq!(cfg.argv(&layout), expected);
    }

    #[test]
    fn argv_includes_netns_and_resource_limits_when_present() {
        let layout = JailerLayout::new(
            Path::new("/d"),
            Path::new("/sys/fs/cgroup"),
            "jkbase-build",
            "fc",
            "x",
        );
        let cfg = JailerConfig {
            jailer_bin: PathBuf::from("/j"),
            firecracker_bin: PathBuf::from("/fc"),
            id: "x".to_string(),
            uid: 1,
            gid: 2,
            chroot_base: PathBuf::from("/d"),
            parent_cgroup: "p".to_string(),
            cgroups: vec![],
            resource_limits: vec![("fsize".into(), "1024".into())],
            netns: Some(PathBuf::from("/var/run/netns/build")),
        };
        let argv = cfg.argv(&layout);
        assert!(argv.contains(&OsString::from("--resource-limit")));
        assert!(argv.contains(&OsString::from("fsize=1024")));
        assert!(argv.contains(&OsString::from("--netns")));
        assert!(argv.contains(&OsString::from("/var/run/netns/build")));
    }

    #[test]
    fn layout_paths_diverge_host_vs_chroot_relative() {
        // Chroot dir uses the exec-file basename (confirmed on box); the cgroup
        // leaf does not.
        let l = JailerLayout::new(
            Path::new("/data/jailer"),
            Path::new("/sys/fs/cgroup"),
            "jkbase-build",
            "firecracker-v1.15.1-x86_64",
            "abc",
        );
        assert_eq!(
            l.chroot_id_dir,
            PathBuf::from("/data/jailer/firecracker-v1.15.1-x86_64/abc")
        );
        assert_eq!(
            l.chroot_root,
            PathBuf::from("/data/jailer/firecracker-v1.15.1-x86_64/abc/root")
        );
        assert_eq!(
            l.host_socket,
            PathBuf::from(
                "/data/jailer/firecracker-v1.15.1-x86_64/abc/root/run/firecracker.socket"
            )
        );
        assert_eq!(l.api_sock_arg, "run/firecracker.socket");
        assert_eq!(
            l.drives_dir,
            PathBuf::from("/data/jailer/firecracker-v1.15.1-x86_64/abc/root/drives")
        );
        assert_eq!(
            l.cgroup_dir,
            PathBuf::from("/sys/fs/cgroup/jkbase-build/abc")
        );
        assert_eq!(
            l.parent_cgroup_dir,
            PathBuf::from("/sys/fs/cgroup/jkbase-build")
        );
        assert_eq!(l.drive_rel("scratch.img"), "drives/scratch.img");
    }

    #[test]
    fn sanitize_id_filters_and_bounds() {
        assert_eq!(sanitize_id("abc-123").unwrap(), "abc-123");
        assert_eq!(sanitize_id("a/b..c d").unwrap(), "abcd"); // drops / . space
        assert!(sanitize_id("").is_err());
        assert!(sanitize_id("/").is_err());
        assert!(sanitize_id(&"a".repeat(65)).is_err());
        assert_eq!(sanitize_id(&"a".repeat(64)).unwrap().len(), 64);
    }
}
