//! Boot-time reaping of build VMs a previous server process left behind.
//!
//! Build VMs live OUTSIDE the service cgroup (`<cgroup>/jkbase-build/<id>`, put there by the
//! jailer) so a crash never strands a half-written artifact mid-host-write; the price is that a
//! restart doesn't kill them either. Every upgrade restart deliberately leaves VMs running
//! (zero-bounce, for TENANT VMs), so a deploy that lands mid-build orphans that build's VM: no
//! process tracks it any more, its wall-clock timeout never fires, and it runs forever — on prod
//! one sat at 100% of a core for 56 days. It also holds memory the fresh `BuildMemBudget` doesn't
//! know about, so the budget would overcommit the box by every orphan's size.
//!
//! Nothing is in flight at boot (build records left Queued/Building are failed by
//! `reconcile_on_boot`, and build VMs are never re-adopted), so EVERY build VM present at boot is
//! an orphan. [`reap_orphan_builds`] runs before the egress proxies bind and before any build can
//! be admitted, and removes all three things a build VM holds:
//! 1. its cgroup leaf: `cgroup.kill` (the whole subtree, SIGKILL, no escape by forking), wait
//!    until `cgroup.events` reports it unpopulated, then `rmdir` depth-first;
//! 2. its `jkbld<N>` TAP — deleted even when the kill failed, so an unkillable orphan is at least
//!    cut off the build bridge (the guest is untrusted: it must not reach the new egress proxy);
//! 3. its jail under the chroot base — removed without following symlinks (std's
//!    `remove_dir_all` is symlink-safe) and never across a mount (a jail with anything mounted
//!    under it is left for an operator, not recursed into).
//!
//! Runtime VMs are untouched: they live under `jkbase-runtime` and in other dirs, and are
//! re-adopted by the zero-bounce path. Every step is best-effort and logged: a reap failure must
//! not keep the platform (and every tenant's site) from starting.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::{error, info, warn};

/// How long a killed cgroup gets to become unpopulated. SIGKILL of a Firecracker VMM (and its
/// jailer, if still alive) completes in milliseconds; this only bounds a wedged kernel.
const KILL_WAIT: Duration = Duration::from_secs(10);
const KILL_POLL: Duration = Duration::from_millis(50);

/// What a reap removed, for the boot log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReapReport {
    pub killed: Vec<String>,
    pub taps: Vec<String>,
    pub jails: Vec<String>,
    /// Things that could not be removed (already logged at ERROR).
    pub failures: usize,
}

/// Where the reaper looks. Production: [`ReapPaths::host`].
pub struct ReapPaths {
    /// The build cgroup parent, e.g. `/sys/fs/cgroup/jkbase-build`.
    pub build_cgroup: PathBuf,
    /// The jailer chroot base (`<data>/bj`): `<base>/<exec-name>/<id>/root/…`.
    pub chroot_base: PathBuf,
    /// `/sys/class/net`, listing the host's network devices.
    pub sys_class_net: PathBuf,
}

impl ReapPaths {
    pub fn host(cgroup_mount: &Path, parent_cgroup: &str, chroot_base: &Path) -> Self {
        Self {
            build_cgroup: cgroup_mount.join(parent_cgroup),
            chroot_base: chroot_base.to_path_buf(),
            sys_class_net: PathBuf::from("/sys/class/net"),
        }
    }
}

/// Kill and remove every build VM left by a previous process. See the module doc.
pub async fn reap_orphan_builds(paths: &ReapPaths) -> ReapReport {
    let mut report = ReapReport::default();

    for leaf in subdirs(&paths.build_cgroup) {
        let name = file_name(&leaf);
        match kill_cgroup(&leaf).await {
            Ok(()) => report.killed.push(name),
            Err(e) => {
                error!(cgroup = %leaf.display(), error = %format!("{e:#}"),
                       "could not reap an orphaned build VM; its TAP is still removed");
                report.failures += 1;
            }
        }
    }

    for tap in orphan_taps(&paths.sys_class_net) {
        match delete_link(&tap).await {
            Ok(()) => report.taps.push(tap),
            Err(e) => {
                error!(tap = %tap, error = %format!("{e:#}"), "could not delete an orphaned build TAP");
                report.failures += 1;
            }
        }
    }

    let mounts = mount_points();
    for jail in jail_dirs(&paths.chroot_base) {
        match remove_jail(&jail, &mounts) {
            Ok(()) => report.jails.push(file_name(&jail)),
            Err(e) => {
                error!(jail = %jail.display(), error = %format!("{e:#}"),
                       "could not remove an orphaned build jail");
                report.failures += 1;
            }
        }
    }

    if report.killed.is_empty() && report.taps.is_empty() && report.jails.is_empty() {
        if report.failures == 0 {
            info!("no orphaned build VMs to reap");
        }
    } else {
        warn!(killed = ?report.killed, taps = ?report.taps, jails = ?report.jails,
              failures = report.failures, "reaped build VMs orphaned by a previous server process");
    }
    report
}

/// Real (non-symlink) subdirectories of `dir`, sorted; none if `dir` is missing.
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// SIGKILL everything in a cgroup subtree, wait until it's empty, then remove its dirs.
async fn kill_cgroup(leaf: &Path) -> Result<()> {
    // `cgroup.kill` (kernel ≥ 5.14) kills the whole subtree atomically: a process can't fork
    // its way out of the kill the way it could race a read-procs-then-kill loop.
    std::fs::write(leaf.join("cgroup.kill"), "1")
        .with_context(|| format!("write {}/cgroup.kill", leaf.display()))?;
    let deadline = tokio::time::Instant::now() + KILL_WAIT;
    loop {
        let events = std::fs::read_to_string(leaf.join("cgroup.events"))
            .with_context(|| format!("read {}/cgroup.events", leaf.display()))?;
        if !populated(&events) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("still populated {}s after cgroup.kill", KILL_WAIT.as_secs());
        }
        tokio::time::sleep(KILL_POLL).await;
    }
    remove_cgroup_tree(leaf)
}

/// `cgroup.events` says `populated 1` while any process is in the subtree.
fn populated(events: &str) -> bool {
    events
        .lines()
        .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["populated", "1"])
}

/// `rmdir` a cgroup and its descendants, deepest first (a cgroup with children can't be
/// removed; its control files are virtual and go with the dir).
fn remove_cgroup_tree(dir: &Path) -> Result<()> {
    for child in subdirs(dir) {
        remove_cgroup_tree(&child)?;
    }
    std::fs::remove_dir(dir).with_context(|| format!("rmdir {}", dir.display()))
}

/// The build-bridge TAPs (`jkbld<N>`) present on the host. Exactly that shape, so the build
/// bridge itself (`jkbuild0`) and runtime TAPs (`tap<N>`) are never matched.
fn orphan_taps(sys_class_net: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(sys_class_net) else {
        return Vec::new();
    };
    let mut taps: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_build_tap(n))
        .collect();
    taps.sort();
    taps
}

fn is_build_tap(name: &str) -> bool {
    name.strip_prefix("jkbld")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

async fn delete_link(dev: &str) -> Result<()> {
    let status = tokio::process::Command::new("ip")
        .args(["link", "delete", dev])
        .status()
        .await
        .context("run ip")?;
    if !status.success() {
        bail!("ip link delete {dev} failed: {status}");
    }
    Ok(())
}

/// The jails under the chroot base: `<base>/<exec-name>/<id>`.
fn jail_dirs(chroot_base: &Path) -> Vec<PathBuf> {
    subdirs(chroot_base)
        .iter()
        .flat_map(|exec_dir| subdirs(exec_dir))
        .collect()
}

/// Host mount points, from `/proc/self/mountinfo` (field 5, octal escapes decoded).
fn mount_points() -> Vec<PathBuf> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|s| parse_mount_points(&s))
        .unwrap_or_default()
}

fn parse_mount_points(mountinfo: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|p| PathBuf::from(unescape_mount_path(p)))
        .collect()
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape_mount_path(p: &str) -> String {
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Remove one jail, unless something is mounted at or under it.
fn remove_jail(jail: &Path, mounts: &[PathBuf]) -> Result<()> {
    if let Some(m) = mounts.iter().find(|m| m.starts_with(jail)) {
        bail!(
            "{} is mounted inside it; left for an operator (never recursed across a mount)",
            m.display()
        );
    }
    std::fs::remove_dir_all(jail).with_context(|| format!("remove {}", jail.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_build_bridge_taps_match() {
        for yes in ["jkbld0", "jkbld6", "jkbld63"] {
            assert!(is_build_tap(yes), "{yes}");
        }
        for no in [
            "jkbld", "jkbuild0", "jkbld6x", "tap5", "jkbr0", "xjkbld1", "jkbld-1",
        ] {
            assert!(!is_build_tap(no), "{no}");
        }
    }

    #[test]
    fn taps_are_read_from_sys_class_net() {
        let d = tempfile::tempdir().unwrap();
        for n in ["jkbld3", "jkbuild0", "tap1", "jkbld10", "lo"] {
            std::fs::create_dir(d.path().join(n)).unwrap();
        }
        assert_eq!(orphan_taps(d.path()), ["jkbld10", "jkbld3"]);
        assert!(orphan_taps(&d.path().join("missing")).is_empty());
    }

    #[test]
    fn populated_is_read_exactly() {
        assert!(populated("populated 1\nfrozen 0\n"));
        assert!(!populated("populated 0\nfrozen 0\n"));
        assert!(!populated("frozen 1\n"));
        assert!(!populated("populated 10\n"));
    }

    #[test]
    fn mountinfo_paths_are_unescaped() {
        let mi = "36 35 98:0 / /mnt/a\\040b rw - ext4 /dev/x rw\n\
                  37 35 98:0 / /var/jkbase/bj/fc/b1/root/proc rw - proc proc rw\n";
        assert_eq!(
            parse_mount_points(mi),
            [
                PathBuf::from("/mnt/a b"),
                PathBuf::from("/var/jkbase/bj/fc/b1/root/proc")
            ]
        );
        assert_eq!(unescape_mount_path("a\\134b\\0"), "a\\b\\0");
    }

    // A jail is removed whole, but a symlink inside it (the VMM runs as the untrusted build uid
    // and owns parts of its jail) is unlinked, never followed — and a jail with a mount under
    // it is refused rather than recursed into.
    #[test]
    fn jails_are_removed_without_following_symlinks_or_crossing_mounts() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("precious"), "keep").unwrap();
        let exec = base.path().join("firecracker-v1.15.1-x86_64");
        let jail = exec.join("b5-s-api");
        std::fs::create_dir_all(jail.join("root/drives")).unwrap();
        std::fs::write(jail.join("root/drives/scratch.img"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), jail.join("root/escape")).unwrap();
        let mounted = exec.join("b6-s-web");
        std::fs::create_dir_all(mounted.join("root/proc")).unwrap();

        let jails = jail_dirs(base.path());
        assert_eq!(jails, [jail.clone(), mounted.clone()]);
        let mounts = vec![mounted.join("root/proc")];
        remove_jail(&jail, &mounts).unwrap();
        assert!(!jail.exists());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("precious")).unwrap(),
            "keep",
            "the symlink's target survives"
        );
        let err = remove_jail(&mounted, &mounts).unwrap_err().to_string();
        assert!(err.contains("mounted inside it"), "{err}");
        assert!(mounted.exists());
    }

    #[tokio::test]
    async fn nothing_to_reap_is_a_clean_report() {
        let d = tempfile::tempdir().unwrap();
        let paths = ReapPaths {
            build_cgroup: d.path().join("no-cgroup"),
            chroot_base: d.path().join("no-bj"),
            sys_class_net: d.path().join("no-net"),
        };
        assert_eq!(reap_orphan_builds(&paths).await, ReapReport::default());
    }

    /// On-box: a real cgroup-v2 leaf holding a live process (standing in for an orphaned
    /// Firecracker) is killed, waited for and removed; a real `jkbld` TAP is deleted and a
    /// jail removed.
    ///
    ///   sudo <test-bin> --ignored --nocapture build_reaper::tests::reaps_a_live_cgroup
    #[tokio::test]
    #[ignore = "needs root + cgroup v2 at /sys/fs/cgroup"]
    async fn reaps_a_live_cgroup() {
        let parent = PathBuf::from("/sys/fs/cgroup/jkbase-reaper-test");
        let _ = remove_cgroup_tree(&parent);
        let leaf = parent.join("b1-s-orphan");
        std::fs::create_dir_all(leaf.join("nested")).unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .unwrap();
        std::fs::write(leaf.join("nested/cgroup.procs"), child.id().to_string()).unwrap();
        assert!(populated(
            &std::fs::read_to_string(leaf.join("cgroup.events")).unwrap()
        ));

        // A real persistent TAP of the build shape. The listing dir names only it, so the
        // reap never touches this box's own build TAPs.
        let tap = "jkbld990";
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", tap])
            .status();
        let made = std::process::Command::new("ip")
            .args(["tuntap", "add", "dev", tap, "mode", "tap"])
            .status()
            .unwrap();
        assert!(made.success(), "create test TAP");
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("net").join(tap)).unwrap();
        let jail = d.path().join("bj/firecracker-v1.15.1-x86_64/b1-s-orphan");
        std::fs::create_dir_all(jail.join("root/drives")).unwrap();
        std::fs::write(jail.join("root/drives/scratch.img"), "x").unwrap();

        let report = reap_orphan_builds(&ReapPaths {
            build_cgroup: parent.clone(),
            chroot_base: d.path().join("bj"),
            sys_class_net: d.path().join("net"),
        })
        .await;
        assert_eq!(report.killed, ["b1-s-orphan"]);
        assert_eq!(report.taps, [tap]);
        assert_eq!(report.jails, ["b1-s-orphan"]);
        assert_eq!(report.failures, 0);
        let status = child.wait().unwrap();
        assert!(!status.success(), "the orphan was killed: {status}");
        assert!(!leaf.exists());
        assert!(
            !Path::new("/sys/class/net").join(tap).exists(),
            "TAP deleted"
        );
        assert!(!jail.exists());
        std::fs::remove_dir(&parent).unwrap();
        println!("PASS: live cgroup killed + removed ({status}), TAP deleted, jail removed");
    }
}
