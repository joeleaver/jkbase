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
//! `reconcile_on_boot`, build VMs are never re-adopted, and an upgrading server has exited before
//! systemd starts its successor), so EVERY build VM present at boot is an orphan.
//! [`reap_orphan_builds`] runs before the egress proxies bind and before any build can be
//! admitted, and removes all three things a build VM holds:
//! 1. its cgroup leaf: `cgroup.kill` on every leaf first (the whole subtree, SIGKILL, no escape by
//!    forking), then one shared deadline for all of them to report unpopulated in
//!    `cgroup.events`, then `rmdir` depth-first (retried while the kernel still says EBUSY);
//! 2. its `jkbld<N>` TAP — deleted even when the kill failed, so an unkillable orphan is at least
//!    cut off the build bridge (the guest is untrusted: it must not reach the new egress proxy);
//! 3. its jail under the chroot base — removed without following symlinks (std's
//!    `remove_dir_all` is symlink-safe) and never across a mount: a jail with anything mounted at
//!    or under it (checked against the canonical path, as mountinfo lists it) is left for an
//!    operator, and if the mount table can't be read no jail is removed at all. A jail whose VM
//!    may still be running (its kill failed) is left too.
//!
//! Scope is the HOST's build VMs (cgroups + TAPs), not just this data dir's: one jkbase-server
//! per host is the only supported configuration. On a dev box that means starting a server kills
//! any on-box e2e build VM running at the same moment.
//!
//! Runtime VMs are untouched: they live under `jkbase-runtime`, outside the chroot base, and are
//! re-adopted by the zero-bounce path. Every step is bounded, best-effort and logged: a reap
//! failure must not keep the platform (and every tenant's site) from starting.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::{error, info, warn};

/// How long the killed cgroups get, together, to become unpopulated and removable. SIGKILL of a
/// Firecracker VMM (and its jailer, if still alive) completes in milliseconds; this only bounds a
/// wedged kernel.
const KILL_WAIT: Duration = Duration::from_secs(10);
const KILL_POLL: Duration = Duration::from_millis(50);
/// Bound on one `ip link delete`.
const IP_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// `/proc/self/mountinfo`, the mount table jails are checked against.
    pub mountinfo: PathBuf,
}

impl ReapPaths {
    pub fn host(cgroup_mount: &Path, parent_cgroup: &str, chroot_base: &Path) -> Self {
        Self {
            build_cgroup: cgroup_mount.join(parent_cgroup),
            chroot_base: chroot_base.to_path_buf(),
            sys_class_net: PathBuf::from("/sys/class/net"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

/// Kill and remove every build VM left by a previous process. See the module doc.
pub async fn reap_orphan_builds(paths: &ReapPaths) -> ReapReport {
    let mut report = ReapReport::default();
    let maybe_alive = kill_cgroups(&paths.build_cgroup, &mut report).await;

    for tap in orphan_taps(&paths.sys_class_net) {
        match delete_link(&tap).await {
            Ok(()) => report.taps.push(tap),
            Err(e) => {
                error!(tap = %tap, error = %format!("{e:#}"), "could not delete an orphaned build TAP");
                report.failures += 1;
            }
        }
    }

    remove_jails(paths, &maybe_alive, &mut report);

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

/// A killed leaf still being waited on.
struct Pending {
    leaf: PathBuf,
    /// The subtree reported unpopulated (its processes are gone), only the rmdir is left.
    dead: bool,
}

/// Kill every build cgroup leaf, wait for all of them under one deadline, remove them. Returns
/// the ids whose processes may still be running, or `None` if the leaves couldn't be listed.
async fn kill_cgroups(build_cgroup: &Path, report: &mut ReapReport) -> Option<BTreeSet<String>> {
    // Only a MISSING parent means "nothing to reap". Any other listing error leaves every build
    // VM's state unknown, so no jail may be removed from under one (fail closed).
    let leaves = match list_subdirs(build_cgroup) {
        Ok(leaves) => leaves,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            error!(cgroup = %build_cgroup.display(), error = %e,
                   "could not list build cgroups; no orphaned build VMs killed or jails removed");
            report.failures += 1;
            return None;
        }
    };
    let mut maybe_alive = BTreeSet::new();
    let mut pending = Vec::new();
    // `cgroup.kill` (kernel ≥ 5.14) kills the whole subtree atomically: a process can't fork its
    // way out of the kill the way it could race a read-procs-then-kill loop. All leaves are
    // killed before any wait, so N wedged orphans cost one deadline, not N.
    for leaf in leaves {
        match std::fs::write(leaf.join("cgroup.kill"), "1") {
            Ok(()) => pending.push(Pending { leaf, dead: false }),
            Err(e) => {
                error!(cgroup = %leaf.display(), error = %e,
                       "could not kill an orphaned build VM (cgroup.kill); its TAP is still removed");
                report.failures += 1;
                maybe_alive.insert(file_name(&leaf));
            }
        }
    }
    let deadline = tokio::time::Instant::now() + KILL_WAIT;
    loop {
        pending.retain_mut(|p| match step(p) {
            Ok(true) => {
                report.killed.push(file_name(&p.leaf));
                false
            }
            Ok(false) => true,
            Err(e) => {
                error!(cgroup = %p.leaf.display(), error = %format!("{e:#}"),
                       "could not reap an orphaned build VM");
                report.failures += 1;
                if !p.dead {
                    maybe_alive.insert(file_name(&p.leaf));
                }
                false
            }
        });
        if pending.is_empty() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            for p in pending {
                let state = if p.dead {
                    "unremovable (EBUSY)"
                } else {
                    "still populated"
                };
                error!(cgroup = %p.leaf.display(),
                       "orphaned build VM cgroup {state} {}s after cgroup.kill; its TAP is still removed",
                       KILL_WAIT.as_secs());
                report.failures += 1;
                if !p.dead {
                    maybe_alive.insert(file_name(&p.leaf));
                }
            }
            break;
        }
        tokio::time::sleep(KILL_POLL).await;
    }
    report.killed.sort();
    Some(maybe_alive)
}

/// One poll of a killed leaf: `Ok(true)` once it's gone, `Ok(false)` to poll again.
fn step(p: &mut Pending) -> Result<bool> {
    if !p.dead {
        let events = std::fs::read_to_string(p.leaf.join("cgroup.events"))
            .with_context(|| format!("read {}/cgroup.events", p.leaf.display()))?;
        if populated(&events) {
            return Ok(false);
        }
        p.dead = true;
    }
    match remove_cgroup_tree(&p.leaf) {
        Ok(()) => Ok(true),
        // The kernel can refuse the rmdir briefly after the subtree empties.
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("rmdir under {}", p.leaf.display())),
    }
}

/// Real (non-symlink) subdirectories of `dir`, sorted.
fn list_subdirs(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.path());
        }
    }
    out.sort();
    Ok(out)
}

/// [`list_subdirs`], where an unreadable dir only means less is removed (jails, cgroup
/// children: a leftover fails its rmdir loudly), never more.
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    list_subdirs(dir).unwrap_or_default()
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `cgroup.events` says `populated 1` while any process is in the subtree.
fn populated(events: &str) -> bool {
    events
        .lines()
        .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["populated", "1"])
}

/// `rmdir` a cgroup and its descendants, deepest first (a cgroup with children can't be
/// removed; its control files are virtual and go with the dir).
fn remove_cgroup_tree(dir: &Path) -> std::io::Result<()> {
    for child in subdirs(dir) {
        remove_cgroup_tree(&child)?;
    }
    std::fs::remove_dir(dir)
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
    let run = tokio::process::Command::new("ip")
        .args(["link", "delete", dev])
        .kill_on_drop(true)
        .status();
    let status = tokio::time::timeout(IP_TIMEOUT, run)
        .await
        .with_context(|| format!("ip link delete {dev} timed out"))?
        .context("run ip")?;
    if !status.success() {
        bail!("ip link delete {dev} failed: {status}");
    }
    Ok(())
}

/// Remove every jail under the chroot base, except those that may still hold a live VM or have
/// a mount inside. Fails closed: no readable mount table, no removal.
fn remove_jails(
    paths: &ReapPaths,
    maybe_alive: &Option<BTreeSet<String>>,
    report: &mut ReapReport,
) {
    let Some(maybe_alive) = maybe_alive else {
        return; // the cgroup listing failed (already logged): any jail may hold a live VM
    };
    // Canonical, because mountinfo lists resolved paths: a data dir reached through a symlink
    // would otherwise never match a mount inside one of its jails.
    let base = match std::fs::canonicalize(&paths.chroot_base) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            error!(dir = %paths.chroot_base.display(), error = %e,
                   "could not resolve the build chroot base; no orphaned jails removed");
            report.failures += 1;
            return;
        }
    };
    let jails = jail_dirs(&base);
    if jails.is_empty() {
        return;
    }
    let mounts = match std::fs::read_to_string(&paths.mountinfo) {
        Ok(s) => parse_mount_points(&s),
        Err(e) => {
            error!(mountinfo = %paths.mountinfo.display(), error = %e,
                   "could not read the mount table; no orphaned jails removed");
            report.failures += 1;
            return;
        }
    };
    for jail in jails {
        let id = file_name(&jail);
        let removed = if maybe_alive.contains(&id) {
            Err(anyhow::anyhow!(
                "its VM may still be running (the kill failed); left for an operator"
            ))
        } else {
            remove_jail(&jail, &mounts)
        };
        match removed {
            Ok(()) => report.jails.push(id),
            Err(e) => {
                error!(jail = %jail.display(), error = %format!("{e:#}"),
                       "could not remove an orphaned build jail");
                report.failures += 1;
            }
        }
    }
}

/// The jails under the chroot base: `<base>/<exec-name>/<id>`.
fn jail_dirs(chroot_base: &Path) -> Vec<PathBuf> {
    subdirs(chroot_base)
        .iter()
        .flat_map(|exec_dir| subdirs(exec_dir))
        .collect()
}

/// Mount points from mountinfo (field 5, octal escapes decoded).
fn parse_mount_points(mountinfo: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|p| PathBuf::from(OsString::from_vec(unescape_mount_path(p))))
        .collect()
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`; anything else (including an
/// out-of-range `\777`) is kept literally. Raw bytes: a path needn't be UTF-8.
fn unescape_mount_path(p: &str) -> Vec<u8> {
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b
            .get(i + 1..i + 4)
            .filter(|d| b[i] == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)));
        let byte = octal.and_then(|d| {
            let v = d.iter().fold(0u16, |v, c| v * 8 + u16::from(c - b'0'));
            u8::try_from(v).ok()
        });
        match byte {
            Some(v) => {
                out.push(v);
                i += 4;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    out
}

/// Remove one jail, unless something is mounted at or under it. `jail` must be canonical.
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
mod tests;
