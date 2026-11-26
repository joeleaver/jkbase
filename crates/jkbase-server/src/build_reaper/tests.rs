//! Tests for the boot-time build-VM reaper (`#[ignore]`d one needs root on the box).

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
    assert_eq!(unescape_mount_path("a\\134b\\0"), b"a\\b\\0");
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

fn paths_in(d: &Path) -> ReapPaths {
    ReapPaths {
        build_cgroup: d.join("cg"),
        chroot_base: d.join("bj"),
        sys_class_net: d.join("net"),
        mountinfo: d.join("mountinfo"),
    }
}

fn make_jail(base: &Path, id: &str) -> PathBuf {
    let jail = base.join("firecracker-v1.15.1-x86_64").join(id);
    std::fs::create_dir_all(jail.join("root/drives")).unwrap();
    std::fs::write(jail.join("root/drives/scratch.img"), "x").unwrap();
    jail
}

#[tokio::test]
async fn nothing_to_reap_is_a_clean_report() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(
        reap_orphan_builds(&paths_in(d.path())).await,
        ReapReport::default()
    );
}

#[test]
fn out_of_range_octal_is_kept_literally() {
    assert_eq!(unescape_mount_path("a\\777b"), b"a\\777b");
    assert_eq!(unescape_mount_path("\\04"), b"\\04");
}

// Fail closed: with no readable mount table no jail is removed (a mount inside one can't
// be ruled out, and remove_dir_all doesn't stop at a filesystem boundary).
#[tokio::test]
async fn an_unreadable_mount_table_removes_no_jail() {
    let d = tempfile::tempdir().unwrap();
    let paths = paths_in(d.path());
    let jail = make_jail(&paths.chroot_base, "b1-s-api");
    let report = reap_orphan_builds(&paths).await;
    assert!(report.jails.is_empty());
    assert_eq!(report.failures, 1);
    assert!(jail.exists());
}

// mountinfo lists resolved paths; a chroot base reached through a symlink must still see a
// mount inside one of its jails.
#[tokio::test]
async fn a_symlinked_chroot_base_still_sees_mounts_inside_jails() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("real-bj");
    let mounted = make_jail(&real, "b2-s-web");
    let plain = make_jail(&real, "b3-s-web");
    let paths = paths_in(d.path());
    std::os::unix::fs::symlink(&real, &paths.chroot_base).unwrap();
    let canon = std::fs::canonicalize(&mounted).unwrap();
    std::fs::write(
        &paths.mountinfo,
        format!(
            "37 35 0:5 / {}/root/proc rw - proc proc rw\n",
            canon.display()
        ),
    )
    .unwrap();
    let report = reap_orphan_builds(&paths).await;
    assert_eq!(report.jails, ["b3-s-web"]);
    assert_eq!(report.failures, 1);
    assert!(mounted.exists());
    assert!(!plain.exists());
}

// A leaf whose kill can't be confirmed (here: no cgroup.events, as if the kernel refused)
// may still hold a live VMM; its jail is left for an operator while the others go.
#[tokio::test]
async fn a_failed_kill_keeps_that_vms_jail() {
    let d = tempfile::tempdir().unwrap();
    let paths = paths_in(d.path());
    std::fs::create_dir_all(paths.build_cgroup.join("b4-s-api")).unwrap();
    std::fs::write(&paths.mountinfo, "").unwrap();
    let alive = make_jail(&paths.chroot_base, "b4-s-api");
    let gone = make_jail(&paths.chroot_base, "b5-s-api");
    let report = reap_orphan_builds(&paths).await;
    assert!(report.killed.is_empty());
    assert_eq!(report.jails, ["b5-s-api"]);
    assert_eq!(report.failures, 2, "the kill and the kept jail");
    assert!(alive.exists());
    assert!(!gone.exists());
}

// A leaf that stays populated past the deadline may hold a live VMM: its jail is kept.
#[tokio::test(start_paused = true)]
async fn a_leaf_still_populated_at_the_deadline_keeps_its_jail() {
    let d = tempfile::tempdir().unwrap();
    let paths = paths_in(d.path());
    let leaf = paths.build_cgroup.join("b6-s-api");
    std::fs::create_dir_all(&leaf).unwrap();
    std::fs::write(leaf.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
    std::fs::write(&paths.mountinfo, "").unwrap();
    let jail = make_jail(&paths.chroot_base, "b6-s-api");
    let report = reap_orphan_builds(&paths).await;
    assert!(report.killed.is_empty());
    assert!(report.jails.is_empty());
    assert_eq!(report.failures, 2, "the stuck kill and the kept jail");
    assert!(leaf.exists());
    assert!(jail.exists());
}

// An unlistable build cgroup parent (not merely missing) leaves every VM's state unknown:
// no jail is removed.
#[tokio::test]
async fn an_unlistable_build_cgroup_removes_no_jail() {
    let d = tempfile::tempdir().unwrap();
    let mut paths = paths_in(d.path());
    paths.build_cgroup = d.path().join("not-a-dir");
    std::fs::write(&paths.build_cgroup, "").unwrap(); // read_dir => ENOTDIR
    std::fs::write(&paths.mountinfo, "").unwrap();
    let jail = make_jail(&paths.chroot_base, "b7-s-api");
    let report = reap_orphan_builds(&paths).await;
    assert!(report.jails.is_empty());
    assert_eq!(report.failures, 1);
    assert!(jail.exists());
}

/// Undoes the on-box test's host changes even when an assertion fails.
struct HostCleanup {
    parent: PathBuf,
    tap: &'static str,
    child: std::process::Child,
}

impl Drop for HostCleanup {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", self.tap])
            .status();
        for _ in 0..20 {
            if remove_cgroup_tree(&self.parent).is_ok() || !self.parent.exists() {
                break;
            }
            std::thread::sleep(KILL_POLL);
        }
    }
}

/// On-box: a real cgroup-v2 leaf holding a live process in a nested cgroup (standing in for
/// an orphaned Firecracker) is killed, waited for and removed; a real `jkbld` TAP is deleted
/// and the jail removed.
///
///   sudo <test-bin> --ignored --nocapture build_reaper::tests::reaps_a_live_cgroup
#[tokio::test]
#[ignore = "needs root + cgroup v2 at /sys/fs/cgroup"]
async fn reaps_a_live_cgroup() {
    let parent = PathBuf::from("/sys/fs/cgroup/jkbase-reaper-test");
    let _ = remove_cgroup_tree(&parent);
    let leaf = parent.join("b1-s-orphan");
    std::fs::create_dir_all(leaf.join("nested")).unwrap();
    // A real persistent TAP of the build shape. The listing dir names only it, so the
    // reap never touches this box's own build TAPs.
    let tap = "jkbld990";
    let _ = std::process::Command::new("ip")
        .args(["link", "delete", tap])
        .status();
    let child = std::process::Command::new("sleep")
        .arg("600")
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut guard = HostCleanup {
        parent: parent.clone(),
        tap,
        child,
    };
    std::fs::write(leaf.join("nested/cgroup.procs"), pid.to_string()).unwrap();
    assert!(populated(
        &std::fs::read_to_string(leaf.join("cgroup.events")).unwrap()
    ));
    let made = std::process::Command::new("ip")
        .args(["tuntap", "add", "dev", tap, "mode", "tap"])
        .status()
        .unwrap();
    assert!(made.success(), "create test TAP");

    let d = tempfile::tempdir().unwrap();
    let mut paths = paths_in(d.path());
    paths.build_cgroup = parent.clone();
    paths.mountinfo = PathBuf::from("/proc/self/mountinfo");
    std::fs::create_dir_all(paths.sys_class_net.join(tap)).unwrap();
    let jail = make_jail(&paths.chroot_base, "b1-s-orphan");

    let report = reap_orphan_builds(&paths).await;
    assert_eq!(report.killed, ["b1-s-orphan"]);
    assert_eq!(report.taps, [tap]);
    assert_eq!(report.jails, ["b1-s-orphan"]);
    assert_eq!(report.failures, 0);
    let status = guard.child.wait().unwrap();
    assert!(!status.success(), "the orphan was killed: {status}");
    assert!(!leaf.exists());
    assert!(
        !Path::new("/sys/class/net").join(tap).exists(),
        "TAP deleted"
    );
    assert!(!jail.exists());
    println!("PASS: live cgroup killed + removed ({status}), TAP deleted, jail removed");
}
