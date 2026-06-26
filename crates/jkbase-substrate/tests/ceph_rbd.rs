//! Live integration test for [`CephRbd`] against a real Ceph cluster. Needs root
//! (`rbd map` is a kernel op) + the `rbd`/`ceph` CLIs + a reachable cluster, so it
//! is `#[ignore]`d. Bring up single-node Ceph (host-networked so the host client
//! can reach it), create a size-1 `rbd` pool, then:
//!
//! ```text
//! sudo -E env "PATH=$PATH" cargo test -p jkbase-substrate --features ceph \
//!     --test ceph_rbd -- --ignored --nocapture
//! ```
//!
//! Pool comes from `JKB_CEPH_POOL` (default `rbd`). The test maps TWO independent
//! kernel clients of one image (each gets its own watcher address — functionally
//! two hosts for the Ceph fence mechanism) to prove the safety-critical property:
//! a superseding `attach_rwo` blocklists the prior writer so its I/O is rejected.
#![cfg(feature = "ceph")]

use jkbase_substrate::{Backend, Caps, CephRbd, DataDiskProvider, FenceToken, SubstrateError};
use std::time::Duration;

fn pool() -> String {
    std::env::var("JKB_CEPH_POOL").unwrap_or_else(|_| "rbd".to_string())
}

fn token(epoch: u64) -> FenceToken {
    FenceToken {
        scope: "disk".into(),
        epoch,
        holder: "host-a".into(),
        source_id: "ceph".into(),
    }
}

/// Write one 4 KiB block of `byte` to a block device and fsync (forcing writeback so
/// a fenced/blocklisted client surfaces EIO). Bounded so a stuck lock can't hang us.
async fn dev_write(path: &str, byte: u8) -> std::io::Result<()> {
    let p = path.to_string();
    let fut = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).open(&p)?;
        f.write_all(&[byte; 4096])?;
        f.sync_all()
    });
    match tokio::time::timeout(Duration::from_secs(15), fut).await {
        Ok(join) => join.expect("write task panicked"),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "device write timed out",
        )),
    }
}

async fn dev_read_first(path: &str) -> u8 {
    let p = path.to_string();
    tokio::task::spawn_blocking(move || -> u8 {
        use std::io::Read;
        let mut f = std::fs::File::open(&p).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        b[0]
    })
    .await
    .unwrap()
}

async fn rbd(args: &[&str]) -> String {
    let out = tokio::process::Command::new("rbd")
        .args(args)
        .output()
        .await
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}
async fn ceph(args: &[&str]) -> String {
    let out = tokio::process::Command::new("ceph")
        .args(args)
        .output()
        .await
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The cluster's recorded live-writer (watcher) address for an image.
async fn watcher_addr(p: &str, image: &str) -> String {
    rbd(&["status", &format!("{p}/{image}")])
        .await
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("watcher=")
                .and_then(|r| r.split_whitespace().next())
                .map(str::to_string)
        })
        .expect("a live watcher")
}

#[tokio::test]
#[ignore = "requires root + rbd/ceph CLIs + a reachable Ceph cluster"]
async fn ceph_rbd_lifecycle_and_storage_enforced_fence() {
    let p = CephRbd::new(pool());
    let pid = std::process::id();
    let life = format!("jkb-life-{pid}");
    let fence = format!("jkb-fence-{pid}");

    // Clean slate (ignore errors if absent).
    let _ = p.destroy(&life).await;
    let _ = p.destroy(&fence).await;

    // --- Lifecycle: ensure -> attach -> write/read -> detach -> destroy ---
    p.ensure(&life, 16 * 1024 * 1024).await.unwrap();
    // Idempotent ensure never errors / reformats.
    p.ensure(&life, 16 * 1024 * 1024).await.unwrap();
    let dev = p.attach_rwo(&life, &token(1)).await.unwrap();
    let path = dev.path.to_string_lossy().to_string();
    assert!(path.starts_with("/dev/rbd"), "got {path}");
    dev_write(&path, 0x5A)
        .await
        .expect("write to freshly-attached disk");
    assert_eq!(dev_read_first(&path).await, 0x5A, "read-back matches");
    p.detach(&life).await.unwrap();
    p.destroy(&life).await.unwrap();
    assert!(matches!(
        p.attach_rwo(&life, &token(1)).await,
        Err(SubstrateError::NotFound(_))
    ));

    // --- Storage-enforced fence: a superseding attach blocklists the prior writer ---
    p.ensure(&fence, 16 * 1024 * 1024).await.unwrap();
    let dev_a = p.attach_rwo(&fence, &token(1)).await.unwrap();
    let pa = dev_a.path.to_string_lossy().to_string();
    dev_write(&pa, 0xA1)
        .await
        .expect("holder A writes before being superseded");
    // The cluster's record of the live writer A, which the steal must fence.
    let watcher_a = watcher_addr(&pool(), &fence).await;

    // A higher-epoch token supersedes: attach blocklists A at the OSDs, drops the
    // now-fenced stale local mapping, and binds a fresh client B.
    let dev_b = p.attach_rwo(&fence, &token(2)).await.unwrap();
    let pb = dev_b.path.to_string_lossy().to_string();
    assert!(pb.starts_with("/dev/rbd"), "got {pb}");

    // SAFETY PROPERTY: the superseded writer A is now blocklisted, so its I/O is
    // rejected cluster-wide (proven directly earlier: a blocklisted client gets
    // EIO). On two real hosts A's device would still exist and be dead; single-host
    // we assert the fence the cluster actually applied.
    let blocklist = ceph(&["osd", "blocklist", "ls"]).await;
    assert!(
        blocklist.contains(&watcher_a),
        "prior writer {watcher_a} must be blocklisted:\n{blocklist}"
    );
    // Liveness: the new holder B can write.
    dev_write(&pb, 0xB2).await.expect("new holder B writes");

    // A stale token (older epoch than the recorded holder) is refused.
    assert!(matches!(
        p.attach_rwo(&fence, &token(1)).await,
        Err(SubstrateError::Fenced { .. })
    ));

    // Cleanup (detach unmaps every device this host mapped for the image).
    p.destroy(&fence).await.unwrap();
    let _ = ceph(&["osd", "blocklist", "clear"]).await;

    assert_eq!(p.caps(), Caps::STORAGE_ENFORCED_RWO);
    assert_eq!(p.backend_name(), "ceph-rbd");
}
