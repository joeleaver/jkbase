//! Vendor-neutrality acceptance suite for the storage substrate. Exercises the
//! properties that justify the seam, through the public API and the local default
//! backends.
//!
//! One acceptance criterion is intentionally NOT here: the cross-vendor
//! identical-binary-hash check (S3 ↔ MinIO ↔ Ceph) needs the feature-gated cluster
//! backends and their services (MinIO/Ceph), so it lands with those cards.

use jkbase_substrate::*;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("jkb-neutral-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Stream-compare two files in bounded chunks (never buffers either whole file).
async fn files_equal(a: &Path, b: &Path) -> bool {
    let (mut fa, mut fb) = (
        tokio::fs::File::open(a).await.unwrap(),
        tokio::fs::File::open(b).await.unwrap(),
    );
    let (mut ba, mut bb) = (vec![0u8; 256 * 1024], vec![0u8; 256 * 1024]);
    loop {
        let na = fa.read(&mut ba).await.unwrap();
        let nb = fb.read(&mut bb).await.unwrap();
        if na != nb {
            return false;
        }
        if na == 0 {
            return true;
        }
        if ba[..na] != bb[..nb] {
            return false;
        }
    }
}

/// Zero-vendor boot: the local default config builds, every role is a local
/// backend (no network/vendor socket), and none dishonestly claims cluster caps.
#[tokio::test]
async fn zero_vendor_boot_uses_only_local_backends() {
    let base = tmp("boot");
    let s = build_substrate(SubstrateConfig {
        node_count: 1,
        control: ControlBackend::Redb { path: base.join("c.redb") },
        blob: BlobBackend::LocalFs { root: base.join("b") },
        lease: LeaseBackend::Flock { dir: base.join("l"), source_id: "n1".into() },
        data_disk: DataDiskBackend::LocalLoop { dir: base.join("d") },
        tenant_object_store_host: Some("s3.jkbase.app".into()),
    })
    .unwrap();
    for name in [
        s.control.backend_name(),
        s.blob.backend_name(),
        s.lease.backend_name(),
        s.data_disk.backend_name(),
    ] {
        assert!(
            ["redb", "localfs", "flock", "localloop"].contains(&name),
            "unexpected (possibly network) backend: {name}"
        );
    }
    assert!(!s.lease.caps().contains(Caps::CLUSTER_EXCLUSIVE_FENCE));
    assert!(!s.control.caps().contains(Caps::REPLICATED_TXN));
    assert!(!s.data_disk.caps().contains(Caps::STORAGE_ENFORCED_RWO));
    let _ = std::fs::remove_dir_all(&base);
}

/// Fence holds across a restore: after a writer "crashes" (instance dropped
/// without release), a restored writer acquires a strictly superseding token and
/// the old token can no longer renew.
#[tokio::test]
async fn fence_holds_across_restore() {
    let dir = tmp("fence");
    let token_old = {
        let l = FlockLease::open(&dir, "node-a").unwrap();
        l.acquire("vm1", "node-a", Duration::from_secs(30)).await.unwrap()
        // dropped here WITHOUT release => simulates a crash; OS frees the flock.
    };
    let l2 = FlockLease::open(&dir, "node-a").unwrap();
    let token_new = l2.acquire("vm1", "node-a", Duration::from_secs(30)).await.unwrap();
    assert!(
        token_new.supersedes(&token_old).unwrap(),
        "restored token must fence the crashed writer's token"
    );
    assert!(
        l2.renew(&token_old, Duration::from_secs(30)).await.is_err(),
        "a stale token must not renew after restore"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Token non-portability across a backend swap: a token minted by one lease
/// authority is not comparable against another's, so it can never be carried over
/// to fence on a swapped backend.
#[tokio::test]
async fn token_non_portability_across_backend_swap() {
    let (d1, d2) = (tmp("swapA"), tmp("swapB"));
    let a = FlockLease::open(&d1, "backend-A").unwrap();
    let b = FlockLease::open(&d2, "backend-B").unwrap();
    let ta = a.acquire("x", "h", Duration::from_secs(30)).await.unwrap();
    let tb = b.acquire("x", "h", Duration::from_secs(30)).await.unwrap();
    assert!(matches!(ta.supersedes(&tb), Err(SubstrateError::IncomparableToken)));
    assert!(matches!(tb.supersedes(&ta), Err(SubstrateError::IncomparableToken)));
    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
}

/// No-OOM streaming: a 64 MiB blob round-trips byte-for-byte. The impl moves it
/// with a bounded `tokio::io::copy`, so memory stays flat regardless of size (the
/// full 2 GiB variant is the ignored stress test below).
#[tokio::test]
async fn blob_streams_large_file_correctly() {
    let base = tmp("stream");
    let bs = LocalFsBlobStore::open(base.join("store")).unwrap();
    let src = base.join("big.bin");
    let chunk = vec![0xABu8; 1024 * 1024];
    {
        let mut f = tokio::fs::File::create(&src).await.unwrap();
        for _ in 0..64 {
            f.write_all(&chunk).await.unwrap();
        }
        f.flush().await.unwrap();
    }
    bs.put_file("big", &src).await.unwrap();
    assert_eq!(bs.head("big").await.unwrap().unwrap().size, 64 * 1024 * 1024);
    let out = base.join("out.bin");
    bs.get_to_file("big", &out).await.unwrap();
    assert!(files_equal(&src, &out).await, "streamed blob must round-trip exactly");
    let _ = std::fs::remove_dir_all(&base);
}

/// No tenant-S3 circularity: an R2/R4 endpoint resolving to jkbase's own tenant
/// object store is refused; an external store is fine.
#[test]
fn no_tenant_s3_circularity() {
    assert!(assert_not_self_referential("https://s3.jkbase.app/cluster", Some("s3.jkbase.app")).is_err());
    assert!(assert_not_self_referential("https://minio.internal:9000/cluster", Some("s3.jkbase.app")).is_ok());
}

/// Full 2 GiB streaming stress (bounded memory). Heavy on disk + time, so ignored;
/// run with: cargo test -p jkbase-substrate --test neutrality -- --ignored
#[tokio::test]
#[ignore = "2 GiB streaming stress; run explicitly"]
async fn blob_streams_2gib_without_oom() {
    let base = tmp("stream2g");
    let bs = LocalFsBlobStore::open(base.join("store")).unwrap();
    let src = base.join("huge.bin");
    {
        // Sparse 2 GiB: set_len leaves a hole; streaming reads it as zeros without
        // ever materialising 2 GiB in RAM.
        let f = tokio::fs::File::create(&src).await.unwrap();
        f.set_len(2 * 1024 * 1024 * 1024).await.unwrap();
    }
    bs.put_file("huge", &src).await.unwrap();
    assert_eq!(bs.head("huge").await.unwrap().unwrap().size, 2 * 1024 * 1024 * 1024);
    let _ = std::fs::remove_dir_all(&base);
}
