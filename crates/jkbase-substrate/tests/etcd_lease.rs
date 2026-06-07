//! Live integration test for [`EtcdLease`] against a real etcd v3 cluster. Marked
//! `#[ignore]` so the default `cargo test` never reaches the network; run it
//! against a running etcd (see `tests/etcd_control.rs` for the docker one-liner):
//!
//! ```text
//! cargo test -p jkbase-substrate --features etcd --test etcd_lease -- --ignored
//! ```
//!
//! Endpoint comes from `JKB_ETCD_ENDPOINT` (default http://127.0.0.1:2379). Scopes
//! are pid-namespaced so the suite is safe to re-run against a persistent cluster.
//! It mirrors the FlockLease contract tests AND exercises the etcd-specific
//! steal-on-expiry path (native lease TTL auto-deletes the holder key).
#![cfg(feature = "etcd")]

use jkbase_substrate::{Backend, Caps, EtcdLease, Lease, SubstrateError};
use std::time::Duration;

fn endpoint() -> String {
    std::env::var("JKB_ETCD_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:2379".to_string())
}

async fn lease() -> EtcdLease {
    EtcdLease::connect(&[endpoint()], "test-cluster").await.expect("connect etcd")
}

#[tokio::test]
#[ignore = "requires a running etcd; run with --ignored"]
async fn etcd_lease_contract_and_steal_on_expiry() {
    let l = lease().await;
    let pid = std::process::id();
    let proj = format!("{pid}-proj");
    let held = format!("{pid}-held");
    let ren = format!("{pid}-renew");
    let exp = format!("{pid}-expire");
    let ttl = Duration::from_secs(30);

    // Epochs strictly increase across acquire/release; tokens are comparable.
    let t1 = l.acquire(&proj, "h1", ttl).await.unwrap();
    assert_eq!(t1.source_id, "test-cluster");
    l.release(&t1).await.unwrap();
    let t2 = l.acquire(&proj, "h2", ttl).await.unwrap();
    assert!(t2.epoch > t1.epoch, "epoch monotonic: {} > {}", t2.epoch, t1.epoch);
    assert!(t2.supersedes(&t1).unwrap());
    l.release(&t2).await.unwrap();

    // A second acquire while a live holder owns it is rejected (cluster-exclusive).
    let _h = l.acquire(&held, "h1", ttl).await.unwrap();
    assert!(matches!(
        l.acquire(&held, "h2", ttl).await,
        Err(SubstrateError::LeaseHeld { .. })
    ));

    // renew honors token identity; a released token can no longer be renewed.
    let tr = l.acquire(&ren, "h", ttl).await.unwrap();
    assert!(l.renew(&tr, ttl).await.is_ok());
    let cur = l.current(&ren).await.unwrap().unwrap();
    assert_eq!(cur.epoch, tr.epoch);
    assert_eq!(cur.holder, "h");
    l.release(&tr).await.unwrap();
    assert!(l.current(&ren).await.unwrap().is_none());
    assert!(matches!(l.renew(&tr, ttl).await, Err(SubstrateError::Fenced { .. })));

    // Steal-on-expiry: a holder that stops renewing loses the lease (etcd expires
    // it and deletes the key), so a later acquire wins with a strictly higher epoch.
    let short = Duration::from_secs(1);
    let dying = l.acquire(&exp, "crashed", short).await.unwrap();
    // Wait for etcd to expire the 1s lease (poll current() until free, ~bounded).
    let mut freed = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if l.current(&exp).await.unwrap().is_none() {
            freed = true;
            break;
        }
    }
    assert!(freed, "lease should expire and free the scope");
    let stolen = l.acquire(&exp, "successor", ttl).await.unwrap();
    assert!(stolen.epoch > dying.epoch, "stolen epoch strictly higher");
    // The fenced-out original holder can neither renew nor wrongly release.
    assert!(matches!(l.renew(&dying, ttl).await, Err(SubstrateError::Fenced { .. })));
    assert!(matches!(l.release(&dying).await, Err(SubstrateError::Fenced { .. })));
    l.release(&stolen).await.unwrap();

    // Honest cluster caps.
    assert!(l.caps().contains(Caps::CLUSTER_EXCLUSIVE_FENCE | Caps::MONOTONIC_FENCE));
    assert_eq!(l.backend_name(), "etcd-lease");
}
