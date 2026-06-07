//! Live integration test for [`EtcdControlStore`] against a real etcd v3 cluster.
//! Marked `#[ignore]` so the default `cargo test` never reaches the network; run
//! it against a running etcd:
//!
//! ```text
//! docker run -d --name jkb-etcd -p 2379:2379 quay.io/coreos/etcd:v3.5.17 \
//!   /usr/local/bin/etcd --advertise-client-urls http://0.0.0.0:2379 \
//!   --listen-client-urls http://0.0.0.0:2379
//! cargo test -p jkbase-substrate --features etcd --test etcd_control -- --ignored
//! ```
//!
//! Endpoint comes from `JKB_ETCD_ENDPOINT` (default http://127.0.0.1:2379). Every
//! table is namespaced by pid so the suite is safe to re-run against a persistent
//! cluster. It mirrors the redb `ControlStore` contract tests so the two backends
//! are proven behavior-equivalent through the seam.
#![cfg(feature = "etcd")]

use bytes::Bytes;
use jkbase_substrate::{ControlStore, EtcdControlStore, Guard, SubstrateError, Write};

fn endpoint() -> String {
    std::env::var("JKB_ETCD_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:2379".to_string())
}

async fn store() -> EtcdControlStore {
    EtcdControlStore::connect(&[endpoint()]).await.expect("connect etcd")
}

fn put(table: &str, key: &[u8], value: &[u8]) -> Write {
    Write::Put {
        table: table.into(),
        key: Bytes::copy_from_slice(key),
        value: Bytes::copy_from_slice(value),
    }
}

#[tokio::test]
#[ignore = "requires a running etcd; run with --ignored"]
async fn etcd_control_contract_matches_redb() {
    let s = store().await;
    let pid = std::process::id();
    // pid-namespaced tables so re-runs against a persistent cluster don't collide.
    let projects = format!("{pid}_projects");
    let domains = format!("{pid}_domains");
    let t = format!("{pid}_t");
    let p = format!("{pid}_p");
    let other = format!("{pid}_other");

    // put → get round-trips; absent key is None; table namespacing is independent.
    s.transact(vec![], vec![put(&projects, b"p1", b"v1")]).await.unwrap();
    assert_eq!(s.get(&projects, b"p1").await.unwrap().as_deref(), Some(&b"v1"[..]));
    assert!(s.get(&projects, b"absent").await.unwrap().is_none());
    assert!(s.get(&domains, b"p1").await.unwrap().is_none());

    // Absent guard = create-if-absent: the second create must conflict.
    let g = || vec![Guard::Absent { table: t.clone(), key: Bytes::from_static(b"k") }];
    s.transact(g(), vec![put(&t, b"k", b"first")]).await.unwrap();
    assert!(matches!(
        s.transact(g(), vec![put(&t, b"k", b"second")]).await,
        Err(SubstrateError::TxnConflict)
    ));
    assert_eq!(s.get(&t, b"k").await.unwrap().as_deref(), Some(&b"first"[..]));

    // Equals guard = compare-and-set. Wrong expected value conflicts, writes nothing.
    let bad = vec![Guard::Equals { table: t.clone(), key: Bytes::from_static(b"k"), value: Bytes::from_static(b"WRONG") }];
    assert!(matches!(
        s.transact(bad, vec![put(&t, b"k", b"v1")]).await,
        Err(SubstrateError::TxnConflict)
    ));
    assert_eq!(s.get(&t, b"k").await.unwrap().as_deref(), Some(&b"first"[..]));
    let good = vec![Guard::Equals { table: t.clone(), key: Bytes::from_static(b"k"), value: Bytes::from_static(b"first") }];
    s.transact(good, vec![put(&t, b"k", b"v1")]).await.unwrap();
    assert_eq!(s.get(&t, b"k").await.unwrap().as_deref(), Some(&b"v1"[..]));

    // CAS against a MISSING key never matches (even though etcd treats absent as
    // empty) — Equals emits an existence check too.
    let miss = vec![Guard::Equals { table: t.clone(), key: Bytes::from_static(b"ghost"), value: Bytes::from_static(b"") }];
    assert!(matches!(
        s.transact(miss, vec![put(&t, b"ghost", b"x")]).await,
        Err(SubstrateError::TxnConflict)
    ));

    // scan_prefix is ordered ascending + table-scoped; empty prefix = whole table.
    s.transact(
        vec![],
        vec![
            put(&p, b"a/1", b"1"),
            put(&p, b"a/2", b"2"),
            put(&p, b"b/1", b"3"),
            put(&other, b"a/9", b"9"),
        ],
    )
    .await
    .unwrap();
    let keys: Vec<_> = s.scan_prefix(&p, b"a/").await.unwrap().into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, vec![Bytes::from_static(b"a/1"), Bytes::from_static(b"a/2")]);
    assert_eq!(s.scan_prefix(&p, b"").await.unwrap().len(), 3);
    assert_eq!(s.scan_prefix(&other, b"").await.unwrap().len(), 1);

    // Delete removes the key.
    s.transact(vec![], vec![Write::Delete { table: t.clone(), key: Bytes::from_static(b"k") }])
        .await
        .unwrap();
    assert!(s.get(&t, b"k").await.unwrap().is_none());

    // Honest cluster cap.
    use jkbase_substrate::{Backend, Caps};
    assert!(s.caps().contains(Caps::REPLICATED_TXN));
    assert_eq!(s.backend_name(), "etcd");
}
