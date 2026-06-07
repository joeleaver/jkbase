//! [`RedbControlStore`] — the R1 default [`ControlStore`], backed by an embedded
//! redb database. ACID but single-node, so it advertises [`Caps::SINGLE_NODE_TXN`];
//! a multi-node cluster needs a replicated backend (separate feature-gated card).
//!
//! The trait's dynamic `table: &str` is mapped onto redb's static table names by
//! namespacing every logical table into ONE physical redb table with composite
//! keys `<table>\0<key>` (table identifiers never contain NUL). The guards+writes
//! `transact` runs as a single redb write transaction — guards are checked, and on
//! any miss the transaction is abandoned uncommitted ([`SubstrateError::TxnConflict`]).
//! redb work runs on `spawn_blocking` (it fsyncs on commit) so the async runtime
//! is never blocked.

use crate::{Backend, Caps, ControlStore, Guard, Result, SubstrateError, Write};
use async_trait::async_trait;
use bytes::Bytes;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("jkbase_control");

pub struct RedbControlStore {
    db: Arc<Database>,
}

fn be<E: std::fmt::Display>(e: E) -> SubstrateError {
    SubstrateError::Backend(e.to_string())
}

/// `<table>\0<key>` — the physical redb key for a logical (table, key) pair.
fn ckey(table: &str, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(table.len() + 1 + key.len());
    k.extend_from_slice(table.as_bytes());
    k.push(0);
    k.extend_from_slice(key);
    k
}

impl RedbControlStore {
    /// Open (creating if absent) the control store at `path`, ensuring the backing
    /// table exists so reads never race table creation.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(be)?;
        let wtx = db.begin_write().map_err(be)?;
        {
            wtx.open_table(TABLE).map_err(be)?;
        }
        wtx.commit().map_err(be)?;
        Ok(Self { db: Arc::new(db) })
    }
}

#[async_trait]
impl ControlStore for RedbControlStore {
    async fn get(&self, table: &str, key: &[u8]) -> Result<Option<Bytes>> {
        let db = self.db.clone();
        let ck = ckey(table, key);
        tokio::task::spawn_blocking(move || -> Result<Option<Bytes>> {
            let rtx = db.begin_read().map_err(be)?;
            let t = rtx.open_table(TABLE).map_err(be)?;
            let v = t.get(ck.as_slice()).map_err(be)?;
            Ok(v.map(|g| Bytes::copy_from_slice(g.value())))
        })
        .await
        .map_err(be)?
    }

    async fn scan_prefix(&self, table: &str, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let db = self.db.clone();
        let start = ckey(table, prefix);
        let strip = table.len() + 1; // bytes to drop to recover the logical key
        tokio::task::spawn_blocking(move || -> Result<Vec<(Bytes, Bytes)>> {
            let rtx = db.begin_read().map_err(be)?;
            let t = rtx.open_table(TABLE).map_err(be)?;
            let mut out = Vec::new();
            for item in t.range(start.as_slice()..).map_err(be)? {
                let (k, v) = item.map_err(be)?;
                let kb = k.value();
                if !kb.starts_with(&start) {
                    break; // ordered scan: first non-match ends the prefix range
                }
                out.push((
                    Bytes::copy_from_slice(&kb[strip..]),
                    Bytes::copy_from_slice(v.value()),
                ));
            }
            Ok(out)
        })
        .await
        .map_err(be)?
    }

    async fn transact(&self, guards: Vec<Guard>, writes: Vec<Write>) -> Result<()> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let wtx = db.begin_write().map_err(be)?;
            {
                let mut t = wtx.open_table(TABLE).map_err(be)?;
                // Check every guard first; a single miss abandons the whole txn.
                for g in &guards {
                    let (ck, holds) = match g {
                        Guard::Absent { table, key } => {
                            let cur = t.get(ckey(table, key).as_slice()).map_err(be)?;
                            (None::<()>, cur.is_none())
                        }
                        Guard::Present { table, key } => {
                            let cur = t.get(ckey(table, key).as_slice()).map_err(be)?;
                            (None, cur.is_some())
                        }
                        Guard::Equals { table, key, value } => {
                            let cur = t.get(ckey(table, key).as_slice()).map_err(be)?;
                            let ok = cur.map(|g| g.value() == value.as_ref()).unwrap_or(false);
                            (None, ok)
                        }
                    };
                    let _ = ck;
                    if !holds {
                        // Drop the table + abort without committing.
                        drop(t);
                        wtx.abort().map_err(be)?;
                        return Err(SubstrateError::TxnConflict);
                    }
                }
                for w in &writes {
                    match w {
                        Write::Put { table, key, value } => {
                            t.insert(ckey(table, key).as_slice(), value.as_ref())
                                .map_err(be)?;
                        }
                        Write::Delete { table, key } => {
                            t.remove(ckey(table, key).as_slice()).map_err(be)?;
                        }
                    }
                }
            }
            wtx.commit().map_err(be)?;
            Ok(())
        })
        .await
        .map_err(be)?
    }
}

impl Backend for RedbControlStore {
    fn backend_name(&self) -> &str {
        "redb"
    }
    fn caps(&self) -> Caps {
        Caps::SINGLE_NODE_TXN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_path(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-redb-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("control.redb")
    }

    fn put(table: &str, key: &[u8], value: &[u8]) -> Write {
        Write::Put {
            table: table.into(),
            key: Bytes::copy_from_slice(key),
            value: Bytes::copy_from_slice(value),
        }
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let s = RedbControlStore::open(db_path("rt")).unwrap();
        s.transact(vec![], vec![put("projects", b"p1", b"v1")]).await.unwrap();
        assert_eq!(s.get("projects", b"p1").await.unwrap().as_deref(), Some(&b"v1"[..]));
        assert!(s.get("projects", b"absent").await.unwrap().is_none());
        // Table namespacing: same key in another table is independent.
        assert!(s.get("domains", b"p1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn absent_guard_gives_create_if_absent() {
        let s = RedbControlStore::open(db_path("absent")).unwrap();
        let g = || vec![Guard::Absent { table: "t".into(), key: Bytes::from_static(b"k") }];
        s.transact(g(), vec![put("t", b"k", b"first")]).await.unwrap();
        // Second create must conflict (key now present).
        assert!(matches!(
            s.transact(g(), vec![put("t", b"k", b"second")]).await,
            Err(SubstrateError::TxnConflict)
        ));
        assert_eq!(s.get("t", b"k").await.unwrap().as_deref(), Some(&b"first"[..]));
    }

    #[tokio::test]
    async fn equals_guard_is_compare_and_set() {
        let s = RedbControlStore::open(db_path("cas")).unwrap();
        s.transact(vec![], vec![put("t", b"k", b"v0")]).await.unwrap();
        // CAS with the wrong expected value conflicts and writes nothing.
        let bad = vec![Guard::Equals { table: "t".into(), key: Bytes::from_static(b"k"), value: Bytes::from_static(b"WRONG") }];
        assert!(matches!(
            s.transact(bad, vec![put("t", b"k", b"v1")]).await,
            Err(SubstrateError::TxnConflict)
        ));
        assert_eq!(s.get("t", b"k").await.unwrap().as_deref(), Some(&b"v0"[..]));
        // CAS with the right value commits.
        let good = vec![Guard::Equals { table: "t".into(), key: Bytes::from_static(b"k"), value: Bytes::from_static(b"v0") }];
        s.transact(good, vec![put("t", b"k", b"v1")]).await.unwrap();
        assert_eq!(s.get("t", b"k").await.unwrap().as_deref(), Some(&b"v1"[..]));
    }

    #[tokio::test]
    async fn scan_prefix_is_ordered_and_table_scoped() {
        let s = RedbControlStore::open(db_path("scan")).unwrap();
        s.transact(
            vec![],
            vec![
                put("p", b"a/1", b"1"),
                put("p", b"a/2", b"2"),
                put("p", b"b/1", b"3"),
                put("other", b"a/9", b"9"),
            ],
        )
        .await
        .unwrap();
        let got = s.scan_prefix("p", b"a/").await.unwrap();
        let keys: Vec<_> = got.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys, vec![Bytes::from_static(b"a/1"), Bytes::from_static(b"a/2")]);
        // Empty prefix returns the whole table, not other tables.
        assert_eq!(s.scan_prefix("p", b"").await.unwrap().len(), 3);
        assert_eq!(s.scan_prefix("other", b"").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn delete_write_removes_key_and_caps() {
        let s = RedbControlStore::open(db_path("del")).unwrap();
        s.transact(vec![], vec![put("t", b"k", b"v")]).await.unwrap();
        s.transact(vec![], vec![Write::Delete { table: "t".into(), key: Bytes::from_static(b"k") }])
            .await
            .unwrap();
        assert!(s.get("t", b"k").await.unwrap().is_none());
        assert_eq!(s.caps(), Caps::SINGLE_NODE_TXN);
        assert_eq!(s.backend_name(), "redb");
    }
}
