//! [`EtcdControlStore`] — the cluster-grade, **replicated** R1 [`ControlStore`]
//! over an etcd v3 cluster. The control plane is written ONCE against the
//! `ControlStore` seam; this backend lets that same code run with metadata that
//! survives node loss (raft), so it advertises [`Caps::REPLICATED_TXN`] and a
//! multi-node topology will accept it where the single-node redb default is
//! refused.
//!
//! The mapping is near-mechanical because the seam was shaped after etcd's own
//! transaction: a logical `(table, key)` becomes the physical etcd key
//! `<table>\0<key>` (identical to the redb backend's composite key; table names
//! never contain NUL), a prefix scan is an etcd ranged `get … with_prefix`, and
//! the guards+writes [`ControlStore::transact`] is exactly one etcd
//! `Txn::when(compares).and_then(ops)` — etcd ANDs the comparisons and applies the
//! ops iff they all hold, returning `succeeded=false` (→ [`SubstrateError::TxnConflict`])
//! otherwise. No locks, no read-modify-write races: the compare-and-set is atomic
//! cluster-wide.

use crate::{Backend, Caps, ControlStore, Guard, Result, SubstrateError, Write};
use async_trait::async_trait;
use bytes::Bytes;
use etcd_client::{Client, Compare, CompareOp, GetOptions, SortOrder, SortTarget, Txn, TxnOp};

pub struct EtcdControlStore {
    client: Client,
}

fn be<E: std::fmt::Display>(e: E) -> SubstrateError {
    SubstrateError::Backend(e.to_string())
}

/// `<table>\0<key>` — the physical etcd key for a logical (table, key) pair.
fn ekey(table: &str, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(table.len() + 1 + key.len());
    k.extend_from_slice(table.as_bytes());
    k.push(0);
    k.extend_from_slice(key);
    k
}

/// Translate one guard into the etcd comparisons that must hold. etcd ANDs every
/// comparison in a txn's `when`, so `Equals` emits BOTH an existence check and a
/// value check — matching the redb backend, where a missing key never "equals"
/// (not even an empty expected value).
fn guard_compares(g: &Guard, out: &mut Vec<Compare>) {
    match g {
        Guard::Absent { table, key } => {
            // create_revision == 0 ⇔ the key has never existed (or was deleted).
            out.push(Compare::create_revision(
                ekey(table, key),
                CompareOp::Equal,
                0,
            ));
        }
        Guard::Present { table, key } => {
            out.push(Compare::create_revision(
                ekey(table, key),
                CompareOp::Greater,
                0,
            ));
        }
        Guard::Equals { table, key, value } => {
            out.push(Compare::create_revision(
                ekey(table, key),
                CompareOp::Greater,
                0,
            ));
            out.push(Compare::value(
                ekey(table, key),
                CompareOp::Equal,
                value.to_vec(),
            ));
        }
    }
}

impl EtcdControlStore {
    /// Connect to an etcd cluster (one or more `host:port` endpoints).
    pub async fn connect(endpoints: &[String]) -> Result<Self> {
        let client = Client::connect(endpoints, None).await.map_err(be)?;
        Ok(Self { client })
    }

    /// Wrap an already-connected client (used by tests).
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ControlStore for EtcdControlStore {
    async fn get(&self, table: &str, key: &[u8]) -> Result<Option<Bytes>> {
        let mut client = self.client.clone();
        let resp = client.get(ekey(table, key), None).await.map_err(be)?;
        Ok(resp
            .kvs()
            .first()
            .map(|kv| Bytes::copy_from_slice(kv.value())))
    }

    async fn scan_prefix(&self, table: &str, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let start = ekey(table, prefix);
        let strip = table.len() + 1; // drop `<table>\0` to recover the logical key
        let opts = GetOptions::new()
            .with_prefix()
            .with_sort(SortTarget::Key, SortOrder::Ascend);
        let mut client = self.client.clone();
        let resp = client.get(start, Some(opts)).await.map_err(be)?;
        let out = resp
            .kvs()
            .iter()
            .map(|kv| {
                (
                    Bytes::copy_from_slice(&kv.key()[strip..]),
                    Bytes::copy_from_slice(kv.value()),
                )
            })
            .collect();
        Ok(out)
    }

    async fn transact(&self, guards: Vec<Guard>, writes: Vec<Write>) -> Result<()> {
        let mut compares = Vec::new();
        for g in &guards {
            guard_compares(g, &mut compares);
        }
        let ops: Vec<TxnOp> = writes
            .iter()
            .map(|w| match w {
                Write::Put { table, key, value } => {
                    TxnOp::put(ekey(table, key), value.to_vec(), None)
                }
                Write::Delete { table, key } => TxnOp::delete(ekey(table, key), None),
            })
            .collect();
        let mut client = self.client.clone();
        let resp = client
            .txn(Txn::new().when(compares).and_then(ops))
            .await
            .map_err(be)?;
        if resp.succeeded() {
            Ok(())
        } else {
            Err(SubstrateError::TxnConflict)
        }
    }
}

impl Backend for EtcdControlStore {
    fn backend_name(&self) -> &str {
        "etcd"
    }
    fn caps(&self) -> Caps {
        // raft-replicated transactions survive node loss.
        Caps::REPLICATED_TXN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Non-network coverage: the (table,key) encoding + the guard→compare mapping.
    #[test]
    fn ekey_composes_table_and_key_with_nul() {
        assert_eq!(ekey("projects", b"p1"), b"projects\0p1");
        assert_eq!(ekey("t", b""), b"t\0");
    }

    #[test]
    fn equals_guard_emits_existence_plus_value_check() {
        // A missing key must never satisfy Equals, so it expands to 2 comparisons;
        // Absent/Present are a single comparison each.
        let mut v = Vec::new();
        guard_compares(
            &Guard::Equals {
                table: "t".into(),
                key: Bytes::from_static(b"k"),
                value: Bytes::from_static(b"x"),
            },
            &mut v,
        );
        assert_eq!(v.len(), 2);
        let mut a = Vec::new();
        guard_compares(
            &Guard::Absent {
                table: "t".into(),
                key: Bytes::from_static(b"k"),
            },
            &mut a,
        );
        assert_eq!(a.len(), 1);
    }
}
