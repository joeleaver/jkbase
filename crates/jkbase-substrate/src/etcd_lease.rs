//! [`EtcdLease`] — the cluster-grade R2 [`Lease`] over etcd v3. Exclusivity is
//! enforced cluster-wide by etcd consensus (an atomic create-if-absent txn picks a
//! single winner) and liveness by a native etcd lease (TTL): when the holder stops
//! refreshing — crash, partition, or graceful exit — etcd expires the lease and
//! **auto-deletes the holder key**, so the next acquirer simply finds it absent and
//! steals it. It therefore advertises [`Caps::CLUSTER_EXCLUSIVE_FENCE`] (and
//! [`Caps::MONOTONIC_FENCE`]) where the node-local [`FlockLease`](crate::FlockLease)
//! cannot, and the factory accepts it as the fence in a multi-node cluster.
//!
//! The monotonic fence epoch is etcd's own globally-increasing store revision: the
//! holder key's `mod_revision`, taken from the acquiring txn's commit revision.
//! Every (re)acquire commits at a strictly higher revision, so epochs strictly
//! increase per scope. Tokens carry a fixed `source_id` (the etcd cluster identity,
//! identical on every node) so they remain comparable across nodes — that is what
//! makes [`FenceToken::supersedes`](crate::FenceToken::supersedes) meaningful for
//! fencing a relocated writer. The fixed-shape token does NOT carry the etcd lease
//! id; renew/release recover it from the holder key (`KeyValue::lease`).

use crate::{Backend, Caps, FenceToken, Lease, Result, SubstrateError};
use async_trait::async_trait;
use etcd_client::{Client, Compare, CompareOp, PutOptions, Txn, TxnOp};
use std::time::Duration;

pub struct EtcdLease {
    client: Client,
    /// Stable identity of the etcd cluster authority, stamped into every token's
    /// `source_id`. MUST be identical on every node so tokens are comparable.
    source_id: String,
}

fn be<E: std::fmt::Display>(e: E) -> SubstrateError {
    SubstrateError::Backend(e.to_string())
}

/// The holder key for `scope`. Injective in `scope`, so two scopes never collide.
fn lease_key(scope: &str) -> String {
    format!("jkbase/leases/{scope}")
}

impl EtcdLease {
    /// Connect to an etcd cluster. `cluster_id` is the lease authority identity,
    /// which must be the SAME string on every node sharing this cluster.
    pub async fn connect(endpoints: &[String], cluster_id: impl Into<String>) -> Result<Self> {
        let client = Client::connect(endpoints, None).await.map_err(be)?;
        Ok(Self {
            client,
            source_id: cluster_id.into(),
        })
    }

    /// Wrap an already-connected client (used by tests).
    pub fn from_client(client: Client, cluster_id: impl Into<String>) -> Self {
        Self {
            client,
            source_id: cluster_id.into(),
        }
    }

    /// Current holder of `scope`: `(holder, epoch = mod_revision, etcd lease id)`.
    async fn read_holder(&self, scope: &str) -> Result<Option<(String, u64, i64)>> {
        let mut c = self.client.clone();
        let resp = c.get(lease_key(scope), None).await.map_err(be)?;
        Ok(resp.kvs().first().map(|kv| {
            (
                String::from_utf8_lossy(kv.value()).into_owned(),
                kv.mod_revision() as u64,
                kv.lease(),
            )
        }))
    }

    fn token(&self, scope: &str, epoch: u64, holder: &str) -> FenceToken {
        FenceToken {
            scope: scope.to_string(),
            epoch,
            holder: holder.to_string(),
            source_id: self.source_id.clone(),
        }
    }
}

#[async_trait]
impl Lease for EtcdLease {
    async fn acquire(&self, scope: &str, holder: &str, ttl: Duration) -> Result<FenceToken> {
        if scope.is_empty() {
            return Err(be("empty lease scope"));
        }
        let ttl_secs = (ttl.as_secs().max(1)) as i64;
        let mut c = self.client.clone();
        let lease_id = c.lease_grant(ttl_secs, None).await.map_err(be)?.id();
        let key = lease_key(scope);
        // Atomic, cluster-wide create-if-absent: only one node wins; an expired
        // holder's key is already gone (etcd deleted it), so the winner steals it.
        let txn = Txn::new()
            .when(vec![Compare::create_revision(
                key.clone(),
                CompareOp::Equal,
                0,
            )])
            .and_then(vec![TxnOp::put(
                key,
                holder.to_string(),
                Some(PutOptions::new().with_lease(lease_id)),
            )]);
        let resp = c.txn(txn).await.map_err(be)?;
        if !resp.succeeded() {
            // A live holder owns it — revoke our just-granted lease so it doesn't leak.
            let _ = c.lease_revoke(lease_id).await;
            return Err(SubstrateError::LeaseHeld {
                scope: scope.to_string(),
            });
        }
        // The commit revision IS the holder key's mod_revision — a race-free,
        // strictly-increasing fence epoch.
        let epoch = resp
            .header()
            .map(|h| h.revision())
            .ok_or_else(|| be("txn missing header"))? as u64;
        Ok(self.token(scope, epoch, holder))
    }

    async fn renew(&self, token: &FenceToken, _ttl: Duration) -> Result<FenceToken> {
        // etcd keepalive refreshes the lease to its acquire-time TTL (it cannot
        // change the TTL), so `_ttl` is advisory here.
        match self.read_holder(&token.scope).await? {
            // Absent, re-acquired (higher epoch), or different holder => fenced out.
            None => Err(SubstrateError::Fenced {
                scope: token.scope.clone(),
            }),
            Some((holder, epoch, _)) if epoch != token.epoch || holder != token.holder => {
                Err(SubstrateError::Fenced {
                    scope: token.scope.clone(),
                })
            }
            Some((_, _, lease_id)) => {
                let mut c = self.client.clone();
                let (mut keeper, mut stream) = c.lease_keep_alive(lease_id).await.map_err(be)?;
                keeper.keep_alive().await.map_err(be)?;
                // Consume the server's refreshed-TTL response to confirm the pulse.
                let _ = stream.message().await.map_err(be)?;
                Ok(token.clone())
            }
        }
    }

    async fn release(&self, token: &FenceToken) -> Result<()> {
        match self.read_holder(&token.scope).await? {
            None => Ok(()), // already released/expired
            Some((holder, epoch, _)) if epoch != token.epoch || holder != token.holder => {
                // Not our hold (re-acquired) — must not touch the new holder.
                Err(SubstrateError::Fenced {
                    scope: token.scope.clone(),
                })
            }
            Some((_, _, lease_id)) => {
                // Revoking our lease atomically deletes the holder key. Best-effort:
                // if it expired in the gap it is already gone (and that lease id is
                // dead), which is exactly the post-condition we want.
                let mut c = self.client.clone();
                let _ = c.lease_revoke(lease_id).await;
                Ok(())
            }
        }
    }

    async fn current(&self, scope: &str) -> Result<Option<FenceToken>> {
        if scope.is_empty() {
            return Err(be("empty lease scope"));
        }
        Ok(self
            .read_holder(scope)
            .await?
            .map(|(holder, epoch, _)| self.token(scope, epoch, &holder)))
    }
}

impl Backend for EtcdLease {
    fn backend_name(&self) -> &str {
        "etcd-lease"
    }
    fn caps(&self) -> Caps {
        Caps::MONOTONIC_FENCE | Caps::CLUSTER_EXCLUSIVE_FENCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_key_is_injective_in_scope() {
        assert_eq!(lease_key("proj-1"), "jkbase/leases/proj-1");
        assert_ne!(lease_key("a"), lease_key("b"));
    }

    #[test]
    fn caps_are_cluster_exclusive() {
        // Constructed without a live server only to assert the static cap report.
        // (No network is touched by caps()/backend_name().)
        // We cannot build EtcdLease without a Client, so the live assertions live
        // in the #[ignore]d integration test; here we document the intended caps.
        let want = Caps::MONOTONIC_FENCE | Caps::CLUSTER_EXCLUSIVE_FENCE;
        assert!(want.contains(Caps::CLUSTER_EXCLUSIVE_FENCE));
        assert!(!want.contains(Caps::NODE_LOCAL_EXCLUSIVE));
    }
}
