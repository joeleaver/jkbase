//! [`FlockLease`] — a node-local [`Lease`] backend built on advisory file locks
//! (`std::fs::File` locking, stable since Rust 1.89) plus a persisted monotonic
//! epoch per scope.
//!
//! Exclusivity is **host-local only** — advisory locks don't cross hosts — so this
//! advertises [`Caps::NODE_LOCAL_EXCLUSIVE`], never [`Caps::CLUSTER_EXCLUSIVE_FENCE`];
//! the `build_substrate` factory refuses it as the sole fence in a multi-node
//! cluster. Liveness is implicit: the lock is held only while the holding process
//! keeps the file open, so a crashed holder is automatically released by the OS and
//! the next acquirer wins with a strictly higher epoch.

use crate::{Backend, Caps, FenceToken, Lease, Result, SubstrateError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// A node-local lease authority. Each held scope keeps a locked file open; the
/// monotonic epoch is persisted next to it so it survives restarts.
pub struct FlockLease {
    dir: PathBuf,
    source_id: String,
    held: Mutex<HashMap<String, Held>>,
}

struct Held {
    /// Kept open to hold the advisory lock; dropping it releases the lock.
    _lock: File,
    token: FenceToken,
}

impl FlockLease {
    /// Open a lease authority rooted at `dir` (created if absent), identified by
    /// `source_id` (this node's stable id, stamped into every token's `source_id`).
    pub fn open(dir: impl AsRef<Path>, source_id: impl Into<String>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            source_id: source_id.into(),
            held: Mutex::new(HashMap::new()),
        })
    }

    fn lock_path(&self, scope: &str) -> PathBuf {
        self.dir.join(format!("{scope}.lock"))
    }
    fn epoch_path(&self, scope: &str) -> PathBuf {
        self.dir.join(format!("{scope}.epoch"))
    }
    fn token_path(&self, scope: &str) -> PathBuf {
        self.dir.join(format!("{scope}.holder"))
    }

    fn read_epoch(&self, scope: &str) -> u64 {
        std::fs::read_to_string(self.epoch_path(scope))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Reconstruct the persisted token of the current holder, if recorded.
    fn read_token(&self, scope: &str) -> Option<FenceToken> {
        let body = std::fs::read_to_string(self.token_path(scope)).ok()?;
        let mut lines = body.lines();
        let epoch = lines.next()?.trim().parse().ok()?;
        let holder = lines.next()?.to_string();
        let source_id = lines.next()?.to_string();
        Some(FenceToken {
            scope: scope.to_string(),
            epoch,
            holder,
            source_id,
        })
    }

    fn open_lock_file(&self, scope: &str) -> Result<File> {
        Ok(OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(self.lock_path(scope))?)
    }
}

/// Scopes become filenames, so reject anything that isn't a plain id (no path
/// separators / traversal) — a sanitizing transform could collide two scopes onto
/// one lock, which for a lease is silent loss of exclusivity.
fn validate_scope(scope: &str) -> Result<()> {
    let ok = !scope.is_empty()
        && scope != "."
        && scope != ".."
        && scope
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(SubstrateError::Backend(format!(
            "invalid lease scope {scope:?} (must be a plain id)"
        )))
    }
}

#[async_trait]
impl Lease for FlockLease {
    async fn acquire(&self, scope: &str, holder: &str, _ttl: Duration) -> Result<FenceToken> {
        validate_scope(scope)?;
        let lock_file = self.open_lock_file(scope)?;
        // Take the advisory lock. A live holder (this host) blocks; a crashed
        // holder's lock was already released by the OS, so we win.
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(SubstrateError::LeaseHeld {
                    scope: scope.to_string(),
                });
            }
            Err(TryLockError::Error(e)) => return Err(SubstrateError::Io(e)),
        }
        // Bump the persisted, monotonic-per-source epoch under the lock.
        let epoch = self.read_epoch(scope) + 1;
        std::fs::write(self.epoch_path(scope), epoch.to_string())?;
        let token = FenceToken {
            scope: scope.to_string(),
            epoch,
            holder: holder.to_string(),
            source_id: self.source_id.clone(),
        };
        std::fs::write(
            self.token_path(scope),
            format!("{}\n{}\n{}", token.epoch, token.holder, token.source_id),
        )?;
        self.held.lock().unwrap().insert(
            scope.to_string(),
            Held {
                _lock: lock_file,
                token: token.clone(),
            },
        );
        Ok(token)
    }

    async fn renew(&self, token: &FenceToken, _ttl: Duration) -> Result<FenceToken> {
        // The advisory lock is held continuously, so renewal is just a liveness
        // re-assertion: succeed iff we still hold exactly this token.
        match self.held.lock().unwrap().get(&token.scope) {
            Some(h) if &h.token == token => Ok(h.token.clone()),
            _ => Err(SubstrateError::Fenced {
                scope: token.scope.clone(),
            }),
        }
    }

    async fn release(&self, token: &FenceToken) -> Result<()> {
        let mut held = self.held.lock().unwrap();
        match held.get(&token.scope) {
            Some(h) if &h.token != token => {
                return Err(SubstrateError::Fenced {
                    scope: token.scope.clone(),
                });
            }
            _ => {}
        }
        // Drop the entry -> closes the File -> releases the advisory lock. Keep the
        // .epoch file (monotonic across acquisitions); clear the holder record.
        held.remove(&token.scope);
        let _ = std::fs::remove_file(self.token_path(&token.scope));
        Ok(())
    }

    async fn current(&self, scope: &str) -> Result<Option<FenceToken>> {
        validate_scope(scope)?;
        if let Some(h) = self.held.lock().unwrap().get(scope) {
            return Ok(Some(h.token.clone()));
        }
        // Not ours: probe the lock. If we can take it, it is free.
        let lock_file = self.open_lock_file(scope)?;
        match lock_file.try_lock() {
            Ok(()) => {
                let _ = lock_file.unlock();
                Ok(None)
            }
            Err(TryLockError::WouldBlock) => Ok(self.read_token(scope)),
            Err(TryLockError::Error(e)) => Err(SubstrateError::Io(e)),
        }
    }
}

impl Backend for FlockLease {
    fn backend_name(&self) -> &str {
        "flock"
    }
    fn caps(&self) -> Caps {
        Caps::MONOTONIC_FENCE | Caps::NODE_LOCAL_EXCLUSIVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-flock-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[tokio::test]
    async fn epochs_are_monotonic_across_acquire_release() {
        let l = FlockLease::open(tmp("mono"), "node-a").unwrap();
        let t1 = l.acquire("proj", "h1", Duration::from_secs(30)).await.unwrap();
        assert_eq!(t1.epoch, 1);
        assert_eq!(t1.source_id, "node-a");
        l.release(&t1).await.unwrap();
        let t2 = l.acquire("proj", "h2", Duration::from_secs(30)).await.unwrap();
        assert_eq!(t2.epoch, 2);
        assert!(t2.supersedes(&t1).unwrap());
    }

    #[tokio::test]
    async fn second_acquire_while_held_is_rejected() {
        let l = FlockLease::open(tmp("held"), "node-a").unwrap();
        let _t = l.acquire("p", "h1", Duration::from_secs(30)).await.unwrap();
        let err = l.acquire("p", "h2", Duration::from_secs(30)).await.unwrap_err();
        assert!(matches!(err, SubstrateError::LeaseHeld { .. }));
    }

    #[tokio::test]
    async fn renew_honors_token_identity() {
        let l = FlockLease::open(tmp("renew"), "node-a").unwrap();
        let t = l.acquire("p", "h", Duration::from_secs(30)).await.unwrap();
        assert!(l.renew(&t, Duration::from_secs(30)).await.is_ok());
        l.release(&t).await.unwrap();
        // A stale token can no longer be renewed.
        assert!(matches!(
            l.renew(&t, Duration::from_secs(30)).await,
            Err(SubstrateError::Fenced { .. })
        ));
    }

    #[tokio::test]
    async fn current_reports_holder_then_free() {
        let l = FlockLease::open(tmp("current"), "node-a").unwrap();
        assert!(l.current("p").await.unwrap().is_none());
        let t = l.acquire("p", "holder-x", Duration::from_secs(30)).await.unwrap();
        let cur = l.current("p").await.unwrap().unwrap();
        assert_eq!(cur.epoch, t.epoch);
        assert_eq!(cur.holder, "holder-x");
        l.release(&t).await.unwrap();
        assert!(l.current("p").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn advertises_node_local_fence_caps() {
        let l = FlockLease::open(tmp("caps"), "n").unwrap();
        assert!(l.caps().contains(Caps::MONOTONIC_FENCE | Caps::NODE_LOCAL_EXCLUSIVE));
        assert!(!l.caps().contains(Caps::CLUSTER_EXCLUSIVE_FENCE));
        assert_eq!(l.backend_name(), "flock");
    }
}
