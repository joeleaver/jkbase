//! [`LocalFsBlobStore`] — a [`BlobStore`] over the local filesystem. Every object
//! is moved through a **bounded-buffer streaming copy** (`tokio::io::copy`), so a
//! multi-GiB snapshot/image/layer never lands wholly in memory (preserving the
//! OOM fixes). Writes are atomic: `put_file` streams to a temp sibling then
//! `rename`s over the target; `put_if_absent_file` `hard_link`s the temp into
//! place, which fails iff the key already exists — the primitive content-addressed
//! dedup relies on. This backend takes **no cloud dependency**; the S3 backend
//! (`object_store`) is a separate card.

use crate::{Backend, BlobMeta, BlobStore, Caps, Result, SubstrateError};
use async_trait::async_trait;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct LocalFsBlobStore {
    root: PathBuf,
}

impl LocalFsBlobStore {
    /// Open (creating if absent) a blob store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Resolve `key` under root, rejecting absolute paths and any `.`/`..`
    /// traversal so a key can never escape the store.
    fn resolve(&self, key: &str) -> Result<PathBuf> {
        let rel = Path::new(key);
        let safe = !key.is_empty()
            && rel
                .components()
                .all(|c| matches!(c, Component::Normal(_)));
        if !safe {
            return Err(SubstrateError::Backend(format!(
                "invalid blob key {key:?} (must be a relative path with no traversal)"
            )));
        }
        Ok(self.root.join(rel))
    }

    /// A unique temp sibling of `dest` on the same filesystem (so rename/hard_link
    /// stay atomic). pid + an atomic counter — no RNG needed.
    fn tmp_sibling(dest: &Path) -> PathBuf {
        let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let mut name = dest.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".tmp.{pid}.{n}"));
        dest.with_file_name(name)
    }
}

/// Stream `src` → `dst` in bounded chunks; never reads the whole file into memory.
async fn stream_copy(src: &Path, dst: &Path) -> Result<()> {
    let mut r = tokio::fs::File::open(src).await?;
    let mut w = tokio::fs::File::create(dst).await?;
    tokio::io::copy(&mut r, &mut w).await?;
    w.sync_all().await?;
    Ok(())
}

#[async_trait]
impl BlobStore for LocalFsBlobStore {
    async fn put_file(&self, key: &str, src: &Path) -> Result<()> {
        let dest = self.resolve(key)?;
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = Self::tmp_sibling(&dest);
        if let Err(e) = stream_copy(src, &tmp).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        match tokio::fs::rename(&tmp, &dest).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(e.into())
            }
        }
    }

    async fn put_if_absent_file(&self, key: &str, src: &Path) -> Result<bool> {
        let dest = self.resolve(key)?;
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = Self::tmp_sibling(&dest);
        if let Err(e) = stream_copy(src, &tmp).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        // hard_link is the atomic "create iff absent": it fails AlreadyExists if
        // `dest` is taken. The temp is always cleaned up afterwards.
        let linked = tokio::fs::hard_link(&tmp, &dest).await;
        let _ = tokio::fs::remove_file(&tmp).await;
        match linked {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_to_file(&self, key: &str, dst: &Path) -> Result<()> {
        let src = self.resolve(key)?;
        if !tokio::fs::try_exists(&src).await.unwrap_or(false) {
            return Err(SubstrateError::NotFound(key.to_string()));
        }
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        stream_copy(&src, dst).await
    }

    async fn head(&self, key: &str) -> Result<Option<BlobMeta>> {
        let p = self.resolve(key)?;
        match tokio::fs::metadata(&p).await {
            Ok(md) => Ok(Some(BlobMeta {
                key: key.to_string(),
                size: md.len(),
                etag: None,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = match tokio::fs::read_dir(&dir).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = rd.next_entry().await? {
                let ft = entry.file_type().await?;
                let path = entry.path();
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file()
                    && let Ok(rel) = path.strip_prefix(&self.root)
                {
                    let key = rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                    // Skip in-flight temp siblings; surface only committed objects.
                    if !key.contains(".tmp.") && key.starts_with(prefix) {
                        out.push(key);
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let p = self.resolve(key)?;
        match tokio::fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            // Idempotent: absent is success (the post-condition "key is gone" holds).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl Backend for LocalFsBlobStore {
    fn backend_name(&self) -> &str {
        "localfs"
    }
    fn caps(&self) -> Caps {
        // hard_link gives a genuinely atomic create-if-absent.
        Caps::ATOMIC_PUT_IF_ABSENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-blob-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    async fn write(path: &Path, bytes: &[u8]) {
        if let Some(p) = path.parent() {
            tokio::fs::create_dir_all(p).await.unwrap();
        }
        tokio::fs::write(path, bytes).await.unwrap();
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let base = tmp("rt");
        let bs = LocalFsBlobStore::open(base.join("store")).unwrap();
        let src = base.join("src.bin");
        write(&src, b"hello-blob").await;
        bs.put_file("a/b/c.bin", &src).await.unwrap();
        let dst = base.join("out.bin");
        bs.get_to_file("a/b/c.bin", &dst).await.unwrap();
        assert_eq!(tokio::fs::read(&dst).await.unwrap(), b"hello-blob");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn put_if_absent_does_not_overwrite() {
        let base = tmp("absent");
        let bs = LocalFsBlobStore::open(base.join("store")).unwrap();
        let s1 = base.join("s1");
        let s2 = base.join("s2");
        write(&s1, b"first").await;
        write(&s2, b"second").await;
        assert!(bs.put_if_absent_file("k", &s1).await.unwrap()); // written
        assert!(!bs.put_if_absent_file("k", &s2).await.unwrap()); // already present
        let dst = base.join("o");
        bs.get_to_file("k", &dst).await.unwrap();
        assert_eq!(tokio::fs::read(&dst).await.unwrap(), b"first"); // unchanged
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn head_and_list_and_traversal() {
        let base = tmp("hl");
        let bs = LocalFsBlobStore::open(base.join("store")).unwrap();
        let src = base.join("src");
        write(&src, b"12345").await;
        bs.put_file("layers/x", &src).await.unwrap();
        bs.put_file("layers/y", &src).await.unwrap();
        bs.put_file("other/z", &src).await.unwrap();

        let meta = bs.head("layers/x").await.unwrap().unwrap();
        assert_eq!(meta.size, 5);
        assert!(bs.head("nope").await.unwrap().is_none());

        let mut listed = bs.list("layers/").await.unwrap();
        listed.sort();
        assert_eq!(listed, vec!["layers/x".to_string(), "layers/y".to_string()]);

        assert!(matches!(
            bs.put_file("../escape", &src).await,
            Err(SubstrateError::Backend(_))
        ));
        assert!(matches!(
            bs.get_to_file("nope", &base.join("o")).await,
            Err(SubstrateError::NotFound(_))
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn delete_removes_and_is_idempotent() {
        let base = tmp("del");
        let bs = LocalFsBlobStore::open(base.join("store")).unwrap();
        let src = base.join("src");
        write(&src, b"bytes").await;
        bs.put_file("a/b.bin", &src).await.unwrap();
        assert!(bs.head("a/b.bin").await.unwrap().is_some());
        bs.delete("a/b.bin").await.unwrap();
        assert!(bs.head("a/b.bin").await.unwrap().is_none());
        // Idempotent: deleting an absent key is success, not an error.
        bs.delete("a/b.bin").await.unwrap();
        bs.delete("never/existed").await.unwrap();
        // Traversal is still rejected.
        assert!(matches!(
            bs.delete("../escape").await,
            Err(SubstrateError::Backend(_))
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn advertises_atomic_put_caps() {
        let bs = LocalFsBlobStore::open(tmp("caps").join("s")).unwrap();
        assert!(bs.caps().contains(Caps::ATOMIC_PUT_IF_ABSENT));
        assert_eq!(bs.backend_name(), "localfs");
    }
}
