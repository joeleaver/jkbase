//! The byte half of the object store: immutable segments addressed by an id the engine
//! mints. A [`SegmentStore`] never sees a bucket, a key or anything else a tenant chose —
//! only ids — so no tenant input can reach a filesystem path or a remote object name.
//! Which segments make up an object (and whether a segment is still reachable) is the
//! index's business ([`crate::index`]); this layer just stores bytes.
//!
//! Backends: [`LocalSegments`] today; a remote S3-compatible backend is step 2 of
//! `docs/storage-scale-out-design.md`. Ids are random per write, never content hashes:
//! a shared content address would be a cross-tenant existence oracle.

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::Stream;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

/// A streamed body: a segment range, or an object stitched from several.
pub type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

/// Immutable byte blobs by engine-minted id.
#[async_trait]
pub trait SegmentStore: Send + Sync {
    /// Stable backend name for logs.
    fn backend_name(&self) -> &str;
    /// Start writing segment `id`. Nothing is readable under `id` until
    /// [`SegmentWriter::commit`] returns.
    async fn create(&self, id: &str) -> io::Result<Box<dyn SegmentWriter>>;
    /// Stream bytes `[offset, offset + len)` of `id`. Errors (rather than returning a
    /// short stream) if the segment holds fewer bytes than that: the caller has already
    /// promised the client a length.
    async fn read(&self, id: &str, offset: u64, len: u64) -> io::Result<ByteStream>;
    /// Remove `id`. Idempotent.
    async fn delete(&self, id: &str) -> io::Result<()>;
    /// Adopt an existing local file as segment `id` (legacy-layout migration). The
    /// default streams it through [`create`](Self::create); a local backend links it.
    async fn import_file(&self, id: &str, src: &Path) -> io::Result<()> {
        let mut f = tokio::fs::File::open(src).await?;
        let mut w = self.create(id).await?;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            w.write(&buf[..n]).await?;
        }
        w.commit().await
    }
}

/// An in-progress segment write. Dropping it without [`commit`](Self::commit) discards it.
#[async_trait]
pub trait SegmentWriter: Send {
    async fn write(&mut self, buf: &[u8]) -> io::Result<()>;
    /// Make the bytes durable and visible under the writer's id.
    async fn commit(self: Box<Self>) -> io::Result<()>;
}

/// Segments as files under `{root}/.segments/`, fanned out over 256 directories by a
/// hash of the id (ids are time-ordered, so their own leading chars would pile every
/// segment into one directory). In-progress writes live in `.tmp/`, which is emptied on
/// open: anything there belonged to a process that is gone.
pub struct LocalSegments {
    dir: PathBuf,
}

impl LocalSegments {
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let tmp = dir.join(".tmp");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        Ok(Self { dir })
    }

    /// Blocking [`SegmentStore::import_file`], for the migration that runs inside `open`.
    pub(crate) fn link_blocking(&self, id: &str, src: &Path) -> io::Result<()> {
        let dst = self.path(id)?;
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::hard_link(src, &dst)
    }

    fn path(&self, id: &str) -> io::Result<PathBuf> {
        check_id(id)?;
        let fan = &hex(&Sha256::digest(id.as_bytes()))[..2];
        Ok(self.dir.join(fan).join(id))
    }
}

#[async_trait]
impl SegmentStore for LocalSegments {
    fn backend_name(&self) -> &str {
        "local"
    }

    async fn create(&self, id: &str) -> io::Result<Box<dyn SegmentWriter>> {
        let dst = self.path(id)?;
        let tmp = self.dir.join(".tmp").join(id);
        let file = tokio::fs::File::create(&tmp).await?;
        Ok(Box::new(LocalWriter {
            file,
            tmp,
            dst,
            done: false,
        }))
    }

    async fn read(&self, id: &str, offset: u64, len: u64) -> io::Result<ByteStream> {
        let mut f = tokio::fs::File::open(self.path(id)?).await?;
        let have = f.metadata().await?.len();
        if offset.checked_add(len).is_none_or(|end| end > have) {
            return Err(io::Error::other(format!(
                "segment {id} holds {have} bytes, {len} wanted at {offset}"
            )));
        }
        f.seek(io::SeekFrom::Start(offset)).await?;
        Ok(Box::pin(ReaderStream::new(f.take(len))))
    }

    async fn delete(&self, id: &str) -> io::Result<()> {
        match tokio::fs::remove_file(self.path(id)?).await {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// A hard link: the legacy file and the segment are one inode, so migration moves no
    /// bytes and never needs twice the space. Both live under the project root.
    async fn import_file(&self, id: &str, src: &Path) -> io::Result<()> {
        let dst = self.path(id)?;
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::hard_link(src, &dst).await
    }
}

impl LocalSegments {
    #[cfg(test)]
    pub(crate) fn exists(&self, id: &str) -> bool {
        self.path(id).is_ok_and(|p| p.exists())
    }
}

struct LocalWriter {
    file: tokio::fs::File,
    tmp: PathBuf,
    dst: PathBuf,
    done: bool,
}

#[async_trait]
impl SegmentWriter for LocalWriter {
    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf).await
    }

    async fn commit(mut self: Box<Self>) -> io::Result<()> {
        self.file.sync_all().await?;
        if let Some(parent) = self.dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&self.tmp, &self.dst).await?;
        self.done = true;
        Ok(())
    }
}

impl Drop for LocalWriter {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Ids are lowercase hex the engine minted; anything else never reaches a path.
fn check_id(id: &str) -> io::Result<()> {
    if (1..=64).contains(&id.len()) && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(io::Error::other(format!("invalid segment id {id:?}")))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
