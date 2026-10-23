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
///
/// A segment becomes visible by `link(tmp, dst)` — which, unlike rename, never replaces
/// an existing segment — followed by an fsync of its directory, so a segment the index
/// references after a power loss is still there. Writes are refused once the directory
/// is no longer the one this handle opened (the project was deleted, maybe recreated):
/// bytes never land in another incarnation's store, unreferenced and billed to it.
pub struct LocalSegments {
    dir: PathBuf,
    ident: FileIdent,
}

impl LocalSegments {
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let tmp = dir.join(".tmp");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let ident = file_ident(&dir)?;
        Ok(Self { dir, ident })
    }

    fn check_live(&self) -> io::Result<()> {
        if file_ident(&self.dir).ok() == Some(self.ident) {
            Ok(())
        } else {
            Err(io::Error::other("object store root was replaced"))
        }
    }

    /// Blocking hard link of `src` as segment `id`, for the migration that runs inside
    /// `open`. Returns the directory it landed in, which the caller fsyncs (once per
    /// batch) before committing the rows that reference it.
    pub(crate) fn link_blocking(&self, id: &str, src: &Path) -> io::Result<PathBuf> {
        let dst = self.path(id)?;
        let fan = dst
            .parent()
            .expect("segment paths have a fan directory")
            .to_path_buf();
        if !fan.exists() {
            std::fs::create_dir_all(&fan)?;
            sync_dir_blocking(&self.dir)?;
        }
        std::fs::hard_link(src, &dst)?;
        Ok(fan)
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
        self.check_live()?;
        let dst = self.path(id)?;
        let tmp = self.dir.join(".tmp").join(id);
        let file = tokio::fs::File::create(&tmp).await?;
        Ok(Box::new(LocalWriter {
            file,
            tmp,
            dst,
            dir: self.dir.clone(),
            ident: self.ident,
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

    /// The unlink is fsynced before returning: the index forgets the segment next, and an
    /// unlink a crash undid would leave a file nothing references (billed, never reclaimed).
    async fn delete(&self, id: &str) -> io::Result<()> {
        let path = self.path(id)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => sync_dir(path.parent().expect("segment paths have a fan directory")).await,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// A hard link: the legacy file and the segment are one inode, so migration moves no
    /// bytes and never needs twice the space. Both live under the project root.
    async fn import_file(&self, id: &str, src: &Path) -> io::Result<()> {
        self.check_live()?;
        let fan = self.link_blocking(id, src)?;
        sync_dir(&fan).await
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
    dir: PathBuf,
    ident: FileIdent,
    done: bool,
}

#[async_trait]
impl SegmentWriter for LocalWriter {
    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf).await
    }

    async fn commit(mut self: Box<Self>) -> io::Result<()> {
        self.file.sync_all().await?;
        if file_ident(&self.dir).ok() != Some(self.ident) {
            return Err(io::Error::other("object store root was replaced"));
        }
        let fan = self
            .dst
            .parent()
            .expect("segment paths have a fan directory")
            .to_path_buf();
        if tokio::fs::metadata(&fan).await.is_err() {
            tokio::fs::create_dir_all(&fan).await?;
            sync_dir(&self.dir).await?;
        }
        // EEXIST rather than replace if an id ever repeated.
        tokio::fs::hard_link(&self.tmp, &self.dst).await?;
        let _ = tokio::fs::remove_file(&self.tmp).await;
        self.done = true;
        sync_dir(&fan).await
    }
}

impl Drop for LocalWriter {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Which file (or directory) a path names: `(dev, inode, birth time)`. The inode alone
/// isn't enough — ext4 reuses inode numbers, so a root deleted and recreated could get
/// its old number back; the birth time (statx) tells the two incarnations apart.
pub(crate) type FileIdent = (u64, u64, u128);

pub(crate) fn file_ident(p: &Path) -> io::Result<FileIdent> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(p)?;
    let born = m
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    Ok((m.dev(), m.ino(), born))
}

/// fsync a directory so the entries just created in it survive a power loss.
pub(crate) fn sync_dir_blocking(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

async fn sync_dir(dir: &Path) -> io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || sync_dir_blocking(&dir))
        .await
        .map_err(io::Error::other)?
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
