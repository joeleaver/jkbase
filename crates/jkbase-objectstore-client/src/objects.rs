//! Object operations: put (buffered + streaming), get (buffered + streaming), head, delete.

use crate::xml::strip_quotes;
use crate::{Error, ObjectClient, ReqBody, Result, object_path};
use bytes::Bytes;
use reqwest::{Method, header};

/// Object metadata read from response headers.
#[derive(Debug, Clone, Default)]
pub struct ObjectMeta {
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    /// The raw hex MD5 ETag (surrounding quotes stripped).
    pub etag: Option<String>,
    /// The `Last-Modified` HTTP-date, verbatim.
    pub last_modified: Option<String>,
}

/// A streamed GET response: metadata up front, body consumed on demand.
#[derive(Debug)]
pub struct GetObject {
    pub meta: ObjectMeta,
    resp: reqwest::Response,
}

impl GetObject {
    /// Metadata from the response headers.
    pub fn meta(&self) -> &ObjectMeta {
        &self.meta
    }

    /// Buffer the whole body into memory.
    pub async fn bytes(self) -> Result<Bytes> {
        Ok(self.resp.bytes().await?)
    }

    /// Stream the body in chunks without buffering it all — for large objects.
    ///
    /// ```no_run
    /// # async fn d(g: jkbase_objectstore_client::GetObject) -> Result<(), jkbase_objectstore_client::Error> {
    /// use futures_util::StreamExt;
    /// let mut s = g.into_stream();
    /// while let Some(chunk) = s.next().await { let _bytes = chunk?; }
    /// # Ok(()) }
    /// ```
    pub fn into_stream(self) -> impl futures_util::Stream<Item = Result<Bytes>> {
        use futures_util::TryStreamExt;
        self.resp.bytes_stream().map_err(Error::from)
    }
}

impl ObjectClient {
    /// Upload an in-memory object; returns the raw hex MD5 ETag. With payload signing on,
    /// the body is bound to its SHA-256.
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: impl Into<Bytes>,
        content_type: &str,
    ) -> Result<String> {
        let resp = self
            .send(Method::PUT, &object_path(bucket, key), &[], Some(content_type), ReqBody::Bytes(body.into()))
            .await?;
        Ok(etag_of(resp.headers()))
    }

    /// Upload an object by streaming a body (e.g. `reqwest::Body::wrap_stream(..)` or a
    /// file) without buffering it. Always uses `UNSIGNED-PAYLOAD` (a stream can't be
    /// hashed without buffering). Returns the ETag.
    pub async fn put_object_stream(
        &self,
        bucket: &str,
        key: &str,
        body: impl Into<reqwest::Body>,
        content_type: &str,
    ) -> Result<String> {
        let resp = self
            .send(Method::PUT, &object_path(bucket, key), &[], Some(content_type), ReqBody::Stream(body.into()))
            .await?;
        Ok(etag_of(resp.headers()))
    }

    /// Fetch an object as a streamed [`GetObject`] (metadata immediately; body on demand).
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<GetObject> {
        let resp = self.send(Method::GET, &object_path(bucket, key), &[], None, ReqBody::Empty).await?;
        let meta = meta_of(resp.headers());
        Ok(GetObject { meta, resp })
    }

    /// Convenience: fetch an object fully into memory.
    pub async fn get_object_bytes(&self, bucket: &str, key: &str) -> Result<Bytes> {
        self.get_object(bucket, key).await?.bytes().await
    }

    /// Metadata-only fetch (HEAD). `Err(..).is_not_found()` for a missing key.
    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta> {
        let resp = self.send(Method::HEAD, &object_path(bucket, key), &[], None, ReqBody::Empty).await?;
        Ok(meta_of(resp.headers()))
    }

    /// Delete an object. Idempotent server-side (deleting a missing key is not an error
    /// the engine raises).
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.send(Method::DELETE, &object_path(bucket, key), &[], None, ReqBody::Empty).await?;
        Ok(())
    }
}

/// The ETag header, quotes stripped, or empty if absent.
pub(crate) fn etag_of(h: &header::HeaderMap) -> String {
    h.get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(strip_quotes)
        .unwrap_or_default()
}

fn meta_of(h: &header::HeaderMap) -> ObjectMeta {
    let str_of = |name: &header::HeaderName| h.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    ObjectMeta {
        content_type: str_of(&header::CONTENT_TYPE),
        content_length: h
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok()),
        etag: h.get(header::ETAG).and_then(|v| v.to_str().ok()).map(strip_quotes),
        last_modified: str_of(&header::LAST_MODIFIED),
    }
}
