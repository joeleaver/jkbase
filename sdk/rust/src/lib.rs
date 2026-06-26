//! A lean, tenant-facing Rust client for the jkbase S3-compatible object store
//! (`storage.{domain}`).
//!
//! It signs every request with SigV4 via the shared [`jkbase-sigv4`] crate — the *same*
//! canonicalisation the server verifies — so a tenant app can read and write its buckets
//! without pulling in an AWS SDK or the jkbase server surface. Dependencies are just
//! `reqwest` + the tiny signer.
//!
//! ```no_run
//! # async fn demo() -> Result<(), jkbase_objectstore_client::Error> {
//! use jkbase_objectstore_client::ObjectClient;
//!
//! let s3 = ObjectClient::new("https://storage.jkbase.app", "JKBA…", "secret…");
//! s3.create_bucket("assets").await?;
//! s3.put_object("assets", "hello.txt", "hi".as_bytes().to_vec(), "text/plain").await?;
//! let body = s3.get_object_bytes("assets", "hello.txt").await?;
//! assert_eq!(&body[..], b"hi");
//! # Ok(()) }
//! ```
//!
//! ## Advanced: the `aws-sdk-s3` escape hatch
//!
//! The service is S3-compatible (path-style, static access keys), so for advanced needs
//! you can point the AWS Rust SDK at it instead — see `README.md`. This crate exists for
//! the lean, zero-AWS-dep happy path.

mod buckets;
mod error;
mod list;
mod multipart;
mod objects;
mod presign;
mod xml;

pub use error::{Error, Result, S3ErrorCode};
pub use list::{ListObjectsOptions, ListPage, ObjectEntry};
pub use multipart::{MultipartUpload, PendingUpload};
pub use objects::{GetObject, ObjectMeta};

use bytes::Bytes;
use reqwest::Method;
use std::time::{SystemTime, UNIX_EPOCH};

/// How the request body is bound into the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadMode {
    /// `UNSIGNED-PAYLOAD` — the body is not hashed into the signature. The default, and
    /// the only option for streaming bodies (hashing a stream would force buffering).
    Unsigned,
    /// Bind an in-memory body to a SHA-256 in `x-amz-content-sha256` (the server verifies
    /// it). Silently falls back to `Unsigned` for streaming uploads.
    Signed,
}

/// A signed object-store client bound to one set of credentials + endpoint. Cheap to
/// clone where you need to (it holds a connection-pooling [`reqwest::Client`]).
#[derive(Clone)]
pub struct ObjectClient {
    base_url: String,
    host: String,
    access_key: String,
    secret: String,
    region: String,
    payload_mode: PayloadMode,
    http: reqwest::Client,
}

impl ObjectClient {
    /// A client for `base_url` (e.g. `https://storage.jkbase.app`) with region
    /// `us-east-1`. The access key/secret are the tenant's issued object-store credentials.
    pub fn new(
        base_url: impl Into<String>,
        access_key: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        Self::with_region(base_url, access_key, secret, "us-east-1")
    }

    /// Like [`new`](Self::new) but with an explicit region (the server signs/verifies in a
    /// single region; `us-east-1` unless your deployment says otherwise).
    pub fn with_region(
        base_url: impl Into<String>,
        access_key: impl Into<String>,
        secret: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let host = authority(&base_url);
        Self {
            base_url,
            host,
            access_key: access_key.into(),
            secret: secret.into(),
            region: region.into(),
            payload_mode: PayloadMode::Unsigned,
            http: reqwest::Client::new(),
        }
    }

    /// Bind in-memory uploads to a payload SHA-256 (`x-amz-content-sha256`) so the server
    /// rejects a body that doesn't match what was signed. Streaming uploads stay unsigned.
    pub fn with_payload_signing(mut self, on: bool) -> Self {
        self.payload_mode = if on {
            PayloadMode::Signed
        } else {
            PayloadMode::Unsigned
        };
        self
    }

    /// Supply a pre-configured [`reqwest::Client`] (custom timeouts, proxy, pool limits).
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// The endpoint base URL (no trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // ---- shared request core (used by the per-concern modules) ---------------

    /// Sign and send one request. `path` is the RAW (unencoded) request path
    /// (`/{bucket}/{key}`); query keys/values are raw too. Both are percent-encoded with
    /// the *same* encoder the signature uses, so the bytes on the wire are exactly what
    /// was signed (for any key — spaces, `%`, unicode). A non-2xx response becomes a typed
    /// [`Error::Api`].
    pub(crate) async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        content_type: Option<&str>,
        body: ReqBody,
    ) -> Result<reqwest::Response> {
        // Only an in-memory body can be hashed; streams (and Unsigned mode) go unsigned.
        let payload_hash = match (self.payload_mode, &body) {
            (PayloadMode::Signed, ReqBody::Bytes(b)) => jkbase_sigv4::sha256_hex(b),
            _ => "UNSIGNED-PAYLOAD".to_string(),
        };
        let (authorization, amz_date) = jkbase_sigv4::sign_header(
            method.as_str(),
            &self.host,
            path,
            query,
            &payload_hash,
            &self.access_key,
            &self.secret,
            &self.region,
            now_unix(),
        );
        let url = self.build_url(path, query);
        let mut rb = self
            .http
            .request(method, url)
            .header("authorization", authorization)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_hash);
        if let Some(ct) = content_type {
            rb = rb.header(reqwest::header::CONTENT_TYPE, ct);
        }
        rb = match body {
            ReqBody::Empty => rb,
            // A buffered body has a known length, so reqwest sets Content-Length itself.
            ReqBody::Bytes(b) => rb.body(b),
            // A streamed body goes out chunked with no Content-Length; the server REQUIRES a
            // declared length for object writes (411 MissingContentLength otherwise), so we
            // pass it via x-amz-decoded-content-length (not a signed header, so it doesn't
            // affect the signature). It also bounds the server-side write/quota deadline.
            ReqBody::Stream(b, len) => rb
                .header("x-amz-decoded-content-length", len.to_string())
                .body(b),
        };
        let resp = rb.send().await?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            // The engine's error bodies are tiny; parse_api_error caps the fallback message.
            let body = resp.text().await.unwrap_or_default();
            Err(error::parse_api_error(status, &body))
        }
    }

    /// Build the on-the-wire URL with the path percent-encoded (slashes intact) and query
    /// keys/values encoded, using the signer's encoder so it matches the signature.
    fn build_url(&self, path: &str, query: &[(String, String)]) -> String {
        let mut url = format!("{}{}", self.base_url, jkbase_sigv4::uri_encode(path, false));
        if !query.is_empty() {
            url.push('?');
            let qs = query
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}={}",
                        jkbase_sigv4::uri_encode(k, true),
                        jkbase_sigv4::uri_encode(v, true)
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            url.push_str(&qs);
        }
        url
    }

    // Accessors the presign module needs (it signs URLs without sending).
    pub(crate) fn host(&self) -> &str {
        &self.host
    }
    pub(crate) fn access_key(&self) -> &str {
        &self.access_key
    }
    pub(crate) fn secret(&self) -> &str {
        &self.secret
    }
    pub(crate) fn region(&self) -> &str {
        &self.region
    }
}

/// The body of a request. A streamed body carries its declared length (the server
/// requires one for object writes).
pub(crate) enum ReqBody {
    Empty,
    Bytes(Bytes),
    Stream(reqwest::Body, u64),
}

/// `/{bucket}/{key}` — the raw object path (encoding happens at send time).
pub(crate) fn object_path(bucket: &str, key: &str) -> String {
    format!("/{bucket}/{key}")
}

/// Reject keys with a `.` or `..` path segment. HTTP clients (the `url` crate reqwest
/// uses, browsers, curl) resolve dot-segments before sending, so the bytes on the wire
/// would diverge from the signed canonical path — a silent AccessDenied or wrong-object.
/// Every other byte sequence (spaces, `%`, `&`, unicode, empty segments) is percent-encoded
/// correctly and round-trips, so only bare dot segments are refused.
pub(crate) fn validate_object_key(key: &str) -> Result<()> {
    if key.is_empty() {
        // An empty key makes the path `/{bucket}/`, which the server routes as a
        // bucket-level op, not an object write — reject it with a clear error.
        return Err(Error::InvalidKey("object key must not be empty".into()));
    }
    if key.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(Error::InvalidKey(format!(
            "{key:?} has a '.' or '..' path segment that HTTP clients normalize away (signed and sent paths would differ)"
        )));
    }
    Ok(())
}

/// Current unix time in seconds (for SigV4 `x-amz-date`).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `host[:port]` from a `scheme://host[:port]/…` base URL — the SigV4 `Host`.
fn authority(base_url: &str) -> String {
    base_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base_url)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_strips_scheme_and_path() {
        assert_eq!(
            authority("https://storage.jkbase.app"),
            "storage.jkbase.app"
        );
        assert_eq!(
            authority("https://storage.jkbase.app:443/foo"),
            "storage.jkbase.app:443"
        );
        assert_eq!(authority("http://127.0.0.1:9091"), "127.0.0.1:9091");
    }

    #[test]
    fn build_url_encodes_path_and_query() {
        let c = ObjectClient::new("https://h.test/", "AK", "SK");
        assert_eq!(c.base_url(), "https://h.test"); // trailing slash trimmed
        // Space in key -> %20; slashes preserved as separators.
        let u = c.build_url("/b/dir/a b", &[("prefix".into(), "x/y".into())]);
        assert_eq!(u, "https://h.test/b/dir/a%20b?prefix=x%2Fy");
    }

    /// The client must reproduce the SAME presigned signature pinned in the JS SDK test
    /// (sdk/js/objectstore.test.mjs) and the jkbase-sigv4 cross_vector — proving the
    /// client wires host/path/credential into the shared signer identically, so a
    /// client-signed request verifies server-side.
    #[test]
    fn presign_matches_the_shared_cross_vector() {
        const NOW: u64 = 1_700_000_000;
        let c = ObjectClient::with_region("http://s3.test", "AKID", "SECRET", "us-east-1");
        let url = c.presigned_at("GET", "b", "k", 900, NOW);
        assert!(url.starts_with("http://s3.test/b/k?"), "{url}");
        assert!(
            url.ends_with(
                "X-Amz-Signature=67dfd03db2009a8216e3779a68cb239b0ba9579b44c4b3fe168cd0b0bab28614"
            ),
            "{url}"
        );
    }
}
