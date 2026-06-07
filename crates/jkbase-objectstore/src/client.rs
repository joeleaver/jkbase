//! A minimal Rust client for the jkbase object store (the Rust half of the SDK
//! card). Signs every request with SigV4 (UNSIGNED-PAYLOAD streaming mode) and
//! talks to the S3 HTTP API, so a tenant app can read/write its buckets without
//! pulling a full AWS SDK.

use crate::sigv4;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("server returned {status}: {body}")]
    Status { status: u16, body: String },
}

type Result<T> = std::result::Result<T, ClientError>;

/// A signed client bound to one set of credentials + endpoint.
pub struct ObjectClient {
    base_url: String,
    host: String,
    access_key: String,
    secret: String,
    region: String,
    http: reqwest::Client,
}

impl ObjectClient {
    pub fn new(
        base_url: impl Into<String>,
        access_key: impl Into<String>,
        secret: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        let base_url = base_url.into();
        let host = authority(&base_url);
        Self {
            base_url,
            host,
            access_key: access_key.into(),
            secret: secret.into(),
            region: region.into(),
            http: reqwest::Client::new(),
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(String, String)],
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response> {
        let (auth, amzd) = sigv4::sign_header(
            method.as_str(),
            &self.host,
            path,
            query,
            "UNSIGNED-PAYLOAD",
            &self.access_key,
            &self.secret,
            &self.region,
            now_secs(),
        );
        let url = if query.is_empty() {
            format!("{}{path}", self.base_url)
        } else {
            let qs = query
                .iter()
                .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
                .collect::<Vec<_>>()
                .join("&");
            format!("{}{path}?{qs}", self.base_url)
        };
        let mut rb = self
            .http
            .request(method, url)
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        if let Some(ct) = content_type {
            rb = rb.header("content-type", ct);
        }
        if let Some(b) = body {
            rb = rb.body(b);
        }
        let resp = rb.send().await?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Status { status, body })
        }
    }

    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        self.send(reqwest::Method::PUT, &format!("/{bucket}"), &[], None, Some(Vec::new())).await?;
        Ok(())
    }

    /// Upload an object; returns its (quoted) ETag.
    pub async fn put_object(&self, bucket: &str, key: &str, body: Vec<u8>, content_type: &str) -> Result<String> {
        let resp = self
            .send(reqwest::Method::PUT, &format!("/{bucket}/{key}"), &[], Some(content_type), Some(body))
            .await?;
        Ok(resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string())
    }

    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>> {
        let resp = self.send(reqwest::Method::GET, &format!("/{bucket}/{key}"), &[], None, None).await?;
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.send(reqwest::Method::DELETE, &format!("/{bucket}/{key}"), &[], None, None).await?;
        Ok(())
    }

    /// List object keys under `prefix` (empty = all).
    pub async fn list_objects(&self, bucket: &str, prefix: &str) -> Result<Vec<String>> {
        let query: Vec<(String, String)> = if prefix.is_empty() {
            vec![]
        } else {
            vec![("prefix".to_string(), prefix.to_string())]
        };
        let resp = self.send(reqwest::Method::GET, &format!("/{bucket}"), &query, None, None).await?;
        let xml = resp.text().await?;
        Ok(extract_tags(&xml, "<Key>", "</Key>"))
    }

    /// A presigned GET URL valid for `expires_secs` (no auth header needed to use).
    pub fn presigned_get(&self, bucket: &str, key: &str, expires_secs: u64) -> String {
        let signed = sigv4::presign(
            "GET",
            &self.host,
            &format!("/{bucket}/{key}"),
            &self.access_key,
            &self.secret,
            &self.region,
            expires_secs,
            now_secs(),
        );
        format!("{}{signed}", self.base_url)
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// host[:port] from a `scheme://host[:port]/...` base URL (for the SigV4 Host).
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

/// RFC 3986 percent-encode for query values (encodes `/` too), matching the
/// server's SigV4 canonicalisation.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Pull every `<tag>..</tag>` value from `xml`, in order.
fn extract_tags(xml: &str, open: &str, close: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(open) {
        rest = &rest[i + open.len()..];
        match rest.find(close) {
            Some(j) => {
                out.push(rest[..j].to_string());
                rest = &rest[j..];
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectStore, StaticCredentials, router_with_auth};
    use std::sync::Arc;

    #[tokio::test]
    async fn rust_client_round_trips_against_the_server() {
        let dir = std::env::temp_dir().join(format!("jkb-objclient-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(ObjectStore::open(&dir).unwrap());
        let creds = Arc::new(StaticCredentials::new().with("AK", "SK", "tenant-a"));
        let app = router_with_auth(store, creds);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let c = ObjectClient::new(format!("http://{addr}"), "AK", "SK", "us-east-1");
        c.create_bucket("my-bucket").await.unwrap();
        let etag = c.put_object("my-bucket", "dir/obj", b"hello sdk".to_vec(), "text/plain").await.unwrap();
        assert!(etag.contains('"')); // quoted hex md5
        assert_eq!(c.get_object("my-bucket", "dir/obj").await.unwrap(), b"hello sdk");
        c.put_object("my-bucket", "dir/two", b"2".to_vec(), "text/plain").await.unwrap();
        let mut keys = c.list_objects("my-bucket", "dir/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["dir/obj".to_string(), "dir/two".to_string()]);
        c.delete_object("my-bucket", "dir/obj").await.unwrap();
        assert_eq!(c.list_objects("my-bucket", "dir/").await.unwrap(), vec!["dir/two".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
