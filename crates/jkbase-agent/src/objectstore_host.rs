//! Host implementation of the `jkbase:objectstore/store` capability — the typed own-bucket
//! binding a function imports. The guest names KEYS; the agent (host-side, in the tenant VM)
//! supplies the endpoint, the ephemeral credential, and the project scope, then issues a
//! SigV4-signed request to the host-pinned platform storage endpoint over the Zone-1
//! OWN-storage egress path (always allowed, survives `egress = false`). No credential ever
//! enters the guest's `process.env` (P0-OBJ-NOKEY); the WIT exposes no host/bucket/region
//! surface (P0-OBJ-SCOPE).
//!
//! The credential is the platform-managed binding key (deploy-rotated, owner-bound, NOT the
//! user's own key — P0-OBJ-NO-STANDING-KEY), read from the sidecar's reserved channel. The
//! request lands at the unchanged `ObjectStoreService` front, which derives `{project_id}`
//! from the verified key + owner-re-binds + meters quota — so isolation/quota are inherited
//! (P0-OBJ-SCOPE/-QUOTA). Requests can ONLY reach the host-pinned storage IP
//! (P0-OBJ-PINNED-DEST, enforced in `EgressContext::own_storage_request`).

use crate::function_runtime::HostState;
use jkbase_common::sigv4;

wasmtime::component::bindgen!({
    path: "wit/objectstore.wit",
    world: "host-store",
    async: true,
});

pub use jkbase::objectstore::store::{Error as StoreError, ListPage, ObjectMeta};
use jkbase::objectstore::store::Host;

/// The project's default binding bucket. The WIT exposes no bucket surface; every key lives
/// under this one bucket in the project's own object-store namespace (the function can also
/// use the SigV4-secret path for other buckets). Auto-created on first `put`.
const BINDING_BUCKET: &str = "fn";
/// SigV4 region — self-consistent (the verify path derives the region from the signed scope),
/// matches the rest of the platform's `us-east-1` convention.
const REGION: &str = "us-east-1";
/// `UNSIGNED-PAYLOAD` — sign without hashing the body (same as the platform's S3 client); the
/// `x-amz-content-sha256` header carries this sentinel and is part of the signed set.
const UNSIGNED: &str = "UNSIGNED-PAYLOAD";

/// Validate a guest-supplied key: non-empty, bounded, and confined to a safe charset so the
/// raw path == the URL-encoded path (no SigV4 path-encoding ambiguity) and no traversal.
/// A power user with exotic keys can use the SigV4-secret path; the typed binding takes the
/// safe common case.
fn key_ok(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && !key.starts_with('/')
        && !key.split('/').any(|seg| seg == ".." || seg.is_empty())
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// A prefix may be empty and may end in a separator, but otherwise the same safe charset.
fn prefix_ok(prefix: &str) -> bool {
    prefix.len() <= 1024
        && prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl HostState {
    /// Sign + issue one S3 request to the OWN platform storage host. `path` is the raw
    /// (already-safe) resource path; `query` are unencoded pairs (signed + sent identically
    /// via the shared canonical encoding). Returns `(status, body)` or a typed `StoreError`.
    // `&mut self` (not `&self`) so the returned future captures `&mut HostState` rather than
    // `&HostState` — the generated Host trait requires Send futures, and HostState is Send but
    // not Sync (WasiCtx holds non-Sync RNG/clock trait objects).
    async fn s3(
        &mut self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), StoreError> {
        let cred = self.storage_cred.as_ref().ok_or(StoreError::AccessDenied)?;
        let host = self.egress_ctx.storage_host().ok_or(StoreError::Internal)?;
        let (auth, amzd) = sigv4::sign_header(
            method,
            host,
            path,
            query,
            UNSIGNED,
            &cred.access_key_id,
            &cred.secret_key,
            REGION,
            now_unix(),
        );
        // Wire query == signed query (same canonical encoding).
        let path_and_query = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", sigv4::canonical_query(query, ""))
        };
        let headers = [
            ("authorization".to_string(), auth),
            ("x-amz-date".to_string(), amzd),
            ("x-amz-content-sha256".to_string(), UNSIGNED.to_string()),
        ];
        self.egress_ctx
            .own_storage_request(method, &path_and_query, &headers, body)
            .await
            // Transport/fence failures are opaque internal errors (P0-OBJ-OPAQUE) — never
            // reflect host detail to the guest.
            .map_err(|_| StoreError::Internal)
    }

    /// Create the binding bucket (idempotent: an already-existing bucket is success).
    async fn ensure_bucket(&mut self) -> Result<(), StoreError> {
        let (status, _) = self.s3("PUT", &format!("/{BINDING_BUCKET}"), &[], Vec::new()).await?;
        match status {
            200 | 204 | 409 => Ok(()), // 409 = BucketAlreadyExists
            403 => Err(StoreError::AccessDenied),
            _ => Err(StoreError::Internal),
        }
    }
}

/// Map an object-level HTTP status to the WIT error set (opaque — no host detail).
fn status_err(status: u16) -> StoreError {
    match status {
        403 => StoreError::AccessDenied,
        404 => StoreError::NotFound,
        413 => StoreError::TooLarge,
        507 => StoreError::QuotaExceeded,
        _ => StoreError::Internal,
    }
}

impl Host for HostState {
    async fn get(&mut self, key: String) -> Result<Vec<u8>, StoreError> {
        if !key_ok(&key) {
            return Err(StoreError::InvalidKey);
        }
        let (status, body) = self.s3("GET", &format!("/{BINDING_BUCKET}/{key}"), &[], Vec::new()).await?;
        match status {
            200 => Ok(body),
            other => Err(status_err(other)),
        }
    }

    async fn put(&mut self, key: String, body: Vec<u8>) -> Result<(), StoreError> {
        if !key_ok(&key) {
            return Err(StoreError::InvalidKey);
        }
        let path = format!("/{BINDING_BUCKET}/{key}");
        let (status, _) = self.s3("PUT", &path, &[], body.clone()).await?;
        match status {
            200 | 204 => Ok(()),
            // First write to a project: the bucket doesn't exist yet — create it, retry once.
            404 => {
                self.ensure_bucket().await?;
                let (status, _) = self.s3("PUT", &path, &[], body).await?;
                match status {
                    200 | 204 => Ok(()),
                    other => Err(status_err(other)),
                }
            }
            other => Err(status_err(other)),
        }
    }

    async fn delete(&mut self, key: String) -> Result<(), StoreError> {
        if !key_ok(&key) {
            return Err(StoreError::InvalidKey);
        }
        let (status, _) = self.s3("DELETE", &format!("/{BINDING_BUCKET}/{key}"), &[], Vec::new()).await?;
        match status {
            200 | 204 | 404 => Ok(()), // delete is idempotent (S3 semantics)
            other => Err(status_err(other)),
        }
    }

    async fn list_objects(
        &mut self,
        prefix: String,
        delimiter: Option<String>,
        cursor: Option<String>,
    ) -> Result<ListPage, StoreError> {
        if !prefix_ok(&prefix) {
            return Err(StoreError::InvalidKey);
        }
        let mut query: Vec<(String, String)> = vec![("list-type".into(), "2".into())];
        if !prefix.is_empty() {
            query.push(("prefix".into(), prefix));
        }
        if let Some(d) = delimiter.filter(|d| !d.is_empty()) {
            query.push(("delimiter".into(), d));
        }
        if let Some(c) = cursor.filter(|c| !c.is_empty()) {
            query.push(("continuation-token".into(), c));
        }
        let (status, body) = self.s3("GET", &format!("/{BINDING_BUCKET}"), &query, Vec::new()).await?;
        match status {
            200 => Ok(parse_list_xml(&String::from_utf8_lossy(&body))),
            404 => Ok(ListPage {
                objects: Vec::new(),
                common_prefixes: Vec::new(),
                next_cursor: None,
            }),
            other => Err(status_err(other)),
        }
    }
}

/// Parse an S3 `ListBucketResult` into the WIT `list-page`. Crude tag extraction (the
/// engine emits a fixed, well-formed shape — see jkbase-objectstore http.rs); robust to
/// missing optional fields. `last-modified` is best-effort (0 if unparseable).
fn parse_list_xml(xml: &str) -> ListPage {
    fn inner<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = s.find(&open)? + open.len();
        let end = s[start..].find(&close)? + start;
        Some(&s[start..end])
    }
    fn each<'a>(s: &'a str, tag: &str) -> Vec<&'a str> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut out = Vec::new();
        let mut rest = s;
        while let Some(i) = rest.find(&open) {
            let from = i + open.len();
            if let Some(j) = rest[from..].find(&close) {
                out.push(&rest[from..from + j]);
                rest = &rest[from + j + close.len()..];
            } else {
                break;
            }
        }
        out
    }
    let objects = each(xml, "Contents")
        .into_iter()
        .map(|c| ObjectMeta {
            key: unescape(inner(c, "Key").unwrap_or("")),
            size: inner(c, "Size").and_then(|s| s.parse().ok()).unwrap_or(0),
            etag: unescape(inner(c, "ETag").unwrap_or("")).trim_matches('"').to_string(),
            last_modified: inner(c, "LastModified").map(parse_iso8601).unwrap_or(0),
        })
        .collect();
    let common_prefixes = each(xml, "CommonPrefixes")
        .into_iter()
        .filter_map(|c| inner(c, "Prefix").map(unescape))
        .collect();
    let next_cursor = inner(xml, "NextContinuationToken").map(unescape).filter(|s| !s.is_empty());
    ListPage {
        objects,
        common_prefixes,
        next_cursor,
    }
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Parse an ISO-8601 `YYYY-MM-DDTHH:MM:SS[.fff]Z` to unix seconds (best-effort, 0 on miss).
fn parse_iso8601(s: &str) -> u64 {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return 0;
    }
    let n = |r: std::ops::Range<usize>| s.get(r).and_then(|x| x.parse::<i64>().ok());
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(sec)) =
        (n(0..4), n(5..7), n(8..10), n(11..13), n(14..16), n(17..19))
    else {
        return 0;
    };
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy.rem_euclid(400);
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).unwrap_or(0)
}

/// Register the `jkbase:objectstore/store` import on the component linker, supplying
/// `HostState` as the host. Called alongside the wasi + wasi:http linker setup. A component
/// that does NOT import the interface is unaffected (an extra linker definition is harmless).
pub fn add_to_linker(linker: &mut wasmtime::component::Linker<HostState>) -> wasmtime::Result<()> {
    jkbase::objectstore::store::add_to_linker::<HostState, HostState>(linker, |s| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation() {
        assert!(key_ok("a/b/c.txt"));
        assert!(key_ok("simple"));
        assert!(!key_ok(""));
        assert!(!key_ok("/leading"));
        assert!(!key_ok("a/../b"), "traversal rejected");
        assert!(!key_ok("a//b"), "empty segment rejected");
        assert!(!key_ok("has space"));
        assert!(!key_ok("weird*char"));
    }

    #[test]
    fn parses_list_xml_with_objects_and_prefixes() {
        let xml = "<?xml version=\"1.0\"?><ListBucketResult>\
            <Contents><Key>a/x.txt</Key><LastModified>2024-01-02T03:04:05.000Z</LastModified><ETag>\"abc\"</ETag><Size>12</Size></Contents>\
            <CommonPrefixes><Prefix>a/sub/</Prefix></CommonPrefixes>\
            <NextContinuationToken>tok123</NextContinuationToken></ListBucketResult>";
        let p = parse_list_xml(xml);
        assert_eq!(p.objects.len(), 1);
        assert_eq!(p.objects[0].key, "a/x.txt");
        assert_eq!(p.objects[0].size, 12);
        assert_eq!(p.objects[0].etag, "abc");
        assert!(p.objects[0].last_modified > 0);
        assert_eq!(p.common_prefixes, vec!["a/sub/".to_string()]);
        assert_eq!(p.next_cursor.as_deref(), Some("tok123"));
    }

    #[test]
    fn iso8601_roundtrips_a_known_epoch() {
        // 2024-01-02T03:04:05Z = 1704164645
        assert_eq!(parse_iso8601("2024-01-02T03:04:05.000Z"), 1_704_164_645);
        assert_eq!(parse_iso8601("garbage"), 0);
    }
}
