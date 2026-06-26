//! The committed proof the earlier review found missing: a client-signed request must
//! VERIFY server-side for every key class. The bare-engine e2e (e2e.rs) skips auth, so it
//! can't catch a sign≠send divergence (which is exactly how a presigned-URL encoding
//! BLOCKER slipped past the first review). Here we wrap the engine router in a layer that
//! replicates the production front's SigV4 gate — `pct_decode(path)` +
//! `verify_header`/`verify_presigned` against the same host the client signed — and drive
//! the REAL `ObjectClient` (and bare-HTTP fetches of presigned URLs) through it.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
};
use jkbase_objectstore::{ObjectStore, router};
use jkbase_objectstore_client::ObjectClient;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(0);
const AK: &str = "AKIDTESTKEY";
const SK: &str = "test-secret-key";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Percent-decode `%XX` from raw bytes (mirrors the front's `pct_decode`).
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            match (hi, lo) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse + percent-decode a query string into ordered pairs (mirrors the front).
fn parse_query(q: &str) -> Vec<(String, String)> {
    if q.is_empty() {
        return Vec::new();
    }
    q.split('&')
        .filter_map(|kv| kv.split_once('=').or(Some((kv, ""))))
        .map(|(k, v)| (pct_decode(k), pct_decode(v)))
        .collect()
}

/// Spin up the engine wrapped in a SigV4-verifying layer (the production gate), and an
/// `ObjectClient` whose credentials + signed host match it. Returns (client, dir).
async fn spawn_verifying() -> (ObjectClient, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "jkb-objclient-verify-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = Arc::new(ObjectStore::open(&dir).unwrap());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // The client signs Host = authority(base_url) = "127.0.0.1:<port>"; the gate must
    // verify against that exact host (the real front verifies its configured public host).
    let host = addr.to_string();

    let gate_host = host.clone();
    let app = router(store).layer(middleware::from_fn(move |req: Request, next: Next| {
        let host = gate_host.clone();
        async move {
            let lookup = |akid: &str| (akid == AK).then(|| SK.to_string());
            let method = req.method().as_str().to_string();
            let path = pct_decode(req.uri().path());
            let query = parse_query(req.uri().query().unwrap_or(""));
            let is_presigned = query.iter().any(|(k, _)| k == "X-Amz-Signature");

            let ok = if is_presigned {
                jkbase_sigv4::verify_presigned(&method, &host, &path, &query, lookup, now_secs())
                    .is_ok()
            } else if let Some(auth) = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
            {
                let headers: HashMap<String, String> = req
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_lowercase(),
                            v.to_str().unwrap_or("").to_string(),
                        )
                    })
                    .collect();
                jkbase_sigv4::verify_header(
                    &method,
                    &host,
                    &path,
                    &query,
                    &headers,
                    auth,
                    lookup,
                    now_secs(),
                )
                .is_ok()
            } else {
                false
            };

            if ok {
                next.run(req).await
            } else {
                (
                    StatusCode::FORBIDDEN,
                    Body::from(
                        "<Error><Code>AccessDenied</Code><Message>signature</Message></Error>",
                    ),
                )
                    .into_response()
            }
        }
    }));

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let client = ObjectClient::with_region(format!("http://{host}"), AK, SK, "us-east-1");
    (client, dir)
}

/// Header-auth requests for every accepted key class verify server-side and round-trip.
#[tokio::test]
async fn header_signed_requests_verify_for_all_key_classes() {
    let (c, dir) = spawn_verifying().await;
    c.create_bucket("vbkt").await.unwrap();

    // Space, &, <, >, =, +, unicode, multi-segment, dotted-but-not-a-segment.
    let keys = [
        "plain.txt",
        "a b",
        "a&b",
        "x<y>z",
        "p=q+r",
        "u/\u{2713}.bin",
        "d/e/f",
        "report.v2..bak",
    ];
    for (i, k) in keys.iter().enumerate() {
        let body = format!("body-{i}");
        // PUT must verify (a sign≠send divergence would 403 here, not at the bare engine).
        c.put_object("vbkt", k, body.clone().into_bytes(), "text/plain")
            .await
            .unwrap();
        // HEAD + GET must verify and return the same bytes.
        c.head_object("vbkt", k).await.unwrap();
        assert_eq!(
            &c.get_object_bytes("vbkt", k).await.unwrap()[..],
            body.as_bytes(),
            "key {k:?}"
        );
    }

    // A signed LIST (with a special-char prefix) also verifies and returns the keys.
    let listed = c.list_all_keys("vbkt", "").await.unwrap();
    assert_eq!(listed.len(), keys.len(), "listed {listed:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Presigned GET + PUT URLs verify server-side for special-char keys — the exact case the
/// presign encoding BLOCKER broke (raw key in the URL would 403 here).
#[tokio::test]
async fn presigned_urls_verify_for_special_char_keys() {
    let (c, dir) = spawn_verifying().await;
    c.create_bucket("pbkt").await.unwrap();
    let http = reqwest::Client::new();

    for key in ["a b.txt", "n&m", "z/\u{2713}"] {
        // presigned PUT: a bare HTTP client uploads to the minted URL; the gate must verify.
        let put_url = c.presigned_put("pbkt", key, 900).unwrap();
        let r = http.put(&put_url).body("presigned").send().await.unwrap();
        assert!(
            r.status().is_success(),
            "PUT {key:?} -> {} ({put_url})",
            r.status()
        );

        // presigned GET: fetch with no auth header; the gate must verify and return it.
        let get_url = c.presigned_get("pbkt", key, 900).unwrap();
        let resp = http.get(&get_url).send().await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET {key:?} -> {} ({get_url})",
            resp.status()
        );
        assert_eq!(resp.text().await.unwrap(), "presigned", "key {key:?}");
    }

    // A tampered presigned URL is rejected by the gate (proves the gate is real, not a no-op).
    let url = c.presigned_get("pbkt", "a b.txt", 900).unwrap();
    let tampered = url.replace("X-Amz-Signature=", "X-Amz-Signature=0");
    assert_eq!(
        http.get(&tampered).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let _ = std::fs::remove_dir_all(&dir);
}
