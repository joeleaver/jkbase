//! AWS Signature Version 4 (query-string / presigned form) for the object store.
//! One implementation serves both presigned URLs (this card) and request auth (the
//! auth card): [`presign`] mints a time-limited signed URL, [`verify_presigned`]
//! validates one against the access key's secret + expiry.
//!
//! Canonicalisation follows the SigV4 spec (UNSIGNED-PAYLOAD, `host` the only
//! signed header) so the round-trip is self-consistent; byte-exact interop with
//! the AWS SDKs should be spot-checked against a real client when wired up.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SERVICE: &str = "s3";
const AWS_REQUEST: &str = "aws4_request";

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Length-checked constant-time compare (don't leak signature bytes via timing).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// RFC 3986 percent-encoding as SigV4 requires (encode everything but the
/// unreserved set; `/` is left intact in paths when `encode_slash` is false).
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The four-step SigV4 signing key derivation.
fn signing_key(secret: &str, date: &str, region: &str) -> [u8; 32] {
    let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, SERVICE.as_bytes());
    hmac(&k, AWS_REQUEST.as_bytes())
}

/// Sorted, percent-encoded `k=v&...` canonical query string, optionally excluding
/// one key (the signature itself, which isn't part of what it signs).
fn canonical_query(pairs: &[(String, String)], exclude: &str) -> String {
    let mut enc: Vec<(String, String)> = pairs
        .iter()
        .filter(|(k, _)| k != exclude)
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    enc.sort();
    enc.into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn build_canonical_request(method: &str, path: &str, cquery: &str, host: &str) -> String {
    // host is the only signed header; payload is unsigned for presigned URLs.
    format!(
        "{method}\n{}\n{cquery}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
        uri_encode(path, false)
    )
}

fn date_stamp(now_unix: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(now_unix as i64, 0)
        .unwrap_or_default()
        .format("%Y%m%d")
        .to_string()
}

fn amz_date(now_unix: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(now_unix as i64, 0)
        .unwrap_or_default()
        .format("%Y%m%dT%H%M%SZ")
        .to_string()
}

fn parse_amz_date(s: &str) -> Option<u64> {
    let ndt = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%SZ").ok()?;
    u64::try_from(ndt.and_utc().timestamp()).ok()
}

/// Mint a presigned URL `"<path>?<query>"` valid for `expires_secs` from `now_unix`.
#[allow(clippy::too_many_arguments)] // inherent to a SigV4 signer; all distinct inputs
pub fn presign(
    method: &str,
    host: &str,
    path: &str,
    access_key: &str,
    secret: &str,
    region: &str,
    expires_secs: u64,
    now_unix: u64,
) -> String {
    let date = date_stamp(now_unix);
    let amzd = amz_date(now_unix);
    let scope = format!("{date}/{region}/{SERVICE}/{AWS_REQUEST}");
    let mut params = vec![
        ("X-Amz-Algorithm".to_string(), ALGORITHM.to_string()),
        ("X-Amz-Credential".to_string(), format!("{access_key}/{scope}")),
        ("X-Amz-Date".to_string(), amzd.clone()),
        ("X-Amz-Expires".to_string(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    let cquery = canonical_query(&params, "");
    let creq = build_canonical_request(method, path, &cquery, host);
    let sts = format!("{ALGORITHM}\n{amzd}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
    let sig = hex(&hmac(&signing_key(secret, &date, region), sts.as_bytes()));
    params.push(("X-Amz-Signature".to_string(), sig));
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{qs}")
}

/// Validate a presigned request. `query` is the request's parsed query params.
/// `lookup_secret` resolves an access-key id to its secret. Returns the access-key
/// id on success.
pub fn verify_presigned(
    method: &str,
    host: &str,
    path: &str,
    query: &[(String, String)],
    lookup_secret: impl Fn(&str) -> Option<String>,
    now_unix: u64,
) -> Result<String, String> {
    let get = |k: &str| query.iter().find(|(qk, _)| qk == k).map(|(_, v)| v.as_str());
    let cred = get("X-Amz-Credential").ok_or("missing X-Amz-Credential")?;
    let amzd = get("X-Amz-Date").ok_or("missing X-Amz-Date")?;
    let expires: u64 = get("X-Amz-Expires")
        .ok_or("missing X-Amz-Expires")?
        .parse()
        .map_err(|_| "bad X-Amz-Expires")?;
    // Bound the lifetime like AWS (max 7 days): an unbounded X-Amz-Expires would mint a
    // forever-valid bearer grant to the object for anyone who captures the URL.
    if expires == 0 || expires > 604_800 {
        return Err("X-Amz-Expires out of range (1..=604800)".into());
    }
    let provided = get("X-Amz-Signature").ok_or("missing X-Amz-Signature")?;

    let parts: Vec<&str> = cred.split('/').collect();
    if parts.len() != 5 || parts[3] != SERVICE || parts[4] != AWS_REQUEST {
        return Err("malformed X-Amz-Credential".into());
    }
    let (access_key, date, region) = (parts[0], parts[1], parts[2]);
    let secret = lookup_secret(access_key).ok_or("unknown access key")?;

    let signed_at = parse_amz_date(amzd).ok_or("bad X-Amz-Date")?;
    // Reject a future-dated signature (small skew allowed) so a URL can't be pre-minted
    // to become "valid from now" for its full lifetime.
    if signed_at > now_unix.saturating_add(300) {
        return Err("X-Amz-Date is in the future".into());
    }
    if now_unix > signed_at.saturating_add(expires) {
        return Err("presigned URL expired".into());
    }

    let cquery = canonical_query(query, "X-Amz-Signature");
    let creq = build_canonical_request(method, path, &cquery, host);
    let scope = format!("{date}/{region}/{SERVICE}/{AWS_REQUEST}");
    let sts = format!("{ALGORITHM}\n{amzd}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
    let sig = hex(&hmac(&signing_key(&secret, date, region), sts.as_bytes()));

    if ct_eq(sig.as_bytes(), provided.as_bytes()) {
        Ok(access_key.to_string())
    } else {
        Err("signature mismatch".into())
    }
}

/// Sign a request with an `Authorization: AWS4-HMAC-SHA256 ...` header, signing the
/// minimal common header set (host;x-amz-content-sha256;x-amz-date). Returns
/// `(authorization_header_value, x_amz_date)`; the caller also sets
/// `X-Amz-Content-Sha256: <payload_hash>` and `Host`.
#[allow(clippy::too_many_arguments)]
pub fn sign_header(
    method: &str,
    host: &str,
    path: &str,
    query: &[(String, String)],
    payload_hash: &str,
    access_key: &str,
    secret: &str,
    region: &str,
    now_unix: u64,
) -> (String, String) {
    let amzd = amz_date(now_unix);
    let date = date_stamp(now_unix);
    let scope = format!("{date}/{region}/{SERVICE}/{AWS_REQUEST}");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_headers = format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amzd}\n");
    let cquery = canonical_query(query, "");
    let creq = format!(
        "{method}\n{}\n{cquery}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        uri_encode(path, false)
    );
    let sts = format!("{ALGORITHM}\n{amzd}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
    let sig = hex(&hmac(&signing_key(secret, &date, region), sts.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={sig}"
    );
    (auth, amzd)
}

/// Verify an `Authorization`-header SigV4 request. `headers` holds the request's
/// headers by lowercased name (must include the ones in SignedHeaders, e.g.
/// `x-amz-date`); `host` is supplied separately. Returns the access-key id.
#[allow(clippy::too_many_arguments)] // inherent to a SigV4 verifier; all distinct inputs
pub fn verify_header(
    method: &str,
    host: &str,
    path: &str,
    query: &[(String, String)],
    headers: &HashMap<String, String>,
    authorization: &str,
    lookup_secret: impl Fn(&str) -> Option<String>,
    now_unix: u64,
) -> Result<String, String> {
    let rest = authorization
        .strip_prefix("AWS4-HMAC-SHA256")
        .ok_or("not an AWS4-HMAC-SHA256 authorization")?
        .trim();
    let (mut cred, mut signed, mut sig) = (None, None, None);
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            cred = Some(v);
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed = Some(v);
        } else if let Some(v) = part.strip_prefix("Signature=") {
            sig = Some(v);
        }
    }
    let cred = cred.ok_or("missing Credential")?;
    let signed_headers = signed.ok_or("missing SignedHeaders")?;
    let provided = sig.ok_or("missing Signature")?;

    let cp: Vec<&str> = cred.split('/').collect();
    if cp.len() != 5 || cp[3] != SERVICE || cp[4] != AWS_REQUEST {
        return Err("malformed Credential".into());
    }
    let (access_key, date, region) = (cp[0], cp[1], cp[2]);
    let secret = lookup_secret(access_key).ok_or("unknown access key")?;

    let amzd = headers.get("x-amz-date").ok_or("missing x-amz-date")?;
    let signed_at = parse_amz_date(amzd).ok_or("bad x-amz-date")?;
    let skew = now_unix.abs_diff(signed_at);
    if skew > 900 {
        return Err("request time too skewed".into());
    }
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .map(String::as_str)
        .unwrap_or("UNSIGNED-PAYLOAD");

    let mut canonical_headers = String::new();
    for h in signed_headers.split(';') {
        let val = if h == "host" {
            host
        } else {
            headers.get(h).map(String::as_str).unwrap_or("")
        };
        canonical_headers.push_str(&format!("{h}:{}\n", val.trim()));
    }
    let cquery = canonical_query(query, "");
    let creq = format!(
        "{method}\n{}\n{cquery}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        uri_encode(path, false)
    );
    let scope = format!("{date}/{region}/{SERVICE}/{AWS_REQUEST}");
    let sts = format!("{ALGORITHM}\n{amzd}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
    let computed = hex(&hmac(&signing_key(&secret, date, region), sts.as_bytes()));

    if ct_eq(computed.as_bytes(), provided.as_bytes()) {
        Ok(access_key.to_string())
    } else {
        Err("signature mismatch".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse "/path?a=b&c=d" into (path, query pairs) the way the server would.
    fn split(url: &str) -> (String, Vec<(String, String)>) {
        let (path, qs) = url.split_once('?').unwrap();
        let pairs = qs
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (pct_decode(k), pct_decode(v)))
            .collect();
        (path.to_string(), pairs)
    }

    fn pct_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let h = u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'%');
                out.push(h);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    const KEY: &str = "AKIAEXAMPLE";
    const SECRET: &str = "supersecretkey";
    const NOW: u64 = 1_700_000_000;

    fn lookup(k: &str) -> Option<String> {
        (k == KEY).then(|| SECRET.to_string())
    }

    #[test]
    fn presign_then_verify_round_trips() {
        let url = presign("GET", "s3.jkbase.app", "/bucket/dir/obj.txt", KEY, SECRET, "us-east-1", 900, NOW);
        let (path, q) = split(&url);
        assert_eq!(
            verify_presigned("GET", "s3.jkbase.app", &path, &q, lookup, NOW + 100),
            Ok(KEY.to_string())
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let url = presign("GET", "s3.jkbase.app", "/b/k", KEY, SECRET, "us-east-1", 900, NOW);
        let (path, mut q) = split(&url);
        for (k, v) in q.iter_mut() {
            if k == "X-Amz-Signature" {
                v.replace_range(0..1, "0"); // flip the first sig char
            }
        }
        assert!(verify_presigned("GET", "s3.jkbase.app", &path, &q, lookup, NOW).is_err());
    }

    #[test]
    fn presign_rejects_unbounded_expiry_and_future_date() {
        // Expiry beyond the 7-day cap is rejected even with a valid signature.
        let url = presign("GET", "s3.jkbase.app", "/b/k", KEY, SECRET, "us-east-1", 700_000, NOW);
        let (path, q) = split(&url);
        assert!(verify_presigned("GET", "s3.jkbase.app", &path, &q, lookup, NOW).is_err());
        // A future-dated signature (signed_at well ahead of now) is rejected.
        let url2 = presign("GET", "s3.jkbase.app", "/b/k", KEY, SECRET, "us-east-1", 900, NOW + 100_000);
        let (path2, q2) = split(&url2);
        assert!(verify_presigned("GET", "s3.jkbase.app", &path2, &q2, lookup, NOW).is_err());
        // A normal one still round-trips.
        let url3 = presign("GET", "s3.jkbase.app", "/b/k", KEY, SECRET, "us-east-1", 900, NOW);
        let (path3, q3) = split(&url3);
        assert!(verify_presigned("GET", "s3.jkbase.app", &path3, &q3, lookup, NOW + 10).is_ok());
    }

    #[test]
    fn expired_url_is_rejected() {
        let url = presign("GET", "s3.jkbase.app", "/b/k", KEY, SECRET, "us-east-1", 60, NOW);
        let (path, q) = split(&url);
        assert!(verify_presigned("GET", "s3.jkbase.app", &path, &q, lookup, NOW + 61).is_err());
    }

    #[test]
    fn wrong_secret_and_unknown_key_are_rejected() {
        let url = presign("GET", "s3.jkbase.app", "/b/k", KEY, "OTHER-SECRET", "us-east-1", 900, NOW);
        let (path, q) = split(&url);
        // Signed with a different secret than `lookup` returns -> mismatch.
        assert!(verify_presigned("GET", "s3.jkbase.app", &path, &q, lookup, NOW).is_err());
        // Unknown key -> rejected before signature check.
        assert!(verify_presigned("GET", "s3.jkbase.app", &path, &q, |_| None, NOW).is_err());
    }

    #[test]
    fn host_and_method_are_bound() {
        let url = presign("GET", "s3.jkbase.app", "/b/k", KEY, SECRET, "us-east-1", 900, NOW);
        let (path, q) = split(&url);
        // Different host or method must not validate (they're in the signature).
        assert!(verify_presigned("GET", "evil.example.com", &path, &q, lookup, NOW).is_err());
        assert!(verify_presigned("PUT", "s3.jkbase.app", &path, &q, lookup, NOW).is_err());
    }

    fn hdrs(amzd: &str, payload: &str) -> std::collections::HashMap<String, String> {
        [
            ("x-amz-date".to_string(), amzd.to_string()),
            ("x-amz-content-sha256".to_string(), payload.to_string()),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn header_sign_then_verify_round_trips() {
        let q: Vec<(String, String)> = vec![];
        let (auth, amzd) =
            sign_header("PUT", "s3.jkbase.app", "/bucket/key", &q, "UNSIGNED-PAYLOAD", KEY, SECRET, "us-east-1", NOW);
        let h = hdrs(&amzd, "UNSIGNED-PAYLOAD");
        assert_eq!(
            verify_header("PUT", "s3.jkbase.app", "/bucket/key", &q, &h, &auth, lookup, NOW + 10),
            Ok(KEY.to_string())
        );
    }

    #[test]
    fn header_rejects_skew_unknown_key_and_tamper() {
        let q: Vec<(String, String)> = vec![];
        let (auth, amzd) =
            sign_header("GET", "s3.jkbase.app", "/b/k", &q, "UNSIGNED-PAYLOAD", KEY, SECRET, "us-east-1", NOW);
        let h = hdrs(&amzd, "UNSIGNED-PAYLOAD");
        // Clock skew beyond 15 minutes.
        assert!(verify_header("GET", "s3.jkbase.app", "/b/k", &q, &h, &auth, lookup, NOW + 1000).is_err());
        // Unknown access key.
        assert!(verify_header("GET", "s3.jkbase.app", "/b/k", &q, &h, &auth, |_| None, NOW).is_err());
        // Tamper a signed header value -> signature mismatch.
        let tampered = hdrs(&amzd, "deadbeef");
        assert!(verify_header("GET", "s3.jkbase.app", "/b/k", &q, &tampered, &auth, lookup, NOW).is_err());
    }
}

#[cfg(test)]
mod cross_vector {
    use super::*;
    // Fixed SigV4 vectors shared verbatim with the JS SDK test
    // (sdk/js/objectstore.test.mjs) so both implementations stay pinned to the same
    // canonicalisation — that equality is what makes JS-signed requests verify here.
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn header_signature_is_stable() {
        let (auth, amzd) =
            sign_header("GET", "s3.test", "/b/k", &[], "UNSIGNED-PAYLOAD", "AKID", "SECRET", "us-east-1", NOW);
        assert_eq!(amzd, "20231114T221320Z");
        assert!(auth.ends_with(
            "Signature=0f0c7b988b19fb25857e216bac0116a054f0cb91696c0ae00e81bb06520cf115"
        ));
    }

    #[test]
    fn presign_signature_is_stable() {
        let url = presign("GET", "s3.test", "/b/k", "AKID", "SECRET", "us-east-1", 900, NOW);
        assert!(url.ends_with(
            "X-Amz-Signature=67dfd03db2009a8216e3779a68cb239b0ba9579b44c4b3fe168cd0b0bab28614"
        ));
    }
}
