//! jkbase-Auth issuer service (P3) — the loopback HTTP service behind the `auth.{domain}`
//! reserved host. It is a **signing oracle**: a tenant's own (already-authenticated) backend
//! presents its per-project `jkbk_` issuer key and gets a short-lived per-end-user EdDSA JWT,
//! signed with the project's private key (which stays host-side — P0-AUTH-2); anyone verifies it
//! offline against the project's JWKS. jkbase stores NO end-user accounts (the minter-core scope,
//! `docs/managed-rhypedb-p3-design.md` §0/§1).
//!
//! Structurally it mirrors [`crate::objectstore_service`]: an in-process axum router bound on
//! `127.0.0.1`, forwarded to by the proxy's `auth.` reserved-host branch (the P0 loopback invariant
//! — never reachable off loopback except via the edge). Two routes:
//! - `GET  /v1/projects/{id}/.well-known/jwks.json` — anonymous, cacheable, CORS-open (verifiers
//!   are everywhere). 404s a nonexistent project; an existing-but-unprovisioned one gets `{keys:[]}`.
//! - `POST /v1/projects/{id}/token` — Bearer `jkbk_…` → owner-rebind (P0-AUTH-3) + project-scope
//!   (P0-AUTH-6) + per-key rate limit (P0-AUTH-7) → lazily provision the signing key → sign.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use jkbase_control::auth;
use jkbase_control::jose::Claims;
use jkbase_control::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};
use tracing::warn;

/// Token lifetime bounds (seconds). The default is short; the hard max is bounded by the signing-key
/// rotation window (`Store::AUTH_SIGNING_ROTATION_WINDOW_SECS` ≥ this) so a live token is never
/// stranded by a rotation (P0-AUTH-4).
const DEFAULT_TTL_SECS: u64 = 3600; // 1h
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 24 * 3600; // 24h

/// Caps on tenant-supplied token inputs — bound the size of a minted token (a giant `sub`/`claims`
/// would inflate every token and the sign cost).
const MAX_SUB_LEN: usize = 256;
const MAX_CLAIMS_BYTES: usize = 8 * 1024;

/// Per-issuer-key mint rate (token bucket): generous for a legit backend (which caches a token per
/// end-user session, so it mints rarely) while throttling a leaked key (P0-AUTH-7).
const MINT_RATE_PER_SEC: f64 = 100.0;
const MINT_BURST: f64 = 200.0;

pub struct AuthService {
    control: Store,
    /// Public host, e.g. `auth.jkbase.app` — builds the JWT `iss`.
    public_host: String,
    limiter: MintRateLimiter,
}

impl AuthService {
    pub fn new(control: Store, public_host: String) -> Self {
        Self {
            control,
            public_host,
            limiter: MintRateLimiter::new(MINT_RATE_PER_SEC, MINT_BURST),
        }
    }

    pub fn into_router(self: Arc<Self>) -> Router {
        // JWKS is a universally-fetched public document and `/token` is called cross-origin by
        // tenant frontends/backends; CORS is open because neither response is protected BY CORS —
        // JWKS is public and `/token` is gated by the `jkbk_` bearer, not by the browser origin.
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
        Router::new()
            .route("/v1/projects/{id}/.well-known/jwks.json", get(jwks))
            .route("/v1/projects/{id}/token", post(mint_token))
            .layer(cors)
            .with_state(self)
    }
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// Extract a non-empty `Authorization: Bearer <secret>`.
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Publish a project's JWKS. Anonymous + cacheable. 404 a NONEXISTENT project (so the endpoint
/// doesn't imply key material exists); an existing-but-unprovisioned project returns `{keys:[]}`
/// (fail-closed — verifies nothing) until its first token mint provisions a key.
async fn jwks(State(svc): State<Arc<AuthService>>, Path(id): Path<String>) -> Response {
    match svc.control.get_project(&id) {
        Ok(Some(_)) => {}
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "project not found"),
        Err(e) => {
            warn!(project = %id, error = %e, "auth: get_project failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "lookup failed");
        }
    }
    match svc.control.get_jwks(&id, auth::timestamp()) {
        Ok(set) => ([(header::CACHE_CONTROL, "public, max-age=300")], Json(set)).into_response(),
        Err(e) => {
            warn!(project = %id, error = %e, "auth: get_jwks failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "jwks unavailable")
        }
    }
}

#[derive(Deserialize)]
struct MintRequest {
    /// The end-user subject the tenant's backend has authenticated (becomes `sub`).
    sub: String,
    /// Token audience; defaults to the project id.
    #[serde(default)]
    aud: Option<String>,
    /// Requested lifetime (seconds); clamped to [MIN, MAX].
    #[serde(default)]
    ttl: Option<u64>,
    /// Opaque custom claims (nested under the token's `claims` so they can't shadow registered ones).
    #[serde(default)]
    claims: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct MintResponse {
    token: String,
    exp: u64,
    kid: String,
}

/// Mint a per-end-user JWT for the tenant's backend. Auth = the project's `jkbk_` issuer key
/// (Bearer). The mint is gated by, in order: valid key → key's project == path project (P0-AUTH-6)
/// → current-owner re-bind (P0-AUTH-3) → per-key rate limit (P0-AUTH-7). Then the project's signing
/// key is lazily provisioned and used to sign.
async fn mint_token(
    State(svc): State<Arc<AuthService>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MintRequest>,
) -> Response {
    let Some(secret) = bearer(&headers) else {
        return json_error(StatusCode::UNAUTHORIZED, "missing issuer key");
    };
    let key = match svc.control.lookup_issuer_key_by_secret(&secret) {
        Ok(Some(k)) => k,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, "invalid issuer key"),
        Err(e) => {
            warn!(error = %e, "auth: issuer-key lookup failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "auth unavailable");
        }
    };
    // P0-AUTH-6: the project comes from the KEY (authoritative); the path id is only cross-checked.
    // The caller already proved they hold a valid key for `key.project_id`, so revealing the
    // mismatch is not a probe.
    if key.project_id != id {
        return json_error(
            StatusCode::FORBIDDEN,
            "issuer key not valid for this project",
        );
    }
    // P0-AUTH-3: the key's tenant must STILL own the project (fail-closed if deleted/transferred —
    // an orphaned key from a crash-interrupted teardown can't be inherited by a new owner).
    match svc.control.get_project(&id) {
        Ok(Some(p))
            if !key.tenant_id.is_empty()
                && p.tenant_id.as_deref() == Some(key.tenant_id.as_str()) => {}
        Ok(_) => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "issuer key not valid for the current project owner",
            );
        }
        Err(e) => {
            warn!(project = %id, error = %e, "auth: owner re-bind lookup failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "lookup failed");
        }
    }
    // P0-AUTH-7: throttle per issuer key (only reachable by a VALID key, so the bucket map can't be
    // flooded by bogus secrets).
    if !svc.limiter.allow(&key.key_id) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }
    // Validate + bound the tenant-supplied inputs.
    let sub = body.sub.trim();
    if sub.is_empty() || sub.len() > MAX_SUB_LEN {
        return json_error(StatusCode::BAD_REQUEST, "invalid sub");
    }
    if let Some(claims) = &body.claims {
        let size = serde_json::to_vec(claims)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if size > MAX_CLAIMS_BYTES {
            return json_error(StatusCode::BAD_REQUEST, "claims too large");
        }
    }

    let now = auth::timestamp();
    let signer = match svc.control.ensure_signing_key(&id, now) {
        Ok(s) => s,
        Err(e) => {
            warn!(project = %id, error = %e, "auth: ensure_signing_key failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "signing key unavailable");
        }
    };
    let ttl = body
        .ttl
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
    let exp = now + ttl;
    let claims = Claims {
        iss: format!("https://{}/v1/projects/{}", svc.public_host, id),
        sub: sub.to_string(),
        aud: body.aud.unwrap_or_else(|| id.clone()),
        iat: now,
        exp,
        jti: auth::generate_id(),
        claims: body.claims,
    };
    match signer.sign(&claims) {
        Ok(token) => Json(MintResponse {
            token,
            exp,
            kid: signer.kid().to_string(),
        })
        .into_response(),
        Err(e) => {
            warn!(project = %id, error = %e, "auth: sign failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "sign failed")
        }
    }
}

/// A per-key token-bucket rate limiter. Keyed by issuer-key id; the map only ever grows for VALID
/// keys (a bogus secret 401s before reaching here), and idle-full buckets are pruned when the map
/// grows, so memory is bounded.
struct MintRateLimiter {
    rate_per_sec: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl MintRateLimiter {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            rate_per_sec,
            burst,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Consume one token for `key_id`; `false` if the bucket is empty (rate-limited).
    fn allow(&self, key_id: &str) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        // Bound memory: if the map has grown large, drop buckets that have refilled to full (idle).
        if map.len() > 10_000 {
            let (rate, burst) = (self.rate_per_sec, self.burst);
            map.retain(|_, b| {
                let refilled = b.tokens + now.duration_since(b.last).as_secs_f64() * rate;
                refilled < burst
            });
        }
        let b = map.entry(key_id.to_string()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rate_per_sec).min(self.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::jose::{self, VerifyOptions};
    use jkbase_control::store::{Project, ProjectState};

    #[test]
    fn rate_limiter_allows_burst_then_throttles() {
        let lim = MintRateLimiter::new(0.0, 3.0); // no refill, burst 3
        assert!(lim.allow("k"));
        assert!(lim.allow("k"));
        assert!(lim.allow("k"));
        assert!(!lim.allow("k")); // 4th in the same instant is throttled
        // A different key has its own bucket.
        assert!(lim.allow("other"));
    }

    fn tmp_store() -> Store {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("jkbase-auth-svc-test-{nanos}.redb"));
        Store::open(&path).unwrap()
    }

    fn seed_project(store: &Store, id: &str, tenant: &str) {
        store
            .create_project(&Project {
                id: id.to_string(),
                name: id.to_string(),
                tenant_id: Some(tenant.to_string()),
                current_version: None,
                state: ProjectState::Active,
                vm_ip: None,
                domains: vec![],
            })
            .unwrap();
    }

    async fn spawn(store: Store) -> String {
        let svc = Arc::new(AuthService::new(store, "auth.jkbase.app".to_string()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, svc.into_router()).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// The full P3c seam over real HTTP: mint via the issuer key → fetch JWKS → verify offline.
    #[tokio::test]
    async fn mint_jwks_and_offline_verify_roundtrip() {
        let store = tmp_store();
        seed_project(&store, "proj", "tenantA");
        let (_rec, secret) = store.create_issuer_key("proj", "tenantA", "web").unwrap();
        let base = spawn(store).await;
        let http = reqwest::Client::new();

        // Mint a token for an end-user.
        let resp = http
            .post(format!("{base}/v1/projects/proj/token"))
            .bearer_auth(&secret)
            .json(&serde_json::json!({ "sub": "end-user-1", "claims": { "role": "admin" } }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let minted: serde_json::Value = resp.json().await.unwrap();
        let token = minted["token"].as_str().unwrap().to_string();
        assert_eq!(minted["kid"], "proj.0");

        // Fetch the published JWKS (anonymous).
        let jwks: jose::Jwks = http
            .get(format!("{base}/v1/projects/proj/.well-known/jwks.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(jwks.keys.len(), 1);

        // Verify the token offline against the JWKS, pinning iss + aud.
        let now = jkbase_control::auth::timestamp();
        let v = jose::verify(
            &token,
            &jwks,
            &VerifyOptions::at(now)
                .expect_iss("https://auth.jkbase.app/v1/projects/proj")
                .expect_aud("proj"),
        )
        .unwrap();
        assert_eq!(v.claims.sub, "end-user-1");
        assert_eq!(v.claims.claims.unwrap()["role"], "admin");
    }

    /// Fail-closed HTTP surface: bad bearer, cross-project mint, unknown-project JWKS.
    #[tokio::test]
    async fn mint_fails_closed_on_bad_auth_and_scope() {
        let store = tmp_store();
        seed_project(&store, "proj", "tenantA");
        seed_project(&store, "other", "tenantB");
        let (_r, secret) = store.create_issuer_key("proj", "tenantA", "web").unwrap();
        let base = spawn(store).await;
        let http = reqwest::Client::new();

        let post = |path: &str, bearer: Option<String>| {
            let mut rb = http
                .post(format!("{base}{path}"))
                .json(&serde_json::json!({ "sub": "u" }));
            if let Some(b) = bearer {
                rb = rb.bearer_auth(b);
            }
            rb.send()
        };

        // No bearer → 401.
        assert_eq!(
            post("/v1/projects/proj/token", None)
                .await
                .unwrap()
                .status(),
            401
        );
        // Bogus bearer → 401.
        assert_eq!(
            post("/v1/projects/proj/token", Some("jkbk_nope".into()))
                .await
                .unwrap()
                .status(),
            401
        );
        // Valid key but wrong project in the path → 403 (P0-AUTH-6).
        assert_eq!(
            post("/v1/projects/other/token", Some(secret.clone()))
                .await
                .unwrap()
                .status(),
            403
        );
        // JWKS for a nonexistent project → 404.
        assert_eq!(
            http.get(format!("{base}/v1/projects/ghost/.well-known/jwks.json"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        // JWKS for an existing but unprovisioned project → 200 with an empty set.
        let empty: jose::Jwks = http
            .get(format!("{base}/v1/projects/other/.well-known/jwks.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(empty.keys.is_empty());
    }
}
