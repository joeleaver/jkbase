//! jkbase-Auth crypto core — per-project **EdDSA (Ed25519) JWT** issuing + verification and
//! per-project **JWKS** (RFC 7517) emission. This is the expensive, hard-to-change part of P3
//! (`docs/managed-rhypedb-p3-design.md` §3, §5.1); it is deliberately **clock-free** (callers pass
//! `now`/`iat`/`exp`) so the whole surface is unit-testable without a wall clock, and it is the ONE
//! place the net-new asymmetric crypto lives.
//!
//! Invariants it enforces (P0-AUTH-*):
//! - **P0-AUTH-2** — a [`SigningKeypair`] holds the 32-byte private *seed*; only [`SigningKeypair::jwk`]
//!   (the public key) is ever exported. The seed stays host-side; callers persist it in the control
//!   store, never in a VM.
//! - **P0-AUTH-5** — [`verify`] **pins `alg = EdDSA`** and `kty = OKP / crv = Ed25519`, reading the key
//!   from the trusted JWKS by `kid` and IGNORING any algorithm the attacker-supplied token header
//!   claims. This is the classic JWT break (`alg:none`, `HS256`-substitution) closed by construction.
//! - **P0-AUTH-8** — every failure path returns [`VerifyError`] (fail-closed): unknown `kid`, bad key,
//!   bad signature, expired, not-yet-valid, `iss`/`aud` mismatch, or any malformed segment.
//!
//! The token/JWKS wire formats are hand-rolled on `serde_json` + base64url (`URL_SAFE_NO_PAD`),
//! both already in the tree; the only new dependency is `ed25519-dalek` for keygen/sign/verify.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The only JWS algorithm we mint or accept. Pinned at verify time (P0-AUTH-5).
pub const ALG_EDDSA: &str = "EdDSA";

/// A per-project Ed25519 signing keypair. The `seed` is the 32-byte private key material — it is
/// recoverable at rest in the control store (host-only) and NEVER exported; only [`Self::jwk`]
/// (the public key) leaves the host (P0-AUTH-2). `kid` is `"{project_id}.{serial}"`.
#[derive(Clone)]
pub struct SigningKeypair {
    kid: String,
    seed: [u8; 32],
    public: [u8; 32],
}

impl SigningKeypair {
    /// Build from a caller-supplied 32-byte seed (the store persists exactly these bytes). Deriving
    /// the public key here means the persisted record can hold only the seed and still round-trip.
    pub fn from_seed(kid: impl Into<String>, seed: [u8; 32]) -> Self {
        let dalek = DalekSigningKey::from_bytes(&seed);
        let public = dalek.verifying_key().to_bytes();
        Self {
            kid: kid.into(),
            seed,
            public,
        }
    }

    /// The 32-byte private seed — for the store to persist (host-only). Not exposed off-host.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public [`Jwk`] for this key — safe to publish in a project's JWKS.
    pub fn jwk(&self) -> Jwk {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            use_: "sig".into(),
            alg: ALG_EDDSA.into(),
            kid: self.kid.clone(),
            x: B64.encode(self.public),
        }
    }

    /// Sign `claims` into a compact EdDSA JWT (`b64(header).b64(claims).b64(sig)`). The header pins
    /// `alg=EdDSA` and carries this key's `kid` so a verifier can select the right JWK.
    pub fn sign(&self, claims: &Claims) -> Result<String, SignError> {
        let header = Header {
            alg: ALG_EDDSA.into(),
            typ: "JWT".into(),
            kid: self.kid.clone(),
        };
        let header_b64 = B64.encode(serde_json::to_vec(&header).map_err(|_| SignError::Encode)?);
        let claims_b64 = B64.encode(serde_json::to_vec(claims).map_err(|_| SignError::Encode)?);
        let signing_input = format!("{header_b64}.{claims_b64}");
        let dalek = DalekSigningKey::from_bytes(&self.seed);
        let sig: Signature = dalek.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", B64.encode(sig.to_bytes())))
    }
}

/// The JOSE header we emit. `kid` selects the verifying key; `alg` is always `EdDSA`.
#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: String,
    kid: String,
}

/// Registered + custom claims. The registered fields are set by the issuer and cannot be forged by
/// a tenant; any tenant-supplied custom claims live NESTED under [`Claims::claims`] so they can
/// never shadow `iss`/`aud`/`exp`/`sub` (design doc §3). P4's rules read `sub` (=`request.auth.uid`)
/// and `claims.*` (=`request.auth.claims.*`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    /// Opaque tenant-supplied custom claims (namespaced so they can't shadow registered claims).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

/// A single public JWK (RFC 7517, OKP/Ed25519).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    /// Serialized as the reserved JWK member name `use`.
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kid: String,
    /// base64url(no-pad) of the 32-byte Ed25519 public key.
    pub x: String,
}

impl Jwk {
    /// Decode `x` into a strict Ed25519 verifying key (validates the point). Also enforces the
    /// OKP/Ed25519 key type so a JWK of the wrong family can't be coerced into an Ed25519 verify.
    fn verifying_key(&self) -> Result<VerifyingKey, VerifyError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(VerifyError::BadKey);
        }
        let raw = B64
            .decode(self.x.as_bytes())
            .map_err(|_| VerifyError::BadKey)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| VerifyError::BadKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| VerifyError::BadKey)
    }
}

/// A project's published key set. Holds the CURRENT key plus any rotating-out keys still inside the
/// overlap window (P0-AUTH-4), so a token minted just before a rotation still verifies.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Verification policy. `iss`/`aud` are checked only when supplied (a JWKS-only verifier may not
/// know them); `leeway_secs` bounds clock skew for both `exp` and `iat`.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub now: u64,
    pub leeway_secs: u64,
    pub expected_iss: Option<String>,
    pub expected_aud: Option<String>,
}

impl VerifyOptions {
    /// A permissive-but-safe default: 60s skew, no iss/aud pinning (caller sets those when known).
    pub fn at(now: u64) -> Self {
        Self {
            now,
            leeway_secs: 60,
            expected_iss: None,
            expected_aud: None,
        }
    }
    pub fn expect_iss(mut self, iss: impl Into<String>) -> Self {
        self.expected_iss = Some(iss.into());
        self
    }
    pub fn expect_aud(mut self, aud: impl Into<String>) -> Self {
        self.expected_aud = Some(aud.into());
        self
    }
}

/// A validated token: the `kid` that signed it and its decoded claims.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub kid: String,
    pub claims: Claims,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Not three base64url segments, or a segment failed to decode/parse.
    Malformed,
    /// Header `alg` is not `EdDSA` (rejects `none` and alg-substitution) — P0-AUTH-5.
    UnsupportedAlg,
    /// No JWK in the project's JWKS matched the header `kid`.
    UnknownKid,
    /// The JWK is not a usable OKP/Ed25519 public key.
    BadKey,
    /// Signature did not verify against the selected key.
    BadSignature,
    /// `now > exp + leeway`.
    Expired,
    /// `iat > now + leeway` (token minted implausibly in the future).
    NotYetValid,
    IssuerMismatch,
    AudienceMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VerifyError::Malformed => "malformed token",
            VerifyError::UnsupportedAlg => "unsupported alg (only EdDSA accepted)",
            VerifyError::UnknownKid => "unknown key id",
            VerifyError::BadKey => "unusable verifying key",
            VerifyError::BadSignature => "bad signature",
            VerifyError::Expired => "token expired",
            VerifyError::NotYetValid => "token not yet valid",
            VerifyError::IssuerMismatch => "issuer mismatch",
            VerifyError::AudienceMismatch => "audience mismatch",
        })
    }
}
impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    Encode,
}
impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed to encode token")
    }
}
impl std::error::Error for SignError {}

/// Verify a compact JWT against `jwks` under `opts`, **fail-closed** (P0-AUTH-8). The algorithm is
/// pinned to EdDSA and the key is chosen from the trusted JWKS by `kid` — the token header's `alg`
/// is used ONLY to reject anything that isn't `EdDSA`, never to select the verification scheme
/// (P0-AUTH-5). The signature is checked over the exact received `header.claims` bytes (no
/// re-encoding) with `verify_strict` (rejects the small-order/malleable edge cases).
pub fn verify(
    token: &str,
    jwks: &Jwks,
    opts: &VerifyOptions,
) -> Result<VerifiedToken, VerifyError> {
    let mut parts = token.split('.');
    let (header_b64, claims_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(c), Some(s), None) if !h.is_empty() && !c.is_empty() => (h, c, s),
            _ => return Err(VerifyError::Malformed),
        };

    let header: Header = decode_json(header_b64).ok_or(VerifyError::Malformed)?;
    // Pin the algorithm BEFORE touching the key or signature (P0-AUTH-5).
    if header.alg != ALG_EDDSA {
        return Err(VerifyError::UnsupportedAlg);
    }

    let jwk = jwks.find(&header.kid).ok_or(VerifyError::UnknownKid)?;
    let vk = jwk.verifying_key()?;

    let sig_bytes = B64
        .decode(sig_b64.as_bytes())
        .map_err(|_| VerifyError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::Malformed)?;

    let signing_input = format!("{header_b64}.{claims_b64}");
    vk.verify_strict(signing_input.as_bytes(), &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    // Signature is good — now the claims can be trusted enough to parse and time/scope-check.
    let claims: Claims = decode_json(claims_b64).ok_or(VerifyError::Malformed)?;
    if opts.now > claims.exp.saturating_add(opts.leeway_secs) {
        return Err(VerifyError::Expired);
    }
    if claims.iat > opts.now.saturating_add(opts.leeway_secs) {
        return Err(VerifyError::NotYetValid);
    }
    if let Some(iss) = &opts.expected_iss
        && &claims.iss != iss
    {
        return Err(VerifyError::IssuerMismatch);
    }
    if let Some(aud) = &opts.expected_aud
        && &claims.aud != aud
    {
        return Err(VerifyError::AudienceMismatch);
    }

    Ok(VerifiedToken {
        kid: header.kid,
        claims,
    })
}

fn decode_json<T: for<'de> Deserialize<'de>>(seg: &str) -> Option<T> {
    let raw = B64.decode(seg.as_bytes()).ok()?;
    serde_json::from_slice(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(kid: &str, seed_byte: u8) -> SigningKeypair {
        SigningKeypair::from_seed(kid, [seed_byte; 32])
    }

    fn claims(now: u64) -> Claims {
        Claims {
            iss: "https://auth.jkbase.app/v1/projects/proj".into(),
            sub: "user-42".into(),
            aud: "proj".into(),
            iat: now,
            exp: now + 3600,
            jti: "jti-abc".into(),
            claims: Some(serde_json::json!({ "role": "admin" })),
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let k = kp("proj.1", 7);
        let now = 1_000_000;
        let tok = k.sign(&claims(now)).unwrap();
        let jwks = Jwks::new(vec![k.jwk()]);
        let v = verify(&tok, &jwks, &VerifyOptions::at(now + 10)).unwrap();
        assert_eq!(v.kid, "proj.1");
        assert_eq!(v.claims.sub, "user-42");
        assert_eq!(v.claims.claims.unwrap()["role"], "admin");
    }

    #[test]
    fn iss_and_aud_pinning() {
        let k = kp("proj.1", 7);
        let now = 1_000_000;
        let tok = k.sign(&claims(now)).unwrap();
        let jwks = Jwks::new(vec![k.jwk()]);
        let ok = VerifyOptions::at(now)
            .expect_iss("https://auth.jkbase.app/v1/projects/proj")
            .expect_aud("proj");
        assert!(verify(&tok, &jwks, &ok).is_ok());
        assert_eq!(
            verify(&tok, &jwks, &VerifyOptions::at(now).expect_iss("other")).unwrap_err(),
            VerifyError::IssuerMismatch
        );
        assert_eq!(
            verify(&tok, &jwks, &VerifyOptions::at(now).expect_aud("other")).unwrap_err(),
            VerifyError::AudienceMismatch
        );
    }

    #[test]
    fn rejects_alg_none() {
        // Forge a token whose header claims alg:none, with an empty signature.
        let hdr = B64.encode(br#"{"alg":"none","typ":"JWT","kid":"proj.1"}"#);
        let now = 1_000_000u64;
        let payload = B64.encode(serde_json::to_vec(&claims(now)).unwrap());
        let forged = format!("{hdr}.{payload}.");
        let jwks = Jwks::new(vec![kp("proj.1", 7).jwk()]);
        assert_eq!(
            verify(&forged, &jwks, &VerifyOptions::at(now)).unwrap_err(),
            VerifyError::UnsupportedAlg
        );
    }

    #[test]
    fn rejects_alg_substitution_hs256() {
        // alg:HS256 with the public key bytes used as an HMAC secret — the classic confusion attack.
        // We must reject at the alg pin, never treat the token as HMAC.
        let hdr = B64.encode(br#"{"alg":"HS256","typ":"JWT","kid":"proj.1"}"#);
        let now = 1_000_000u64;
        let payload = B64.encode(serde_json::to_vec(&claims(now)).unwrap());
        let forged = format!("{hdr}.{payload}.AAAA");
        let jwks = Jwks::new(vec![kp("proj.1", 7).jwk()]);
        assert_eq!(
            verify(&forged, &jwks, &VerifyOptions::at(now)).unwrap_err(),
            VerifyError::UnsupportedAlg
        );
    }

    #[test]
    fn rejects_tampered_payload() {
        let k = kp("proj.1", 7);
        let now = 1_000_000;
        let tok = k.sign(&claims(now)).unwrap();
        let mut parts: Vec<&str> = tok.split('.').collect();
        // Swap the payload for a different (validly-signed-by-nobody) claim set.
        let mut evil = claims(now);
        evil.sub = "root".into();
        let evil_b64 = B64.encode(serde_json::to_vec(&evil).unwrap());
        parts[1] = &evil_b64;
        let tampered = parts.join(".");
        let jwks = Jwks::new(vec![k.jwk()]);
        assert_eq!(
            verify(&tampered, &jwks, &VerifyOptions::at(now)).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn rejects_unknown_kid_and_cross_project_key() {
        let signer = kp("projA.1", 7);
        let now = 1_000_000;
        let tok = signer.sign(&claims(now)).unwrap();
        // JWKS holds a DIFFERENT project's key under a different kid → unknown kid, fail-closed.
        let other = kp("projB.1", 9);
        let jwks = Jwks::new(vec![other.jwk()]);
        assert_eq!(
            verify(&tok, &jwks, &VerifyOptions::at(now)).unwrap_err(),
            VerifyError::UnknownKid
        );
        // Same kid but the wrong key material → bad signature (a forged JWKS entry can't validate).
        let impostor = Jwk {
            kid: "projA.1".into(),
            ..kp("projB.1", 9).jwk()
        };
        let jwks2 = Jwks::new(vec![impostor]);
        assert_eq!(
            verify(&tok, &jwks2, &VerifyOptions::at(now)).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn rejects_expired_and_future() {
        let k = kp("proj.1", 7);
        let now = 1_000_000;
        let tok = k.sign(&claims(now)).unwrap(); // exp = now+3600
        let jwks = Jwks::new(vec![k.jwk()]);
        // Well past exp+leeway.
        assert_eq!(
            verify(&tok, &jwks, &VerifyOptions::at(now + 3600 + 61)).unwrap_err(),
            VerifyError::Expired
        );
        // Verifier's clock is far behind iat → not yet valid.
        assert_eq!(
            verify(&tok, &jwks, &VerifyOptions::at(now - 3600)).unwrap_err(),
            VerifyError::NotYetValid
        );
        // Within leeway on both edges → ok.
        assert!(verify(&tok, &jwks, &VerifyOptions::at(now + 3600 + 30)).is_ok());
    }

    #[test]
    fn rotation_window_old_kid_still_verifies() {
        // A token minted under the previous key still verifies while its JWK stays in the set.
        let prev = kp("proj.1", 7);
        let cur = kp("proj.2", 11);
        let now = 1_000_000;
        let tok = prev.sign(&claims(now)).unwrap();
        let jwks = Jwks::new(vec![cur.jwk(), prev.jwk()]); // overlap window
        assert!(verify(&tok, &jwks, &VerifyOptions::at(now)).is_ok());
        // After the window closes (prev dropped) the same token no longer verifies.
        let closed = Jwks::new(vec![cur.jwk()]);
        assert_eq!(
            verify(&tok, &closed, &VerifyOptions::at(now)).unwrap_err(),
            VerifyError::UnknownKid
        );
    }

    #[test]
    fn malformed_shapes_rejected() {
        let jwks = Jwks::new(vec![kp("proj.1", 7).jwk()]);
        for bad in ["", "a.b", "a.b.c.d", "...", "notb64.notb64.notb64"] {
            assert!(verify(bad, &jwks, &VerifyOptions::at(1)).is_err());
        }
    }

    #[test]
    fn jwk_shape_is_rfc7517_okp() {
        let j = kp("proj.1", 7).jwk();
        assert_eq!(j.kty, "OKP");
        assert_eq!(j.crv, "Ed25519");
        assert_eq!(j.alg, "EdDSA");
        assert_eq!(j.use_, "sig");
        // `use` is the serialized member name.
        let v = serde_json::to_value(&j).unwrap();
        assert_eq!(v["use"], "sig");
        assert!(v.get("use_").is_none());
        // x decodes to 32 bytes.
        assert_eq!(B64.decode(j.x.as_bytes()).unwrap().len(), 32);
    }
}
