use anyhow::Result;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub token_hash: String,
    pub created_at: u64,
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "jkb_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

pub fn generate_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Mint a per-project git-push token (the Basic-auth password `git push` sends).
/// Distinct `jkbg_` prefix so it can't be confused with a tenant API token, and
/// 256 bits of entropy so it's safe to index by a fast hash (see
/// [`token_fingerprint`]).
pub fn generate_git_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "jkbg_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Mint an S3 access-key id — the PUBLIC identifier a tenant puts in their SDK
/// config. It travels in the SigV4 `Credential` scope (`{akid}/{date}/...`), which
/// splits on `/`, so it must stay `/`-free: uppercase hex keeps it `[A-Z0-9]` and
/// AWS-AKID-shaped (20 chars) for SDK familiarity. 64 bits of entropy — it's only
/// an identifier, not a secret.
pub fn generate_access_key_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(20);
    s.push_str("JKBA");
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Mint an S3 secret access key (240 bits). Used ONLY as SigV4 HMAC key material —
/// it never appears in a URL, so URL-safe base64 is for tenant copy/paste ergonomics
/// rather than correctness. Shown once at creation and stored at rest in the control
/// db (it must be recoverable to verify signatures, unlike argon2'd passwords).
pub fn generate_secret_access_key() -> String {
    let mut bytes = [0u8; 30];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Mint a managed-DB access-key id — the PUBLIC identifier the reach-plane preamble
/// carries (`{akid, secret}`). A distinct `JKBD` prefix (vs the S3 `JKBA`) keeps the DB
/// keyspace visibly separate; combined with a separate control-db table this is the
/// [R2] partition — an S3 key can never resolve on the DB path and vice versa. 64 bits
/// of entropy: it's an identifier, not a secret. `[A-Z0-9]`, 20 chars, AKID-shaped.
pub fn generate_db_access_key_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(20);
    s.push_str("JKBD");
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Mint a managed-DB access-key secret (240 bits). UNLIKE the S3 secret it is NEVER
/// stored — only its [`token_fingerprint`] is — so the high entropy makes the sha256
/// preimage-safe (the git-token rationale). Distinct `jkbd_` prefix so a leaked secret
/// is self-identifying and can't be mistaken for a git (`jkbg_`) or tenant (`jkb_`) token.
/// Shown once at mint.
pub fn generate_db_secret() -> String {
    let mut bytes = [0u8; 30];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "jkbd_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Mint a managed-DB reach-plane **splice secret** (256-bit) — the per-deploy host→agent
/// shared secret the edge presents on `/_jkbase/db` and the in-VM agent verifies before
/// splicing ([R3]). Distinct `jkbs_` prefix so a leaked value is self-identifying. Stored
/// host-side (control db + the per-VM metadata image), never tenant-facing.
pub fn generate_splice_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "jkbs_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Mint a per-deploy rhypedb admin bearer (256-bit) — the `RHYPEDB_ADMIN_TOKEN` the agent
/// injects into the DB's process env to authorize `/admin/*` (backup stream) over loopback.
/// Distinct `jkba_` prefix so a leaked value is self-identifying (vs the `jkbs_` splice
/// secret). Stored host-side (control db + the per-VM metadata image), never tenant-facing,
/// rotated every deploy so a leak dies at the next deploy ([RB1]).
pub fn generate_rhypedb_admin_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "jkba_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// SHA-256 (hex) fingerprint of a high-entropy token, used to store and look up
/// the per-project git-push token WITHOUT keeping the plaintext. A 256-bit random
/// token makes SHA-256 preimage-resistant (unlike a low-entropy password, which
/// needs argon2), and a single keyed lookup by fingerprint avoids the argon2
/// full-table scan that `authenticate` does — which would be a DoS amplifier on
/// the unauthenticated, attacker-reachable git endpoint.
pub fn token_fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Const-time check that `presented_secret` hashes to `stored_fingerprint`
/// (`sha256` hex). Compares the two 64-byte digests with an XOR accumulator so it
/// can't leak, via early-exit timing, how many leading digest bytes matched — the same
/// discipline the git-push and webhook paths use. Used to verify a managed-DB
/// access-key secret against its at-rest fingerprint without storing the secret.
pub fn fingerprint_eq(presented_secret: &str, stored_fingerprint: &str) -> bool {
    let computed = token_fingerprint(presented_secret);
    let (a, b) = (computed.as_bytes(), stored_fingerprint.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn hash_token(token: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash token: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_token(token: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed)
        .is_ok()
}

pub fn hash_password(password: &str) -> Result<String> {
    hash_token(password)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    verify_token(password, hash)
}

pub fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Unix time in milliseconds — used where sub-second ordering matters (e.g. the managed-DB
/// backup catalog's `created_at_ms`).
pub fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Mint a managed-DB backup id: `bkp_<unix_ms>_<8 hex>`. Time-prefixed so ids sort by age,
/// with random entropy so two backups in the same millisecond don't collide. Only
/// `[a-z0-9_]`, so it is a safe object-store key component (`{project_id}/{backup_id}.tar`).
pub fn generate_backup_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(16);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("bkp_{}_{}", timestamp_ms(), hex)
}
