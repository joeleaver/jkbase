use anyhow::Result;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::SaltString;
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
