//! Push-webhook verification for the connected-repo build trigger (build · D).
//!
//! A connected repo (or the CLI) POSTs to `/projects/{id}/hooks/push` with a
//! timestamp and an HMAC-SHA256 signature over `"{timestamp}.{body}"` (Stripe
//! style), so tampering the body OR the timestamp invalidates the signature, and a
//! bounded timestamp-skew window blocks replay. Secrets are a SET (current +
//! not-yet-expired previous) so they rotate without a flag-day.
//!
//! This is the security core only; the route, the per-project secret store, and
//! the shallow-clone-inside-the-build-VM are the integration steps that wire it
//! onto the control plane.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq)]
pub enum WebhookError {
    /// The timestamp is outside the allowed skew window (likely a replay).
    TimestampSkew,
    /// The signature did not match any configured secret.
    SignatureMismatch,
}

/// Verifies push webhooks against a rotating set of secrets + a replay window.
pub struct WebhookVerifier {
    secrets: Vec<String>,
    max_skew_secs: u64,
}

impl WebhookVerifier {
    /// `secrets`: the currently-valid secrets (current + any not-yet-expired
    /// previous, for rotation). `max_skew_secs`: the anti-replay window.
    pub fn new(secrets: Vec<String>, max_skew_secs: u64) -> Self {
        Self {
            secrets,
            max_skew_secs,
        }
    }

    /// Verify a push: the timestamp must be within the skew window of `now`, and
    /// the signature must match one of the configured secrets.
    pub fn verify(
        &self,
        body: &[u8],
        signature_hex: &str,
        timestamp: u64,
        now: u64,
    ) -> Result<(), WebhookError> {
        if now.abs_diff(timestamp) > self.max_skew_secs {
            return Err(WebhookError::TimestampSkew);
        }
        let payload = signed_payload(timestamp, body);
        for secret in &self.secrets {
            let expected = hex(&hmac(secret.as_bytes(), &payload));
            if ct_eq(expected.as_bytes(), signature_hex.as_bytes()) {
                return Ok(());
            }
        }
        Err(WebhookError::SignatureMismatch)
    }
}

/// The signature a sender (CLI / forge) must present for `body` at `timestamp`.
pub fn sign(secret: &str, timestamp: u64, body: &[u8]) -> String {
    hex(&hmac(secret.as_bytes(), &signed_payload(timestamp, body)))
}

fn signed_payload(timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut v = format!("{timestamp}.").into_bytes();
    v.extend_from_slice(body);
    v
}

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

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn sign_then_verify_round_trips() {
        let v = WebhookVerifier::new(vec!["s3cr3t".into()], 300);
        let body = br#"{"ref":"refs/heads/main"}"#;
        let sig = sign("s3cr3t", NOW, body);
        assert_eq!(v.verify(body, &sig, NOW, NOW + 5), Ok(()));
    }

    #[test]
    fn tampered_body_or_timestamp_rejected() {
        let v = WebhookVerifier::new(vec!["s".into()], 300);
        let sig = sign("s", NOW, b"payload");
        // Body tampered.
        assert_eq!(
            v.verify(b"PAYLOAD", &sig, NOW, NOW),
            Err(WebhookError::SignatureMismatch)
        );
        // Timestamp tampered (it's bound into the signed payload).
        assert_eq!(
            v.verify(b"payload", &sig, NOW + 1, NOW + 1),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn replay_outside_window_rejected() {
        let v = WebhookVerifier::new(vec!["s".into()], 300);
        let sig = sign("s", NOW, b"x");
        assert_eq!(
            v.verify(b"x", &sig, NOW, NOW + 301),
            Err(WebhookError::TimestampSkew)
        );
    }

    #[test]
    fn rotation_accepts_previous_secret_only_while_listed() {
        let sig = sign("old-secret", NOW, b"x");
        // During rotation both secrets are listed -> old signature still valid.
        let v = WebhookVerifier::new(vec!["new-secret".into(), "old-secret".into()], 300);
        assert_eq!(v.verify(b"x", &sig, NOW, NOW), Ok(()));
        // Once the old secret is retired, the same signature is rejected.
        let v2 = WebhookVerifier::new(vec!["new-secret".into()], 300);
        assert_eq!(
            v2.verify(b"x", &sig, NOW, NOW),
            Err(WebhookError::SignatureMismatch)
        );
    }
}
