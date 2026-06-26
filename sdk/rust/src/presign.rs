//! Presigned URLs — time-limited, credential-free GET and PUT links anyone can use until
//! they expire (the server caps the lifetime at 7 days; `0` or `>604800` is rejected).

use crate::{ObjectClient, Result, object_path, validate_object_key};
use std::time::{SystemTime, UNIX_EPOCH};

impl ObjectClient {
    /// A presigned GET URL valid for `expires_secs`, usable with no auth header. Errors on a
    /// key with a `.`/`..` segment (the minted URL would normalize away from its signature).
    pub fn presigned_get(&self, bucket: &str, key: &str, expires_secs: u64) -> Result<String> {
        validate_object_key(key)?;
        Ok(self.presigned("GET", bucket, key, expires_secs, now_unix()))
    }

    /// A presigned PUT URL valid for `expires_secs` — hand it out so a client can upload
    /// directly. The uploader sends the bytes as the request body (no extra headers). Same
    /// key restriction as [`presigned_get`](Self::presigned_get).
    pub fn presigned_put(&self, bucket: &str, key: &str, expires_secs: u64) -> Result<String> {
        validate_object_key(key)?;
        Ok(self.presigned("PUT", bucket, key, expires_secs, now_unix()))
    }

    /// Mint a presigned URL at a fixed time — test-only, so the cross-vector test can pin
    /// the timestamp against the shared SigV4 vectors. Not part of the public API: the
    /// public `presigned_get`/`presigned_put` (which validate the key) are the only minters.
    #[cfg(test)]
    pub(crate) fn presigned_at(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        expires_secs: u64,
        now_unix: u64,
    ) -> String {
        self.presigned(method, bucket, key, expires_secs, now_unix)
    }

    fn presigned(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        expires_secs: u64,
        now_unix: u64,
    ) -> String {
        let signed = jkbase_sigv4::presign(
            method,
            self.host(),
            &object_path(bucket, key),
            self.access_key(),
            self.secret(),
            self.region(),
            expires_secs,
            now_unix,
        );
        format!("{}{signed}", self.base_url())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
