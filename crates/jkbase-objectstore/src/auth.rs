//! Tenant credentials for the object store: maps an S3 access-key id to the owning
//! tenant + its secret key (used by SigV4 verification). The control plane is the
//! source of truth for tenant access keys; this trait is the lookup seam, with a
//! static in-memory impl for tests + single-tenant setups.

use std::collections::HashMap;

/// A resolved credential: which tenant an access key belongs to + its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub tenant_id: String,
    pub secret_key: String,
}

/// Resolve an S3 access-key id to its tenant + secret.
pub trait Credentials: Send + Sync {
    fn resolve(&self, access_key: &str) -> Option<Credential>;
}

/// An in-memory credential set (tests + single-node/static deployments).
#[derive(Default)]
pub struct StaticCredentials {
    by_key: HashMap<String, Credential>,
}

impl StaticCredentials {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `access_key` -> (`tenant_id`, `secret_key`).
    pub fn with(
        mut self,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Self {
        self.by_key.insert(
            access_key.into(),
            Credential {
                tenant_id: tenant_id.into(),
                secret_key: secret_key.into(),
            },
        );
        self
    }
}

impl Credentials for StaticCredentials {
    fn resolve(&self, access_key: &str) -> Option<Credential> {
        self.by_key.get(access_key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_credentials_resolve() {
        let c = StaticCredentials::new()
            .with("AKIA1", "secret1", "tenant-a")
            .with("AKIA2", "secret2", "tenant-b");
        assert_eq!(
            c.resolve("AKIA1"),
            Some(Credential {
                tenant_id: "tenant-a".into(),
                secret_key: "secret1".into()
            })
        );
        assert_eq!(c.resolve("AKIA2").unwrap().tenant_id, "tenant-b");
        assert!(c.resolve("nope").is_none());
    }
}
