//! `build_ca` — the platform **build-mirror CA**.
//!
//! The package mirror TLS-terminates (MITM) traffic to package registries so the
//! egress proxy can serve cached, content-verified artifacts from one shared store
//! (cross-tenant dedup). To do that without the build tools screaming about an
//! untrusted cert, we run ONE shared self-signed CA:
//!
//!   * its **public cert** (`ca.crt`) is baked into the build-toolchain trust store
//!     (`/etc/ssl/certs/ca-certificates.crt`) at image-bake time — and ONLY there,
//!     never into any runtime image (invariant I-3);
//!   * its **private key** (`ca.key`) is a host-only secret at
//!     `{data_dir}/build-ca/ca.key` (0600), distributed to each mirror host like the
//!     bun asset; it NEVER touches a VM drive, boot arg, image, or log (I-1).
//!
//! At runtime the [`CertSigner`] mints a short-lived per-SNI leaf for each registry
//! host, signed by the CA key. The leaf is generated on first SNI hit and memoized.
//!
//! ## Persistence model (why we only persist the key)
//!
//! `rcgen::CertificateParams::signed_by` only reads the issuer's distinguished name,
//! key-identifier method, and key-usages off the issuer certificate — plus the issuer
//! key. All of those are fixed by [`ca_params`] / the CA key. So we persist only the
//! secret `ca.key`; the in-memory issuer certificate is **rebuilt** from the loaded
//! key on every start via `self_signed`. The rebuilt issuer has the same subject DN
//! and the same (key-derived) subject-key-identifier as the baked `ca.crt`, so leaves
//! it signs chain cleanly to the baked anchor — the rebuilt issuer's own validity
//! window is irrelevant (it is never the client's trust anchor; `ca.crt` is). This
//! avoids depending on rcgen's `x509-parser` feature to reload a CA cert.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

/// The registry hosts the mirror is allowed to TLS-terminate. EVERYTHING else —
/// git-over-https (github/gitlab), arbitrary hosts, the dockerfile allow-any proxy —
/// stays a blind CONNECT tunnel and is NEVER impersonated. This is both the egress
/// MITM gate and the CA's "hosts I will ever sign a leaf for" allowlist (I-4, I-7).
pub const MIRROR_HOSTS: &[&str] = &[
    "index.crates.io",
    "static.crates.io",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
];

/// Exact, case-insensitive, trailing-dot-tolerant membership in [`MIRROR_HOSTS`].
/// Never matches a subdomain or suffix — same discipline as the egress allowlist.
pub fn host_is_mirrorable(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    MIRROR_HOSTS.iter().any(|m| h.eq_ignore_ascii_case(m))
}

const CA_COMMON_NAME: &str = "jkbase build mirror CA";
const CA_ORG: &str = "jkbase";
/// CA validity: 10 years, anchored a day in the past for clock-skew tolerance.
const CA_VALID_DAYS: i64 = 3650;
/// Leaf validity: 30 days, anchored an hour in the past for skew tolerance.
const LEAF_VALID_DAYS: i64 = 30;

/// Fixed CA certificate parameters. MUST be deterministic in everything that
/// affects chaining (subject DN, key-usages, key-id method) so a rebuilt issuer
/// matches the baked `ca.crt` anchor.
fn ca_params() -> Result<CertificateParams> {
    let mut p = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, CA_ORG);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(CA_VALID_DAYS);
    Ok(p)
}

/// Per-SNI leaf parameters: a server-auth cert whose only SAN is the registry host.
fn leaf_params(sni: &str) -> Result<CertificateParams> {
    let mut p = CertificateParams::new(vec![sni.to_string()]).context("leaf params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, sni);
    p.distinguished_name = dn;
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::hours(1);
    p.not_after = now + Duration::days(LEAF_VALID_DAYS);
    Ok(p)
}

/// The loaded CA: the private key plus an in-memory issuer certificate rebuilt from
/// it. Holds no leaf state (that lives in [`CertSigner`]).
pub struct BuildCa {
    ca_key: KeyPair,
    issuer: Certificate,
}

impl BuildCa {
    /// Load `{dir}/ca.key` (generating + persisting a fresh CA if absent), then
    /// rebuild the in-memory issuer certificate. Always ensures `{dir}/ca.crt`
    /// exists on disk (the public cert the toolchain bake injects).
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create build-ca dir {}", dir.display()))?;
        let key_path = dir.join("ca.key");
        let crt_path = dir.join("ca.crt");

        let ca_key = if key_path.exists() {
            let pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("read {}", key_path.display()))?;
            KeyPair::from_pem(&pem).with_context(|| format!("parse {}", key_path.display()))?
        } else {
            let kp = KeyPair::generate().context("generate CA key")?;
            write_secret(&key_path, kp.serialize_pem().as_bytes())
                .with_context(|| format!("write {}", key_path.display()))?;
            kp
        };

        // Rebuild the issuer from the (loaded or new) key + the fixed params.
        let issuer = ca_params()?
            .self_signed(&ca_key)
            .context("self-sign CA issuer")?;

        // Materialize ca.crt for the bake step if it is not already present. Do NOT
        // overwrite an existing ca.crt — that one is the stable baked anchor.
        if !crt_path.exists() {
            write_public(&crt_path, issuer.pem().as_bytes())
                .with_context(|| format!("write {}", crt_path.display()))?;
        }

        Ok(Self { ca_key, issuer })
    }

    /// Sign a fresh leaf for `sni` and wrap it as a rustls [`CertifiedKey`].
    fn sign_leaf(&self, sni: &str) -> Result<Arc<CertifiedKey>> {
        let leaf_key = KeyPair::generate().context("generate leaf key")?;
        let leaf = leaf_params(sni)?
            .signed_by(&leaf_key, &self.issuer, &self.ca_key)
            .context("sign leaf")?;
        let cert_der = leaf.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let provider =
            CryptoProvider::get_default().context("no rustls crypto provider installed")?;
        let ck = CertifiedKey::from_der(vec![cert_der], key_der, provider)
            .context("assemble leaf CertifiedKey")?;
        Ok(Arc::new(ck))
    }
}

/// A rustls cert resolver that mints + memoizes one leaf per registry SNI, signed by
/// the [`BuildCa`]. SNIs outside [`MIRROR_HOSTS`] are refused (defense in depth — the
/// egress layer already only enters MITM for mirrorable CONNECT hosts).
pub struct CertSigner {
    ca: BuildCa,
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertSigner {
    pub fn new(ca: BuildCa) -> Self {
        Self {
            ca,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Build the shared rustls [`ServerConfig`] (one per process; per-SNI leaves are
    /// resolved lazily). Pins ALPN to `http/1.1` — the mirror speaks HTTP/1.1 only.
    pub fn into_server_config(self: Arc<Self>) -> Arc<ServerConfig> {
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self);
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    }

    /// Get-or-mint a leaf for `sni`. Returns `None` for non-mirrorable hosts.
    fn leaf_for(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        if !host_is_mirrorable(sni) {
            return None;
        }
        if let Some(ck) = self.cache.read().unwrap().get(sni).cloned() {
            return Some(ck);
        }
        let mut w = self.cache.write().unwrap();
        // Re-check under the write lock so concurrent first-hits collapse to one sign.
        if let Some(ck) = w.get(sni).cloned() {
            return Some(ck);
        }
        match self.ca.sign_leaf(sni) {
            Ok(ck) => {
                w.insert(sni.to_string(), ck.clone());
                Some(ck)
            }
            Err(e) => {
                tracing::error!(sni, error = %e, "build-mirror leaf signing failed");
                None
            }
        }
    }
}

impl std::fmt::Debug for CertSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertSigner").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertSigner {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        self.leaf_for(sni)
    }
}

/// Write a host-only secret with 0600 perms (owner read/write only).
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    // Belt-and-suspenders: tighten perms even if the file pre-existed.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Write a public artifact with 0644 perms.
fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn provider_installed() {
        // Tests share the process default provider; install once, ignore re-install.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-ca-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn host_membership_is_exact() {
        assert!(host_is_mirrorable("registry.npmjs.org"));
        assert!(host_is_mirrorable("REGISTRY.NPMJS.ORG"));
        assert!(host_is_mirrorable("static.crates.io."));
        assert!(!host_is_mirrorable("evil.registry.npmjs.org"));
        assert!(!host_is_mirrorable("registry.npmjs.org.evil.com"));
        assert!(!host_is_mirrorable("github.com"));
        assert!(!host_is_mirrorable("crates.io"));
    }

    #[test]
    fn generate_persists_key_0600_and_cert() {
        provider_installed();
        let dir = tmp("persist");
        let ca = BuildCa::load_or_generate(&dir).unwrap();
        let key_path = dir.join("ca.key");
        let crt_path = dir.join("ca.crt");
        assert!(key_path.exists() && crt_path.exists());
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ca.key must be host-only 0600");
        // A leaf can be minted from the fresh CA.
        assert!(ca.sign_leaf("registry.npmjs.org").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_reuses_persisted_key() {
        provider_installed();
        let dir = tmp("reload");
        let _ = BuildCa::load_or_generate(&dir).unwrap();
        let key1 = std::fs::read_to_string(dir.join("ca.key")).unwrap();
        let crt1 = std::fs::read_to_string(dir.join("ca.crt")).unwrap();
        // Reload: must NOT regenerate the key or rewrite the anchor cert.
        let _ = BuildCa::load_or_generate(&dir).unwrap();
        let key2 = std::fs::read_to_string(dir.join("ca.key")).unwrap();
        let crt2 = std::fs::read_to_string(dir.join("ca.crt")).unwrap();
        assert_eq!(key1, key2, "ca.key must be stable across reloads");
        assert_eq!(crt1, crt2, "ca.crt anchor must not change across reloads");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signer_memoizes_and_refuses_non_mirror() {
        provider_installed();
        let dir = tmp("signer");
        let ca = BuildCa::load_or_generate(&dir).unwrap();
        let signer = CertSigner::new(ca);
        let a = signer.leaf_for("registry.npmjs.org").unwrap();
        let b = signer.leaf_for("registry.npmjs.org").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same SNI must return the memoized leaf");
        assert!(signer.leaf_for("github.com").is_none());
        assert!(signer.leaf_for("evil.com").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // THE crux test: a client trusting the PERSISTED (gen-time) ca.crt must accept a
    // leaf signed at RUNTIME by an issuer rebuilt from the reloaded ca.key — proving
    // the "persist only the key, rebuild the issuer" model produces a valid chain.
    #[tokio::test]
    async fn reloaded_signer_chains_to_persisted_anchor() {
        provider_installed();
        let dir = tmp("handshake");
        // Generate, persisting ca.crt at gen-time validity.
        let _ = BuildCa::load_or_generate(&dir).unwrap();
        // Reload: rebuilds the issuer (different validity window) but reuses the key.
        let ca = BuildCa::load_or_generate(&dir).unwrap();
        let signer = Arc::new(CertSigner::new(ca));
        let server_cfg = signer.into_server_config();

        // Client trust anchor = the persisted gen-time ca.crt.
        let ca_pem = std::fs::read(dir.join("ca.crt")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
            roots.add(cert.unwrap()).unwrap();
        }
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let server = tokio::spawn(async move { acceptor.accept(server_io).await });
        let sni = rustls::pki_types::ServerName::try_from("registry.npmjs.org").unwrap();
        let client = tokio::spawn(async move { connector.connect(sni, client_io).await });

        let s = server.await.unwrap();
        let c = client.await.unwrap();
        assert!(s.is_ok(), "server handshake failed: {:?}", s.err());
        assert!(
            c.is_ok(),
            "client rejected runtime leaf against persisted anchor: {:?}",
            c.err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
