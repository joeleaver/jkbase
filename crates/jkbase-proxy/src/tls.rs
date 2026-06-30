//! TLS for the proxy.
//!
//! A single [`CertManager`] backs a dynamic rustls cert resolver:
//! - the `*.jkbase.app` + apex **wildcard** is provisioned via ACME DNS-01
//!   (Cloudflare) and held in memory so it can be renewed in place;
//! - **per-custom-domain** certs are issued on demand via ACME HTTP-01 (the
//!   proxy already owns port 80) and cached on disk under `certs/custom/<host>/`.
//!
//! Issuance for a custom host only happens when that host is an Active entry in
//! the shared domain map (i.e. ownership was verified) — never for arbitrary SNI.

use crate::DomainMap;
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::proto::op::ResponseCode;
use hickory_client::proto::rr::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_client::proto::rr::dnssec::tsig::TSigner;
use hickory_client::proto::rr::rdata::TXT;
use hickory_client::proto::rr::{Name, RData, Record};
use hickory_client::proto::udp::UdpClientStream;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock as AsyncRwLock;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tracing::{info, warn};

/// Renew a cert once it's within this window of (assumed 90-day) expiry. We track
/// age by file mtime rather than parsing the cert — simple and good enough.
const RENEW_AFTER: Duration = Duration::from_secs(60 * 24 * 60 * 60); // 60 days
/// How often the reconcile loop runs (wildcard renewal + custom issuance/retry).
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Don't re-attempt issuance for a host that failed within this window.
const ISSUE_BACKOFF: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct TlsConfig {
    pub domain: String,
    pub cert_dir: PathBuf,
    /// The ACME DNS-01 backend used to provision the wildcard cert (Cloudflare,
    /// RFC2136, …). Behind `Arc<dyn>` so the config stays cheap to clone and the
    /// vendor choice is made once at startup.
    pub dns_provider: Arc<dyn DnsProvider>,
    pub acme_email: String,
}

/// rustls cert resolver: picks a cert by SNI. Lives behind `Arc` and is shared
/// with the running `ServerConfig`; its certs are swapped in place on renewal.
#[derive(Debug)]
struct Resolver {
    platform_domain: String,
    wildcard: RwLock<Option<Arc<CertifiedKey>>>,
    /// The `*.db.{domain}` wildcard for the managed-DB reach plane. A SEPARATE slot
    /// because `*.{domain}` (one label) can't validate a two-label `<proj>.db.{domain}`
    /// host — the resolver serves this more-specific cert for `.db.{domain}` SNIs
    /// (longest-zone-first). `None` until provisioned, so DB ingress fails closed.
    db_wildcard: RwLock<Option<Arc<CertifiedKey>>>,
    hosts: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(sni) = hello.server_name() else {
            // SNI-less clients get the apex wildcard. The DB demux additionally requires
            // a present `.db.{domain}` SNI + the `jkbase-db` ALPN and drops anything
            // else before it can wake a VM ([R6]/[R7]), so serving the apex here is safe.
            return self.wildcard.read().unwrap().clone();
        };
        if let Some(ck) = self.hosts.read().unwrap().get(sni).cloned() {
            return Some(ck);
        }
        match classify_wildcard(sni, &self.platform_domain) {
            WildcardKind::Db => self.db_wildcard.read().unwrap().clone(),
            WildcardKind::Apex => self.wildcard.read().unwrap().clone(),
            // Known-but-not-yet-issued custom domain (or unknown SNI): fail cleanly.
            WildcardKind::None => None,
        }
    }
}

/// Which platform wildcard (if any) covers `sni`. The `.db.{domain}` zone is checked
/// FIRST (longest-zone-first): `<proj>.db.{domain}` ends with both `.db.{domain}` and
/// `.{domain}`, but only the dedicated `*.db.{domain}` cert validates its two labels.
#[derive(Debug, PartialEq, Eq)]
enum WildcardKind {
    Apex,
    Db,
    None,
}

fn classify_wildcard(sni: &str, platform_domain: &str) -> WildcardKind {
    if sni.ends_with(&format!(".db.{platform_domain}")) {
        WildcardKind::Db
    } else if sni == platform_domain || sni.ends_with(&format!(".{platform_domain}")) {
        WildcardKind::Apex
    } else {
        WildcardKind::None
    }
}

pub struct CertManager {
    cfg: TlsConfig,
    domains: DomainMap,
    account: Account,
    resolver: Arc<Resolver>,
    /// ACME HTTP-01 challenge responses: token → key authorization.
    challenges: Arc<AsyncRwLock<HashMap<String, String>>>,
    /// Last issuance attempt per host, for dedupe + failure backoff.
    inflight: Mutex<HashMap<String, Instant>>,
}

impl CertManager {
    /// Build the manager: load-or-create the ACME account, ensure the wildcard
    /// cert, and load any cached per-host certs. Blocks on wildcard provisioning
    /// (as the old startup path did) so HTTPS is ready before serving.
    pub async fn new(cfg: TlsConfig, domains: DomainMap, staging: bool) -> Result<Arc<Self>> {
        tokio::fs::create_dir_all(&cfg.cert_dir).await?;
        let account = obtain_account(&cfg, staging).await?;

        let resolver = Arc::new(Resolver {
            platform_domain: cfg.domain.clone(),
            wildcard: RwLock::new(None),
            db_wildcard: RwLock::new(None),
            hosts: RwLock::new(HashMap::new()),
        });

        let mgr = Arc::new(CertManager {
            cfg,
            domains,
            account,
            resolver,
            challenges: Arc::new(AsyncRwLock::new(HashMap::new())),
            inflight: Mutex::new(HashMap::new()),
        });

        mgr.ensure_wildcard().await?;
        // Best-effort: the platform (web hosting) must boot even if the DB-ingress cert
        // can't issue; reconcile retries. Failure leaves the db_wildcard slot None.
        mgr.ensure_db_wildcard().await;
        mgr.load_cached_hosts();
        Ok(mgr)
    }

    pub fn server_config(&self) -> Arc<ServerConfig> {
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self.resolver.clone());
        // Advertise the managed-DB reach-plane ALPN alongside `http/1.1` (the edge
        // speaks http1). The DB ingress demuxes on a negotiated `jkbase-db`; `http/1.1`
        // MUST be listed too — otherwise a normal client that offers ALPN with no
        // overlap would get a fatal `no_application_protocol` alert. Clients that send
        // no ALPN at all negotiate nothing and take the HTTP path exactly as before.
        cfg.alpn_protocols = vec![crate::db_preamble::DB_ALPN.to_vec(), b"http/1.1".to_vec()];
        Arc::new(cfg)
    }

    /// HTTP-01 challenge body for `token`, if one is currently outstanding.
    pub async fn challenge_response(&self, token: &str) -> Option<String> {
        self.challenges.read().await.get(token).cloned()
    }

    /// Whether a per-host certificate has been issued and loaded for `host`.
    pub fn has_cert(&self, host: &str) -> bool {
        self.resolver.hosts.read().unwrap().contains_key(host)
    }

    /// Provision/renew the wildcard cert if missing or near expiry, and load it
    /// into the resolver.
    async fn ensure_wildcard(&self) -> Result<()> {
        let cert_path = self.cfg.cert_dir.join("fullchain.pem");
        let key_path = self.cfg.cert_dir.join("privkey.pem");
        let have_cached = cert_path.exists() && key_path.exists();
        let fresh = have_cached && !needs_renewal(&cert_path);
        if !fresh {
            info!("provisioning wildcard certificate via ACME DNS-01");
            // Apex order: `{domain}` + `*.{domain}` both validate at the SAME challenge
            // name `_acme-challenge.{domain}`, so the order shares one challenge.
            let identifiers = [
                Identifier::Dns(self.cfg.domain.clone()),
                Identifier::Dns(format!("*.{}", self.cfg.domain)),
            ];
            let challenge = format!("_acme-challenge.{}", self.cfg.domain);
            if let Err(e) = self
                .provision_cert(&identifiers, &challenge, &cert_path, &key_path)
                .await
            {
                // Don't take the whole server down over a transient ACME/DNS error
                // if we already have a usable (if aging) cert; reconcile will retry.
                if have_cached {
                    warn!(error = %e, "wildcard provisioning failed; using existing cert, will retry");
                } else {
                    return Err(e)
                        .context("wildcard provisioning failed and no cached cert exists");
                }
            }
        }
        let ck = read_certified_key(&cert_path, &key_path)?;
        *self.resolver.wildcard.write().unwrap() = Some(Arc::new(ck));
        Ok(())
    }

    /// Provision/renew the `*.db.{domain}` wildcard for the managed-DB reach plane and
    /// load it into the resolver's `db_wildcard` slot. BEST-EFFORT: unlike the apex
    /// wildcard a failure must NOT down the platform — the slot stays `None` (a
    /// `.db.{domain}` handshake then fails closed) and reconcile retries.
    async fn ensure_db_wildcard(&self) {
        let cert_path = self.cfg.cert_dir.join("db-fullchain.pem");
        let key_path = self.cfg.cert_dir.join("db-privkey.pem");
        let have_cached = cert_path.exists() && key_path.exists();
        let fresh = have_cached && !needs_renewal(&cert_path);
        if !fresh {
            info!("provisioning *.db wildcard certificate via ACME DNS-01");
            // Single-SAN order — its one authorization validates at
            // `_acme-challenge.db.{domain}` (NOT the apex name).
            let identifiers = [Identifier::Dns(format!("*.db.{}", self.cfg.domain))];
            let challenge = format!("_acme-challenge.db.{}", self.cfg.domain);
            if let Err(e) = self
                .provision_cert(&identifiers, &challenge, &cert_path, &key_path)
                .await
            {
                if have_cached {
                    warn!(error = %e, "db wildcard provisioning failed; using existing cert, will retry");
                } else {
                    warn!(error = %e, "db wildcard provisioning failed; managed-DB ingress unavailable until it succeeds");
                    return;
                }
            }
        }
        match read_certified_key(&cert_path, &key_path) {
            Ok(ck) => *self.resolver.db_wildcard.write().unwrap() = Some(Arc::new(ck)),
            Err(e) => warn!(error = %e, "failed to load db wildcard cert"),
        }
    }

    fn load_cached_hosts(&self) {
        let dir = self.cfg.cert_dir.join("custom");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let host = entry.file_name().to_string_lossy().to_string();
            let cert = entry.path().join("fullchain.pem");
            let key = entry.path().join("privkey.pem");
            match read_certified_key(&cert, &key) {
                Ok(ck) => {
                    self.resolver
                        .hosts
                        .write()
                        .unwrap()
                        .insert(host.clone(), Arc::new(ck));
                    info!(host = %host, "loaded cached custom-domain certificate");
                }
                Err(e) => warn!(host = %host, error = %e, "failed to load cached cert"),
            }
        }
    }

    /// Whether we're allowed to issue for `host`: it must be an Active custom
    /// domain (present in the domain map and not a platform subdomain).
    async fn is_issuable(&self, host: &str) -> bool {
        if host == self.cfg.domain || host.ends_with(&format!(".{}", self.cfg.domain)) {
            return false; // covered by the wildcard
        }
        if !host.contains('.') {
            return false; // bare label = platform subdomain
        }
        self.domains.read().await.contains_key(host)
    }

    fn host_cert_fresh(&self, host: &str) -> bool {
        if !self.resolver.hosts.read().unwrap().contains_key(host) {
            return false;
        }
        let cert = self
            .cfg
            .cert_dir
            .join("custom")
            .join(host)
            .join("fullchain.pem");
        cert.exists() && !needs_renewal(&cert)
    }

    /// Ensure a valid cert exists for a verified custom `host`, issuing via
    /// HTTP-01 if needed. Best-effort, deduped, and backed off on failure.
    pub async fn ensure_cert(&self, host: &str) {
        if !self.is_issuable(host).await {
            return;
        }
        if self.host_cert_fresh(host) {
            return;
        }
        // Dedupe / backoff.
        {
            let mut inflight = self.inflight.lock().unwrap();
            if inflight
                .get(host)
                .is_some_and(|last| last.elapsed() < ISSUE_BACKOFF)
            {
                return;
            }
            inflight.insert(host.to_string(), Instant::now());
        }

        info!(host = %host, "issuing custom-domain certificate via ACME HTTP-01");
        match self.issue_http01(host).await {
            Ok(ck) => {
                self.resolver
                    .hosts
                    .write()
                    .unwrap()
                    .insert(host.to_string(), Arc::new(ck));
                info!(host = %host, "custom-domain certificate issued");
            }
            Err(e) => warn!(host = %host, error = %e, "custom-domain issuance failed (will retry)"),
        }
    }

    async fn issue_http01(&self, host: &str) -> Result<CertifiedKey> {
        let mut order = self
            .account
            .new_order(&NewOrder::new(&[Identifier::Dns(host.to_string())]))
            .await
            .context("failed to create ACME order")?;

        let mut tokens: Vec<String> = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut auth = result.context("failed to get authorization")?;
                let mut challenge = auth
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| anyhow::anyhow!("no HTTP-01 challenge offered"))?;
                let token = challenge.token.clone();
                let key_auth = challenge.key_authorization().as_str().to_string();
                self.challenges
                    .write()
                    .await
                    .insert(token.clone(), key_auth);
                tokens.push(token);
                challenge
                    .set_ready()
                    .await
                    .context("failed to mark challenge ready")?;
            }
        }

        let result = self.finalize_order(&mut order, host).await;

        // Always clean up published challenge responses.
        {
            let mut challenges = self.challenges.write().await;
            for t in &tokens {
                challenges.remove(t);
            }
        }
        result
    }

    async fn finalize_order(
        &self,
        order: &mut instant_acme::Order,
        host: &str,
    ) -> Result<CertifiedKey> {
        order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("order did not become ready")?;

        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params.serialize_request(&key_pair)?;
        order
            .finalize_csr(csr.der())
            .await
            .context("failed to finalize order")?;
        let cert_chain = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("failed to get certificate")?;
        let key_pem = key_pair.serialize_pem();

        // Persist for restart, then build the in-memory key.
        let dir = self.cfg.cert_dir.join("custom").join(host);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(dir.join("fullchain.pem"), &cert_chain).await?;
        tokio::fs::write(dir.join("privkey.pem"), &key_pem).await?;

        certified_key_from_pem(cert_chain.as_bytes(), key_pem.as_bytes())
    }

    async fn provision_cert(
        &self,
        identifiers: &[Identifier],
        challenge_name: &str,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<()> {
        let mut record_handles: Vec<String> = Vec::new();
        let outcome = self
            .issue_cert_order(
                identifiers,
                challenge_name,
                cert_path,
                key_path,
                &mut record_handles,
            )
            .await;
        // Always remove the published challenge records — on success AND failure — so a failed
        // attempt doesn't leak `_acme-challenge` TXTs (which the RFC2136 `append` path would
        // otherwise accumulate at the same name across retries). Best-effort.
        for handle in &record_handles {
            let _ = self.cfg.dns_provider.delete_txt(handle).await;
        }
        outcome
    }

    /// One ACME DNS-01 order flow. ALL of `identifiers` are expected to share the single
    /// DNS-01 `challenge_name` — true for the apex order (`{domain}` + `*.{domain}` both
    /// validate at `_acme-challenge.{domain}`) and trivially for the single-SAN db order.
    /// Keeping apex and db as SEPARATE orders is exactly what lets each hard-code its own
    /// challenge name instead of deriving it per authorization. Each published challenge
    /// handle is pushed into `record_handles` so [`Self::provision_cert`] always cleans up.
    async fn issue_cert_order(
        &self,
        identifiers: &[Identifier],
        challenge_name: &str,
        cert_path: &Path,
        key_path: &Path,
        record_handles: &mut Vec<String>,
    ) -> Result<()> {
        let mut order = self
            .account
            .new_order(&NewOrder::new(identifiers))
            .await
            .context("failed to create ACME order")?;

        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut auth = result.context("failed to get authorization")?;
                let mut challenge = auth
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| anyhow::anyhow!("no DNS-01 challenge found"))?;
                let dns_value = challenge.key_authorization().dns_value();
                let record_id = self
                    .cfg
                    .dns_provider
                    .create_txt(challenge_name, &dns_value)
                    .await?;
                record_handles.push(record_id);
                info!("waiting for DNS propagation...");
                tokio::time::sleep(Duration::from_secs(15)).await;
                challenge
                    .set_ready()
                    .await
                    .context("failed to mark challenge ready")?;
            }
        }

        order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("order not ready")?;
        let key_pair = KeyPair::generate()?;
        let domain_names: Vec<String> = identifiers
            .iter()
            .filter_map(|id| match id {
                Identifier::Dns(d) => Some(d.clone()),
                _ => None,
            })
            .collect();
        let mut params = CertificateParams::new(domain_names)?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params.serialize_request(&key_pair)?;
        order
            .finalize_csr(csr.der())
            .await
            .context("failed to finalize order")?;
        let cert_chain = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("failed to get certificate")?;

        tokio::fs::write(cert_path, &cert_chain).await?;
        tokio::fs::write(key_path, key_pair.serialize_pem()).await?;
        info!(cert = %cert_path.display(), "certificate provisioned");
        Ok(())
    }

    /// Background loop: renew the wildcard near expiry and ensure/renew certs for
    /// every Active custom domain (covers proactive misses + DNS-pointed-late).
    pub fn spawn_reconcile(self: &Arc<Self>) {
        let mgr = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RECONCILE_INTERVAL).await;

                let cert_path = mgr.cfg.cert_dir.join("fullchain.pem");
                if needs_renewal(&cert_path) {
                    info!("wildcard certificate renewal triggered");
                    if let Err(e) = mgr.ensure_wildcard().await {
                        warn!(error = %e, "wildcard renewal failed");
                    }
                }

                // The `*.db` wildcard: renew near expiry OR retry if a prior provision
                // (e.g. at startup) never produced a cert (best-effort, so it can be absent).
                let db_cert_path = mgr.cfg.cert_dir.join("db-fullchain.pem");
                if !db_cert_path.exists() || needs_renewal(&db_cert_path) {
                    mgr.ensure_db_wildcard().await;
                }

                let custom_hosts: Vec<String> = {
                    let map = mgr.domains.read().await;
                    map.keys()
                        .filter(|h| h.contains('.'))
                        .filter(|h| {
                            **h != mgr.cfg.domain && !h.ends_with(&format!(".{}", mgr.cfg.domain))
                        })
                        .cloned()
                        .collect()
                };
                for host in custom_hosts {
                    mgr.ensure_cert(&host).await;
                }
            }
        });
    }
}

async fn obtain_account(cfg: &TlsConfig, staging: bool) -> Result<Account> {
    let creds_path = cfg.cert_dir.join("acme-account.json");
    if let Some(creds) = tokio::fs::read(&creds_path)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice::<AccountCredentials>(&b).ok())
    {
        match Account::builder()?.from_credentials(creds).await {
            Ok(account) => {
                info!("loaded existing ACME account");
                return Ok(account);
            }
            Err(e) => warn!(error = %e, "stored ACME account invalid, creating a new one"),
        }
    }
    let directory = if staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[&format!("mailto:{}", cfg.acme_email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.to_string(),
            None,
        )
        .await
        .context("failed to create ACME account")?;
    if let Ok(json) = serde_json::to_vec(&credentials) {
        let _ = tokio::fs::write(&creds_path, json).await;
    }
    info!(staging, "created ACME account");
    Ok(account)
}

fn needs_renewal(cert_path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(cert_path) else {
        return true;
    };
    let Ok(modified) = meta.modified() else {
        return true;
    };
    modified
        .elapsed()
        .map(|age| age > RENEW_AFTER)
        .unwrap_or(true)
}

fn read_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let cert_pem =
        std::fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
    certified_key_from_pem(&cert_pem, &key_pem)
}

fn certified_key_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..]).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates in PEM");
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;
    let provider = CryptoProvider::get_default()
        .ok_or_else(|| anyhow::anyhow!("no rustls crypto provider installed"))?;
    CertifiedKey::from_der(certs, key, provider).context("invalid cert/key pair")
}

/// A pluggable ACME **DNS-01** backend: publish the `_acme-challenge` TXT record the CA
/// validates against, then remove it afterwards. `create_txt` returns an opaque handle
/// that the SAME provider interprets in `delete_txt` (a Cloudflare record id, an encoded
/// name+value for RFC2136, …) — so issuance is vendor-neutral above this seam.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Publish a TXT record at `name` (an FQDN like `_acme-challenge.example.com`) with
    /// `value`; return a handle for later deletion.
    async fn create_txt(&self, name: &str, value: &str) -> Result<String>;
    /// Remove the TXT record identified by a handle from [`create_txt`](Self::create_txt).
    async fn delete_txt(&self, handle: &str) -> Result<()>;
}

/// Cloudflare DNS-01 backend (the default; reads the `CLOUDFLARE_*` config for back-compat).
pub struct CloudflareProvider {
    token: String,
    zone_id: String,
}

impl CloudflareProvider {
    pub fn new(token: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            zone_id: zone_id.into(),
        }
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn create_txt(&self, name: &str, content: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                self.zone_id
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "content": content,
                "ttl": 120,
            }))
            .send()
            .await
            .context("failed to create Cloudflare TXT record")?;

        let body: serde_json::Value = resp.json().await?;
        if !body["success"].as_bool().unwrap_or(false) {
            anyhow::bail!(
                "Cloudflare API error: {}",
                serde_json::to_string_pretty(&body["errors"])?
            );
        }
        body["result"]["id"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("no record ID in Cloudflare response"))
    }

    async fn delete_txt(&self, record_id: &str) -> Result<()> {
        let client = reqwest::Client::new();
        client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                self.zone_id, record_id
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("failed to delete Cloudflare TXT record")?;
        Ok(())
    }
}

/// RFC 2136 (dynamic DNS UPDATE) backend with TSIG auth — vendor-neutral: works against any
/// compliant authoritative server (BIND/Knot/PowerDNS/…), no proprietary API. Each call opens
/// a short-lived TSIG-signed UDP client to the nameserver and `append`s / `delete_by_rdata`s
/// the `_acme-challenge` TXT (append, not create, so the wildcard + apex challenges can share
/// the name with two distinct values).
pub struct Rfc2136Provider {
    /// `host:port` — resolved at connect time (so a hostname works, not just an IP literal).
    nameserver: String,
    zone: String,
    tsig_name: String,
    tsig_secret: Vec<u8>,
    tsig_alg: TsigAlgorithm,
}

impl Rfc2136Provider {
    /// `nameserver` is `host:port` (hostname or IP); `tsig_secret` is base64 (as in a BIND key
    /// file); `tsig_alg` is `hmac-sha256` (default) / `hmac-sha384` / `hmac-sha512`.
    pub fn new(
        nameserver: &str,
        zone: &str,
        tsig_name: &str,
        tsig_secret_b64: &str,
        tsig_alg: &str,
    ) -> Result<Self> {
        // Validate the host:port shape now; the host is resolved at connect time so a hostname
        // (ns1.example.com:53) works — std::net::SocketAddr's parser only accepts IP:port.
        let nameserver = nameserver.trim().to_string();
        let shape_ok = nameserver.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0)
        });
        if !shape_ok {
            anyhow::bail!(
                "RFC2136_NAMESERVER must be host:port (e.g. ns1.example.com:53 or 192.0.2.1:53), got {nameserver:?}"
            );
        }
        let zone = zone.trim();
        if zone.is_empty() {
            anyhow::bail!("RFC2136_ZONE must not be empty");
        }
        if tsig_name.trim().is_empty() {
            anyhow::bail!("RFC2136_TSIG_NAME must not be empty");
        }
        let tsig_secret = base64::engine::general_purpose::STANDARD
            .decode(tsig_secret_b64.trim())
            .context("RFC2136_TSIG_SECRET must be base64")?;
        if tsig_secret.is_empty() {
            anyhow::bail!("RFC2136_TSIG_SECRET must not be empty");
        }
        let tsig_alg = match tsig_alg.trim().to_ascii_lowercase().as_str() {
            "" | "hmac-sha256" => TsigAlgorithm::HmacSha256,
            "hmac-sha384" => TsigAlgorithm::HmacSha384,
            "hmac-sha512" => TsigAlgorithm::HmacSha512,
            other => anyhow::bail!(
                "unsupported RFC2136_TSIG_ALGORITHM {other:?} (hmac-sha256 | hmac-sha384 | hmac-sha512)"
            ),
        };
        Ok(Self {
            nameserver,
            zone: zone.to_string(),
            tsig_name: tsig_name.to_string(),
            tsig_secret,
            tsig_alg,
        })
    }

    fn signer(&self) -> Result<TSigner> {
        TSigner::new(
            self.tsig_secret.clone(),
            self.tsig_alg.clone(),
            fqdn(&self.tsig_name)?,
            300,
        )
        .context("invalid TSIG signer (key name / secret / algorithm)")
    }

    /// Open a fresh TSIG-signed UDP client to the nameserver. The background driver is
    /// spawned for the lifetime of the returned client.
    async fn client(&self) -> Result<AsyncClient> {
        // Resolve here (accepts hostname:port and ip:port) rather than at construction.
        let addr = tokio::net::lookup_host(&self.nameserver)
            .await
            .with_context(|| format!("RFC2136_NAMESERVER {:?} failed to resolve", self.nameserver))?
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "RFC2136_NAMESERVER {:?} resolved to no addresses",
                    self.nameserver
                )
            })?;
        let stream = UdpClientStream::<UdpSocket, TSigner>::with_timeout_and_signer(
            addr,
            Duration::from_secs(10),
            Some(Arc::new(self.signer()?)),
        );
        let (client, bg) = AsyncClient::connect(stream)
            .await
            .context("rfc2136: TSIG client connect failed")?;
        tokio::spawn(bg);
        Ok(client)
    }

    /// Build the TXT record + zone for an UPDATE, guarding that the zone actually contains the
    /// record. hickory's `append`/`delete_by_rdata` `assert!(zone_of)` and would PANIC the
    /// process on a NOTZONE misconfig; bail with a clear error instead.
    fn record_and_zone(&self, name: &str, value: &str) -> Result<(Record, Name)> {
        let rec_name = fqdn(name)?;
        let zone = fqdn(&self.zone)?;
        if !zone.zone_of(&rec_name) {
            anyhow::bail!(
                "RFC2136_ZONE {:?} does not contain the challenge record {name:?}; set RFC2136_ZONE to the zone that holds _acme-challenge.<domain>",
                self.zone
            );
        }
        let record =
            Record::from_rdata(rec_name, 120, RData::TXT(TXT::new(vec![value.to_string()])));
        Ok((record, zone))
    }
}

/// Parse a DNS name as an FQDN (exactly one trailing dot), so records/zones resolve absolutely.
fn fqdn(s: &str) -> Result<Name> {
    Name::from_ascii(format!("{}.", s.trim_end_matches('.')))
        .with_context(|| format!("invalid DNS name {s:?}"))
}

#[async_trait]
impl DnsProvider for Rfc2136Provider {
    async fn create_txt(&self, name: &str, value: &str) -> Result<String> {
        // append (must_exist=false): adds this TXT RR, creating the RRset if absent — so the
        // wildcard and apex challenges (same name, different values) both land.
        let (record, zone) = self.record_and_zone(name, value)?;
        let mut client = self.client().await?;
        let resp = client
            .append(record, zone, false)
            .await
            .context("rfc2136: TXT append (dynamic UPDATE) failed")?;
        if resp.response_code() != ResponseCode::NoError {
            anyhow::bail!(
                "rfc2136: nameserver rejected append: {}",
                resp.response_code()
            );
        }
        // Handle encodes name+value so delete_by_rdata can remove exactly this RR.
        Ok(format!("{name}\t{value}"))
    }

    async fn delete_txt(&self, handle: &str) -> Result<()> {
        let (name, value) = handle
            .split_once('\t')
            .ok_or_else(|| anyhow::anyhow!("malformed rfc2136 record handle"))?;
        let (record, zone) = self.record_and_zone(name, value)?;
        let mut client = self.client().await?;
        let resp = client
            .delete_by_rdata(record, zone)
            .await
            .context("rfc2136: TXT delete (dynamic UPDATE) failed")?;
        if resp.response_code() != ResponseCode::NoError {
            anyhow::bail!(
                "rfc2136: nameserver rejected delete: {}",
                resp.response_code()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_wildcard_prefers_the_db_zone() {
        let d = "jkbase.app";
        // `<proj>.db.{domain}` → the dedicated db wildcard (longest-zone-first), even
        // though it also ends with `.{domain}`.
        assert_eq!(
            classify_wildcard("myapp.db.jkbase.app", d),
            WildcardKind::Db
        );
        // Ordinary project + infra subdomains → apex wildcard.
        assert_eq!(classify_wildcard("myapp.jkbase.app", d), WildcardKind::Apex);
        assert_eq!(
            classify_wildcard("storage.jkbase.app", d),
            WildcardKind::Apex
        );
        assert_eq!(classify_wildcard("jkbase.app", d), WildcardKind::Apex);
        // A bare `db.jkbase.app` (no label before `.db`) is NOT a db-zone host — the
        // apex wildcard covers it; we never serve it anyway.
        assert_eq!(classify_wildcard("db.jkbase.app", d), WildcardKind::Apex);
        // Off-platform SNI → no platform cert.
        assert_eq!(classify_wildcard("evil.com", d), WildcardKind::None);
    }

    #[test]
    fn rfc2136_config_validation() {
        // Valid config parses (IP:port).
        assert!(
            Rfc2136Provider::new(
                "192.0.2.1:53",
                "example.com",
                "acme-key",
                "c2VjcmV0",
                "hmac-sha256"
            )
            .is_ok()
        );
        // A HOSTNAME:port is accepted at construction (resolved later, not via SocketAddr parse).
        assert!(
            Rfc2136Provider::new(
                "ns1.example.com:53",
                "example.com",
                "k",
                "c2VjcmV0",
                "hmac-sha256"
            )
            .is_ok()
        );
        // Empty algorithm string defaults to hmac-sha256.
        assert!(Rfc2136Provider::new("192.0.2.1:53", "example.com", "k", "c2VjcmV0", "").is_ok());
        // Bad nameserver (no port).
        assert!(
            Rfc2136Provider::new(
                "ns1.example.com",
                "example.com",
                "k",
                "c2VjcmV0",
                "hmac-sha256"
            )
            .is_err()
        );
        assert!(
            Rfc2136Provider::new(
                "not-a-nameserver",
                "example.com",
                "k",
                "c2VjcmV0",
                "hmac-sha256"
            )
            .is_err()
        );
        // Empty zone / key name rejected.
        assert!(Rfc2136Provider::new("192.0.2.1:53", "", "k", "c2VjcmV0", "hmac-sha256").is_err());
        assert!(
            Rfc2136Provider::new("192.0.2.1:53", "example.com", "", "c2VjcmV0", "hmac-sha256")
                .is_err()
        );
        // Port 0 rejected (cleaner than a late connect failure).
        assert!(
            Rfc2136Provider::new("192.0.2.1:0", "example.com", "k", "c2VjcmV0", "hmac-sha256")
                .is_err()
        );
        // Non-base64 secret, and empty secret, rejected.
        assert!(
            Rfc2136Provider::new(
                "192.0.2.1:53",
                "example.com",
                "k",
                "!!! not base64 !!!",
                "hmac-sha256"
            )
            .is_err()
        );
        assert!(
            Rfc2136Provider::new("192.0.2.1:53", "example.com", "k", "", "hmac-sha256").is_err()
        );
        // Unsupported algorithm.
        assert!(
            Rfc2136Provider::new("192.0.2.1:53", "example.com", "k", "c2VjcmV0", "hmac-md5")
                .is_err()
        );
    }

    #[test]
    fn record_and_zone_rejects_record_outside_zone() {
        let p = Rfc2136Provider::new(
            "192.0.2.1:53",
            "example.com",
            "acme-key",
            "c2VjcmV0",
            "hmac-sha256",
        )
        .unwrap();
        // In-zone record is accepted (no panic, builds record+zone).
        assert!(
            p.record_and_zone("_acme-challenge.example.com", "v")
                .is_ok()
        );
        // Out-of-zone record is a clean error, NOT a hickory zone_of panic.
        let p2 = Rfc2136Provider::new(
            "192.0.2.1:53",
            "other.net",
            "acme-key",
            "c2VjcmV0",
            "hmac-sha256",
        )
        .unwrap();
        assert!(
            p2.record_and_zone("_acme-challenge.example.com", "v")
                .is_err()
        );
    }

    /// Execution-backed proof of the RFC2136 wire path: build the EXACT UPDATE messages
    /// `create_txt`/`delete_txt` send (the same `update_message::append`/`delete_by_rdata` the
    /// hickory client calls, from our `record_and_zone`, TSIG-signed with our `signer()`), then
    /// run the SERVER's own verification (`verify_message_byte` — the BADSIG check a real
    /// BIND/Knot/PowerDNS performs) and assert they're well-formed OpCode::Update messages
    /// carrying the `_acme-challenge` TXT. This proves the TSIG key/alg/name + message
    /// construction would be accepted by a real RFC2136 server, without one in the loop.
    #[test]
    fn rfc2136_update_messages_are_valid_signed_updates() {
        use hickory_client::proto::op::{Message, OpCode, update_message};
        use hickory_client::proto::rr::RecordType;
        use hickory_client::proto::serialize::binary::BinEncodable;

        let p = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "acme-key",
            "c2VjcmV0",
            "hmac-sha256",
        )
        .unwrap();
        let (record, zone) = p
            .record_and_zone("_acme-challenge.example.com", "tok-base64url-value")
            .unwrap();
        let signer = p.signer().unwrap();
        let now = 1_700_000_000u32;

        // create_txt path: client.append(record, zone, false) == update_message::append + TSIG.
        let mut add = update_message::append(record.clone().into(), zone.clone(), false, true);
        add.finalize(&signer, now).expect("TSIG-sign append");
        let add_bytes = add.to_bytes().expect("encode append");
        signer
            .verify_message_byte(None, &add_bytes, true)
            .expect("a real server's TSIG verify accepts the append");
        let parsed = Message::from_vec(&add_bytes).unwrap();
        assert_eq!(parsed.op_code(), OpCode::Update);
        assert!(
            parsed.name_servers().iter().any(|r| {
                r.record_type() == RecordType::TXT
                    && r.name()
                        .to_ascii()
                        .starts_with("_acme-challenge.example.com")
            }),
            "append UPDATE must carry the _acme-challenge TXT in the update section: {parsed:?}"
        );

        // delete_txt path: client.delete_by_rdata(record, zone) == update_message::delete_by_rdata + TSIG.
        let mut del = update_message::delete_by_rdata(record.into(), zone, true);
        del.finalize(&signer, now).expect("TSIG-sign delete");
        let del_bytes = del.to_bytes().expect("encode delete");
        signer
            .verify_message_byte(None, &del_bytes, true)
            .expect("a real server's TSIG verify accepts the delete");
        assert_eq!(
            Message::from_vec(&del_bytes).unwrap().op_code(),
            OpCode::Update
        );

        // A DIFFERENT key must NOT verify our message (proves the check is real, not a no-op).
        let other = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "acme-key",
            "ZGlmZmVyZW50",
            "hmac-sha256",
        )
        .unwrap()
        .signer()
        .unwrap();
        assert!(
            other.verify_message_byte(None, &add_bytes, true).is_err(),
            "wrong TSIG key must be rejected"
        );
    }

    #[test]
    fn fqdn_normalizes_to_single_trailing_dot() {
        assert_eq!(
            fqdn("_acme-challenge.example.com").unwrap().to_string(),
            "_acme-challenge.example.com."
        );
        assert_eq!(fqdn("example.com.").unwrap().to_string(), "example.com.");
    }

    #[test]
    fn signer_builds_for_valid_config() {
        let p = Rfc2136Provider::new(
            "192.0.2.1:53",
            "example.com",
            "acme-key",
            "c2VjcmV0",
            "hmac-sha512",
        )
        .unwrap();
        assert!(p.signer().is_ok());
    }
}
