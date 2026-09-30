//! TLS for the proxy.
//!
//! A single [`CertManager`] backs a dynamic rustls cert resolver:
//! - the `*.jkbase.app` + apex **wildcard** is provisioned via ACME DNS-01
//!   (Cloudflare) and held in memory so it can be renewed in place;
//! - **per-custom-domain** certs are issued on demand via ACME HTTP-01 (the
//!   proxy already owns port 80) and cached on disk under `certs/custom/<host>/`;
//! - **tenant wildcard** (`*.<base>`) certs are issued via ACME DNS-01 through CNAME
//!   delegation: the tenant points `_acme-challenge.<base>` at
//!   `<random-label>.<acme_delegation_zone>` and we publish the TXT there with the SAME
//!   platform DNS-01 backend. Cached under `certs/wildcard/<base>/`.
//!
//! Issuance for a custom host or wildcard only happens when it is an Active entry in
//! the shared domain map (i.e. ownership was verified) — never for arbitrary SNI — and
//! a wildcard's TXT goes ONLY to the label control minted for it (carried on its
//! `DomainTarget`), never to a tenant-chosen name.

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
use jkbase_common::routing::{WILDCARD_PREFIX, is_wildcard_key, normalize_host, wildcard_key};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock as AsyncRwLock;
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tracing::{info, warn};

/// Renew a cert once it's within this window of (assumed 90-day) expiry. We track
/// age by file mtime rather than parsing the cert — simple and good enough.
const RENEW_AFTER: Duration = Duration::from_secs(60 * 24 * 60 * 60); // 60 days
/// The same assumed lifetime: past it, a loaded cert no longer serves validly.
const ASSUMED_CERT_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// Deadline for a tenant order's WHOLE pre-check (every lookup, the CAA climb included):
/// per-lookup timeouts alone would let a deep name whose nameservers answer slowly and
/// empty hold a reconcile slot for minutes. Expiry is transient (no strike).
const PRECHECK_DEADLINE: Duration = Duration::from_secs(15);
/// Custom-host orders run at most this many at a time per tick, so one tenant's slow
/// hosts can't serialize every other tenant's issuance and renewal behind them.
const CUSTOM_ORDER_CONCURRENCY: usize = 8;
/// How often the reconcile loop runs (wildcard renewal + custom issuance/retry).
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Tenant certs (custom + wildcard) back off exponentially from here (doubling per
/// consecutive failure)…
const ISSUE_BACKOFF_BASE: u64 = 5 * 60;
/// …up to this cap…
const ISSUE_BACKOFF_MAX: u64 = 24 * 60 * 60;
/// …and a WILDCARD gives up after this many consecutive failures (~10.5h of retries)
/// until the owner re-verifies. (A custom domain keeps retrying at the cap: its DNS is
/// often pointed late.)
const WILDCARD_MAX_FAILURES: u32 = 8;
/// DNS-01 orders sleep ~15s for propagation; the reconcile loop runs at most this many
/// tenant-wildcard orders per tick (concurrently), so a pile of them can't starve
/// custom-domain and platform renewals.
const MAX_WILDCARD_ORDERS_PER_TICK: usize = 4;
/// The CAA identity of the CA we order from (Let's Encrypt, prod and staging alike).
const ACME_CA_IDENTITY: &str = "letsencrypt.org";
/// Where issue health (backoff / give-up / budget blocks) persists across restarts.
const ISSUE_HEALTH_FILE: &str = "issue-health.json";

/// `(fqdn, "CNAME" | "CAA")` → the answers' data. `Ok` is an authoritative answer
/// (possibly empty); `Err` is a failed lookup — never read as "record absent", or a
/// resolver outage would count against tenants' give-up budgets. The server wires this to
/// the SAME resolver control's `verify` uses, so "verified" and "still delegated" agree.
pub type DnsLookup = Arc<
    dyn Fn(String, &'static str) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send>>
        + Send
        + Sync,
>;

/// Upper bound on one pre-order DNS lookup, whatever [`DnsLookup`] is plugged in: the
/// custom-host pass is serial and shares a loop with the platform certs' renewal, so a
/// hung resolver must cost one host a transient failure, never wedge the loop.
const DNS_PRECHECK_TIMEOUT: Duration = Duration::from_secs(10);

async fn lookup(l: &DnsLookup, name: String, rtype: &'static str) -> Result<Vec<String>> {
    tokio::time::timeout(DNS_PRECHECK_TIMEOUT, l(name.clone(), rtype))
        .await
        .map_err(|_| anyhow::anyhow!("DNS lookup of {name} {rtype} timed out"))?
}

/// Why a pre-order check stopped an order. Only [`Precheck::Tenant`] — DNS positively
/// answered and the tenant's records are wrong — counts toward give-up; a failed lookup
/// says nothing about the tenant and only backs the host off.
enum Precheck {
    Tenant(anyhow::Error),
    Transient(anyhow::Error),
}

impl From<anyhow::Error> for Precheck {
    /// `?` on a lookup: a failed lookup is transient.
    fn from(e: anyhow::Error) -> Self {
        Precheck::Transient(e)
    }
}

/// Verdict of the per-tenant order budget on one prospective order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderPermit {
    /// Charged to the owning tenant; go.
    Allowed,
    /// Over budget (next slot frees at `retry_at`, unix secs) or not a registered host.
    Denied { retry_at: Option<u64> },
}

/// Charge one tenant cert order to its owner's persisted budget (server-built over the
/// control store, so spent orders survive removal, re-add and restart). `host` is the
/// domain-map key.
pub type OrderGate = Arc<dyn Fn(&str) -> OrderPermit + Send + Sync>;

#[derive(Clone)]
pub struct TlsConfig {
    pub domain: String,
    pub cert_dir: PathBuf,
    /// The ACME DNS-01 backend used to provision the wildcard cert (Cloudflare,
    /// RFC2136, …). Behind `Arc<dyn>` so the config stays cheap to clone and the
    /// vendor choice is made once at startup.
    pub dns_provider: Arc<dyn DnsProvider>,
    pub acme_email: String,
    /// ACME directory URL overriding Let's Encrypt (production / `staging`): a private CA
    /// (step-ca, …) or a test CA (Pebble). `None` = Let's Encrypt.
    pub acme_directory: Option<String>,
    /// PEM root(s) to trust for the ACME API's own TLS, when the CA isn't publicly trusted.
    pub acme_ca_root: Option<PathBuf>,
    /// Zone (under `domain`, writable by `dns_provider`) holding the TXT answers for
    /// tenant wildcards' delegated `_acme-challenge` CNAMEs.
    pub acme_delegation_zone: String,
    /// DNS reads for the pre-order checks (delegation CNAME, CAA).
    pub dns_lookup: DnsLookup,
    /// Per-tenant persisted order budget; `None` = unmetered (tests / embedders).
    pub order_gate: Option<OrderGate>,
    /// Global cap on tenant-initiated orders per 3 h (see [`TokenBucket`]).
    pub tenant_orders_per_3h: u32,
    /// Percent of that bucket only renewals of already-issued certs may use.
    pub tenant_renewal_reserve_percent: u32,
}

/// A host's cert state, for the control API's `tls` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCertState {
    Missing,
    Issued,
    /// Issuance stopped, no cert serving: gave up (`retry_at: None`, re-verify to retry)
    /// or the owner's order budget is spent (`retry_at: Some(unix)`).
    Failed {
        retry_at: Option<u64>,
    },
    /// Like `Failed`, but the previous cert still serves until it expires.
    RenewalFailed {
        retry_at: Option<u64>,
    },
}

/// Per-host issuance health: in-flight dedupe, exponential backoff, give-up, budget
/// block. Unix seconds, so it persists ([`ISSUE_HEALTH_FILE`]) — a restart must not
/// re-arm a host that gave up or refund a backoff.
#[derive(Default, Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IssueHealth {
    /// Consecutive failures of any kind; drives the backoff.
    failures: u32,
    /// Consecutive failures that may count toward give-up (tenant-caused, on a host with
    /// no cert yet); [`WILDCARD_MAX_FAILURES`] of them stops issuance until re-verify.
    #[serde(default)]
    strikes: u32,
    next_attempt: Option<u64>,
    gave_up: bool,
    blocked_until: Option<u64>,
    #[serde(skip)]
    in_flight: bool,
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
struct IssueHealthBook(HashMap<String, IssueHealth>);

fn issue_backoff(failures: u32) -> u64 {
    let exp = failures.saturating_sub(1).min(20);
    ISSUE_BACKOFF_BASE
        .saturating_mul(1u64 << exp)
        .min(ISSUE_BACKOFF_MAX)
}

impl IssueHealthBook {
    fn due(&self, host: &str, now: u64) -> bool {
        self.0
            .get(host)
            .is_none_or(|h| !h.in_flight && !h.gave_up && h.next_attempt.is_none_or(|t| now >= t))
    }
    /// Take the host's order slot; `false` if not due (in flight, backing off, blocked,
    /// gave up).
    fn begin(&mut self, host: &str, now: u64) -> bool {
        if !self.due(host, now) {
            return false;
        }
        let h = self.0.entry(host.to_string()).or_default();
        h.in_flight = true;
        h.blocked_until = None;
        true
    }
    /// Give the slot back without an attempt (a transient platform-side throttle).
    fn release(&mut self, host: &str) {
        if let Some(h) = self.0.get_mut(host) {
            h.in_flight = false;
        }
    }
    fn succeed(&mut self, host: &str) {
        self.0.remove(host);
    }
    /// Record a failed attempt; returns `true` once the host has given up. Every failure
    /// backs off; only a `strike` counts toward give-up.
    fn fail(&mut self, host: &str, now: u64, strike: bool) -> bool {
        let h = self.0.entry(host.to_string()).or_default();
        h.in_flight = false;
        h.failures = h.failures.saturating_add(1);
        if strike {
            h.strikes = h.strikes.saturating_add(1);
        }
        if h.strikes >= WILDCARD_MAX_FAILURES {
            h.gave_up = true;
        } else {
            h.next_attempt = Some(now + issue_backoff(h.failures));
        }
        h.gave_up
    }
    /// The owner's order budget is spent: park the host until `until` (not a failure).
    fn block(&mut self, host: &str, until: u64) {
        let h = self.0.entry(host.to_string()).or_default();
        h.in_flight = false;
        h.blocked_until = Some(until);
        h.next_attempt = Some(until);
    }
    /// `Some(retry_at)` when issuance is stopped (see [`HostCertState::Failed`]).
    fn stopped(&self, host: &str, now: u64) -> Option<Option<u64>> {
        let h = self.0.get(host)?;
        if h.gave_up {
            Some(None)
        } else {
            h.blocked_until.filter(|&t| t > now).map(Some)
        }
    }
    /// Owner re-verified (or the name was released): forget the history, but keep an
    /// in-flight marker so a concurrent order isn't duplicated. The ORDER budget is not
    /// here — it lives in the control store, keyed by tenant, and is never reset.
    fn reset(&mut self, host: &str) {
        match self.0.get_mut(host) {
            Some(h) if h.in_flight => {
                *h = IssueHealth {
                    in_flight: true,
                    ..Default::default()
                }
            }
            _ => {
                self.0.remove(host);
            }
        }
    }
}

/// Global bucket for TENANT-initiated orders (custom + wildcard), across all tenants:
/// `capacity` orders, refilled evenly over 3 h. Platform certs (apex, `*.db`) never draw
/// from it, so whatever the account's limit is beyond `capacity` stays reserved for them.
/// The bottom `reserve` tokens only serve RENEWALS of certs already issued, so new-cert
/// churn (whoever's) can never block a renewal; one tenant's share of the rest is capped
/// by its persisted budget (`AcmeOrderBudget::share_max`). In memory: a restart refills
/// it, but restarts aren't tenant-triggerable, and the per-tenant budget still binds.
#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    reserve: f64,
    tokens: f64,
    per_sec: f64,
    last: u64,
}

impl TokenBucket {
    fn per_3h(capacity: u32, renewal_reserve_percent: u32, now: u64) -> Self {
        let capacity = f64::from(capacity);
        Self {
            capacity,
            reserve: capacity * f64::from(renewal_reserve_percent.min(100)) / 100.0,
            tokens: capacity,
            per_sec: capacity / (3.0 * 3600.0),
            last: now,
        }
    }
    fn try_take(&mut self, now: u64, renewal: bool) -> bool {
        let dt = now.saturating_sub(self.last) as f64;
        self.last = now.max(self.last);
        self.tokens = (self.tokens + dt * self.per_sec).min(self.capacity);
        let need = if renewal { 1.0 } else { 1.0 + self.reserve };
        if self.tokens >= need {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
    fn refund(&mut self) {
        self.tokens = (self.tokens + 1.0).min(self.capacity);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether `_acme-challenge.<base>` currently CNAMEs to exactly `challenge_name`.
/// `Err` = the lookup failed (no verdict).
async fn delegation_in_place(l: &DnsLookup, base: &str, challenge_name: &str) -> Result<bool> {
    let want = normalize_host(challenge_name);
    Ok(lookup(l, format!("_acme-challenge.{base}"), "CNAME")
        .await?
        .iter()
        .any(|t| normalize_host(t.trim()) == want))
}

/// RFC 8659 CAA pre-check: does DNS let [`ACME_CA_IDENTITY`] issue for `name` (a host,
/// or the base of a wildcard)? Climbs from `name` towards the root and judges the FIRST
/// non-empty CAA set; no set anywhere = allowed. Refusing here costs nothing, whereas an
/// order a CAA record forbids fails at the CA AND spends the shared account's budget.
async fn caa_permits(l: &DnsLookup, name: &str, wildcard: bool) -> Result<bool> {
    let mut n = name.to_string();
    loop {
        let set = lookup(l, n.clone(), "CAA").await?;
        if !set.is_empty() {
            return Ok(caa_set_permits(&set, wildcard));
        }
        match n.split_once('.') {
            Some((_, rest)) if rest.contains('.') => n = rest.to_string(),
            _ => return Ok(true),
        }
    }
}

/// Judge one CAA RRset (presentation format, `flags tag "value"`). A wildcard uses the
/// `issuewild` entries if there are any, else `issue`. No relevant entries = allowed; an
/// unparseable record (e.g. RFC 3597 `\#` form) is ignored rather than trusted to deny.
fn caa_set_permits(records: &[String], wildcard: bool) -> bool {
    let parsed: Vec<(String, String)> = records
        .iter()
        .filter_map(|r| {
            let mut it = r.trim().splitn(3, char::is_whitespace);
            it.next()?.parse::<u8>().ok()?;
            let tag = it.next()?.to_ascii_lowercase();
            let value = it.next().unwrap_or("").trim().trim_matches('"').to_string();
            Some((tag, value))
        })
        .collect();
    let values = |tag: &str| -> Vec<&String> {
        parsed
            .iter()
            .filter(|(t, _)| t == tag)
            .map(|(_, v)| v)
            .collect()
    };
    let wild = values("issuewild");
    let relevant = if wildcard && !wild.is_empty() {
        wild
    } else {
        values("issue")
    };
    relevant.is_empty()
        || relevant.iter().any(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
                == ACME_CA_IDENTITY
        })
}

/// The persisted issue-health book (empty if absent/unreadable — fail open to "retry",
/// which the order budgets still bound).
fn load_health(path: &Path) -> IssueHealthBook {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Default ACME delegation zone for a platform domain. The leading underscore keeps it
/// out of the tenant namespace: no project/subdomain label can contain `_`.
pub fn default_acme_delegation_zone(platform_domain: &str) -> String {
    format!("_acme-delegation.{platform_domain}")
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
        self.select(&normalize_host(sni))
    }
}

impl Resolver {
    /// Cert for a normalized SNI, mirroring routing precedence: an exact per-host cert,
    /// then the platform wildcards, then — off-platform only — the ONE tenant wildcard
    /// covering exactly one label (`*.sub.example.com` for `abc.sub.example.com`).
    /// Every key is platform-held, so serving a tenant wildcard's cert for a host a
    /// different tenant registered exactly (before its own cert lands) discloses nothing;
    /// routing still sends that host to its exact owner.
    fn select(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        if sni.contains('*') {
            return None;
        }
        let hosts = self.hosts.read().unwrap();
        if let Some(ck) = hosts.get(sni).cloned() {
            return Some(ck);
        }
        match classify_wildcard(sni, &self.platform_domain) {
            WildcardKind::Db => self.db_wildcard.read().unwrap().clone(),
            WildcardKind::Apex => self.wildcard.read().unwrap().clone(),
            // A tenant wildcard, else a known-but-not-yet-issued custom domain (or an
            // unknown SNI): fail cleanly.
            WildcardKind::None => wildcard_key(sni).and_then(|k| hosts.get(&k).cloned()),
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
    /// Tenant-cert issuance health (dedupe, backoff, give-up, budget blocks); persisted.
    health: Mutex<IssueHealthBook>,
    /// `health` changed since the last [`Self::flush_health`].
    health_dirty: std::sync::atomic::AtomicBool,
    /// Serializes [`Self::flush_health`]: a reconcile tick and an explicit request can
    /// flush concurrently, and they share one temp file.
    health_flush: AsyncMutex<()>,
    /// Global budget for tenant-initiated orders.
    tenant_bucket: Mutex<TokenBucket>,
}

impl CertManager {
    /// Build the manager: load-or-create the ACME account, ensure the wildcard
    /// cert, and load any cached per-host certs. Blocks on wildcard provisioning
    /// (as the old startup path did) so HTTPS is ready before serving.
    pub async fn new(cfg: TlsConfig, domains: DomainMap, staging: bool) -> Result<Arc<Self>> {
        tokio::fs::create_dir_all(&cfg.cert_dir).await?;
        let account = obtain_account(&cfg, staging).await?;

        let health = load_health(&cfg.cert_dir.join(ISSUE_HEALTH_FILE));
        let tenant_bucket = TokenBucket::per_3h(
            cfg.tenant_orders_per_3h,
            cfg.tenant_renewal_reserve_percent,
            unix_now(),
        );
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
            health: Mutex::new(health),
            health_dirty: std::sync::atomic::AtomicBool::new(false),
            health_flush: AsyncMutex::new(()),
            tenant_bucket: Mutex::new(tenant_bucket),
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

    /// `host`'s cert state (issued / pending / stopped) for the control API.
    pub fn cert_state(&self, host: &str) -> HostCertState {
        let stopped = self.health.lock().unwrap().stopped(host, unix_now());
        match (self.has_cert(host), stopped) {
            (true, None) => HostCertState::Issued,
            (true, Some(retry_at)) => HostCertState::RenewalFailed { retry_at },
            (false, Some(retry_at)) => HostCertState::Failed { retry_at },
            (false, None) => HostCertState::Missing,
        }
    }

    /// An explicit issuance request (a domain was just verified / re-verified): clear
    /// `host`'s backoff and give-up, then try now. Still bound by both order budgets
    /// (control only re-arms within the tenant's). The reconcile loop calls
    /// [`Self::ensure_cert`] instead, which honours the backoff.
    pub fn request_cert(self: &Arc<Self>, host: String) {
        self.with_health(|h| h.reset(&host));
        let mgr = self.clone();
        tokio::spawn(async move {
            mgr.ensure_cert(&host).await;
            mgr.flush_health().await;
        });
    }

    /// Mutate the issue-health book in memory; [`Self::flush_health`] persists it (once
    /// per reconcile tick / explicit request, off the lock, async I/O).
    fn with_health<R>(&self, f: impl FnOnce(&mut IssueHealthBook) -> R) -> R {
        let out = f(&mut self.health.lock().unwrap());
        self.health_dirty
            .store(true, std::sync::atomic::Ordering::Release);
        out
    }

    /// Persist the issue-health book if it changed (best-effort, atomic replace). A crash
    /// loses at most the last tick's changes, which the order budgets still bound.
    async fn flush_health(&self) {
        use std::sync::atomic::Ordering;
        let _flushing = self.health_flush.lock().await;
        if !self.health_dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        let Ok(json) = serde_json::to_vec(&*self.health.lock().unwrap()) else {
            return;
        };
        let path = self.cfg.cert_dir.join(ISSUE_HEALTH_FILE);
        let tmp = path.with_extension("json.tmp");
        let written = match tokio::fs::write(&tmp, json).await {
            Ok(()) => tokio::fs::rename(&tmp, &path).await,
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            self.health_dirty.store(true, Ordering::Release);
            warn!(error = %e, "failed to persist certificate issue health");
        }
    }

    /// The shared pre-order gates for a TENANT cert, in cost order — all before any ACME
    /// call: the host's own backoff slot, then the free DNS pre-checks (`precheck`: the
    /// delegation CNAME for a wildcard; CAA for both), then the global tenant bucket,
    /// then the owner's persisted budget. `false` = don't order now (state recorded).
    /// A tenant-caused precheck failure is a give-up strike iff `may_give_up`; a failed
    /// lookup never is.
    async fn gate_tenant_order(
        &self,
        host: &str,
        precheck: impl Future<Output = std::result::Result<(), Precheck>>,
        may_give_up: bool,
    ) -> bool {
        if !self.with_health(|h| h.begin(host, unix_now())) {
            return false;
        }
        let precheck = async {
            tokio::time::timeout(PRECHECK_DEADLINE, precheck)
                .await
                .unwrap_or_else(|_| {
                    Err(Precheck::Transient(anyhow::anyhow!(
                        "pre-order DNS checks exceeded {PRECHECK_DEADLINE:?}"
                    )))
                })
        };
        match precheck.await {
            Ok(()) => {}
            Err(Precheck::Tenant(e)) => {
                self.record_failure(host, &e, may_give_up);
                return false;
            }
            Err(Precheck::Transient(e)) => {
                self.record_failure(host, &e, false);
                return false;
            }
        }
        // A renewal (a cert is already loaded) may dip into the renewal reserve.
        let renewal = self.has_cert(host);
        if !self
            .tenant_bucket
            .lock()
            .unwrap()
            .try_take(unix_now(), renewal)
        {
            // Platform-wide throttle: not the tenant's failure; retried next tick.
            self.with_health(|h| h.release(host));
            info!(host = %host, "tenant ACME order budget (global) exhausted; deferring");
            return false;
        }
        match self.cfg.order_gate.as_ref().map(|g| g(host)) {
            None | Some(OrderPermit::Allowed) => true,
            Some(OrderPermit::Denied { retry_at }) => {
                self.tenant_bucket.lock().unwrap().refund();
                let until = retry_at.unwrap_or_else(|| unix_now() + ISSUE_BACKOFF_BASE);
                self.with_health(|h| h.block(host, until));
                warn!(host = %host, retry_at = until, "owner's ACME order budget exhausted");
                false
            }
        }
    }

    fn record_failure(&self, host: &str, e: &anyhow::Error, strike: bool) {
        if self.with_health(|h| h.fail(host, unix_now(), strike)) {
            warn!(host = %host, error = %e,
                "certificate issuance failed repeatedly; giving up until re-verified");
        } else {
            warn!(host = %host, error = %e, "certificate issuance failed (backing off)");
        }
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
        self.load_cached_dir("custom", "");
        self.load_cached_dir("wildcard", WILDCARD_PREFIX);
    }

    /// Load every `<dir>/<name>/{fullchain,privkey}.pem` into the resolver under
    /// `<key_prefix><name>` (wildcards live on disk by base, keyed `*.<base>`).
    fn load_cached_dir(&self, dir: &str, key_prefix: &str) {
        let dir = self.cfg.cert_dir.join(dir);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let host = format!("{key_prefix}{}", entry.file_name().to_string_lossy());
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
        if host.contains('*') {
            return false; // wildcards are DNS-01 only — see ensure_wildcard_cert
        }
        self.domains.read().await.contains_key(host)
    }

    /// Unload cached per-host / wildcard certs whose host is not an Active domain (a row
    /// purged at boot, or one whose removal failed to delete the cache). Call once the
    /// domain map is built: until then a released `*.<base>` cert would keep answering
    /// SNI for every label under it, and a re-claim would read it as already Issued.
    /// Files stay on disk (a re-claim overwrites them); only serving stops.
    pub async fn unload_unmapped_certs(&self) {
        let map = self.domains.read().await;
        self.resolver.hosts.write().unwrap().retain(|host, _| {
            let keep = map.contains_key(host);
            if !keep {
                info!(host = %host, "not an active domain; cached certificate not served");
            }
            keep
        });
    }

    fn host_cert_dir(&self, host: &str) -> Option<PathBuf> {
        cert_cache_dir(&self.cfg.cert_dir, host)
    }

    /// Stop serving + renewing a released host's cert and delete its cache. Called when
    /// a custom/wildcard domain is removed (or its project deleted).
    pub fn forget_cert(&self, host: &str) {
        let host = normalize_host(host);
        self.resolver.hosts.write().unwrap().remove(&host);
        self.with_health(|h| h.reset(&host));
        if let Some(dir) = self.host_cert_dir(&host)
            && dir.exists()
        {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => info!(host = %host, "removed certificate for released domain"),
                Err(e) => warn!(host = %host, error = %e, "failed to remove released certificate"),
            }
        }
    }

    /// A cert for `host` is loaded and still inside its (assumed) lifetime.
    fn host_cert_live(&self, host: &str) -> bool {
        self.has_cert(host)
            && self
                .host_cert_dir(host)
                .and_then(|d| std::fs::metadata(d.join("fullchain.pem")).ok())
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age < ASSUMED_CERT_LIFETIME)
    }

    fn host_cert_fresh(&self, host: &str) -> bool {
        if !self.resolver.hosts.read().unwrap().contains_key(host) {
            return false;
        }
        let Some(dir) = self.host_cert_dir(host) else {
            return false;
        };
        let cert = dir.join("fullchain.pem");
        cert.exists() && !needs_renewal(&cert)
    }

    /// Ensure a valid cert exists for a verified custom `host` (HTTP-01) or tenant
    /// wildcard `*.<base>` (DNS-01 via delegation), issuing if needed. Best-effort,
    /// deduped, backed off on failure, and metered (see [`Self::gate_tenant_order`]).
    pub async fn ensure_cert(&self, host: &str) {
        if is_wildcard_key(host) {
            return self.ensure_wildcard_cert(host).await;
        }
        if !self.is_issuable(host).await || self.host_cert_fresh(host) {
            return;
        }
        let caa = async {
            if caa_permits(&self.cfg.dns_lookup, host, false).await? {
                Ok(())
            } else {
                Err(Precheck::Tenant(anyhow::anyhow!(
                    "CAA forbids {ACME_CA_IDENTITY} for {host}"
                )))
            }
        };
        if !self.gate_tenant_order(host, caa, false).await {
            return;
        }

        info!(host = %host, "issuing custom-domain certificate via ACME HTTP-01");
        match self.issue_http01(host).await {
            Ok(ck) => {
                // Hold the domain map across the insert: a removal takes the map's WRITE
                // lock before `forget_cert`, so it either happened already (we see it and
                // drop what finalize_order wrote) or runs after our insert (and forgets it).
                let map = self.domains.read().await;
                if map.contains_key(host) {
                    self.resolver
                        .hosts
                        .write()
                        .unwrap()
                        .insert(host.to_string(), Arc::new(ck));
                    drop(map);
                    self.with_health(|h| h.succeed(host));
                    info!(host = %host, "custom-domain certificate issued");
                } else {
                    drop(map);
                    self.forget_cert(host);
                    // forget_cert keeps the in-flight marker for a concurrent order —
                    // which is THIS one; free the slot or the host could never issue
                    // again (e.g. re-added to another project) until a restart.
                    self.with_health(|h| h.succeed(host));
                }
            }
            Err(e) => self.record_failure(host, &e, false),
        }
    }

    /// Issue/renew a tenant wildcard's cert. Gated EXACTLY like a custom host: `host`
    /// must be an Active domain-map entry — and it must carry the delegation label
    /// control minted, which is the only place its DNS-01 TXT is ever published.
    /// Backed off exponentially and abandoned after [`WILDCARD_MAX_FAILURES`] until the
    /// owner re-verifies ([`Self::request_cert`]).
    async fn ensure_wildcard_cert(&self, host: &str) {
        let label = match self.domains.read().await.get(host) {
            Some(t) => t.acme_delegation.clone(),
            None => return, // not (or no longer) an Active wildcard
        };
        let Some(order) = wildcard_order(host, label.as_deref(), &self.cfg) else {
            warn!(host = %host, "wildcard has no usable ACME delegation; not issuing");
            return;
        };
        if self.host_cert_fresh(host) {
            return;
        }
        let base = host.strip_prefix(WILDCARD_PREFIX).unwrap_or(host);
        // No order (and no spend on the shared ACME account) unless the CA can actually
        // reach our TXT through the tenant's CNAME and CAA lets it issue — re-checked
        // before EVERY order, renewals included; the tenant can change DNS any time.
        let prechecks = async {
            if !delegation_in_place(&self.cfg.dns_lookup, base, &order.challenge_name).await? {
                return Err(Precheck::Tenant(anyhow::anyhow!(
                    "_acme-challenge.{base} no longer CNAMEs to {}",
                    order.challenge_name
                )));
            }
            if !caa_permits(&self.cfg.dns_lookup, base, true).await? {
                return Err(Precheck::Tenant(anyhow::anyhow!(
                    "CAA forbids {ACME_CA_IDENTITY} for *.{base}"
                )));
            }
            Ok(())
        };
        // A cert that is still VALIDLY serving never gives up for good: its renewals only
        // back off (capped, budget-metered), so a platform-side outage (DNS provider, CA,
        // DoH) can't strand every tenant wildcard until each owner re-verifies. Once it has
        // expired, failures are strikes again — otherwise an abandoned or deliberately
        // unvalidatable wildcard would order (from the renewal reserve) forever.
        let first_issue = !self.host_cert_live(host);
        if !self.gate_tenant_order(host, prechecks, first_issue).await {
            return;
        }
        match self
            .run_wildcard_order(host, label.as_deref(), &order)
            .await
        {
            Ok(()) => self.with_health(|h| h.succeed(host)),
            Err(e) => self.record_failure(host, &e, first_issue),
        }
    }

    async fn run_wildcard_order(
        &self,
        host: &str,
        label: Option<&str>,
        order: &WildcardOrder,
    ) -> Result<()> {
        let dir = self
            .host_cert_dir(host)
            .ok_or_else(|| anyhow::anyhow!("unsafe cert cache name"))?;
        tokio::fs::create_dir_all(&dir)
            .await
            .context("cannot create wildcard cert dir")?;
        let (cert_path, key_path) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
        info!(host = %host, challenge = %order.challenge_name,
            "issuing wildcard certificate via ACME DNS-01 (CNAME delegation)");
        self.provision_cert(
            &order.identifiers,
            &order.challenge_name,
            &cert_path,
            &key_path,
        )
        .await?;
        let ck = read_certified_key(&cert_path, &key_path)?;
        // Removed (or re-registered under a new label) while the order ran: don't
        // resurrect a released name's cert. The map is held across the insert (see
        // `ensure_cert`).
        let map = self.domains.read().await;
        let still_ours = map
            .get(host)
            .is_some_and(|t| t.acme_delegation.as_deref() == label);
        if still_ours {
            self.resolver
                .hosts
                .write()
                .unwrap()
                .insert(host.to_string(), Arc::new(ck));
            info!(host = %host, "wildcard certificate issued");
        } else {
            drop(map);
            self.forget_cert(host);
        }
        Ok(())
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
    /// every Active custom domain and tenant wildcard (covers proactive misses +
    /// DNS-pointed-late). A removed domain leaves the map, so it stops renewing.
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

                let (wildcards, custom_hosts): (Vec<String>, Vec<String>) = {
                    let map = mgr.domains.read().await;
                    map.keys()
                        .filter(|h| h.contains('.'))
                        .filter(|h| {
                            **h != mgr.cfg.domain && !h.ends_with(&format!(".{}", mgr.cfg.domain))
                        })
                        .cloned()
                        .partition(|h| is_wildcard_key(h))
                };
                // A bounded batch of DUE wildcard orders runs concurrently alongside the
                // custom-domain pass (itself bounded-concurrent); the rest wait for a later tick.
                let due: Vec<String> = {
                    let now = unix_now();
                    let book = mgr.health.lock().unwrap();
                    wildcards
                        .into_iter()
                        .filter(|h| book.due(h, now) && !mgr.host_cert_fresh(h))
                        .take(MAX_WILDCARD_ORDERS_PER_TICK)
                        .collect()
                };
                let mut orders = tokio::task::JoinSet::new();
                for host in due {
                    let m = mgr.clone();
                    orders.spawn(async move { m.ensure_cert(&host).await });
                }
                let mut custom = tokio::task::JoinSet::new();
                for host in custom_hosts {
                    if custom.len() >= CUSTOM_ORDER_CONCURRENCY {
                        custom.join_next().await;
                    }
                    let m = mgr.clone();
                    custom.spawn(async move { m.ensure_cert(&host).await });
                }
                while custom.join_next().await.is_some() {}
                while orders.join_next().await.is_some() {}
                mgr.flush_health().await;
            }
        });
    }
}

/// On-disk cache dir for a per-host (`custom/<host>`) or wildcard (`wildcard/<base>`)
/// cert. `None` for anything that isn't a plain LDH name — the name becomes a path we
/// write and `remove_dir_all`, so it must never be able to climb out of `cert_dir`
/// (control validates names too; this is the last line).
fn cert_cache_dir(cert_dir: &Path, host: &str) -> Option<PathBuf> {
    let (sub, name) = match host.strip_prefix(WILDCARD_PREFIX) {
        Some(base) => ("wildcard", base),
        None => ("custom", host),
    };
    let safe = !name.is_empty()
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    safe.then(|| cert_dir.join(sub).join(name))
}

/// A tenant wildcard's ACME DNS-01 order: the single `*.<base>` identifier, validated at
/// `_acme-challenge.<base>`, which the tenant CNAMEs to `<label>.<delegation zone>` —
/// so THAT is where we publish (the CA follows the CNAME). `None` without a sane label
/// (1–63 lowercase alnum; minted by control) — never publish under anything else.
struct WildcardOrder {
    identifiers: Vec<Identifier>,
    challenge_name: String,
}

fn wildcard_order(host: &str, label: Option<&str>, cfg: &TlsConfig) -> Option<WildcardOrder> {
    let base = host.strip_prefix(WILDCARD_PREFIX)?;
    let label = label?;
    let label_ok = !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if base.is_empty() || !label_ok {
        return None;
    }
    Some(WildcardOrder {
        identifiers: vec![Identifier::Dns(host.to_string())],
        challenge_name: format!("{label}.{}", cfg.acme_delegation_zone),
    })
}

async fn obtain_account(cfg: &TlsConfig, staging: bool) -> Result<Account> {
    let creds_path = cfg.cert_dir.join("acme-account.json");
    if let Some(creds) = tokio::fs::read(&creds_path)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice::<AccountCredentials>(&b).ok())
    {
        match account_builder(cfg)?.from_credentials(creds).await {
            Ok(account) => {
                info!("loaded existing ACME account");
                return Ok(account);
            }
            Err(e) => warn!(error = %e, "stored ACME account invalid, creating a new one"),
        }
    }
    let directory = match &cfg.acme_directory {
        Some(url) => url.as_str(),
        None if staging => LetsEncrypt::Staging.url(),
        None => LetsEncrypt::Production.url(),
    };
    let (account, credentials) = account_builder(cfg)?
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
    info!(staging, directory, "created ACME account");
    Ok(account)
}

fn account_builder(cfg: &TlsConfig) -> Result<instant_acme::AccountBuilder> {
    Ok(match &cfg.acme_ca_root {
        Some(pem) => Account::builder_with_root(pem)
            .with_context(|| format!("cannot load ACME CA root {}", pem.display()))?,
        None => Account::builder()?,
    })
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

    /// A self-signed cert for `names`, as a resolver entry.
    fn ck(names: &[&str]) -> Arc<CertifiedKey> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.self_signed(&key).unwrap();
        Arc::new(
            certified_key_from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap(),
        )
    }

    /// A resolver holding the platform certs; returns it + the apex wildcard.
    fn resolver() -> (Resolver, Arc<CertifiedKey>) {
        let (apex, db) = (ck(&["*.jkbase.app"]), ck(&["*.db.jkbase.app"]));
        let r = Resolver {
            platform_domain: "jkbase.app".into(),
            wildcard: RwLock::new(Some(apex.clone())),
            db_wildcard: RwLock::new(Some(db)),
            hosts: RwLock::new(HashMap::new()),
        };
        (r, apex)
    }

    #[test]
    fn sni_prefers_exact_then_platform_then_single_label_tenant_wildcard() {
        let (r, apex) = resolver();
        let wild = ck(&["*.sub.example.com"]);
        let exact = ck(&["special.sub.example.com"]);
        r.hosts
            .write()
            .unwrap()
            .insert("*.sub.example.com".into(), wild.clone());
        r.hosts
            .write()
            .unwrap()
            .insert("special.sub.example.com".into(), exact.clone());
        let pick = |sni: &str| r.select(&normalize_host(sni));

        // Any one label → the tenant wildcard (case- and root-dot-insensitive).
        assert!(Arc::ptr_eq(&pick("abc.sub.example.com").unwrap(), &wild));
        assert!(Arc::ptr_eq(&pick("ABC.Sub.Example.com.").unwrap(), &wild));
        // An exact per-host cert wins over the wildcard that also covers it.
        assert!(Arc::ptr_eq(
            &pick("special.sub.example.com").unwrap(),
            &exact
        ));
        // Single-level only (RFC 6125): neither the base nor a deeper name is covered.
        assert!(pick("a.b.sub.example.com").is_none());
        assert!(pick("sub.example.com").is_none());
        // A literal `*` SNI never selects a wildcard slot.
        assert!(pick("*.sub.example.com").is_none());
        // Platform names keep the platform wildcard.
        assert!(Arc::ptr_eq(&pick("app.jkbase.app").unwrap(), &apex));
    }

    #[test]
    fn a_tenant_wildcard_can_never_shadow_platform_names() {
        let (r, apex) = resolver();
        // Control never admits these, but even if a key slipped in, platform SNIs are
        // classified BEFORE the tenant-wildcard fallback.
        let rogue = ck(&["*.jkbase.app"]);
        r.hosts
            .write()
            .unwrap()
            .insert("*.jkbase.app".into(), rogue.clone());
        let got = r.select("api.jkbase.app").unwrap();
        assert!(Arc::ptr_eq(&got, &apex));
        assert!(!Arc::ptr_eq(&got, &rogue));
    }

    fn cfg_with_zone(zone: &str) -> TlsConfig {
        struct NoDns;
        #[async_trait]
        impl DnsProvider for NoDns {
            async fn create_txt(&self, _: &str, _: &str) -> Result<String> {
                unreachable!()
            }
            async fn delete_txt(&self, _: &str) -> Result<()> {
                unreachable!()
            }
        }
        TlsConfig {
            domain: "jkbase.app".into(),
            cert_dir: PathBuf::from("/nonexistent"),
            dns_provider: Arc::new(NoDns),
            acme_email: "ops@example.com".into(),
            acme_directory: None,
            acme_ca_root: None,
            acme_delegation_zone: zone.into(),
            dns_lookup: Arc::new(|_, _| Box::pin(async { Ok(Vec::new()) })),
            order_gate: None,
            tenant_orders_per_3h: 60,
            tenant_renewal_reserve_percent: 33,
        }
    }

    /// A DNS table: `(name, rtype)` → answers.
    fn dns(table: &[(&str, &str, &[&str])]) -> DnsLookup {
        let table: HashMap<(String, String), Vec<String>> = table
            .iter()
            .map(|(n, t, a)| {
                (
                    (n.to_string(), t.to_string()),
                    a.iter().map(|x| x.to_string()).collect(),
                )
            })
            .collect();
        Arc::new(move |name, rtype| {
            let a = table
                .get(&(name, rtype.to_string()))
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(a) })
        })
    }

    #[tokio::test]
    async fn pre_order_check_requires_the_exact_delegation_cname() {
        let want = "ab12._acme-delegation.jkbase.app";
        let at = |targets: &[&str]| {
            let t: Vec<&str> = targets.to_vec();
            dns(&[("_acme-challenge.play.develup.win", "CNAME", &t)])
        };
        assert!(
            delegation_in_place(
                &at(&["AB12._acme-delegation.jkbase.app."]),
                "play.develup.win",
                want
            )
            .await.unwrap()
        );
        // Removed, or pointed elsewhere (e.g. another domain's label): no order.
        assert!(!delegation_in_place(&at(&[]), "play.develup.win", want).await.unwrap());
        assert!(
            !delegation_in_place(
                &at(&["ffff._acme-delegation.jkbase.app."]),
                "play.develup.win",
                want
            )
            .await.unwrap()
        );
    }

    /// Review a4: a CAA `issue ";"` passes the CNAME check but fails EVERY order at the
    /// CA. It is now refused before any order (and before any budget is charged).
    #[tokio::test]
    async fn caa_pre_check_follows_rfc8659() {
        let none = dns(&[]);
        assert!(caa_permits(&none, "n1.attacker.com", true).await.unwrap());
        // Forbid-all at the base, or at an ancestor (tree climbing).
        let forbid = dns(&[("n1.attacker.com", "CAA", &["0 issue \";\""])]);
        assert!(!caa_permits(&forbid, "n1.attacker.com", true).await.unwrap());
        let parent = dns(&[("attacker.com", "CAA", &["0 issue \"digicert.com\""])]);
        assert!(!caa_permits(&parent, "n1.attacker.com", false).await.unwrap());
        // The closest set wins, even if an ancestor would forbid.
        let closest = dns(&[
            ("n1.attacker.com", "CAA", &["0 issue \"letsencrypt.org\""]),
            ("attacker.com", "CAA", &["0 issue \";\""]),
        ]);
        assert!(caa_permits(&closest, "n1.attacker.com", false).await.unwrap());
        // Wildcards read `issuewild` when present, else `issue`.
        let split = dns(&[(
            "b.example.com",
            "CAA",
            &[
                "0 issue \"letsencrypt.org\"",
                "0 issuewild \";\"",
                "0 iodef \"mailto:x@example.com\"",
            ],
        )]);
        assert!(caa_permits(&split, "b.example.com", false).await.unwrap());
        assert!(!caa_permits(&split, "b.example.com", true).await.unwrap());
        // Parameters after `;`, case, and iodef-only sets.
        assert!(caa_set_permits(
            &["128 issue \"LetsEncrypt.org; accounturi=x\"".to_string()],
            true
        ));
        assert!(caa_set_permits(
            &["0 iodef \"mailto:x@y\"".to_string()],
            true
        ));
        // Unparseable (RFC 3597) records are ignored, not trusted to deny.
        assert!(caa_set_permits(&["\\# 5 0005697373".to_string()], false));
    }

    #[test]
    fn issue_backoff_doubles_to_a_day_then_wildcards_give_up_until_reset() {
        assert_eq!(issue_backoff(1), 5 * 60);
        assert_eq!(issue_backoff(2), 10 * 60);
        assert_eq!(issue_backoff(4), 40 * 60);
        assert_eq!(issue_backoff(9), 1280 * 60);
        assert_eq!(issue_backoff(10), ISSUE_BACKOFF_MAX);
        assert_eq!(issue_backoff(u32::MAX), ISSUE_BACKOFF_MAX);

        let mut book = IssueHealthBook::default();
        let h = "*.play.develup.win";
        let t0 = 1_000_000u64;
        assert!(book.begin(h, t0));
        // In flight: no duplicate order.
        assert!(!book.due(h, t0));
        assert!(!book.fail(h, t0, true));
        assert!(!book.due(h, t0 + 4 * 60));
        assert!(book.due(h, t0 + 5 * 60));
        let mut now = t0;
        for n in 2..=WILDCARD_MAX_FAILURES {
            now += ISSUE_BACKOFF_MAX;
            assert!(book.begin(h, now), "attempt {n}");
            assert_eq!(book.fail(h, now, true), n == WILDCARD_MAX_FAILURES);
        }
        // Given up: never due again, however long we wait…
        assert_eq!(book.stopped(h, now), Some(None));
        assert!(!book.due(h, now + ISSUE_BACKOFF_MAX * 30));
        // …until the owner re-verifies.
        book.reset(h);
        assert!(book.due(h, now));
        assert!(book.begin(h, now));
        book.succeed(h);
        assert!(book.stopped(h, now).is_none() && book.due(h, now));
        // A reset during an in-flight order keeps it deduped.
        assert!(book.begin(h, now));
        book.reset(h);
        assert!(!book.due(h, now));

        // A custom host never gives up: it keeps retrying at the cap.
        let c = "docs.example.com";
        let mut now = t0;
        for _ in 0..50 {
            assert!(book.begin(c, now));
            assert!(!book.fail(c, now, false));
            now += ISSUE_BACKOFF_MAX;
        }
        assert!(book.due(c, now));
    }

    #[test]
    fn a_budget_block_reports_failed_with_a_retry_time_and_then_expires() {
        let mut book = IssueHealthBook::default();
        let h = "*.play.develup.win";
        assert!(book.begin(h, 100));
        book.block(h, 500);
        assert_eq!(book.stopped(h, 100), Some(Some(500)));
        assert!(!book.due(h, 499));
        assert!(book.due(h, 500));
        assert!(book.stopped(h, 500).is_none());
        // A block isn't a failure: no backoff growth.
        assert!(book.begin(h, 500));
        assert!(!book.fail(h, 500, true));
        assert_eq!(book.0[h].failures, 1);
    }

    /// Review: give-up state must survive a restart.
    #[test]
    fn issue_health_persists_give_up_and_backoff_but_not_in_flight() {
        let mut book = IssueHealthBook::default();
        for i in 0..WILDCARD_MAX_FAILURES {
            assert!(book.begin("*.a.example.com", u64::from(i) * ISSUE_BACKOFF_MAX));
            book.fail("*.a.example.com", u64::from(i) * ISSUE_BACKOFF_MAX, true);
        }
        assert!(book.begin("docs.example.com", 0));
        book.fail("docs.example.com", 0, false);
        assert!(book.begin("*.inflight.example.com", 0));

        let dir = std::env::temp_dir().join(format!("jk-health-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(ISSUE_HEALTH_FILE);
        std::fs::write(&path, serde_json::to_vec(&book).unwrap()).unwrap();
        let back = load_health(&path);
        assert_eq!(back.stopped("*.a.example.com", u64::MAX), Some(None));
        assert!(!back.due("docs.example.com", 1));
        assert!(back.due("docs.example.com", ISSUE_BACKOFF_BASE));
        // An order in flight at shutdown didn't finish: it's due again after restart.
        assert!(back.due("*.inflight.example.com", 0));
        // A missing / corrupt file is an empty book.
        std::fs::write(&path, b"{not json").unwrap();
        assert!(load_health(&path).0.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tenant_bucket_caps_orders_per_3h_and_refills() {
        let mut b = TokenBucket::per_3h(60, 0, 0);
        for _ in 0..60 {
            assert!(b.try_take(0, false));
        }
        assert!(!b.try_take(0, false));
        // One order's worth refills every 3 minutes.
        assert!(!b.try_take(179, false));
        assert!(b.try_take(180, false));
        assert!(!b.try_take(180, false));
        b.refund();
        assert!(b.try_take(180, false));
        // Never above capacity, however long idle.
        let mut b = TokenBucket::per_3h(2, 0, 0);
        assert!(
            b.try_take(1_000_000, false)
                && b.try_take(1_000_000, false)
                && !b.try_take(1_000_000, false)
        );
        // Zero disables tenant issuance entirely.
        assert!(!TokenBucket::per_3h(0, 0, 0).try_take(1_000_000, true));
    }

    /// Review N2: new-cert churn can drain only the unreserved part of the bucket;
    /// renewals of already-issued certs can always use the reserve.
    #[test]
    fn renewal_reserve_survives_new_cert_churn() {
        let mut b = TokenBucket::per_3h(60, 33, 0);
        let mut new_orders = 0;
        while b.try_take(0, false) {
            new_orders += 1;
        }
        // 60 − 19.8 reserved → 40 new orders at most.
        assert_eq!(new_orders, 40);
        let mut renewals = 0;
        while b.try_take(0, true) {
            renewals += 1;
        }
        assert_eq!(renewals, 20);
        // A 100% reserve serves renewals only.
        let mut r = TokenBucket::per_3h(10, 100, 0);
        assert!(!r.try_take(0, false));
        assert!(r.try_take(0, true));
    }

    #[test]
    fn wildcard_order_publishes_only_at_the_minted_delegation_name() {
        let cfg = cfg_with_zone(&default_acme_delegation_zone("jkbase.app"));
        let label = "0123456789abcdef0123456789abcdef";
        let o = wildcard_order("*.play.develup.win", Some(label), &cfg).unwrap();
        // One wildcard identifier (the base apex is not part of a wildcard route) …
        assert_eq!(o.identifiers.len(), 1);
        assert!(matches!(&o.identifiers[0], Identifier::Dns(d) if d == "*.play.develup.win"));
        // … validated at `_acme-challenge.play.develup.win`, which the tenant CNAMEs here.
        assert_eq!(
            o.challenge_name,
            format!("{label}._acme-delegation.jkbase.app")
        );
        // No/garbled label → no order at all (never publish under a tenant-shaped name).
        for bad in [
            None,
            Some(""),
            Some("../x"),
            Some("ABC"),
            Some("a.b"),
            Some("_x"),
        ] {
            assert!(
                wildcard_order("*.play.develup.win", bad, &cfg).is_none(),
                "{bad:?}"
            );
        }
        assert!(wildcard_order("play.develup.win", Some(label), &cfg).is_none());
    }

    #[test]
    fn rfc2136_backend_can_write_the_delegated_challenge_name() {
        // RFC2136_ZONE defaults to --domain; the delegation zone sits under it, so the
        // existing backend writes wildcard challenges with no extra config.
        let p = Rfc2136Provider::new(
            "192.0.2.1:53",
            "jkbase.app",
            "acme-key",
            "c2VjcmV0",
            "hmac-sha256",
        )
        .unwrap();
        let cfg = cfg_with_zone(&default_acme_delegation_zone("jkbase.app"));
        let o = wildcard_order("*.play.develup.win", Some("ab12"), &cfg).unwrap();
        assert!(p.record_and_zone(&o.challenge_name, "v").is_ok());
        // …and it can NEVER be pointed at the tenant's own zone.
        assert!(
            p.record_and_zone("_acme-challenge.play.develup.win", "v")
                .is_err()
        );
    }

    #[test]
    fn cert_cache_dir_is_confined_to_the_cert_dir() {
        let root = Path::new("/var/jkbase/certs");
        assert_eq!(
            cert_cache_dir(root, "*.play.develup.win").unwrap(),
            root.join("wildcard").join("play.develup.win")
        );
        assert_eq!(
            cert_cache_dir(root, "docs.example.com").unwrap(),
            root.join("custom").join("docs.example.com")
        );
        for bad in [
            "",
            "..",
            "../etc",
            "a/../../b",
            "*.",
            "*..x",
            "a/b",
            "*.*.x.com",
            ".x",
        ] {
            assert!(cert_cache_dir(root, bad).is_none(), "{bad:?}");
        }
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

    /// Review (TLS M2): a platform-side failure — resolver outage, DNS provider or CA
    /// trouble — must never strand a tenant wildcard. Only strikes count toward give-up;
    /// plain failures still back off.
    #[test]
    fn only_strikes_count_toward_give_up() {
        let mut book = IssueHealthBook::default();
        let h = "*.play.develup.win";
        let mut now = 1_000_000u64;
        for _ in 0..(WILDCARD_MAX_FAILURES * 4) {
            assert!(book.begin(h, now));
            assert!(!book.fail(h, now, false), "a transient failure gave up");
            assert!(!book.due(h, now), "a transient failure must still back off");
            now += ISSUE_BACKOFF_MAX;
        }
        // Tenant-caused failures after a long transient streak get the full allowance.
        for n in 1..=WILDCARD_MAX_FAILURES {
            assert!(book.begin(h, now));
            assert_eq!(book.fail(h, now, true), n == WILDCARD_MAX_FAILURES);
            now += ISSUE_BACKOFF_MAX;
        }
        // Old books (no `strikes`) still load.
        let old: IssueHealthBook =
            serde_json::from_str(r#"{"x.example.com":{"failures":3,"next_attempt":5,"gave_up":false,"blocked_until":null}}"#)
                .unwrap();
        assert_eq!(old.0["x.example.com"].strikes, 0);
    }

    /// Review (TLS M1): an order finishing after its host was removed must free the
    /// host's slot, or a re-add could never issue again until a restart.
    #[test]
    fn an_order_outliving_its_host_frees_the_slot() {
        let mut book = IssueHealthBook::default();
        let h = "x.example.com";
        assert!(book.begin(h, 10));
        book.reset(h); // forget_cert during the order: stays deduped…
        assert!(!book.due(h, 10));
        book.reset(h); // …the finishing order's own forget_cert…
        book.succeed(h); // …then it frees the slot.
        assert!(book.due(h, 10) && book.begin(h, 10));
    }

    /// A failed or hung lookup is no verdict: it surfaces as `Err` (→ transient), never
    /// as "no CNAME" / "no CAA".
    #[tokio::test(start_paused = true)]
    async fn failed_or_hung_lookups_are_errors_not_answers() {
        let failing: DnsLookup =
            Arc::new(|_, _| Box::pin(async { Err(anyhow::anyhow!("SERVFAIL")) }));
        assert!(delegation_in_place(&failing, "b.example.com", "x.z.jkbase.app").await.is_err());
        assert!(caa_permits(&failing, "b.example.com", true).await.is_err());
        let hung: DnsLookup = Arc::new(|_, _| Box::pin(std::future::pending()));
        assert!(delegation_in_place(&hung, "b.example.com", "x.z.jkbase.app").await.is_err());
        assert!(caa_permits(&hung, "b.example.com", false).await.is_err());
    }
}
