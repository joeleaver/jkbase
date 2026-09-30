//! Live DNS-01 issuance through the REAL `CertManager` against a real ACME CA (Pebble) and a
//! real RFC2136 nameserver (BIND) — the piece the unit tests can't cover, because
//! `instant_acme::Account` only talks to a CA. Ignored by default; `tools/wildcard-issuance-e2e.sh`
//! brings up Pebble + BIND in Docker, exports the `JK_E2E_*` env and runs it.
//!
//! Proves, end to end: the platform apex + `*.db` wildcards issue over RFC2136; a tenant
//! wildcard issues through CNAME delegation (`_acme-challenge.<base>` in the TENANT's zone →
//! `<label>._acme-delegation.<platform>`, written by the platform); the challenge TXT is
//! cleaned up; and a wildcard whose delegation CNAME is missing places NO order.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::proto::op::ResponseCode;
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
use hickory_client::udp::UdpClientStream;
use jkbase_common::routing::DomainTarget;
use jkbase_proxy::tls::{CertManager, DnsLookup, HostCertState, Rfc2136Provider, TlsConfig};
use tokio::net::UdpSocket;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} unset — run tools/wildcard-issuance-e2e.sh"))
}

/// Straight to the test nameserver (the zones are private), same `Ok`/`Err` contract as the
/// production DoH lookup: NOERROR/NXDOMAIN answer, anything else fails.
fn ns_lookup(ns: SocketAddr) -> DnsLookup {
    Arc::new(move |name: String, rtype: &'static str| {
        Box::pin(async move {
            let rt = RecordType::from_str(rtype)?;
            let stream = UdpClientStream::<UdpSocket>::new(ns);
            let (mut client, bg) = AsyncClient::connect(stream).await?;
            tokio::spawn(bg);
            let resp = client.query(Name::from_str(&name)?, DNSClass::IN, rt).await?;
            match resp.response_code() {
                ResponseCode::NoError | ResponseCode::NXDomain => {}
                rc => anyhow::bail!("{name} {rtype}: {rc}"),
            }
            Ok(resp
                .answers()
                .iter()
                .filter(|r| r.record_type() == rt)
                .filter_map(|r| r.data().map(|d| d.to_string()))
                .collect())
        })
    })
}

#[tokio::test]
#[ignore = "needs Pebble + BIND: tools/wildcard-issuance-e2e.sh"]
async fn tenant_wildcard_issues_through_cname_delegation() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    // As the server does at startup (both ring and aws-lc are linked in).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ns: SocketAddr = env("JK_E2E_DNS").parse().unwrap();
    let cert_dir = PathBuf::from(env("JK_E2E_CERT_DIR"));
    let provider = Rfc2136Provider::new(
        &ns.to_string(),
        "jk.test",
        "jkbase-e2e",
        &env("JK_E2E_TSIG_SECRET"),
        "hmac-sha256",
    )
    .unwrap();
    let lookup = ns_lookup(ns);
    let cfg = TlsConfig {
        domain: "jk.test".into(),
        cert_dir: cert_dir.clone(),
        dns_provider: Arc::new(provider),
        acme_email: "ops@jk.test".into(),
        acme_directory: Some(env("JK_E2E_ACME_DIR")),
        acme_ca_root: Some(PathBuf::from(env("JK_E2E_ACME_ROOT"))),
        acme_delegation_zone: "_acme-delegation.jk.test".into(),
        dns_lookup: lookup.clone(),
        order_gate: None,
        tenant_orders_per_3h: 60,
        tenant_renewal_reserve_percent: 33,
    };
    let target = |label: &str| DomainTarget {
        project_id: "p".into(),
        site: None,
        acme_delegation: Some(label.into()),
    };
    let domains = Arc::new(tokio::sync::RwLock::new(HashMap::from([
        // Delegated in the tenant zone (see the script's tenant.test zone file).
        ("*.play.tenant.test".to_string(), target("e2elabel01")),
        // No `_acme-challenge` CNAME at all.
        ("*.nodelegate.tenant.test".to_string(), target("e2elabel02")),
    ])));

    // Boot issues the platform apex + `*.db` wildcards over RFC2136 (fails the test if not).
    let mgr = CertManager::new(cfg, domains, false).await.expect("platform certs");
    assert!(cert_dir.join("fullchain.pem").exists());
    assert!(cert_dir.join("db-fullchain.pem").exists());

    mgr.ensure_cert("*.play.tenant.test").await;
    assert_eq!(mgr.cert_state("*.play.tenant.test"), HostCertState::Issued);
    let pem = cert_dir.join("wildcard/play.tenant.test/fullchain.pem");
    assert!(pem.exists(), "tenant wildcard cert not cached at {}", pem.display());
    // The platform removes its challenge answer once the order completes.
    let txt = lookup("e2elabel01._acme-delegation.jk.test".into(), "TXT")
        .await
        .unwrap();
    assert!(txt.is_empty(), "challenge TXT left behind: {txt:?}");

    // Not delegated: the pre-check refuses before any order (no cert dir, not issued).
    mgr.ensure_cert("*.nodelegate.tenant.test").await;
    assert_ne!(mgr.cert_state("*.nodelegate.tenant.test"), HostCertState::Issued);
    assert!(!cert_dir.join("wildcard/nodelegate.tenant.test").exists());
}
