//! Wildcard domains through the public control API (`POST/GET/DELETE
//! /projects/{id}/domains`, `…/verify`), offline: DNS answers come from an in-memory
//! table via `AppState::dns_lookup`, and the cert manager is replaced by recorders.
//! Covers the tenant-hostile invariants: ownership proof on the base, the ACME CNAME
//! delegation (random, per-domain), cross-tenant verified-overlap refusal, the
//! fail-closed capability gate, and that removal drops route + cert.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jkbase_control::api::{AppState, CertState, DomainMap, WildcardSupport, router};
use jkbase_control::auth::{self, ApiToken};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{
    AcmeOrderBudget, DomainKind, DomainRecord, DomainStatus, Project, ProjectState, Store,
    WildcardLimits,
};
use serde_json::{Value, json};

type Dns = Arc<Mutex<HashMap<(String, String), Vec<String>>>>;

/// Artificial DNS latency, to open the window between verify's read and its write.
static DNS_DELAY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Harness {
    addr: std::net::SocketAddr,
    /// Bearer tokens for tenant-1 (owns project `app`) and tenant-2 (owns `rival`).
    t1: String,
    t2: String,
    store: Store,
    dns: Dns,
    domain_map: DomainMap,
    cert_requests: Arc<Mutex<Vec<String>>>,
    cert_removed: Arc<Mutex<Vec<String>>>,
    certs: Arc<Mutex<HashMap<String, CertState>>>,
}

fn tenant_with_project(store: &Store, tenant: &str, project: &str) -> String {
    store
        .create_tenant(&auth::Tenant {
            id: tenant.to_string(),
            email: format!("{tenant}@example.com"),
            password_hash: None,
            created_at: 1,
        })
        .unwrap();
    let raw = auth::generate_token();
    store
        .save_api_token(&ApiToken {
            id: auth::generate_id(),
            tenant_id: tenant.to_string(),
            name: "default".to_string(),
            token_hash: auth::hash_token(&raw).unwrap(),
            created_at: 1,
        })
        .unwrap();
    store
        .create_project(&Project {
            id: project.to_string(),
            name: project.to_string(),
            tenant_id: Some(tenant.to_string()),
            current_version: None,
            state: ProjectState::Stopped,
            vm_ip: None,
            domains: vec![],
        })
        .unwrap();
    raw
}

async fn spawn(tag: &str, support: WildcardSupport) -> Harness {
    spawn_with(tag, support, WildcardLimits::default()).await
}

async fn spawn_with(tag: &str, support: WildcardSupport, limits: WildcardLimits) -> Harness {
    let mut base = std::env::temp_dir();
    base.push(format!("jkbase-wildcard-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let store = Store::open(&base.join("db.redb")).unwrap();
    let t1 = tenant_with_project(&store, "tenant-1", "app");
    let t2 = tenant_with_project(&store, "tenant-2", "rival");

    let dns: Dns = Arc::default();
    let domain_map: DomainMap = Arc::default();
    let cert_requests: Arc<Mutex<Vec<String>>> = Arc::default();
    let cert_removed: Arc<Mutex<Vec<String>>> = Arc::default();
    let certs: Arc<Mutex<HashMap<String, CertState>>> = Arc::default();

    let mut state = AppState::new(
        store.clone(),
        LogStore::new(base.join("logs")),
        base.join("hosting"),
    );
    state.platform_domain = "jkbase.app".to_string();
    state.wildcard_support = support;
    state.wildcard_limits = limits;
    state.domain_map = Some(domain_map.clone());
    let d = dns.clone();
    state.dns_lookup = Arc::new(move |name, rtype| {
        let answers = d
            .lock()
            .unwrap()
            .get(&(name, rtype.to_string()))
            .cloned()
            .unwrap_or_default();
        Box::pin(async move {
            let ms = DNS_DELAY_MS.load(std::sync::atomic::Ordering::SeqCst);
            if ms > 0 {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            answers
        })
    });
    let reqs = cert_requests.clone();
    state.cert_request = Some(Arc::new(move |h| reqs.lock().unwrap().push(h)));
    let c = certs.clone();
    state.cert_status = Some(Arc::new(move |h| {
        c.lock()
            .unwrap()
            .get(h)
            .copied()
            .unwrap_or(CertState::Missing)
    }));
    let rem = cert_removed.clone();
    state.cert_remove = Some(Arc::new(move |h| rem.lock().unwrap().push(h)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::new(state), "jkbase.app".to_string());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        reqwest::get(format!("http://{addr}/health")),
    )
    .await
    .expect("server did not come up")
    .expect("health request failed");

    Harness {
        addr,
        t1,
        t2,
        store,
        dns,
        domain_map,
        cert_requests,
        cert_removed,
        certs,
    }
}

impl Harness {
    async fn call(
        &self,
        token: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut req = reqwest::Client::new()
            .request(method, format!("http://{}{path}", self.addr))
            .bearer_auth(token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let v = resp.json::<Value>().await.unwrap_or(Value::Null);
        (status, v)
    }

    async fn add(&self, token: &str, project: &str, domain: &str) -> (u16, Value) {
        self.call(
            token,
            reqwest::Method::POST,
            &format!("/projects/{project}/domains"),
            Some(json!({ "domain": domain })),
        )
        .await
    }

    async fn verify(&self, token: &str, project: &str, host: &str) -> (u16, Value) {
        self.call(
            token,
            reqwest::Method::POST,
            &format!("/projects/{project}/domains/{host}/verify"),
            None,
        )
        .await
    }

    fn publish(&self, name: &str, rtype: &str, data: &str) {
        self.dns
            .lock()
            .unwrap()
            .entry((name.to_string(), rtype.to_string()))
            .or_default()
            .push(data.to_string());
    }
}

fn dns01() -> WildcardSupport {
    WildcardSupport::Dns01 {
        zone: "_acme-delegation.jkbase.app".to_string(),
    }
}

#[tokio::test]
async fn add_returns_txt_and_a_random_per_domain_acme_cname() {
    let h = spawn("add", dns01()).await;
    let (st, a) = h.add(&h.t1, "app", "*.Play.DevelUp.win.").await;
    assert_eq!(st, 200, "{a}");
    assert_eq!(a["host"], "*.play.develup.win");
    assert_eq!(a["kind"], "wildcard");
    assert_eq!(a["status"], "pending");
    // Ownership is proven on the BASE, with the ordinary custom-domain TXT challenge.
    assert_eq!(
        a["verification"]["record"],
        "_jkbase-challenge.play.develup.win"
    );
    assert!(
        a["verification"]["value"]
            .as_str()
            .unwrap()
            .starts_with("jkb_")
    );
    assert_eq!(
        a["acme_challenge"]["record"],
        "_acme-challenge.play.develup.win"
    );
    let cname = a["acme_challenge"]["cname"].as_str().unwrap().to_string();
    let label = cname
        .strip_suffix("._acme-delegation.jkbase.app")
        .expect("CNAME target sits in the platform delegation zone");
    assert_eq!(label.len(), 32);

    // A second wildcard (any tenant) never shares the delegation target.
    let (st, b) = h.add(&h.t2, "rival", "*.other.example.com").await;
    assert_eq!(st, 200, "{b}");
    assert_ne!(b["acme_challenge"]["cname"].as_str().unwrap(), cname);

    // Pending: not routable, no cert requested.
    assert!(
        h.domain_map
            .read()
            .await
            .get("*.play.develup.win")
            .is_none()
    );
    assert!(h.cert_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_and_platform_wildcards_are_rejected() {
    let h = spawn("invalid", dns01()).await;
    for bad in [
        "*.jkbase.app",
        "*.api.jkbase.app",
        "*.db.jkbase.app",
        "*.co.uk",
        "*.com",
        "*.*.example.com",
        "a.*.example.com",
        "*.github.io",
        // Platform labels are LDH: the `_`-prefixed delegation zone is unclaimable.
        "_acme-delegation",
        "_acme-delegation.jkbase.app",
        "my_site",
    ] {
        let (st, v) = h.add(&h.t1, "app", bad).await;
        assert_eq!(st, 400, "{bad}: {v}");
    }
}

#[tokio::test]
async fn wildcards_are_refused_without_a_dns01_backend_but_route_on_plain_http() {
    let h = spawn("unsupported", WildcardSupport::Unsupported).await;
    let (st, v) = h.add(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 501, "{v}");
    assert!(v["error"].as_str().unwrap().contains("DNS-01"), "{v}");
    assert!(h.store.get_domain("*.play.develup.win").unwrap().is_none());

    // Local dev (no TLS): no cert needed → no CNAME demanded; TXT alone activates it.
    let h = spawn("plain", WildcardSupport::PlainHttp).await;
    let (st, v) = h.add(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 200, "{v}");
    assert!(v["acme_challenge"].is_null());
    let token = v["verification"]["value"].as_str().unwrap().to_string();
    h.publish(
        "_jkbase-challenge.play.develup.win",
        "TXT",
        &format!("\"{token}\""),
    );
    let (st, v) = h.verify(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "active");
    assert!(v["tls"].is_null());
    assert!(h.domain_map.read().await.contains_key("*.play.develup.win"));
}

#[tokio::test]
async fn verify_needs_txt_then_cname_and_stays_pending_until_the_cert_issues() {
    let h = spawn("verify", dns01()).await;
    let (_, a) = h.add(&h.t1, "app", "*.play.develup.win").await;
    let token = a["verification"]["value"].as_str().unwrap().to_string();
    let cname = a["acme_challenge"]["cname"].as_str().unwrap().to_string();

    // No TXT yet.
    let (st, v) = h.verify(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 400, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("_jkbase-challenge.play.develup.win")
    );

    // TXT but no delegation CNAME: refused (issuance could never succeed).
    h.publish(
        "_jkbase-challenge.play.develup.win",
        "TXT",
        &format!("\"{token}\""),
    );
    let (st, v) = h.verify(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 400, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("_acme-challenge.play.develup.win")
    );

    // A CNAME to some OTHER target (e.g. another domain's label) is not accepted.
    h.publish(
        "_acme-challenge.play.develup.win",
        "CNAME",
        "ffffffffffffffffffffffffffffffff._acme-delegation.jkbase.app.",
    );
    let (st, _) = h.verify(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 400);

    h.publish(
        "_acme-challenge.play.develup.win",
        "CNAME",
        &format!("{cname}."),
    );
    let (st, v) = h.verify(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 200, "{v}");
    // Verified (stored Active, routable, issuance requested) but reported Pending until
    // the cert exists.
    assert_eq!(v["status"], "pending");
    assert_eq!(v["tls"], "provisioning");
    assert!(v["verification"].is_null());
    let rec = h.store.get_domain("*.play.develup.win").unwrap().unwrap();
    assert_eq!(rec.status, DomainStatus::Active);
    let label = cname.split('.').next().unwrap();
    assert_eq!(
        h.domain_map.read().await["*.play.develup.win"]
            .acme_delegation
            .as_deref(),
        Some(label)
    );
    assert_eq!(
        *h.cert_requests.lock().unwrap(),
        vec!["*.play.develup.win".to_string()]
    );

    h.certs
        .lock()
        .unwrap()
        .insert("*.play.develup.win".into(), CertState::Issued);
    let (_, list) = h
        .call(&h.t1, reqwest::Method::GET, "/projects/app/domains", None)
        .await;
    let w = list
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["host"] == "*.play.develup.win")
        .unwrap();
    assert_eq!(w["status"], "active");
    assert_eq!(w["tls"], "active");
}

/// Seed `host` as a VERIFIED record of tenant-2's project.
fn seed_active(h: &Harness, host: &str, kind: DomainKind) {
    h.store
        .claim_domain(&DomainRecord {
            host: host.to_string(),
            project_id: "rival".to_string(),
            tenant_id: "tenant-2".to_string(),
            site: None,
            kind,
            status: DomainStatus::Active,
            token: "jkb_t2".to_string(),
            created_at: 1,
            acme_delegation: None,
        })
        .unwrap();
}

#[tokio::test]
async fn a_base_verified_by_another_tenant_blocks_the_wildcard_and_vice_versa() {
    let h = spawn("conflict", dns01()).await;
    // Tenant-2 verified the exact base → tenant-1 can't take `*.base`.
    seed_active(&h, "sub.example.com", DomainKind::Custom);
    let (st, v) = h.add(&h.t1, "app", "*.sub.example.com").await;
    assert_eq!(st, 409, "{v}");

    // Tenant-2 verified a wildcard → tenant-1 can't take its exact base …
    seed_active(&h, "*.other.example.com", DomainKind::Wildcard);
    let (st, v) = h.add(&h.t1, "app", "other.example.com").await;
    assert_eq!(st, 409, "{v}");
    // … nor the same wildcard (global uniqueness, as for exact hosts).
    let (st, _) = h.add(&h.t1, "app", "*.other.example.com").await;
    assert_eq!(st, 409);
    // … but an exact host UNDER it is allowed (and wins routing once verified).
    let (st, v) = h.add(&h.t1, "app", "x.other.example.com").await;
    assert_eq!(st, 200, "{v}");

    // Verify-time re-check: a claim that was clean at add time loses if the other
    // tenant verified the overlapping base in the meantime.
    let (st, a) = h.add(&h.t1, "app", "*.late.example.com").await;
    assert_eq!(st, 200, "{a}");
    let token = a["verification"]["value"].as_str().unwrap().to_string();
    let cname = a["acme_challenge"]["cname"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.late.example.com", "TXT", &token);
    h.publish("_acme-challenge.late.example.com", "CNAME", &cname);
    seed_active(&h, "late.example.com", DomainKind::Custom);
    let (st, v) = h.verify(&h.t1, "app", "*.late.example.com").await;
    assert_eq!(st, 409, "{v}");
    assert_eq!(
        h.store
            .get_domain("*.late.example.com")
            .unwrap()
            .unwrap()
            .status,
        DomainStatus::Pending
    );
    assert!(!h.domain_map.read().await.contains_key("*.late.example.com"));
}

#[tokio::test]
async fn only_the_owner_can_verify_or_remove_and_removal_drops_route_and_cert() {
    let h = spawn("remove", WildcardSupport::PlainHttp).await;
    let (_, a) = h.add(&h.t1, "app", "*.play.develup.win").await;
    let token = a["verification"]["value"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.play.develup.win", "TXT", &token);

    // Another tenant can neither verify nor remove it (even via its own project path).
    let (st, _) = h.verify(&h.t2, "app", "*.play.develup.win").await;
    assert_eq!(st, 404);
    let (st, _) = h
        .call(
            &h.t2,
            reqwest::Method::DELETE,
            "/projects/rival/domains/*.play.develup.win",
            None,
        )
        .await;
    assert_eq!(st, 404);

    let (st, _) = h.verify(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 200);
    assert!(h.domain_map.read().await.contains_key("*.play.develup.win"));

    let (st, _) = h
        .call(
            &h.t1,
            reqwest::Method::DELETE,
            "/projects/app/domains/%2A.play.develup.win",
            None,
        )
        .await;
    assert_eq!(st, 204);
    assert!(h.store.get_domain("*.play.develup.win").unwrap().is_none());
    assert!(!h.domain_map.read().await.contains_key("*.play.develup.win"));
    assert_eq!(
        *h.cert_removed.lock().unwrap(),
        vec!["*.play.develup.win".to_string()]
    );
}

impl Harness {
    async fn rm(&self, token: &str, project: &str, host: &str) -> (u16, Value) {
        self.call(
            token,
            reqwest::Method::DELETE,
            &format!("/projects/{project}/domains/{host}"),
            None,
        )
        .await
    }

    async fn list(&self, token: &str, project: &str, host: &str) -> Value {
        let (_, list) = self
            .call(
                token,
                reqwest::Method::GET,
                &format!("/projects/{project}/domains"),
                None,
            )
            .await;
        list.as_array()
            .unwrap()
            .iter()
            .find(|d| d["host"] == host)
            .cloned()
            .unwrap_or(Value::Null)
    }
}

/// Review F: verify reads the claim, awaits DNS, then writes. A removal during that
/// wait — and another tenant's fresh claim on the freed key — must survive: the
/// write re-reads the row in its txn and refuses a stale claim.
#[tokio::test]
async fn verify_racing_a_removal_neither_resurrects_nor_clobbers() {
    let h = spawn("race", WildcardSupport::PlainHttp).await;
    let (st, a) = h.add(&h.t1, "app", "*.race.example.com").await;
    assert_eq!(st, 200, "{a}");
    let token = a["verification"]["value"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.race.example.com", "TXT", &token);

    DNS_DELAY_MS.store(800, std::sync::atomic::Ordering::SeqCst);
    let (addr, t1) = (h.addr, h.t1.clone());
    let verify = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!(
                "http://{addr}/projects/app/domains/*.race.example.com/verify"
            ))
            .bearer_auth(t1)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (st, _) = h.rm(&h.t1, "app", "*.race.example.com").await;
    assert_eq!(st, 204);
    let (st, v) = h.add(&h.t2, "rival", "*.race.example.com").await;
    assert_eq!(st, 200, "{v}");
    let verify_status = verify.await.unwrap();
    DNS_DELAY_MS.store(0, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(verify_status, 409);
    let row = h.store.get_domain("*.race.example.com").unwrap().unwrap();
    assert_eq!(row.tenant_id, "tenant-2");
    assert_eq!(row.status, DomainStatus::Pending);
    assert!(!h.domain_map.read().await.contains_key("*.race.example.com"));
}

/// Review: an unverified claim must not lock the real owner out forever. A fresh
/// foreign claim holds (409); once stale it is replaced, and whoever proves DNS wins.
#[tokio::test]
async fn a_stale_pending_squat_is_taken_over_by_the_owner() {
    let fresh = spawn("squat-fresh", dns01()).await;
    let (st, _) = fresh.add(&fresh.t2, "rival", "*.play.victim.com").await;
    assert_eq!(st, 200);
    let (st, v) = fresh.add(&fresh.t1, "app", "*.play.victim.com").await;
    // Not replaced while fresh — but the owner gets their own records to prove with.
    assert_eq!(st, 202, "{v}");
    assert!(v["note"].as_str().unwrap().contains("proves DNS"), "{v}");

    // Takeover grace of zero: the squat is immediately stale.
    let limits = WildcardLimits {
        pending_takeover_secs: 0,
        ..WildcardLimits::default()
    };
    let h = spawn_with("squat-stale", WildcardSupport::PlainHttp, limits).await;
    let (st, _) = h.add(&h.t2, "rival", "*.play.victim.com").await;
    assert_eq!(st, 200);
    let (st, a) = h.add(&h.t1, "app", "*.play.victim.com").await;
    assert_eq!(st, 200, "{a}");
    // The squatter's claim is gone. It may still try to prove over the owner's pending
    // row — but its own proof isn't in DNS, so it fails and the row stays the owner's.
    let (st, _) = h.verify(&h.t2, "rival", "*.play.victim.com").await;
    assert_eq!(st, 400);
    assert_eq!(
        h.store
            .get_domain("*.play.victim.com")
            .unwrap()
            .unwrap()
            .tenant_id,
        "tenant-1"
    );
    let token = a["verification"]["value"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.play.victim.com", "TXT", &token);
    let (st, v) = h.verify(&h.t1, "app", "*.play.victim.com").await;
    assert_eq!(st, 200, "{v}");
    // Verified rows are never replaceable.
    let (st, _) = h.add(&h.t2, "rival", "*.play.victim.com").await;
    assert_eq!(st, 409);
}

#[tokio::test]
async fn wildcard_claims_are_capped_per_tenant() {
    let limits = WildcardLimits {
        max_pending_per_tenant: 2,
        max_per_tenant: 3,
        ..WildcardLimits::default()
    };
    let h = spawn_with("caps", WildcardSupport::PlainHttp, limits).await;
    for base in ["a.t1.com", "b.t1.com"] {
        let (st, v) = h.add(&h.t1, "app", &format!("*.{base}")).await;
        assert_eq!(st, 200, "{v}");
    }
    let (st, v) = h.add(&h.t1, "app", "*.c.t1.com").await;
    assert_eq!(st, 429, "{v}");
    // Verifying one frees a pending slot, up to the total cap.
    let (_, a) = h.add(&h.t1, "app", "*.a.t1.com").await; // already attached → 400
    assert!(a["error"].as_str().unwrap().contains("already attached"));
    let tok = h.store.get_domain("*.a.t1.com").unwrap().unwrap().token;
    h.publish("_jkbase-challenge.a.t1.com", "TXT", &tok);
    assert_eq!(h.verify(&h.t1, "app", "*.a.t1.com").await.0, 200);
    assert_eq!(h.add(&h.t1, "app", "*.c.t1.com").await.0, 200);
    let (st, v) = h.add(&h.t1, "app", "*.d.t1.com").await;
    assert_eq!(st, 429, "{v}");
    // Caps are per tenant.
    assert_eq!(h.add(&h.t2, "rival", "*.d.t1.com").await.0, 200);
}

/// Review: the old binary's boot grandfathering recreates cached hosts that have no
/// DOMAINS row as ACTIVE, proof-less custom domains. Wildcards (whose rows it can't
/// see) and pending hosts must therefore never be in the cache.
#[tokio::test]
async fn project_domain_cache_never_holds_wildcards_or_pending_hosts() {
    let h = spawn("cache", WildcardSupport::PlainHttp).await;
    let (st, a) = h.add(&h.t2, "rival", "*.victim.com").await;
    assert_eq!(st, 200);
    assert_eq!(h.add(&h.t2, "rival", "pending.example.com").await.0, 200);
    let cache = || h.store.get_project("rival").unwrap().unwrap().domains;
    assert!(cache().is_empty(), "{:?}", cache());

    // Even once verified, a wildcard stays out of it.
    let tok = a["verification"]["value"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.victim.com", "TXT", &tok);
    assert_eq!(h.verify(&h.t2, "rival", "*.victim.com").await.0, 200);
    assert!(cache().is_empty(), "{:?}", cache());
    // A verified exact host is cached as before.
    let tok = h
        .store
        .get_domain("pending.example.com")
        .unwrap()
        .unwrap()
        .token;
    h.publish("_jkbase-challenge.pending.example.com", "TXT", &tok);
    assert_eq!(h.verify(&h.t2, "rival", "pending.example.com").await.0, 200);
    assert_eq!(cache(), vec!["pending.example.com".to_string()]);
}

/// Review: after repeated failures the cert manager stops ordering and reports
/// `tls: failed`; re-verifying (DNS re-checked) re-arms issuance.
#[tokio::test]
async fn a_given_up_wildcard_reports_failed_and_reverify_rearms_it() {
    let h = spawn("failed", dns01()).await;
    let (_, a) = h.add(&h.t1, "app", "*.play.develup.win").await;
    let tok = a["verification"]["value"].as_str().unwrap().to_string();
    let cname = a["acme_challenge"]["cname"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.play.develup.win", "TXT", &tok);
    h.publish("_acme-challenge.play.develup.win", "CNAME", &cname);
    assert_eq!(h.verify(&h.t1, "app", "*.play.develup.win").await.0, 200);
    assert_eq!(h.cert_requests.lock().unwrap().len(), 1);

    h.certs.lock().unwrap().insert(
        "*.play.develup.win".into(),
        CertState::Failed { retry_at: None },
    );
    let w = h.list(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(w["tls"], "failed");
    assert_eq!(w["status"], "pending");

    // Re-verify with the CNAME gone: refused, nothing re-armed.
    h.dns
        .lock()
        .unwrap()
        .remove(&("_acme-challenge.play.develup.win".into(), "CNAME".into()));
    assert_eq!(h.verify(&h.t1, "app", "*.play.develup.win").await.0, 400);
    assert_eq!(h.cert_requests.lock().unwrap().len(), 1);
    // CNAME back: re-armed.
    h.publish("_acme-challenge.play.develup.win", "CNAME", &cname);
    assert_eq!(h.verify(&h.t1, "app", "*.play.develup.win").await.0, 200);
    assert_eq!(h.cert_requests.lock().unwrap().len(), 2);

    // A renewal that gave up while the old cert still serves stays `active`.
    h.certs.lock().unwrap().insert(
        "*.play.develup.win".into(),
        CertState::RenewalFailed { retry_at: None },
    );
    let w = h.list(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(w["tls"], "renewal-failed");
    assert_eq!(w["status"], "active");
}

/// Review a3: a squatter bot re-taking the pending row every grace period used to rotate
/// the owner's token + ACME label, invalidating their published records. Proofs are now
/// deterministic per (tenant, host), and verify lets the owner's proof win over a foreign
/// pending row — so the owner's records never change and ping-pong gets the squatter
/// nothing.
#[tokio::test]
async fn squat_ping_pong_cannot_rotate_the_owners_records_and_proof_wins() {
    let limits = WildcardLimits {
        pending_takeover_secs: 0,
        ..WildcardLimits::default()
    };
    let h = spawn_with("pingpong", dns01(), limits).await;
    let host = "*.play.victim.com";
    let records = |v: &Value| {
        (
            v["verification"]["value"].as_str().unwrap().to_string(),
            v["acme_challenge"]["cname"].as_str().unwrap().to_string(),
        )
    };

    assert_eq!(h.add(&h.t2, "rival", host).await.0, 200); // squat
    let (st, first) = h.add(&h.t1, "app", host).await; // owner takes the stale row
    assert_eq!(st, 200, "{first}");
    let mine = records(&first);
    for round in 0..3 {
        // Bot re-takes; owner re-adds: the owner's records are the same every time.
        let (st, _) = h.add(&h.t2, "rival", host).await;
        assert_eq!(st, 200, "round {round}");
        let (st, again) = h.add(&h.t1, "app", host).await;
        assert_eq!(st, 200, "round {round}: {again}");
        assert_eq!(records(&again), mine, "round {round}");
    }
    // The squatter holds the row at the moment the owner verifies: proof still wins.
    let (_, squat) = h.add(&h.t2, "rival", host).await;
    assert_ne!(records(&squat), mine, "tenants' proofs differ");
    assert_eq!(
        h.store.get_domain(host).unwrap().unwrap().tenant_id,
        "tenant-2"
    );
    h.publish("_jkbase-challenge.play.victim.com", "TXT", &mine.0);
    h.publish("_acme-challenge.play.victim.com", "CNAME", &mine.1);
    let (st, v) = h.verify(&h.t1, "app", host).await;
    assert_eq!(st, 200, "{v}");
    let row = h.store.get_domain(host).unwrap().unwrap();
    assert_eq!(
        (row.tenant_id.as_str(), row.project_id.as_str(), row.status),
        ("tenant-1", "app", DomainStatus::Active)
    );
    assert_eq!(row.token, mine.0);
    // …and the squatter's proof, absent from DNS, never could have.
    assert_eq!(h.verify(&h.t2, "rival", host).await.0, 404);
    assert_eq!(h.add(&h.t2, "rival", host).await.0, 409);
}

/// With the default grace, a fresh foreign pending claim isn't replaced — but the owner
/// still gets their (deterministic) records (202) and wins by proving DNS.
#[tokio::test]
async fn a_fresh_squat_returns_the_owners_records_and_proof_wins() {
    let h = spawn("fresh-squat", WildcardSupport::PlainHttp).await;
    assert_eq!(h.add(&h.t2, "rival", "*.play.victim.com").await.0, 200);
    let (st, v) = h.add(&h.t1, "app", "*.play.victim.com").await;
    assert_eq!(st, 202, "{v}");
    assert!(v["note"].as_str().unwrap().contains("proves DNS"), "{v}");
    let token = v["verification"]["value"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.play.victim.com", "TXT", &token);
    let (st, v) = h.verify(&h.t1, "app", "*.play.victim.com").await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        h.store
            .get_domain("*.play.victim.com")
            .unwrap()
            .unwrap()
            .tenant_id,
        "tenant-1"
    );
    // A third party can't ride the takeover path without its own proof.
    let (st, _) = h.verify(&h.t2, "rival", "*.play.victim.com").await;
    assert_eq!(st, 404);
}

/// Review a4: add → verify → remove over fresh bases fired an immediate, backoff-reset
/// order per verify. Every order is now charged to the TENANT's persisted budget (here
/// emulating the server's gate exactly: `charge_tenant_acme_order` per order attempt),
/// so churning names or removing them refunds nothing.
#[tokio::test]
async fn order_churn_via_readd_is_bounded_by_the_tenants_persisted_budget() {
    let h = spawn("churn", dns01()).await;
    let budget = AcmeOrderBudget {
        max_orders: 5,
        window_secs: 24 * 3600,
    };
    for i in 0..12 {
        let host = format!("*.n{i}.attacker.com");
        let (st, a) = h.add(&h.t1, "app", &host).await;
        assert_eq!(st, 200, "{a}");
        let base = &host[2..];
        h.publish(
            &format!("_jkbase-challenge.{base}"),
            "TXT",
            a["verification"]["value"].as_str().unwrap(),
        );
        h.publish(
            &format!("_acme-challenge.{base}"),
            "CNAME",
            a["acme_challenge"]["cname"].as_str().unwrap(),
        );
        assert_eq!(h.verify(&h.t1, "app", &host).await.0, 200);
        assert_eq!(h.rm(&h.t1, "app", &host).await.0, 204);
    }
    // The API still asks for 12 certs; the cert manager's gate lets 5 orders through.
    let requested = h.cert_requests.lock().unwrap().clone();
    assert_eq!(requested.len(), 12);
    let allowed = requested
        .iter()
        .filter(|_| {
            h.store
                .charge_tenant_acme_order("tenant-1", 1_000, &budget)
                .unwrap()
                .is_none()
        })
        .count();
    assert_eq!(allowed, 5);
    // Another tenant has its own budget.
    assert!(
        h.store
            .charge_tenant_acme_order("tenant-2", 1_000, &budget)
            .unwrap()
            .is_none()
    );
}

/// Re-verify may re-arm a stopped cert only within the tenant's order budget; the
/// response says when it can retry.
#[tokio::test]
async fn rearm_is_refused_past_the_tenants_order_budget() {
    let h = spawn("rearm-budget", dns01()).await;
    let (_, a) = h.add(&h.t1, "app", "*.play.develup.win").await;
    let tok = a["verification"]["value"].as_str().unwrap().to_string();
    let cname = a["acme_challenge"]["cname"].as_str().unwrap().to_string();
    h.publish("_jkbase-challenge.play.develup.win", "TXT", &tok);
    h.publish("_acme-challenge.play.develup.win", "CNAME", &cname);
    assert_eq!(h.verify(&h.t1, "app", "*.play.develup.win").await.0, 200);

    // Budget spent (default 20/day), cert manager reports the block.
    let now = jkbase_control::auth::timestamp();
    for _ in 0..AcmeOrderBudget::default().max_orders {
        h.store
            .charge_tenant_acme_order("tenant-1", now, &AcmeOrderBudget::default())
            .unwrap();
    }
    h.certs.lock().unwrap().insert(
        "*.play.develup.win".into(),
        CertState::Failed {
            retry_at: Some(now + 86_400),
        },
    );
    let w = h.list(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(w["tls"], "failed");
    assert!(w["tls_error"].as_str().unwrap().contains("budget"), "{w}");
    let before = h.cert_requests.lock().unwrap().len();
    let (st, v) = h.verify(&h.t1, "app", "*.play.develup.win").await;
    assert_eq!(st, 429, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("try again after"),
        "{v}"
    );
    assert_eq!(h.cert_requests.lock().unwrap().len(), before);
}
