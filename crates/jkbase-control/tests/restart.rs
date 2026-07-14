//! `POST /projects/{id}/restart` drives the deploy callback to re-inject current
//! secrets WITHOUT a rebuild. Two invariants are load-bearing and covered here:
//!   1. A bandwidth-quota-BLOCKED project must NOT be re-booted (the restart path
//!      bypasses the wake gate, so it must gate itself — else it hands a capped
//!      tenant unmetered egress for the rest of the month). The callback must not fire.
//!   2. The happy path re-runs the callback, heals the store row to Active (a restart
//!      of an idle-Hibernated project boots it Running), and reports the TRUE current
//!      version.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use jkbase_control::api::{router, AppState};
use jkbase_control::auth::{self, ApiToken};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{Project, ProjectState, QuotaStatus, Store};

struct Harness {
    addr: std::net::SocketAddr,
    token: String,
    calls: Arc<AtomicUsize>,
    store: Store,
}

/// Build a running control API over a temp store with a single tenant + API token,
/// a project, an on-disk `v{version}` deployment dir, and a deploy callback that
/// only counts its invocations (returns Ok — restart's callback is a no-op success
/// path in tests without an orchestrator).
async fn spawn(tag: &str, project_state: ProjectState, current_version: Option<u64>) -> Harness {
    let mut base = std::env::temp_dir();
    base.push(format!("jkbase-restart-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let store = Store::open(&base.join("db.redb")).unwrap();
    let logs = LogStore::new(base.join("logs"));
    let deploy_dir = base.join("data").join("hosting");
    std::fs::create_dir_all(&deploy_dir).unwrap();

    // Tenant + Bearer token (mirrors create_tenant_and_token).
    let tenant_id = "tenant-1".to_string();
    store
        .create_tenant(&auth::Tenant {
            id: tenant_id.clone(),
            email: "t@example.com".to_string(),
            password_hash: None,
            created_at: 1,
        })
        .unwrap();
    let raw_token = auth::generate_token();
    store
        .save_api_token(&ApiToken {
            id: auth::generate_id(),
            tenant_id: tenant_id.clone(),
            name: "default".to_string(),
            token_hash: auth::hash_token(&raw_token).unwrap(),
            created_at: 1,
        })
        .unwrap();

    let project_id = "app";
    store
        .create_project(&Project {
            id: project_id.to_string(),
            name: "app".to_string(),
            tenant_id: Some(tenant_id),
            current_version,
            state: project_state,
            vm_ip: None,
            domains: vec![],
        })
        .unwrap();

    // The restart handler's defence-in-depth existence probe requires the live
    // deployment dir on disk.
    if let Some(v) = current_version {
        std::fs::create_dir_all(
            deploy_dir
                .join(project_id)
                .join("deployments")
                .join(format!("v{v}")),
        )
        .unwrap();
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_cb = calls.clone();
    let mut state = AppState::new(store.clone(), logs, deploy_dir);
    state.deploy_callback = Some(Box::new(move |_id: String, _version: u64| {
        let calls = calls_cb.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::new(state), "jkbase.app".to_string());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
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
        token: raw_token,
        calls,
        store,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// [M1] A bandwidth-capped project is 402'd and its VM is NOT re-booted — the
/// callback must never fire, or the restart would defeat the monthly cap.
#[tokio::test]
async fn restart_refuses_a_bandwidth_blocked_project_without_booting() {
    let h = spawn("blocked", ProjectState::Hibernated, Some(1)).await;
    h.store
        .save_quota_status(&QuotaStatus {
            project_id: "app".to_string(),
            bandwidth_blocked: true,
            blocked_reason: Some("monthly bandwidth cap exceeded".to_string()),
            blocked_at: 1,
            blocked_month: 1,
        })
        .unwrap();

    let resp = client()
        .post(format!("http://{}/projects/app/restart", h.addr))
        .bearer_auth(&h.token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 402, "blocked project must be 402");
    assert_eq!(
        h.calls.load(Ordering::SeqCst),
        0,
        "the deploy callback must NOT run for a blocked project"
    );
    // Still Hibernated — the gate returned before any boot.
    assert_eq!(
        h.store.get_project("app").unwrap().unwrap().state,
        ProjectState::Hibernated
    );
}

/// The happy path: the callback runs, the reported version is the true current
/// version [L2], and an idle-Hibernated row is healed to Active [L1].
#[tokio::test]
async fn restart_reboots_reports_version_and_heals_state() {
    let h = spawn("ok", ProjectState::Hibernated, Some(3)).await;

    let resp = client()
        .post(format!("http://{}/projects/app/restart", h.addr))
        .bearer_auth(&h.token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["version"].as_u64(), Some(3), "reports current version");
    assert_eq!(h.calls.load(Ordering::SeqCst), 1, "callback ran once");
    assert_eq!(
        h.store.get_project("app").unwrap().unwrap().state,
        ProjectState::Active,
        "restart heals the store row to Active"
    );
}

/// Fails closed with 400 when the project has never been deployed.
#[tokio::test]
async fn restart_fails_closed_with_no_deployment() {
    let h = spawn("nodeploy", ProjectState::Stopped, None).await;

    let resp = client()
        .post(format!("http://{}/projects/app/restart", h.addr))
        .bearer_auth(&h.token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
}
