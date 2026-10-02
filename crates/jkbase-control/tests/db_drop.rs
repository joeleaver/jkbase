//! `DELETE /projects/{id}/db/dedicated` is the tenant's only reclaim of a dedicated DB disk
//! (leaving the tier keeps it; it counts against the quota at full size). It is irreversible,
//! so the invariants covered here are about who can fire it and what it clears:
//!   1. Only the owner, and only with `confirm` echoing the project id — else the server-side
//!      drop must never run.
//!   2. A drop clears a recorded `dedicated` [R4] tier (the data a tier change would strand is
//!      gone, so migration is back-up → drop → redeploy → restore), but never a `colocated` one.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use jkbase_control::api::{router, AppState};
use jkbase_control::auth::{self, ApiToken};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{Project, ProjectState, Store};

struct Harness {
    addr: std::net::SocketAddr,
    token: String,
    other_token: String,
    calls: Arc<AtomicUsize>,
    store: Store,
}

fn add_tenant(store: &Store, id: &str) -> String {
    store
        .create_tenant(&auth::Tenant {
            id: id.to_string(),
            email: format!("{id}@example.com"),
            password_hash: None,
            created_at: 1,
        })
        .unwrap();
    let raw = auth::generate_token();
    store
        .save_api_token(&ApiToken {
            id: auth::generate_id(),
            tenant_id: id.to_string(),
            name: "default".to_string(),
            token_hash: auth::hash_token(&raw).unwrap(),
            created_at: 1,
        })
        .unwrap();
    raw
}

/// A control API with project `app` owned by `tenant-1`, a second tenant, and a drop callback
/// that counts its calls and reports `dropped`.
async fn spawn(tag: &str, dropped: bool) -> Harness {
    let mut base = std::env::temp_dir();
    base.push(format!("jkbase-dbdrop-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let store = Store::open(&base.join("db.redb")).unwrap();
    let logs = LogStore::new(base.join("logs"));
    let deploy_dir = base.join("data").join("hosting");
    std::fs::create_dir_all(&deploy_dir).unwrap();

    let token = add_tenant(&store, "tenant-1");
    let other_token = add_tenant(&store, "tenant-2");
    store
        .create_project(&Project {
            id: "app".to_string(),
            name: "app".to_string(),
            tenant_id: Some("tenant-1".to_string()),
            current_version: Some(1),
            state: ProjectState::Active,
            vm_ip: None,
            domains: vec![],
        })
        .unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_cb = calls.clone();
    let mut state = AppState::new(store.clone(), logs, deploy_dir);
    state.db_drop_callback = Some(Box::new(move |id: String| {
        let calls = calls_cb.clone();
        Box::pin(async move {
            assert_eq!(id, "app");
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(dropped)
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
        token,
        other_token,
        calls,
        store,
    }
}

async fn drop_db(h: &Harness, token: &str, confirm: &str) -> reqwest::Response {
    reqwest::Client::new()
        .delete(format!("http://{}/projects/app/db/dedicated", h.addr))
        .bearer_auth(token)
        .json(&serde_json::json!({ "confirm": confirm }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn drop_requires_the_owner_and_an_exact_confirmation() {
    let h = spawn("auth", true).await;
    // Another tenant can't even see the project.
    assert_eq!(drop_db(&h, &h.other_token, "app").await.status().as_u16(), 404);
    // The owner must echo the project id exactly.
    assert_eq!(drop_db(&h, &h.token, "").await.status().as_u16(), 400);
    assert_eq!(drop_db(&h, &h.token, "App").await.status().as_u16(), 400);
    assert_eq!(h.calls.load(Ordering::SeqCst), 0, "the drop must never have run");
}

#[tokio::test]
async fn drop_clears_a_dedicated_tier_record_only() {
    let h = spawn("tier", true).await;
    h.store.set_deployed_tier("app", "dedicated").unwrap();
    let resp = drop_db(&h, &h.token, "app").await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["dropped"], true);
    assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.store.get_deployed_tier("app").unwrap(), None);

    // A co-located DB's record survives: its data is on the app disk, untouched by a drop.
    h.store.set_deployed_tier("app", "colocated").unwrap();
    assert_eq!(drop_db(&h, &h.token, "app").await.status().as_u16(), 200);
    assert_eq!(
        h.store.get_deployed_tier("app").unwrap().as_deref(),
        Some("colocated")
    );
}

#[tokio::test]
async fn drop_reports_nothing_to_drop() {
    let h = spawn("none", false).await;
    let resp = drop_db(&h, &h.token, "app").await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["dropped"], false);
}
