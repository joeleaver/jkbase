//! `POST /projects/{id}/db/rewrite-covers` drives a mutating `/admin/*` pass on a tenant's
//! managed DB, so the invariants covered here are about who can fire it and what it reaches:
//!   1. Only the owner — another tenant gets the same 404 as a missing project, and the
//!      transport must never run.
//!   2. The path's project id is the ONLY target handed to the transport (no body, header or
//!      query can retarget it), and only as [`DbQueryOp::RewriteCovers`].
//!   3. No admin token minted ⇒ 400 before the transport (the agent could not authorize it).
//!   4. The engine's answer comes back verbatim, and a transport failure is a JSON 502.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use jkbase_control::api::{AppState, DbQueryOp, DbQueryResult, router};
use jkbase_control::auth::{self, ApiToken};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{Project, ProjectState, Store};

struct Harness {
    addr: std::net::SocketAddr,
    token: String,
    other_token: String,
    /// Every (project id, op name) the transport was invoked with.
    calls: Arc<Mutex<Vec<(String, &'static str)>>>,
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

fn add_project(store: &Store, id: &str, tenant: &str) {
    store
        .create_project(&Project {
            id: id.to_string(),
            name: id.to_string(),
            tenant_id: Some(tenant.to_string()),
            current_version: Some(1),
            state: ProjectState::Active,
            vm_ip: None,
            domains: vec![],
        })
        .unwrap();
}

/// A control API with `app` owned by `tenant-1` and `theirs` owned by `tenant-2`, and a DB
/// transport that records its calls and answers `reply`.
async fn spawn(tag: &str, reply: Result<(u16, &'static str), &'static str>) -> Harness {
    let mut base = std::env::temp_dir();
    base.push(format!("jkbase-dbrwc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let store = Store::open(&base.join("db.redb")).unwrap();
    let logs = LogStore::new(base.join("logs"));
    let deploy_dir = base.join("data").join("hosting");
    std::fs::create_dir_all(&deploy_dir).unwrap();

    let token = add_tenant(&store, "tenant-1");
    let other_token = add_tenant(&store, "tenant-2");
    add_project(&store, "app", "tenant-1");
    add_project(&store, "theirs", "tenant-2");

    let calls = Arc::new(Mutex::new(Vec::new()));
    let calls_cb = calls.clone();
    let mut state = AppState::new(store.clone(), logs, deploy_dir);
    state.db_query_callback = Some(Arc::new(move |id: String, op: DbQueryOp| {
        let name = match op {
            DbQueryOp::Query(_) => "query",
            DbQueryOp::Schema => "schema",
            DbQueryOp::Status => "status",
            DbQueryOp::RewriteCovers => "rewrite-covers",
        };
        calls_cb.lock().unwrap().push((id, name));
        Box::pin(async move {
            reply
                .map(|(status, body)| DbQueryResult {
                    status,
                    body: body.as_bytes().to_vec(),
                })
                .map_err(str::to_string)
        })
    }));

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
        token,
        other_token,
        calls,
        store,
    }
}

async fn rewrite(h: &Harness, project: &str, token: Option<&str>) -> reqwest::Response {
    let mut req = reqwest::Client::new().post(format!(
        "http://{}/projects/{project}/db/rewrite-covers",
        h.addr
    ));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap()
}

const STATS: &str = r#"{"ok":true,"ms":12,"objects":40,"rev_edges_rewritten":7,"index_entries_rewritten":0,"cover_peers_sound":true}"#;

#[tokio::test]
async fn only_the_owner_can_run_it_and_only_on_their_own_project() {
    let h = spawn("auth", Ok((200, STATS))).await;
    h.store.mint_db_admin_token("app").unwrap();
    h.store.mint_db_admin_token("theirs").unwrap();

    assert_eq!(rewrite(&h, "app", None).await.status().as_u16(), 401);
    // Another tenant can't see the project, let alone drive its DB.
    assert_eq!(
        rewrite(&h, "app", Some(&h.other_token))
            .await
            .status()
            .as_u16(),
        404
    );
    // Nor can the owner of `app` reach `theirs`.
    assert_eq!(
        rewrite(&h, "theirs", Some(&h.token))
            .await
            .status()
            .as_u16(),
        404
    );
    assert!(
        h.calls.lock().unwrap().is_empty(),
        "the transport must never have run"
    );

    let resp = rewrite(&h, "app", Some(&h.token)).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().await.unwrap(), STATS, "engine stats verbatim");
    assert_eq!(
        *h.calls.lock().unwrap(),
        vec![("app".to_string(), "rewrite-covers")]
    );
}

#[tokio::test]
async fn no_admin_token_is_a_400_before_the_transport() {
    let h = spawn("notoken", Ok((200, STATS))).await;
    let resp = rewrite(&h, "app", Some(&h.token)).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("redeploy"));
    assert!(h.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn engine_and_transport_failures_reach_the_owner() {
    // The server's single-flight refusal (or any engine status) is passed through as-is.
    let h = spawn("busy", Ok((409, r#"{"error":"already running"}"#))).await;
    h.store.mint_db_admin_token("app").unwrap();
    let resp = rewrite(&h, "app", Some(&h.token)).await;
    assert_eq!(resp.status().as_u16(), 409);
    assert_eq!(resp.text().await.unwrap(), r#"{"error":"already running"}"#);

    let h = spawn("down", Err("wake project: Unavailable")).await;
    h.store.mint_db_admin_token("app").unwrap();
    let resp = rewrite(&h, "app", Some(&h.token)).await;
    assert_eq!(resp.status().as_u16(), 502);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "wake project: Unavailable");
}
