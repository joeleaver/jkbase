//! `GET /projects/{id}/usage` reports BOTH storage figures: the billed sample (`storage_bytes`,
//! data disks by blocks in use) and `storage_reserved_bytes` — what the quota checks count, with
//! each data disk at its full size. A UI showing only the billed figure would contradict the caps
//! (a project "using 300 MB" refused at deploy because its empty 1 GiB disk counts in full).

use std::sync::Arc;
use std::time::Duration;

use jkbase_control::api::{router, AppState};
use jkbase_control::auth::{self, ApiToken};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{Project, ProjectState, Store};

#[tokio::test]
async fn usage_reports_reserved_storage_with_disks_at_full_size() {
    let mut base = std::env::temp_dir();
    base.push(format!("jkbase-usage-storage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let data = base.join("data");
    let deploy_dir = data.join("hosting");
    std::fs::create_dir_all(&deploy_dir).unwrap();
    // A sparse 1 GiB data disk: ~nothing in use, but reserved in full.
    std::fs::create_dir_all(data.join("data-disks")).unwrap();
    std::fs::File::create(data.join("data-disks").join("app.img"))
        .unwrap()
        .set_len(1 << 30)
        .unwrap();

    let store = Store::open(&base.join("db.redb")).unwrap();
    store
        .create_tenant(&auth::Tenant {
            id: "t".to_string(),
            email: "t@example.com".to_string(),
            password_hash: None,
            created_at: 1,
        })
        .unwrap();
    let token = auth::generate_token();
    store
        .save_api_token(&ApiToken {
            id: auth::generate_id(),
            tenant_id: "t".to_string(),
            name: "default".to_string(),
            token_hash: auth::hash_token(&token).unwrap(),
            created_at: 1,
        })
        .unwrap();
    store
        .create_project(&Project {
            id: "app".to_string(),
            name: "app".to_string(),
            tenant_id: Some("t".to_string()),
            current_version: None,
            state: ProjectState::Active,
            vm_ip: None,
            domains: vec![],
        })
        .unwrap();

    let state = AppState::new(store, LogStore::new(base.join("logs")), deploy_dir);
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

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/projects/app/usage"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["storage_reserved_bytes"].as_u64(), Some(1 << 30));
    // No metering sample yet → billed is 0; the disk's reservation is reported regardless.
    assert_eq!(body["storage_bytes"].as_u64(), Some(0));
    let _ = std::fs::remove_dir_all(&base);
}
