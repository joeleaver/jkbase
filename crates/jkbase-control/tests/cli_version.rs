//! `GET /cli` is public (the CLI asks without a token) and advertises exactly the workspace's CLI
//! version + floor — the numbers `jkbase upgrade` and the CLI's staleness notice key off.

use std::sync::Arc;
use std::time::Duration;

use jkbase_common::cli_version::{CliVersionInfo, CLI_VERSION, MIN_CLI_VERSION};
use jkbase_control::api::{router, AppState};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::Store;

#[tokio::test]
async fn cli_endpoint_is_public_and_advertises_the_workspace_version() {
    let mut base = std::env::temp_dir();
    base.push(format!("jkbase-cli-version-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("hosting")).unwrap();
    let store = Store::open(&base.join("db.redb")).unwrap();
    let state = AppState::new(store, LogStore::new(base.join("logs")), base.join("hosting"));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::new(state), "jkbase.app".to_string());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });

    // No Authorization header.
    let resp = tokio::time::timeout(Duration::from_secs(5), reqwest::get(format!("http://{addr}/cli")))
        .await
        .expect("server did not come up")
        .expect("request failed");
    assert_eq!(resp.status(), 200);
    let info: CliVersionInfo = resp.json().await.unwrap();
    assert_eq!(info.latest, CLI_VERSION);
    assert_eq!(info.minimum, MIN_CLI_VERSION);
    let _ = std::fs::remove_dir_all(&base);
}
