use anyhow::Result;
use jkbase_control::api::{self, AppState};
use jkbase_control::store::Store;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let data_dir = PathBuf::from(
        std::env::var("JKBASE_DATA_DIR").unwrap_or_else(|_| "/var/jkbase".to_string()),
    );
    let api_port: u16 = std::env::var("JKBASE_API_PORT")
        .unwrap_or_else(|_| "9090".to_string())
        .parse()?;

    tokio::fs::create_dir_all(&data_dir).await?;

    let db_path = data_dir.join("jkbase.redb");
    let deploy_dir = data_dir.join("hosting");
    tokio::fs::create_dir_all(&deploy_dir).await?;

    let store = Store::open(&db_path)?;
    let state = Arc::new(AppState::new(store, deploy_dir));
    let router = api::router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], api_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "jkbase-server listening");

    axum::serve(listener, router).await?;

    Ok(())
}
