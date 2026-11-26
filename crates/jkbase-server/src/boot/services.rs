//! The in-process loopback services the proxy forwards reserved hosts to: the tenant S3
//! object store (`storage.{domain}`) and the jkbase-Auth issuer (`auth.{domain}`).

use crate::cli::Args;
use crate::{auth_service, objectstore_service};
use jkbase_control::store::Store;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Tenant S3 object-store service on its OWN local listener (the proxy forwards
/// `storage.{domain}` to it via a reserved-host branch). Separate from the control
/// app: SigV4 auth (not Bearer), no global body cap (uploads stream to disk), and
/// it must never co-mingle with control-plane state.
pub(crate) fn spawn_storage(
    args: &Args,
    data_dir: PathBuf,
    store: &Store,
    storage_tok: CancellationToken,
) -> JoinHandle<()> {
    let svc = Arc::new(objectstore_service::ObjectStoreService::new(
        data_dir,
        store.clone(),
        format!("storage.{}", args.domain),
    ));
    // Object-store sweeper, on boot then on a timer: aborts multipart uploads older
    // than MULTIPART_MAX_AGE (S3's abort-incomplete-multipart lifecycle) and deletes
    // segments that became unreachable (overwrite/delete/abort) once their grace has
    // passed, so neither can pin disk forever. The boot pass also migrates any
    // layout-1 store to the index layout.
    {
        let sweeper = svc.clone();
        tokio::spawn(async move {
            const MULTIPART_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
            const SWEEP_INTERVAL: Duration = Duration::from_secs(600);
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tick.tick().await; // fires immediately on the first iteration (boot)
                let n = sweeper.sweep_all_stale_uploads(MULTIPART_MAX_AGE).await;
                if n > 0 {
                    info!(reaped = n, "object-store: swept stale multipart uploads");
                }
            }
        });
    }
    // Loopback bind stays IN-PROCESS (NOT socket-activated): the 127.0.0.1 P0 invariant
    // (function-outbound-io — the object-store front must never be reachable off loopback)
    // stays a structural guarantee in the binary, not a unit-file line. with_graceful_shutdown
    // drains in-flight S3 transfers on an upgrade instead of cutting them mid-stream.
    let bind = format!("127.0.0.1:{}", args.storage_port);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(&bind).await {
            Ok(listener) => {
                info!(storage = %bind, "object-store service listening");
                if let Err(e) = axum::serve(listener, svc.into_router())
                    .with_graceful_shutdown(async move { storage_tok.cancelled().await })
                    .await
                {
                    tracing::error!(error = %e, "object-store service error");
                }
            }
            Err(e) => tracing::error!(error = %e, addr = %bind, "object-store bind failed"),
        }
    })
}

/// jkbase-Auth issuer service (P3): same in-process loopback model as the object store — the
/// proxy's `auth.{domain}` reserved-host branch forwards to it; it is never reachable off
/// loopback (P0 invariant). It signs per-project JWTs with host-held private keys.
pub(crate) fn spawn_auth(
    args: &Args,
    store: &Store,
    auth_tok: CancellationToken,
) -> JoinHandle<()> {
    let svc = Arc::new(auth_service::AuthService::new(
        store.clone(),
        format!("auth.{}", args.domain),
    ));
    let bind = format!("127.0.0.1:{}", args.auth_port);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(&bind).await {
            Ok(listener) => {
                info!(auth = %bind, "jkbase-auth issuer service listening");
                if let Err(e) = axum::serve(listener, svc.into_router())
                    .with_graceful_shutdown(async move { auth_tok.cancelled().await })
                    .await
                {
                    tracing::error!(error = %e, "jkbase-auth service error");
                }
            }
            Err(e) => tracing::error!(error = %e, addr = %bind, "jkbase-auth bind failed"),
        }
    })
}
