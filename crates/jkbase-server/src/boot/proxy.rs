//! The public proxy's configuration: its wake seams, the socket-activated listeners and the
//! managed-DB reach-plane auth callback.

use super::Planes;
use crate::cli::Args;
use crate::socket_activation;
use crate::wake::{app_wake_callback, db_reach_wake_callback};
use anyhow::Result;
use jkbase_control::store::Store;
use jkbase_proxy::db_relay::DbRelayRegistry;
use jkbase_proxy::tls::CertManager;
use jkbase_proxy::{ActivityTracker, ProxyConfig};
use std::sync::Arc;

pub(crate) fn proxy_config(
    args: &Args,
    store: &Store,
    planes: &Planes,
    activity_tracker: &ActivityTracker,
    cert_manager: Option<Arc<CertManager>>,
    db_relay_registry: &Arc<DbRelayRegistry>,
) -> Result<ProxyConfig> {
    // The proxy's two wake seams: HTTP/WebSocket routing wakes the APP VM (it forwards the request
    // to the returned IP); the `jkbase-db` edge wakes the VM serving the managed DB.
    let wake_callback = app_wake_callback(
        planes.platform.clone(),
        planes.routing.clone(),
        planes.domains.clone(),
        planes.shipper.clone(),
    );
    let db_wake_callback = db_reach_wake_callback(
        planes.platform.clone(),
        planes.routing.clone(),
        planes.domains.clone(),
        planes.shipper.clone(),
    );

    let api_addr = format!("127.0.0.1:{}", args.api_port);

    // Zero-bounce Phase 2: adopt the systemd-activated public :80/:443 fds if present (so the
    // listening sockets — and their accept backlog — survive this binary's restart). When activated
    // but a name is missing, FAIL CLOSED: the port is held by systemd, so serve()'s bind() fallback
    // would hit EADDRINUSE (adversarial HIGH-3). Not activated (local dev) ⇒ None ⇒ serve() binds.
    let (proxy_http_listener, proxy_https_listener) = if socket_activation::activated() {
        let http = match socket_activation::take_listener("proxy-http") {
            Some(l) => Some(tokio::net::TcpListener::from_std(l)?),
            None => anyhow::bail!(
                "socket-activated but no fd named 'proxy-http' — check jkbase-proxy-http.socket FileDescriptorName="
            ),
        };
        let https = if args.tls {
            match socket_activation::take_listener("proxy-https") {
                Some(l) => Some(tokio::net::TcpListener::from_std(l)?),
                None => anyhow::bail!(
                    "socket-activated but no fd named 'proxy-https' — check jkbase-proxy-https.socket FileDescriptorName="
                ),
            }
        } else {
            None
        };
        (http, https)
    } else {
        (None, None)
    };

    // Managed-DB reach plane: the live-relay registry (shared with the idle loop, the
    // drain, and revocation) + the auth callback that resolves a preamble against the
    // control store. The closure closes over a `Store` clone, so `jkbase-proxy` needs no
    // `jkbase-control` dependency (mirrors `wake_callback`). The tls-exporter channel-bind
    // ([R-replay]) is checked edge-side BEFORE this runs.
    let db_auth_store = store.clone();
    let db_auth_callback: jkbase_proxy::DbAuthCallback =
        Arc::new(move |akid: &str, secret: &str, claimed_project: &str| {
            let key = db_auth_store.lookup_db_access_key(akid).ok().flatten()?;
            if !key.verify_secret(secret) {
                return None;
            }
            // [R1] The SNI's claimed project must equal the KEY's project.
            if key.project_id != claimed_project {
                return None;
            }
            // Owner re-bind: the key's tenant must still own the project (fail-closed if
            // the project was deleted or transferred — an orphaned key can't be inherited).
            let project = db_auth_store.get_project(&key.project_id).ok().flatten()?;
            if project.tenant_id.as_deref() != Some(key.tenant_id.as_str()) {
                return None;
            }
            let splice_secret = db_auth_store
                .get_db_splice_secret(&key.project_id)
                .ok()
                .flatten()?;
            // The owner re-bind above proved `project.tenant_id == Some(key.tenant_id)`,
            // so a successful auth always has an owner. Resolve the owner's effective
            // per-tenant caps here (server-side, over the store) so the edge can enforce
            // them without a control-store dependency. On a store error, fall back to
            // the conservative platform default rather than an unbounded cap.
            let quota = db_auth_store
                .get_tenant_quota(&key.tenant_id)
                .unwrap_or(jkbase_control::store::DEFAULT_TENANT_QUOTA);
            Some(jkbase_proxy::DbAuthOk {
                project_id: key.project_id,
                splice_secret,
                tenant_id: Some(key.tenant_id),
                warm_vm_max: quota.warm_vm_max,
                warm_relay_max: quota.warm_relay_max,
            })
        });

    Ok(ProxyConfig {
        http_port: args.proxy_port,
        https_port: if args.tls {
            Some(args.https_port)
        } else {
            None
        },
        platform_domain: args.domain.clone(),
        cert_manager,
        api_addr: Some(api_addr),
        storage_addr: Some(format!("127.0.0.1:{}", args.storage_port)),
        auth_addr: Some(format!("127.0.0.1:{}", args.auth_port)),
        domains: Some(planes.domains.clone()),
        activity_tracker: Some(activity_tracker.clone()),
        wake_callback: Some(wake_callback),
        db_wake_callback: Some(db_wake_callback),
        backend_port: 80,
        relay_idle_timeout: jkbase_wsproxy::DEFAULT_RELAY_IDLE_TIMEOUT,
        max_concurrent_upgrades: 1024,
        http_listener: proxy_http_listener,
        https_listener: proxy_https_listener,
        db_auth_callback: Some(db_auth_callback),
        db_relay_registry: Some(db_relay_registry.clone()),
        db_max_concurrent: 1024,
        db_preauth_max: 256,
        // One source IP may hold at most 1/8 of the global preauth pool, so a single host
        // can't slow-loris every slot for the preamble deadline and deny the DB reach plane
        // platform-wide ([R6]); still ample headroom for a legit sidecar's connection bursts.
        db_preauth_per_ip_max: 32,
        db_max_per_project: 64,
    })
}
