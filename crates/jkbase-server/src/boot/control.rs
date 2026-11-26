//! The control app's state: TLS hooks, wildcard support and the lifecycle callbacks that
//! hand deploys, prechecks, teardowns and DB drops to this server.

use super::Planes;
use super::tls::Tls;
use crate::cli::Args;
use crate::deploy::handle_deploy;
use crate::deploy_gate::deploy_refusal;
use crate::teardown::{drop_dedicated_db, handle_teardown};
use jkbase_control::api::AppState;
use jkbase_control::logstore::LogStore;
use jkbase_control::store::Store;
use jkbase_proxy::DomainMap;
use std::path::PathBuf;
use std::sync::Arc;

/// The control app's state over a clone of `store` (the caller keeps its own handle for the
/// managed-DB reach-plane auth callback and the data planes).
pub(crate) fn app_state(
    args: &Args,
    store: &Store,
    log_store: &LogStore,
    deploy_dir: PathBuf,
    routing_table: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    tls: &Tls,
) -> AppState {
    let Tls {
        acme_delegation_zone,
        acme_budget,
        cert_manager,
    } = tls;
    let mut state = AppState::new(store.clone(), log_store.clone(), deploy_dir);
    state.routing_table = Some(routing_table.clone());
    state.domain_map = Some(domain_map.clone());
    state.platform_domain = args.domain.clone();
    state.admin_token = args.admin_token.clone();
    if let Some(cm) = cert_manager {
        // An explicit request (verify / re-verify) re-arms a backed-off or abandoned
        // wildcard; the reconcile loop honours the backoff.
        let cm_req = cm.clone();
        state.cert_request = Some(Arc::new(move |host: String| cm_req.request_cert(host)));
        let cm_status = cm.clone();
        state.cert_status = Some(Arc::new(move |host: &str| {
            use jkbase_control::api::CertState;
            use jkbase_proxy::tls::HostCertState;
            match cm_status.cert_state(host) {
                HostCertState::Missing => CertState::Missing,
                HostCertState::Issued => CertState::Issued,
                HostCertState::Failed { retry_at } => CertState::Failed { retry_at },
                HostCertState::RenewalFailed { retry_at } => CertState::RenewalFailed { retry_at },
            }
        }));
        let cm_remove = cm.clone();
        state.cert_remove = Some(Arc::new(move |host: String| cm_remove.forget_cert(&host)));
    }
    state.wildcard_limits.max_per_tenant = args.max_wildcard_domains_per_tenant;
    state.acme_budget = acme_budget.clone();
    // Every TLS config carries a DNS-01 backend (it's how the platform wildcard issues),
    // so wildcards are always issuable with TLS on; without TLS they route on plain HTTP.
    state.wildcard_support = if cert_manager.is_some() {
        jkbase_control::api::WildcardSupport::Dns01 {
            zone: acme_delegation_zone.clone(),
        }
    } else {
        jkbase_control::api::WildcardSupport::PlainHttp
    };
    state
}

pub(crate) fn wire_lifecycle_callbacks(state: &mut AppState, planes: &Planes) {
    let platform_for_cb = planes.platform.clone();
    let routing_for_cb = planes.routing.clone();
    let domain_for_cb = planes.domains.clone();
    let shipper_for_cb = planes.shipper.clone();
    state.deploy_callback = Some(Box::new(move |project_id: String, _version: u64| {
        let platform = platform_for_cb.clone();
        let routing = routing_for_cb.clone();
        let domains = domain_for_cb.clone();
        let shipper = shipper_for_cb.clone();
        Box::pin(
            async move { handle_deploy(&project_id, platform, routing, domains, shipper).await },
        )
    }));

    let platform_for_precheck = planes.platform.clone();
    state.deploy_precheck_callback = Some(Box::new(
        move |project_id: String, deployment_dir: PathBuf| {
            let platform = platform_for_precheck.clone();
            Box::pin(async move {
                let plat = platform.lock().await;
                deploy_refusal(&plat, &project_id, &deployment_dir).await
            })
        },
    ));

    let platform_for_teardown = planes.platform.clone();
    state.teardown_callback = Some(Box::new(move |project_id: String| {
        let platform = platform_for_teardown.clone();
        Box::pin(async move { handle_teardown(&project_id, &platform).await })
    }));

    let platform_for_db_drop = planes.platform.clone();
    state.db_drop_callback = Some(Box::new(move |project_id: String| {
        let platform = platform_for_db_drop.clone();
        Box::pin(async move { drop_dedicated_db(&project_id, &platform).await })
    }));
}
