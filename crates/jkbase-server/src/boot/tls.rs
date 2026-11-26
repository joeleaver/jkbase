//! TLS: the ACME delegation zone, the per-tenant order budget and the cert manager.

use crate::cli::Args;
use anyhow::Result;
use jkbase_control::store::{AcmeOrderBudget, Store};
use jkbase_proxy::DomainMap;
use jkbase_proxy::tls::CertManager;
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

/// What the TLS phase hands the control app and the proxy.
pub(crate) struct Tls {
    pub(crate) acme_delegation_zone: String,
    pub(crate) acme_budget: AcmeOrderBudget,
    pub(crate) cert_manager: Option<Arc<CertManager>>,
}

pub(crate) async fn setup(
    args: &Args,
    data_dir: &Path,
    store: &Store,
    domain_map: &DomainMap,
) -> Result<Tls> {
    // Tenant wildcard certs are DNS-01 through CNAME delegation into this zone. It must sit
    // under the platform domain: that's the zone the DNS-01 backend can write, and the
    // tenant-facing CNAME target must be a platform-owned name.
    let acme_delegation_zone = args
        .acme_delegation_zone
        .clone()
        .map(|z| z.trim().trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_else(|| jkbase_proxy::tls::default_acme_delegation_zone(&args.domain));
    if !acme_delegation_zone.ends_with(&format!(".{}", args.domain)) {
        anyhow::bail!(
            "ACME_DELEGATION_ZONE '{acme_delegation_zone}' must be a zone under --domain ({})",
            args.domain
        );
    }

    if args.tenant_acme_orders_per_day == 0 {
        tracing::warn!("TENANT_ACME_ORDERS_PER_DAY=0: tenant certificates will never be ordered");
    }
    let acme_budget = jkbase_control::store::AcmeOrderBudget {
        max_orders: args.tenant_acme_orders_per_day,
        window_secs: 24 * 60 * 60,
        // One tenant's fair share of the global per-3h bucket (at least one order).
        share_max: (args.tenant_acme_orders_per_3h as usize
            * args.tenant_acme_max_share_percent as usize)
            .div_ceil(100)
            .max(1),
        share_window_secs: 3 * 60 * 60,
    };

    // Build the TLS cert manager up front (wildcard via DNS-01 + on-demand
    // per-custom-domain certs via HTTP-01) so we can wire issuance into AppState.
    let cert_manager: Option<Arc<CertManager>> = if args.tls {
        let acme_email = args
            .acme_email
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--acme-email required when --tls is enabled"))?;
        // Select the DNS-01 backend; Cloudflare is the default for back-compat.
        let dns_provider: Arc<dyn jkbase_proxy::tls::DnsProvider> = match args
            .acme_dns_provider
            .as_str()
        {
            "cloudflare" => {
                let token = args.cloudflare_token.clone().ok_or_else(|| {
                    anyhow::anyhow!("CLOUDFLARE_API_TOKEN (--cloudflare-token) required when --tls and ACME_DNS_PROVIDER=cloudflare")
                })?;
                let zone = args.cloudflare_zone_id.clone().ok_or_else(|| {
                    anyhow::anyhow!("CLOUDFLARE_ZONE_ID (--cloudflare-zone-id) required when --tls and ACME_DNS_PROVIDER=cloudflare")
                })?;
                Arc::new(jkbase_proxy::tls::CloudflareProvider::new(token, zone))
            }
            "rfc2136" => {
                let ns = args.rfc2136_nameserver.clone().ok_or_else(|| {
                    anyhow::anyhow!("RFC2136_NAMESERVER (--rfc2136-nameserver) required when ACME_DNS_PROVIDER=rfc2136")
                })?;
                let zone = args
                    .rfc2136_zone
                    .clone()
                    .unwrap_or_else(|| args.domain.clone());
                // The delegation TXTs are written through THIS zone; one outside it would
                // let tenants verify (and spend their order budget) on wildcards whose
                // every order then fails at the DNS UPDATE.
                let rfc_zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
                if acme_delegation_zone != rfc_zone
                    && !acme_delegation_zone.ends_with(&format!(".{rfc_zone}"))
                {
                    anyhow::bail!(
                        "ACME_DELEGATION_ZONE '{acme_delegation_zone}' must be inside RFC2136_ZONE '{rfc_zone}'"
                    );
                }
                let key_name = args.rfc2136_tsig_name.clone().ok_or_else(|| {
                    anyhow::anyhow!("RFC2136_TSIG_NAME (--rfc2136-tsig-name) required when ACME_DNS_PROVIDER=rfc2136")
                })?;
                let secret = args.rfc2136_tsig_secret.clone().ok_or_else(|| {
                    anyhow::anyhow!("RFC2136_TSIG_SECRET (--rfc2136-tsig-secret) required when ACME_DNS_PROVIDER=rfc2136")
                })?;
                Arc::new(jkbase_proxy::tls::Rfc2136Provider::new(
                    &ns,
                    &zone,
                    &key_name,
                    &secret,
                    &args.rfc2136_tsig_algorithm,
                )?)
            }
            other => anyhow::bail!(
                "unknown ACME_DNS_PROVIDER '{other}' (expected 'cloudflare' or 'rfc2136')"
            ),
        };
        let tls_config = jkbase_proxy::tls::TlsConfig {
            domain: args.domain.clone(),
            cert_dir: data_dir.join("certs"),
            dns_provider,
            acme_email,
            acme_directory: args.acme_directory_url.clone(),
            acme_ca_root: args.acme_ca_root.clone(),
            acme_delegation_zone: acme_delegation_zone.clone(),
            // The same resolver control's `verify` checks the CNAME with.
            dns_lookup: Arc::new(|name: String, rtype: &'static str| {
                Box::pin(jkbase_control::api::doh_lookup(name, rtype))
            }),
            order_gate: Some(tenant_order_gate(store.clone(), acme_budget.clone())),
            tenant_orders_per_3h: args.tenant_acme_orders_per_3h,
            tenant_renewal_reserve_percent: args.tenant_acme_renewal_reserve_percent,
        };
        Some(CertManager::new(tls_config, domain_map.clone(), args.acme_staging).await?)
    } else {
        None
    };
    Ok(Tls {
        acme_delegation_zone,
        acme_budget,
        cert_manager,
    })
}

/// The cert manager's per-tenant order gate: charge each tenant cert order (by domain-map
/// key) to the owning tenant's persisted budget. Unknown host, or a store error, denies
/// (fail closed; a store error retries shortly).
fn tenant_order_gate(
    store: Store,
    budget: jkbase_control::store::AcmeOrderBudget,
) -> jkbase_proxy::tls::OrderGate {
    use jkbase_proxy::tls::OrderPermit;
    Arc::new(move |host: &str| {
        let now = jkbase_control::auth::timestamp();
        let Ok(Some(rec)) = store.get_domain(host) else {
            return OrderPermit::Denied { retry_at: None };
        };
        match store.charge_tenant_acme_order(&rec.tenant_id, now, &budget) {
            Ok(None) => OrderPermit::Allowed,
            Ok(Some(t)) => OrderPermit::Denied { retry_at: Some(t) },
            Err(e) => {
                warn!(host = %host, error = %e, "ACME order budget check failed; denying");
                OrderPermit::Denied {
                    retry_at: Some(now + 300),
                }
            }
        }
    })
}
