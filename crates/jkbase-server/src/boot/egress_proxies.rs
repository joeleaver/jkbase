//! The build egress proxies: the narrow default-deny proxy (optionally with the package
//! mirror) and the public-any proxy for dockerfile builds.

use super::builds::PublicAnyProxy;
use crate::cli::Args;
use crate::{build_ca, egress, mirror};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

pub(crate) fn spawn_egress_proxies(
    args: &Args,
    data_dir: &Path,
    public_any_proxy: Option<PublicAnyProxy>,
) {
    // Spawn the build egress proxy (default-deny forward proxy + SSRF defense).
    // With --build-net it binds on the build gateway (where the firewall lets the
    // build VMs reach it); otherwise on an explicit --egress-addr.
    let egress_addr = if args.build_net {
        Some(format!("{}:{}", args.build_gateway, args.build_proxy_port))
    } else {
        args.egress_addr.clone()
    };
    if let Some(egress_addr) = egress_addr {
        // Optionally attach the cross-tenant package mirror to the NARROW proxy only.
        // Dormant unless --build-mirror; the public-any proxy below always stays
        // mirror-less (I-4). On any init failure we log and fall back to blind tunnels
        // rather than breaking builds.
        let mirror = if args.build_mirror {
            let ca_dir = data_dir.join("build-ca");
            match build_ca::BuildCa::load_or_generate(&ca_dir) {
                Ok(ca) => {
                    let fp = ca.fingerprint();
                    // A freshly generated CA means the operator skipped the
                    // gen-build-ca + rebake step: the build toolchains do NOT trust this
                    // CA, so every MITM'd registry handshake will fail. Warn loudly (we
                    // still proceed dormant-safe: builds fall back to the real registry
                    // cert path only if NOT mirrored — but mirrored hosts will break).
                    if ca.generated {
                        tracing::warn!(
                            ca_dir = %ca_dir.display(), fingerprint = %fp,
                            "build mirror enabled but a NEW CA was generated — toolchains must be \
                             rebaked to trust it (run `jkbase-server gen-build-ca` then rebake), \
                             else registry TLS will fail"
                        );
                    }
                    match mirror::MirrorTls::new(
                        data_dir,
                        Arc::new(build_ca::CertSigner::new(ca)),
                        args.build_mirror_max_bytes,
                    ) {
                        Ok(m) => {
                            info!(ca_dir = %ca_dir.display(), fingerprint = %fp,
                                "build package mirror enabled (narrow proxy)");
                            Some(m)
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to init build mirror; serving blind tunnels");
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to load build CA; serving blind tunnels");
                    None
                }
            }
        } else {
            None
        };
        let cfg = Arc::new(egress::EgressConfig::with_default_allowlist().with_mirror(mirror));
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&egress_addr).await {
                Ok(listener) => {
                    info!(addr = %egress_addr, "egress proxy starting");
                    egress::serve(listener, cfg).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, addr = %egress_addr, "failed to bind egress proxy")
                }
            }
        });
        // The SECOND proxy — public-any (allowlist bypassed, SSRF pin retained) — for
        // dockerfile builds. Already bound above (bind-before-arm); just serve it.
        if let Some((_, any_addr, listener)) = public_any_proxy {
            let any_cfg = Arc::new(egress::EgressConfig::allow_any_public());
            tokio::spawn(async move {
                info!(addr = %any_addr, "public-any egress proxy starting (dockerfile builds)");
                egress::serve(listener, any_cfg).await;
            });
        }
    }
}
