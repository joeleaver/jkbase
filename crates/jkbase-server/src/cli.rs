//! Command-line surface of `jkbase-server`: the run-time [`Args`], their up-front validation,
//! and the host facts resolved from them (host id, guest kernel).

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::warn;

#[derive(Parser)]
#[command(name = "jkbase-server", about = "jkbase platform server")]
pub(crate) struct Args {
    #[arg(long, default_value = "/var/jkbase")]
    pub(crate) data_dir: PathBuf,

    #[arg(long)]
    pub(crate) fc_dir: PathBuf,

    #[arg(long)]
    pub(crate) agent_bin: PathBuf,

    #[arg(long, default_value = "9090")]
    pub(crate) api_port: u16,

    /// Local port for the tenant S3 object-store service. Bound on 127.0.0.1 and
    /// reached only via the proxy's `storage.{domain}` reserved-host branch.
    #[arg(long, default_value = "9091")]
    pub(crate) storage_port: u16,

    /// Local port for the jkbase-Auth issuer service (P3). Bound on 127.0.0.1 and
    /// reached only via the proxy's `auth.{domain}` reserved-host branch.
    #[arg(long, default_value = "9092")]
    pub(crate) auth_port: u16,

    #[arg(long, default_value = "8080")]
    pub(crate) proxy_port: u16,

    #[arg(long, default_value = "jkbase.app")]
    pub(crate) domain: String,

    #[arg(long)]
    pub(crate) tls: bool,

    #[arg(long, default_value = "443")]
    pub(crate) https_port: u16,

    /// ACME DNS-01 provider for the wildcard cert: "cloudflare" (default) or "rfc2136".
    #[arg(long, env = "ACME_DNS_PROVIDER", default_value = "cloudflare")]
    pub(crate) acme_dns_provider: String,

    // --- Cloudflare provider (ACME_DNS_PROVIDER=cloudflare) ---
    #[arg(long, env = "CLOUDFLARE_API_TOKEN")]
    pub(crate) cloudflare_token: Option<String>,

    #[arg(long, env = "CLOUDFLARE_ZONE_ID")]
    pub(crate) cloudflare_zone_id: Option<String>,

    #[arg(long, env = "ACME_EMAIL")]
    pub(crate) acme_email: Option<String>,

    // --- RFC2136 provider (ACME_DNS_PROVIDER=rfc2136): dynamic DNS UPDATE + TSIG ---
    /// Authoritative nameserver to send dynamic updates to, as host:port.
    #[arg(long, env = "RFC2136_NAMESERVER")]
    pub(crate) rfc2136_nameserver: Option<String>,

    /// Zone origin to update; defaults to --domain.
    #[arg(long, env = "RFC2136_ZONE")]
    pub(crate) rfc2136_zone: Option<String>,

    /// TSIG key name (must match the server's key).
    #[arg(long, env = "RFC2136_TSIG_NAME")]
    pub(crate) rfc2136_tsig_name: Option<String>,

    /// TSIG shared secret, base64-encoded (as in a BIND key file).
    #[arg(long, env = "RFC2136_TSIG_SECRET")]
    pub(crate) rfc2136_tsig_secret: Option<String>,

    /// TSIG algorithm: hmac-sha256 (default) | hmac-sha384 | hmac-sha512.
    #[arg(long, env = "RFC2136_TSIG_ALGORITHM", default_value = "hmac-sha256")]
    pub(crate) rfc2136_tsig_algorithm: String,

    /// Zone under --domain holding the DNS-01 TXT answers for tenant wildcard domains
    /// (their `_acme-challenge.<base>` CNAMEs to `<random>.<this zone>`). Must be
    /// writable by the ACME DNS-01 backend. Defaults to `_acme-delegation.<domain>`.
    #[arg(long, env = "ACME_DELEGATION_ZONE")]
    pub(crate) acme_delegation_zone: Option<String>,

    /// Max wildcard domains (any status) per tenant. Each is an ACME order stream on the
    /// shared platform account, so keep this small.
    #[arg(long, env = "MAX_WILDCARD_DOMAINS_PER_TENANT", default_value = "20")]
    pub(crate) max_wildcard_domains_per_tenant: usize,

    /// Global cap on TENANT-initiated ACME orders (custom + wildcard certs, all tenants)
    /// per 3 hours. Keep it well under the CA's per-account order limit (Let's Encrypt:
    /// 300 / 3 h): the remainder is reserved for the platform's own certs.
    #[arg(long, env = "TENANT_ACME_ORDERS_PER_3H", default_value = "60")]
    pub(crate) tenant_acme_orders_per_3h: u32,

    /// Per-tenant ACME order budget per 24 hours (persisted; survives domain removal,
    /// re-add and restart). Over it, the tenant's certs report `tls: failed` with a
    /// retry time.
    #[arg(long, env = "TENANT_ACME_ORDERS_PER_DAY", default_value = "20")]
    pub(crate) tenant_acme_orders_per_day: usize,

    /// Max share (percent) of `TENANT_ACME_ORDERS_PER_3H` any ONE tenant may use per 3 h,
    /// so a single tenant can't starve everyone else's issuance.
    #[arg(long, env = "TENANT_ACME_MAX_SHARE_PERCENT", default_value = "25")]
    pub(crate) tenant_acme_max_share_percent: u32,

    /// Percent of `TENANT_ACME_ORDERS_PER_3H` reserved for RENEWALS of certs already
    /// issued, so new-cert churn can't block renewals.
    #[arg(
        long,
        env = "TENANT_ACME_RENEWAL_RESERVE_PERCENT",
        default_value = "33"
    )]
    pub(crate) tenant_acme_renewal_reserve_percent: u32,

    /// Idle timeout in seconds before VMs hibernate (0 = disable)
    #[arg(long, default_value = "300")]
    pub(crate) idle_timeout_secs: u64,

    /// Use the Let's Encrypt staging environment (untrusted certs; avoids prod rate limits)
    #[arg(long)]
    pub(crate) acme_staging: bool,

    /// ACME directory URL to use instead of Let's Encrypt (a private CA such as step-ca, or
    /// Pebble for tests). Overrides --acme-staging.
    #[arg(long, env = "ACME_DIRECTORY_URL")]
    pub(crate) acme_directory_url: Option<String>,

    /// PEM root(s) to trust for the ACME directory's own HTTPS, when it isn't publicly trusted.
    #[arg(long, env = "ACME_CA_ROOT")]
    pub(crate) acme_ca_root: Option<std::path::PathBuf>,

    /// Bind address for the build egress proxy (host-side default-deny forward
    /// proxy with allowlist + public-IP pinning). Disabled when unset. Build VMs
    /// route their dependency fetches through this; bind it where only the build
    /// network can reach it (e.g. the build gateway IP). Ignored when --build-net
    /// is set (then it binds on the build gateway automatically).
    #[arg(long)]
    pub(crate) egress_addr: Option<String>,

    /// Enable the isolated build network so build VMs fetch deps through the
    /// egress proxy and are sealed for compile (provision the bridge + firewall
    /// first with tools/setup-build-net.sh).
    #[arg(long)]
    pub(crate) build_net: bool,

    #[arg(long, default_value = "jkbuild0")]
    pub(crate) build_bridge: String,

    #[arg(long, default_value = "172.31.0.1")]
    pub(crate) build_gateway: String,

    #[arg(long, default_value = "3128")]
    pub(crate) build_proxy_port: u16,

    /// Port of the SECOND egress proxy — public-any mode (allowlist bypassed, SSRF
    /// pin retained) — used only by `builder = "dockerfile"` builds (their FROM/RUN
    /// need broad egress). OPT-IN: unset (default) = no public-any proxy, so a box's
    /// egress posture is unchanged until an operator deliberately enables it. To
    /// turn it on, set this (e.g. 3129) AND pass the same PROXY_ANY_PORT to
    /// tools/setup-build-net.sh so the firewall opens it.
    #[arg(long)]
    pub(crate) build_proxy_any_port: Option<u16>,

    /// Enable the cross-tenant package MIRROR on the narrow build proxy: CONNECTs to
    /// package registries (crates.io/npm/PyPI) are TLS-terminated and served from a
    /// shared content-addressed cache ({data_dir}/buildmirror), so an upstream package
    /// is fetched once and reused by every tenant. OPT-IN and DORMANT by default — a
    /// box's egress posture is unchanged until enabled. Requires the shared build CA at
    /// {data_dir}/build-ca/ca.key AND build toolchains baked to trust it (run
    /// `jkbase-server gen-build-ca` then rebake the toolchains). Only meaningful with
    /// --build-net (the mirror rides the narrow proxy).
    #[arg(long)]
    pub(crate) build_mirror: bool,

    /// Host-wide build-memory budget (MiB) shared by EVERY build VM of every tenant: a VM
    /// reserves its cgroup cap (guest RAM + VMM headroom; 4608 MiB for a default 4096 MiB VM)
    /// before booting; builds that don't fit queue, admitted fairly across tenants (the tenant
    /// holding least goes first, so one tenant's backlog can't stall others), for at most twice
    /// the build-VM timeout before failing "capacity busy". This is what makes an admin-granted bigger build
    /// VM (`jkbase quota --set-build-mem-mib`) safe on a shared host. The default admits four
    /// default-size VMs at once; size it to the RAM the box can give builds alongside its
    /// tenant VMs. The server refuses to start with a budget too small for one default VM.
    #[arg(long, default_value = "18432")]
    pub(crate) build_mem_budget_mib: u32,

    /// Ceiling (bytes) on the package mirror's content store. Once the cached blobs
    /// exceed this, the mirror evicts least-recently-used artifacts (via the substrate
    /// delete seam) back under the cap, so an untrusted tenant flooding the mirror with
    /// distinct registry artifacts cannot fill {data_dir} (shared with redb/runtime
    /// data) and DoS the host. Only consulted when --build-mirror is set; default 10 GiB.
    /// Set well above a single artifact (per-blob cap is 1 GiB) for an effective cache.
    #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024)]
    pub(crate) build_mirror_max_bytes: u64,

    /// Platform-operator admin token. When set, a `POST /projects/{id}/quota`
    /// bearing `X-Admin-Token: <this>` may raise per-project limits ABOVE the
    /// platform defaults and target any project. Unset (default) = no admin path:
    /// every tenant stays clamped to defaults. This is an OPERATOR credential,
    /// not a tenant privilege — keep it out of tenant reach.
    #[arg(long, env = "JKBASE_ADMIN_TOKEN")]
    pub(crate) admin_token: Option<String>,

    /// The platform's own public/uplink IP(s) (comma-separated) — where the proxy /
    /// control API / object-store terminate. Stamped into each VM's `_platform.json` as the
    /// Zone-2 deny-set so a function cannot reach `api.{domain}` (control plane) by IP or
    /// domain-fronting (P0-EGRESS-PLATFORM-BY-IP). When unset, the server auto-discovers
    /// the global IPs on the default-route uplink (mirrors tools/setup-bridge.sh). Set this
    /// to be explicit / on hosts where auto-discovery is wrong (e.g. behind NAT).
    #[arg(long, env = "JKBASE_PLATFORM_IPS", value_delimiter = ',')]
    pub(crate) platform_ips: Vec<String>,

    // --- HA cluster identity (HA P0: schema/config only — parsed, validated, and
    // logged, but NOT yet wired into placement/failover; later phases consume it) ---
    /// Stable, cluster-unique id for THIS server instance. Unset = derive from the
    /// system hostname (single-node default); give each node a distinct id to form a
    /// cluster (and a distinct id per process for a single-box sim cluster).
    #[arg(long, env = "JKBASE_HOST_ID")]
    pub(crate) host_id: Option<String>,

    /// Placement region for this host; projects are placed least-loaded WITHIN a
    /// region (P3). Default "default" = one flat region (single-node).
    #[arg(long, env = "JKBASE_REGION", default_value = "default")]
    pub(crate) region: String,

    /// Address peers/the proxy use to forward to THIS host (deploy forwarding P3,
    /// routing backend P4). Unset on single-node.
    #[arg(long, env = "JKBASE_PUBLIC_ADDR")]
    pub(crate) public_addr: Option<String>,

    /// Firecracker CPU template this host bakes into its VMs from first boot (P5); a
    /// warm cross-host restore needs source+target to match. Unset = cold-boot only.
    #[arg(long, env = "JKBASE_CPU_TEMPLATE_ID")]
    pub(crate) cpu_template_id: Option<String>,

    /// Guest-kernel identity for warm/cold migration decisions (P5). Unset = derived
    /// later from the resolved guest kernel.
    #[arg(long, env = "JKBASE_KERNEL_ID")]
    pub(crate) kernel_id: Option<String>,

    /// Declared scheduling capacity for placement bin-packing (P3): host vCPUs.
    /// 0 = unset/auto (no declared bound).
    #[arg(long, default_value_t = 0)]
    pub(crate) host_vcpus: u32,
    /// Declared host memory (MiB) for placement (P3). 0 = unset/auto.
    #[arg(long, default_value_t = 0)]
    pub(crate) host_mem_mib: u64,
    /// Declared max concurrent VMs for placement (P3). 0 = unset/auto.
    #[arg(long, default_value_t = 0)]
    pub(crate) host_max_vms: u32,

    // --- [substrate] backend selection (HA P0: schema/config only) ---
    /// Control-store backend: "redb" (default, single-node) | "etcd" (clustered).
    #[arg(long, env = "JKBASE_SUBSTRATE_CONTROL_STORE", default_value = "redb")]
    pub(crate) substrate_control_store: String,
    /// Lease backend: "flock" (default, single-node) | "etcd" (clustered).
    #[arg(long, env = "JKBASE_SUBSTRATE_LEASE", default_value = "flock")]
    pub(crate) substrate_lease: String,
    /// Data-disk provider: "localloop" (default) | "cephrbd" (clustered).
    #[arg(long, env = "JKBASE_SUBSTRATE_DATA_DISK", default_value = "localloop")]
    pub(crate) substrate_data_disk: String,
    /// Blob store: "localfs" (default) | "s3" (clustered/offsite).
    #[arg(long, env = "JKBASE_SUBSTRATE_BLOB_STORE", default_value = "localfs")]
    pub(crate) substrate_blob_store: String,
}

/// Validate the `[substrate]` backend selection (HA P0). Accepts the single-node
/// defaults and the known clustered backends; bails on an unknown name so a typo
/// fails fast instead of silently falling back. A non-default (clustered) backend is
/// accepted as config but warns that it is NOT wired until HA P1+.
pub(crate) fn validate_substrate_selection(args: &Args) -> Result<()> {
    fn check(role: &str, val: &str, allowed: &[&str]) -> Result<()> {
        if !allowed.contains(&val) {
            anyhow::bail!("unknown substrate {role} backend {val:?}; expected one of {allowed:?}");
        }
        Ok(())
    }
    check(
        "control-store",
        &args.substrate_control_store,
        &["redb", "etcd"],
    )?;
    check("lease", &args.substrate_lease, &["flock", "etcd"])?;
    check(
        "data-disk",
        &args.substrate_data_disk,
        &["localloop", "cephrbd"],
    )?;
    check("blob-store", &args.substrate_blob_store, &["localfs", "s3"])?;
    let clustered = args.substrate_control_store != "redb"
        || args.substrate_lease != "flock"
        || args.substrate_data_disk != "localloop"
        || args.substrate_blob_store != "localfs";
    if clustered {
        warn!(
            "non-default substrate backend selected; accepted as config but NOT wired until HA P1"
        );
    }
    Ok(())
}

/// This host's identity when `--host-id` is unset: the system hostname, or
/// "node-local" if that can't be read. (Single-node default; a cluster sets --host-id.)
pub(crate) fn resolve_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "node-local".to_string())
}

/// Pick the guest kernel: prefer the bumped 6.12 LTS image (erofs/fs-verity/
/// dm-verity — required for the layered runtime) when present, else fall back to
/// the historical `vmlinux.bin` so a server whose provisioning hasn't published
/// 6.12 yet still boots. Used for both the runtime VM and the build-kernel source.
pub(crate) fn resolve_guest_kernel(fc_dir: &std::path::Path) -> std::path::PathBuf {
    let lts = fc_dir.join("vmlinux-6.12.92.bin");
    if lts.exists() {
        lts
    } else {
        fc_dir.join("vmlinux.bin")
    }
}
