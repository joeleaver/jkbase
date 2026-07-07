mod build_ca;
mod build_orchestrator;
mod db_backup_store;
mod db_gateway;
mod egress;
mod handoff;
mod layer_plan;
mod log_shipper;
mod metering;
mod mirror;
mod objectstore_service;
mod rootfs_cas;
mod socket_activation;
mod vm_identity;

use anyhow::{Context, Result};
use clap::Parser;
use jkbase_common::config::PlatformEgress;
use jkbase_control::api::{self, AppState};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{
    DomainKind, DomainRecord, DomainStatus, HostCapacity, HostRecord, Project, ProjectState,
    QuotaStatus, SnapshotMeta, Store, VmAllocation, month_start_epoch,
};
use jkbase_orch::rootfs;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_proxy::tls::CertManager;
use jkbase_proxy::{
    self, ActivityTracker, DomainMap, DomainTarget, ProxyConfig, new_domain_map, new_routing_table,
};
use jkbase_substrate::{
    DataDiskProvider, FenceToken, FlockLease, Lease, LocalLoop, SubstrateError,
};
use log_shipper::LogShipper;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "jkbase-server", about = "jkbase platform server")]
struct Args {
    #[arg(long, default_value = "/var/jkbase")]
    data_dir: PathBuf,

    #[arg(long)]
    fc_dir: PathBuf,

    #[arg(long)]
    agent_bin: PathBuf,

    #[arg(long, default_value = "9090")]
    api_port: u16,

    /// Local port for the tenant S3 object-store service. Bound on 127.0.0.1 and
    /// reached only via the proxy's `storage.{domain}` reserved-host branch.
    #[arg(long, default_value = "9091")]
    storage_port: u16,

    #[arg(long, default_value = "8080")]
    proxy_port: u16,

    #[arg(long, default_value = "jkbase.app")]
    domain: String,

    #[arg(long)]
    tls: bool,

    #[arg(long, default_value = "443")]
    https_port: u16,

    /// ACME DNS-01 provider for the wildcard cert: "cloudflare" (default) or "rfc2136".
    #[arg(long, env = "ACME_DNS_PROVIDER", default_value = "cloudflare")]
    acme_dns_provider: String,

    // --- Cloudflare provider (ACME_DNS_PROVIDER=cloudflare) ---
    #[arg(long, env = "CLOUDFLARE_API_TOKEN")]
    cloudflare_token: Option<String>,

    #[arg(long, env = "CLOUDFLARE_ZONE_ID")]
    cloudflare_zone_id: Option<String>,

    #[arg(long, env = "ACME_EMAIL")]
    acme_email: Option<String>,

    // --- RFC2136 provider (ACME_DNS_PROVIDER=rfc2136): dynamic DNS UPDATE + TSIG ---
    /// Authoritative nameserver to send dynamic updates to, as host:port.
    #[arg(long, env = "RFC2136_NAMESERVER")]
    rfc2136_nameserver: Option<String>,

    /// Zone origin to update; defaults to --domain.
    #[arg(long, env = "RFC2136_ZONE")]
    rfc2136_zone: Option<String>,

    /// TSIG key name (must match the server's key).
    #[arg(long, env = "RFC2136_TSIG_NAME")]
    rfc2136_tsig_name: Option<String>,

    /// TSIG shared secret, base64-encoded (as in a BIND key file).
    #[arg(long, env = "RFC2136_TSIG_SECRET")]
    rfc2136_tsig_secret: Option<String>,

    /// TSIG algorithm: hmac-sha256 (default) | hmac-sha384 | hmac-sha512.
    #[arg(long, env = "RFC2136_TSIG_ALGORITHM", default_value = "hmac-sha256")]
    rfc2136_tsig_algorithm: String,

    /// Idle timeout in seconds before VMs hibernate (0 = disable)
    #[arg(long, default_value = "300")]
    idle_timeout_secs: u64,

    /// Use the Let's Encrypt staging environment (untrusted certs; avoids prod rate limits)
    #[arg(long)]
    acme_staging: bool,

    /// Bind address for the build egress proxy (host-side default-deny forward
    /// proxy with allowlist + public-IP pinning). Disabled when unset. Build VMs
    /// route their dependency fetches through this; bind it where only the build
    /// network can reach it (e.g. the build gateway IP). Ignored when --build-net
    /// is set (then it binds on the build gateway automatically).
    #[arg(long)]
    egress_addr: Option<String>,

    /// Enable the isolated build network so build VMs fetch deps through the
    /// egress proxy and are sealed for compile (provision the bridge + firewall
    /// first with tools/setup-build-net.sh).
    #[arg(long)]
    build_net: bool,

    #[arg(long, default_value = "jkbuild0")]
    build_bridge: String,

    #[arg(long, default_value = "172.31.0.1")]
    build_gateway: String,

    #[arg(long, default_value = "3128")]
    build_proxy_port: u16,

    /// Port of the SECOND egress proxy — public-any mode (allowlist bypassed, SSRF
    /// pin retained) — used only by `builder = "dockerfile"` builds (their FROM/RUN
    /// need broad egress). OPT-IN: unset (default) = no public-any proxy, so a box's
    /// egress posture is unchanged until an operator deliberately enables it. To
    /// turn it on, set this (e.g. 3129) AND pass the same PROXY_ANY_PORT to
    /// tools/setup-build-net.sh so the firewall opens it.
    #[arg(long)]
    build_proxy_any_port: Option<u16>,

    /// Enable the cross-tenant package MIRROR on the narrow build proxy: CONNECTs to
    /// package registries (crates.io/npm/PyPI) are TLS-terminated and served from a
    /// shared content-addressed cache ({data_dir}/buildmirror), so an upstream package
    /// is fetched once and reused by every tenant. OPT-IN and DORMANT by default — a
    /// box's egress posture is unchanged until enabled. Requires the shared build CA at
    /// {data_dir}/build-ca/ca.key AND build toolchains baked to trust it (run
    /// `jkbase-server gen-build-ca` then rebake the toolchains). Only meaningful with
    /// --build-net (the mirror rides the narrow proxy).
    #[arg(long)]
    build_mirror: bool,

    /// Ceiling (bytes) on the package mirror's content store. Once the cached blobs
    /// exceed this, the mirror evicts least-recently-used artifacts (via the substrate
    /// delete seam) back under the cap, so an untrusted tenant flooding the mirror with
    /// distinct registry artifacts cannot fill {data_dir} (shared with redb/runtime
    /// data) and DoS the host. Only consulted when --build-mirror is set; default 10 GiB.
    /// Set well above a single artifact (per-blob cap is 1 GiB) for an effective cache.
    #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024)]
    build_mirror_max_bytes: u64,

    /// Platform-operator admin token. When set, a `POST /projects/{id}/quota`
    /// bearing `X-Admin-Token: <this>` may raise per-project limits ABOVE the
    /// platform defaults and target any project. Unset (default) = no admin path:
    /// every tenant stays clamped to defaults. This is an OPERATOR credential,
    /// not a tenant privilege — keep it out of tenant reach.
    #[arg(long, env = "JKBASE_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// The platform's own public/uplink IP(s) (comma-separated) — where the proxy /
    /// control API / object-store terminate. Stamped into each VM's `_platform.json` as the
    /// Zone-2 deny-set so a function cannot reach `api.{domain}` (control plane) by IP or
    /// domain-fronting (P0-EGRESS-PLATFORM-BY-IP). When unset, the server auto-discovers
    /// the global IPs on the default-route uplink (mirrors tools/setup-bridge.sh). Set this
    /// to be explicit / on hosts where auto-discovery is wrong (e.g. behind NAT).
    #[arg(long, env = "JKBASE_PLATFORM_IPS", value_delimiter = ',')]
    platform_ips: Vec<String>,

    // --- HA cluster identity (HA P0: schema/config only — parsed, validated, and
    // logged, but NOT yet wired into placement/failover; later phases consume it) ---
    /// Stable, cluster-unique id for THIS server instance. Unset = derive from the
    /// system hostname (single-node default); give each node a distinct id to form a
    /// cluster (and a distinct id per process for a single-box sim cluster).
    #[arg(long, env = "JKBASE_HOST_ID")]
    host_id: Option<String>,

    /// Placement region for this host; projects are placed least-loaded WITHIN a
    /// region (P3). Default "default" = one flat region (single-node).
    #[arg(long, env = "JKBASE_REGION", default_value = "default")]
    region: String,

    /// Address peers/the proxy use to forward to THIS host (deploy forwarding P3,
    /// routing backend P4). Unset on single-node.
    #[arg(long, env = "JKBASE_PUBLIC_ADDR")]
    public_addr: Option<String>,

    /// Firecracker CPU template this host bakes into its VMs from first boot (P5); a
    /// warm cross-host restore needs source+target to match. Unset = cold-boot only.
    #[arg(long, env = "JKBASE_CPU_TEMPLATE_ID")]
    cpu_template_id: Option<String>,

    /// Guest-kernel identity for warm/cold migration decisions (P5). Unset = derived
    /// later from the resolved guest kernel.
    #[arg(long, env = "JKBASE_KERNEL_ID")]
    kernel_id: Option<String>,

    /// Declared scheduling capacity for placement bin-packing (P3): host vCPUs.
    /// 0 = unset/auto (no declared bound).
    #[arg(long, default_value_t = 0)]
    host_vcpus: u32,
    /// Declared host memory (MiB) for placement (P3). 0 = unset/auto.
    #[arg(long, default_value_t = 0)]
    host_mem_mib: u64,
    /// Declared max concurrent VMs for placement (P3). 0 = unset/auto.
    #[arg(long, default_value_t = 0)]
    host_max_vms: u32,

    // --- [substrate] backend selection (HA P0: schema/config only) ---
    /// Control-store backend: "redb" (default, single-node) | "etcd" (clustered).
    #[arg(long, env = "JKBASE_SUBSTRATE_CONTROL_STORE", default_value = "redb")]
    substrate_control_store: String,
    /// Lease backend: "flock" (default, single-node) | "etcd" (clustered).
    #[arg(long, env = "JKBASE_SUBSTRATE_LEASE", default_value = "flock")]
    substrate_lease: String,
    /// Data-disk provider: "localloop" (default) | "cephrbd" (clustered).
    #[arg(long, env = "JKBASE_SUBSTRATE_DATA_DISK", default_value = "localloop")]
    substrate_data_disk: String,
    /// Blob store: "localfs" (default) | "s3" (clustered/offsite).
    #[arg(long, env = "JKBASE_SUBSTRATE_BLOB_STORE", default_value = "localfs")]
    substrate_blob_store: String,
}

/// Validate the `[substrate]` backend selection (HA P0). Accepts the single-node
/// defaults and the known clustered backends; bails on an unknown name so a typo
/// fails fast instead of silently falling back. A non-default (clustered) backend is
/// accepted as config but warns that it is NOT wired until HA P1+.
fn validate_substrate_selection(args: &Args) -> Result<()> {
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
fn resolve_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "node-local".to_string())
}

// HA P2 — cluster leader election parameters.
const LEADER_SCOPE: &str = "cluster-leader";
const LEADER_TTL: Duration = Duration::from_secs(20);
const LEADER_TICK: Duration = Duration::from_secs(5);
/// Step down once leadership's time-since-last-successful-renew reaches this (a real
/// supersession steps down immediately). Keeps
/// `LEADER_FENCE_DEADLINE + (LEADER_TICK + RENEW_RPC_TIMEOUT) < LEADER_TTL` so a deposed
/// leader yields before a peer could steal its still-live key.
const LEADER_FENCE_DEADLINE: Duration = Duration::from_secs(8);

/// Outcome of evaluating one lease renewal in the fence/election loops. We must
/// discriminate a genuine loss from a transient backend blip: the substrate returns
/// [`SubstrateError::Fenced`] only when a newer token has superseded us (etcd maps an
/// expired/absent key here too) — a definitive loss — and a catch-all
/// [`SubstrateError::Backend`] / I/O error when the authority was momentarily
/// unreachable while we STILL hold the lease. Acting destructively on the latter (kill
/// a live VM / drop leadership) on one dropped packet is a self-inflicted outage, so
/// transient errors are tolerated until a deadline measured from the LAST SUCCESSFUL
/// renew (the same clock the lease TTL runs on, kept below it) before failing closed.
#[derive(Debug, PartialEq, Eq)]
enum FenceDecision {
    /// Renewal confirmed — we hold the lease; reset the last-success clock.
    Hold,
    /// Transient failure, last success still within the deadline — keep the lease, retry.
    KeepWaiting,
    /// Definitively lost (superseded/expired), or last success aged past the deadline —
    /// act now (self-fence / step down), failing closed before the lease can expire.
    FenceNow,
}

/// Decide what a renewal result means. `last_success` is when this scope's lease was last
/// confirmed; `now`/`deadline` bound how long transient failures are tolerated. Anchoring
/// at last success (not first-observed-failure) and bounding each renew RPC keeps the
/// self-fence ahead of the lease TTL even when renews hang or fail slowly under a partition.
fn evaluate_renew(
    result: &Result<FenceToken, SubstrateError>,
    last_success: Instant,
    now: Instant,
    deadline: Duration,
) -> FenceDecision {
    match result {
        Ok(_) => FenceDecision::Hold,
        // A newer token superseded us (etcd also maps an expired/absent key here): lost.
        Err(SubstrateError::Fenced { .. }) => FenceDecision::FenceNow,
        // Transient (backend unreachable / I/O / a timed-out renew RPC): we still hold the
        // lease. Tolerate until we've been unable to confirm it for `deadline` since the
        // last success — then fail closed before the TTL can expire and admit a survivor.
        Err(_) => {
            if now.duration_since(last_success) >= deadline {
                FenceDecision::FenceNow
            } else {
                FenceDecision::KeepWaiting
            }
        }
    }
}

/// HA P2 — cluster leader election. The elected leader (holder of the `cluster-leader`
/// lease) will own cluster-wide placement (P3); followers reconcile only their own host.
/// On a single node the one process wins the lease and stays leader. Backend-agnostic:
/// acquire once, then renew each tick — a no-op re-assert for `FlockLease`, the TTL
/// keepalive for a distributed lease — and on a lost/expired token drop back to
/// contender and re-acquire. `is_leader` is advisory at P2 (nothing gates on it yet);
/// the data-disk write-boundary self-fence, NOT this flag, is the split-brain guarantee.
async fn leader_election_loop(lease: Arc<dyn Lease>, host_id: String, is_leader: Arc<AtomicBool>) {
    let mut token: Option<FenceToken> = None;
    let mut last_success = Instant::now();
    loop {
        if let Some(t) = token.take() {
            // Re-assert leadership (keepalive), bounded so a blackhole partition can't hang
            // the loop. Discriminate a genuine loss (Fenced → step down now) from a transient
            // blip/timeout (retain within the deadline) so one dropped packet never flaps.
            let result =
                match tokio::time::timeout(RENEW_RPC_TIMEOUT, lease.renew(&t, LEADER_TTL)).await {
                    Ok(r) => r,
                    Err(_) => Err(SubstrateError::Backend(
                        "leader lease renew timed out".into(),
                    )),
                };
            match evaluate_renew(&result, last_success, Instant::now(), LEADER_FENCE_DEADLINE) {
                FenceDecision::Hold => {
                    last_success = Instant::now();
                    is_leader.store(true, Ordering::Relaxed);
                    token = Some(result.unwrap_or(t)); // adopt the refreshed token
                }
                FenceDecision::KeepWaiting => {
                    // Still leader — the lease is held; the authority is briefly unreachable.
                    // Keep the token and retry next tick.
                    is_leader.store(true, Ordering::Relaxed);
                    token = Some(t);
                    if let Err(e) = &result {
                        warn!(host_id = %host_id, error = %e,
                              "cluster-leader renew failed transiently; retaining leadership within deadline");
                    }
                }
                FenceDecision::FenceNow => {
                    is_leader.store(false, Ordering::Relaxed);
                    token = None;
                    warn!(host_id = %host_id, "lost cluster leadership; re-contesting");
                }
            }
        } else {
            // We are a contender: try to win the lease.
            match lease.acquire(LEADER_SCOPE, &host_id, LEADER_TTL).await {
                Ok(t) => {
                    info!(host_id = %host_id, epoch = t.epoch, "acquired cluster leadership");
                    is_leader.store(true, Ordering::Relaxed);
                    last_success = Instant::now();
                    token = Some(t);
                }
                // Another live host holds it — stay a follower and retry next tick.
                Err(SubstrateError::LeaseHeld { .. }) => is_leader.store(false, Ordering::Relaxed),
                Err(e) => {
                    is_leader.store(false, Ordering::Relaxed);
                    warn!(host_id = %host_id, error = %e, "cluster leader election error");
                }
            }
        }
        tokio::time::sleep(LEADER_TICK).await;
    }
}

/// HA P2 — the data-disk write-boundary self-fence: the split-brain safety core.
///
/// Periodically re-asserts (renews) every data-disk lease this host holds. A renewal
/// failure means the lease was lost — superseded by a survivor the leader reassigned
/// this project to, or expired under a network partition. The host then **self-fences**:
/// it kills its Firecracker process (stopping all writes) BEFORE the survivor attaches,
/// then detaches the disk. Combined with the restore-path fence (the survivor's
/// `attach_rwo` fails closed while a prior writer is provably alive), this guarantees a
/// data disk is never written by two hosts at once.
///
/// Inert on a single node: the node-local FlockLease renew always succeeds while this
/// process holds the lock, so the fence never trips. Cross-host correctness rides a
/// distributed lease (EtcdLease) and is exercised by the split-brain test harness.
async fn disk_fence_loop(platform: Arc<Mutex<PlatformState>>, lease: Arc<dyn Lease>) {
    // Per-project time of last SUCCESSFUL renew — the clock the etcd lease TTL also runs
    // on. A disk self-fences once its last success ages past DISK_FENCE_DEADLINE; a genuine
    // supersession (Fenced) self-fences immediately.
    let mut last_success: HashMap<String, Instant> = HashMap::new();
    loop {
        tokio::time::sleep(DISK_RENEW_INTERVAL).await;
        // Snapshot the held tokens, then renew OFF the platform lock — a slow or
        // unreachable lease backend must never block the whole platform.
        let held: Vec<(String, FenceToken)> = {
            let plat = platform.lock().await;
            plat.disk_tokens
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let still_held: HashSet<String> = held.iter().map(|(p, _)| p.clone()).collect();
        // Seed last-success for freshly-acquired disks (just fenced + attached).
        for (project, _) in &held {
            last_success
                .entry(project.clone())
                .or_insert_with(Instant::now);
        }
        // Renew every held disk CONCURRENTLY, each bounded by RENEW_RPC_TIMEOUT, so one
        // slow/hung disk never delays another's self-fence (the serialization the review
        // flagged) — and a blackhole partition becomes a prompt transient error.
        let mut set = tokio::task::JoinSet::new();
        for (project, token) in held {
            let lease = lease.clone();
            set.spawn(async move {
                let r = match tokio::time::timeout(
                    RENEW_RPC_TIMEOUT,
                    lease.renew(&token, DISK_LEASE_TTL),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err(SubstrateError::Backend("disk lease renew timed out".into())),
                };
                (project, token, r)
            });
        }
        while let Some(joined) = set.join_next().await {
            let (project, token, result) = match joined {
                Ok(tuple) => tuple,
                Err(_) => continue, // a renew task panicked; next tick retries
            };
            let since = last_success
                .get(&project)
                .copied()
                .unwrap_or_else(Instant::now);
            match evaluate_renew(&result, since, Instant::now(), DISK_FENCE_DEADLINE) {
                FenceDecision::Hold => {
                    last_success.insert(project, Instant::now());
                }
                FenceDecision::KeepWaiting => {
                    if let Err(e) = &result {
                        warn!(project = %project, scope = %token.scope, error = %e,
                              "data-disk lease renew failed transiently; retrying within deadline");
                    }
                }
                FenceDecision::FenceNow => {
                    last_success.remove(&project);
                    warn!(project = %project, scope = %token.scope,
                          "data-disk lease lost — self-fencing");
                    self_fence_project(&platform, &project, &token).await;
                }
            }
        }
        // Forget tracking for disks we no longer hold (torn down / fenced).
        last_success.retain(|k, _| still_held.contains(k));
    }
}

/// True iff `tokens` still maps `project` to EXACTLY `token`. The self-fence guard: a
/// concurrent (re)deploy may have rotated the disk token (a fresh, higher-epoch token
/// renewed independently) while a stale renewal was in flight; fencing then would kill
/// the live, freshly-attached VM — a self-inflicted outage. Fence only the holder of
/// the precise token whose renewal was lost.
fn token_still_held(
    tokens: &HashMap<String, FenceToken>,
    project: &str,
    token: &FenceToken,
) -> bool {
    tokens.get(project) == Some(token)
}

/// Self-fence one project whose data-disk lease was lost: kill its Firecracker (stop
/// writes) and detach the disk, so a survivor can safely take over. Guarded on token
/// identity so a redeploy that rotated the token is never killed.
async fn self_fence_project(
    platform: &Arc<Mutex<PlatformState>>,
    project_id: &str,
    lost_token: &FenceToken,
) {
    // Take the VM out under the lock, but ONLY if we still hold exactly the lost token.
    let (vm, data_disk) = {
        let mut plat = platform.lock().await;
        if !token_still_held(&plat.disk_tokens, project_id, lost_token) {
            // Token rotated (redeploy) or already released (teardown) — not ours to fence.
            return;
        }
        // Don't fence a project mid-transition: an in-flight hibernate owns the VM handle
        // (so we can neither kill it nor safely detach the loop device its FC still maps),
        // and wake re-fences on its own. We cannot act here; during the transition a
        // survivor is instead held off by the attach-time storage fence (LocalLoop liveness
        // / Ceph blocklist on `attach_rwo`) until the op releases the token, after which the
        // next tick self-fences if still lost. (A genuine loss is NOT dropped — FenceNow
        // recurs every tick and bypasses the deadline.) NB the guest may still be writing
        // in hibernate's brief pre-pause window, so this is defense-in-depth deferral, not
        // a "no writes" guarantee — the storage-layer fence is the actual backstop.
        if matches!(
            plat.vm_states.get(project_id),
            Some(VmLifecycle::Hibernating) | Some(VmLifecycle::Waking)
        ) {
            return;
        }
        tracing::error!(project = %project_id, scope = %lost_token.scope, epoch = lost_token.epoch,
               "DATA-DISK LEASE LOST — self-fencing: killing Firecracker before any survivor attaches");
        // Drop our claim first so no other path still treats us as the holder. Remove the
        // re-adoption record too: the FC is about to be killed, so a future start must NOT
        // re-adopt it (it'll cold-boot once the lease situation clears).
        plat.disk_tokens.remove(project_id);
        handoff::remove(&plat.data_dir.join("run"), project_id);
        plat.vm_states.remove(project_id);
        plat.vm_rootfs_hashes.remove(project_id);
        (plat.vms.remove(project_id), plat.data_disk.clone())
    };
    // Kill the FC HARD — the safety action — before anything slow.
    if let Some(mut vm) = vm
        && let Err(e) = vm.stop().await
    {
        tracing::error!(project = %project_id, error = %e, "self-fence: failed to kill Firecracker");
    }
    // Best-effort detach so the survivor's attach is unblocked (the lease is already lost).
    let _ = data_disk.detach(project_id).await;
}

/// A host is live iff it has beaten at least once and its last heartbeat is within
/// `threshold_secs` of `now`. The single liveness predicate the heartbeat detection,
/// reconciler, and placement all share.
fn host_is_live(h: &HostRecord, now: u64, threshold_secs: u64) -> bool {
    h.last_heartbeat != 0 && now.saturating_sub(h.last_heartbeat) <= threshold_secs
}

/// HA P3 — hosts whose heartbeat has gone stale, excluding `self_id` (we're alive) and
/// never-beaten rows (`last_heartbeat == 0`, e.g. a peer that just registered). The leader
/// reassigns these; the heartbeat loop only DETECTS them.
fn dead_hosts<'a>(
    hosts: &'a [HostRecord],
    now: u64,
    threshold_secs: u64,
    self_id: &str,
) -> Vec<&'a HostRecord> {
    hosts
        .iter()
        .filter(|h| h.host_id != self_id)
        .filter(|h| h.last_heartbeat != 0)
        .filter(|h| !host_is_live(h, now, threshold_secs))
        .collect()
}

/// Current allocation count per host (the placement load). Skips unplaced (empty host_id).
fn current_load(allocations: &[VmAllocation]) -> HashMap<String, u32> {
    let mut load: HashMap<String, u32> = HashMap::new();
    for a in allocations {
        if !a.host_id.is_empty() {
            *load.entry(a.host_id.clone()).or_insert(0) += 1;
        }
    }
    load
}

/// HA P3 placement — the least-loaded LIVE host in `region` that still has spare capacity
/// (`capacity.max_vms == 0` means unbounded). Ties broken by host_id for determinism.
/// `None` if no live host in the region can take it (region at capacity / empty).
fn place_project<'a>(
    hosts: &'a [HostRecord],
    load: &HashMap<String, u32>,
    region: &str,
    now: u64,
    dead_threshold_secs: u64,
) -> Option<&'a HostRecord> {
    hosts
        .iter()
        .filter(|h| h.region == region)
        .filter(|h| host_is_live(h, now, dead_threshold_secs))
        .filter(|h| {
            h.capacity.max_vms == 0
                || load.get(&h.host_id).copied().unwrap_or(0) < h.capacity.max_vms
        })
        .min_by(|a, b| {
            let la = load.get(&a.host_id).copied().unwrap_or(0);
            let lb = load.get(&b.host_id).copied().unwrap_or(0);
            la.cmp(&lb).then_with(|| a.host_id.cmp(&b.host_id))
        })
}

/// HA P3 — assign each orphaned project to a freshly-placed live host, in the SAME region
/// as its (now-dead) prior host so it stays near its data. Spreads multiple orphans by
/// simulating load as it assigns. Returns `(project_id, new_host_id)`; an orphan with no
/// available host in its region is omitted (the caller logs — region at capacity). Pure.
fn reassign_plan(
    orphaned: &[String],
    hosts: &[HostRecord],
    allocations: &[VmAllocation],
    now: u64,
    dead_threshold_secs: u64,
) -> Vec<(String, String)> {
    let alloc_by_project: HashMap<&str, &VmAllocation> = allocations
        .iter()
        .map(|a| (a.project_id.as_str(), a))
        .collect();
    let mut load = current_load(allocations);
    let mut out = Vec::new();
    for pid in orphaned {
        let region = alloc_by_project
            .get(pid.as_str())
            .and_then(|a| hosts.iter().find(|h| h.host_id == a.host_id))
            .map(|h| h.region.clone())
            .unwrap_or_else(|| "default".to_string());
        if let Some(h) = place_project(hosts, &load, &region, now, dead_threshold_secs) {
            *load.entry(h.host_id.clone()).or_insert(0) += 1; // simulate the assignment
            out.push((pid.clone(), h.host_id.clone()));
        }
    }
    out
}

/// HA P3 — the cluster heartbeat. Upserts THIS host's HOSTS row with a fresh
/// `last_heartbeat` every [`HEARTBEAT_INTERVAL`] (re-registering if the row vanished), so
/// peers/the leader can tell it is alive WITHOUT a cross-host TCP probe (which can't cross
/// the per-host network islands). When this host is the leader it also scans for peers
/// whose heartbeat has gone stale and logs them — the P3 reconciler consumes those to
/// reassign their projects. Single-node: the one host beats itself and sees no dead peers.
async fn host_heartbeat_loop(store: Store, mut self_host: HostRecord, is_leader: Arc<AtomicBool>) {
    loop {
        self_host.last_heartbeat = jkbase_control::auth::timestamp();
        if let Err(e) = store.save_host(&self_host) {
            warn!(host_id = %self_host.host_id, error = %e, "failed to write host heartbeat");
        }
        if is_leader.load(Ordering::Relaxed)
            && let Ok(hosts) = store.list_hosts()
        {
            let now = jkbase_control::auth::timestamp();
            for h in dead_hosts(
                &hosts,
                now,
                DEAD_HOST_THRESHOLD.as_secs(),
                &self_host.host_id,
            ) {
                warn!(host_id = %h.host_id, region = %h.region,
                      stale_secs = now.saturating_sub(h.last_heartbeat),
                      "dead host detected (stale heartbeat) — pending reconcile");
            }
        }
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
    }
}

/// What the leader's reconcile tick found needs doing to converge running → desired.
#[derive(Debug, Default, PartialEq, Eq)]
struct ReconcilePlan {
    /// Deployed, wakeable projects whose owning host is dead or absent — they need
    /// (re)placement onto a live host. Computed by the leader; APPLIED by placement (the
    /// next P3 card). Empty on a healthy single node (allocations are unplaced/local).
    orphaned: Vec<String>,
}

/// Compare desired (deployed, wakeable projects) vs running (allocations + live hosts) and
/// return the drift the leader must act on. Pure + deterministic. A host counts as live
/// iff its heartbeat is within `dead_threshold_secs`; an allocation with an empty host_id
/// is single-node/pre-placement (local) and never orphaned.
fn reconcile_plan(
    projects: &[Project],
    allocations: &[VmAllocation],
    hosts: &[HostRecord],
    now: u64,
    dead_threshold_secs: u64,
) -> ReconcilePlan {
    let live: HashSet<&str> = hosts
        .iter()
        .filter(|h| host_is_live(h, now, dead_threshold_secs))
        .map(|h| h.host_id.as_str())
        .collect();
    let alloc_by_project: HashMap<&str, &VmAllocation> = allocations
        .iter()
        .map(|a| (a.project_id.as_str(), a))
        .collect();
    let mut orphaned = Vec::new();
    for p in projects {
        if p.current_version.is_none() {
            continue; // never deployed → nothing to place
        }
        if !matches!(p.state, ProjectState::Active | ProjectState::Hibernated) {
            continue; // NeedsRedeploy / Stopped are not wakeable
        }
        if let Some(alloc) = alloc_by_project.get(p.id.as_str())
            && !alloc.host_id.is_empty()
            && !live.contains(alloc.host_id.as_str())
        {
            // Owned by a host that is no longer live → needs (re)placement.
            orphaned.push(p.id.clone());
        }
    }
    orphaned.sort();
    ReconcilePlan { orphaned }
}

/// HA P3 — the continuous cluster reconciler. Only the leader reconciles cluster-wide
/// (followers no-op here and reconcile their own host via the wake/boot paths). Each tick
/// it compares desired (deployed projects) vs running (allocations + live hosts) via
/// [`reconcile_plan`] and surfaces the drift; the actual (re)placement of orphaned
/// projects onto live hosts is the next P3 card (placement + ownership + deploy
/// forwarding) — this loop is the engine that drives it. Inert on a single node (no
/// placed allocations, so nothing is ever orphaned).
async fn reconcile_loop(platform: Arc<Mutex<PlatformState>>, is_leader: Arc<AtomicBool>) {
    loop {
        tokio::time::sleep(RECONCILE_INTERVAL).await;
        if !is_leader.load(Ordering::Relaxed) {
            continue;
        }
        // Hold the platform lock for the read + reassign writes — all fast redb ops, no VM
        // work here. On a single node `orphaned` is empty, so this is lock + 3 reads + bail.
        let plat = platform.lock().await;
        let projects = plat.store.list_projects().unwrap_or_default();
        let allocs = plat.store.list_vm_allocations().unwrap_or_default();
        let hosts = plat.store.list_hosts().unwrap_or_default();
        let now = jkbase_control::auth::timestamp();
        let plan = reconcile_plan(
            &projects,
            &allocs,
            &hosts,
            now,
            DEAD_HOST_THRESHOLD.as_secs(),
        );
        if plan.orphaned.is_empty() {
            continue;
        }
        // Place each orphan on a live host (least-loaded in its region) and reassign: update
        // the allocation's owner + bump placement_epoch. The new owner boots it on its next
        // wake/reconcile, acquiring the disk lease (whose epoch the old host has already
        // self-fenced from); the data disk moves via the substrate DataDiskProvider (Ceph).
        let reassignments = reassign_plan(
            &plan.orphaned,
            &hosts,
            &allocs,
            now,
            DEAD_HOST_THRESHOLD.as_secs(),
        );
        for (pid, new_host) in &reassignments {
            match plat.store.get_vm_allocation(pid) {
                Ok(Some(mut alloc)) => {
                    let from = alloc.host_id.clone();
                    alloc.host_id = new_host.clone();
                    alloc.placement_epoch = alloc.placement_epoch.saturating_add(1);
                    if let Err(e) = plat.store.save_vm_allocation(&alloc) {
                        warn!(project = %pid, error = %e, "reconcile: failed to persist reassignment");
                    } else {
                        info!(project = %pid, from = %from, to = %new_host,
                              epoch = alloc.placement_epoch, "reconcile: reassigned to a live host");
                    }
                }
                _ => warn!(project = %pid, "reconcile: orphan has no allocation to reassign"),
            }
        }
        let unplaced = plan.orphaned.len() - reassignments.len();
        if unplaced > 0 {
            warn!(
                unplaced,
                "reconcile: orphaned projects with no live host in-region (cluster at capacity)"
            );
        }
    }
}

/// HA P3 — where a deploy for a project must run, given its allocation + the fleet.
#[derive(Debug, PartialEq, Eq)]
enum DeployTarget {
    /// Run here: we own it, or it is unplaced (single-node / pre-placement / first deploy).
    Local,
    /// Owned by a live remote host — forward the deploy there.
    Remote {
        host_id: String,
        addr: Option<String>,
    },
    /// Owned by a host that is no longer live; the reconciler must reassign it first. Fail
    /// closed (deploy is retryable) rather than have a non-owner boot a second copy.
    OwnerDead { host_id: String },
}

/// Decide where `alloc`'s deploy belongs. Local when unplaced / owned-by-me / no-alloc;
/// Remote when a live peer owns it; OwnerDead when the owner is gone. Pure.
fn deploy_target(
    alloc: Option<&VmAllocation>,
    hosts: &[HostRecord],
    me: &str,
    now: u64,
    dead_threshold_secs: u64,
) -> DeployTarget {
    match alloc {
        None => DeployTarget::Local,
        Some(a) if a.host_id.is_empty() || a.host_id == me => DeployTarget::Local,
        Some(a) => match hosts.iter().find(|h| h.host_id == a.host_id) {
            Some(h) if host_is_live(h, now, dead_threshold_secs) => DeployTarget::Remote {
                host_id: h.host_id.clone(),
                addr: h.public_addr.clone(),
            },
            _ => DeployTarget::OwnerDead {
                host_id: a.host_id.clone(),
            },
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmLifecycle {
    Running,
    Hibernated,
    Waking,
    Hibernating,
}

struct PlatformState {
    vms: HashMap<String, VmInstance>,
    vm_states: HashMap<String, VmLifecycle>,
    /// The base-rootfs hash each RUNNING VM is ACTUALLY mapped against (cold boot ⇒ the current
    /// hash; a restored VM ⇒ the hash it restored from, which after a redeploy is the OLD blob,
    /// not `base_rootfs_hash`). Stamped into the snapshot at hibernate so the next restore + the
    /// GC reference set point at the bytes the guest RAM truly depends on. Keyed by project_id;
    /// set on commit-to-Running, removed on hibernate/teardown.
    vm_rootfs_hashes: HashMap<String, String>,
    /// Last failed-wake instant per project — the wake path fast-fails (Retry-After) within
    /// [`WAKE_BACKOFF`] of it so a doomed project can't be spun into unbounded boot attempts by
    /// continuous traffic. Cleared on a successful wake.
    wake_failures: HashMap<String, std::time::Instant>,
    store: Store,
    firecracker_bin: PathBuf,
    kernel_path: PathBuf,
    /// The content-addressed base rootfs every VM boots from: `base-rootfs/<hash>.ext4`,
    /// an IMMUTABLE blob. A redeploy that ships a new agent mints a new hash/blob next to
    /// the old one, so a snapshot taken before the redeploy still restores byte-correct
    /// against the bytes its guest RAM expects (vs. the old in-place rewrite that poisoned
    /// every pre-existing snapshot). See `base_rootfs_hash` and the startup CAS placement.
    base_rootfs_path: PathBuf,
    /// sha256 of `base_rootfs_path` — stamped into each snapshot at hibernate time and the
    /// "keep" root of the startup CAS GC.
    base_rootfs_hash: String,
    data_dir: PathBuf,
    /// Read-write-once data-disk provider (R3) + exclusive lease (R2) — every data
    /// disk is fenced through these so a restored/relocated VM can never write a disk
    /// a prior VM still holds. Single-node today (LocalLoop + FlockLease); the same
    /// seam swaps to CephRbd + EtcdLease for HA.
    data_disk: Arc<dyn DataDiskProvider>,
    lease: Arc<dyn Lease>,
    /// The live fence token per project that currently holds its data disk RWO.
    disk_tokens: HashMap<String, FenceToken>,
    /// This host's stable identity, stamped into lease tokens.
    host_id: String,
    /// HA P2: set while THIS host holds the `cluster-leader` lease. Advisory at P2 —
    /// nothing gates on it yet (placement is P3) — and the data-disk write-boundary
    /// self-fence, not this flag, is the split-brain safety guarantee.
    is_leader: Arc<AtomicBool>,
    /// Host-asserted platform egress facts (OWN object-store host + the platform's own
    /// public IP deny-set), stamped into every per-VM metadata image as `_platform.json`
    /// so the in-VM agent can recognize OWN-storage (Zone 1) and deny the control-plane /
    /// proxy IP(s) (Zone 2). Computed once at startup; the same for every VM on this host.
    platform_egress: PlatformEgress,
}

/// Data disk size (MiB) created on first use for projects that declare volumes.
const DATA_DISK_MIB: u64 = 1024;
/// Parent cgroup-v2 dir for runtime Firecrackers. Every runtime FC is migrated into a
/// `<this>/<project_id>` leaf right after spawn so it lives OUTSIDE `jkbase.service`'s
/// cgroup and survives `systemctl restart` (`KillMode=mixed` reaps only the service's own
/// cgroup) for the next process to re-adopt. Provisioned by `tools/setup-runtime-cgroup.sh`
/// (an `ExecStartPre`), mirroring `jkbase-build`. See `docs/vm-readoption-design.md` §1.
const RUNTIME_CGROUP_PARENT: &str = "/sys/fs/cgroup/jkbase-runtime";
/// How recently the `.upgrading` flag must have been written for `shutdown_signal` to treat a
/// SIGTERM as an UPGRADE (skip the drain, leave VMs for re-adoption) rather than a real
/// shutdown. A stale flag (deploy crashed after touching it but before `systemctl restart`)
/// falls back to draining — so a later operator `stop` never silently leaks running tenants.
const UPGRADE_FLAG_FRESHNESS_SECS: u64 = 300;
/// Hard ceiling (seconds) on the upgrade-restart HTTP drain (zero-bounce Phase 2). The process is
/// GUARANTEED to `process::exit(0)` within this window of the SIGTERM — event-driven (it exits the
/// instant the proxy + storage in-flight work empties), so an idle box pays ~0. Well under
/// `TimeoutStopSec=120`, and small so a slow/hostile in-flight request can't widen the successor's
/// start delay. Bulk transfers exceeding it are cut at exit (no worse than today). See
/// `docs/zero-bounce-phase2-design.md`.
const DRAIN_GRACE: Duration = Duration::from_secs(5);
/// Data-disk lease TTL — the failover horizon. With the node-local FlockLease it is moot
/// (the lock is held for the life of the process); with a distributed lease (HA) it is
/// the etcd grant TTL: a crashed/partitioned holder's key expires this long after its
/// LAST SUCCESSFUL renew, which is the earliest a survivor may take the disk. The
/// disk-fence loop self-fences once a disk's last success ages past [`DISK_FENCE_DEADLINE`]
/// — anchored at last success (NOT first-observed-failure) and with each renew bounded by
/// [`RENEW_RPC_TIMEOUT`] — so the safety relation holds even under a blackhole partition:
///   DISK_FENCE_DEADLINE + (DISK_RENEW_INTERVAL + RENEW_RPC_TIMEOUT) + kill  <  DISK_LEASE_TTL
/// i.e. the holder kills its Firecracker before its lease can expire and admit a survivor.
const DISK_LEASE_TTL: Duration = Duration::from_secs(30);
/// How often the disk-fence loop re-asserts (renews) each held data-disk lease.
const DISK_RENEW_INTERVAL: Duration = Duration::from_secs(5);
/// Self-fence once a disk's time-since-last-successful-renew reaches this (fail closed).
/// A genuine supersession ([`SubstrateError::Fenced`]) self-fences immediately regardless.
/// Satisfies the relation on [`DISK_LEASE_TTL`]: long enough that a brief blip never kills
/// a live VM, short enough to beat lease-expiry/takeover by a margin.
const DISK_FENCE_DEADLINE: Duration = Duration::from_secs(15);
/// Per-attempt bound on a lease renew RPC. Under a network blackhole an unbounded etcd
/// renew (`get` + keepalive) can hang for minutes on TCP retransmit, which would stall the
/// fence loop past the lease TTL and let a survivor attach over a still-live writer.
/// Bounding each attempt turns a hang into a prompt transient error, so the deadline clock
/// (anchored at last success) keeps advancing and the host self-fences in time.
const RENEW_RPC_TIMEOUT: Duration = Duration::from_secs(2);
/// How often a host re-asserts its own liveness into HOSTS (the cluster heartbeat).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Past this with no heartbeat, the leader treats a host as dead and (P3 reconciler/
/// placement) reassigns its projects. Tunable for the RTO budget; kept above a few
/// heartbeat intervals so one missed beat / a brief GC pause is not a false positive.
const DEAD_HOST_THRESHOLD: Duration = Duration::from_secs(15);
/// How often the leader runs the continuous cluster reconcile (desired vs running).
const RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

impl PlatformState {
    /// HA P2: whether this host currently holds cluster leadership. Advisory until P3
    /// (placement) gates on it.
    #[allow(dead_code)] // consumed by the P3 placement gate
    fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    fn allocate_ip(&self) -> Result<(String, String, String)> {
        let existing = self.store.list_vm_allocations()?;
        match next_free_octet(&existing, &self.host_id) {
            Some(octet) => {
                let (tap, ip, mac) = slot_identity(octet);
                Ok((ip, tap, mac))
            }
            None => anyhow::bail!("no available IP addresses in this host's 172.16.0.0/24 island"),
        }
    }
}

/// HA P4 — the next free last-octet in THIS host's `172.16.0.0/24` island, considering
/// only allocations owned by `host_id` (empty host_id = single-node / pre-placement =
/// ours). Each host runs the same /24 on its own L2 bridge, so a peer's IPs are on a
/// separate segment — they neither collide with ours nor count against our range. This
/// also removes the cross-host uniqueness race on the shared control store (each host
/// allocates independently). `None` when the island is full.
fn next_free_octet(allocations: &[VmAllocation], host_id: &str) -> Option<u8> {
    let used: HashSet<u8> = allocations
        .iter()
        .filter(|a| a.host_id.is_empty() || a.host_id == host_id)
        .filter_map(|a| a.ip.split('.').next_back()?.parse::<u8>().ok())
        .collect();
    (2..=254u8).find(|o| !used.contains(o))
}

/// Pick the guest kernel: prefer the bumped 6.12 LTS image (erofs/fs-verity/
/// dm-verity — required for the layered runtime) when present, else fall back to
/// the historical `vmlinux.bin` so a server whose provisioning hasn't published
/// 6.12 yet still boots. Used for both the runtime VM and the build-kernel source.
fn resolve_guest_kernel(fc_dir: &std::path::Path) -> std::path::PathBuf {
    let lts = fc_dir.join("vmlinux-6.12.92.bin");
    if lts.exists() {
        lts
    } else {
        fc_dir.join("vmlinux.bin")
    }
}

fn main() -> Result<()> {
    // Single-threaded prologue (zero-bounce Phase 2): parse + scrub the systemd socket-activation
    // env (LISTEN_*) and arm FD_CLOEXEC on every inherited listener fd BEFORE the tokio runtime —
    // and thus any worker thread or fork+exec child (jailer/FC/buildpack) — exists. remove_var is
    // racy under threads (edition 2024) and an un-CLOEXEC'd :443 fd would leak into a tenant FC.
    socket_activation::init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Bootstrap subcommand: `jkbase-server gen-build-ca [<dir>]` materializes the
    // shared build-mirror CA (ca.key + ca.crt) and exits, so the toolchain bake can
    // inject the public cert before the server proper ever runs. Detected before
    // Args::parse() so it does not require the full run-time args (--fc-dir, etc.).
    if std::env::args().nth(1).as_deref() == Some("gen-build-ca") {
        // Resolve the CA dir consistently with the server's {data_dir}/build-ca so a
        // mismatched default can't silently bake one CA while the server mints another:
        //   1) an explicit positional dir, else
        //   2) {--data-dir}/build-ca if --data-dir is on the command line, else
        //   3) /var/jkbase/build-ca (the server's default data dir).
        let argv: Vec<String> = std::env::args().collect();
        let explicit = argv
            .get(2)
            .filter(|a| !a.starts_with("--"))
            .map(PathBuf::from);
        let dir = explicit.unwrap_or_else(|| {
            let data_dir = argv
                .windows(2)
                .find(|w| w[0] == "--data-dir")
                .map(|w| PathBuf::from(&w[1]))
                .unwrap_or_else(|| PathBuf::from("/var/jkbase"));
            data_dir.join("build-ca")
        });
        let ca = build_ca::BuildCa::load_or_generate(&dir)?;
        println!(
            "build-mirror CA ready ({}): key={} cert={} fingerprint={}",
            if ca.generated {
                "generated"
            } else {
                "loaded existing"
            },
            dir.join("ca.key").display(),
            dir.join("ca.crt").display(),
            ca.fingerprint(),
        );
        return Ok(());
    }

    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // HA cluster identity (P0/P2) + [substrate] backend selection. The host id is the
    // configured --host-id, else the system hostname (single-node default); it names
    // this server in lease tokens and the P2 leader election. Validate the substrate
    // backend selection up front so a typo fails fast (the factory itself is not wired
    // until P1+).
    validate_substrate_selection(&args)?;
    let host_id = args
        .host_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(resolve_hostname);
    info!(
        host_id = %host_id,
        region = %args.region,
        public_addr = ?args.public_addr,
        cap_vcpus = args.host_vcpus,
        cap_mem_mib = args.host_mem_mib,
        cap_max_vms = args.host_max_vms,
        control_store = %args.substrate_control_store,
        lease = %args.substrate_lease,
        data_disk = %args.substrate_data_disk,
        blob_store = %args.substrate_blob_store,
        "cluster config"
    );

    let data_dir = args.data_dir.clone();
    let guest_kernel = resolve_guest_kernel(&args.fc_dir);
    tracing::info!(kernel = %guest_kernel.display(), "guest kernel selected");

    tokio::fs::create_dir_all(&data_dir).await?;

    let db_path = data_dir.join("jkbase.redb");
    let deploy_dir = data_dir.join("hosting");
    tokio::fs::create_dir_all(&deploy_dir).await?;

    let store = Store::open(&db_path)?;
    let logs_dir = data_dir.join("logs");
    tokio::fs::create_dir_all(&logs_dir).await?;
    let log_store = LogStore::new(logs_dir.clone());
    let log_shipper = LogShipper::new(log_store.clone(), logs_dir.join(".cursors.json"));

    // Tenant S3 object-store service on its OWN local listener (the proxy forwards
    // `storage.{domain}` to it via a reserved-host branch). Separate from the control
    // app: SigV4 auth (not Bearer), no global body cap (uploads stream to disk), and
    // it must never co-mingle with control-plane state.
    // Zero-bounce Phase 2: cancellation tokens for the graceful data-plane drain on an upgrade
    // restart (cancelled in shutdown_signal's upgrade branch; bounded by the DRAIN_GRACE watchdog).
    let proxy_shutdown = tokio_util::sync::CancellationToken::new();
    let storage_shutdown = tokio_util::sync::CancellationToken::new();
    let storage_join = {
        let storage_tok = storage_shutdown.clone();
        let svc = Arc::new(objectstore_service::ObjectStoreService::new(
            data_dir.clone(),
            store.clone(),
            format!("storage.{}", args.domain),
        ));
        // Multipart-staging sweeper: reap abandoned `.uploads/{id}` dirs older than
        // MULTIPART_MAX_AGE on boot, then on a timer (mirrors S3's abort-incomplete-
        // multipart lifecycle), so a crashed/forgotten upload can't pin disk forever.
        {
            let sweeper = svc.clone();
            tokio::spawn(async move {
                const MULTIPART_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
                const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
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
    };
    let routing_table = new_routing_table();
    let domain_map: DomainMap = new_domain_map();
    let activity_tracker: ActivityTracker = Arc::new(RwLock::new(HashMap::new()));

    // Content-address the base rootfs so a redeploy that ships a new agent can never poison a
    // pre-existing hibernation snapshot (incident: nlnwt, 2026-06-26). The staging artifact at
    // `base-rootfs.ext4` is built by the deploy script in prod (apko may not be on the service's
    // PATH) or the local-dev fallback; we hash it and pin it immutably at `base-rootfs/<hash>.ext4`.
    // ORDER IS LOAD-BEARING (see docs/rootfs-cas-snapshot-durability.md): CAS-ize → GC, ALL
    // synchronously here, before any loop that can boot/restore a VM is spawned (the HA
    // reconciler/disk-fence below) and before the proxy binds. VM re-adoption (§6) changes the
    // premise that this used to depend on: runtime FCs now SURVIVE a restart (they live in the
    // jkbase-runtime cgroup), so we do NOT reap them here — the old blunt pre-GC reaper is gone.
    // Instead the survivors' rootfs blobs are kept out of the sweep (the keep-set scan below), and
    // the full verify/adopt/reap of survivors happens after PlatformState is built (§6b). GC
    // unlinking a still-mapped blob is non-destructive anyway (the FC holds the fd; bytes survive
    // until it closes), and a true orphan is reaped in §6b.
    let staging_rootfs = data_dir.join("base-rootfs.ext4");
    rootfs::build_base_rootfs(&args.agent_bin, &staging_rootfs).await?;
    let cas_dir = data_dir.join("base-rootfs");
    let runtime_dir = data_dir.join("run");
    let (base_rootfs_path, base_rootfs_hash) = rootfs_cas::place(&staging_rootfs, &cas_dir)?;
    // FAIL CLOSED: only reap a blob we can PROVE no restorable snapshot references. If we can't
    // enumerate every snapshot's stamped hash, skip all deletes (a partial set would reap a live
    // blob). Over-deletion is self-healing anyway (missing blob ⇒ non-viable restore ⇒ cold boot).
    match store.list_snapshot_metas() {
        Ok(metas) => {
            let mut keep: HashSet<String> = HashSet::new();
            keep.insert(base_rootfs_hash.clone());
            for m in &metas {
                if let Some(h) = &m.base_rootfs_hash
                    && rootfs_cas::is_sha256_hex(h)
                {
                    keep.insert(h.clone());
                }
            }
            // §6a: keep every LIVE survivor's mapped rootfs blob — an upgrade mints a new
            // current_hash, and a survivor that hibernated before this start carries no snapshot
            // yet, so without this union its (old) blob would be reaped and its next hibernate
            // would stamp a missing blob → forced cold-boot. Cheap scan of run/*/handoff.json.
            for rec in handoff::scan(&runtime_dir) {
                if rootfs_cas::is_sha256_hex(&rec.base_rootfs_hash) {
                    keep.insert(rec.base_rootfs_hash.clone());
                }
            }
            match rootfs_cas::gc(&cas_dir, &keep) {
                Ok(removed) if !removed.is_empty() => {
                    info!(
                        count = removed.len(),
                        "GC: reaped unreferenced base-rootfs blobs"
                    )
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "base-rootfs GC failed; skipped (no blobs reaped)"),
            }
        }
        Err(e) => {
            warn!(error = %e, "could not enumerate snapshots; skipping base-rootfs GC (fail closed)")
        }
    }

    // Data-disk RWO substrate: R3 LocalLoop (loop-device exclusivity) + R2 FlockLease
    // (monotonic fence token). Migrate any legacy `{id}.ext4` disks to LocalLoop's
    // `{id}.img` naming so they become loop-managed + fenced. (`host_id` was resolved
    // from --host-id / the hostname at startup, above.)
    let data_disks_dir = data_dir.join("data-disks");
    migrate_legacy_data_disks(&data_disks_dir).await?;
    let data_disk: Arc<dyn DataDiskProvider> = Arc::new(LocalLoop::open(&data_disks_dir)?);
    let lease: Arc<dyn Lease> =
        Arc::new(FlockLease::open(data_dir.join("leases"), host_id.clone())?);

    // Host-asserted platform egress facts, computed once. The OWN object-store host is
    // `storage.{domain}`; the Zone-2 deny-set is the host's own public uplink IP(s).
    //
    // ALWAYS union the operator's --platform-ips with auto-discovery (never replace) — review
    // M-1. tools/setup-bridge.sh independently opens guest→PUB_IP:80,443 for EVERY global IP on
    // the uplink (its own discovery), so if an operator passed a NARROWER explicit list the
    // agent's deny-set could miss a secondary/failover IP the firewall still exposes → a
    // function could reach the control-plane proxy on that IP. Unioning guarantees the agent
    // deny-set ⊇ the discovered uplink set the firewall allows, closing the desync; --platform-ips
    // only ADDS (e.g. an IP behind NAT that discovery can't see), never subtracts.
    let mut platform_ips = discover_uplink_ips();
    for ip in &args.platform_ips {
        if !platform_ips.contains(ip) {
            platform_ips.push(ip.clone());
        }
    }
    if platform_ips.is_empty() {
        // The netfilter fence ALLOWS guest→public-IP:80,443 (servers reach the object-store /
        // own-sites through the proxy there), so the agent's platform-IP list is the ONLY
        // layer denying a function the control plane on those ports. Empty = that agent-side
        // Zone-2 deny is disabled — loudly flag it (the control API is still loopback-bound +
        // auth-gated, but this is a real gap to close before tenant exposure).
        warn!(
            "no platform uplink IPs (auto-discovery empty and --platform-ips unset); function egress Zone-2 deny by IP is DISABLED — set --platform-ips"
        );
    } else {
        info!(ips = ?platform_ips, "platform egress deny-set (Zone-2 platform IPs)");
    }
    let platform_egress = PlatformEgress {
        storage_host: Some(format!("storage.{}", args.domain)),
        platform_ips,
    };

    // HA P2: cluster leadership flag + the lease/host_id the election loop needs
    // (the originals are moved into PlatformState below).
    let is_leader = Arc::new(AtomicBool::new(false));
    let lease_for_election = lease.clone();
    let lease_for_fence = lease.clone();
    let host_id_for_election = host_id.clone();
    let host_id_for_heartbeat = host_id.clone();
    let is_leader_for_heartbeat = is_leader.clone();
    let is_leader_for_reconcile = is_leader.clone();

    let platform = Arc::new(Mutex::new(PlatformState {
        vms: HashMap::new(),
        vm_states: HashMap::new(),
        vm_rootfs_hashes: HashMap::new(),
        wake_failures: HashMap::new(),
        store: store.clone(),
        firecracker_bin: args
            .fc_dir
            .join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"),
        kernel_path: guest_kernel.clone(),
        base_rootfs_path,
        base_rootfs_hash,
        data_dir: data_dir.clone(),
        data_disk,
        lease,
        disk_tokens: HashMap::new(),
        host_id,
        platform_egress,
        is_leader: is_leader.clone(),
    }));

    // HA P2: elect a single cluster leader (the holder of the `cluster-leader` lease).
    // On a single node this process simply wins and stays leader. Advisory at P2 — P3's
    // placement gate reads `is_leader`; the data-disk self-fence is the real safety net.
    tokio::spawn(leader_election_loop(
        lease_for_election,
        host_id_for_election,
        is_leader,
    ));

    // HA P2: the data-disk write-boundary self-fence. Renews each held disk lease and
    // self-terminates this host's Firecracker for any project whose lease it loses,
    // before a survivor attaches. Inert on a single node (FlockLease renew always
    // succeeds while we hold the lock).
    tokio::spawn(disk_fence_loop(platform.clone(), lease_for_fence));

    // HA P3: register THIS host in the fleet (HOSTS) and heartbeat it so peers/the leader
    // know it is alive without a cross-host TCP probe; when leader, it detects stale peers.
    let self_host = HostRecord {
        host_id: host_id_for_heartbeat,
        region: args.region.clone(),
        public_addr: args.public_addr.clone(),
        last_heartbeat: 0,
        cpu_template_id: args.cpu_template_id.clone(),
        kernel_id: args.kernel_id.clone(),
        capacity: HostCapacity {
            vcpus: args.host_vcpus,
            mem_mib: args.host_mem_mib,
            max_vms: args.host_max_vms,
        },
    };
    tokio::spawn(host_heartbeat_loop(
        store.clone(),
        self_host,
        is_leader_for_heartbeat,
    ));

    // HA P3: the continuous cluster reconciler — the leader compares desired vs running
    // each tick and surfaces drift (placement applies it, next card). Inert single-node.
    tokio::spawn(reconcile_loop(platform.clone(), is_leader_for_reconcile));

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
        };
        Some(CertManager::new(tls_config, domain_map.clone(), args.acme_staging).await?)
    } else {
        None
    };

    let store_for_builds = store.clone();
    // Keep a `store` handle after this move: the managed-DB reach-plane auth callback
    // (built below) closes over a clone.
    let mut state = AppState::new(store.clone(), log_store.clone(), deploy_dir);
    state.routing_table = Some(routing_table.clone());
    state.domain_map = Some(domain_map.clone());
    state.platform_domain = args.domain.clone();
    state.admin_token = args.admin_token.clone();
    if let Some(ref cm) = cert_manager {
        let cm_req = cm.clone();
        state.cert_request = Some(Arc::new(move |host: String| {
            let cm = cm_req.clone();
            tokio::spawn(async move { cm.ensure_cert(&host).await });
        }));
        let cm_status = cm.clone();
        state.cert_status = Some(Arc::new(move |host: &str| cm_status.has_cert(host)));
    }

    let platform_for_cb = platform.clone();
    let routing_for_cb = routing_table.clone();
    let domain_for_cb = domain_map.clone();
    let shipper_for_cb = log_shipper.clone();
    state.deploy_callback = Some(Box::new(move |project_id: String, _version: u64| {
        let platform = platform_for_cb.clone();
        let routing = routing_for_cb.clone();
        let domains = domain_for_cb.clone();
        let shipper = shipper_for_cb.clone();
        Box::pin(
            async move { handle_deploy(&project_id, platform, routing, domains, shipper).await },
        )
    }));

    let platform_for_teardown = platform.clone();
    state.teardown_callback = Some(Box::new(move |project_id: String| {
        let platform = platform_for_teardown.clone();
        Box::pin(async move { handle_teardown(&project_id, &platform).await })
    }));

    // Build-pipeline wiring: control owns the `POST /build` funnel + build-job;
    // this server owns jkbase-orch + the jailer privilege, exposed via
    // `build_callback` (mirrors `deploy_callback`). The kernel is staged onto the
    // data-dir filesystem (same-fs hard-link into the jail), and the parent build
    // cgroup is provisioned best-effort (needs root).
    let fc_release = args.fc_dir.join("release-v1.15.1-x86_64");
    let build_kernel = data_dir.join("build-kernel").join("vmlinux.bin");
    // Non-fatal: a build-provisioning gap disables builds but must not knock over
    // the (separate) runtime hosting path — the kernel here feeds only builds.
    if let Err(e) = build_orchestrator::stage_kernel(&guest_kernel, &build_kernel) {
        tracing::warn!(error = %e, "build kernel staging failed; builds disabled until provisioned");
    }
    // Isolated build network (per-build TAP pool on the build bridge). Build VMs
    // reach only the egress proxy on the gateway; the firewall from
    // tools/setup-build-net.sh enforces it. `None` → offline builds.
    let build_uid = 100_000u32;
    // Bind the public-any (:3129) egress proxy listener BEFORE arming the firewall
    // scoping, so the per-VM :3129 grant is never opened toward a port nothing is
    // listening on (firewall posture stays consistent with the live service). OPT-IN:
    // only with --build-net + a distinct --build-proxy-any-port. Held to serve below.
    let public_any_proxy = if let Some(any_port) = args.build_proxy_any_port
        && args.build_net
        && any_port != args.build_proxy_port
    {
        let any_addr = format!("{}:{}", args.build_gateway, any_port);
        match tokio::net::TcpListener::bind(&any_addr).await {
            Ok(listener) => Some((any_port, any_addr, listener)),
            Err(e) => {
                tracing::error!(error = %e, addr = %any_addr,
                    "failed to bind public-any egress proxy — dockerfile builds get no broad egress");
                None
            }
        }
    } else {
        None
    };
    // Arm the per-VM scoping only for the port we actually bound.
    let effective_any_port = public_any_proxy.as_ref().map(|(p, _, _)| *p);
    let build_net = if args.build_net {
        Some(Arc::new(build_orchestrator::BuildNet::new(
            args.build_bridge.clone(),
            args.build_gateway.clone(),
            args.build_proxy_port,
            effective_any_port, // armed only if the :3129 listener actually bound
            build_uid,
            64, // concurrent build-network slots
        )))
    } else {
        None
    };
    // Fail closed: with --build-net we MUST NOT run attacker-controlled build VMs
    // unless their isolation firewall is actually provisioned + present. When the
    // public-any (:3129) proxy is active, also install the L2 source-guard that pins
    // each build VM to its own source IP/MAC — without it the per-lease :3129 grant
    // is spoofable (a hostile non-dockerfile VM could forge a dockerfile VM's IP).
    if let Some(net) = &build_net {
        net.verify_firewall().await?;
        net.ensure_source_guard().await?;
    }
    // Pre-create + hook the runtime VM L2 source-guard chain at startup (defense in depth:
    // it exists before the first project wakes; per-TAP rules are added lazily in setup_tap).
    // Fail-closed — ebtables is a provisioned dependency (provision.sh / deploy-server.sh).
    {
        let _g = runtime_ebtables_lock().lock().await;
        ensure_runtime_source_guard_chain().await?;
    }
    let build_deps = Arc::new(build_orchestrator::BuildDeps {
        jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
        kernel_path: build_kernel,
        data_dir: data_dir.clone(),
        deploy_dir: data_dir.join("hosting"),
        toolchain_dir: data_dir.join("toolchains"),
        store: store_for_builds,
        // Short base: it prefixes the jailer chroot, and the Firecracker API
        // socket path under it must stay within SUN_LEN (~108 bytes).
        chroot_base: data_dir.join("bj"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        parent_cgroup: "jkbase-build".to_string(),
        uid: build_uid,
        gid: build_uid,
        // Sized for real apps (Vite/monorepo builds + sizeable node_modules), not the
        // toy fixtures: a Vite build can use multiple GiB of RAM, the full (dev-incl.)
        // install + source + build output needs GiB of scratch, and the app erofs blob
        // needs room in the output drive even after the production prune. The cgroup
        // memory cap (> guest RAM) keeps a hostile build from host-OOM. Tunable per box.
        timeout: Duration::from_secs(900),
        vcpu_count: 4,
        mem_size_mib: 4096,
        cgroup_pids_max: 1024,
        cgroup_mem_max_bytes: 4608 * 1024 * 1024,
        cgroup_cpu_max: "400000 100000".to_string(),
        scratch_size_bytes: 4096 * 1024 * 1024,
        output_size_bytes: 1024 * 1024 * 1024,
        console_log_max_bytes: 1024 * 1024,
        max_concurrent: 4,
        net: build_net,
        fetch_deadline: Duration::from_secs(600),
        cache_locks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        // Per-(project,language) warm cache image (vde): sparse 4 GiB logical, grows
        // on demand, billed by actual blocks against the project storage quota.
        cache_size_bytes: 4096 * 1024 * 1024,
        // The agent binary doubles as the function precompiler (host-side `--precompile`),
        // so a function's component compiles once at deploy, not on every cold VM boot.
        agent_bin: Some(args.agent_bin.clone()),
    });
    // The jail chroot base + toolchain dir must exist on the data-dir fs.
    let _ = std::fs::create_dir_all(&build_deps.chroot_base);
    let _ = std::fs::create_dir_all(&build_deps.toolchain_dir);
    build_orchestrator::provision_cgroup(&build_deps.cgroup_mount, &build_deps.parent_cgroup);
    // Fail builds left mid-flight by a previous crash + reap their orphan dirs.
    build_orchestrator::reconcile_on_boot(
        &build_deps.store,
        &build_deps.data_dir,
        &build_deps.deploy_dir,
    );
    state.build_callback = Some(build_orchestrator::build_callback(build_deps));

    // Managed-DB reach-plane live-relay registry — shared with the proxy edge, the idle
    // loop, and the drain. [R5]: the control API force-closes live relays through it when a
    // DB key is revoked or a project is deleted/transferred. Built here (before `state` is
    // sealed into the router) so the revoke callback can reach it.
    let db_relay_registry = jkbase_proxy::db_relay::DbRelayRegistry::new();
    {
        let reg = db_relay_registry.clone();
        state.db_revoke_callback = Some(Arc::new(move |scope| match scope {
            jkbase_control::api::DbRevokeScope::Key(k) => {
                let n = reg.cancel_key(&k);
                if n > 0 {
                    info!(key = %k, count = n, "db key revoked: closed live relays");
                }
            }
            jkbase_control::api::DbRevokeScope::Project(p) => {
                let n = reg.cancel_project(&p);
                if n > 0 {
                    info!(project = %p, count = n, "project teardown: closed live db relays");
                }
            }
        }));
    }

    // Managed-DB backups ([RB*]): the platform-owned blob store + the executor context shared by
    // the on-demand callbacks and the nightly loop. The control API records intent + owner-scopes;
    // execution (VM wake, agent relay, blob store) is server-side here.
    let db_backup_ctx = DbBackupCtx {
        platform: platform.clone(),
        routing: routing_table.clone(),
        domains: domain_map.clone(),
        shipper: log_shipper.clone(),
        store: state.store.clone(),
        backups: Arc::new(db_backup_store::BackupStore::new(&data_dir)),
        backup_sem: Arc::new(tokio::sync::Semaphore::new(DB_BACKUP_MAX_CONCURRENT)),
        restoring: Arc::new(std::sync::Mutex::new(HashSet::new())),
    };
    {
        let ctx = db_backup_ctx.clone();
        state.db_backup_callback = Some(Arc::new(move |project_id, backup_id| {
            tokio::spawn(run_db_backup(ctx.clone(), project_id, backup_id));
        }));
    }
    {
        let ctx = db_backup_ctx.clone();
        state.db_restore_callback = Some(Arc::new(move |project_id, backup_id| {
            tokio::spawn(run_db_restore(ctx.clone(), project_id, backup_id));
        }));
    }
    {
        // Console DB tools (query / schema / status) — a SYNCHRONOUS proxy (the console blocks
        // on the result), unlike the fire-and-forget backup/restore callbacks. Captures the wake
        // inputs + store directly (no need for the backup ctx's store/sem/restoring).
        let platform = platform.clone();
        let routing = routing_table.clone();
        let domains = domain_map.clone();
        let shipper = log_shipper.clone();
        let store = state.store.clone();
        let cb: jkbase_control::api::DbQueryCallback = Arc::new(
            move |project_id: String, op: jkbase_control::api::DbQueryOp| {
                let platform = platform.clone();
                let routing = routing.clone();
                let domains = domains.clone();
                let shipper = shipper.clone();
                let store = store.clone();
                Box::pin(async move {
                    do_db_query(platform, routing, domains, shipper, store, project_id, op).await
                })
            },
        );
        state.db_query_callback = Some(cb);
    }

    let state = Arc::new(state);
    let router = api::router(state, args.domain.clone());

    // Set up wake callback for the proxy
    let platform_for_wake = platform.clone();
    let routing_for_wake = routing_table.clone();
    let domain_for_wake = domain_map.clone();
    let shipper_for_wake = log_shipper.clone();
    let wake_callback: jkbase_proxy::WakeCallback = Arc::new(move |project_id: String| {
        let platform = platform_for_wake.clone();
        let routing = routing_for_wake.clone();
        let domains = domain_for_wake.clone();
        let shipper = shipper_for_wake.clone();
        Box::pin(
            async move { wake_db_reach(&project_id, platform, routing, domains, shipper).await },
        )
    });

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

    let proxy_config = ProxyConfig {
        http_port: args.proxy_port,
        https_port: if args.tls {
            Some(args.https_port)
        } else {
            None
        },
        platform_domain: args.domain,
        cert_manager: cert_manager.clone(),
        api_addr: Some(api_addr),
        storage_addr: Some(format!("127.0.0.1:{}", args.storage_port)),
        domains: Some(domain_map.clone()),
        activity_tracker: Some(activity_tracker.clone()),
        wake_callback: Some(wake_callback),
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
    };
    let proxy_port = proxy_config.http_port;
    let proxy_routes = routing_table.clone();

    // VM re-adoption §6b: BEFORE the proxy serves and BEFORE any wake-capable loop, verify every
    // runtime Firecracker that survived the prior process, re-adopt the live ones (re-fence the
    // disk at a fresh epoch WITHOUT detaching, rebuild vms/vm_states/routing) and reap the rest.
    // Replaces the old blunt `pkill -9 firecracker` that would have SIGKILLed every survivor. Must
    // precede the reconcilers below so they see the adopted Running state (they are survivor-aware).
    adopt_or_reap_runtime_vms(&platform, &routing_table, &domain_map).await;
    // Adoption is complete — clear the upgrade flag so a later operator `stop`/`restart` without a
    // fresh flag drains/hibernates normally (and a crashed deploy's stale flag never lingers).
    let _ = std::fs::remove_file(upgrade_flag_path(&data_dir));

    // Reconcile state and build the domain map BEFORE the proxy serves traffic,
    // or apex/www/console would 404 in the gap.
    cleanup_orphans(&platform).await;
    reconcile_orphans_on_boot(&platform).await;
    reconcile_baselayers_on_boot(&platform).await;
    backfill_domains(&platform, &domain_map).await;

    let proxy_tok = proxy_shutdown.clone();
    let proxy_join = tokio::spawn(async move {
        if let Err(e) = jkbase_proxy::serve(proxy_config, proxy_routes, proxy_tok).await {
            tracing::error!(error = %e, "proxy error");
        }
    });

    // P2 §7.6 — the app→DB in-guest leg's host gateway. Lets a dedicated project's app VM reach
    // its sibling DB VM on the same `127.0.0.1:4200/4201` as co-located, host-mediated over the
    // bridge gateway IP and authenticated by the guest's unforgeable source IP. Best-effort bind
    // (see `db_gateway::serve`); its own wake closure mirrors the proxy's (both call `wake_db_reach`,
    // which resolves the dedicated `.db` target).
    {
        let store = store.clone();
        let platform_for_gw = platform.clone();
        let routing_for_gw = routing_table.clone();
        let domain_for_gw = domain_map.clone();
        let shipper_for_gw = log_shipper.clone();
        let gw_wake: jkbase_proxy::WakeCallback = Arc::new(move |project_id: String| {
            let platform = platform_for_gw.clone();
            let routing = routing_for_gw.clone();
            let domains = domain_for_gw.clone();
            let shipper = shipper_for_gw.clone();
            Box::pin(async move { wake_db_reach(&project_id, platform, routing, domains, shipper).await })
        });
        let registry = db_relay_registry.clone();
        tokio::spawn(async move { db_gateway::serve(store, gw_wake, registry).await });
    }

    // Spawn log shipper loop (pulls guest logs into the persistent store)
    tokio::spawn(log_shipper_loop(platform.clone(), log_shipper.clone()));

    // Nightly automatic managed-DB backups ([RB12]).
    tokio::spawn(db_backup_nightly_loop(db_backup_ctx.clone()));

    // Spawn idle detection loop
    if args.idle_timeout_secs > 0 {
        let idle_timeout = Duration::from_secs(args.idle_timeout_secs);
        info!(
            timeout_secs = args.idle_timeout_secs,
            "idle detection enabled"
        );
        tokio::spawn(idle_detection_loop(
            platform.clone(),
            routing_table.clone(),
            activity_tracker.clone(),
            idle_timeout,
            log_shipper.clone(),
            Some(db_relay_registry.clone()),
        ));
    }

    // Spawn the scheduled-functions loop (host-driven cron). Reads the durable
    // SCHEDULES registry each tick, wakes + invokes due functions.
    tokio::spawn(scheduler_loop(
        platform.clone(),
        routing_table.clone(),
        domain_map.clone(),
        log_shipper.clone(),
        activity_tracker.clone(),
    ));

    // Spawn the metering + quota-enforcement loop. Samples per-project CPU,
    // bandwidth, and storage into hourly rollup buckets and hibernates +
    // blocks projects that exceed their monthly bandwidth cap.
    tokio::spawn(metering_loop(
        platform.clone(),
        routing_table.clone(),
        log_shipper.clone(),
        Some(db_relay_registry.clone()),
    ));

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
                        &data_dir,
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

    // P0 (function-outbound-io, Phase 0): bind the control API to LOOPBACK, not 0.0.0.0.
    // The proxy reaches it at 127.0.0.1 (api_addr, above) and external clients reach it
    // via the `api.` reserved host THROUGH the proxy — nothing legitimate needs it on a
    // routable address. Binding 0.0.0.0 also put the socket on the runtime bridge IP
    // (172.16.0.1:9090), so a hostile guest's only barrier to the control plane was ufw
    // ordering; never listening off loopback closes that structurally (setup-bridge.sh's
    // JKRUNFW INPUT chain is the netfilter backstop). Threat model: all tenants untrusted.
    let addr = SocketAddr::from(([127, 0, 0, 1], args.api_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        api = %addr,
        proxy = %format!("0.0.0.0:{proxy_port}"),
        "jkbase-server listening"
    );

    let platform_for_shutdown = platform.clone();
    let routing_for_shutdown = routing_table.clone();
    let shipper_for_shutdown = log_shipper.clone();
    // Set by shutdown_signal's upgrade branch so the post-serve code knows to exit(0) (never
    // unwind) rather than fall through to a normal return.
    let upgrade_kind = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serve_res = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(
            platform_for_shutdown,
            routing_for_shutdown,
            shipper_for_shutdown,
            proxy_shutdown.clone(),
            storage_shutdown.clone(),
            upgrade_kind.clone(),
        ))
        .await;

    // UPGRADE path: NEVER let `main` unwind — a `?` here would drop PlatformState → vms →
    // VmInstance::Drop (kill_on_drop) SIGKILLing every Owned survivor (adversarial HIGH-2). The
    // api drained via axum's graceful shutdown (shutdown_signal RETURNED on the upgrade branch);
    // now finish the proxy + storage in-flight work under DRAIN_GRACE (the shutdown_signal watchdog
    // is the hard backstop if a join hangs), then exit(0) skipping all destructors.
    if upgrade_kind.load(std::sync::atomic::Ordering::SeqCst) {
        let _ = tokio::time::timeout(DRAIN_GRACE, async {
            let _ = proxy_join.await; // serve() returns once its in-flight connections drain
            let _ = storage_join.await; // axum storage graceful drain returns
        })
        .await;
        // exit(0): survivors live in the jkbase-runtime cgroup, adopted by the successor; the open
        // socket DUPs close harmlessly (systemd keeps the originals listening for the successor).
        std::process::exit(0);
    }

    serve_res?; // normal shutdown: shutdown_signal already hibernated the VMs
    Ok(())
}

/// Path of the upgrade-in-progress flag `deploy-server.sh` writes immediately before
/// `systemctl restart`. Its first line is the epoch second it was written (a second optional
/// line carries the deploy pid, for diagnostics only).
fn upgrade_flag_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".upgrading")
}

/// True iff a FRESH upgrade flag is present (written < [`UPGRADE_FLAG_FRESHNESS_SECS`] ago).
fn upgrade_in_progress(data_dir: &Path) -> bool {
    let Ok(body) = std::fs::read_to_string(upgrade_flag_path(data_dir)) else {
        return false;
    };
    let Some(ts) = body
        .lines()
        .next()
        .and_then(|l| l.trim().parse::<u64>().ok())
    else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(ts) < UPGRADE_FLAG_FRESHNESS_SECS
}

async fn shutdown_signal(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    proxy_shutdown: tokio_util::sync::CancellationToken,
    storage_shutdown: tokio_util::sync::CancellationToken,
    upgrade_kind: Arc<std::sync::atomic::AtomicBool>,
) {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm.recv() => {},
    }

    // VM re-adoption §8: an UPGRADE restart (a fresh .upgrading flag) leaves tenant VMs RUNNING for
    // the next process to re-adopt — the zero-bounce goal. Phase 2 ALSO keeps the data plane up:
    // the systemd-owned :80/:443 sockets stay open (new connections queue for the successor) while
    // this process GRACEFULLY DRAINS in-flight HTTP. We must still exit WITHOUT running VmInstance
    // destructors (Drop/kill_on_drop would SIGKILL every survivor); the survivors live in the
    // jkbase-runtime cgroup, untouched by KillMode=mixed. A real shutdown (no fresh flag) falls
    // through and drains/hibernates as before.
    let data_dir = { platform.lock().await.data_dir.clone() };
    if upgrade_in_progress(&data_dir) {
        let n = platform.lock().await.vms.len();
        info!(
            running_vms = n,
            "upgrade restart (.upgrading present) — draining HTTP (proxy+storage+api), leaving \
             tenant VMs running for re-adoption"
        );
        // Stop accepting + begin draining the proxy + storage. The api drains via axum's own
        // graceful shutdown once we RETURN (NOT process::exit inline — that would skip the api
        // drain). Draining touches only connection-level state, never a VmInstance (the proxy's
        // SharedState is disjoint from PlatformState.vms), so no survivor is dropped.
        proxy_shutdown.cancel();
        storage_shutdown.cancel();
        upgrade_kind.store(true, std::sync::atomic::Ordering::SeqCst);
        // Watchdog (adversarial BLOCKER-1): GUARANTEE the process exits within DRAIN_GRACE of the
        // SIGTERM no matter what any drain is doing — axum's graceful shutdown has NO internal
        // timeout, so a hostile tenant holding an authenticated `api.` request open could otherwise
        // stall to TimeoutStopSec (a LONGER gap than Phase 1). exit(0) skips destructors, sparing
        // the jkbase-runtime FCs.
        tokio::spawn(async {
            tokio::time::sleep(DRAIN_GRACE).await;
            tracing::warn!("upgrade drain grace elapsed — exiting (cutting any remaining streams)");
            std::process::exit(0);
        });
        return;
    }

    info!("shutdown signal received, hibernating running VMs...");

    let running_projects: Vec<String> = {
        let plat = platform.lock().await;
        plat.vm_states
            .iter()
            .filter(|(_, state)| **state == VmLifecycle::Running)
            .map(|(id, _)| id.clone())
            .collect()
    };

    for project_id in &running_projects {
        info!(project = %project_id, "hibernating for shutdown");
        if let Err(e) = hibernate_project(
            project_id,
            platform.clone(),
            routing.clone(),
            shipper.clone(),
            None,
        )
        .await
        {
            // hibernate_project self-cleans its own wedge/timeout paths; this is a
            // last-resort catch for an unexpected Err, routed through the same helper.
            tracing::error!(project = %project_id, error = %e, "hibernate errored, force stopping");
            force_stop_and_cleanup(project_id, &platform).await;
        }
    }

    info!("all VMs hibernated, shutdown complete");
}

async fn cleanup_orphans(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let me_host = plat.host_id.clone();
    let allocs = match plat.store.list_vm_allocations() {
        Ok(a) => a,
        Err(_) => return,
    };

    for alloc in &allocs {
        // VM re-adoption §7: never reap a survivor re-adopted Running this start — adoption
        // already proved its liveness via the agent HTTP probe, and a momentarily-slow guest
        // could otherwise false-negative this 2s TCP probe and sever a live VM's allocation.
        if plat.vm_states.get(&alloc.project_id) == Some(&VmLifecycle::Running) {
            continue;
        }
        // Only probe our OWN VMs. A peer host's VM IP lives on its own network island,
        // unreachable from here, so a TCP probe would false-negative and wrongly reap a
        // live peer's allocation; peer/host liveness is via heartbeats (HOSTS), not TCP.
        // (Empty host_id = single-node / pre-placement = treat as local.)
        if !alloc.host_id.is_empty() && alloc.host_id != me_host {
            continue;
        }
        let reachable = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(format!("{}:80", alloc.ip)),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);

        if !reachable {
            info!(
                project = %alloc.project_id,
                ip = %alloc.ip,
                "cleaning up orphaned allocation"
            );
            let _ = teardown_tap(&alloc.tap_device).await;
            let _ = plat.store.remove_vm_allocation(&alloc.project_id);
        }
    }
}

/// Fully reap a deleted project (the `teardown_callback` control invokes from
/// `DELETE /projects/{id}`): stop the VM, free its IP/TAP allocation, drop its
/// snapshot, and remove every on-disk artifact. Best-effort + idempotent — any
/// step that fails is reconciled by `reconcile_orphans_on_boot` on the next boot.
async fn handle_teardown(project_id: &str, platform: &Arc<Mutex<PlatformState>>) -> Result<()> {
    // Reap under the platform lock, but only once no wake/hibernate is mid-flight for
    // this project: those drop the lock during the slow VM op, and destroying the disk
    // under a live restoring VM would free a loop device another project could reuse
    // (silent corruption). Wait it out (bounded ~30s), then do stop + release + destroy
    // in ONE locked section so a new wake can't interleave (it needs the lock to set
    // Waking).
    let (alloc, data_dir) = {
        let mut attempt = 0;
        loop {
            let mut plat = platform.lock().await;
            if attempt < 150
                && matches!(
                    plat.vm_states.get(project_id),
                    Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
                )
            {
                drop(plat);
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            if let Some(mut vm) = plat.vms.remove(project_id) {
                let _ = vm.stop().await;
            }
            // Force-kill ANY Firecracker for this project — including one a wake that
            // outlasted our wait-loop hasn't yet recorded in `vms` — BEFORE we destroy
            // the disk, so `destroy()` can never detach a loop device a live VM still
            // maps (which another project could then be handed = corruption). The wake,
            // finding its FC dead, fails and its guard releases.
            reap_firecracker(project_id).await;
            // The project is being deleted: drop its re-adoption record so a surviving FC
            // can't be re-adopted on a later start (remove_project_artifacts also nukes
            // run/{id} below; this is the explicit, lock-held removal beside disk_tokens).
            handoff::remove(&plat.data_dir.join("run"), project_id);
            // Release the data-disk lease + destroy the disk (detach loop device,
            // remove the image + holder record) as part of reaping the project.
            if let Some(token) = plat.disk_tokens.remove(project_id) {
                let ls = plat.lease.clone();
                let _ = ls.release(&token).await;
            }
            let dd = plat.data_disk.clone();
            let _ = dd.destroy(project_id).await;
            plat.vm_states.remove(project_id);
            plat.vm_rootfs_hashes.remove(project_id);
            let alloc = plat.store.get_vm_allocation(project_id).ok().flatten();
            let _ = plat.store.remove_snapshot_meta(project_id);
            let _ = plat.store.remove_vm_allocation(project_id);
            break (alloc, plat.data_dir.clone());
        }
    };

    // Kill any leaked Firecracker that outlived the handle, then drop its TAP.
    let _ = tokio::process::Command::new("pkill")
        // Anchor to the EXACT api-sock path segment (/<id>/firecracker.sock), not an unanchored
        // `firecracker.*<id>` substring of the whole cmdline: project ids are user-chosen slugs
        // ([a-z0-9-]), and every FC cmdline carries `--api-sock .../run/<id>/firecracker.sock`, so
        // a short id like `a` matched as a substring would SIGKILL every tenant's FC host-wide
        // (cross-tenant kill). `<id>` is a single path segment bounded by `/`, so `/a/` never
        // matches `/ab/`. A rendered DB VM id (`{id}.db`) carries a `.` — itself an ERE
        // metacharacter — so `fc_sock_pkill_pattern` escapes every `.` in the id (else `foo.db`
        // would match `/fooadb/…` and cross-tenant-kill project `fooadb`).
        .args(["-f", &vm_identity::fc_sock_pkill_pattern(project_id)])
        .status()
        .await;
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
    remove_project_artifacts(&data_dir, project_id).await;
    // Reap the sibling dedicated DB VM (`{id}.db`), if any — its VM handle, Firecracker, data disk,
    // lease, snapshot, IP/TAP allocation, and on-disk artifacts. Unconditional + idempotent: a
    // co-located or DB-less project has no `.db` VM, so every step no-ops; this also cleans up a
    // project that toggled dedicated→colocated (or a half-built dedicated deploy) leaving a stale
    // DB VM behind. Without it, deleting a dedicated project leaks its whole DB VM.
    teardown_db_vm_sibling(project_id, platform).await;
    info!(project = %project_id, "project torn down");
    Ok(())
}

/// Best-effort teardown of a project's **sibling DB VM** (`{project_id}.db`). Mirrors
/// [`handle_teardown`]'s reap keyed by the rendered DB id: stop the VM, hard-kill any surviving
/// Firecracker (BEFORE destroying its disk, so a live FC can't corrupt a reused loop device),
/// destroy the DB data disk + release its lease, drop lifecycle/snapshot state, free the IP/TAP,
/// and remove the on-disk artifacts. Idempotent and safe for a project with no DB VM (every step
/// no-ops). The rendered id's `.` is dot-escaped by [`vm_identity::fc_sock_pkill_pattern`], so the
/// pkill can never match a sibling tenant's Firecracker.
async fn teardown_db_vm_sibling(project_id: &str, platform: &Arc<Mutex<PlatformState>>) {
    let db_id = vm_identity::vm_id(project_id, vm_identity::VmRole::Db);
    let (alloc, data_dir) = {
        let mut plat = platform.lock().await;
        if let Some(mut vm) = plat.vms.remove(&db_id) {
            let _ = vm.stop().await;
        }
        // Kill any DB Firecracker not tracked in `vms` BEFORE destroying its disk.
        reap_firecracker(&db_id).await;
        handoff::remove(&plat.data_dir.join("run"), &db_id);
        if let Some(token) = plat.disk_tokens.remove(&db_id) {
            let ls = plat.lease.clone();
            let _ = ls.release(&token).await;
        }
        let dd = plat.data_disk.clone();
        let _ = dd.destroy(&db_id).await;
        plat.vm_states.remove(&db_id);
        plat.vm_rootfs_hashes.remove(&db_id);
        plat.wake_failures.remove(&db_id);
        let alloc = plat.store.get_vm_allocation(&db_id).ok().flatten();
        let _ = plat.store.remove_snapshot_meta(&db_id);
        let _ = plat.store.remove_vm_allocation(&db_id);
        (alloc, plat.data_dir.clone())
    };
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
    // `remove_project_artifacts` for a `.db` id clears content-images/`{id}.db.ext4`,
    // data-disks/`{id}.db.{img,holder}`, snapshots/`{id}.db`, run/`{id}.db`; the base-only trees
    // (hosting/builds/git/buildcache/`{id}.db`) simply don't exist → no-ops.
    remove_project_artifacts(&data_dir, &db_id).await;
}

/// Remove every per-project on-disk artifact (content image, data disk, snapshot,
/// run dir, hosting tree, build workspace). Best-effort; absent paths are ignored.
async fn remove_project_artifacts(data_dir: &Path, project_id: &str) {
    let _ = tokio::fs::remove_file(
        data_dir
            .join("content-images")
            .join(format!("{project_id}.ext4")),
    )
    .await;
    // Data disk: legacy `.ext4` plus the loop-managed `.img` + its holder record.
    let disks = data_dir.join("data-disks");
    for f in [
        format!("{project_id}.ext4"),
        format!("{project_id}.img"),
        format!("{project_id}.holder"),
    ] {
        let _ = tokio::fs::remove_file(disks.join(f)).await;
    }
    for dir in ["snapshots", "run", "hosting", "builds", "buildcache"] {
        // `buildcache/{id}/` holds the per-(project,language) warm-cache images.
        // Purge on delete so a recreated same-name project can't inherit the prior
        // tenant's cache (same isolation rule as secrets/data — the project id IS the
        // slug, so a reused name would otherwise read another tenant's build cache).
        let _ = tokio::fs::remove_dir_all(data_dir.join(dir).join(project_id)).await;
    }
    // Per-project git bare repo (build·D push-to-deploy): `git/{id}.git`.
    let _ = tokio::fs::remove_dir_all(data_dir.join("git").join(format!("{project_id}.git"))).await;
}

/// Boot-time sweep for projects deleted but left with artifacts behind (a teardown
/// that failed midway, or a project removed before teardown existed). For every
/// per-project image/dir whose name is NOT a currently registered project, drop the
/// stale artifact. Registered projects are never touched, so live data disks are
/// safe. `builds/` is reaped wholesale by the build reconcile, so it is omitted.
async fn reconcile_orphans_on_boot(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let mut registered: HashSet<String> = match plat.store.list_projects() {
        Ok(ps) => ps.into_iter().map(|p| p.id).collect(),
        Err(_) => return,
    };
    // VM re-adoption §7: treat every re-adopted survivor as protected too (belt-and-suspenders
    // — a survivor is always also `registered`, but this guards the data-disks loop-detach below
    // against ever `losetup -d`'ing a live survivor's loop even if a store read drifted).
    for (id, state) in plat.vm_states.iter() {
        if *state == VmLifecycle::Running {
            registered.insert(id.clone());
        }
    }
    let data_dir = plat.data_dir.clone();
    drop(plat);

    // A dedicated DB VM's artifacts are named by its RENDERED id (`{base}.db.img`,
    // `snapshots/{base}.db`, `run/{base}.db`, `content-images/{base}.db.ext4`) but there is no
    // `{base}.db` project row — the DB VM belongs to its BASE project. Protect a `.db` artifact iff
    // its base is registered (or the DB VM is itself Running, inserted above). WITHOUT this, a clean
    // restart with the DB VM not-yet-woken reaps `{base}.db.img` as an "orphan" — a loop-detach +
    // delete that DESTROYS the tenant's database. (For an app-id artifact `base_project_id` is a
    // no-op, so the check is unchanged for every existing project.)
    let is_registered = |id: &str| {
        registered.contains(id) || registered.contains(vm_identity::base_project_id(id))
    };

    // Collect each directory's entries up front: removing files while iterating a
    // live read_dir handle skips entries (the kernel readdir cursor shifts under
    // the deletions), so a single pass would reap only a subset of the orphans.
    // content-images: `{id}.ext4`.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("content-images")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".ext4") else {
                continue;
            };
            if !is_registered(id) {
                let _ = std::fs::remove_file(entry.path());
                info!(project = %id, artifact = "content-images", "reaped orphaned artifact");
            }
        }
    }
    // data-disks: loop-managed `{id}.img` + its `{id}.holder` record (+ legacy
    // `{id}.ext4`). Detach any loop device still bound to an orphan image before
    // removing it, so deleted projects can't leak loop devices that another project
    // would later reuse.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("data-disks")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Orphaned atomic-write temp files (`{id}.holder.tmp.{pid}`) left by a crash
            // mid `write_holder`: always stale (a completed write renames into place), so
            // reap unconditionally — they carry no live identity to match `registered`.
            // Match the EXACT `.holder.tmp.<digits>` suffix, not a substring: a real disk
            // ends in `.img`/`.holder`/`.ext4`, and a project id may itself legally contain
            // `.holder.tmp.`, so a substring check could delete a live disk.
            if name
                .rsplit_once(".holder.tmp.")
                .is_some_and(|(_, pid)| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
            {
                let _ = std::fs::remove_file(entry.path());
                continue;
            }
            let Some(id) = name
                .strip_suffix(".img")
                .or_else(|| name.strip_suffix(".holder"))
                .or_else(|| name.strip_suffix(".ext4"))
            else {
                continue;
            };
            if is_registered(id) {
                continue;
            }
            let path = entry.path();
            if name.ends_with(".img")
                && let Ok(out) = tokio::process::Command::new("losetup")
                    .args(["-j", &path.to_string_lossy()])
                    .output()
                    .await
            {
                for dev in String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|l| l.split(':').next())
                    .filter(|d| !d.is_empty())
                {
                    let _ = tokio::process::Command::new("losetup")
                        .args(["-d", dev])
                        .status()
                        .await;
                }
            }
            let _ = std::fs::remove_file(&path);
            info!(project = %id, artifact = "data-disks", "reaped orphaned artifact");
        }
    }
    // `objectstore/{id}` + `db-backups/{id}`: a deleted project's bucket tree / managed-DB
    // backup blobs ([RB11]). Delete purges them, but a crash-interrupted teardown can leave them
    // — reap so a recreated slug starts clean and a deleted tenant's DB data doesn't linger.
    for sub in ["hosting", "run", "snapshots", "objectstore", "db-backups"] {
        let Ok(entries) = std::fs::read_dir(data_dir.join(sub)) else {
            continue;
        };
        let entries: Vec<_> = entries.flatten().collect();
        for entry in entries {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            if !is_registered(&id) {
                let _ = std::fs::remove_dir_all(entry.path());
                info!(project = %id, artifact = %sub, "reaped orphaned dir");
            }
        }
    }
    // git bare repos (build·D push-to-deploy): `git/{id}.git` dirs. Reaps the
    // bare repo (and its credential's pushed objects) when a delete-time cleanup
    // was missed, so a recreated slug can't inherit them.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("git")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".git") else {
                continue;
            };
            if !is_registered(id) {
                let _ = std::fs::remove_dir_all(entry.path());
                info!(project = %id, artifact = "git", "reaped orphaned bare repo");
            }
        }
    }
}

/// Boot-time GC of the shared layer store (`baselayers/`). Base + per-language
/// runtime erofs blobs are content-addressed, dm-verity'd, and shared across ALL
/// projects; they accumulate as the platform's layers are rebuilt (each new base/
/// runtime version adds a `sha256-<hex>.erofs` and `platform.json` is repointed).
/// A blob is LIVE iff the CURRENT `platform.json` names it, OR some registered
/// project's current metadata image still attaches it (its baked `_layerpaths.json`
/// pins the exact base/runtime version that project deployed with — possibly older
/// than `platform.json` if it hasn't redeployed since). Everything else is an
/// unreferenced old version: reap it.
///
/// Runs at boot ONLY — before the proxy/control serve, so no deploy/wake can race
/// (same ordering guarantee as [`reconcile_orphans_on_boot`]); the live set needs no
/// lock. Per-tenant app layers live under each version dir and are already reclaimed
/// with the dir on prune, so only `baselayers/` leaks and only it is swept here.
///
/// FAILS SAFE: if `platform.json` is present but unparseable, or any project's layer
/// map can't be read, the sweep aborts (leak rather than risk reaping a live blob).
async fn reconcile_baselayers_on_boot(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let registered: Vec<String> = match plat.store.list_projects() {
        Ok(ps) => ps.into_iter().map(|p| p.id).collect(),
        Err(_) => return,
    };
    let data_dir = plat.data_dir.clone();
    drop(plat);

    let baselayers = data_dir.join("baselayers");
    if !baselayers.is_dir() {
        return;
    }

    // The LIVE set of baselayers blob filenames a deletion must never touch.
    let mut live: HashSet<String> = HashSet::new();

    // (1) Current platform.json base + every runtime are ALWAYS live (the next deploy
    //     and any project mid-deploy use them). baselayers/ existing implies platform.json
    //     should too — the platform-layer build installs the blobs THEN writes the
    //     manifest — so treat absent/unreadable/unparseable IDENTICALLY: abort the sweep
    //     rather than risk reaping the current (or a freshly-baked, not-yet-deployed-onto)
    //     base/runtime when the manifest momentarily isn't there.
    let platform_json = baselayers.join("platform.json");
    let parsed = std::fs::read(&platform_json)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let Some(v) = parsed else {
        warn!("baselayers GC: platform.json missing/unreadable/unparseable; skipping sweep");
        return;
    };
    if let Some(f) = v
        .get("base")
        .and_then(|b| b.get("file"))
        .and_then(|f| f.as_str())
    {
        live.insert(f.to_string());
    }
    if let Some(rts) = v.get("runtimes").and_then(|r| r.as_object()) {
        for desc in rts.values() {
            if let Some(f) = desc.get("file").and_then(|f| f.as_str()) {
                live.insert(f.to_string());
            }
        }
    }

    // (2) Each registered project's CURRENT metadata image pins the exact base/runtime
    //     blobs it attaches. If a project's layer map can't be read, abort the whole
    //     sweep (treating it as "references nothing" could reap a blob it still needs).
    let content_images = data_dir.join("content-images");
    for id in &registered {
        let img = content_images.join(format!("{id}.ext4"));
        let paths = match layer_plan::try_read_layer_paths(&img) {
            Ok(p) => p,
            Err(e) => {
                warn!(project = %id, error = %e, "baselayers GC: cannot read layer paths; skipping sweep");
                return;
            }
        };
        for p in paths {
            // Match by content-addressed FILENAME, not parent path: the baked paths carry
            // the data_dir spelling AS OF deploy time, so a relocated/re-spelled data_dir
            // would make a live base/runtime's parent lexically != the boot-time baselayers
            // dir and silently drop it from the set. A `sha256-<hex>.erofs` name uniquely
            // identifies its blob regardless of directory; adding app-layer names too is
            // harmless (they never collide with a baselayers blob's content address).
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                live.insert(name.to_string());
            }
        }
    }

    // Sweep: reap content-addressed blobs (`sha256-<hex>.erofs`) not in the live set.
    // Anything else in baselayers/ (platform.json, verity sidecars) is left untouched.
    let Ok(entries) = std::fs::read_dir(&baselayers) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !layer_plan::is_safe_layer_filename(&name) || live.contains(&name) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => info!(blob = %name, "reaped unreferenced baselayer blob"),
            Err(e) => warn!(blob = %name, error = %e, "failed to reap unreferenced baselayer blob"),
        }
    }
}

/// Reconcile persisted state into the in-memory domain map at startup. Grandfathers
/// each deployed project's primary subdomain and any legacy `project.domains` into
/// the DOMAINS registry as Active (trusted prod data — no re-verification), then
/// loads all Active domains into the map so hosts resolve before traffic arrives.
/// Whether a registered project can actually be woken: it needs EITHER cold-boot
/// content (`hosting/{id}/live`) OR a restorable snapshot (snapshot + mem files
/// present) atop its metadata image (`content-images/{id}.ext4`). When neither holds,
/// its deployable artifacts were removed out-of-band (e.g. an over-aggressive cleanup)
/// and it can only come back via a redeploy — see [`ProjectState::NeedsRedeploy`].
fn project_can_wake(data_dir: &Path, store: &Store, project_id: &str) -> bool {
    if data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .is_dir()
    {
        return true; // can cold-boot from the deployed content
    }
    let content_image = data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"))
        .is_file();
    let snapshot_ok = store
        .get_snapshot_meta(project_id)
        .ok()
        .flatten()
        .map(|m| Path::new(&m.snapshot_path).exists() && Path::new(&m.mem_file_path).exists())
        .unwrap_or(false);
    content_image && snapshot_ok // can restore from snapshot
}

async fn backfill_domains(platform: &Arc<Mutex<PlatformState>>, domain_map: &DomainMap) {
    let active = {
        let mut plat = platform.lock().await;
        let projects = match plat.store.list_projects() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "failed to list projects");
                return;
            }
        };

        for project in &projects {
            if project.current_version.is_none() {
                continue;
            }
            match project.state {
                ProjectState::Active | ProjectState::Hibernated => {
                    // VM re-adoption §7: a project re-adopted Running this start is ALREADY live
                    // (its survivor VM + routes are up). Do NOT overwrite its state to Hibernated
                    // or flip redb — that silently breaks metering/log-ship/idle-hibernate/drain,
                    // which all filter on `== Running`. Just keep its domains grandfathered.
                    let adopted = plat.vm_states.get(&project.id) == Some(&VmLifecycle::Running)
                        || plat.vms.contains_key(&project.id);
                    // Reconcile a registered project whose deployable artifacts were
                    // removed out-of-band: it would otherwise be registered for wake and
                    // loop the proxy on "starting up" forever. Mark it NeedsRedeploy so
                    // the proxy serves a clear message; still grandfather its domains so
                    // the user gets that message (not a 404). A redeploy clears it.
                    let data_dir = plat.data_dir.clone();
                    if adopted {
                        // live survivor — leave Running + routes intact; grandfather only.
                    } else if !project_can_wake(&data_dir, &plat.store, &project.id) {
                        warn!(
                            project = %project.id,
                            "registered project has no deployable artifacts (content + snapshot gone) — marking needs-redeploy"
                        );
                        let mut p = project.clone();
                        p.state = ProjectState::NeedsRedeploy;
                        let _ = plat.store.update_project(&p);
                        // Drop the dangling snapshot pointer so nothing tries to restore it.
                        let _ = plat.store.remove_snapshot_meta(&project.id);
                    } else {
                        plat.vm_states
                            .insert(project.id.clone(), VmLifecycle::Hibernated);
                        if project.state == ProjectState::Active {
                            let mut p = project.clone();
                            p.state = ProjectState::Hibernated;
                            let _ = plat.store.update_project(&p);
                        }
                        // Clear a stale snapshot pointer (snapshot file gone but content
                        // present) so wake cold-boots cleanly from content instead of
                        // attempting a doomed restore.
                        if let Ok(Some(meta)) = plat.store.get_snapshot_meta(&project.id)
                            && !Path::new(&meta.snapshot_path).exists()
                        {
                            let _ = plat.store.remove_snapshot_meta(&project.id);
                        }
                    }

                    let tenant_id = project.tenant_id.clone().unwrap_or_default();
                    // Grandfather the primary subdomain (host-key == project id).
                    grandfather_domain(&plat.store, &project.id, &project.id, &tenant_id);
                    // Grandfather legacy project.domains (already-trusted aliases).
                    for host in &project.domains {
                        grandfather_domain(&plat.store, host, &project.id, &tenant_id);
                    }
                }
                ProjectState::NeedsRedeploy | ProjectState::Stopped => {
                    // NeedsRedeploy: still grandfather domains so the proxy can serve the
                    // clear "redeploy" message rather than a 404; don't register for wake.
                    if project.state == ProjectState::NeedsRedeploy {
                        let tenant_id = project.tenant_id.clone().unwrap_or_default();
                        grandfather_domain(&plat.store, &project.id, &project.id, &tenant_id);
                        for host in &project.domains {
                            grandfather_domain(&plat.store, host, &project.id, &tenant_id);
                        }
                    }
                }
            }
        }

        plat.store.list_all_domains().unwrap_or_default()
    };

    let mut map = domain_map.write().await;
    let mut count = 0usize;
    for d in active {
        if d.status == DomainStatus::Active {
            map.insert(
                d.host,
                DomainTarget {
                    project_id: d.project_id,
                    site: d.site,
                },
            );
            count += 1;
        }
    }
    info!(
        domains = count,
        "domain map built; projects registered for on-demand wake"
    );
}

/// Ensure an Active DomainRecord exists for `host` (idempotent). Used by backfill
/// to migrate pre-registry data without forcing re-verification.
fn grandfather_domain(store: &Store, host: &str, project_id: &str, tenant_id: &str) {
    if matches!(store.get_domain(host), Ok(Some(_))) {
        return;
    }
    let kind = if host.contains('.') {
        DomainKind::Custom
    } else {
        DomainKind::Subdomain
    };
    let record = DomainRecord {
        host: host.to_string(),
        project_id: project_id.to_string(),
        tenant_id: tenant_id.to_string(),
        site: None,
        kind,
        status: DomainStatus::Active,
        token: String::new(),
        created_at: 0,
    };
    let _ = store.claim_domain(&record);
}

/// Discover the host's public uplink IPv4(s): the global-scope addresses on the
/// default-route interface. Mirrors `tools/setup-bridge.sh` (`ip route show default` →
/// `ip -4 -o addr show $IFACE scope global`). Fail-soft: returns empty on any error (the
/// caller warns), never a partial/garbage IP. Used to build the agent's Zone-2 deny-set.
fn discover_uplink_ips() -> Vec<String> {
    let iface = match std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            // "default via <gw> dev <iface> ..." — take the token after `dev`.
            text.lines().next().and_then(|l| {
                let mut it = l.split_whitespace();
                while let Some(tok) = it.next() {
                    if tok == "dev" {
                        return it.next().map(str::to_string);
                    }
                }
                None
            })
        }
        _ => None,
    };
    let Some(iface) = iface else {
        return Vec::new();
    };
    match std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", &iface, "scope", "global"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                // "<n>: <iface>    inet <ip>/<prefix> ..." — take the addr after `inet`,
                // strip the prefix, and only keep a parseable IPv4.
                let mut it = l.split_whitespace();
                while let Some(tok) = it.next() {
                    if tok == "inet" {
                        let addr = it.next()?.split('/').next()?;
                        if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                            return Some(addr.to_string());
                        }
                    }
                }
                None
            })
            .collect(),
        _ => Vec::new(),
    }
}

async fn handle_deploy(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<()> {
    // Wait out any in-flight wake/hibernate before touching the disk: those drop the
    // platform lock during the slow VM op while still holding the data-disk lease, so
    // releasing + re-fencing underneath one would (a) fail transiently with LeaseHeld,
    // or worse (b) for a still-live hibernate, detach the disk its paused-but-alive FC
    // still maps and start a second writer. Budget ~80s to actually outlast hibernate's
    // worst case (3s log-ship + 60s snapshot timeout); on expiry FAIL CLOSED rather than
    // charge ahead into a re-fence under a live peer — deploy is retryable.
    let mut plat = {
        let mut attempt = 0;
        loop {
            let plat = platform.lock().await;
            if matches!(
                plat.vm_states.get(project_id),
                Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
            ) {
                if attempt >= 400 {
                    anyhow::bail!(
                        "project {project_id} busy (wake/hibernate still in flight after ~80s); retry deploy"
                    );
                }
                drop(plat);
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            break plat;
        }
    };

    // HA P3: only the OWNER host may deploy a project. On a single node every project is
    // local (unplaced / owned by this host), so this is a no-op; in a cluster a deploy that
    // reached a non-owner fails closed (retry) rather than booting a second owner.
    {
        let me = plat.host_id.clone();
        let alloc = plat.store.get_vm_allocation(project_id).ok().flatten();
        let hosts = plat.store.list_hosts().unwrap_or_default();
        let now = jkbase_control::auth::timestamp();
        match deploy_target(
            alloc.as_ref(),
            &hosts,
            &me,
            now,
            DEAD_HOST_THRESHOLD.as_secs(),
        ) {
            DeployTarget::Local => {}
            DeployTarget::Remote { host_id, addr } => anyhow::bail!(
                "project {project_id} is owned by host {host_id} ({}); the deploy must run there \
                 (cross-host deploy forwarding not yet wired)",
                addr.as_deref().unwrap_or("addr unknown")
            ),
            DeployTarget::OwnerDead { host_id } => anyhow::bail!(
                "project {project_id}'s owner host {host_id} is down; the reconciler will reassign \
                 it — retry the deploy shortly"
            ),
        }
    }

    // A deploy/rollback supersedes any prior snapshot UNCONDITIONALLY — not only when
    // `Hibernated`. A VM that was restored-then-Running still carries its snapshot (restore
    // doesn't delete it), and the metadata image / layers it baked are about to be rewritten in
    // place; leaving that snapshot would let a later restart restore stale guest RAM against the
    // new bytes if the version happened to re-match (e.g. a rollback). Clearing here closes that
    // window — the `deployment_version` viability gate is then defence in depth, not the only guard.
    {
        info!(project = %project_id, "clearing any stale snapshot for fresh deploy");
        let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
        let _ = std::fs::remove_dir_all(&snapshot_dir);
        let _ = plat.store.remove_snapshot_meta(project_id);
    }

    if let Some(mut old_vm) = plat.vms.remove(project_id) {
        plat.vm_rootfs_hashes.remove(project_id);
        info!(project = %project_id, "syncing and stopping old VM for redeploy");
        if let Ok(Some(alloc)) = plat.store.get_vm_allocation(project_id) {
            let _ = sync_agent(&alloc.ip).await;
            // Capture any final log lines before the old agent goes away.
            shipper.ship(project_id, &alloc.ip).await;
        }
        let _ = old_vm.stop().await;
    }
    // The old VM is gone (or being replaced); drop its re-adoption record so a crash between
    // here and the new commit can't leave a handoff pointing at the now-dead old FC. The new
    // VM writes a fresh record at its commit-to-Running below.
    handoff::remove(&plat.data_dir.join("run"), project_id);
    // Release the old VM's data-disk hold (if any) before re-fencing for the new VM —
    // UNCONDITIONALLY: a stop() error or a missing VM handle must not leak the lease
    // (which would then fail the re-fence below with LeaseHeld and brick the redeploy).
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    let content_dir = plat.data_dir.join("hosting").join(project_id).join("live");
    if !content_dir.exists() {
        anyhow::bail!("no deployed content for project {project_id}");
    }

    let alloc = match plat.store.get_vm_allocation(project_id)? {
        Some(existing) => {
            info!(project = %project_id, ip = %existing.ip, "reusing persisted IP");
            existing
        }
        None => {
            let (ip, tap, mac) = plat.allocate_ip()?;
            let alloc = VmAllocation {
                project_id: project_id.to_string(),
                ip,
                tap_device: tap,
                mac,
                // HA P3: the host that first deploys a project owns it (initial placement);
                // the leader reassigns on host death (reconcile_loop). On a single node this
                // is the one live host, so ownership is a no-op for routing.
                host_id: plat.host_id.clone(),
                placement_epoch: 1,
            };
            plat.store.save_vm_allocation(&alloc)?;
            info!(project = %project_id, ip = %alloc.ip, "allocated new IP");
            alloc
        }
    };

    // Read what the slow build + fence + boot need, then DROP the platform lock: the
    // metadata-image build (mkfs + sha256 layer verify), the RWO attach (first-deploy
    // mkfs / reap+300ms / losetup), and the VM boot must NOT head-of-line block every
    // other project on the single platform lock. Re-acquire only to commit.
    // Dedicated projects run their managed DB in a SIBLING VM, so the app VM must NOT be forced a
    // data disk on account of the DB (`check_project_has_database`) — it only fences a disk for its
    // OWN volumes. A co-located project (the default) keeps forcing the disk for the loopback DB.
    let dedicated = project_is_dedicated(&plat.data_dir, project_id);
    let has_disk = check_project_has_volumes(&plat.data_dir, project_id)
        || (!dedicated && check_project_has_database(&plat.data_dir, project_id))
        || plat.data_disk.exists(project_id).await.unwrap_or(false);
    let data_dir = plat.data_dir.clone();
    let dd = plat.data_disk.clone();
    let ls = plat.lease.clone();
    let hid = plat.host_id.clone();
    let firecracker_bin = plat.firecracker_bin.clone();
    let kernel_path = plat.kernel_path.clone();
    let rootfs_path = plat.base_rootfs_path.clone();
    let runtime_dir = data_dir.join("run");
    // Project secrets → merged into each server's runtime env in the per-project
    // metadata image below (read here under the platform lock). That image is rebuilt
    // ONLY on deploy; wake/restore reuse the last-deployed image (a restored live
    // process can't be re-env'd), so a secret change takes effect on the next DEPLOY,
    // not on an idle wake/restart.
    let secrets: std::collections::BTreeMap<String, String> = plat
        .store
        .list_secrets(project_id)
        .map(|v| v.into_iter().map(|s| (s.key, s.value)).collect())
        .unwrap_or_default();
    // Host-asserted platform egress facts, stamped into this VM's metadata image as
    // `_platform.json` (the agent's OWN-storage host + Zone-2 deny-set). Read under the lock.
    let platform_egress = plat.platform_egress.clone();
    // Mint (rotate) the project's own-bucket binding credential and write it into the
    // function sidecars' reserved channel below. Owner-bound to the project's CURRENT tenant
    // (the object-store owner re-bind fail-closes a stale one); a fresh secret each deploy.
    // Only when the project has an owner — an ownerless project gets no binding (the SigV4
    // owner re-check would reject it anyway). Best-effort: a mint failure must not fail the
    // deploy (functions just can't use the typed binding until the next deploy).
    let storage_binding: Option<layer_plan::StorageBinding> = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .and_then(|p| p.tenant_id)
        .and_then(|tenant| plat.store.mint_binding_key(project_id, &tenant).ok())
        .map(|k| layer_plan::StorageBinding {
            access_key_id: k.access_key_id,
            secret_key: k.secret_key,
        });
    // Mint (rotate) the per-deploy reach-plane secrets for a project with a managed DB and
    // persist them — the edge reads the splice secret from the control store to present on the
    // `/_jkbase/db` upgrade, and the SAME values are baked into the per-VM image below so the
    // in-VM agent can verify the splice ([R3]) and inject the admin token into the DB env
    // ([RB1]). Best-effort: a mint failure just means the reach plane / backups can't run until
    // the next deploy (fail-closed), never a failed deploy. The admin token rides the reserved
    // channel ONLY — never `_database.json`.
    let db_reach: Option<jkbase_common::config::DbReachFacts> =
        if check_project_has_database(&data_dir, project_id) {
            plat.store
                .mint_db_splice_secret(project_id)
                .ok()
                .map(|splice_secret| {
                    let admin_token = plat
                        .store
                        .mint_db_admin_token(project_id)
                        .unwrap_or_default();
                    jkbase_common::config::DbReachFacts {
                        splice_secret,
                        admin_token,
                        // Base value (the DB VM's own image keeps this); the app VM's copy is
                        // flipped to `dedicated` below so its agent starts the app→DB loopback proxy.
                        dedicated: false,
                    }
                })
        } else {
            None
        };
    drop(plat);

    setup_tap(&alloc.tap_device).await?;

    // Build the per-project metadata image (device map + manifests + static sites)
    // and resolve the erofs layer blobs to attach. Replaces the flat content image:
    // a layered server's root is an overlay of app:runtime:base, so the runtime VM
    // gets the metadata image (vdb) + the layer blobs (vdc..) instead of one blob.
    let content_images_dir = data_dir.join("content-images");
    tokio::fs::create_dir_all(&content_images_dir).await?;
    let metadata_image_path = content_images_dir.join(format!("{project_id}.ext4"));
    // A dedicated project's app VM image excludes the managed DB (it runs in a sibling VM); a
    // co-located project's app VM carries the rhypedb overlay as before. `db_reach` rides the app
    // image EITHER way — the app reaches its DB on loopback (co-located) or host-mediated via the
    // sibling VM (dedicated), so it needs the splice secret regardless.
    let app_content = if dedicated {
        layer_plan::ImageContent::AppNoDb
    } else {
        layer_plan::ImageContent::All
    };
    // The DB VM boot below reuses the SAME per-deploy reach facts (the splice secret both VMs must
    // present); clone them out before the app build MOVES `db_reach` into its blocking closure. The
    // DB VM's copy keeps `dedicated=false` (it IS the DB — no loopback proxy); flip the APP VM's
    // copy so its agent starts the app→DB in-guest leg (P2 §7.6).
    let db_reach_for_db_vm = db_reach.clone();
    let mut db_reach = db_reach;
    if let Some(r) = db_reach.as_mut() {
        r.dedicated = dedicated;
    }
    let plan = {
        let content_dir = content_dir.clone();
        let store_dir = data_dir.join("baselayers");
        let out = metadata_image_path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<layer_plan::LayerPlan> {
            // verify=true: cold-boot deploy re-checks every tenant + platform blob's
            // sha256 before it can be attached to a VM.
            let plan =
                layer_plan::compute_layer_plan_with(&content_dir, &store_dir, has_disk, true, app_content)?;
            layer_plan::build_metadata_image_with(
                &content_dir,
                &plan,
                &secrets,
                &platform_egress,
                storage_binding.as_ref(),
                db_reach.as_ref(),
                &out,
                app_content,
            )?;
            Ok(plan)
        })
        .await
        .context("metadata image build task")??
    };

    // Fence the data disk read-write-once for projects that declare volumes (or
    // already have a disk): acquire the lease + attach via the RWO provider, preempting
    // any prior writer. Held by an RAII guard until the VM is up, so a boot failure (or
    // a cancelled future) releases the lease instead of bricking the project.
    let disk_guard = if has_disk {
        let disk_mib = data_disk_mib_for(&data_dir, project_id);
        Some(fence_data_disk(&dd, &ls, &hid, project_id, disk_mib).await?)
    } else {
        None
    };

    // `handle_deploy` only ever boots the APP VM (the dedicated DB VM boots via its own helper),
    // so it keeps the historical App sizing. Sourced from VmSize so the DB VM reuses the same
    // plumbing and hibernate/restore can't drift the mem-file size.
    let app_size = vm_identity::vm_size_for(vm_identity::VmRole::App);
    let config = VmConfig {
        firecracker_bin,
        kernel_path,
        rootfs_path,
        metadata_image_path: Some(metadata_image_path),
        layer_paths: plan.layer_paths.clone(),
        data_disk_path: disk_guard.as_ref().map(|g| g.device()),
        vcpu_count: app_size.vcpu_count,
        mem_size_mib: app_size.mem_size_mib,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
        runtime_cgroup_parent: Some(PathBuf::from(RUNTIME_CGROUP_PARENT)),
    };
    // If start fails, release the fenced disk + lease AWAITED (not via the Drop
    // backstop) so an immediate re-deploy/re-wake can't race a fire-and-forget cleanup
    // and fail transiently with LeaseHeld/RwoUnsafe.
    let mut vm = match VmInstance::start(project_id, &config, &runtime_dir).await {
        Ok(vm) => vm,
        Err(e) => {
            if let Some(g) = disk_guard {
                g.release().await;
            }
            return Err(e);
        }
    };

    // Re-acquire to commit the running VM: record Firecracker's PID as the data-disk
    // writer (so a future attach's liveness check tracks the real writer, not this
    // server), then DISARM the guard and hand the token to disk_tokens.
    let mut plat = platform.lock().await;
    let fc_pid = vm.pid();
    // Capture the disk fence facts for the handoff, and make the writer-pid commit FATAL: the
    // holder must record the FC pid (so attach_rwo's liveness gate + re-adoption track the real
    // writer) before the handoff names it. On failure, KILL the FC synchronously-to-death FIRST
    // (so the loop it maps is free) THEN release the guard AWAITED, and bail (deploy is
    // retryable) — never commit a VM whose holder still names this server, never detach a loop a
    // live FC still writes.
    let (loop_dev, lease_epoch) = if let Some(guard) = disk_guard {
        if let Some(pid) = fc_pid
            && let Err(e) = dd.set_writer_pid(project_id, guard.token(), pid).await
        {
            drop(plat);
            let _ = vm.stop().await;
            guard.release().await;
            return Err(anyhow::anyhow!("commit set_writer_pid {project_id}: {e}"));
        }
        let dev = guard.device().to_string_lossy().into_owned();
        let epoch = guard.token().epoch;
        plat.disk_tokens
            .insert(project_id.to_string(), guard.disarm());
        (Some(dev), Some(epoch))
    } else {
        (None, None)
    };
    plat.vms.insert(project_id.to_string(), vm);
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Running);
    // Cold boot always runs the CURRENT rootfs; track it so a later hibernate stamps the truthful
    // hash (and keeps the GC reference set honest). Clear any wake-failure throttle: this project
    // is now freshly booted, so a stale entry mustn't fast-fail a routing-miss request.
    let ran_hash = plat.base_rootfs_hash.clone();
    plat.vm_rootfs_hashes
        .insert(project_id.to_string(), ran_hash.clone());
    plat.wake_failures.remove(project_id);
    let deployment_version = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .and_then(|p| p.current_version);
    let active_domains = plat
        .store
        .list_active_domains_for_project(project_id)
        .unwrap_or_default();
    drop(plat);

    // Persist the re-adoption record so a future jkbase-server upgrade re-adopts this VM (no
    // bounce) instead of draining → cold-restoring it. Removed on every teardown. Best-effort:
    // a write failure just means this VM cold-boots on the next restart (the prior behavior).
    write_handoff_record(
        &runtime_dir,
        project_id,
        fc_pid,
        &alloc,
        loop_dev,
        lease_epoch,
        ran_hash,
        deployment_version,
    );

    wait_for_agent(&alloc.ip).await?;

    register_active_routes(
        &routing,
        &domain_map,
        &active_domains,
        project_id,
        &alloc.ip,
    )
    .await;

    info!(project = %project_id, ip = %alloc.ip, "VM ready, routing active");

    // A dedicated project runs its managed DB in a SIBLING VM (`{project_id}.db`); boot it now that
    // the app VM is up. A DB-VM boot failure fails the whole deploy (retryable) rather than leaving
    // a half-provisioned dedicated project whose app can't reach a DB. Co-located projects skip
    // this entirely (their DB is the loopback process inside the app VM booted above).
    if dedicated {
        boot_db_vm(project_id, &platform, db_reach_for_db_vm.as_ref()).await?;
    }
    Ok(())
}

/// Boot (or, on redeploy, replace) a project's dedicated DB VM (`{project_id}.db`). Mirrors the
/// app-VM cold boot but for a lean, rhypedb-only sibling: its OWN IP/TAP + data disk
/// (`{id}.db.img`) + metadata image (`content-images/{id}.db.ext4`, built `DbOnly`), booted at
/// [`vm_identity::DB_VM_SIZE`] and committed into the platform maps under the rendered id. All
/// deployment/store reads use the BASE `project_id` (the DB VM has no `hosting/<id>.db/` — it
/// reuses the app's live tree); all per-VM-instance state uses the rendered `db_id`. A boot error
/// propagates so the caller fails the deploy (retryable) rather than half-provisioning.
async fn boot_db_vm(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
    db_reach: Option<&jkbase_common::config::DbReachFacts>,
) -> Result<()> {
    let db_id = vm_identity::vm_id(project_id, vm_identity::VmRole::Db);

    // Snapshot the substrate handles + supersede any prior DB VM (redeploy), then release the lock
    // for the slow build + fence + boot.
    let (data_dir, dd, ls, hid, firecracker_bin, kernel_path, rootfs_path, platform_egress, alloc) = {
        let mut plat = platform.lock().await;

        // Supersede a prior DB VM incarnation (redeploy): drop its stale snapshot, stop it, and
        // release its data-disk hold before re-fencing — mirrors the app redeploy path.
        let snapshot_dir = plat.data_dir.join("snapshots").join(&db_id);
        let _ = std::fs::remove_dir_all(&snapshot_dir);
        let _ = plat.store.remove_snapshot_meta(&db_id);
        if let Some(mut old) = plat.vms.remove(&db_id) {
            let _ = old.stop().await;
        }
        plat.vm_rootfs_hashes.remove(&db_id);
        handoff::remove(&plat.data_dir.join("run"), &db_id);
        if let Some(token) = plat.disk_tokens.remove(&db_id) {
            let dd = plat.data_disk.clone();
            let ls = plat.lease.clone();
            release_data_disk(&dd, &ls, &db_id, token).await;
        }

        // Allocate (or reuse) the DB VM's own IP under the `{id}.db` allocation row — a 2nd octet.
        let alloc = match plat.store.get_vm_allocation(&db_id)? {
            Some(existing) => existing,
            None => {
                let (ip, tap, mac) = plat.allocate_ip()?;
                let a = VmAllocation {
                    project_id: db_id.clone(),
                    ip,
                    tap_device: tap,
                    mac,
                    host_id: plat.host_id.clone(),
                    placement_epoch: 1,
                };
                plat.store.save_vm_allocation(&a)?;
                info!(project = %project_id, db_vm = %db_id, ip = %a.ip, "allocated DB VM IP");
                a
            }
        };
        (
            plat.data_dir.clone(),
            plat.data_disk.clone(),
            plat.lease.clone(),
            plat.host_id.clone(),
            plat.firecracker_bin.clone(),
            plat.kernel_path.clone(),
            plat.base_rootfs_path.clone(),
            plat.platform_egress.clone(),
            alloc,
        )
    };

    let content_dir = data_dir.join("hosting").join(project_id).join("live");
    let runtime_dir = data_dir.join("run");
    setup_tap(&alloc.tap_device).await?;

    // Build the DB VM's OWN metadata image (DbOnly: rhypedb overlay + `_database.json`/`_database/`
    // only — no app servers/routes/sites) + resolve its layer blobs from the same live tree.
    let metadata_image_path = data_dir
        .join("content-images")
        .join(format!("{db_id}.ext4"));
    let plan = {
        let content_dir = content_dir.clone();
        let store_dir = data_dir.join("baselayers");
        let out = metadata_image_path.clone();
        let db_reach = db_reach.cloned();
        tokio::task::spawn_blocking(move || -> anyhow::Result<layer_plan::LayerPlan> {
            let plan = layer_plan::compute_layer_plan_with(
                &content_dir,
                &store_dir,
                true,
                true,
                layer_plan::ImageContent::DbOnly,
            )?;
            layer_plan::build_metadata_image_with(
                &content_dir,
                &plan,
                &std::collections::BTreeMap::new(),
                &platform_egress,
                None,
                db_reach.as_ref(),
                &out,
                layer_plan::ImageContent::DbOnly,
            )?;
            Ok(plan)
        })
        .await
        .context("DB VM metadata image build task")??
    };

    // Fence the DB VM's OWN data disk (`{id}.db.img`), sized from the BASE project's
    // `_database.json` (`[database].size`). The `.db` scope is validator-legal (F1).
    let disk_mib = data_disk_mib_for(&data_dir, project_id);
    let disk_guard = fence_data_disk(&dd, &ls, &hid, &db_id, disk_mib).await?;

    let db_size = vm_identity::vm_size_for(vm_identity::VmRole::Db);
    let config = VmConfig {
        firecracker_bin,
        kernel_path,
        rootfs_path,
        metadata_image_path: Some(metadata_image_path),
        layer_paths: plan.layer_paths.clone(),
        data_disk_path: Some(disk_guard.device()),
        vcpu_count: db_size.vcpu_count,
        mem_size_mib: db_size.mem_size_mib,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
        runtime_cgroup_parent: Some(PathBuf::from(RUNTIME_CGROUP_PARENT)),
    };
    // On start failure, release the fenced disk AWAITED (not via the Drop backstop) so an immediate
    // redeploy/re-wake can't race a fire-and-forget cleanup into a transient LeaseHeld/RwoUnsafe.
    let mut vm = match VmInstance::start(&db_id, &config, &runtime_dir).await {
        Ok(vm) => vm,
        Err(e) => {
            disk_guard.release().await;
            return Err(e);
        }
    };

    // Commit-to-Running: record the FC pid as the disk writer (FATAL — mirrors the app commit),
    // disarm the guard, and insert into the platform maps under the rendered id.
    let mut plat = platform.lock().await;
    let fc_pid = vm.pid();
    let (loop_dev, lease_epoch) = {
        if let Some(pid) = fc_pid
            && let Err(e) = dd.set_writer_pid(&db_id, disk_guard.token(), pid).await
        {
            drop(plat);
            let _ = vm.stop().await;
            disk_guard.release().await;
            return Err(anyhow::anyhow!("commit set_writer_pid {db_id}: {e}"));
        }
        let dev = disk_guard.device().to_string_lossy().into_owned();
        let epoch = disk_guard.token().epoch;
        plat.disk_tokens.insert(db_id.clone(), disk_guard.disarm());
        (Some(dev), Some(epoch))
    };
    plat.vms.insert(db_id.clone(), vm);
    plat.vm_states.insert(db_id.clone(), VmLifecycle::Running);
    let ran_hash = plat.base_rootfs_hash.clone();
    plat.vm_rootfs_hashes.insert(db_id.clone(), ran_hash.clone());
    plat.wake_failures.remove(&db_id);
    // The DB VM's snapshot version token is the BASE project's deploy version: its metadata image is
    // rewritten every deploy (like the app's), so its snapshot is valid within a deploy version and
    // invalidated on redeploy (fail-open to a cold boot from the persistent data disk).
    let deployment_version = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .and_then(|p| p.current_version);
    drop(plat);

    // Re-adoption record for the DB VM (role Db, derived from the rendered id); removed on teardown.
    write_handoff_record(
        &runtime_dir,
        &db_id,
        fc_pid,
        &alloc,
        loop_dev,
        lease_epoch,
        ran_hash,
        deployment_version,
    );

    // The DB VM is NOT proxy-routed (it's reached host-mediated); just wait for its agent to serve.
    wait_for_agent(&alloc.ip).await?;
    info!(project = %project_id, db_vm = %db_id, ip = %alloc.ip, "DB VM ready");
    Ok(())
}

/// Write the per-VM re-adoption record at commit-to-Running (deploy + wake). `fc_pid` +
/// `fc_starttime` are captured from the SAME `/proc` read so the pid is pinned to one
/// incarnation. Best-effort: if `fc_pid` is unknown (FC already exited) or the write fails, we
/// skip — the only consequence is that this VM cold-boots on the next restart (the prior
/// behavior), never a correctness hazard. See [`handoff`].
#[allow(clippy::too_many_arguments)]
fn write_handoff_record(
    runtime_dir: &Path,
    project_id: &str,
    fc_pid: Option<u32>,
    alloc: &VmAllocation,
    loop_dev: Option<String>,
    lease_epoch: Option<u64>,
    base_rootfs_hash: String,
    deployment_version: Option<u64>,
) {
    let Some(pid) = fc_pid else {
        warn!(project = %project_id, "no FC pid at commit; skipping re-adoption handoff");
        return;
    };
    let Some(st) = proc_starttime(pid) else {
        warn!(project = %project_id, %pid, "FC pid gone at commit; skipping re-adoption handoff");
        return;
    };
    let rec = handoff::HandoffRecord {
        schema_version: handoff::SCHEMA_VERSION,
        project_id: project_id.to_string(),
        // `project_id` here is the RENDERED vm id (bare for App, `{id}.db` for a DB VM), so the
        // role is implied by its suffix — App today, Db once the dedicated-DB boot writes its own.
        role: vm_identity::split_vm_id(project_id).1,
        fc_pid: pid,
        fc_starttime: st,
        ip: alloc.ip.clone(),
        tap: alloc.tap_device.clone(),
        mac: alloc.mac.clone(),
        loop_dev,
        lease_epoch,
        base_rootfs_hash,
        deployment_version,
    };
    if let Err(e) = handoff::write(runtime_dir, project_id, &rec) {
        warn!(project = %project_id, error = %e,
            "failed to write re-adoption handoff (VM will cold-boot on next restart)");
    }
}

/// Point all of a project's Active hosts at its VM IP (fast-path routes) and
/// ensure the shared domain map reflects them. `routes` is keyed by host-key.
async fn register_active_routes(
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    active_domains: &[DomainRecord],
    project_id: &str,
    ip: &str,
) {
    let mut table = routing.write().await;
    let mut map = domain_map.write().await;
    // The primary label always routes, even if its DomainRecord predates the registry.
    table.insert(project_id.to_string(), ip.to_string());
    map.entry(project_id.to_string())
        .or_insert_with(|| DomainTarget {
            project_id: project_id.to_string(),
            site: None,
        });
    for d in active_domains {
        table.insert(d.host.clone(), ip.to_string());
        map.insert(
            d.host.clone(),
            DomainTarget {
                project_id: d.project_id.clone(),
                site: d.site.clone(),
            },
        );
    }
}

async fn hibernate_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    // Idle-path callers pass the DB relay registry so we can re-check for a LIVE managed-DB
    // relay UNDER the platform lock (§5); shutdown/quota callers pass `None` — those paths
    // hibernate regardless (relays are force-closed on drain; over-quota must win).
    db_registry: Option<&Arc<jkbase_proxy::db_relay::DbRelayRegistry>>,
) -> Result<()> {
    let mut plat = platform.lock().await;

    match plat.vm_states.get(project_id) {
        Some(VmLifecycle::Running) => {
            // §5: re-check under the platform lock that no live DB relay appeared since the
            // idle loop's UNLOCKED conn_count read (db_ingress reserves the relay before its
            // wake, so a racing connection is already counted here) — otherwise a byte-silent
            // realtime subscription would be hibernated out from under itself. A relay that
            // slips in during this function's own critical section instead fails its bounded
            // connect and the client retries, waking the VM cleanly.
            if db_registry
                .map(|r| r.conn_count(vm_identity::base_project_id(project_id)) > 0)
                .unwrap_or(false)
            {
                return Ok(());
            }
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Hibernating);
        }
        _ => anyhow::bail!("project {project_id} is not running"),
    }

    // Remove from the routes fast-path first (new requests will trigger wake).
    // Leave the domain map intact so hibernated hosts still resolve + wake.
    {
        let mut table = routing.write().await;
        table.remove(project_id);
        if let Ok(domains) = plat.store.list_active_domains_for_project(project_id) {
            for d in &domains {
                table.remove(&d.host);
            }
        }
    }

    let mut vm = match plat.vms.remove(project_id) {
        Some(vm) => vm,
        None => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Running);
            anyhow::bail!("no VM instance for {project_id}");
        }
    };

    // VM re-adoption §6/R4: remove the handoff record FIRST — before the pause below — so even a
    // SIGKILL of this server mid-snapshot can't leave a PAUSED FC that the next start would
    // re-adopt as "running" (the paused-FC-resurrection hole). Decoupled from the disk_tokens
    // clear, which is in the SECOND lock after the pause. The teardown paths that have no pause
    // (force-stop / self-fence / teardown) remove it beside their disk_tokens clear instead.
    handoff::remove(&plat.data_dir.join("run"), project_id);

    let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
    let agent_ip = plat
        .store
        .get_vm_allocation(project_id)
        .ok()
        .flatten()
        .map(|a| a.ip);
    drop(plat);

    // Pre-pause wedge detection: if the agent is unreachable/wedged, skip the
    // flush + pause/snapshot entirely and go straight to a clean force-stop. A
    // wedged guest can't complete a Firecracker Pause+snapshot anyway, and
    // attempting it is what produces the "failed to pause VM" stall.
    let wedged = match &agent_ip {
        Some(ip) => !agent_alive(ip).await,
        None => true, // no allocation/ip -> nothing to pause cleanly
    };
    if wedged {
        tracing::warn!(project = %project_id, "agent unreachable/wedged, force-stopping instead of hibernating");
        force_stop_and_cleanup(project_id, &platform).await;
        return Ok(());
    }

    // Final flush of the agent's buffer before we pause it. Bounded so a wedged
    // agent (that passed the probe but then stalls) can't block shutdown.
    if let Some(ip) = &agent_ip {
        let _ = tokio::time::timeout(Duration::from_secs(3), shipper.ship(project_id, ip)).await;
    }

    // Bound pause+snapshot so one bad VM can't stall the drain of the rest. The
    // budget is generous because snapshotting a 1 GiB mem file is legit slow I/O
    // (Pause itself is sub-second). Any timeout or error -> clean force-stop.
    let (snapshot_path, mem_file_path) = match tokio::time::timeout(
        Duration::from_secs(60),
        vm.hibernate(&snapshot_dir),
    )
    .await
    {
        Ok(Ok(paths)) => paths,
        Ok(Err(e)) => {
            tracing::error!(project = %project_id, error = %e, "hibernate failed, force-stopping");
            // stop() is synchronous-to-death for BOTH variants; a bare drop() would NOT kill an
            // Adopted survivor (its Drop is a no-op), leaving force_stop to detach the loop under a
            // live FC. Kill here so the FC is gone before force_stop releases the disk.
            let _ = vm.stop().await;
            force_stop_and_cleanup(project_id, &platform).await;
            return Ok(());
        }
        Err(_elapsed) => {
            tracing::error!(project = %project_id, "hibernate timed out (VM wedged), force-stopping");
            let _ = vm.stop().await;
            force_stop_and_cleanup(project_id, &platform).await;
            return Ok(());
        }
    };

    let mut plat = platform.lock().await;

    // The VM is down (hibernate killed the FC); release its data-disk hold NOW —
    // before persisting snapshot meta — so a persistence error can't leak the lease
    // (which would wedge the project in Hibernating + LeaseHeld on the next wake). The
    // image file persists; the next wake re-fences + the restore patches the drive.
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    // Stamp the snapshot with what the restore will byte-depend on: the rootfs the VM was
    // ACTUALLY mapped against (NOT the process's current hash — a restored-then-rehibernated VM
    // runs the OLD blob), and the deployment version (gates the metadata image + layers, which
    // are rebuilt-in-place per deploy and snapshot-baked by fixed path). Either being absent on
    // the next wake ⇒ non-viable ⇒ fail open to a clean cold boot. Drop the per-VM hash now: the
    // VM is down.
    let base_rootfs_hash = plat.vm_rootfs_hashes.remove(project_id);
    // Version-gate token from the BASE project (a DB VM has no project row of its own), so a DB
    // VM's snapshot is stamped with — and on wake compared against — the same deploy version its
    // metadata image was built at, keeping fast-restore viable within a deploy version.
    let deployment_version = plat
        .store
        .get_project(vm_identity::base_project_id(project_id))
        .ok()
        .flatten()
        .and_then(|p| p.current_version);

    // Stamp the snapshot with THIS VM's role-derived size so the restore (which reads these
    // fields back) maps the mem file at the identical geometry — an app VM at App sizing, a
    // dedicated DB VM at DB sizing.
    let snap_size = vm_identity::vm_size_for(vm_identity::split_vm_id(project_id).1);
    let meta = SnapshotMeta {
        project_id: project_id.to_string(),
        snapshot_path: snapshot_path.to_string_lossy().to_string(),
        mem_file_path: mem_file_path.to_string_lossy().to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        vcpu_count: snap_size.vcpu_count,
        mem_size_mib: snap_size.mem_size_mib,
        base_rootfs_hash,
        deployment_version,
    };
    plat.store.save_snapshot_meta(&meta)?;

    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Hibernated;
        plat.store.update_project(&proj)?;
    }

    // Keep TAP device and VmAllocation for fast restore
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Hibernated);

    info!(project = %project_id, "VM hibernated");
    Ok(())
}

/// RAII reset of the in-memory `Waking` lifecycle for the task that elected itself the wake
/// driver. On drop WITHOUT an explicit `commit()`, it removes the project's `Waking` entry so
/// the project can be re-driven on the next request. This closes the brick (incident: nlnwt)
/// where a client disconnect — the proxy awaits the wake inline per-request, so a disconnect
/// DROPS this future mid-boot — or ANY early `?` exit (alloc read, `setup_tap`, `fence_data_disk`,
/// the boot block) left `vm_states` stuck at `Waking` forever, recoverable only by a full service
/// restart. Drop can't await the async mutex, so it spawns the removal (eventually-consistent),
/// but it ALWAYS fires: the success path `commit()`s (disarming it); every other exit, including
/// cancel/unwind, runs Drop. It only removes an entry that is STILL `Waking`, so it can't stomp a
/// concurrent transition.
struct WakingGuard {
    platform: Arc<Mutex<PlatformState>>,
    project_id: String,
    committed: bool,
}

impl WakingGuard {
    fn new(platform: Arc<Mutex<PlatformState>>, project_id: String) -> Self {
        Self {
            platform,
            project_id,
            committed: false,
        }
    }
    /// The wake reached `Running`; disarm the reset.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for WakingGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let platform = self.platform.clone();
        let pid = self.project_id.clone();
        tokio::spawn(async move {
            let mut plat = platform.lock().await;
            if plat.vm_states.get(&pid) == Some(&VmLifecycle::Waking) {
                plat.vm_states.remove(&pid);
                plat.vm_rootfs_hashes.remove(&pid);
            }
        });
    }
}

/// How long after a failed wake to fast-fail subsequent wakes of the same project, so a broken
/// app (or hostile traffic at a doomed project) can't spin unbounded full boot attempts — each
/// of which bumps the data-disk lease epoch and spawns Firecracker(s). Short enough to keep the
/// self-healing "next request re-drives a boot" property.
const WAKE_BACKOFF: Duration = Duration::from_secs(5);

/// Wake a project, refusing if it is over an enforced quota. The quota gate
/// reads QUOTA_STATUS (the metering loop's source of truth) so a request racing
/// the over-quota hibernation is still refused. All other failures are transient
/// (`Unavailable`) and the proxy retries them.
async fn wake_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> std::result::Result<String, jkbase_proxy::WakeError> {
    // Quota + deployability gate on the BASE project: waking a DB VM (`{id}.db`, driven by the DB
    // reach seams) is gated on its owning project's quota + content (the DB VM has no project row
    // of its own), while `wake_project_inner` boots the rendered id. For an app VM base == id.
    let base = vm_identity::base_project_id(project_id);
    {
        let plat = platform.lock().await;
        if let Ok(Some(status)) = plat.store.get_quota_status(base)
            && status.bandwidth_blocked
        {
            return Err(jkbase_proxy::WakeError::OverQuota(
                status
                    .blocked_reason
                    .unwrap_or_else(|| "over quota".to_string()),
            ));
        }
        // Authoritative gate: a registered project with no deployable artifacts can
        // never wake (cold-boot content + snapshot both gone). Persist NeedsRedeploy
        // and surface a clear "redeploy" rather than looping the proxy on the
        // transient "starting up" path. The boot reconcile marks these too; this also
        // catches a project whose artifacts go missing while the server is up.
        if !project_can_wake(&plat.data_dir, &plat.store, base) {
            if let Ok(Some(mut proj)) = plat.store.get_project(base)
                && proj.state != ProjectState::NeedsRedeploy
            {
                proj.state = ProjectState::NeedsRedeploy;
                let _ = plat.store.update_project(&proj);
                let _ = plat.store.remove_snapshot_meta(base);
            }
            return Err(jkbase_proxy::WakeError::Gone(
                "no deployable content — redeploy to bring it back".to_string(),
            ));
        }
    }
    wake_project_inner(project_id, platform, routing, domain_map, shipper)
        .await
        .map_err(|e| jkbase_proxy::WakeError::Unavailable(e.to_string()))
}

/// Wake the VM that serves a project's managed DB for the reach plane, and return its IP. Resolves
/// the target via [`db_reach_target_vm`] — the sibling DB VM (`{id}.db`) when `tier="dedicated"`,
/// else the app VM — then delegates to [`wake_project`] (whose gates run on the base project). All
/// four DB reach seams (external `:443` edge, console query/schema/status, backup, restore) route
/// through this so a dedicated project is uniformly followed to its DB VM; the splice secret + dial
/// on `:80` are unchanged (the DB VM's agent holds the same secret).
async fn wake_db_reach(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> std::result::Result<String, jkbase_proxy::WakeError> {
    let target = {
        let plat = platform.lock().await;
        db_reach_target_vm(&plat.data_dir, project_id)
    };
    wake_project(&target, platform, routing, domain_map, shipper).await
}

/// Decide whether a hibernation snapshot can be restored **byte-correct**, or whether the wake
/// must fail OPEN to a clean cold boot from the current rootfs. Returns `(Some(hash)` to restore
/// against that immutable CAS blob | `None` to cold-boot, a `wake_outcome` label`)`.
///
/// A restore is viable iff the snapshot stamps the rootfs it actually ran (present + valid-hex,
/// its CAS blob still on disk) AND its deployment version still matches the project's current
/// version — which transitively guarantees the metadata image + erofs layers it bakes by fixed
/// path are the current, coherent set. Every other case (no snapshot, missing files, a legacy
/// unstamped record, a reaped/renamed rootfs blob, or version drift) cold-boots — never a brick.
fn snapshot_restore_decision(
    snap_meta: Option<&SnapshotMeta>,
    current_version: Option<u64>,
    cas_dir: &Path,
) -> (Option<String>, &'static str) {
    let Some(m) = snap_meta else {
        return (None, "coldboot_fresh");
    };
    if !(Path::new(&m.snapshot_path).exists() && Path::new(&m.mem_file_path).exists()) {
        return (None, "skipped_snapshot_files_missing");
    }
    match m.base_rootfs_hash.as_deref() {
        None => (None, "skipped_legacy_unstamped"),
        Some(h) if !rootfs_cas::is_sha256_hex(h) => (None, "skipped_bad_hash"),
        Some(h) if !rootfs_cas::blob_path(cas_dir, h).is_file() => {
            (None, "skipped_rootfs_blob_missing")
        }
        Some(_) if m.deployment_version != current_version => (None, "skipped_version_drift"),
        Some(h) => (Some(h.to_string()), "restored"),
    }
}

async fn wake_project_inner(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<String> {
    let mut plat = platform.lock().await;

    // Throttle a project that just failed to wake: fast-fail (the proxy retries) within
    // WAKE_BACKOFF, so continuous traffic at a broken/doomed project can't spin unbounded full
    // boot attempts — each of which bumps the data-disk lease epoch and spawns Firecracker(s).
    if let Some(t) = plat.wake_failures.get(project_id)
        && t.elapsed() < WAKE_BACKOFF
    {
        drop(plat);
        anyhow::bail!("project {project_id} recently failed to wake; retry shortly");
    }

    match plat.vm_states.get(project_id) {
        Some(VmLifecycle::Hibernated) => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Waking);
        }
        Some(VmLifecycle::Waking) => {
            drop(plat);
            // A DB VM is never proxy-routed (§ security: a routing-table entry would expose it via a
            // `foo.db.jkbase.app` Host), so a concurrent waiter waits on its lifecycle and resolves
            // its IP from the allocation, not the routing table. An app VM waits for its route.
            if vm_identity::split_vm_id(project_id).1 == vm_identity::VmRole::Db {
                return wait_for_db_vm_running(project_id, &platform).await;
            }
            return wait_for_route(project_id, &platform, &routing).await;
        }
        Some(VmLifecycle::Running) => {
            if vm_identity::split_vm_id(project_id).1 == vm_identity::VmRole::Db {
                // Not in the routing table by design; the allocation is the DB VM's stable address.
                if let Ok(Some(a)) = plat.store.get_vm_allocation(project_id) {
                    return Ok(a.ip);
                }
                anyhow::bail!("DB VM {project_id} running but has no allocation");
            }
            let table = routing.read().await;
            if let Some(ip) = table.get(project_id) {
                return Ok(ip.clone());
            }
            anyhow::bail!("VM running but not in routing table");
        }
        Some(VmLifecycle::Hibernating) => {
            // Wait for hibernation to complete, then wake
            drop(plat);
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let p = platform.lock().await;
                if p.vm_states.get(project_id) == Some(&VmLifecycle::Hibernated) {
                    drop(p);
                    return Box::pin(wake_project_inner(
                        project_id,
                        platform.clone(),
                        routing,
                        domain_map,
                        shipper,
                    ))
                    .await;
                }
            }
            anyhow::bail!("timed out waiting for {project_id} to finish hibernating");
        }
        None => {
            // No lifecycle state — cold boot
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Waking);
        }
    }

    // We are now the elected wake driver in `Waking`. This guard resets that state on ANY exit
    // that doesn't reach `Running` — including a client-disconnect cancellation that DROPS this
    // future mid-boot, and every early `?` below — so the project can never get stuck `Waking`
    // (the nlnwt brick). The success path `commit()`s it.
    let waking_guard = WakingGuard::new(platform.clone(), project_id.to_string());

    // Try snapshot restore first, fall back to cold boot
    let snap_meta = plat.store.get_snapshot_meta(project_id)?;

    let alloc = match plat.store.get_vm_allocation(project_id)? {
        Some(a) => a,
        None => {
            // No allocation — need full cold boot via handle_deploy (which drives its own
            // lifecycle); drop our Waking driver state and disarm the guard so it no-ops.
            plat.vm_states.remove(project_id);
            drop(plat);
            waking_guard.commit();
            info!(project = %project_id, "no allocation, cold booting");
            let routing_clone = routing.clone();
            handle_deploy(project_id, platform, routing, domain_map, shipper).await?;
            let table = routing_clone.read().await;
            return table
                .get(project_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("cold boot completed but no route"));
        }
    };

    // The metadata image already exists from deploy (with `_layers.json` baked in);
    // wake reuses it as-is — no rebuild.
    let metadata_image_path = plat
        .data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"));

    // Decide restore-vs-cold-boot while we still hold the lock (needs the store + data_dir). A
    // restore is byte-correct ONLY if the snapshot stamps the rootfs it ACTUALLY ran (valid hex,
    // its immutable CAS blob still present) AND its deployment version still matches the project's
    // current version (so the metadata image + erofs layers it bakes by fixed path are the
    // current, coherent set). Anything else fails OPEN to a clean cold boot from the current
    // rootfs — never a brick. The reason becomes the `wake_outcome` so a post-deploy spike in
    // cold-boot fallbacks (e.g. a bad staged rootfs) is visible instead of silent.
    // Per-role/-tier identity: a dedicated DB VM (`{id}.db`) reuses its BASE project's deployment
    // for every store/content read (it has no `hosting/<id>.db/`), so the snapshot version gate
    // (and thus fast-restore) works. A co-located app VM is unchanged (base == project_id).
    let (base_pid, vm_role) = vm_identity::split_vm_id(project_id);
    let dedicated = project_is_dedicated(&plat.data_dir, base_pid);
    let current_version = plat
        .store
        .get_project(base_pid)
        .ok()
        .flatten()
        .and_then(|p| p.current_version);
    let current_rootfs_hash = plat.base_rootfs_hash.clone();
    let cas_dir = plat.data_dir.join("base-rootfs");
    let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
    let (restore_hash, nonviable_outcome) =
        snapshot_restore_decision(snap_meta.as_ref(), current_version, &cas_dir);

    // Whether this VM has a data disk, plus clones of the RWO substrate so the fence (below) can
    // run AFTER dropping the platform lock. The DB VM ALWAYS has one; a dedicated project's app VM
    // must NOT fence a disk on account of the DB (it runs in the sibling VM) — only for its own
    // volumes or a disk it already owns (e.g. a colocated→dedicated migration keeps `{id}.img`).
    let has_disk = match vm_role {
        vm_identity::VmRole::Db => true,
        vm_identity::VmRole::App => {
            check_project_has_volumes(&plat.data_dir, base_pid)
                || (!dedicated && check_project_has_database(&plat.data_dir, base_pid))
                || plat.data_disk.exists(project_id).await.unwrap_or(false)
        }
    };
    let dd = plat.data_disk.clone();
    let ls = plat.lease.clone();
    let hid = plat.host_id.clone();
    let data_dir = plat.data_dir.clone();

    // The erofs layer attach order for the cold-boot fallback (restore re-derives
    // drives from the snapshot, so this only matters when restore fails/misses). Read
    // the sidecar PAIRED with the metadata image — NOT a recompute from `live`, which
    // can drift from the (last successfully built) image's baked `_layers.json` and
    // mis-assign device letters. Absent ⇒ legacy/static image with no layers.
    let layer_paths = layer_plan::read_layer_paths(&metadata_image_path);

    // Size by ROLE: an app VM wakes at App sizing (unchanged), a dedicated DB VM (`{id}.db`) at
    // the lean DB sizing. A restore reads the size back from `SnapshotMeta`, which was stamped at
    // hibernate from this SAME `vm_size_for`, so the snapshot and restore sizes can't drift.
    let vm_size = vm_identity::vm_size_for(vm_identity::split_vm_id(project_id).1);
    let mut config = VmConfig {
        firecracker_bin: plat.firecracker_bin.clone(),
        kernel_path: plat.kernel_path.clone(),
        rootfs_path: plat.base_rootfs_path.clone(),
        metadata_image_path: Some(metadata_image_path),
        layer_paths,
        data_disk_path: None,
        vcpu_count: vm_size.vcpu_count,
        mem_size_mib: vm_size.mem_size_mib,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
        runtime_cgroup_parent: Some(PathBuf::from(RUNTIME_CGROUP_PARENT)),
    };
    let runtime_dir = plat.data_dir.join("run");
    let active_domains = plat
        .store
        .list_active_domains_for_project(project_id)
        .unwrap_or_default();
    drop(plat);

    setup_tap(&alloc.tap_device).await?;

    // Fence the data disk read-write-once BEFORE restore/boot, so the restored guest
    // — which would otherwise re-derive the RW data drive straight from the snapshot,
    // bypassing the gate — only ever writes through the exclusivity attach. The
    // restore path patches the data drive to this fenced device; refuse→cold-boot
    // (reap + retry, else error) lives in fence_data_disk. None when no data disk.
    let disk_guard = if has_disk {
        // Size from the BASE project's `_database.json` ([database].size) — the DB VM has no
        // `hosting/<id>.db/` — but fence the disk under the RENDERED id (`{id}.db.img`), its own.
        let disk_mib = data_disk_mib_for(&data_dir, base_pid);
        let g = fence_data_disk(&dd, &ls, &hid, project_id, disk_mib).await?;
        config.data_disk_path = Some(g.device());
        Some(g)
    } else {
        None
    };

    // Boot (restore-or-cold) + agent readiness, fenced by `disk_guard`. Returns the VM, the
    // rootfs hash it ACTUALLY ran (stamped into the next snapshot), and a `wake_outcome` for
    // observability. On Err we release the fenced disk + lease AWAITED (not via the Drop
    // backstop) so a re-wake/re-deploy can't race a fire-and-forget cleanup and fail transiently
    // with LeaseHeld/RwoUnsafe.
    let boot: Result<(VmInstance, String, &'static str)> = async {
        // Cold boot the CURRENT rootfs; shared by the non-viable path and the restore fallbacks.
        // Reuses the already-held `disk_guard` (config.data_disk_path) — never re-fences — so a
        // restore fallback can't self-deadlock against its own just-released lease.
        async fn cold_boot(
            project_id: &str,
            config: &VmConfig,
            runtime_dir: &Path,
            agent_ip: &str,
            current_hash: &str,
            outcome: &'static str,
        ) -> Result<(VmInstance, String, &'static str)> {
            let mut vm = VmInstance::start(project_id, config, runtime_dir).await?;
            // Synchronous-to-death on agent-wait failure, mirroring the restore arm's
            // `restored.stop().await`: a bare `?` here would drop `vm` (SIGKILL via Drop, NOT
            // awaited), so the caller's `disk_guard.release()` could `losetup -d` the data disk
            // out from under a still-dying FC. `stop()` reaps the FC before we return Err.
            if let Err(e) = wait_for_agent(agent_ip).await {
                let _ = vm.stop().await;
                return Err(e);
            }
            Ok((vm, current_hash.to_string(), outcome))
        }

        let (vm, ran_hash, outcome) = if let (Some(meta), Some(hash)) =
            (snap_meta.as_ref(), restore_hash.as_ref())
        {
            let snap_path = PathBuf::from(&meta.snapshot_path);
            let mem_path = PathBuf::from(&meta.mem_file_path);
            info!(project = %project_id, "restoring from snapshot");
            match VmInstance::restore_from_snapshot(
                project_id,
                &config,
                &runtime_dir,
                &snap_path,
                &mem_path,
            )
            .await
            {
                Ok(mut restored) => match wait_for_agent(&alloc.ip).await {
                    Ok(()) => (restored, hash.clone(), "restored"),
                    Err(e) => {
                        // Restore resumed the guest but its agent never came ready (corrupt/wedged
                        // snapshot, or a tenant pinned hostile RAM before hibernate). Synchronously
                        // REAP the restored FC (stop = SIGKILL + waitpid, so it releases the fenced
                        // data loop BEFORE the cold boot reopens it — never two Firecrackers on one
                        // RWO disk), POISON the snapshot (so subsequent wakes cold-boot directly
                        // rather than repeating this ~10s+ cycle every wake), then cold-boot the
                        // current rootfs reusing the held fence.
                        tracing::warn!(project = %project_id, error = %e, "restored VM agent not ready; reaping + poisoning snapshot + cold booting");
                        // The whole no-double-writer guarantee rests on FC1 being dead before the
                        // cold boot reopens the fenced loop — surface (don't swallow) a reap error.
                        if let Err(re) = restored.stop().await {
                            tracing::warn!(project = %project_id, error = %re, "reap of restored FC before cold boot reported an error");
                        }
                        {
                            let p = platform.lock().await;
                            let _ = p.store.remove_snapshot_meta(project_id);
                        }
                        let _ = tokio::fs::remove_dir_all(&snapshot_dir).await;
                        cold_boot(
                            project_id,
                            &config,
                            &runtime_dir,
                            &alloc.ip,
                            &current_rootfs_hash,
                            "restore_ok_agent_fail_coldboot",
                        )
                        .await?
                    }
                },
                Err(e) => {
                    tracing::warn!(project = %project_id, error = %e, "snapshot restore failed, cold booting");
                    // Defensive cleanup of a half-spawned restore FC, by EXACT socket path —
                    // never a `pkill -f firecracker.*{id}` substring (which could reap a project
                    // whose id contains this one).
                    let failed_sock = runtime_dir.join(project_id).join("firecracker.sock");
                    if failed_sock.exists() {
                        let _ = tokio::fs::remove_file(&failed_sock).await;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    cold_boot(
                        project_id,
                        &config,
                        &runtime_dir,
                        &alloc.ip,
                        &current_rootfs_hash,
                        "restore_failed_coldboot",
                    )
                    .await?
                }
            }
        } else {
            info!(project = %project_id, reason = nonviable_outcome, "cold booting (no viable snapshot)");
            cold_boot(
                project_id,
                &config,
                &runtime_dir,
                &alloc.ip,
                &current_rootfs_hash,
                nonviable_outcome,
            )
            .await?
        };

        // A restored snapshot resumes with its wall clock frozen at snapshot time, so
        // it lags by the whole hibernation; a cold boot's tsc clock is undisciplined.
        // Nudge the agent to re-read its KVM PTP reference and step CLOCK_REALTIME now,
        // so the first request after wake sees correct time instead of waiting for the
        // agent's periodic discipline tick. Best-effort — never fail a wake on this.
        resync_clock_agent(&alloc.ip).await;
        Ok((vm, ran_hash, outcome))
    }
    .await;
    let (mut vm, ran_hash, outcome) = match boot {
        Ok(t) => t,
        Err(e) => {
            // Release the fenced disk AWAITED, THEN record the failure. Ordering matters: the
            // disk is fully released before the next request can re-fence, so the retry doesn't
            // hit a transient LeaseHeld/RwoUnsafe. `waking_guard` (dropped on return) resets the
            // `Waking` state so the project isn't bricked.
            if let Some(g) = disk_guard {
                g.release().await;
            }
            let mut p = platform.lock().await;
            p.wake_failures
                .insert(project_id.to_string(), std::time::Instant::now());
            drop(p);
            return Err(e);
        }
    };

    let mut plat = platform.lock().await;

    // Re-validate the project still exists before committing the VM. handle_teardown
    // waits out our `Waking` state, so a delete can't race the body above — but a
    // delete that landed BEFORE we set Waking would leave us booting a ghost. If so,
    // abort: SIGKILL the FC (drop `vm`) FIRST, then release the guard AWAITED — not via
    // the fire-and-forget Drop backstop, whose deferred detach could later `losetup -d`
    // a recreated same-slug VM's live device. Drop the platform lock first so the
    // release's losetup I/O isn't held under the mutex.
    if plat.store.get_project(project_id).ok().flatten().is_none() {
        plat.vm_states.remove(project_id);
        plat.vm_rootfs_hashes.remove(project_id);
        drop(plat);
        let _ = vm.stop().await; // synchronous-to-death before detaching the disk it maps
        if let Some(g) = disk_guard {
            g.release().await; // detach + lease release inline; disarms so Drop no-ops
        }
        // No handoff was written this wake (that happens at commit, below), but a stale one
        // from a prior incarnation must not survive a delete-during-wake — remove defensively.
        handoff::remove(&runtime_dir, project_id);
        anyhow::bail!("project {project_id} was deleted during wake; aborting");
    }

    // Record Firecracker's PID as the data-disk writer (FATAL — see the deploy commit), capture
    // the fence facts for the handoff, then DISARM the guard and hold the token for the VM's
    // lifetime (released on hibernate/stop/teardown).
    let fc_pid = vm.pid();
    let (loop_dev, lease_epoch) = if let Some(guard) = disk_guard {
        if let Some(pid) = fc_pid {
            let dd2 = plat.data_disk.clone();
            if let Err(e) = dd2.set_writer_pid(project_id, guard.token(), pid).await {
                drop(plat);
                // Kill the FC synchronously-to-death BEFORE releasing (detaching) the disk it maps.
                let _ = vm.stop().await;
                guard.release().await;
                let mut p = platform.lock().await;
                p.wake_failures
                    .insert(project_id.to_string(), std::time::Instant::now());
                drop(p);
                return Err(anyhow::anyhow!("commit set_writer_pid {project_id}: {e}"));
            }
        }
        let dev = guard.device().to_string_lossy().into_owned();
        let epoch = guard.token().epoch;
        plat.disk_tokens
            .insert(project_id.to_string(), guard.disarm());
        (Some(dev), Some(epoch))
    } else {
        (None, None)
    };
    plat.vms.insert(project_id.to_string(), vm);
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Running);
    // Track the rootfs this VM actually ran so the NEXT hibernate stamps the truthful hash
    // (a restored VM ran the OLD blob, not `current`). Clear any prior wake-failure throttle.
    plat.vm_rootfs_hashes
        .insert(project_id.to_string(), ran_hash.clone());
    plat.wake_failures.remove(project_id);

    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Active;
        plat.store.update_project(&proj)?;
    }
    drop(plat);
    waking_guard.commit();

    // Persist the re-adoption record (mirrors the deploy commit; removed on every teardown).
    write_handoff_record(
        &runtime_dir,
        project_id,
        fc_pid,
        &alloc,
        loop_dev,
        lease_epoch,
        ran_hash,
        current_version,
    );

    // A DB VM is reached host-mediated only; it must NOT enter the routing table (a `foo.db` entry
    // would be reachable via a `foo.db.jkbase.app` Host). Its address is the allocation IP, returned
    // below. App VMs register their fast-path route + domains as before.
    if vm_identity::split_vm_id(project_id).1 != vm_identity::VmRole::Db {
        register_active_routes(
            &routing,
            &domain_map,
            &active_domains,
            project_id,
            &alloc.ip,
        )
        .await;
    }

    info!(project = %project_id, ip = %alloc.ip, wake_outcome = outcome, "VM awake");
    Ok(alloc.ip)
}

/// A non-driver request waits here for the elected wake driver to publish the project's route.
/// It also fast-fails the moment the driver leaves `Waking`/`Running` WITHOUT a route — i.e. the
/// driver failed and reset the state — instead of hanging the full 30s, so the proxy returns
/// Retry-After promptly and a fresh request re-drives a boot. (`Running` is tolerated: there's a
/// brief window where the driver set `Running` but hasn't registered the route yet.)
async fn wait_for_route(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
) -> Result<String> {
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let table = routing.read().await;
            if let Some(ip) = table.get(project_id) {
                return Ok(ip.clone());
            }
        }
        let p = platform.lock().await;
        match p.vm_states.get(project_id) {
            Some(VmLifecycle::Waking) | Some(VmLifecycle::Running) => {}
            _ => {
                drop(p);
                anyhow::bail!("wake of {project_id} did not complete; retry");
            }
        }
    }
    anyhow::bail!("timed out waiting for {project_id} to wake");
}

/// The DB-VM analogue of [`wait_for_route`]: a non-driver DB-reach request waits for the elected
/// wake driver to bring the DB VM to `Running`, then resolves its IP from the allocation (the DB VM
/// is never in the routing table — see the `wake_project_inner` commit). Fast-fails the moment the
/// driver leaves `Waking`/`Running` without success, so the reach caller retries promptly.
async fn wait_for_db_vm_running(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
) -> Result<String> {
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let p = platform.lock().await;
        match p.vm_states.get(project_id) {
            Some(VmLifecycle::Running) => {
                if let Ok(Some(a)) = p.store.get_vm_allocation(project_id) {
                    return Ok(a.ip);
                }
                drop(p);
                anyhow::bail!("DB VM {project_id} running but has no allocation");
            }
            Some(VmLifecycle::Waking) => {}
            _ => {
                drop(p);
                anyhow::bail!("wake of DB VM {project_id} did not complete; retry");
            }
        }
    }
    anyhow::bail!("timed out waiting for DB VM {project_id} to wake");
}

async fn idle_detection_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    activity: ActivityTracker,
    idle_timeout: Duration,
    shipper: Arc<LogShipper>,
    db_registry: Option<Arc<jkbase_proxy::db_relay::DbRelayRegistry>>,
) {
    let check_interval = Duration::from_secs(60);

    loop {
        tokio::time::sleep(check_interval).await;

        // Seed a baseline for any Running VM the proxy hasn't tracked. Activity is
        // only recorded on proxy requests, so a project that receives none — e.g. a
        // cron-only function project, woken host->agent — would otherwise never be a
        // hibernation candidate and never scale to zero. Seeding `now` gives it an
        // idle clock that ages out after `idle_timeout` of no further activity.
        {
            let running: Vec<String> = {
                let plat = platform.lock().await;
                plat.vm_states
                    .iter()
                    .filter(|(_, s)| **s == VmLifecycle::Running)
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            let mut tracker = activity.write().await;
            let now = Instant::now();
            for id in running {
                tracker.entry(id).or_insert(now);
            }
        }

        let candidates: Vec<String> = {
            let tracker = activity.read().await;
            let now = Instant::now();
            tracker
                .iter()
                .filter(|(_, last)| now.duration_since(**last) > idle_timeout)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for project_id in candidates {
            let should_hibernate = {
                let plat = platform.lock().await;
                plat.vm_states.get(&project_id) == Some(&VmLifecycle::Running)
            }
            // §5: never hibernate a project with a LIVE managed-DB relay — a realtime
            // subscription can be open but byte-silent, so last-byte activity alone would
            // scale it to zero out from under the connection. Relays are keyed by the BASE
            // project, so a dedicated DB VM (`{id}.db`) candidate is kept warm by the same count.
            && db_registry
                .as_ref()
                .map(|r| r.conn_count(vm_identity::base_project_id(&project_id)) == 0)
                .unwrap_or(true);

            if should_hibernate {
                info!(project = %project_id, "idle timeout, hibernating");
                if let Err(e) = hibernate_project(
                    &project_id,
                    platform.clone(),
                    routing.clone(),
                    shipper.clone(),
                    db_registry.as_ref(),
                )
                .await
                {
                    tracing::error!(project = %project_id, error = %e, "failed to hibernate");
                }

                let mut tracker = activity.write().await;
                tracker.remove(&project_id);
            }
        }
    }
}

/// Periodically pull new guest logs from every running VM into the persistent
/// log store so they survive hibernation, restart, and crashes.
async fn log_shipper_loop(platform: Arc<Mutex<PlatformState>>, shipper: Arc<LogShipper>) {
    loop {
        tokio::time::sleep(log_shipper::POLL_INTERVAL).await;

        let targets: Vec<(String, String)> = {
            let plat = platform.lock().await;
            plat.vm_states
                .iter()
                .filter(|(_, s)| **s == VmLifecycle::Running)
                .filter_map(|(id, _)| {
                    plat.store
                        .get_vm_allocation(id)
                        .ok()
                        .flatten()
                        .map(|a| (id.clone(), a.ip))
                })
                .collect()
        };

        for (project_id, ip) in targets {
            shipper.ship(&project_id, &ip).await;
        }
    }
}

// ===================================================================
// Managed-DB backups — host-relay pull + host-push restore ([RB*]).
// ===================================================================

/// Hard cap on a backup tar the agent may relay + the host stages ([RB3]). The tar is roughly
/// the DB's on-disk size (bounded by the RWO data disk); this ceiling fails a runaway/garbage
/// stream fast, well before it could exhaust host disk under the concurrency bound below.
const MAX_DB_BACKUP_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Retained COMPLETE backups per project (retention bound; the store cap
/// [`Store::MAX_DB_BACKUPS_PER_PROJECT`] is the backstop).
const DB_BACKUP_KEEP: usize = 14;
/// Retained Failed rows per project — enough for the nightly loop's failure backoff to see the
/// last failure time (so a persistently-failing project retries once per interval, not per tick),
/// and for the owner to see recent failures, without letting Failed rows wedge the cap.
const DB_BACKUP_FAILED_KEEP: usize = 3;
/// Nightly-loop cadence + the age at which a managed DB is due for an automatic backup.
const DB_BACKUP_TICK: Duration = Duration::from_secs(30 * 60);
const DB_BACKUP_INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;
/// Max concurrent backup PULLS across the WHOLE host (on-demand AND nightly share this), so a
/// tenant spamming on-demand backups — or the nightly fan-out — can't stage many full-DB tars
/// into off-quota host disk at once (adversarial-review finding).
const DB_BACKUP_MAX_CONCURRENT: usize = 2;

/// Everything the backup/restore executors need. All handles are cheap Arc clones.
#[derive(Clone)]
struct DbBackupCtx {
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domains: DomainMap,
    shipper: Arc<LogShipper>,
    store: Store,
    backups: Arc<db_backup_store::BackupStore>,
    /// Host-wide concurrency bound shared by on-demand + nightly backups.
    backup_sem: Arc<tokio::sync::Semaphore>,
    /// Per-project in-flight restore guard so two overlapping restores can't corrupt the shared
    /// staging dir (adversarial-review finding).
    restoring: Arc<std::sync::Mutex<HashSet<String>>>,
}

/// Client-side HTTP/1.1 `Upgrade` to `<vm_ip>:80{path}` presenting the reach-plane splice
/// secret (mirrors the proxy edge's `connect_agent`). On `101` returns the raw upgraded stream.
/// Used by the backup PULL and restore PUSH executors — the DB stays loopback-only, the agent
/// is the sole mediator.
async fn connect_agent_db_upgrade(
    vm_ip: &str,
    path: &str,
    splice_secret: &str,
    proto: &str,
) -> Result<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>> {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let stream = tokio::net::TcpStream::connect((vm_ip, 80u16))
        .await
        .context("connect agent")?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("agent handshake")?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", vm_ip)
        .header("connection", "upgrade")
        .header("upgrade", proto)
        .header("x-jkbase-db-secret", splice_secret)
        .body(Full::<Bytes>::new(Bytes::new()))
        .context("agent req build")?;
    let mut resp = sender.send_request(req).await.context("agent send")?;
    if resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        anyhow::bail!("agent refused {path} upgrade ({})", resp.status());
    }
    let upgraded = hyper::upgrade::on(&mut resp)
        .await
        .context("agent upgrade")?;
    Ok(hyper_util::rt::TokioIo::new(upgraded))
}

/// Pull a backup: wake the VM, relay the tar out of the agent, validate + store it, return
/// (size, manifest summary). The admin token never leaves the guest — the agent authorizes the
/// loopback `/admin/backup/stream` and relays only opaque tar bytes.
async fn do_db_backup(
    ctx: &DbBackupCtx,
    project_id: &str,
    backup_id: &str,
) -> Result<(u64, String)> {
    let secret = ctx
        .store
        .get_db_splice_secret(project_id)?
        .ok_or_else(|| anyhow::anyhow!("no reach-plane secret (managed DB not deployed?)"))?;
    let ip = wake_db_reach(
        project_id,
        ctx.platform.clone(),
        ctx.routing.clone(),
        ctx.domains.clone(),
        ctx.shipper.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("wake project: {e:?}"))?;
    let mut upgraded =
        connect_agent_db_upgrade(&ip, "/_jkbase/db/backup", &secret, "jkbase-db-backup").await?;
    let staged = ctx
        .backups
        .stage(project_id, backup_id, &mut upgraded, MAX_DB_BACKUP_BYTES)
        .await?;
    let size = staged.size_bytes;
    match ctx.backups.validate(&staged).await {
        Ok(summary) => {
            ctx.backups.commit(staged).await?;
            Ok((size, summary))
        }
        Err(e) => {
            ctx.backups.discard(staged).await;
            Err(e)
        }
    }
}

/// Max bytes the host buffers from the in-VM DB's HTTP response before relaying to the console.
/// The engine's query governor caps result ROWS; this bounds the host relay against a
/// pathological payload. Schema/status responses are tiny.
const MAX_DB_QUERY_RESP_BYTES: usize = 16 * 1024 * 1024;
/// Outer deadline on one console DB request (agent connect + engine round-trip). The engine
/// governor caps per-query wall-clock; this is the network-level backstop.
const DB_QUERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Send one PLAIN (non-upgrade) request to the agent's eth0 DB-proxy seam and read the bounded
/// JSON response. The DB stays loopback-only; the agent forwards only to rhypedb's OPEN plane
/// (`/query|/schema|/status`, never `/admin/*`). Returns the engine's verbatim status + body.
async fn agent_db_request(
    vm_ip: &str,
    path: &str,
    method: &str,
    splice_secret: &str,
    body: Vec<u8>,
) -> Result<jkbase_control::api::DbQueryResult> {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    let stream = tokio::net::TcpStream::connect((vm_ip, 80u16))
        .await
        .context("connect agent")?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("agent handshake")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", vm_ip)
        .header("content-type", "application/json")
        .header("x-jkbase-db-secret", splice_secret)
        .body(Full::<Bytes>::new(Bytes::from(body)))
        .context("agent req build")?;
    let resp = sender.send_request(req).await.context("agent send")?;
    let status = resp.status().as_u16();
    let collected = Limited::new(resp.into_body(), MAX_DB_QUERY_RESP_BYTES)
        .collect()
        .await
        .map_err(|_| anyhow::anyhow!("db response too large (> {MAX_DB_QUERY_RESP_BYTES} bytes)"))?;
    Ok(jkbase_control::api::DbQueryResult {
        status,
        body: collected.to_bytes().to_vec(),
    })
}

/// Proxy one console DB op to the project's managed DB (wired to `state.db_query_callback`):
/// resolve the reach-plane splice secret, wake the VM, and forward to the agent's eth0 seam.
/// `Err(String)` is a transport/wake failure; the engine's own errors ride back in the `Ok`
/// result's status (e.g. 400 for a parse/governor error).
#[allow(clippy::too_many_arguments)]
async fn do_db_query(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domains: DomainMap,
    shipper: Arc<LogShipper>,
    store: Store,
    project_id: String,
    op: jkbase_control::api::DbQueryOp,
) -> Result<jkbase_control::api::DbQueryResult, String> {
    use jkbase_control::api::DbQueryOp;
    let secret = store
        .get_db_splice_secret(&project_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no managed database deployed for this project".to_string())?;
    let ip = wake_db_reach(&project_id, platform, routing, domains, shipper)
        .await
        .map_err(|e| format!("wake project: {e:?}"))?;
    let (path, method, body): (&str, &str, Vec<u8>) = match &op {
        DbQueryOp::Query(q) => (
            "/_jkbase/db/query",
            "POST",
            serde_json::to_vec(&serde_json::json!({ "query": q })).unwrap_or_default(),
        ),
        DbQueryOp::Schema => ("/_jkbase/db/schema", "GET", Vec::new()),
        DbQueryOp::Status => ("/_jkbase/db/status", "GET", Vec::new()),
    };
    tokio::time::timeout(
        DB_QUERY_DEADLINE,
        agent_db_request(&ip, path, method, &secret, body),
    )
    .await
    .map_err(|_| "database request timed out".to_string())?
    .map_err(|e| format!("{e:#}"))
}

/// Run one backup end-to-end (spawned by the on-demand callback + the nightly loop): acquire the
/// host-wide concurrency permit, execute, record the catalog outcome, and prune the catalog —
/// on EITHER outcome, so failed backups can never wedge the per-project row cap
/// (adversarial-review finding).
async fn run_db_backup(ctx: DbBackupCtx, project_id: String, backup_id: String) {
    // Bound host-wide concurrent pulls (shared by on-demand + nightly). A closed semaphore never
    // happens (we never close it); on the impossible error, fail the backup rather than run
    // unbounded.
    let _permit = match ctx.backup_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            let _ = ctx.store.set_db_backup_status(
                &project_id,
                &backup_id,
                jkbase_control::store::BackupStatus::Failed,
                0,
                "",
            );
            return;
        }
    };
    match do_db_backup(&ctx, &project_id, &backup_id).await {
        Ok((size, summary)) => {
            let _ = ctx.store.set_db_backup_status(
                &project_id,
                &backup_id,
                jkbase_control::store::BackupStatus::Complete,
                size,
                &summary,
            );
            info!(project = %project_id, backup = %backup_id, size, "managed-db backup complete");
        }
        Err(e) => {
            warn!(project = %project_id, backup = %backup_id, error = %e, "managed-db backup failed");
            let _ = ctx.store.set_db_backup_status(
                &project_id,
                &backup_id,
                jkbase_control::store::BackupStatus::Failed,
                0,
                "",
            );
            let _ = ctx.backups.delete(&project_id, &backup_id).await;
        }
    }
    // Prune on EVERY outcome so a run of failures can't fill the per-project row cap and
    // permanently disable backups for the project.
    prune_db_backups(&ctx, &project_id).await;
}

/// Push a restore: resolve the (Complete) backup, wake the VM, and stream the tar to the agent,
/// which untars it in-guest and respawns rhypedb. Reads back the agent's `ok`/`err:` line.
async fn do_db_restore(ctx: &DbBackupCtx, project_id: &str, backup_id: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Serialize restores per project: two overlapping restores share the same in-guest staging
    // paths and would corrupt each other (adversarial-review finding). RAII-remove on return.
    struct RestoreGuard(Arc<std::sync::Mutex<HashSet<String>>>, String);
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            self.0.lock().unwrap().remove(&self.1);
        }
    }
    {
        let mut set = ctx.restoring.lock().unwrap();
        if !set.insert(project_id.to_string()) {
            anyhow::bail!("a restore is already in progress for this project");
        }
    }
    let _guard = RestoreGuard(ctx.restoring.clone(), project_id.to_string());

    let backup = ctx
        .store
        .get_db_backup(project_id, backup_id)?
        .ok_or_else(|| anyhow::anyhow!("backup not found"))?;
    if backup.status != jkbase_control::store::BackupStatus::Complete {
        anyhow::bail!(
            "backup {backup_id} is not restorable (status {:?})",
            backup.status
        );
    }
    let secret = ctx
        .store
        .get_db_splice_secret(project_id)?
        .ok_or_else(|| anyhow::anyhow!("no reach-plane secret"))?;
    let ip = wake_db_reach(
        project_id,
        ctx.platform.clone(),
        ctx.routing.clone(),
        ctx.domains.clone(),
        ctx.shipper.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("wake project: {e:?}"))?;
    let mut tar = ctx.backups.open_read(project_id, backup_id).await?;
    let mut upgraded =
        connect_agent_db_upgrade(&ip, "/_jkbase/db/restore", &secret, "jkbase-db-restore").await?;
    tokio::io::copy(&mut tar, &mut upgraded)
        .await
        .context("stream backup to agent")?;
    // Half-close the write half → the agent sees a clean EOF for the tar, processes it, then
    // writes its status line back on the still-open read half.
    upgraded
        .shutdown()
        .await
        .context("half-close restore push")?;
    let mut status = String::new();
    upgraded
        .read_to_string(&mut status)
        .await
        .context("read restore status")?;
    let status = status.trim();
    if status == "ok" {
        Ok(())
    } else {
        anyhow::bail!(
            "agent restore: {}",
            if status.is_empty() {
                "no response"
            } else {
                status
            }
        )
    }
}

async fn run_db_restore(ctx: DbBackupCtx, project_id: String, backup_id: String) {
    match do_db_restore(&ctx, &project_id, &backup_id).await {
        Ok(()) => info!(project = %project_id, backup = %backup_id, "managed-db restore complete"),
        Err(e) => {
            warn!(project = %project_id, backup = %backup_id, error = %e, "managed-db restore failed")
        }
    }
}

/// Bound the per-project catalog: keep the newest [`DB_BACKUP_KEEP`] COMPLETE backups + any fresh
/// (in-flight) Pending row, and delete everything else — all Failed rows, stale Pending rows
/// (a crashed backup), and Complete rows beyond the retention bound — along with their blobs. Run
/// after every attempt, so a run of failures can't wedge the row cap and disable backups.
async fn prune_db_backups(ctx: &DbBackupCtx, project_id: &str) {
    let backups = match ctx.store.list_db_backups(project_id) {
        Ok(b) => b, // newest-first
        Err(_) => return,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut kept_complete = 0usize;
    let mut kept_failed = 0usize;
    for b in backups {
        use jkbase_control::store::BackupStatus;
        let keep = match b.status {
            BackupStatus::Complete => {
                kept_complete += 1;
                kept_complete <= DB_BACKUP_KEEP
            }
            // A fresh Pending is an in-flight backup — never delete it out from under a running
            // pull; a stale one (crashed) is swept.
            BackupStatus::Pending => {
                now_ms.saturating_sub(b.created_at_ms)
                    < jkbase_control::store::Store::BACKUP_STALE_MS
            }
            // Keep the newest few Failed rows so the nightly backoff can see the last failure;
            // drop the rest so they can't wedge the cap.
            BackupStatus::Failed => {
                kept_failed += 1;
                kept_failed <= DB_BACKUP_FAILED_KEEP
            }
        };
        if !keep {
            let _ = ctx.backups.delete(project_id, &b.backup_id).await;
            let _ = ctx.store.delete_db_backup(project_id, &b.backup_id);
        }
    }
}

/// Nightly automatic backups ([RB12]): each tick, back up every managed-DB project whose newest
/// TERMINAL (Complete or Failed) backup is older than [`DB_BACKUP_INTERVAL_MS`] (or has none),
/// skipping any project with a backup already in flight. Concurrency is bounded inside
/// `run_db_backup` by the host-wide `backup_sem` (shared with on-demand). Considering Failed too
/// gives a failing project a full interval of backoff instead of re-firing every 30-min tick.
/// Single-host owns all projects today (mirrors `scheduler_loop`); a future HA layer gates on
/// ownership.
async fn db_backup_nightly_loop(ctx: DbBackupCtx) {
    loop {
        tokio::time::sleep(DB_BACKUP_TICK).await;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let projects = match ctx.store.list_projects() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "nightly db-backup: could not list projects");
                continue;
            }
        };
        for proj in projects {
            let pid = proj.id.clone();
            // A managed DB that has been deployed has a minted admin token.
            if !matches!(ctx.store.get_db_admin_token(&pid), Ok(Some(_))) {
                continue;
            }
            // Skip if a backup is already in flight (single-flight, shared with on-demand).
            if matches!(ctx.store.has_active_backup(&pid), Ok(true)) {
                continue;
            }
            let due = match ctx.store.list_db_backups(&pid) {
                Ok(list) => match list.iter().find(|b| {
                    matches!(
                        b.status,
                        jkbase_control::store::BackupStatus::Complete
                            | jkbase_control::store::BackupStatus::Failed
                    )
                }) {
                    Some(b) => now_ms.saturating_sub(b.created_at_ms) >= DB_BACKUP_INTERVAL_MS,
                    None => true,
                },
                Err(_) => false,
            };
            if !due {
                continue;
            }
            let tenant_id = proj.tenant_id.clone().unwrap_or_default();
            let row = match ctx.store.create_db_backup_auto(&pid, &tenant_id) {
                Ok(r) => r,
                Err(e) => {
                    warn!(project = %pid, error = %e, "nightly db-backup: could not record row");
                    continue;
                }
            };
            // run_db_backup acquires the shared concurrency permit itself; spawn and move on.
            tokio::spawn(run_db_backup(ctx.clone(), pid, row.backup_id.clone()));
        }
    }
}

async fn setup_tap(tap_name: &str) -> Result<()> {
    let exists = tokio::process::Command::new("ip")
        .args(["link", "show", tap_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?
        .success();

    if !exists {
        run_cmd("ip", &["tuntap", "add", "dev", tap_name, "mode", "tap"]).await?;
        info!(tap_name, "tap device created");
    }

    // (Re)assert master + isolation + IPv6-off UNCONDITIONALLY — not only on fresh
    // creation. A TAP that survives a restart/wake, or one created by an older binary
    // (pre-isolation), must be brought to the current security posture rather than left
    // at whatever it had; all of these are idempotent. Without this, every project
    // already running when this fix first deploys would stay un-isolated.
    run_cmd("ip", &["link", "set", tap_name, "master", "jkbr0"]).await?;
    // Bridge port isolation: isolated ports cannot forward to each other at L2, so one
    // tenant's runtime VM can't reach another's at 172.16.0.x on the shared bridge (the
    // gateway/uplink — a non-isolated port — stays reachable, so egress is unaffected).
    // Fail-closed: if the kernel can't apply it, the deploy fails rather than running a
    // VM with cross-tenant L2 reachability. Port isolation blocks cross-tenant *reach*;
    // the ebtables L2 source-guard installed below closes *spoofing* (the other half).
    run_cmd(
        "ip",
        &[
            "link",
            "set",
            "dev",
            tap_name,
            "type",
            "bridge_slave",
            "isolated",
            "on",
        ],
    )
    .await?;
    // Disable IPv6 on the TAP so a guest can't pivot to metadata/host over v6 around the
    // IPv4-only bridge SSRF DROP (defense in depth — runtime guests also boot
    // ipv6.disable=1). Best-effort: the load-bearing guard is the guest-side disable.
    let _ = run_cmd(
        "sysctl",
        &["-w", &format!("net.ipv6.conf.{tap_name}.disable_ipv6=1")],
    )
    .await;
    run_cmd("ip", &["link", "set", tap_name, "up"]).await?;

    // L2 source-guard (anti IP/MAC spoof): pin this TAP to its deterministic {MAC, IPv4
    // src, ARP src}. Port isolation (above) blocks cross-tenant *reach*; this closes
    // *spoofing* — without it a hostile guest can emit frames bearing another project's
    // source IP, poisoning per-project egress attribution + the bandwidth meter (and any
    // future `-s`-scoped rule). Mirrors the build bridge's JKBUILD_SG. Fail-closed, to
    // match the port-isolation posture above. {ip,mac} derive from the TAP name via the
    // same deterministic octet map as allocate_ip, so setup_tap needs no new args.
    if let Some((ip, mac)) = tap_identity(tap_name) {
        install_tap_source_guard(tap_name, &ip, &mac)
            .await
            .context("install runtime L2 source-guard (is ebtables installed?)")?;
    } else {
        anyhow::bail!(
            "tap {tap_name:?} is outside the tapN scheme — refusing to boot without its L2 source-guard"
        );
    }

    Ok(())
}

async fn teardown_tap(tap_name: &str) -> Result<()> {
    let exists = tokio::process::Command::new("ip")
        .args(["link", "show", tap_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?
        .success();

    if exists {
        run_cmd("ip", &["link", "delete", tap_name]).await?;
        info!(tap_name, "tap device removed");
    }

    Ok(())
}

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new(cmd)
        .args(args)
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("{} {:?} failed with {}", cmd, args, status);
    }
    Ok(())
}

/// The ebtables (L2/bridge filter) chain holding the runtime per-TAP source-guard rules.
const RUNTIME_SOURCE_GUARD_CHAIN: &str = "JKRUN_SG";

/// The deterministic identity of a runtime VM slot, keyed by its last IP octet (2..=254).
/// `PlatformState::allocate_ip` and `tap_identity` BOTH go through this single formula, so
/// the L2 source-guard can never pin a different {ip,mac} than the VM was actually given.
fn slot_identity(octet: u8) -> (String, String, String) {
    (
        format!("tap{}", octet - 2),
        format!("172.16.0.{octet}"),
        format!("AA:FC:00:00:00:{octet:02X}"),
    )
}

/// Derive a runtime TAP's deterministic `(ipv4, mac)` from its name (the inverse of the
/// `slot_identity` map). Because that map is a bijection, a TAP's source-guard rules are
/// stable across project churn — so they need no teardown (a deleted TAP's rules match
/// nothing; a reused octet gets the identical {ip,mac}).
fn tap_identity(tap: &str) -> Option<(String, String)> {
    let n: u16 = tap.strip_prefix("tap")?.parse().ok()?;
    let octet = n.checked_add(2)?;
    if octet > 254 {
        return None;
    }
    let (_, ip, mac) = slot_identity(octet as u8);
    Some((ip, mac))
}

/// Serializes all runtime ebtables edits. The nf_tables ebtables backend does a whole-
/// ruleset read-modify-write per call, so concurrent project wakes (proxy-driven, routine)
/// clobber each other (verified: 20 concurrent `-A` → only 2 land; `--concurrent` does not
/// help). Held across the chain-ensure + per-TAP rule installs.
static RUNTIME_EBTABLES_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();
fn runtime_ebtables_lock() -> &'static tokio::sync::Mutex<()> {
    RUNTIME_EBTABLES_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Ensure the runtime source-guard chain exists and is hooked into the L2 INPUT (frames
/// to the gateway/host) + FORWARD (VM↔VM, already port-isolated — defense in depth) paths.
/// Do NOT flush: unlike the build guard (a static pool repopulated at startup), runtime
/// TAPs are pinned lazily in `setup_tap`, so flushing here would drop active TAPs' rules
/// until their next wake. Idempotent: `-N` ignores "exists", the hook is `-C`-guarded.
/// Rules match `-i tap*`, so build-bridge (`jkbld*`) frames fall straight through.
async fn ensure_runtime_source_guard_chain() -> Result<()> {
    let _ = run_ebtables(&["-t", "filter", "-N", RUNTIME_SOURCE_GUARD_CHAIN]).await;
    for hook in ["INPUT", "FORWARD"] {
        if !ebtables_ok(&[
            "-t",
            "filter",
            "--check",
            hook,
            "-j",
            RUNTIME_SOURCE_GUARD_CHAIN,
        ])
        .await
        {
            run_ebtables(&["-t", "filter", "-I", hook, "-j", RUNTIME_SOURCE_GUARD_CHAIN])
                .await
                .with_context(|| format!("hook runtime source-guard into ebtables {hook}"))?;
        }
    }
    Ok(())
}

/// Install the per-TAP L2 source-guard: DROP any frame on `tap` not bearing this slot's
/// source MAC / IPv4 source / ARP source, plus DROP 802.1Q VLAN-tagged frames outright (a
/// tagged frame's outer ethertype is 0x8100, so `-p IPv4`/`-p ARP` would skip the source
/// pins). Idempotent (`-C` before `-A`), so re-asserting a surviving TAP on wake is a
/// no-op. Mirrors `build_orchestrator::ensure_source_guard` rule-for-rule.
async fn install_tap_source_guard(tap: &str, ip: &str, mac: &str) -> Result<()> {
    let _guard = runtime_ebtables_lock().lock().await;
    ensure_runtime_source_guard_chain().await?;
    let rules: [Vec<&str>; 4] = [
        vec!["-i", tap, "-p", "802_1Q", "-j", "DROP"],
        vec!["-i", tap, "!", "-s", mac, "-j", "DROP"],
        vec!["-i", tap, "-p", "IPv4", "!", "--ip-src", ip, "-j", "DROP"],
        vec![
            "-i",
            tap,
            "-p",
            "ARP",
            "!",
            "--arp-ip-src",
            ip,
            "-j",
            "DROP",
        ],
    ];
    for r in &rules {
        let mut check = vec!["-t", "filter", "--check", RUNTIME_SOURCE_GUARD_CHAIN];
        check.extend_from_slice(r);
        if !ebtables_ok(&check).await {
            let mut add = vec!["-t", "filter", "-A", RUNTIME_SOURCE_GUARD_CHAIN];
            add.extend_from_slice(r);
            run_ebtables(&add).await?;
        }
    }
    Ok(())
}

/// Run an ebtables command, erroring on failure (fail-closed). Distinct from the build
/// orchestrator's own copy so the runtime guard does not couple to that module.
async fn run_ebtables(args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new("ebtables")
        .args(args)
        .status()
        .await
        .context("spawn ebtables")?;
    if !status.success() {
        anyhow::bail!("ebtables {args:?} failed: {status}");
    }
    Ok(())
}

/// True iff the ebtables command succeeds — for `-C` existence checks; never errors.
async fn ebtables_ok(args: &[&str]) -> bool {
    tokio::process::Command::new("ebtables")
        .args(args)
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod source_guard_tests {
    use super::{slot_identity, tap_identity};

    #[test]
    fn tap_identity_inverts_slot_identity_over_all_octets() {
        // The two octet maps live ~1900 lines apart; this binds them so the source-guard
        // can never pin a different {ip,mac} than allocate_ip handed the VM.
        for octet in 2u8..=254 {
            let (tap, ip, mac) = slot_identity(octet);
            assert_eq!(
                tap_identity(&tap),
                Some((ip, mac)),
                "tap_identity must invert slot_identity for octet {octet}"
            );
        }
    }

    #[test]
    fn tap_identity_rejects_out_of_range_and_malformed() {
        assert_eq!(tap_identity("tap253"), None); // octet 255 > 254
        assert_eq!(tap_identity("eth0"), None);
        assert_eq!(tap_identity("tapX"), None);
        assert_eq!(tap_identity("tap"), None);
    }
}

/// Rename any legacy `{id}.ext4` data disks to LocalLoop's `{id}.img` convention so
/// existing per-project data is picked up by the loop-device-backed provider. File
/// contents are untouched; subsequent boots find no `.ext4` and no-op.
async fn migrate_legacy_data_disks(dir: &Path) -> Result<()> {
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()), // dir absent → nothing to migrate
    };
    while let Some(entry) = rd.next_entry().await? {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("ext4") {
            let img = p.with_extension("img");
            if !tokio::fs::try_exists(&img).await.unwrap_or(false) {
                info!(from = %p.display(), to = %img.display(), "migrating legacy data disk to .img");
                tokio::fs::rename(&p, &img).await?;
            } else {
                // Both exist: the loop-managed `.img` is authoritative (storage accounting
                // and the provider already use it), so the legacy `.ext4` is a dead orphan.
                // Reap it BEST-EFFORT — a stuck orphan (immutable attr / read-only FS) must
                // never abort node startup (this runs under `?` in main, before serving);
                // log and leave it for the next boot rather than bricking the whole host.
                warn!(path = %p.display(), "legacy .ext4 data disk shadowed by an existing .img; reaping the orphan");
                if let Err(e) = tokio::fs::remove_file(&p).await {
                    warn!(path = %p.display(), error = %e, "failed to reap shadowed legacy .ext4 orphan; leaving in place");
                }
            }
        }
    }
    Ok(())
}

/// Reap any Firecracker process still running for `project_id` (best-effort).
async fn reap_firecracker(project_id: &str) {
    let _ = tokio::process::Command::new("pkill")
        // Anchor to the EXACT api-sock path segment (/<id>/firecracker.sock), not an unanchored
        // `firecracker.*<id>` substring of the whole cmdline: project ids are user-chosen slugs
        // ([a-z0-9-]), and every FC cmdline carries `--api-sock .../run/<id>/firecracker.sock`, so
        // a short id like `a` matched as a substring would SIGKILL every tenant's FC host-wide
        // (cross-tenant kill). `<id>` is a single path segment bounded by `/`, so `/a/` never
        // matches `/ab/`. A rendered DB VM id (`{id}.db`) carries a `.` — itself an ERE
        // metacharacter — so `fc_sock_pkill_pattern` escapes every `.` in the id (else `foo.db`
        // would match `/fooadb/…` and cross-tenant-kill project `fooadb`).
        .args(["-f", &vm_identity::fc_sock_pkill_pattern(project_id)])
        .status()
        .await;
}

/// RAII hold on a fenced data disk for a VM's **boot window**. [`fence_data_disk`]
/// returns it ARMED (lease acquired + disk attached). If it is dropped before
/// [`disarm`](DiskLeaseGuard::disarm) — i.e. the boot failed on any `?`
/// (`VmInstance::start`/`restore_from_snapshot`/`wait_for_agent`) — it asynchronously
/// detaches the disk + releases the lease, so a failed boot can NEVER leak the lease
/// (a leak would brick the project with `LeaseHeld`/`RwoUnsafe` until the server
/// restarts). On success the caller `disarm`s it and stores the token in `disk_tokens`
/// for teardown-time release.
struct DiskLeaseGuard {
    data_disk: Arc<dyn DataDiskProvider>,
    lease: Arc<dyn Lease>,
    project_id: String,
    token: FenceToken,
    device: PathBuf,
    armed: bool,
}

impl DiskLeaseGuard {
    fn device(&self) -> PathBuf {
        self.device.clone()
    }
    fn token(&self) -> &FenceToken {
        &self.token
    }
    /// Success path: stop auto-releasing and hand back the token to record in
    /// `disk_tokens` (which the teardown/hibernate paths release).
    fn disarm(mut self) -> FenceToken {
        self.armed = false;
        self.token.clone()
    }

    /// Failure-path release: detach the disk + release the lease **awaited inline**,
    /// then disarm so the [`Drop`] backstop no-ops. Call this on every boot error path
    /// instead of leaning on Drop — Drop can only fire-and-forget (it's sync and can't
    /// block on a tokio runtime), so a re-fence landing before that spawned task ran
    /// would hit a transient, self-clearing `LeaseHeld`/`RwoUnsafe`. Awaiting here closes
    /// that window: the lease + holder are gone before the error returns to the caller.
    async fn release(mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        release_data_disk(
            &self.data_disk,
            &self.lease,
            &self.project_id,
            self.token.clone(),
        )
        .await;
    }
}

impl Drop for DiskLeaseGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // BACKSTOP ONLY. Normal boot-error paths call `release().await` (which awaits the
        // cleanup before returning); reaching Drop still armed means an unexpected drop —
        // a panic unwind or a future cancellation. Release fire-and-forget here: Drop is
        // sync and can't block on the runtime, and guard against being dropped outside a
        // runtime (e.g. during shutdown) so we never panic in Drop — the flock releases on
        // process exit anyway.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        warn!(project = %self.project_id, "data-disk boot guard dropped while armed (panic/cancel) — detaching + releasing lease");
        let (dd, ls, id, tok) = (
            self.data_disk.clone(),
            self.lease.clone(),
            self.project_id.clone(),
            self.token.clone(),
        );
        handle.spawn(async move {
            let _ = dd.detach(&id).await;
            let _ = ls.release(&tok).await;
        });
    }
}

/// Acquire the data-disk lease + attach the disk **read-write-once**, fencing any
/// prior writer, and return an armed [`DiskLeaseGuard`]. The armed guard is built the
/// instant `acquire` succeeds and OWNS the `ensure`/`attach` steps, so if those error
/// — OR the whole future is cancelled mid-attach (the wake/deploy callback is awaited
/// inline by the proxy, so a client disconnect cancels it) — the guard drops and
/// releases the lease. On `RwoUnsafe` (a prior writer still proven alive) it reaps a
/// stale Firecracker and retries once. After success the caller `disarm`s the guard.
async fn fence_data_disk(
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    host_id: &str,
    project_id: &str,
    disk_mib: u64,
) -> Result<DiskLeaseGuard> {
    let token = lease
        .acquire(project_id, host_id, DISK_LEASE_TTL)
        .await
        .map_err(|e| anyhow::anyhow!("lease acquire for {project_id}: {e}"))?;
    // Armed BEFORE the slow ensure/attach: any error or cancellation from here drops
    // the guard (which detaches + releases the lease) — no acquire→attach leak.
    let mut guard = DiskLeaseGuard {
        data_disk: data_disk.clone(),
        lease: lease.clone(),
        project_id: project_id.to_string(),
        token,
        device: PathBuf::new(),
        armed: true,
    };
    let device = fence_attach(data_disk, project_id, guard.token(), disk_mib).await?;
    guard.device = device;
    Ok(guard)
}

async fn fence_attach(
    data_disk: &Arc<dyn DataDiskProvider>,
    project_id: &str,
    token: &FenceToken,
    disk_mib: u64,
) -> Result<PathBuf> {
    // `ensure` is grow-or-create and NEVER shrinks, so a re-sized `[database].size`
    // grows the disk on the next boot and a smaller value is a safe no-op (no data loss).
    data_disk
        .ensure(project_id, disk_mib * 1024 * 1024)
        .await
        .map_err(|e| anyhow::anyhow!("ensure data disk {project_id}: {e}"))?;
    let device = match data_disk.attach_rwo(project_id, token).await {
        Ok(d) => d,
        Err(SubstrateError::RwoUnsafe { .. }) => {
            warn!(project = %project_id, "data disk held by a live prior writer; reaping stale Firecracker and retrying attach");
            reap_firecracker(project_id).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            data_disk
                .attach_rwo(project_id, token)
                .await
                .map_err(|e| anyhow::anyhow!("attach_rwo after reap {project_id}: {e}"))?
        }
        Err(e) => return Err(anyhow::anyhow!("attach_rwo {project_id}: {e}")),
    };
    Ok(device.path)
}

/// Release a project's data disk: detach the device + release the lease so another
/// host/boot can acquire without waiting out the TTL. Best-effort (teardown path).
async fn release_data_disk(
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    project_id: &str,
    token: FenceToken,
) {
    let _ = data_disk.detach(project_id).await;
    let _ = lease.release(&token).await;
}

fn check_project_has_volumes(data_dir: &Path, project_id: &str) -> bool {
    let servers_dir = data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .join("_servers");
    if !servers_dir.exists() {
        return false;
    }
    for entry in std::fs::read_dir(&servers_dir).into_iter().flatten() {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Ok(content) = std::fs::read_to_string(&path)
            && content.contains("\"volumes\"")
            && content.contains("\"mount\"")
        {
            return true;
        }
    }
    false
}

/// True when the project's live deployment declares a managed database (a host-baked
/// `_database.json`). A managed DB needs a persistent data disk to survive restart and
/// hibernate/wake even if no server declares a volume, so this forces `has_disk` on —
/// without it the DB would write to the ephemeral overlay tmpfs and lose data. Mirrors
/// [`check_project_has_volumes`] (reads the live deployment, set before this boot).
fn check_project_has_database(data_dir: &Path, project_id: &str) -> bool {
    data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .join("_database.json")
        .exists()
}

/// The VM id the DB reach plane (external `:443` edge, console query/schema/status, backup relay)
/// must wake + dial for a project's managed DB: the sibling **DB VM** (`{id}.db`) when
/// `tier="dedicated"`, else the **app VM** (`id`) where the DB is co-located on loopback. Keyed by
/// the BASE project id; the DB VM's agent holds the same splice secret, so only the target IP
/// changes (the agent side is loopback-only and unchanged).
fn db_reach_target_vm(data_dir: &Path, project_id: &str) -> String {
    if project_is_dedicated(data_dir, project_id) {
        vm_identity::vm_id(project_id, vm_identity::VmRole::Db)
    } else {
        project_id.to_string()
    }
}

/// True when the project's live deployment declares `[database] tier = "dedicated"` (P2) — its
/// managed DB runs in a sibling DB VM rather than co-located in the app VM. Reads the host-baked
/// `hosting/<project>/live/_database.json` `tier` field (always the BASE project id — the DB VM
/// has no `hosting/<id>.db/`). A missing file / absent-or-other tier ⇒ co-located (the default),
/// so this is fail-safe: only an explicit `"dedicated"` opts a project into the second VM.
fn project_is_dedicated(data_dir: &Path, project_id: &str) -> bool {
    let path = data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .join("_database.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| {
            v.get("tier")
                .and_then(serde_json::Value::as_str)
                .map(|t| t.eq_ignore_ascii_case("dedicated"))
        })
        .unwrap_or(false)
}

/// Desired data-disk size (MiB) for a project: the managed-DB `[database].size`
/// (parsed host-side at deploy into `_database.json`'s `size_mib`) when present, else
/// the platform default [`DATA_DISK_MIB`]. Read at deploy AND every wake so a re-sized
/// DB grows on the next boot (`ensure` never shrinks). Floored at the default — the DB
/// disk is never smaller than the platform minimum, so a too-small `size` is harmless.
/// A non-DB project (no `_database.json`, or no `size_mib`) gets the default unchanged.
fn data_disk_mib_for(data_dir: &Path, project_id: &str) -> u64 {
    let path = data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .join("_database.json");
    let configured = std::fs::read_to_string(&path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| v.get("size_mib").and_then(serde_json::Value::as_u64));
    configured.unwrap_or(0).max(DATA_DISK_MIB)
}

/// Application-level liveness probe. Returns true only if the agent answers HTTP
/// within the budget. A wedged agent (kernel up, userspace stuck) completes the
/// TCP handshake but never answers, so a bare TCP connect is NOT sufficient — we
/// must hit `/_jkbase/health` and bound it with a timeout.
async fn agent_alive(ip: &str) -> bool {
    let probe = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80"))
            .await
            .ok()?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri(format!("http://{ip}:80/_jkbase/health"))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        Some(resp.status().is_success())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), probe).await,
        Ok(Some(true))
    )
}

/// Process start time (jiffies since boot) from field 22 of `/proc/<pid>/stat`, or `None` if
/// gone/unparseable. (Mirrors the substrate/orch helpers; main can't reach those privates.)
fn proc_starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().nth(19)?.parse().ok()
}

/// True iff `pid` is alive AND still the same incarnation as `starttime` (PID-reuse-proof).
fn proc_alive_at(pid: u32, starttime: u64) -> bool {
    matches!(proc_starttime(pid), Some(st) if st == starttime)
}

/// Peer pid listening on a Firecracker api-sock, via `SO_PEERCRED`. Binds the socket-liveness
/// probe to a SPECIFIC pid at re-adoption time: the survivor's api-sock must be answered by
/// exactly `fc_pid` — not an unrelated process that bound the path, nor a recycled pid. `None`
/// if the socket is absent/unconnectable or the credential read fails (fail-closed).
fn socket_peer_pid(socket_path: &Path) -> Option<u32> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(socket_path).ok()?;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred/len are sized to ucred; getsockopt writes at most `len` bytes into cred.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 || cred.pid <= 0 {
        return None;
    }
    Some(cred.pid as u32)
}

/// The agent's reported protocol version from the `X-Jkbase-Agent-Proto` header on
/// `/_jkbase/health`. `None` if unreachable OR the header is absent/unparseable — a
/// pre-versioning agent (every survivor during this rollout), which the caller treats as
/// compatible. See [`jkbase_common::AGENT_PROTOCOL_VERSION`].
async fn agent_protocol_version(ip: &str) -> Option<u32> {
    let probe = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80"))
            .await
            .ok()?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri(format!("http://{ip}:80/_jkbase/health"))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        resp.headers()
            .get(jkbase_common::AGENT_PROTOCOL_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
    };
    tokio::time::timeout(Duration::from_secs(2), probe)
        .await
        .ok()
        .flatten()
}

/// SIGKILL a non-survivor runtime Firecracker by exact pid and confirm its death (bounded).
/// The holder record is deliberately LEFT in place so a later cold-boot's `attach_rwo` runs
/// its fail-CLOSED preempt; deleting it would make `attach_rwo` fail-OPEN. The caller removes
/// only `handoff.json`.
///
/// TOCTOU-guarded: only kills if `fc_pid` is STILL the firecracker serving `expected_sock` — the
/// FC could have exited during the seconds of verification between enumeration and here, and its
/// pid been recycled to an unrelated process; a bare-pid SIGKILL would then hit a bystander.
async fn reap_runtime_fc(fc_pid: u32, expected_sock: &Path) {
    let sock_bytes = expected_sock.to_string_lossy().into_owned().into_bytes();
    let still_ours = std::fs::read(format!("/proc/{fc_pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .any(|arg| arg == sock_bytes.as_slice())
        })
        .unwrap_or(false);
    if !still_ours {
        warn!(%fc_pid, sock = %expected_sock.display(),
            "VM re-adoption: pid is no longer the FC for this api-sock (exited/recycled); not killing");
        return;
    }
    warn!(%fc_pid, "VM re-adoption: reaping non-survivor runtime Firecracker");
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(fc_pid.to_string())
        .status();
    // Confirm death so a slow exit can't still be mapping a data loop when a cold-boot reopens
    // it. /proc-existence is enough here (a fresh-killed pid won't be recycled in this window).
    for _ in 0..60 {
        if !Path::new(&format!("/proc/{fc_pid}")).exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    warn!(%fc_pid, "reaped runtime FC did not exit within 3s");
}

/// Outcome of evaluating one surviving runtime Firecracker.
enum AdoptOutcome {
    Adopted,
    Reaped,
    /// A second live `jkbase-server` legitimately holds the disk (`LeaseHeld`) — we refuse this
    /// project and leave the survivor UNTOUCHED (never kill a live peer's VM). Single-host: a
    /// misconfiguration for an operator to resolve; we don't abort the whole startup over it.
    SkippedPeerOwned,
}

/// VM re-adoption (§4/§5/§6b): verify every runtime Firecracker that SURVIVED the prior
/// `jkbase-server`, re-adopt the live ones (re-acquire the lease at a fresh epoch, re-fence the
/// disk WITHOUT detaching, rebuild `vms`/`vm_states`/`routing`) and reap the rest. Runs ONCE at
/// startup, AFTER `PlatformState` is built and BEFORE the proxy binds or any wake-capable loop
/// (scheduler/idle/wake) runs. Replaces the old blunt `pkill -9 firecracker` boot reaper.
async fn adopt_or_reap_runtime_vms(
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
) {
    let (runtime_dir, data_disk, lease, host_id) = {
        let plat = platform.lock().await;
        (
            plat.data_dir.join("run"),
            plat.data_disk.clone(),
            plat.lease.clone(),
            plat.host_id.clone(),
        )
    };
    let fcs = rootfs_cas::list_runtime_firecrackers(&runtime_dir);
    if fcs.is_empty() {
        return;
    }
    info!(
        count = fcs.len(),
        "VM re-adoption: examining surviving runtime Firecrackers"
    );
    let (mut adopted, mut reaped, mut skipped) = (0usize, 0usize, 0usize);
    for (fc_pid, sock) in fcs {
        let Some(id) = sock
            .parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
        else {
            warn!(%fc_pid, sock = %sock.display(), "re-adoption: cannot derive project id; reaping");
            reap_runtime_fc(fc_pid, &sock).await;
            reaped += 1;
            continue;
        };
        match adopt_one_survivor(
            platform,
            routing,
            domain_map,
            &runtime_dir,
            &data_disk,
            &lease,
            &host_id,
            &id,
            fc_pid,
            &sock,
        )
        .await
        {
            AdoptOutcome::Adopted => adopted += 1,
            AdoptOutcome::Reaped => reaped += 1,
            AdoptOutcome::SkippedPeerOwned => skipped += 1,
        }
    }
    info!(adopted, reaped, skipped, "VM re-adoption complete");
}

/// Evaluate + (re-)adopt or reap a single surviving runtime Firecracker `fc_pid` for `id`.
#[allow(clippy::too_many_arguments)]
async fn adopt_one_survivor(
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    runtime_dir: &Path,
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    host_id: &str,
    id: &str,
    fc_pid: u32,
    sock: &Path,
) -> AdoptOutcome {
    // (1) Strict handoff. No valid record ⇒ a true orphan (crash between spawn and
    // handoff-write) ⇒ reap; delete only handoff.json (NOT the holder — leave the
    // fail-closed preempt for a later attach_rwo).
    let Some(rec) = handoff::read_strict(runtime_dir, id) else {
        warn!(project = %id, %fc_pid, "re-adoption: no valid handoff (orphan); reaping");
        reap_runtime_fc(fc_pid, sock).await;
        handoff::remove(runtime_dir, id);
        return AdoptOutcome::Reaped;
    };

    // (2) Verify SURVIVOR. Each check is fail-closed → reap on any miss.
    let reap = |why: &'static str| {
        warn!(project = %id, %fc_pid, reason = why, "re-adoption: not a survivor; reaping + cold-boot on next request");
    };
    if rec.fc_pid != fc_pid {
        reap("handoff pid mismatch");
    } else if !proc_alive_at(fc_pid, rec.fc_starttime) {
        reap("pid not alive at recorded start time");
    } else if socket_peer_pid(sock) != Some(fc_pid) {
        reap("api-sock SO_PEERCRED peer != fc_pid");
    } else if !agent_alive(&rec.ip).await {
        // The AGENT HTTP layer — NOT the bare FC api-sock, which a *paused* FC still answers
        // (the paused-FC-resurrection hole). A real survivor has a live, serving guest.
        reap("agent HTTP layer not answering");
    } else if matches!(agent_protocol_version(&rec.ip).await, Some(v) if v != jkbase_common::AGENT_PROTOCOL_VERSION)
    {
        // Agent-protocol skew: force-recycle (reap → cold-boot on the NEW agent) rather than
        // keep talking the old wire format. Absent header ⇒ compatible (pre-versioning agent).
        reap("agent protocol version skew");
    } else {
        // All checks passed — proceed to adopt below.
        return finish_adoption(
            platform,
            routing,
            domain_map,
            runtime_dir,
            data_disk,
            lease,
            host_id,
            id,
            fc_pid,
            rec,
        )
        .await;
    }
    // Any verification miss fell through to here.
    reap_runtime_fc(fc_pid, sock).await;
    handoff::remove(runtime_dir, id);
    AdoptOutcome::Reaped
}

/// Re-fence + commit a VERIFIED survivor. Split out so the verification arm stays readable.
#[allow(clippy::too_many_arguments)]
async fn finish_adoption(
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    runtime_dir: &Path,
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    host_id: &str,
    id: &str,
    fc_pid: u32,
    rec: handoff::HandoffRecord,
) -> AdoptOutcome {
    let sock = runtime_dir.join(id).join("firecracker.sock");
    // (3) Re-fence the data disk WITHOUT detaching — only for projects that have one. The old
    // process's flock released on its exit, so acquire wins at a fresh (higher) epoch.
    let token = if let Some(loop_dev) = rec.loop_dev.clone() {
        let token = match lease.acquire(id, host_id, DISK_LEASE_TTL).await {
            Ok(t) => t,
            Err(SubstrateError::LeaseHeld { .. }) => {
                // §5.1: a second live server owns the disk. Do NOT adopt and do NOT kill the
                // survivor — refuse this project loudly and move on (never one instance "fixing"
                // a misconfig by SIGKILLing the other's tenant VM).
                tracing::error!(project = %id,
                    "re-adoption: data-disk lease is HELD by another live jkbase-server — refusing \
                     this project and leaving its VM untouched (resolve the duplicate server)");
                return AdoptOutcome::SkippedPeerOwned;
            }
            Err(e) => {
                tracing::warn!(project = %id, error = %e, "re-adoption: lease acquire failed; reaping");
                reap_runtime_fc(fc_pid, &sock).await;
                handoff::remove(runtime_dir, id);
                return AdoptOutcome::Reaped;
            }
        };
        // adopt_writer re-pins the holder at the fresh epoch + verified writer, fail-closed
        // (fresh kernel loop-backing read + fc_pid fd proof + starttime pin). On ANY doubt,
        // RELEASE the freshly-acquired lease FIRST (else the cold-boot's own acquire would hit
        // LeaseHeld against this very process — the §5.3 self-deadlock), then reap → cold-boot.
        if let Err(e) = data_disk
            .adopt_writer(id, &token, &loop_dev, fc_pid, rec.fc_starttime)
            .await
        {
            tracing::warn!(project = %id, error = %e,
                "re-adoption: adopt_writer failed; releasing lease + reaping for cold boot");
            let _ = lease.release(&token).await;
            reap_runtime_fc(fc_pid, &sock).await;
            handoff::remove(runtime_dir, id);
            return AdoptOutcome::Reaped;
        }
        Some(token)
    } else {
        None // diskless project: no lease, no disk_tokens entry (mirrors the deploy/wake path)
    };

    // (4) Commit under the platform lock. Re-validate the project still exists (a delete could
    // have landed via the control API). If gone: kill the FC + release/detach AWAITED, reap.
    let vm = VmInstance::adopt(
        id,
        runtime_dir,
        fc_pid,
        rec.fc_starttime,
        Some(Path::new(RUNTIME_CGROUP_PARENT)),
    );
    let over_quota;
    let active_domains;
    {
        let mut plat = platform.lock().await;
        // A survivor's rendered id may be a DB VM (`{base}.db`): resolve its BASE project for every
        // store/quota/domain read (the DB VM has no project row of its own). Per-VM state (maps,
        // lease, disk) stays keyed by the rendered `id`.
        let (base_pid, vm_role) = vm_identity::split_vm_id(id);
        if plat.store.get_project(base_pid).ok().flatten().is_none() {
            drop(plat);
            let mut vm = vm;
            let _ = vm.stop().await; // synchronous-to-death before detaching the disk
            if let Some(token) = token {
                let _ = data_disk.detach(id).await;
                let _ = lease.release(&token).await;
            }
            handoff::remove(runtime_dir, id);
            warn!(project = %id, "re-adoption: project was deleted; reaped");
            return AdoptOutcome::Reaped;
        }
        over_quota = plat
            .store
            .get_quota_status(base_pid)
            .ok()
            .flatten()
            .map(|s| s.bandwidth_blocked)
            .unwrap_or(false);
        if let Some(token) = &token {
            plat.disk_tokens.insert(id.to_string(), token.clone());
        }
        plat.vms.insert(id.to_string(), vm);
        plat.vm_states.insert(id.to_string(), VmLifecycle::Running);
        plat.vm_rootfs_hashes
            .insert(id.to_string(), rec.base_rootfs_hash.clone());
        plat.wake_failures.remove(id);
        // A DB VM is reached host-mediated and never proxy-routed → no domains to register.
        active_domains = if vm_role == vm_identity::VmRole::Db {
            Vec::new()
        } else {
            plat.store
                .list_active_domains_for_project(base_pid)
                .unwrap_or_default()
        };
    }

    // Rewrite the handoff with the refreshed lease epoch so run/<id>/handoff.json stays
    // consistent with disk_tokens (pid/starttime/loop_dev unchanged — same FC, same loop).
    let mut rec2 = rec;
    rec2.lease_epoch = token.as_ref().map(|t| t.epoch);
    let _ = handoff::write(runtime_dir, id, &rec2);

    // (5) Route — UNLESS this is the DB VM (never proxy-routed; reached host-mediated) or the
    // project is over quota (§10): then leave it unrouted so it isn't served; the idle loop
    // hibernates it and a request is refused by wake_project's quota gate.
    if vm_identity::split_vm_id(id).1 == vm_identity::VmRole::Db {
        info!(project = %id, "re-adoption: DB VM survivor (host-mediated; not registering routes)");
    } else if over_quota {
        warn!(project = %id, "re-adoption: adopted an OVER-QUOTA survivor; not registering routes");
    } else {
        register_active_routes(routing, domain_map, &active_domains, id, &rec2.ip).await;
    }
    info!(project = %id, %fc_pid, ip = %rec2.ip, "VM re-adopted (no bounce)");
    AdoptOutcome::Adopted
}

/// Centralized force-stop + state reconciliation for a project whose graceful
/// hibernate could not complete (wedged agent, pause/snapshot timeout, or error).
/// Idempotent and best-effort: every step is independently fallible-ignored so a
/// failure in one does not strand the others. After this runs the project is left
/// as Hibernated-with-no-snapshot, so the next request cold-boots cleanly.
async fn force_stop_and_cleanup(project_id: &str, platform: &Arc<Mutex<PlatformState>>) {
    let mut plat = platform.lock().await;

    // The VM handle may already be gone (hibernate_project removes it before the
    // pause that fails) — stop() it if present, but don't rely on it.
    if let Some(mut vm) = plat.vms.remove(project_id) {
        let _ = vm.stop().await;
    }
    plat.vm_rootfs_hashes.remove(project_id);
    // The FC is being reaped below — drop its re-adoption record so a later start can't adopt it.
    // (hibernate_project already removed it before its pause; idempotent if so.)
    handoff::remove(&plat.data_dir.join("run"), project_id);
    // Release the data-disk hold so the next wake re-fences (the FC is reaped below).
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    let alloc = plat.store.get_vm_allocation(project_id).ok().flatten();

    // Drop any snapshot meta so wake deterministically cold-boots rather than
    // trying to restore a stale or half-written snapshot.
    let _ = plat.store.remove_snapshot_meta(project_id);

    // Persisted state -> Hibernated keeps the project's domains routed so the next
    // request cold-boots cleanly (snapshot is gone, so wake falls through to boot).
    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Hibernated;
        let _ = plat.store.update_project(&proj);
    }

    // Never leave it stuck at Hibernating (shared with the idle loop — that would
    // make wake_project spin and bail on every subsequent request).
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Hibernated);

    drop(plat);

    // Guarantee the leaked Firecracker process dies even when `vms` had no handle.
    let _ = tokio::process::Command::new("pkill")
        // Anchor to the EXACT api-sock path segment (/<id>/firecracker.sock), not an unanchored
        // `firecracker.*<id>` substring of the whole cmdline: project ids are user-chosen slugs
        // ([a-z0-9-]), and every FC cmdline carries `--api-sock .../run/<id>/firecracker.sock`, so
        // a short id like `a` matched as a substring would SIGKILL every tenant's FC host-wide
        // (cross-tenant kill). `<id>` is a single path segment bounded by `/`, so `/a/` never
        // matches `/ab/`. A rendered DB VM id (`{id}.db`) carries a `.` — itself an ERE
        // metacharacter — so `fc_sock_pkill_pattern` escapes every `.` in the id (else `foo.db`
        // would match `/fooadb/…` and cross-tenant-kill project `fooadb`).
        .args(["-f", &vm_identity::fc_sock_pkill_pattern(project_id)])
        .status()
        .await;

    // Tear down TAP so cleanup_orphans reconciles consistently on next boot (a
    // leaked-but-listening process would otherwise read as "reachable" and the
    // stale allocation would never be reaped). wake re-runs setup_tap.
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
}

use chrono::{TimeZone, Utc};
use cron::Schedule as CronSchedule;

/// Coarse fixed tick. 30s gives `*/1 * * * *` schedules <=30s firing latency.
const SCHED_TICK: Duration = Duration::from_secs(30);
/// Max simultaneous in-flight fires (each can wake a hibernated VM = seconds).
const MAX_CONCURRENT_FIRES: usize = 4;
/// Never replay further back than this after downtime; collapse backlog to one fire.
const CATCHUP_CAP_SECS: u64 = 3600;

/// Parse a 5-field UNIX cron. The `cron` crate is 6-field (field 0 = seconds), so
/// a standard 5-field expression is left-padded with "0 " to fire at second 0.
/// Must stay in sync with the deploy-time validation in jkbase-control.
fn parse_unix_5field(expr: &str) -> Result<CronSchedule, cron::error::Error> {
    use std::str::FromStr;
    CronSchedule::from_str(&format!("0 {expr}"))
}

/// Fire instants strictly after `last_run`, up to and including `now` (epoch secs).
fn due_since(sched: &CronSchedule, last_run: u64, now: u64) -> Vec<u64> {
    let Some(after) = Utc.timestamp_opt(last_run as i64, 0).single() else {
        return Vec::new();
    };
    sched
        .after(&after)
        .take_while(|t| t.timestamp() as u64 <= now)
        .map(|t| t.timestamp() as u64)
        .collect()
}

/// Host-driven cron loop. Reads the durable SCHEDULES registry each tick (the
/// single source of truth), computes occurrences due since each schedule's
/// last_run, and fires them — waking the project if hibernated. Gated, in future
/// HA, to projects this host owns; today single-host owns all.
async fn scheduler_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
    activity: ActivityTracker,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FIRES));
    let in_flight: Arc<Mutex<HashSet<(String, String)>>> = Arc::new(Mutex::new(HashSet::new()));

    loop {
        tokio::time::sleep(SCHED_TICK).await;
        let now = jkbase_control::auth::timestamp();

        // Snapshot the registry under the lock, then release it before per-project
        // work (wake/invoke must not hold the platform lock).
        let schedules = {
            let plat = platform.lock().await;
            match plat.store.list_schedules() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "scheduler: failed to read schedules");
                    continue;
                }
            }
        };

        for sched in schedules {
            let Ok(parsed) = parse_unix_5field(&sched.cron) else {
                continue;
            };

            // Catch-up cap: clamp the replay origin so a long outage doesn't
            // stampede, and collapse any backlog to a single fire.
            let last = sched.last_run.unwrap_or(now);
            let effective_last = last.max(now.saturating_sub(CATCHUP_CAP_SECS));
            let due = due_since(&parsed, effective_last, now);
            let Some(&fire_at) = due.last() else {
                continue;
            };

            let key = (sched.project_id.clone(), sched.function.clone());
            {
                let mut inf = in_flight.lock().await;
                if !inf.insert(key.clone()) {
                    continue; // already firing from a previous tick
                }
            }

            let platform = platform.clone();
            let routing = routing.clone();
            let domain_map = domain_map.clone();
            let shipper = shipper.clone();
            let sem = sem.clone();
            let in_flight = in_flight.clone();
            let activity = activity.clone();

            tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                let result = fire_schedule(
                    &sched.project_id,
                    &sched.function,
                    platform.clone(),
                    routing,
                    domain_map,
                    shipper,
                )
                .await;

                match result {
                    Ok(()) => {
                        let plat = platform.lock().await;
                        let _ = plat.store.update_schedule_last_run(
                            &sched.project_id,
                            &sched.function,
                            fire_at,
                        );
                        drop(plat);
                        // Count the fire as activity so the project re-hibernates
                        // idle_timeout AFTER the last fire (frequent crons stay warm;
                        // sparse crons scale to zero between fires) rather than
                        // churning on the idle loop's seeded baseline.
                        activity
                            .write()
                            .await
                            .insert(sched.project_id.clone(), Instant::now());
                    }
                    Err(e) => {
                        // last_run unadvanced -> retried next tick (bounded by the cap).
                        tracing::error!(project = %sched.project_id, function = %sched.function,
                            error = %e, "scheduled invoke failed; will retry next tick");
                    }
                }
                in_flight.lock().await.remove(&key);
            });
        }
    }
}

/// Wake `project_id` if needed, then invoke `name` over plain HTTP. Lock-free
/// during the call (wake_project drops the platform lock before returning the IP).
async fn fire_schedule(
    project_id: &str,
    name: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<()> {
    let ip = wake_project(project_id, platform, routing, domain_map, shipper)
        .await
        .map_err(|e| anyhow::anyhow!("wake failed: {e:?}"))?;

    let call = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80")).await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("http://{ip}:80/functions/{name}"))
            .header("x-jkbase-trigger", "schedule")
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        let resp = sender.send_request(req).await?;
        Ok::<_, anyhow::Error>(resp.status())
    };

    let status = match tokio::time::timeout(Duration::from_secs(30), call).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("scheduled fn {name} for {project_id} timed out"),
    };
    if !status.is_success() {
        anyhow::bail!("scheduled fn {name} returned {status}");
    }
    Ok(())
}

/// Sample interval. Coarse — usage is billed over hours, not seconds.
const METERING_TICK: Duration = Duration::from_secs(60);
/// Keep ~3 months of hourly buckets; prune older so month-to-date is never lost.
const USAGE_RETENTION_SECS: u64 = 90 * 86400;

/// Host-side metering + quota enforcement. Each tick: sample per-project CPU
/// (/proc), bandwidth (TAP /sys, delta-accumulated), and storage (on-disk), roll
/// them into the current hour bucket, then enforce the monthly bandwidth cap by
/// hibernating + flagging over-quota projects (the wake gate refuses to wake a
/// flagged project). All `/proc`,`/sys`,fs I/O happens with the platform lock
/// released (the log_shipper_loop idiom).
async fn metering_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    db_registry: Option<Arc<jkbase_proxy::db_relay::DbRelayRegistry>>,
) {
    let mut state = metering::SamplerState::default();
    let mut last_sample = Instant::now();
    let mut ticks: u64 = 0;

    loop {
        tokio::time::sleep(METERING_TICK).await;
        ticks += 1;
        let now = jkbase_control::auth::timestamp();
        let hour_epoch = now / 3600 * 3600;
        let elapsed = last_sample.elapsed().as_secs().max(1);
        last_sample = Instant::now();

        // Snapshot everything we need under one platform lock, then release it
        // before any /proc, /sys, or filesystem I/O.
        let (running_pids, allocs, projects, data_dir, store) = {
            let plat = platform.lock().await;
            let running_pids: Vec<(String, u32)> = plat
                .vm_states
                .iter()
                .filter(|(_, s)| **s == VmLifecycle::Running)
                .filter_map(|(id, _)| {
                    plat.vms
                        .get(id)
                        .and_then(|vm| vm.pid())
                        .map(|pid| (id.clone(), pid))
                })
                .collect();
            let allocs: Vec<(String, String)> = plat
                .store
                .list_vm_allocations()
                .unwrap_or_default()
                .into_iter()
                .map(|a| (a.project_id, a.tap_device))
                .collect();
            let projects: Vec<String> = plat
                .store
                .list_projects()
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.id)
                .collect();
            (
                running_pids,
                allocs,
                projects,
                plat.data_dir.clone(),
                plat.store.clone(),
            )
        };

        // CPU deltas (only Running VMs have a live pid).
        let mut cpu: HashMap<String, u64> = HashMap::new();
        for (id, pid) in &running_pids {
            if let Some(cur) = metering::read_cpu_jiffies(*pid) {
                cpu.insert(id.clone(), state.cpu_delta(id, *pid, cur));
            }
        }
        // Bandwidth deltas from each project's TAP.
        let mut bw: HashMap<String, (u64, u64)> = HashMap::new();
        for (id, tap) in &allocs {
            if let Some((rx, tx)) = metering::read_tap_bytes(tap) {
                bw.insert(id.clone(), state.tap_delta(id, tap, rx, tx));
            }
        }

        // A dedicated project's DB VM has its OWN alloc row (`{id}.db`) but no project row, so the
        // per-project roll below skips it — accrue its usage under the rendered id (decision #3:
        // separate rows, rolled up in display by `get_project_usage`). cpu/bw are already keyed by
        // the rendered id; storage is its own `{id}.db.img` disk.
        let db_vm_ids: Vec<String> = allocs
            .iter()
            .map(|(id, _)| id.clone())
            .filter(|id| vm_identity::split_vm_id(id).1 == vm_identity::VmRole::Db)
            .collect();

        // Roll each VM's sample into its current hour bucket. Skip VMs with nothing to record (no
        // storage, no deltas) to avoid empty rows.
        let roll = |id: &str| {
            let cpu_j = cpu.get(id).copied().unwrap_or(0);
            let (rx, tx) = bw.get(id).copied().unwrap_or((0, 0));
            let storage = jkbase_common::storage::project_storage_bytes(&data_dir, id);
            if cpu_j == 0 && rx == 0 && tx == 0 && storage == 0 {
                return;
            }
            if let Err(e) = store.add_usage(id, hour_epoch, cpu_j, rx, tx, storage, elapsed) {
                tracing::warn!(project = %id, error = %e, "metering: add_usage failed");
            }
        };
        for id in &projects {
            roll(id);
        }
        for id in &db_vm_ids {
            roll(id);
        }

        // DB-attributable warm-seconds: accrue for the VM a managed-DB reach-plane relay is holding
        // warm (`conn_count > 0`). This is the resource an idle external DB connection consumes — the
        // VM would otherwise hibernate — so it's metered (billable), complementing the per-tenant
        // warm-VM cap enforced at relay registration. Relays are keyed by the BASE project, and the
        // warm VM is the reach TARGET (the DB VM when dedicated, else the app VM) — attribute only to
        // it, never both, so a dedicated project isn't double-billed. The in-VM app->DB path never
        // registers a relay, so it's not double-counted here.
        if let Some(reg) = &db_registry {
            for (id, _pid) in &running_pids {
                let base = vm_identity::base_project_id(id);
                if reg.conn_count(base) > 0
                    && id == &db_reach_target_vm(&data_dir, base)
                    && let Err(e) = store.add_warm_usage(id, hour_epoch, elapsed)
                {
                    tracing::warn!(project = %id, error = %e, "metering: add_warm_usage failed");
                }
            }
        }

        // --- Quota enforcement (monthly bandwidth cap) ---
        let month_start = month_start_epoch(now);
        for id in &projects {
            let cap = store
                .get_quota(id)
                .map(|q| q.bandwidth_bytes_per_month)
                .unwrap_or(u64::MAX);
            let mtd = store.sum_month_to_date(id, month_start).unwrap_or_default();
            let used = mtd.rx_bytes.saturating_add(mtd.tx_bytes);
            let status = store.get_quota_status(id).ok().flatten();
            let blocked = status
                .as_ref()
                .map(|s| s.bandwidth_blocked)
                .unwrap_or(false);

            if used > cap && !blocked {
                // Write the block FIRST (source of truth for the wake gate) so a
                // request racing the hibernate is refused, then hibernate.
                let _ = store.save_quota_status(&QuotaStatus {
                    project_id: id.clone(),
                    bandwidth_blocked: true,
                    blocked_reason: Some("monthly bandwidth cap exceeded".to_string()),
                    blocked_at: now,
                    blocked_month: month_start,
                });
                tracing::warn!(project = %id, used, cap, "bandwidth cap exceeded; hibernating + blocking wake");
                let is_running =
                    { platform.lock().await.vm_states.get(id) == Some(&VmLifecycle::Running) };
                if is_running
                    && let Err(e) = hibernate_project(
                        id,
                        platform.clone(),
                        routing.clone(),
                        shipper.clone(),
                        None,
                    )
                    .await
                {
                    tracing::error!(project = %id, error = %e, "failed to hibernate over-quota project");
                }
            } else if blocked {
                // Clear on month rollover (new period) or if usage is back under
                // cap (e.g. an admin raised the override).
                let stale_month = status
                    .as_ref()
                    .map(|s| s.blocked_month != month_start)
                    .unwrap_or(false);
                if stale_month || used <= cap {
                    let _ = store.save_quota_status(&QuotaStatus {
                        project_id: id.clone(),
                        bandwidth_blocked: false,
                        blocked_reason: None,
                        blocked_at: 0,
                        blocked_month: month_start,
                    });
                    tracing::info!(project = %id, "bandwidth block cleared");
                }
            }
        }

        // Prune old buckets roughly hourly (60 ticks * 60s).
        if ticks.is_multiple_of(60) {
            let cutoff_hour = now.saturating_sub(USAGE_RETENTION_SECS) / 3600 * 3600;
            if let Ok(n) = store.prune_usage(cutoff_hour)
                && n > 0
            {
                tracing::info!(pruned = n, "metering: pruned old usage buckets");
            }
        }
    }
}

async fn sync_agent(ip: &str) -> Result<()> {
    if let Ok(stream) = tokio::net::TcpStream::connect(format!("{ip}:80")).await {
        let io = hyper_util::rt::TokioIo::new(stream);
        if let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(io).await {
            tokio::spawn(conn);
            let req = hyper::Request::builder()
                .uri(format!("http://{ip}:80/_jkbase/sync"))
                .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
            let _ = sender.send_request(req).await;
        }
    }
    Ok(())
}

/// Ask the agent to step the guest wall clock to its PTP reference now (the agent
/// runs `chronyc makestep`). Used after wake/restore so a restored snapshot — whose
/// clock is frozen at snapshot time — corrects instantly instead of on chrony's
/// next poll. Best-effort and bounded: a clock nudge must never block a wake.
async fn resync_clock_agent(ip: &str) {
    let send = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80"))
            .await
            .ok()?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{ip}:80/_jkbase/resync-clock"))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let _ = sender.send_request(req).await;
        Some(())
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), send).await;
}

async fn wait_for_agent(ip: &str) -> Result<()> {
    for i in 0..50 {
        if let Ok(stream) = tokio::net::TcpStream::connect(format!("{ip}:80")).await {
            drop(stream);
            info!(ip, attempts = i + 1, "agent is ready");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!("agent at {ip} did not become ready within 10 seconds");
}

/// HA P2 — the split-brain GATE. Deterministic tests of the COORDINATION layer of the
/// data-disk fence the self-fence (`disk_fence_loop`/`self_fence_project`) and the
/// restore-path fence rely on: that the lease + epoch + renew-or-die logic admit at most
/// one writer per disk scope. **GATE: the coordination layer must be green before any
/// failover automation (P3+) is wired** — the cluster BLOCK-DEVICE exclusivity gate (a
/// live partition actually being prevented from writing) is the substrate's on-box test
/// plus the EtcdLease 2-host run noted below.
///
/// Admission model: a host may write a disk iff it still holds the lease. Production
/// de-admits (self-fences) on a renew that is `Fenced` (superseded) or that stays failing
/// past the grace window — see `evaluate_renew`, unit-tested for the transient-vs-fenced
/// discrimination by `renew_evaluation_discriminates_fenced_from_transient`. The four
/// scenarios below walk the split-brain space and assert `at most one host is admitted at
/// any moment`.
///
/// Coverage boundary (honest — not silently capped):
///  - These run against the node-local `FlockLease` (no root, CI-deterministic) and so
///    prove the COORDINATION layer (mutual exclusion, de-admission on loss, epoch
///    monotonicity). A voluntary `release` models a definitive (`Fenced`) loss.
///  - The transient-blip-vs-real-loss discrimination (so an etcd hiccup never kills a
///    live VM) is covered separately + deterministically by `evaluate_renew`'s unit test.
///  - The real BLOCK-DEVICE exclusivity (a live prior writer blocks `attach_rwo`) is the
///    substrate's on-box `attach_refuses_while_prior_writer_is_alive`.
///  - The live-partition case (holder still alive while the AUTHORITY expired its lease)
///    needs the distributed `EtcdLease` + a real 2-host/partition run — the rented-
///    hardware last mile, NOT proven here.
#[cfg(test)]
mod split_brain_gate {
    use jkbase_substrate::{FenceToken, FlockLease, Lease, SubstrateError};
    use std::time::Duration;

    const TTL: Duration = Duration::from_secs(15);

    fn leases_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("jkbase-gate-{tag}-{nanos}"))
    }

    /// The production admission gate: a host may write iff its lease token still renews.
    async fn may_write(lease: &FlockLease, token: &FenceToken) -> bool {
        lease.renew(token, TTL).await.is_ok()
    }

    /// S1 — racing writers: two hosts contend for one disk; mutual exclusion admits
    /// at most one. The loser never even gets a token.
    #[tokio::test]
    async fn racing_writers_admit_at_most_one() {
        let dir = leases_dir("race");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        // host-b races for the same disk and is refused while a live holder owns it.
        assert!(matches!(
            b.acquire("disk-p", "host-b", TTL).await,
            Err(SubstrateError::LeaseHeld { .. })
        ));
        assert!(may_write(&a, &ta).await, "exactly one admitted writer (a)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2 — lease loss mid-write: the holder's admission is revoked the instant it loses
    /// the lease (→ self-fence), and a survivor can be admitted ONLY afterwards, with a
    /// strictly higher epoch. There is never a moment with two admitted writers.
    #[tokio::test]
    async fn lease_loss_revokes_admission_before_survivor_is_admitted() {
        let dir = leases_dir("loss");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        assert!(may_write(&a, &ta).await, "a is the writer");
        // While a holds, the survivor CANNOT acquire — so two are never admitted at once.
        assert!(b.acquire("disk-p", "host-b", TTL).await.is_err());

        // a loses the lease (partition / TTL expiry ≈ the OS releasing its flock).
        a.release(&ta).await.unwrap();
        assert!(
            !may_write(&a, &ta).await,
            "a self-fences the instant it loses the lease"
        );
        // Only NOW can the survivor be admitted, with a strictly higher epoch.
        let tb = b.acquire("disk-p", "host-b", TTL).await.unwrap();
        assert!(tb.epoch > ta.epoch);
        assert!(may_write(&b, &tb).await);
        assert!(
            !may_write(&a, &ta).await,
            "deposed a stays de-admitted (no double writer)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S3 — TTL clock skew: authority is by epoch (monotonic, lease-issued), NOT by any
    /// host's wall clock. A clock-skewed old host's token can never supersede the newer
    /// holder's, so skew cannot revive a stale writer.
    #[tokio::test]
    async fn clock_skew_cannot_revive_a_stale_token() {
        let dir = leases_dir("skew");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        a.release(&ta).await.unwrap();
        let tb = b.acquire("disk-p", "host-b", TTL).await.unwrap();
        assert!(tb.supersedes(&ta).unwrap(), "newer epoch supersedes");
        assert!(
            !ta.supersedes(&tb).unwrap(),
            "a clock-skewed stale token never supersedes the live holder"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S4 — zombie double-write: a hung old writer that still 'believes' it holds the
    /// disk after a takeover is denied on both axes — its stale token neither renews nor
    /// supersedes the live holder.
    #[tokio::test]
    async fn zombie_holder_cannot_write_after_takeover() {
        let dir = leases_dir("zombie");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        // a hangs/partitions; its flock is released (OS on crash, modelled by release).
        a.release(&ta).await.unwrap();
        let tb = b.acquire("disk-p", "host-b", TTL).await.unwrap();
        // The zombie keeps trying to use its stale token — denied both ways:
        assert!(
            !may_write(&a, &ta).await,
            "stale token can't renew → denied admission"
        );
        assert!(
            !ta.supersedes(&tb).unwrap(),
            "stale token can't supersede the live holder"
        );
        assert!(
            may_write(&b, &tb).await,
            "the live holder is the sole writer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fail-open routing at the heart of "redeploys never brick": every reason a snapshot
    /// can't be trusted must route to a cold boot (None), and only a fully-coherent snapshot
    /// (stamped+present rootfs blob + matching deployment version) restores.
    #[test]
    fn snapshot_restore_decision_fails_open_on_every_mismatch() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("jkbase-decision-{nanos}"));
        let cas = root.join("base-rootfs");
        std::fs::create_dir_all(&cas).unwrap();
        let snap = root.join("snapshot");
        let mem = root.join("mem");
        std::fs::write(&snap, b"s").unwrap();
        std::fs::write(&mem, b"m").unwrap();
        let good_hash = "a".repeat(64);
        std::fs::write(rootfs_cas::blob_path(&cas, &good_hash), b"rootfs").unwrap();

        let base = |hash: Option<String>, ver: Option<u64>| SnapshotMeta {
            project_id: "p".into(),
            snapshot_path: snap.to_string_lossy().into_owned(),
            mem_file_path: mem.to_string_lossy().into_owned(),
            created_at: 0,
            vcpu_count: 1,
            mem_size_mib: 1024,
            base_rootfs_hash: hash,
            deployment_version: ver,
        };

        // No snapshot at all → fresh cold boot.
        assert_eq!(
            snapshot_restore_decision(None, Some(3), &cas),
            (None, "coldboot_fresh")
        );
        // Fully coherent → restore against the stamped blob.
        let m = base(Some(good_hash.clone()), Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas),
            (Some(good_hash.clone()), "restored")
        );
        // Legacy unstamped → cold boot.
        let m = base(None, Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_legacy_unstamped"
        );
        // Stamped hash whose blob was reaped/never-placed → cold boot (this is the exact
        // self-healing path that saves a project from a GC over-deletion).
        let m = base(Some("b".repeat(64)), Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_rootfs_blob_missing"
        );
        // Non-hex stamp → cold boot (never trust it as a path component).
        let m = base(Some("../etc".to_string()), Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_bad_hash"
        );
        // Version drift (project redeployed since hibernate) → cold boot, so a stale metadata
        // image / secrets / layers can't be restored under the wrong version.
        let m = base(Some(good_hash.clone()), Some(2));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_version_drift"
        );
        // Snapshot files reaped out from under the record → cold boot.
        let m = base(Some(good_hash.clone()), Some(3));
        std::fs::remove_file(&snap).unwrap();
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_snapshot_files_missing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn flock_lease_elects_single_leader() {
        // The election primitive (HA P2): with a SHARED lease backend, exactly one host
        // holds `cluster-leader` at a time; a contender wins only after the holder
        // releases (≈ the holder dying, which the OS does for flock), with a strictly
        // higher epoch. Two FlockLease instances over one leases dir = a single-box sim
        // cluster of two hosts.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let leases = std::env::temp_dir().join(format!("jkbase-leader-{nanos}"));
        let a = jkbase_substrate::FlockLease::open(leases.clone(), "host-a").unwrap();
        let b = jkbase_substrate::FlockLease::open(leases.clone(), "host-b").unwrap();
        let ttl = Duration::from_secs(15);

        // host-a wins leadership.
        let ta = a.acquire(LEADER_SCOPE, "host-a", ttl).await.unwrap();
        // host-b cannot while a live holder owns it.
        assert!(matches!(
            b.acquire(LEADER_SCOPE, "host-b", ttl).await,
            Err(SubstrateError::LeaseHeld { .. })
        ));
        // host-a re-asserts (the loop's keepalive) — same token, no epoch churn.
        assert_eq!(a.renew(&ta, ttl).await.unwrap().epoch, ta.epoch);

        // host-a steps down (≈ crash); host-b now wins, with a higher epoch (fence
        // monotonicity across the leadership change).
        a.release(&ta).await.unwrap();
        let tb = b.acquire(LEADER_SCOPE, "host-b", ttl).await.unwrap();
        assert!(
            tb.epoch > ta.epoch,
            "new leader's epoch must supersede the old"
        );
        // The deposed host can no longer renew its stale token.
        assert!(a.renew(&ta, ttl).await.is_err());

        let _ = std::fs::remove_dir_all(&leases);
    }

    fn test_host(id: &str, region: &str, hb: u64, max_vms: u32) -> HostRecord {
        HostRecord {
            host_id: id.into(),
            region: region.into(),
            public_addr: Some(format!("{id}:9090")),
            last_heartbeat: hb,
            cpu_template_id: None,
            kernel_id: None,
            capacity: HostCapacity {
                vcpus: 0,
                mem_mib: 0,
                max_vms,
            },
        }
    }
    fn test_alloc(pid: &str, host: &str) -> VmAllocation {
        VmAllocation {
            project_id: pid.into(),
            ip: "172.16.0.2".into(),
            tap_device: "tap".into(),
            mac: "AA".into(),
            host_id: host.into(),
            placement_epoch: 1,
        }
    }

    #[test]
    fn next_free_octet_is_scoped_per_host_island() {
        // HA P4: each host's /24 is its own L2 island, so only OUR allocations (and legacy
        // empty-host_id ones) constrain the next octet; a peer reusing the same octets on
        // its own segment must not block us or exhaust our range.
        let a = |pid: &str, ip: &str, host: &str| VmAllocation {
            project_id: pid.into(),
            ip: ip.into(),
            tap_device: "t".into(),
            mac: "AA".into(),
            host_id: host.into(),
            placement_epoch: 1,
        };
        let allocs = vec![
            a("p1", "172.16.0.2", "me"),
            a("p2", "172.16.0.3", "me"),
            a("peer1", "172.16.0.2", "peer"), // peer reuses .2 on ITS island — ignored for us
            a("peer2", "172.16.0.4", "peer"), // peer's .4 — ignored for us
            a("legacy", "172.16.0.5", ""),    // empty host_id = ours
        ];
        // me: own {2,3} + legacy {5}; peer's {2,4} ignored → next free = 4.
        assert_eq!(next_free_octet(&allocs, "me"), Some(4));
        // peer: own {2,4} + legacy {5} → next free = 3.
        assert_eq!(next_free_octet(&allocs, "peer"), Some(3));
        // Empty pool starts at .2.
        assert_eq!(next_free_octet(&[], "me"), Some(2));
    }

    #[test]
    fn place_project_picks_least_loaded_live_in_region_with_capacity() {
        let now = 1000;
        let hosts = vec![
            test_host("a", "east", 995, 0),    // live, region east, unbounded
            test_host("b", "east", 995, 0),    // live, region east
            test_host("c", "west", 995, 0),    // live, wrong region
            test_host("d", "east", 900, 0),    // east but DEAD (100s stale)
            test_host("full", "east", 995, 1), // east, live, but at capacity (1)
        ];
        // a has 2 allocations, b has 0, full has 1 (at its cap).
        let allocs = vec![
            test_alloc("p1", "a"),
            test_alloc("p2", "a"),
            test_alloc("p3", "full"),
        ];
        let load = current_load(&allocs);
        let pick = place_project(&hosts, &load, "east", now, 15).unwrap();
        assert_eq!(
            pick.host_id, "b",
            "least-loaded live in-region with capacity"
        );
        // No host in an empty region.
        assert!(place_project(&hosts, &load, "north", now, 15).is_none());
    }

    #[test]
    fn reassign_plan_spreads_orphans_across_live_in_region() {
        let now = 1000;
        let hosts = vec![
            test_host("dead", "east", 900, 0), // dead owner of the orphans
            test_host("a", "east", 995, 0),
            test_host("b", "east", 995, 0),
        ];
        // Two orphans, both previously on the dead east host → spread across a and b.
        let allocs = vec![test_alloc("p1", "dead"), test_alloc("p2", "dead")];
        let orphaned = vec!["p1".to_string(), "p2".to_string()];
        let plan = reassign_plan(&orphaned, &hosts, &allocs, now, 15);
        let targets: HashSet<&str> = plan.iter().map(|(_, h)| h.as_str()).collect();
        assert_eq!(plan.len(), 2);
        assert_eq!(
            targets,
            HashSet::from(["a", "b"]),
            "spread, not piled onto one host"
        );
    }

    #[test]
    fn deploy_target_routes_by_ownership() {
        let now = 1000;
        let hosts = vec![
            test_host("me", "east", 995, 0),
            test_host("peer", "east", 995, 0),
        ];
        // No allocation (first deploy) → local.
        assert_eq!(
            deploy_target(None, &hosts, "me", now, 15),
            DeployTarget::Local
        );
        // Unplaced (empty host_id) → local.
        assert_eq!(
            deploy_target(Some(&test_alloc("p", "")), &hosts, "me", now, 15),
            DeployTarget::Local
        );
        // Owned by me → local.
        assert_eq!(
            deploy_target(Some(&test_alloc("p", "me")), &hosts, "me", now, 15),
            DeployTarget::Local
        );
        // Owned by a live peer → forward.
        assert!(matches!(
            deploy_target(Some(&test_alloc("p", "peer")), &hosts, "me", now, 15),
            DeployTarget::Remote { ref host_id, .. } if host_id == "peer"
        ));
        // Owned by a host that is gone (not in HOSTS / dead) → fail closed.
        assert!(matches!(
            deploy_target(Some(&test_alloc("p", "ghost")), &hosts, "me", now, 15),
            DeployTarget::OwnerDead { ref host_id } if host_id == "ghost"
        ));
    }

    #[test]
    fn reconcile_plan_orphans_only_projects_on_dead_hosts() {
        // HA P3: the leader's desired-vs-running drift. A deployed, wakeable project is
        // orphaned iff its owning host is no longer live; unplaced (empty host_id),
        // live-owned, never-deployed, and non-wakeable projects are left alone.
        let proj = |id: &str, ver: Option<u64>, state: ProjectState| Project {
            id: id.into(),
            name: id.into(),
            tenant_id: Some("t".into()),
            current_version: ver,
            state,
            vm_ip: None,
            domains: vec![],
        };
        let alloc = |pid: &str, host: &str| VmAllocation {
            project_id: pid.into(),
            ip: "172.16.0.2".into(),
            tap_device: "tap".into(),
            mac: "AA".into(),
            host_id: host.into(),
            placement_epoch: 1,
        };
        let host = |id: &str, hb: u64| HostRecord {
            host_id: id.into(),
            region: "r".into(),
            public_addr: None,
            last_heartbeat: hb,
            cpu_template_id: None,
            kernel_id: None,
            capacity: HostCapacity::default(),
        };
        let now = 1000;
        let projects = vec![
            proj("on-dead", Some(1), ProjectState::Hibernated), // owner dead → orphan
            proj("on-live", Some(1), ProjectState::Active),     // owner live → ok
            proj("unplaced", Some(1), ProjectState::Hibernated), // empty host_id → ok
            proj("undeployed", None, ProjectState::Active),     // no version → ignored
            proj("needs", Some(1), ProjectState::NeedsRedeploy), // not wakeable → ignored
        ];
        let allocs = vec![
            alloc("on-dead", "host-dead"),
            alloc("on-live", "host-live"),
            alloc("unplaced", ""),
            alloc("needs", "host-dead"),
        ];
        let hosts = vec![host("host-live", 995), host("host-dead", 970)]; // dead = 30s stale
        let plan = reconcile_plan(&projects, &allocs, &hosts, now, 15);
        assert_eq!(plan.orphaned, vec!["on-dead".to_string()]);
    }

    #[test]
    fn dead_hosts_flags_only_stale_peers() {
        // HA P3: the leader treats a peer as dead only when its heartbeat is genuinely
        // stale — never itself, and never a just-registered peer that hasn't beat yet.
        let h = |id: &str, hb: u64| HostRecord {
            host_id: id.into(),
            region: "r".into(),
            public_addr: None,
            last_heartbeat: hb,
            cpu_template_id: None,
            kernel_id: None,
            capacity: HostCapacity::default(),
        };
        let now = 1000;
        let hosts = vec![
            h("self", 999),  // me — excluded even though "fresh"
            h("fresh", 990), // 10s ago, within threshold → alive
            h("stale", 980), // 20s ago, past 15s → dead
            h("never", 0),   // registered, never beat → excluded (not a false positive)
        ];
        let dead: Vec<&str> = dead_hosts(&hosts, now, 15, "self")
            .iter()
            .map(|h| h.host_id.as_str())
            .collect();
        assert_eq!(dead, vec!["stale"]);
    }

    #[test]
    fn renew_evaluation_discriminates_fenced_from_transient() {
        // The HIGH-fix core (HA P2): a renew error must NOT be treated uniformly — a
        // transient blip/timeout must never self-fence a live VM / flap leadership, and the
        // deadline is anchored at the LAST SUCCESS (the clock the lease TTL runs on).
        let deadline = Duration::from_secs(12);
        let t0 = Instant::now();
        let tok = FenceToken {
            scope: "disk-p".into(),
            epoch: 1,
            holder: "host-a".into(),
            source_id: "cluster".into(),
        };
        let ok: Result<FenceToken, SubstrateError> = Ok(tok);
        let fenced: Result<FenceToken, SubstrateError> = Err(SubstrateError::Fenced {
            scope: "disk-p".into(),
        });
        // A timed-out renew is surfaced as Backend, indistinguishable here from any blip.
        let transient: Result<FenceToken, SubstrateError> = Err(SubstrateError::Backend(
            "etcd unreachable / timed out".into(),
        ));

        // A confirmed renew holds (resets the last-success clock).
        assert_eq!(evaluate_renew(&ok, t0, t0, deadline), FenceDecision::Hold);
        // A genuine supersession fences IMMEDIATELY, even just after a success.
        assert_eq!(
            evaluate_renew(&fenced, t0, t0 + Duration::from_secs(1), deadline),
            FenceDecision::FenceNow
        );
        // A fresh transient blip (last success just now) → keep waiting; one dropped
        // packet never kills a live VM.
        assert_eq!(
            evaluate_renew(&transient, t0, t0, deadline),
            FenceDecision::KeepWaiting
        );
        // Transient, last success still within the deadline → keep waiting.
        assert_eq!(
            evaluate_renew(&transient, t0, t0 + Duration::from_secs(11), deadline),
            FenceDecision::KeepWaiting
        );
        // Transient and last success aged past the deadline → fail closed before the
        // lease TTL can expire and admit a survivor.
        assert_eq!(
            evaluate_renew(&transient, t0, t0 + Duration::from_secs(12), deadline),
            FenceDecision::FenceNow
        );
    }

    #[test]
    fn self_fence_guard_only_fences_the_exact_lost_token() {
        // The split-brain safety guard (HA P2): fence ONLY the holder of the precise
        // token whose renewal was lost, so a redeploy that rotated the token (a live,
        // freshly-attached VM) is never killed.
        let tok = |scope: &str, epoch: u64| FenceToken {
            scope: scope.into(),
            epoch,
            holder: "host-a".into(),
            source_id: "src".into(),
        };
        let mut tokens: HashMap<String, FenceToken> = HashMap::new();
        tokens.insert("p".to_string(), tok("p", 1));

        // Exact token still held → fence it.
        assert!(token_still_held(&tokens, "p", &tok("p", 1)));
        // Rotated by a redeploy (higher epoch) → do NOT fence (would kill the live VM).
        assert!(!token_still_held(&tokens, "p", &tok("p", 2)));
        // Same epoch but different holder/source → not the same token → do not fence.
        assert!(!token_still_held(
            &tokens,
            "p",
            &FenceToken {
                scope: "p".into(),
                epoch: 1,
                holder: "host-b".into(),
                source_id: "src".into()
            }
        ));
        // Already torn down → nothing to fence.
        tokens.remove("p");
        assert!(!token_still_held(&tokens, "p", &tok("p", 1)));
    }

    #[tokio::test]
    async fn disk_lease_renewal_signals_loss_after_release() {
        // The self-fence trigger (HA P2): while we hold the disk lease, renew succeeds;
        // once it is lost (here: released ≈ superseded by a survivor / expired under a
        // partition), renew fails — that Err is what drives self_fence_project.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let leases = std::env::temp_dir().join(format!("jkbase-diskfence-{nanos}"));
        let l = jkbase_substrate::FlockLease::open(leases.clone(), "host-a").unwrap();
        let t = l.acquire("proj-x", "host-a", DISK_LEASE_TTL).await.unwrap();
        assert!(
            l.renew(&t, DISK_LEASE_TTL).await.is_ok(),
            "held → renew succeeds (no fence)"
        );
        l.release(&t).await.unwrap();
        assert!(
            l.renew(&t, DISK_LEASE_TTL).await.is_err(),
            "lost → renew fails → self-fence fires"
        );
        let _ = std::fs::remove_dir_all(&leases);
    }

    #[test]
    fn cron_parse_5field_and_due_since() {
        // 5-field UNIX cron parses (via the "0 " seconds shim); junk + wrong
        // arity do not.
        assert!(parse_unix_5field("*/5 * * * *").is_ok());
        assert!(parse_unix_5field("0 9 * * *").is_ok());
        assert!(parse_unix_5field("not a cron").is_err());
        assert!(parse_unix_5field("*/5 * * *").is_err()); // only 4 fields

        // 2021-01-01T00:00:00Z. Occurrences are strictly AFTER last_run, so the
        // 00:00:00 instant itself is excluded.
        let base: u64 = 1_609_459_200;
        let due = due_since(
            &parse_unix_5field("*/5 * * * *").unwrap(),
            base,
            base + 12 * 60,
        );
        assert_eq!(due, vec![base + 5 * 60, base + 10 * 60]);
        // The loop fires only the latest (collapse-to-one catch-up).
        assert_eq!(due.last().copied(), Some(base + 10 * 60));

        // Window with no occurrence yields nothing (a daily cron over one minute).
        let none = due_since(&parse_unix_5field("0 0 * * *").unwrap(), base, base + 60);
        assert!(none.is_empty());
    }

    #[test]
    fn project_can_wake_requires_content_or_restorable_snapshot() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("jkbase-cw-{nanos}"));
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let store = Store::open(&root.join("s.redb")).unwrap();
        let snap_meta = |id: &str, sp: PathBuf, mp: PathBuf| SnapshotMeta {
            project_id: id.into(),
            snapshot_path: sp.to_string_lossy().into_owned(),
            mem_file_path: mp.to_string_lossy().into_owned(),
            created_at: 0,
            vcpu_count: 1,
            mem_size_mib: 1024,
            base_rootfs_hash: None,
            deployment_version: None,
        };

        // Nothing on disk, no snapshot → cannot wake.
        assert!(!project_can_wake(&data, &store, "p"));

        // Cold-boot content present (hosting/{id}/live) → can wake.
        std::fs::create_dir_all(data.join("hosting").join("p").join("live")).unwrap();
        assert!(project_can_wake(&data, &store, "p"));

        // Content image + a snapshot whose files BOTH exist → can restore → can wake.
        std::fs::create_dir_all(data.join("content-images")).unwrap();
        std::fs::write(data.join("content-images").join("q.ext4"), b"x").unwrap();
        let qsnap = data.join("snapshots").join("q");
        std::fs::create_dir_all(&qsnap).unwrap();
        std::fs::write(qsnap.join("snapshot"), b"s").unwrap();
        std::fs::write(qsnap.join("mem"), b"m").unwrap();
        store
            .save_snapshot_meta(&snap_meta("q", qsnap.join("snapshot"), qsnap.join("mem")))
            .unwrap();
        assert!(project_can_wake(&data, &store, "q"));

        // nlnwt's failure mode: a content image present but the snapshot files are gone
        // and there's no cold-boot content → CANNOT wake (needs redeploy).
        std::fs::write(data.join("content-images").join("r.ext4"), b"x").unwrap();
        let rsnap = data.join("snapshots").join("r");
        store
            .save_snapshot_meta(&snap_meta("r", rsnap.join("snapshot"), rsnap.join("mem")))
            .unwrap();
        assert!(!project_can_wake(&data, &store, "r"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dedicated_tier_parsing_is_fail_safe_and_drives_reach_target() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data = std::env::temp_dir().join(format!("jkbase-tier-{nanos}"));
        let live = |id: &str| data.join("hosting").join(id).join("live");
        let write_db = |id: &str, json: &str| {
            std::fs::create_dir_all(live(id)).unwrap();
            std::fs::write(live(id).join("_database.json"), json).unwrap();
        };

        // No _database.json → co-located (a project with no managed DB).
        assert!(!project_is_dedicated(&data, "none"));
        assert_eq!(db_reach_target_vm(&data, "none"), "none");

        // Explicit dedicated → the reach target is the DB VM.
        write_db("ded", r#"{"engine":"rhypedb","schema":"s.rhype","tier":"dedicated"}"#);
        assert!(project_is_dedicated(&data, "ded"));
        assert_eq!(db_reach_target_vm(&data, "ded"), "ded.db");

        // Explicit colocated, absent tier, and a garbage value all fail SAFE to co-located
        // (the app VM), so a malformed tier never silently routes reach at a nonexistent VM.
        write_db("colo", r#"{"engine":"rhypedb","schema":"s.rhype","tier":"colocated"}"#);
        write_db("notier", r#"{"engine":"rhypedb","schema":"s.rhype"}"#);
        write_db("junk", r#"not even json"#);
        for id in ["colo", "notier", "junk"] {
            assert!(!project_is_dedicated(&data, id), "{id} must be co-located");
            assert_eq!(db_reach_target_vm(&data, id), id);
        }

        let _ = std::fs::remove_dir_all(&data);
    }
}
