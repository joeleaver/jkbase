mod auth_service;
mod build_ca;
mod build_cache;
mod build_orchestrator;
mod build_reaper;
mod build_mem_budget;
mod build_sizing;
mod db_backup_store;
mod db_admin;
mod db_ops;
use crate::metering_loop::metering_loop;
use crate::scheduler::scheduler_loop;
use crate::log_shipper::log_shipper_loop;
use crate::deploy_gate::{deploy_refusal, record_deployed_tier};
use crate::project_facts::{check_project_has_database, check_project_has_volumes, db_reach_target_vm, deployment_has_database, deployment_is_dedicated, project_db_rules_enabled, project_is_dedicated};
use crate::data_disk::{data_disk_mib, disk_cap_bytes, fence_data_disk, migrate_legacy_data_disks, release_data_disk};
use crate::tap::{ensure_runtime_source_guard_chain, runtime_ebtables_lock, setup_tap, teardown_tap};
use crate::ha_placement::{DEAD_HOST_THRESHOLD, DeployTarget, deploy_target, host_heartbeat_loop, reconcile_loop};
use crate::ha_lease::{DISK_LEASE_TTL, disk_fence_loop, leader_election_loop};
use crate::l4_ports::read_l4_port_decls;
use crate::platform::{Incarnations, PlatformState, RUNTIME_CGROUP_PARENT, VmLifecycle, lifecycle_in_flight, settle_superseded_hibernate, unix_now};
use crate::cli::{Args, resolve_guest_kernel, resolve_hostname, validate_substrate_selection};
use db_ops::{
    DB_BACKUP_MAX_CONCURRENT, DbBackupCtx, DbQueryCtx, db_backup_nightly_loop, do_db_query,
    run_db_backup, run_db_restore,
};
mod db_gateway;
mod dns_forwarder;
mod egress;
mod handoff;
mod l4_runtime;
mod layer_plan;
mod log_shipper;
mod metering;
mod mirror;
mod objectstore_service;
mod rootfs_cas;
mod socket_activation;
mod vm_identity;
mod metering_loop;
mod scheduler;
mod deploy_gate;
mod project_facts;
mod data_disk;
mod tap;
mod ha_placement;
mod ha_lease;
mod l4_ports;
mod platform;
mod cli;

use anyhow::{Context, Result};
use clap::Parser;
use jkbase_common::config::PlatformEgress;
use jkbase_control::api::{self, AppState};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{
    DomainKind, DomainRecord, DomainStatus, HostCapacity, HostRecord,
    ProjectState, SnapshotMeta, Store, VmAllocation,
};
use jkbase_orch::rootfs;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_proxy::tls::CertManager;
use jkbase_proxy::{
    self, ActivityTracker, DomainMap, DomainTarget, ProxyConfig, new_domain_map, new_routing_table,
};
use jkbase_substrate::{
    DataDiskProvider, FlockLease, Lease, LocalLoop, SubstrateError,
};
use log_shipper::LogShipper;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

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
    let auth_shutdown = tokio_util::sync::CancellationToken::new();
    let storage_join = {
        let storage_tok = storage_shutdown.clone();
        let svc = Arc::new(objectstore_service::ObjectStoreService::new(
            data_dir.clone(),
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
    };
    // jkbase-Auth issuer service (P3): same in-process loopback model as the object store — the
    // proxy's `auth.{domain}` reserved-host branch forwards to it; it is never reachable off
    // loopback (P0 invariant). It signs per-project JWTs with host-held private keys.
    let auth_join = {
        let auth_tok = auth_shutdown.clone();
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
        vm_incarnations: Incarnations::default(),
        vm_rootfs_hashes: HashMap::new(),
        wake_failures: HashMap::new(),
        db_boots: HashMap::new(),
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

    let store_for_builds = store.clone();
    // Keep a `store` handle after this move: the managed-DB reach-plane auth callback
    // (built below) closes over a clone.
    let mut state = AppState::new(store.clone(), log_store.clone(), deploy_dir);
    state.routing_table = Some(routing_table.clone());
    state.domain_map = Some(domain_map.clone());
    state.platform_domain = args.domain.clone();
    state.admin_token = args.admin_token.clone();
    if let Some(ref cm) = cert_manager {
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

    let platform_for_precheck = platform.clone();
    state.deploy_precheck_callback = Some(Box::new(
        move |project_id: String, deployment_dir: PathBuf| {
            let platform = platform_for_precheck.clone();
            Box::pin(async move {
                let plat = platform.lock().await;
                deploy_refusal(&plat, &project_id, &deployment_dir).await
            })
        },
    ));

    let platform_for_teardown = platform.clone();
    state.teardown_callback = Some(Box::new(move |project_id: String| {
        let platform = platform_for_teardown.clone();
        Box::pin(async move { handle_teardown(&project_id, &platform).await })
    }));

    let platform_for_db_drop = platform.clone();
    state.db_drop_callback = Some(Box::new(move |project_id: String| {
        let platform = platform_for_db_drop.clone();
        Box::pin(async move { drop_dedicated_db(&project_id, &platform).await })
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
    // Reap build VMs a previous process left running (an upgrade restart keeps VMs up for
    // zero-bounce, and nothing re-adopts a build): kill, un-TAP and un-jail them BEFORE any
    // egress proxy binds or the memory budget admits a build, so an orphan can neither reach
    // the new proxies nor hold memory the fresh budget doesn't count. Runtime VMs untouched.
    build_reaper::reap_orphan_builds(&build_reaper::ReapPaths::host(
        Path::new("/sys/fs/cgroup"),
        "jkbase-build",
        &data_dir.join("bj"),
    ))
    .await;
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
    // The default build VM (see the sizing note on `BuildDeps` below) and the host-wide budget
    // every build VM reserves from. A budget that can't fit even one default VM would fail
    // every build at runtime, so it is refused here instead.
    const BUILD_VM_MEM_MIB: u32 = 4096;
    const BUILD_VM_CGROUP_MEM_BYTES: u64 = 4608 * 1024 * 1024;
    const BUILD_VM_TIMEOUT: Duration = Duration::from_secs(900);
    let default_build_vm =
        build_sizing::size_for(BUILD_VM_MEM_MIB, BUILD_VM_CGROUP_MEM_BYTES, None);
    if args.build_mem_budget_mib < default_build_vm.reserve_mib() {
        anyhow::bail!(
            "--build-mem-budget-mib {} is smaller than one default build VM ({} MiB)",
            args.build_mem_budget_mib,
            default_build_vm.reserve_mib()
        );
    }
    // The fairest waiter waits at most for the running VMs to exit (one build-VM timeout), so
    // a wait of twice that only expires behind a real backlog.
    let build_mem_budget = Arc::new(build_mem_budget::BuildMemBudget::new(
        args.build_mem_budget_mib,
        2 * BUILD_VM_TIMEOUT,
    ));
    info!(
        budget_mib = build_mem_budget.total_mib(),
        "build-memory budget"
    );
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
        timeout: BUILD_VM_TIMEOUT,
        vcpu_count: 4,
        mem_size_mib: BUILD_VM_MEM_MIB,
        cgroup_pids_max: 1024,
        cgroup_mem_max_bytes: BUILD_VM_CGROUP_MEM_BYTES,
        cgroup_cpu_max: "400000 100000".to_string(),
        scratch_size_bytes: 4096 * 1024 * 1024,
        output_size_bytes: 1024 * 1024 * 1024,
        console_log_max_bytes: 1024 * 1024,
        max_concurrent: 4,
        mem_budget: build_mem_budget.clone(),
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
        // Console DB tools (query / schema / status / rewrite-covers) — a SYNCHRONOUS proxy (the
        // caller blocks on the result), unlike the fire-and-forget backup/restore callbacks.
        // Captures the wake inputs + store directly, plus the relay registry the rewrite pass
        // holds the DB VM warm through.
        let ctx = DbQueryCtx {
            platform: platform.clone(),
            routing: routing_table.clone(),
            domains: domain_map.clone(),
            shipper: log_shipper.clone(),
            store: state.store.clone(),
            relays: db_relay_registry.clone(),
            rewriting: Arc::new(std::sync::Mutex::new(HashSet::new())),
        };
        let cb: jkbase_control::api::DbQueryCallback = Arc::new(
            move |project_id: String, op: jkbase_control::api::DbQueryOp| {
                let ctx = ctx.clone();
                Box::pin(async move { do_db_query(ctx, project_id, op).await })
            },
        );
        state.db_query_callback = Some(cb);
    }

    let state = Arc::new(state);
    let router = api::router(state, args.domain.clone());

    // The proxy's two wake seams: HTTP/WebSocket routing wakes the APP VM (it forwards the request
    // to the returned IP); the `jkbase-db` edge wakes the VM serving the managed DB.
    let wake_callback = app_wake_callback(
        platform.clone(),
        routing_table.clone(),
        domain_map.clone(),
        log_shipper.clone(),
    );
    let db_wake_callback = db_reach_wake_callback(
        platform.clone(),
        routing_table.clone(),
        domain_map.clone(),
        log_shipper.clone(),
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
        auth_addr: Some(format!("127.0.0.1:{}", args.auth_port)),
        domains: Some(domain_map.clone()),
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
    // Only now is the domain map authoritative: stop serving cached certs for hosts
    // that are no longer Active domains (e.g. rows the boot purge just removed).
    if let Some(ref cm) = cert_manager {
        cm.unload_unmapped_certs().await;
    }

    let proxy_tok = proxy_shutdown.clone();
    let proxy_join = tokio::spawn(async move {
        if let Err(e) = jkbase_proxy::serve(proxy_config, proxy_routes, proxy_tok).await {
            tracing::error!(error = %e, "proxy error");
        }
    });

    // P2 §7.6 — the app→DB in-guest leg's host gateway. Lets a dedicated project's app VM reach
    // its sibling DB VM on the same `127.0.0.1:4200/4201` as co-located, host-mediated over the
    // bridge gateway IP and authenticated by the guest's unforgeable source IP. Best-effort bind
    // (see `db_gateway::serve`); it wakes like the proxy's DB edge (the dedicated `.db` target).
    {
        let store = store.clone();
        let gw_wake = db_reach_wake_callback(
            platform.clone(),
            routing_table.clone(),
            domain_map.clone(),
            log_shipper.clone(),
        );
        let registry = db_relay_registry.clone();
        // This host's id — the gateway resolves peer_ip→project only among THIS host's allocations
        // ([R3], HA IP-collision safety); empty on single-node/pre-HA (matches every alloc).
        let gw_host_id = platform.lock().await.host_id.clone();
        tokio::spawn(async move { db_gateway::serve(store, gw_wake, registry, gw_host_id).await });
    }

    // Host DNS forwarder — answers runtime-guest `/etc/resolv.conf` queries on `172.16.0.1:53` and
    // relays them to the host's own resolver. Replaces systemd-resolved's `DNSStubListenerExtra`
    // (setup-bridge.sh removes the drop-in + restarts resolved to hand off the port in the server's
    // ExecStartPre), so DNS is jkbase-owned: bound to this process (no boot-order race), per-guest
    // rate-limited, logged, and attributed by unforgeable source IP. Best-effort bind (mirrors the
    // DB gateway). NOT a containment boundary — server-app egress is open NAT — it is observability
    // + abuse-control + listener ownership (see dns_forwarder.rs).
    {
        let store = store.clone();
        let dns_host_id = platform.lock().await.host_id.clone();
        tokio::spawn(async move { dns_forwarder::serve(store, dns_host_id).await });
    }

    // L4 UDP scale-to-zero ingress — the plane-global throttle/egress controller + the reconcile
    // loop that materializes `[l4.*]` port allocations into live edge sockets + the datagram pump.
    // The plane is shared with the idle + metering loops (they read its established-flow gauge,
    // last-activity clock, drop counters, and reflection-suspected kill-switch flags). It wakes the
    // APP VM like HTTP routing does — L4 ports are app-VM only, so a dedicated project's DB VM must
    // never receive its datagrams; Axis-1/Axis-2 abuse bounds live inside the plane + pump, keyed on base-project/tenant/dest-IP
    // — never the spoofable source (design §3(c)).
    // Live L4 ports, so an UPGRADE shutdown can hand its flow identities to the successor: the
    // tenant VM survives a zero-bounce restart, so its agent still holds every loopback socket, and
    // resuming the identities is what keeps the app-visible tuples from moving underneath it.
    let l4_registry: l4_runtime::L4PortRegistry = Default::default();
    let l4_plane: Arc<jkbase_proxy::l4_plane::L4Plane> = {
        let l4_wake = app_wake_callback(
            platform.clone(),
            routing_table.clone(),
            domain_map.clone(),
            log_shipper.clone(),
        );
        let plane = jkbase_proxy::l4_plane::L4Plane::new(Default::default(), l4_wake);
        let (l4_host_id, l4_data_dir) = {
            let plat = platform.lock().await;
            (plat.host_id.clone(), plat.data_dir.clone())
        };
        tokio::spawn(l4_runtime::serve(
            store.clone(),
            routing_table.clone(),
            plane.clone(),
            l4_host_id,
            l4_data_dir.clone(),
            l4_registry.clone(),
        ));
        plane
    };

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
            Some(l4_plane.clone()),
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
        Some(l4_plane.clone()),
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
            auth_shutdown.clone(),
            upgrade_kind.clone(),
            l4_registry.clone(),
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
            let _ = auth_join.await; // axum jkbase-auth graceful drain returns
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

#[allow(clippy::too_many_arguments)]
async fn shutdown_signal(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    proxy_shutdown: tokio_util::sync::CancellationToken,
    storage_shutdown: tokio_util::sync::CancellationToken,
    auth_shutdown: tokio_util::sync::CancellationToken,
    upgrade_kind: Arc<std::sync::atomic::AtomicBool>,
    l4_registry: l4_runtime::L4PortRegistry,
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
        // Hand our L4 flow identities to the successor BEFORE draining, so a slow drain or the
        // DRAIN_GRACE watchdog can never exit past it. Only on THIS branch: a real shutdown
        // hibernates the VMs, so there is no surviving agent to resume against and a hand-off
        // would be a lie. Best-effort — a failure costs tuple continuity for one upgrade, never
        // correctness.
        // Best-effort AND panic-proof: this runs upstream of `upgrade_kind`, the drain and the
        // DRAIN_GRACE watchdog, so an unwind here would escape into `main`, run `PlatformState`'s
        // destructors and SIGKILL every survivor. Catch it and carry on with the upgrade.
        use futures_util::FutureExt as _;
        if std::panic::AssertUnwindSafe(l4_runtime::snapshot_handover(&l4_registry, &data_dir))
            .catch_unwind()
            .await
            .is_err()
        {
            tracing::error!("l4 handover: snapshot panicked — continuing the upgrade without it");
        }
        proxy_shutdown.cancel();
        storage_shutdown.cancel();
        auth_shutdown.cancel();
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

    // Normal shutdown: the VMs hibernate, so no agent survives to resume against. Drop any
    // hand-off rather than leaving the client 5-tuples of every live session on disk.
    l4_runtime::handover::discard(&data_dir);
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
            None,
        )
        .await
        {
            // hibernate_project self-cleans its own wedge/timeout paths; this is a
            // last-resort catch for an unexpected Err, routed through the same helper.
            tracing::error!(project = %project_id, error = %e, "hibernate errored, force stopping");
            force_stop_and_cleanup(project_id, &platform, None).await;
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
            plat.vm_incarnations.retire(project_id);
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
            // Free the project's L4 public ports, quarantining each so a stale client of the
            // torn-down tenant can't later be admitted into a reused port's new owner
            // [threat M1]. (The edge socket + firewall teardown land with the runtime relay.)
            for port in plat
                .store
                .list_port_allocations_for_project(project_id)
                .unwrap_or_default()
            {
                let _ = plat.store.quarantine_port(port.external_port, unix_now());
            }
            let _ = plat.store.remove_all_port_allocations(project_id);
            let _ = plat.store.delete_l4_transit_secret(project_id);
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

/// The tenant's explicit drop of its dedicated DB (`DELETE /projects/{id}/db/dedicated`; the
/// control plane holds the per-project deploy lock around this). Reaps the sibling DB VM and its
/// `{id}.db.img` disk; the app VM and its disk (where a co-located DB lives) are never touched.
///
/// Unlike project teardown, the project lives on — DB wakes (gateway / `*.db` edge / console /
/// backup executors) keep arriving, and a wake-path cold boot runs `boot_db_vm` outside the deploy
/// lock. Destroying the disk under a boot that has fenced it but not yet started Firecracker would
/// let that FC boot on a freed loop device another project may since hold (cross-tenant write);
/// freeing the allocation under a boot that already read it would hand its IP/TAP to another VM.
/// So the reap happens in ONE locked section (no new wake can begin) and only when:
/// - no wake/hibernate of the DB VM is mid-flight (`Waking`/`Hibernating` — set and cleared only by
///   that driver, which holds the allocation from before its fence to its commit), waited out;
/// - no `boot_db_vm` is in flight ([`PlatformState::db_boots`]), likewise waited out;
/// - and the DISK LEASE is ours — the running DB VM's token (then nothing else can be fencing), or
///   one we acquire now (any fence in flight holds it ⇒ `LeaseHeld`). The lease is the actual
///   fence-exclusion invariant; the two checks above keep the allocation safe.
///
/// Anything still mid-flight after the wait ⇒ `Busy` with nothing touched (retryable 409).
async fn drop_dedicated_db(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
) -> Result<jkbase_control::api::DbDropOutcome> {
    use jkbase_control::api::DbDropOutcome;
    let db_id = vm_identity::vm_id(project_id, vm_identity::VmRole::Db);
    let mut attempt = 0;
    let (alloc, data_dir) = loop {
        let mut plat = platform.lock().await;
        let in_flight = matches!(
            plat.vm_states.get(&db_id),
            Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
        ) || plat.db_boots.get(&db_id).is_some_and(|n| *n > 0);
        if in_flight {
            drop(plat);
            if attempt >= 150 {
                return Ok(DbDropOutcome::Busy);
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        let present = plat.vms.contains_key(&db_id)
            || plat.store.get_vm_allocation(&db_id)?.is_some()
            || plat.data_disk.exists(&db_id).await.unwrap_or(false);
        if !present {
            return Ok(DbDropOutcome::NothingToDrop);
        }
        // Not running on our token ⇒ take the lease ourselves for the destroy, or stand down.
        let own_token = if plat.disk_tokens.contains_key(&db_id) {
            None
        } else {
            let (ls, hid) = (plat.lease.clone(), plat.host_id.clone());
            match ls.acquire(&db_id, &hid, DISK_LEASE_TTL).await {
                Ok(t) => Some(t),
                Err(SubstrateError::LeaseHeld { .. }) => {
                    return Ok(DbDropOutcome::Busy);
                }
                Err(e) => anyhow::bail!("lease acquire for {db_id}: {e}"),
            }
        };
        info!(project = %project_id, db_vm = %db_id, "dropping dedicated DB VM + disk (tenant request)");
        let reaped = reap_db_vm_locked(&mut plat, &db_id).await;
        if let Some(t) = own_token {
            let _ = plat.lease.release(&t).await;
        }
        break reaped;
    };
    finish_db_vm_teardown(&db_id, alloc, &data_dir).await;
    Ok(DbDropOutcome::Dropped)
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
        reap_db_vm_locked(&mut plat, &db_id).await
    };
    finish_db_vm_teardown(&db_id, alloc, &data_dir).await;
}

/// The locked half of [`teardown_db_vm_sibling`]: stop + hard-kill the DB VM, release its lease,
/// destroy its disk, drop its lifecycle/snapshot/allocation rows. Runs in ONE locked section so no
/// wake can interleave (a wake needs the lock to set `Waking`). Returns what the unlocked
/// [`finish_db_vm_teardown`] needs.
async fn reap_db_vm_locked(
    plat: &mut PlatformState,
    db_id: &str,
) -> (Option<VmAllocation>, PathBuf) {
    if let Some(mut vm) = plat.vms.remove(db_id) {
        let _ = vm.stop().await;
    }
    plat.vm_incarnations.retire(db_id);
    // Kill any DB Firecracker not tracked in `vms` BEFORE destroying its disk.
    reap_firecracker(db_id).await;
    handoff::remove(&plat.data_dir.join("run"), db_id);
    if let Some(token) = plat.disk_tokens.remove(db_id) {
        let ls = plat.lease.clone();
        let _ = ls.release(&token).await;
    }
    let dd = plat.data_disk.clone();
    let _ = dd.destroy(db_id).await;
    plat.vm_states.remove(db_id);
    plat.vm_rootfs_hashes.remove(db_id);
    plat.wake_failures.remove(db_id);
    let alloc = plat.store.get_vm_allocation(db_id).ok().flatten();
    let _ = plat.store.remove_snapshot_meta(db_id);
    let _ = plat.store.remove_vm_allocation(db_id);
    (alloc, plat.data_dir.clone())
}

/// The unlocked half of [`teardown_db_vm_sibling`]: free the TAP + remove on-disk artifacts.
async fn finish_db_vm_teardown(db_id: &str, alloc: Option<VmAllocation>, data_dir: &Path) {
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
    // `remove_project_artifacts` for a `.db` id clears content-images/`{id}.db.ext4`,
    // data-disks/`{id}.db.{img,holder}`, snapshots/`{id}.db`, run/`{id}.db`; the base-only trees
    // (hosting/builds/git/buildcache/`{id}.db`) simply don't exist → no-ops.
    remove_project_artifacts(data_dir, db_id).await;
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
    // backup blobs ([RB11]). `buildcache/{id}`: its warm build caches + per-target artifact
    // cache. Delete purges them, but a crash-interrupted teardown can leave them — reap so a
    // recreated slug starts clean (it must never inherit the previous tenant's build
    // artifacts) and a deleted tenant's DB data doesn't linger.
    for sub in ["hosting", "run", "snapshots", "objectstore", "db-backups", "buildcache"] {
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
    let Some(live) =
        baselayers_live_set(&data_dir, &registered, layer_plan::try_read_layer_paths)
    else {
        return;
    };

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

/// The LIVE set of `baselayers/` blob filenames the boot GC must never touch, or `None` ⇒ abort
/// the sweep (a manifest or layer map we can't read). `read_paths` is
/// [`layer_plan::try_read_layer_paths`] in production (`Ok(empty)` for an absent image).
///
/// Every VM a project can boot pins its own blobs, so BOTH metadata images count: the app VM's
/// `{id}.ext4` and a dedicated project's sibling DB VM's `{id}.db.ext4`. The DB image is the ONLY
/// referrer of the `rhypedb` runtime layer for a dedicated project (its app VM is built `AppNoDb`),
/// so skipping it reaped the old engine blob on the first host restart after a rhypedb layer swap
/// — and the DB VM's next cold boot / restore then had no engine layer to attach.
fn baselayers_live_set(
    data_dir: &Path,
    registered: &[String],
    read_paths: impl Fn(&Path) -> Result<Vec<PathBuf>>,
) -> Option<HashSet<String>> {
    let baselayers = data_dir.join("baselayers");
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
        return None;
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

    // (2) Each registered project's CURRENT metadata images (app VM + dedicated DB VM) pin
    //     the exact base/runtime blobs they attach. If a layer map can't be read, abort the
    //     whole sweep (treating it as "references nothing" could reap a blob it still needs).
    let content_images = data_dir.join("content-images");
    let images = registered.iter().flat_map(|id| {
        [vm_identity::VmRole::App, vm_identity::VmRole::Db]
            .map(|role| content_images.join(format!("{}.ext4", vm_identity::vm_id(id, role))))
    });
    for img in images {
        let paths = match read_paths(&img) {
            Ok(p) => p,
            Err(e) => {
                warn!(image = %img.display(), error = %e, "baselayers GC: cannot read layer paths; skipping sweep");
                return None;
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
    Some(live)
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
        // Before anything reads the registry: drop rows a pre-wildcard binary may have
        // left behind across a rollback (proof-less `*` rows, orphaned wildcards).
        match plat.store.purge_invalid_domain_rows() {
            Ok(0) => {}
            Ok(n) => warn!(removed = n, "purged invalid domain rows at boot"),
            Err(e) => tracing::error!(error = %e, "domain-row purge failed"),
        }
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
            map.insert(d.host.clone(), d.target());
            count += 1;
        }
    }
    info!(
        domains = count,
        "domain map built; projects registered for on-demand wake"
    );
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

/// Ensure an Active DomainRecord exists for `host` (idempotent). Used by backfill
/// to migrate pre-registry data without forcing re-verification.
fn grandfather_domain(store: &Store, host: &str, project_id: &str, tenant_id: &str) {
    if matches!(store.get_domain(host), Ok(Some(_))) {
        return;
    }
    // Wildcards postdate the registry, so they are never legacy: a `*.` entry left in
    // a stale `project.domains` cache must NOT come back Active without DNS proof.
    if host.contains('*') {
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
        acme_delegation: None,
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
                    // Nothing touched yet: typed as a refusal so the control plane puts `live`
                    // back on the version the (still-running) old VM serves.
                    return Err(jkbase_control::api::DeployRefused(format!(
                        "project {project_id} busy (wake/hibernate still in flight after ~80s); retry deploy"
                    ))
                    .into());
                }
                drop(plat);
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            break plat;
        }
    };

    // The refusals the control plane already ran against this tree before swapping `live` to it
    // (`deploy_precheck_callback`), re-checked here under the platform lock as the last line
    // before teardown: a refused deploy must leave the running VM untouched. Typed as a refusal
    // (only ever returned from before teardown) so the control plane undoes the `live` swap —
    // e.g. the owner-host gate can flip between the precheck and here.
    let live_dir = plat.data_dir.join("hosting").join(project_id).join("live");
    deploy_refusal(&plat, project_id, &live_dir)
        .await
        .map_err(|e| jkbase_control::api::DeployRefused(format!("{e:#}")))?;

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
    plat.vm_incarnations.retire(project_id);
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
    let disk_cap = disk_cap_bytes(&plat.store, project_id);
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
                    // P4: when the project opts into security rules (`[database].rules`), provision
                    // (if needed) + read its PUBLIC JWKS from the jkbase-Auth signing store and bake
                    // it over this reserved channel so the DB VM's engine verifies end-user JWTs
                    // offline (P0-DBA-2/3) — no network on the query path. `ensure_signing_key`
                    // guarantees a NON-EMPTY key set (the engine refuses to start on an empty JWKS),
                    // so a rules-on DB never boots without a verifier. Best-effort like the rest of
                    // this block: a store error leaves `jwks=None`, and the agent then starts the
                    // engine with RHYPEDB_RULES but no JWKS ⇒ the engine fails CLOSED (refuses to
                    // serve an open DB), never silently rules-off. PUBLIC keys only (P0-AUTH-2).
                    let jwks = if project_db_rules_enabled(&data_dir, project_id) {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let _ = plat.store.ensure_signing_key(project_id, now);
                        plat.store
                            .get_jwks(project_id, now)
                            .ok()
                            .filter(|j| !j.keys.is_empty())
                            .and_then(|j| serde_json::to_string(&j).ok())
                    } else {
                        None
                    };
                    jkbase_common::config::DbReachFacts {
                        splice_secret,
                        admin_token,
                        // Base value (the DB VM's own image keeps this); the app VM's copy is
                        // flipped to `dedicated` below so its agent starts the app→DB loopback proxy.
                        dedicated: false,
                        jwks,
                    }
                })
        } else {
            None
        };

    // Raw L4 (UDP/TCP) ingress: for each `[l4.*]` the tenant declared (baked into the new
    // deploy's `_l4_ports.json`), allocate — or sticky-reuse — the PUBLIC `external_port` +
    // in-VM `agent_udp_port`, and author the host→agent reach facts (`_l4.json`) baked into
    // the image below. Neither host-asserted port is tenant-authored [P0-L4-8]; an admin PIN
    // is a pre-existing pinned allocation honored by `allocate_port`'s stickiness. Per-port
    // best-effort: an allocation failure skips that port (fail-closed — no public port) and
    // never fails the deploy. The public edge socket + firewall open land with the runtime
    // relay (design §3(a)); this slice only reserves the port and delivers the facts.
    let l4_decls = read_l4_port_decls(&data_dir, project_id);
    let l4_facts: Option<jkbase_common::config::L4Facts> = {
        let mut facts = Vec::new();
        for decl in &l4_decls {
            let (name, proto, guest_port) = (&decl.name, decl.proto, decl.guest_port);
            match plat.allocate_port(project_id, name, proto, guest_port, None) {
                Ok(a) => facts.push(jkbase_common::config::L4PortFact {
                    name: a.name,
                    proto: a.proto,
                    agent_udp_port: a.agent_udp_port,
                    guest_port: a.guest_port,
                    // Hand the agent the host's per-port idle window so its own flow reaper can
                    // never evict a still-live flow (return-leg nonce blank on re-wake, W0.1).
                    idle_timeout_secs: decl.idle_timeout_secs,
                }),
                Err(e) => warn!(
                    project = %project_id, l4_port = %name, error = %e,
                    "L4 port allocation failed; skipping (no public port opened this deploy)"
                ),
            }
        }
        if facts.is_empty() {
            None
        } else {
            // Per-VM transit secret (sticky) authenticating the host↔guest datagram leg
            // (§3(a-auth)); baked into `_l4.json` for the agent, read from the store by the
            // host relay. Minted independently of `[database]` — a pure-L4 project has no
            // DB splice secret. A mint error ⇒ empty ⇒ the agent starts no land-forward
            // (fail-closed), never a failed deploy.
            let transit_secret = plat.store.l4_transit_secret(project_id).unwrap_or_default();
            Some(jkbase_common::config::L4Facts {
                ports: facts,
                transit_secret,
            })
        }
    };
    // Reconcile: free + quarantine any previously-allocated port whose `[l4.*]` stanza was
    // REMOVED in this deploy, so a stale client of the gone port can't later be admitted
    // into a reused port's new owner [threat M1].
    {
        let declared: HashSet<&str> = l4_decls.iter().map(|d| d.name.as_str()).collect();
        for old in plat
            .store
            .list_port_allocations_for_project(project_id)
            .unwrap_or_default()
        {
            if !declared.contains(old.name.as_str()) {
                let _ = plat.store.remove_port_allocation(project_id, &old.name);
                let _ = plat.store.quarantine_port(old.external_port, unix_now());
            }
        }
    }
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
        // [R5] On a dedicated app VM the rhypedb admin token is dead weight (no co-located DB to
        // inject it into) — and the app→DB leg makes a baked copy ACTIONABLE: a hostile app VM
        // could read `_db_reach.json` and drive `/admin/*` (backup-stream exfil / restore-tamper)
        // against its sibling DB VM through the leg. Strip it so the dedicated app VM is strictly
        // better-isolated than co-located; only the DB VM's own image (`db_reach_for_db_vm`,
        // where no tenant code runs) carries the token.
        if dedicated {
            r.admin_token.clear();
        }
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
                l4_facts.as_ref(),
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
        let disk_mib = data_disk_mib(&data_dir, project_id, !dedicated, disk_cap).await;
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
    plat.vm_incarnations.commit(project_id);
    // [R4] Stamp the tier this deploy committed so the NEXT deploy can detect an in-place flip.
    // Stamped HERE, at commit-to-Running — not after `wait_for_agent`/`boot_db_vm` — because the
    // VM can already be writing its DB from this point: a later failure leaves this tree live (a
    // failed deploy is not rolled back) and an unstamped project would let the next deploy flip
    // tiers unrefused. A dedicated stamp before its DB VM writes anything can only over-refuse
    // (the safe direction). Record only for a managed-DB project (nothing to strand otherwise),
    // and KEEP the record when a deploy drops `[database]`: the data stays on its tier's disk
    // (neither disk is reaped by a config edit), so re-adding the DB at the OTHER tier is the
    // same stranding flip. Deleting it here let colocated → no DB → dedicated launder past R4.
    // Only project deletion clears it.
    record_deployed_tier(
        &plat.store,
        project_id,
        &plat.data_dir.join("hosting").join(project_id).join("live"),
    );
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

    // Count this boot in flight for its whole life (allocation read → fence → commit), so a
    // tenant's `drop_dedicated_db` can't free the allocation/TAP/disk out from under it. The guard
    // is armed with no await between it and the increment, so a cancellation can never make it
    // decrement a count it didn't add.
    *platform.lock().await.db_boots.entry(db_id.clone()).or_default() += 1;
    let _boot_guard = DbBootGuard::new(platform.clone(), db_id.clone());

    // Snapshot the substrate handles + supersede any prior DB VM (redeploy), then release the lock
    // for the slow build + fence + boot.
    let (disk_cap, data_dir, dd, ls, hid, firecracker_bin, kernel_path, rootfs_path, platform_egress, alloc) = {
        // Wait out an in-flight wake/hibernate OF THE DB VM before superseding it (the caller's
        // `handle_deploy` gate only covers the APP id). Hibernate drops the lock mid-snapshot
        // still holding the disk token while its paused FC maps the disk: releasing that token
        // under it lets our fence hit `RwoUnsafe` → `reap_firecracker` the paused FC, after which
        // hibernate's second section would tear down OUR commit (the incarnation check in
        // `hibernate_project` is the backstop for that; this wait keeps us from causing it). Same
        // ~80s budget as `handle_deploy` (outlasts hibernate's 3s ship + 60s snapshot); on expiry
        // FAIL the boot — the deploy is retryable. We only READ `vm_states` here: this boot never
        // writes a shared `Waking` it doesn't own (that broke the dedicated-DB drop's safety). The
        // wait and the supersede share ONE lock section, so nothing starts between THEM; after it,
        // while we build + fence + boot unlocked, a DB wake may still start (the id is left
        // `Hibernated`/`Running`) — the disk lease is what excludes it (one side fails LeaseHeld,
        // retryably), and a hibernate can't (we removed the VM handle it needs).
        let mut attempt = 0;
        let mut plat = loop {
            let plat = platform.lock().await;
            if !lifecycle_in_flight(plat.vm_states.get(&db_id)) {
                break plat;
            }
            drop(plat);
            if attempt >= 400 {
                anyhow::bail!(
                    "DB VM {db_id} busy (wake/hibernate still in flight after ~80s); retry deploy"
                );
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(200)).await;
        };

        // Supersede a prior DB VM incarnation (redeploy): drop its stale snapshot, stop it, and
        // release its data-disk hold before re-fencing — mirrors the app redeploy path.
        let snapshot_dir = plat.data_dir.join("snapshots").join(&db_id);
        let _ = std::fs::remove_dir_all(&snapshot_dir);
        let _ = plat.store.remove_snapshot_meta(&db_id);
        if let Some(mut old) = plat.vms.remove(&db_id) {
            let _ = old.stop().await;
        }
        plat.vm_incarnations.retire(&db_id);
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
        let disk_cap = disk_cap_bytes(&plat.store, project_id);
        (
            disk_cap,
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
                None, // the DB VM carries no L4 ports (L4 is app-VM only)
                &out,
                layer_plan::ImageContent::DbOnly,
            )?;
            Ok(plan)
        })
        .await
        .context("DB VM metadata image build task")??
    };

    // Fence the DB VM's OWN data disk (`{id}.db.img`), sized from the BASE project's
    // `_database.json` (`[database].size`) within the project-wide storage budget. The `.db`
    // scope is validator-legal (F1).
    let disk_mib = data_disk_mib(&data_dir, &db_id, true, disk_cap).await;
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
    plat.vm_incarnations.commit(&db_id);
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
            acme_delegation: None,
        });
    for d in active_domains {
        table.insert(d.host.clone(), ip.to_string());
        map.insert(d.host.clone(), d.target());
    }
}

async fn hibernate_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    // Idle-path callers pass the DB relay registry + L4 plane so we can re-check for a LIVE
    // managed-DB relay / L4 established flow UNDER the platform lock (§5/§3(d)); shutdown/quota
    // callers pass `None` — those paths hibernate regardless (relays are force-closed on drain;
    // over-quota must win).
    db_registry: Option<&Arc<jkbase_proxy::db_relay::DbRelayRegistry>>,
    l4_plane: Option<&Arc<jkbase_proxy::l4_plane::L4Plane>>,
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
            // §3(d): symmetric L4 re-check — an ESTABLISHED L4 flow that promoted since the idle
            // loop's unlocked read keeps the VM warm, so a live UDP session isn't snapshotted
            // mid-stream. Provisional flows deliberately don't count (they can't pin warm).
            if l4_plane
                .map(|p| p.conn_count(vm_identity::base_project_id(project_id)) > 0)
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
    // Pin the incarnation we're hibernating: we drop the lock below for the pause+snapshot, and
    // every later state write (here and in `force_stop_and_cleanup`) is gated on it still being
    // current — a supersede in that window owns the id's state from then on, not us.
    let incarnation = plat.vm_incarnations.capture(project_id);

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
        // Kill OUR FC synchronously-to-death first (as the snapshot-failure arms do): the cleanup
        // below finds no `vms` handle (we took it) and stands down entirely if we've been
        // superseded, so it can't be relied on to reap this FC — and a bare drop() of an Adopted
        // survivor wouldn't kill it at all.
        let _ = vm.stop().await;
        force_stop_and_cleanup(project_id, &platform, Some(incarnation)).await;
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
            force_stop_and_cleanup(project_id, &platform, Some(incarnation)).await;
            return Ok(());
        }
        Err(_elapsed) => {
            tracing::error!(project = %project_id, "hibernate timed out (VM wedged), force-stopping");
            let _ = vm.stop().await;
            force_stop_and_cleanup(project_id, &platform, Some(incarnation)).await;
            return Ok(());
        }
    };

    let mut plat = platform.lock().await;

    // Superseded mid-snapshot (redeploy / teardown / self-fence retired our incarnation while the
    // lock was down): the id's disk token, VM handle, lifecycle and snapshot meta are no longer
    // ours. Our FC is already dead (hibernate kills it), so touch nothing else — releasing the token
    // would detach a newer live FC's disk, and `Hibernated` + this snapshot would clobber its
    // `Running` and later restore stale RAM against its disk. The snapshot files we just wrote
    // are inert without meta (a wake only restores via meta).
    if !plat.vm_incarnations.is_current(project_id, incarnation) {
        tracing::warn!(project = %project_id,
            "VM superseded mid-hibernate; leaving the newer incarnation's state untouched");
        settle_superseded_hibernate(&mut plat, project_id);
        return Ok(());
    }

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
    // Past this point the FC is dead and its disk released, so a store error must not strand the
    // id in `Hibernating` (wakes would time out on it; deploys + boot_db_vm would wait it out and
    // fail): fail OPEN — no snapshot meta ⇒ the next wake cold-boots — and still settle below.
    if let Err(e) = plat.store.save_snapshot_meta(&meta) {
        tracing::error!(project = %project_id, error = %e,
            "persisting snapshot meta failed; settling Hibernated without a snapshot (cold boot next)");
        let _ = plat.store.remove_snapshot_meta(project_id);
    }

    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Hibernated;
        if let Err(e) = plat.store.update_project(&proj) {
            tracing::warn!(project = %project_id, error = %e, "persisting Hibernated project state failed");
        }
    }

    // Keep TAP device and VmAllocation for fast restore
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Hibernated);
    plat.vm_incarnations.retire(project_id);

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

/// One `boot_db_vm` call's share of [`PlatformState::db_boots`]: `boot_db_vm` increments under its
/// first lock section, this decrements on ANY exit (success, error, cancellation). Drop can't await
/// the async mutex, so the decrement is spawned (eventually-consistent) — a lagging decrement only
/// makes a concurrent drop answer Busy, the safe direction. Armed right after the increment.
struct DbBootGuard {
    platform: Arc<Mutex<PlatformState>>,
    db_id: String,
}

impl DbBootGuard {
    fn new(platform: Arc<Mutex<PlatformState>>, db_id: String) -> Self {
        Self { platform, db_id }
    }
}

impl Drop for DbBootGuard {
    fn drop(&mut self) {
        let platform = self.platform.clone();
        let id = self.db_id.clone();
        tokio::spawn(async move {
            let mut plat = platform.lock().await;
            if let Some(n) = plat.db_boots.get_mut(&id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    plat.db_boots.remove(&id);
                }
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
        // Surface the WAKE_BACKOFF throttle as `RateLimited` (distinct from a transient
        // `Unavailable`) so a rate-cap read is legible in metrics and the L4 wake plane can
        // tell "throttled" from "boot failed" — the design's promote-the-bail delta (§3(c)).
        // `wake_project_inner` keeps its own backoff check as a TOCTOU backstop.
        if let Some(t) = plat.wake_failures.get(project_id)
            && t.elapsed() < WAKE_BACKOFF
        {
            return Err(jkbase_proxy::WakeError::RateLimited(format!(
                "project {project_id} recently failed to wake; retry shortly"
            )));
        }
    }
    wake_project_inner(project_id, platform, routing, domain_map, shipper)
        .await
        .map_err(|e| jkbase_proxy::WakeError::Unavailable(e.to_string()))
}

/// The wake seam for anything that then talks to the project's APP VM — HTTP/WebSocket routing
/// and L4 UDP ingress. Wakes the base project id as-is, so a `tier="dedicated"` project's app VM
/// comes up (never its sibling DB VM — the caller forwards tenant traffic to the returned IP).
fn app_wake_callback(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> jkbase_proxy::WakeCallback {
    Arc::new(move |project_id: String| {
        let (platform, routing, domains, shipper) = (
            platform.clone(),
            routing.clone(),
            domain_map.clone(),
            shipper.clone(),
        );
        Box::pin(
            async move { wake_project(&project_id, platform, routing, domains, shipper).await },
        )
    })
}

/// The wake seam for the managed-DB reach plane (`jkbase-db` edge, app→DB host gateway): follows
/// [`wake_db_reach`] to the VM serving the DB. Never hand this to an app-traffic edge — for a
/// dedicated project it resolves the DB VM, and app traffic would then be forwarded there.
fn db_reach_wake_callback(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> jkbase_proxy::WakeCallback {
    Arc::new(move |project_id: String| {
        let (platform, routing, domains, shipper) = (
            platform.clone(),
            routing.clone(),
            domain_map.clone(),
            shipper.clone(),
        );
        Box::pin(
            async move { wake_db_reach(&project_id, platform, routing, domains, shipper).await },
        )
    })
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
        let target = db_reach_target_vm(&plat.data_dir, project_id);
        // A dedicated DB with no lifecycle state, allocation or disk isn't provisioned: dropped
        // (`jkbase db drop`), or a first deploy hasn't reached `boot_db_vm` yet. Only a deploy
        // provisions it, so don't let every connect re-drive a doomed no-allocation cold boot
        // (`handle_deploy` of the `.db` id) under the platform lock. Transient-shaped (503 +
        // retry), as the first-deploy case resolves on its own.
        if target != project_id
            && !plat.vm_states.contains_key(&target)
            && matches!(plat.store.get_vm_allocation(&target), Ok(None))
            && !plat.data_disk.exists(&target).await.unwrap_or(true)
        {
            return Err(jkbase_proxy::WakeError::Unavailable(format!(
                "the dedicated database of {project_id} isn't provisioned (dropped, or its deploy \
                 is still booting it) — redeploy if it doesn't come up"
            )));
        }
        target
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
    let (mut restore_hash, mut nonviable_outcome) =
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
    let disk_cap = disk_cap_bytes(&plat.store, base_pid);
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
        // Sized from the BASE project's `_database.json` ([database].size) — the DB VM has no
        // `hosting/<id>.db/` — within the project-wide budget; fenced under the RENDERED id.
        let holds_db = vm_role == vm_identity::VmRole::Db || !dedicated;
        let disk_mib = data_disk_mib(&data_dir, project_id, holds_db, disk_cap).await;
        let g = fence_data_disk(&dd, &ls, &hid, project_id, disk_mib).await?;
        config.data_disk_path = Some(g.device());
        // A grown disk can't be restored onto: the snapshot's guest believes the old size and
        // would never grow its fs. Drop the snapshot and cold-boot (the agent grows at mount).
        if g.grown && restore_hash.is_some() {
            restore_hash = None;
            nonviable_outcome = "skipped_disk_grown";
            let _ = platform.lock().await.store.remove_snapshot_meta(project_id);
            let _ = tokio::fs::remove_dir_all(&snapshot_dir).await;
        }
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
    //
    // Look up the BASE project: a dedicated DB VM (`{id}.db`) has no project row of its own, so
    // checking the rendered id aborted EVERY DB-VM wake as "deleted" — a hibernated DB VM could
    // never come back short of a redeploy, and each attempt was a full unthrottled FC boot.
    if plat.store.get_project(base_pid).ok().flatten().is_none() {
        plat.vm_states.remove(project_id);
        plat.vm_rootfs_hashes.remove(project_id);
        // Throttle like any failed wake, so traffic at a deleted project can't drive serial boots.
        plat.wake_failures
            .insert(project_id.to_string(), std::time::Instant::now());
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
    plat.vm_incarnations.commit(project_id);
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
    // The L4 plane contributes its OWN keep-warm signals (an established-flow gauge + an
    // un-throttled last-datagram clock), read here and ANDed into `should_hibernate` — NEVER
    // written back into the shared `activity` tracker, which would back-date another plane's
    // hibernate clock and snapshot an HTTP/DB-active project mid-serve (§3(d) mechanics H5).
    l4_plane: Option<Arc<jkbase_proxy::l4_plane::L4Plane>>,
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
                .unwrap_or(true)
            // §3(d): keep an L4 project warm ONLY while it has an ESTABLISHED flow (a byte-silent
            // but live inbound-only/streaming app stays warm via conn_count > 0). PROVISIONAL
            // (unpromoted, spoofable) flows deliberately do NOT count — they carry their own 5s
            // timeout and must not pin the VM warm, else a spoof flood that never establishes would
            // hold it warm for the full idle_timeout (P0-L4-12 / §3(d)). When established flows
            // drain, conn_count → 0 (the per-port idle sweep evicts them) and the VM hibernates on
            // the normal shared-seed idle path — never back-dating the shared ActivityTracker.
            && l4_plane
                .as_ref()
                .map(|p| p.conn_count(vm_identity::base_project_id(&project_id)) == 0)
                .unwrap_or(true);

            if should_hibernate {
                info!(project = %project_id, "idle timeout, hibernating");
                if let Err(e) = hibernate_project(
                    &project_id,
                    platform.clone(),
                    routing.clone(),
                    shipper.clone(),
                    db_registry.as_ref(),
                    l4_plane.as_ref(),
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
        plat.vm_incarnations.commit(id);
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
///
/// `incarnation`: `Some(n)` when acting for a specific VM (a hibernate that dropped the lock) —
/// if `n` is no longer current, a newer incarnation (or a teardown) owns the id and this only
/// settles our own leftover `Hibernating` ([`settle_superseded_hibernate`]): the pkill/TAP-teardown/
/// token-release below are id-keyed and would hit the NEWER VM. The caller has already stopped its
/// own FC. `None` = unconditional (the shutdown last resort).
async fn force_stop_and_cleanup(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
    incarnation: Option<u64>,
) {
    let mut plat = platform.lock().await;
    if let Some(n) = incarnation
        && !plat.vm_incarnations.is_current(project_id, n)
    {
        tracing::warn!(project = %project_id,
            "VM superseded mid-hibernate; skipping force-stop cleanup of the newer incarnation");
        settle_superseded_hibernate(&mut plat, project_id);
        return;
    }

    // The VM handle may already be gone (hibernate_project removes it before the
    // pause that fails) — stop() it if present, but don't rely on it.
    if let Some(mut vm) = plat.vms.remove(project_id) {
        let _ = vm.stop().await;
    }
    plat.vm_incarnations.retire(project_id);
    plat.vm_rootfs_hashes.remove(project_id);
    // The FC is being reaped below — drop its re-adoption record so a later start can't adopt it.
    // (hibernate_project already removed it before its pause; idempotent if so.)
    handoff::remove(&plat.data_dir.join("run"), project_id);

    // Everything id-keyed — the FC kill, the disk release, the TAP teardown — runs UNDER the lock
    // and BEFORE `Hibernated` is published below: deploy / boot_db_vm / wake treat `Hibernated` as
    // settled and proceed, so a kill or TAP teardown still pending after it could land on the NEXT
    // incarnation's FC/TAP (same socket path, same TAP name). Kill first, then release the disk.
    //
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

    // Release the data-disk hold so the next wake re-fences.
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    // Tear down TAP so cleanup_orphans reconciles consistently on next boot (a
    // leaked-but-listening process would otherwise read as "reachable" and the
    // stale allocation would never be reaped). wake re-runs setup_tap.
    if let Ok(Some(a)) = plat.store.get_vm_allocation(project_id) {
        let _ = teardown_tap(&a.tap_device).await;
    }

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

#[cfg(test)]
mod tests {
    use crate::tap::run_cmd;
    use super::*;

    /// On-box, real Firecracker: a dedicated-DB redeploy (`boot_db_vm`) lands while the DB VM is
    /// mid-`hibernate_project` (lock dropped, paused FC still mapping the disk). Whatever order the
    /// two settle in, the result must be ONE coherent incarnation: the new DB VM `Running`, its VM
    /// handle + disk token present, that token still the live lease holder, the disk attached
    /// exactly once, exactly one FC for the id, its agent serving, and no snapshot meta that a
    /// later wake could restore over it. Pre-fix this broke: the supersede released the paused
    /// FC's token, the fence reaped it, and hibernate's cleanup then tore down the new boot.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/.firecracker JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       JKB_BASELAYERS=/abs/.firecracker/baselayers \
    ///       JKB_ROOTFS=/abs/.firecracker/base-rootfs-verity-cur.ext4 \
    ///       <test-bin> --ignored --nocapture db_vm_redeploy_during_hibernate_onbox
    ///
    /// Needs the runtime bridge `jkbr0` at 172.16.0.1/24 (created + removed here if absent) and
    /// `ebtables` (the TAP source-guard). `JKB_RACE_ROUNDS` (default 3) repeats the race.
    #[tokio::test]
    #[ignore = "on-box: needs KVM + root + baselayers + verity rootfs (JKB_ROOTFS)"]
    async fn db_vm_redeploy_during_hibernate_onbox() {
        let env = |k: &str| std::env::var(k).ok().map(PathBuf::from);
        let (Some(fc_data), Some(fc_release), Some(baselayers), Some(rootfs)) = (
            env("JKB_DATA"),
            env("JKB_FC_RELEASE"),
            env("JKB_BASELAYERS"),
            env("JKB_ROOTFS"),
        ) else {
            eprintln!("skip: set JKB_DATA, JKB_FC_RELEASE, JKB_BASELAYERS, JKB_ROOTFS");
            return;
        };
        let rounds: usize = std::env::var("JKB_RACE_ROUNDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        let kernel = if fc_data.join("vmlinux.bin").exists() {
            fc_data.join("vmlinux.bin")
        } else {
            fc_data.join("vmlinux-6.12.92.bin")
        };

        // Runtime bridge: setup_tap enslaves every TAP to jkbr0.
        let made_bridge = !std::process::Command::new("ip")
            .args(["link", "show", "jkbr0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        if made_bridge {
            run_cmd("ip", &["link", "add", "name", "jkbr0", "type", "bridge"])
                .await
                .unwrap();
            run_cmd("ip", &["addr", "add", "172.16.0.1/24", "dev", "jkbr0"])
                .await
                .unwrap();
            run_cmd("ip", &["link", "set", "jkbr0", "up"])
                .await
                .unwrap();
        }

        // A fresh data dir holding just what boot_db_vm reads: the BASE project's live tree (a
        // DbOnly image needs only `_database.json` + schema) and the shared baselayers store.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!("jkbase-dbrace-{nanos}"));
        let pid = "dbrace";
        let db_id = vm_identity::vm_id(pid, vm_identity::VmRole::Db);
        let live = data_dir.join("hosting").join(pid).join("live");
        std::fs::create_dir_all(live.join("_database")).unwrap();
        std::fs::write(
            live.join("_database.json"),
            r#"{"engine":"rhypedb","schema":"schema.rhype","rules":null,"tier":"dedicated"}"#,
        )
        .unwrap();
        std::fs::write(
            live.join("_database/schema.rhype"),
            "type User {\n    name: String\n}\n",
        )
        .unwrap();
        for d in ["content-images", "run", "snapshots", "logs"] {
            std::fs::create_dir_all(data_dir.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(&baselayers, data_dir.join("baselayers")).unwrap();

        let store = Store::open(&data_dir.join("control.redb")).unwrap();
        store
            .create_project(&jkbase_control::store::Project {
                id: pid.to_string(),
                name: pid.to_string(),
                tenant_id: None,
                current_version: Some(1),
                state: ProjectState::Active,
                vm_ip: None,
                domains: Vec::new(),
            })
            .unwrap();
        // Boot from a CAS-shaped rootfs path so a hibernate's snapshot is restore-viable on wake.
        let rootfs_hash = "a".repeat(64);
        let cas_dir = data_dir.join("base-rootfs");
        std::fs::create_dir_all(&cas_dir).unwrap();
        let cas_rootfs = rootfs_cas::blob_path(&cas_dir, &rootfs_hash);
        std::os::unix::fs::symlink(&rootfs, &cas_rootfs).unwrap();
        let host_id = "dbrace-host".to_string();
        let platform = Arc::new(Mutex::new(PlatformState {
            vms: HashMap::new(),
            vm_states: HashMap::new(),
            vm_incarnations: Incarnations::default(),
            db_boots: HashMap::new(),
            vm_rootfs_hashes: HashMap::new(),
            wake_failures: HashMap::new(),
            store,
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel,
            base_rootfs_path: cas_rootfs,
            base_rootfs_hash: rootfs_hash,
            data_dir: data_dir.clone(),
            data_disk: Arc::new(LocalLoop::open(data_dir.join("data-disks")).unwrap()),
            lease: Arc::new(FlockLease::open(data_dir.join("leases"), host_id.clone()).unwrap()),
            disk_tokens: HashMap::new(),
            host_id,
            is_leader: Arc::new(AtomicBool::new(true)),
            platform_egress: PlatformEgress::default(),
        }));
        let routing: jkbase_proxy::RoutingTable = Default::default();
        let domain_map: DomainMap = Default::default();
        let logs = data_dir.join("logs");
        let shipper = LogShipper::new(LogStore::new(logs.clone()), logs.join(".cursors.json"));
        let reach = jkbase_common::config::DbReachFacts {
            splice_secret: "dbrace-splice-secret-0123456789abcdef".to_string(),
            admin_token: "jkba_dbrace-admin-token-0123456789abcdef".to_string(),
            dedicated: false,
            jwks: None,
        };

        let fc_count = || {
            let out = std::process::Command::new("pgrep")
                .args(["-f", &vm_identity::fc_sock_pkill_pattern(&db_id)])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).lines().count()
        };
        let img = data_dir.join("data-disks").join(format!("{db_id}.img"));
        let loop_count = || {
            let out = std::process::Command::new("losetup")
                .args(["-j", img.to_str().unwrap()])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).lines().count()
        };

        // Run the body, then ALWAYS clean up (FCs, loops, TAP, bridge) before reporting.
        let outcome: std::result::Result<(), String> = async {
            boot_db_vm(pid, &platform, Some(&reach))
                .await
                .map_err(|e| format!("initial boot_db_vm: {e:#}"))?;
            for round in 1..=rounds {
                // Hibernate the DB VM; redeploy as soon as hibernate has dropped the lock.
                let hib = tokio::spawn({
                    let (platform, routing, shipper) =
                        (platform.clone(), routing.clone(), shipper.clone());
                    let db_id = db_id.clone();
                    async move {
                        hibernate_project(&db_id, platform, routing, shipper, None, None).await
                    }
                });
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    let st = platform.lock().await.vm_states.get(&db_id).copied();
                    if st == Some(VmLifecycle::Hibernating) {
                        break;
                    }
                    if std::time::Instant::now() > deadline {
                        return Err(format!("round {round}: never saw Hibernating ({st:?})"));
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let redeploy = boot_db_vm(pid, &platform, Some(&reach)).await;
                let hib = hib.await.unwrap();
                eprintln!("[dbrace] round {round}: redeploy={redeploy:?} hibernate={hib:?}");
                redeploy.map_err(|e| format!("round {round}: redeploy failed: {e:#}"))?;
                // Let any straggling hibernate-side cleanup land before judging.
                tokio::time::sleep(Duration::from_millis(500)).await;

                let plat = platform.lock().await;
                let state = plat.vm_states.get(&db_id).copied();
                let has_vm = plat.vms.contains_key(&db_id);
                let token = plat.disk_tokens.get(&db_id).cloned();
                let snap = plat.store.get_snapshot_meta(&db_id).ok().flatten();
                let alloc = plat.store.get_vm_allocation(&db_id).unwrap().unwrap();
                let lease = plat.lease.clone();
                drop(plat);
                let lease_ok = match &token {
                    Some(t) => lease.renew(t, DISK_LEASE_TTL).await.is_ok(),
                    None => false,
                };
                let alive = agent_alive(&alloc.ip).await;
                let (fcs, loops) = (fc_count(), loop_count());
                eprintln!(
                    "[dbrace] round {round}: state={state:?} vm={has_vm} token={} lease_ok={lease_ok} \
                     snapshot_meta={} fcs={fcs} loops={loops} agent_alive={alive}",
                    token.is_some(),
                    snap.is_some()
                );
                if state != Some(VmLifecycle::Running)
                    || !has_vm
                    || !lease_ok
                    || snap.is_some()
                    || fcs != 1
                    || loops != 1
                    || !alive
                {
                    return Err(format!("round {round}: incoherent DB VM after the race"));
                }
            }

            // Then the DB VM must still hibernate + WAKE normally (the reach plane's path): a
            // settled hibernate leaves a snapshot, and `wake_project_inner` on the `.db` id brings
            // it back Running — on main this aborted every DB-VM wake as "deleted".
            hibernate_project(&db_id, platform.clone(), routing.clone(), shipper.clone(), None, None)
                .await
                .map_err(|e| format!("final hibernate: {e:#}"))?;
            {
                let plat = platform.lock().await;
                let st = plat.vm_states.get(&db_id).copied();
                let snap = plat.store.get_snapshot_meta(&db_id).ok().flatten();
                eprintln!("[dbrace] hibernated: state={st:?} snapshot_meta={}", snap.is_some());
                if st != Some(VmLifecycle::Hibernated) || snap.is_none() {
                    return Err("final hibernate did not settle Hibernated with a snapshot".into());
                }
            }
            for wake in 1..=2 {
                let ip = wake_project_inner(
                    &db_id,
                    platform.clone(),
                    routing.clone(),
                    domain_map.clone(),
                    shipper.clone(),
                )
                .await
                .map_err(|e| format!("DB VM wake {wake}: {e:#}"))?;
                let plat = platform.lock().await;
                let state = plat.vm_states.get(&db_id).copied();
                let has_vm = plat.vms.contains_key(&db_id);
                let token = plat.disk_tokens.get(&db_id).cloned();
                let lease = plat.lease.clone();
                drop(plat);
                let lease_ok = match &token {
                    Some(t) => lease.renew(t, DISK_LEASE_TTL).await.is_ok(),
                    None => false,
                };
                let alive = agent_alive(&ip).await;
                let (fcs, loops) = (fc_count(), loop_count());
                eprintln!(
                    "[dbrace] wake {wake}: ip={ip} state={state:?} vm={has_vm} lease_ok={lease_ok} \
                     fcs={fcs} loops={loops} agent_alive={alive}"
                );
                if state != Some(VmLifecycle::Running)
                    || !has_vm
                    || !lease_ok
                    || fcs != 1
                    || loops != 1
                    || !alive
                {
                    return Err(format!("wake {wake}: incoherent DB VM"));
                }
                if wake == 1 {
                    hibernate_project(
                        &db_id,
                        platform.clone(),
                        routing.clone(),
                        shipper.clone(),
                        None,
                        None,
                    )
                    .await
                    .map_err(|e| format!("re-hibernate: {e:#}"))?;
                }
            }
            Ok(())
        }
        .await;

        // Cleanup: stop the VM, kill any straggler FC, detach the disk, drop TAP (+ bridge).
        {
            let mut plat = platform.lock().await;
            if let Some(mut vm) = plat.vms.remove(&db_id) {
                let _ = vm.stop().await;
            }
            reap_firecracker(&db_id).await;
            if let Some(t) = plat.disk_tokens.remove(&db_id) {
                let (dd, ls) = (plat.data_disk.clone(), plat.lease.clone());
                release_data_disk(&dd, &ls, &db_id, t).await;
            }
            let _ = plat.data_disk.detach(&db_id).await;
            if let Ok(Some(a)) = plat.store.get_vm_allocation(&db_id) {
                let _ = teardown_tap(&a.tap_device).await;
            }
        }
        if made_bridge {
            let _ = run_cmd("ip", &["link", "del", "jkbr0"]).await;
        }
        let _ = std::fs::remove_dir_all(&data_dir);

        outcome.unwrap();
        println!("PASS: {rounds} round(s) of DB-VM redeploy-during-hibernate left one coherent VM");
    }

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

    /// A rhypedb layer swap repoints `platform.json` at the new engine; the OLD engine blob is
    /// then pinned only by a dedicated project's DB VM image (`{id}.db.ext4`). The boot GC must
    /// keep it live, and an unreadable DB image must abort the sweep like an app image does.
    #[test]
    fn baselayers_live_set_keeps_blobs_pinned_by_dedicated_db_vm_images() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data = std::env::temp_dir().join(format!("jkbase-blgc-{nanos}"));
        let blob = |c: char| format!("sha256-{}.erofs", c.to_string().repeat(64));
        let (base, new_db, old_db, app) = (blob('a'), blob('b'), blob('c'), blob('d'));
        std::fs::create_dir_all(data.join("baselayers")).unwrap();
        std::fs::write(
            data.join("baselayers/platform.json"),
            format!(r#"{{"base":{{"file":"{base}"}},"runtimes":{{"rhypedb":{{"file":"{new_db}"}}}}}}"#),
        )
        .unwrap();
        let images = data.join("content-images");
        let pins: HashMap<PathBuf, Vec<PathBuf>> = HashMap::from([
            (images.join("p.ext4"), vec![PathBuf::from(&base), PathBuf::from(&app)]),
            (images.join("p.db.ext4"), vec![PathBuf::from(&base), PathBuf::from(&old_db)]),
        ]);
        let registered = vec!["p".to_string(), "q".to_string()];

        let live = baselayers_live_set(&data, &registered, |img| {
            Ok(pins.get(img).cloned().unwrap_or_default())
        })
        .expect("readable manifest + layer maps ⇒ a live set");
        for f in [&base, &new_db, &old_db, &app] {
            assert!(live.contains(f), "{f} must be live: {live:?}");
        }

        // An unreadable DB VM layer map aborts the sweep (never "references nothing").
        let unreadable = images.join("p.db.ext4");
        assert!(
            baselayers_live_set(&data, &registered, |img| {
                if img == unreadable {
                    anyhow::bail!("corrupt")
                }
                Ok(Vec::new())
            })
            .is_none()
        );

        let _ = std::fs::remove_dir_all(&data);
    }

}
