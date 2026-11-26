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
use crate::shutdown::{DRAIN_GRACE, shutdown_signal, upgrade_flag_path};
use crate::wake::{WAKE_BACKOFF, WakingGuard, app_wake_callback, db_reach_wake_callback, snapshot_restore_decision, wait_for_route};
use crate::hibernate::hibernate_project;
use crate::db_vm::wait_for_db_vm_running;
use crate::deploy::handle_deploy;
use crate::boot_reconcile::{backfill_domains, project_can_wake, reconcile_baselayers_on_boot, reconcile_orphans_on_boot};
use crate::vm_runtime::{register_active_routes, write_handoff_record};
use crate::teardown::{cleanup_orphans, drop_dedicated_db, force_stop_and_cleanup, handle_teardown};
use crate::adoption::{adopt_or_reap_runtime_vms, proc_starttime};
use crate::agent_client::{agent_alive, agent_protocol_version, resync_clock_agent, sync_agent, wait_for_agent};
use crate::idle::idle_detection_loop;
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
mod shutdown;
mod wake_vm;
mod wake;
mod hibernate;
mod db_vm;
mod deploy;
mod boot_reconcile;
mod vm_runtime;
mod teardown;
mod adoption;
mod agent_client;
mod idle;
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
    HostCapacity, HostRecord, Store,
};
use jkbase_orch::rootfs;
use jkbase_proxy::tls::CertManager;
use jkbase_proxy::{
    self, ActivityTracker, DomainMap, ProxyConfig, new_domain_map, new_routing_table,
};
use jkbase_substrate::{
    DataDiskProvider, FlockLease, Lease, LocalLoop,
};
use log_shipper::LogShipper;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

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

#[cfg(test)]
mod tests {
    
    
    
    

}
