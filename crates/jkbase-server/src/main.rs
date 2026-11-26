mod adoption;
mod agent_client;
mod auth_service;
mod boot;
mod boot_reconcile;
mod build_ca;
mod build_cache;
mod build_mem_budget;
mod build_orchestrator;
mod build_reaper;
mod build_sizing;
mod cli;
mod data_disk;
mod db_admin;
mod db_backup_store;
mod db_gateway;
mod db_ops;
mod db_vm;
mod deploy;
mod deploy_gate;
mod dns_forwarder;
mod egress;
mod ha_lease;
mod ha_placement;
mod handoff;
mod hibernate;
mod idle;
mod l4_ports;
mod l4_runtime;
mod layer_plan;
mod log_shipper;
mod metering;
mod metering_loop;
mod mirror;
mod objectstore_service;
mod platform;
mod project_facts;
mod rootfs_cas;
mod scheduler;
mod shutdown;
mod socket_activation;
mod tap;
mod teardown;
mod vm_identity;
mod vm_runtime;
mod wake;
mod wake_vm;

use crate::adoption::adopt_or_reap_runtime_vms;
use crate::boot_reconcile::{
    backfill_domains, reconcile_baselayers_on_boot, reconcile_orphans_on_boot,
};
use crate::cli::{Args, resolve_guest_kernel, resolve_hostname, validate_substrate_selection};
use crate::data_disk::migrate_legacy_data_disks;
use crate::log_shipper::LogShipper;
use crate::platform::{Incarnations, PlatformState};
use crate::shutdown::{DRAIN_GRACE, shutdown_signal, upgrade_flag_path};
use crate::tap::{ensure_runtime_source_guard_chain, runtime_ebtables_lock};
use crate::teardown::cleanup_orphans;
use anyhow::Result;
use clap::Parser;
use jkbase_control::api;
use jkbase_control::logstore::LogStore;
use jkbase_control::store::Store;
use jkbase_proxy::{self, ActivityTracker, DomainMap, new_domain_map, new_routing_table};
use jkbase_substrate::{DataDiskProvider, FlockLease, Lease, LocalLoop};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

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
        return boot::gen_build_ca::run();
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

    // Zero-bounce Phase 2: cancellation tokens for the graceful data-plane drain on an upgrade
    // restart (cancelled in shutdown_signal's upgrade branch; bounded by the DRAIN_GRACE watchdog).
    let proxy_shutdown = tokio_util::sync::CancellationToken::new();
    let storage_shutdown = tokio_util::sync::CancellationToken::new();
    let auth_shutdown = tokio_util::sync::CancellationToken::new();
    let storage_join =
        boot::services::spawn_storage(&args, data_dir.clone(), &store, storage_shutdown.clone());
    let auth_join = boot::services::spawn_auth(&args, &store, auth_shutdown.clone());
    let routing_table = new_routing_table();
    let domain_map: DomainMap = new_domain_map();
    let activity_tracker: ActivityTracker = Arc::new(RwLock::new(HashMap::new()));

    // ORDER IS LOAD-BEARING: the base rootfs is CAS-ized and GC'd synchronously here, before any
    // loop that can boot/restore a VM is spawned and before the proxy binds (see place_and_gc).
    let (base_rootfs_path, base_rootfs_hash) =
        boot::base_rootfs::place_and_gc(&args, &data_dir, &store).await?;

    // Data-disk RWO substrate: R3 LocalLoop (loop-device exclusivity) + R2 FlockLease
    // (monotonic fence token). Migrate any legacy `{id}.ext4` disks to LocalLoop's
    // `{id}.img` naming so they become loop-managed + fenced. (`host_id` was resolved
    // from --host-id / the hostname at startup, above.)
    let data_disks_dir = data_dir.join("data-disks");
    migrate_legacy_data_disks(&data_disks_dir).await?;
    let data_disk: Arc<dyn DataDiskProvider> = Arc::new(LocalLoop::open(&data_disks_dir)?);
    let lease: Arc<dyn Lease> =
        Arc::new(FlockLease::open(data_dir.join("leases"), host_id.clone())?);

    let platform_egress = boot::egress_facts::platform_egress(&args);

    // HA P2: cluster leadership flag + the lease/host_id the cluster loops need
    // (the originals are moved into PlatformState below).
    let is_leader = Arc::new(AtomicBool::new(false));
    let lease_for_ha = lease.clone();
    let host_id_for_ha = host_id.clone();

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

    boot::ha::spawn_cluster_loops(
        &platform,
        lease_for_ha,
        host_id_for_ha,
        is_leader,
        &store,
        &args,
    );

    let tls = boot::tls::setup(&args, &data_dir, &store, &domain_map).await?;
    let cert_manager = tls.cert_manager.clone();

    let store_for_builds = store.clone();
    let mut state = boot::control::app_state(
        &args,
        &store,
        &log_store,
        deploy_dir,
        &routing_table,
        &domain_map,
        &tls,
    );
    let planes = boot::Planes {
        platform: platform.clone(),
        routing: routing_table.clone(),
        domains: domain_map.clone(),
        shipper: log_shipper.clone(),
    };
    boot::control::wire_lifecycle_callbacks(&mut state, &planes);

    // Build pipeline. ORDER IS LOAD-BEARING: prepare_build_net reaps orphan build VMs BEFORE any
    // egress proxy binds or the memory budget admits a build, and binds the public-any listener
    // before the firewall scoping is armed.
    let (build_prep, public_any_proxy) =
        boot::builds::prepare_build_net(&args, &data_dir, &guest_kernel).await?;
    // Pre-create + hook the runtime VM L2 source-guard chain at startup (defense in depth:
    // it exists before the first project wakes; per-TAP rules are added lazily in setup_tap).
    // Fail-closed — ebtables is a provisioned dependency (provision.sh / deploy-server.sh).
    {
        let _g = runtime_ebtables_lock().lock().await;
        ensure_runtime_source_guard_chain().await?;
    }
    let build_deps =
        boot::builds::prepare_build_deps(&args, &data_dir, store_for_builds, build_prep)?;
    state.build_callback = Some(build_orchestrator::build_callback(build_deps));

    let (db_relay_registry, db_backup_ctx) =
        boot::db_wiring::wire_db_callbacks(&mut state, &planes, &data_dir);

    let state = Arc::new(state);
    let router = api::router(state, args.domain.clone());

    let proxy_config = boot::proxy::proxy_config(
        &args,
        &store,
        &planes,
        &activity_tracker,
        cert_manager.clone(),
        &db_relay_registry,
    )?;
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

    let (l4_registry, l4_plane) =
        boot::data_plane::spawn_data_plane(&store, &planes, &db_relay_registry).await;

    boot::loops::spawn_loops(
        &args,
        &planes,
        &activity_tracker,
        &db_backup_ctx,
        &db_relay_registry,
        &l4_plane,
    );

    boot::egress_proxies::spawn_egress_proxies(&args, &data_dir, public_any_proxy);

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
