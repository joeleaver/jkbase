//! Build-pipeline provisioning: the build kernel, the orphan-build reaper, the isolated
//! build network (+ its public-any proxy listener) and the `BuildDeps` the callback runs on.

use crate::cli::Args;
use crate::{build_mem_budget, build_orchestrator, build_reaper, build_sizing};
use anyhow::Result;
use jkbase_control::store::Store;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// The public-any (:3129) egress proxy listener, bound before the firewall scoping is armed.
pub(crate) type PublicAnyProxy = (u16, String, tokio::net::TcpListener);

/// What the build-network phase hands on to `prepare_build_deps`.
pub(crate) struct BuildNetPrep {
    pub(crate) fc_release: PathBuf,
    pub(crate) build_kernel: PathBuf,
    pub(crate) build_uid: u32,
    pub(crate) build_net: Option<Arc<build_orchestrator::BuildNet>>,
}

pub(crate) async fn prepare_build_net(
    args: &Args,
    data_dir: &Path,
    guest_kernel: &Path,
) -> Result<(BuildNetPrep, Option<PublicAnyProxy>)> {
    // Build-pipeline wiring: control owns the `POST /build` funnel + build-job;
    // this server owns jkbase-orch + the jailer privilege, exposed via
    // `build_callback` (mirrors `deploy_callback`). The kernel is staged onto the
    // data-dir filesystem (same-fs hard-link into the jail), and the parent build
    // cgroup is provisioned best-effort (needs root).
    let fc_release = args.fc_dir.join("release-v1.15.1-x86_64");
    let build_kernel = data_dir.join("build-kernel").join("vmlinux.bin");
    // Non-fatal: a build-provisioning gap disables builds but must not knock over
    // the (separate) runtime hosting path — the kernel here feeds only builds.
    if let Err(e) = build_orchestrator::stage_kernel(guest_kernel, &build_kernel) {
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
    Ok((
        BuildNetPrep {
            fc_release,
            build_kernel,
            build_uid,
            build_net,
        },
        public_any_proxy,
    ))
}

pub(crate) fn prepare_build_deps(
    args: &Args,
    data_dir: &Path,
    store_for_builds: Store,
    prep: BuildNetPrep,
) -> Result<Arc<build_orchestrator::BuildDeps>> {
    let BuildNetPrep {
        fc_release,
        build_kernel,
        build_uid,
        build_net,
    } = prep;
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
        data_dir: data_dir.to_path_buf(),
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
    Ok(build_deps)
}
