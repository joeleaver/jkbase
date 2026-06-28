use crate::firecracker::{
    BootSource, Drive, FirecrackerClient, MachineConfig, NetworkInterface, VsockConfig,
};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::{Child, Command};
use tracing::info;

pub struct VmConfig {
    pub firecracker_bin: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    /// Per-project metadata image (RO ext4): `_servers`/`_routes`/`_sites`/
    /// `_functions` + the host-written `_layers.json`. Attached as `vdb`.
    pub metadata_image_path: Option<PathBuf>,
    /// Content-addressed erofs layer blobs (base, runtime, then one app layer per
    /// server), attached RO as `vdc..` in this exact order. The host bakes the
    /// matching device assignment into `_layers.json` inside the metadata image.
    pub layer_paths: Vec<PathBuf>,
    pub data_disk_path: Option<PathBuf>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub tap_device: Option<String>,
    pub guest_mac: Option<String>,
    pub guest_ip: Option<String>,
    pub gateway_ip: Option<String>,
    pub vsock_cid: Option<u32>,
    /// Parent cgroup-v2 dir for runtime FCs (e.g. `/sys/fs/cgroup/jkbase-runtime`). When
    /// set, `start`/`restore_from_snapshot` `mkdir` a `<parent>/<id>` leaf and migrate the
    /// Firecracker pid into its `cgroup.procs` immediately after spawn, so the FC lives in a
    /// sibling cgroup OUTSIDE `jkbase.service` and survives `systemctl restart`
    /// (`KillMode=mixed` only reaps the service's own cgroup) for the next process to
    /// re-adopt. `None` keeps the FC in the spawning process's cgroup (build VMs, tests,
    /// pre-cgroup hosts). Best-effort: a migration failure is logged, not fatal — the VM
    /// runs, it just won't survive an upgrade (falls back to the cold-restore path).
    pub runtime_cgroup_parent: Option<PathBuf>,
}

pub struct VmInstance {
    pub id: String,
    socket_path: PathBuf,
    vsock_path: Option<PathBuf>,
    log_path: PathBuf,
    handle: FcHandle,
    client: FirecrackerClient,
}

/// How this process relates to the Firecracker it manages.
enum FcHandle {
    /// Spawned by THIS process: the tokio [`Child`] IS the Firecracker, so `kill_on_drop`
    /// and the `Drop` backstop apply and `wait()` reaps it.
    Owned(Child),
    /// Re-adopted across a server restart: NOT our child (so `process.wait()` would `ECHILD`).
    /// We carry its verified pid + `/proc/<pid>/stat` field-22 start time and act on it via
    /// signals + `/proc` polling, pinned to that incarnation so PID reuse can't fool us.
    Adopted { fc_pid: u32, fc_starttime: u64 },
}

/// Process start time (jiffies since boot) from field 22 of `/proc/<pid>/stat`, or `None`
/// if the process is gone / unparseable. `comm` (field 2) is parenthesised and may contain
/// spaces and `)`, so split the tail AFTER the last `)` — field 22 is then index 19.
/// (Mirrors the substrate's `process_starttime`; orch can't depend on that crate.)
fn proc_starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().nth(19)?.parse().ok()
}

/// True iff `pid` is alive AND still the same incarnation as `starttime` (PID-reuse-proof).
fn proc_alive_at(pid: u32, starttime: u64) -> bool {
    matches!(proc_starttime(pid), Some(st) if st == starttime)
}

impl VmInstance {
    pub async fn start(id: &str, config: &VmConfig, runtime_dir: &Path) -> Result<Self> {
        let vm_dir = runtime_dir.join(id);
        tokio::fs::create_dir_all(&vm_dir)
            .await
            .context("failed to create VM runtime directory")?;

        let socket_path = vm_dir.join("firecracker.sock");
        let vsock_path = config.vsock_cid.map(|_| vm_dir.join("vsock.sock"));

        if socket_path.exists() {
            tokio::fs::remove_file(&socket_path).await?;
        }
        if let Some(ref vp) = vsock_path
            && vp.exists()
        {
            tokio::fs::remove_file(vp).await?;
        }

        let log_path = vm_dir.join("console.log");
        let log_file =
            std::fs::File::create(&log_path).context("failed to create VM console log")?;
        let stderr_log = log_file
            .try_clone()
            .context("failed to clone log file handle")?;

        info!(id, log = %log_path.display(), "starting Firecracker process");
        let process = Command::new(&config.firecracker_bin)
            .arg("--api-sock")
            .arg(&socket_path)
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(stderr_log))
            // Backstop: any of the config `?` calls below (machine-config, boot-source,
            // drives, network, vsock, InstanceStart) can fail after spawn but before the
            // VmInstance is built — dropping this bare Child. kill_on_drop kills the
            // Firecracker with it instead of orphaning it. Matches build_vm.rs.
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn Firecracker process")?;

        // Migrate the FC into the runtime cgroup IMMEDIATELY (before the slow config calls)
        // so it survives a server restart for re-adoption. Best-effort.
        if let Some(parent) = &config.runtime_cgroup_parent
            && let Some(fc_pid) = process.id()
        {
            migrate_to_runtime_cgroup(parent, id, fc_pid);
        }

        // Wait for the socket to appear
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !socket_path.exists() {
            anyhow::bail!(
                "Firecracker socket did not appear at {}",
                socket_path.display()
            );
        }

        let client = FirecrackerClient::new(&socket_path);

        info!(id, "configuring VM");
        client
            .set_machine_config(&MachineConfig {
                vcpu_count: config.vcpu_count,
                mem_size_mib: config.mem_size_mib,
            })
            .await?;

        // Snapshot-safe CPU baseline (custom CPU template). Firecracker v1.15.1's
        // snapshot/restore does not faithfully round-trip the guest's newer XSAVE state
        // (AVX-512 / CET shadow-stack / PKU) on a modern host (e.g. AMD Zen5 + a fresh
        // kernel): a restored guest task whose XSAVE area carries that state #GPs in
        // `restore_fpregs_from_fpstate` and the guest kernel panics ~1s into resume —
        // breaking on-demand wake (the heart of scale-to-zero). The static AMD template
        // (T2A) is gated to specific CPU models (rejected on Zen5), so we mask the
        // offending *gating* feature bits with a custom template: the guest kernel's
        // xstate init drops an xfeature whose CPU-feature bit is absent (xsave_cpuid_
        // features cross-check), so clearing AVX512F + PKU + CET_SS in CPUID leaf 0x7
        // keeps those components out of XCR0 entirely — while AVX2 (which Bun/rhypedb
        // need) stays. A guest cmdline (`clearcpuid`) can't do this: it's applied AFTER
        // xstate init reads raw CPUID, whereas a template masks CPUID from the first read.
        // No-op on hosts that lack these features (e.g. the current Intel prod CPU), since
        // the bits are already 0. Bitmaps are MSB(bit31)→LSB(bit0); '0' clears, 'x' keeps.
        let cpu_template = serde_json::json!({
            "cpuid_modifiers": [{
                "leaf": "0x7",
                "subleaf": "0x0",
                "flags": 2, // KVM_CPUID_FLAG_SIGNIFICANT_INDEX (leaf 0x7 is subleaf-significant)
                "modifiers": [
                    // EBX: clear AVX512 F(16) DQ(17) IFMA(21) CD(28) BW(30) VL(31).
                    {"register": "ebx", "bitmap": "0b00x0xxxxxx0xxx00xxxxxxxxxxxxxxxx"},
                    // ECX: clear PKU(3) OSPKE(4) CET_SS(7).
                    {"register": "ecx", "bitmap": "0bxxxxxxxxxxxxxxxxxxxxxxxx0xx00xxx"}
                ]
            }],
            "msr_modifiers": []
        });
        client
            .set_cpu_config(&cpu_template)
            .await
            .context("set snapshot-safe CPU template")?;

        // ipv6.disable=1: runtime egress is IPv4-only (no v6 NAT/forwarding on jkbr0),
        // and the bridge SSRF DROP is IPv4 — so a live guest v6 stack would be an
        // unguarded path to metadata/host. Disable it in the guest entirely (matches the
        // build VMs); the host bridge/TAP also drop v6 as defense in depth.
        let mut boot_args = "console=ttyS0 reboot=k panic=1 pci=off ro ipv6.disable=1".to_string();
        if let (Some(guest_ip), Some(gateway_ip)) = (&config.guest_ip, &config.gateway_ip) {
            // Kernel IP autoconfiguration:
            //   ip=client::gateway:netmask:hostname:iface:autoconf:dns0
            // dns0 = the gateway, where the host runs a DNS forwarder (see
            // tools/setup-bridge.sh); it populates /proc/net/pnp. The agent also writes
            // an explicit /etc/resolv.conf pointed at the gateway (the load-bearing
            // path, since the app reads /etc/resolv.conf, not pnp).
            boot_args.push_str(&format!(
                " ip={guest_ip}::{gateway_ip}:255.255.255.0::eth0:off:{gateway_ip}"
            ));
        }

        client
            .set_boot_source(&BootSource {
                kernel_image_path: config.kernel_path.to_string_lossy().to_string(),
                boot_args,
            })
            .await?;

        client
            .set_drive(&Drive {
                drive_id: "rootfs".to_string(),
                path_on_host: config.rootfs_path.to_string_lossy().to_string(),
                is_root_device: true,
                is_read_only: true,
            })
            .await?;

        // Drive attach order fixes the guest device letters (Firecracker assigns
        // vda, vdb, vdc… in PUT order, root first): rootfs=vda, metadata=vdb, the
        // erofs layers=vdc.., then the data disk last. The host's `_layers.json`
        // encodes this same assignment so the agent never hardcodes a letter.
        if let Some(meta_path) = &config.metadata_image_path {
            client
                .set_drive(&Drive {
                    drive_id: "metadata".to_string(),
                    path_on_host: meta_path.to_string_lossy().to_string(),
                    is_root_device: false,
                    is_read_only: true,
                })
                .await?;
        }

        for (i, layer) in config.layer_paths.iter().enumerate() {
            client
                .set_drive(&Drive {
                    drive_id: format!("layer{i}"),
                    path_on_host: layer.to_string_lossy().to_string(),
                    is_root_device: false,
                    is_read_only: true,
                })
                .await?;
        }

        if let Some(data_path) = &config.data_disk_path {
            info!(id, data_disk = %data_path.display(), "attaching data disk (drive id `data`, last)");
            client
                .set_drive(&Drive {
                    drive_id: "data".to_string(),
                    path_on_host: data_path.to_string_lossy().to_string(),
                    is_root_device: false,
                    is_read_only: false,
                })
                .await?;
        }

        if let (Some(tap), Some(mac)) = (&config.tap_device, &config.guest_mac) {
            client
                .set_network_interface(&NetworkInterface {
                    iface_id: "eth0".to_string(),
                    guest_mac: mac.clone(),
                    host_dev_name: tap.clone(),
                })
                .await?;
        }

        if let (Some(cid), Some(vp)) = (config.vsock_cid, &vsock_path) {
            client
                .set_vsock(&VsockConfig {
                    guest_cid: cid,
                    uds_path: vp.to_string_lossy().to_string(),
                })
                .await?;
        }

        info!(id, "booting VM");
        client.start().await?;

        info!(id, "VM started");
        Ok(VmInstance {
            id: id.to_string(),
            socket_path,
            vsock_path,
            log_path,
            handle: FcHandle::Owned(process),
            client,
        })
    }

    /// Re-adopt a Firecracker that SURVIVED a prior `jkbase-server` exit (it lives in the
    /// `jkbase-runtime` cgroup, so `systemctl restart` did not reap it). Unlike [`start`],
    /// this ATTACHES to the existing `run/<id>/firecracker.sock` (it does NOT unlink it —
    /// that would sever the live FC's API channel) and does NO `setup_tap`/boot — the TAP +
    /// its source-guard persist across the restart and the guest is already running. The
    /// caller has already verified `fc_pid` is alive at `fc_starttime`, that the agent HTTP
    /// layer answers, and that the api-sock's `SO_PEERCRED` peer == `fc_pid`. The returned
    /// adopted instance re-implements `pid`/`stop`/`hibernate` off the pid (no `Child`), and
    /// its `Drop` is a no-op so it can never kill a VM meant to survive.
    pub fn adopt(id: &str, runtime_dir: &Path, fc_pid: u32, fc_starttime: u64) -> Self {
        let vm_dir = runtime_dir.join(id);
        let socket_path = vm_dir.join("firecracker.sock");
        let vsock_path = vm_dir.join("vsock.sock");
        let vsock_path = if vsock_path.exists() {
            Some(vsock_path)
        } else {
            None
        };
        let client = FirecrackerClient::new(&socket_path);
        VmInstance {
            id: id.to_string(),
            socket_path,
            vsock_path,
            log_path: vm_dir.join("console.log"),
            handle: FcHandle::Adopted {
                fc_pid,
                fc_starttime,
            },
            client,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn vsock_path(&self) -> Option<&Path> {
        self.vsock_path.as_deref()
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// OS pid of the Firecracker process, or `None` once an Owned process has exited.
    /// Used by host-side CPU metering to read `/proc/<pid>/stat`.
    pub fn pid(&self) -> Option<u32> {
        match &self.handle {
            FcHandle::Owned(p) => p.id(),
            FcHandle::Adopted { fc_pid, .. } => Some(*fc_pid),
        }
    }

    /// Kill the Firecracker and BLOCK until its death is confirmed, then clean up the
    /// sockets. Synchronous-to-death is load-bearing: callers (`detach`-after-`stop`, the
    /// restore-fallback cold boot, redeploy/teardown) rely on no live FC still mapping the
    /// data loop once this returns — the no-two-writers-on-one-RWO-disk guarantee.
    pub async fn stop(&mut self) -> Result<()> {
        info!(self.id, "stopping VM");
        match &mut self.handle {
            FcHandle::Owned(process) => {
                process
                    .kill()
                    .await
                    .context("failed to kill Firecracker process")?;
                process.wait().await?;
            }
            FcHandle::Adopted {
                fc_pid,
                fc_starttime,
            } => {
                // Not our child (`wait` would ECHILD): SIGKILL by pid, then poll `/proc`
                // pinned to the start time until the process is gone (or the pid is recycled
                // to a different incarnation — also "our FC is dead"). Bounded so a stuck
                // /proc can't hang the caller forever.
                kill_pid(*fc_pid);
                let mut confirmed = false;
                for _ in 0..600 {
                    if !proc_alive_at(*fc_pid, *fc_starttime) {
                        confirmed = true;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                if !confirmed {
                    anyhow::bail!(
                        "adopted FC pid {fc_pid} did not die within 30s after SIGKILL"
                    );
                }
            }
        }

        if self.socket_path.exists() {
            let _ = tokio::fs::remove_file(&self.socket_path).await;
        }
        if let Some(ref vp) = self.vsock_path
            && vp.exists()
        {
            let _ = tokio::fs::remove_file(vp).await;
        }

        info!(self.id, "VM stopped");
        Ok(())
    }

    pub async fn hibernate(&mut self, snapshot_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        tokio::fs::create_dir_all(snapshot_dir).await?;
        let snapshot_path = snapshot_dir.join("snapshot");
        let mem_file_path = snapshot_dir.join("mem");

        info!(self.id, "pausing VM for snapshot");
        self.client.pause_vm().await?;

        info!(self.id, "creating snapshot");
        self.client
            .create_snapshot(
                snapshot_path.to_str().unwrap(),
                mem_file_path.to_str().unwrap(),
            )
            .await?;

        info!(self.id, "snapshot created, killing process");
        match &mut self.handle {
            FcHandle::Owned(process) => {
                process.kill().await?;
                process.wait().await?;
            }
            FcHandle::Adopted {
                fc_pid,
                fc_starttime,
            } => {
                kill_pid(*fc_pid);
                for _ in 0..600 {
                    if !proc_alive_at(*fc_pid, *fc_starttime) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }

        if self.socket_path.exists() {
            let _ = tokio::fs::remove_file(&self.socket_path).await;
        }

        Ok((snapshot_path, mem_file_path))
    }

    pub async fn restore_from_snapshot(
        id: &str,
        config: &VmConfig,
        runtime_dir: &Path,
        snapshot_path: &Path,
        mem_file_path: &Path,
    ) -> Result<Self> {
        let vm_dir = runtime_dir.join(id);
        tokio::fs::create_dir_all(&vm_dir).await?;

        let socket_path = vm_dir.join("firecracker.sock");
        if socket_path.exists() {
            tokio::fs::remove_file(&socket_path).await?;
        }

        let log_path = vm_dir.join("console.log");
        let log_file = std::fs::File::create(&log_path)?;
        let stderr_log = log_file.try_clone()?;

        info!(id, "starting Firecracker for snapshot restore");
        let process = Command::new(&config.firecracker_bin)
            .arg("--api-sock")
            .arg(&socket_path)
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(stderr_log))
            // Backstop: if restore fails after spawn but before the VmInstance is built
            // (load_snapshot / drive-probe / patch_drive / resume_vm error), this bare
            // Child is dropped — kill_on_drop kills the paused Firecracker with it rather
            // than orphaning it. Matches build_vm.rs and the cold-boot path.
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn Firecracker process")?;

        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !socket_path.exists() {
            anyhow::bail!(
                "Firecracker socket did not appear at {}",
                socket_path.display()
            );
        }

        let client = FirecrackerClient::new(&socket_path);

        // Load the snapshot PAUSED (resume=false). The snapshot carries the device
        // config, including the data drive — whose host path may be stale (the disk
        // was just fenced+attached onto a possibly-different host device). Repoint
        // the data drive to that fenced device, THEN resume, so the restored guest
        // only ever writes through the read-write-once attach gate — never the path
        // Firecracker would re-derive from the snapshot.
        info!(id, "loading snapshot (paused)");
        client
            .load_snapshot(
                snapshot_path.to_str().unwrap(),
                mem_file_path.to_str().unwrap(),
                false,
            )
            .await?;

        if let Some(data_path) = &config.data_disk_path {
            // Fail-closed guard: only repoint a `data` drive the snapshot actually
            // restored. FC v1.15.1 already errors on a PATCH for an absent drive, so this
            // is upgrade-hardening against a future/looser FC that might instead CREATE
            // the drive — binding the data disk OUTSIDE the read-write-once fence. Refuse
            // ONLY on positive evidence (the loaded drive set is reported AND `data` is
            // genuinely missing). If the set can't be read or comes back empty (an FC that
            // doesn't surface restored drives via GET /vm/config), fall through to PATCH
            // and rely on FC's native check — so the normal restore path never regresses.
            match client.loaded_drive_ids().await {
                Ok(ids) if !ids.is_empty() && !ids.iter().any(|d| d == "data") => {
                    anyhow::bail!(
                        "restore {id}: snapshot has no 'data' drive to repoint (loaded: {ids:?}); \
                         refusing PATCH to avoid binding the data disk outside the RWO fence"
                    );
                }
                _ => {}
            }
            info!(id, data = %data_path.display(), "repointing data drive to fenced device");
            client
                .patch_drive("data", &data_path.to_string_lossy())
                .await?;
        }

        info!(id, "resuming restored VM");
        client.resume_vm().await?;

        info!(id, "VM restored from snapshot");
        Ok(VmInstance {
            id: id.to_string(),
            socket_path,
            vsock_path: None,
            log_path,
            handle: FcHandle::Owned(process),
            client,
        })
    }
}

/// SIGKILL `pid` by number — dependency-free, matches `rootfs_cas::reap_orphan_firecrackers`.
/// Used for the Adopted variant, whose FC is not a tokio `Child` (no `kill()`).
fn kill_pid(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .status();
}

/// Best-effort migrate `fc_pid` into a `<parent>/<id>` cgroup-v2 leaf so it lives OUTSIDE
/// `jkbase.service`'s cgroup and survives `systemctl restart` (`KillMode=mixed`). The server
/// runs as root, so it can `mkdir` the leaf and write `cgroup.procs`; the parent is
/// provisioned by `tools/setup-runtime-cgroup.sh`. A failure is logged, not fatal: the VM
/// still runs, it just won't survive an upgrade (degrades to the cold-restore path).
fn migrate_to_runtime_cgroup(parent: &Path, id: &str, fc_pid: u32) {
    let leaf = parent.join(id);
    if let Err(e) = std::fs::create_dir_all(&leaf) {
        tracing::warn!(id, error = %e, leaf = %leaf.display(),
            "could not create runtime cgroup leaf; FC will not survive a restart");
        return;
    }
    let procs = leaf.join("cgroup.procs");
    if let Err(e) = std::fs::write(&procs, fc_pid.to_string()) {
        tracing::warn!(id, %fc_pid, error = %e, procs = %procs.display(),
            "could not migrate FC into runtime cgroup; FC will not survive a restart");
    } else {
        info!(id, %fc_pid, leaf = %leaf.display(), "FC migrated into runtime cgroup (restart-survivable)");
    }
}

impl Drop for VmInstance {
    fn drop(&mut self) {
        match &mut self.handle {
            // Backstop for a spawned FC dropped without an explicit stop()/hibernate()
            // (e.g. a config error between spawn and a successful return). On the upgrade
            // path this never runs — shutdown exits via std::process::exit, skipping every
            // destructor, so survivors are left for re-adoption.
            FcHandle::Owned(process) => {
                if let Ok(Some(_)) = process.try_wait() {
                    return;
                }
                let _ = process.start_kill();
            }
            // NEVER kill an adopted survivor on drop — it is meant to outlive this handle.
            // Teardown of an adopted VM goes through the synchronous-to-death stop().
            FcHandle::Adopted { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_helpers_track_self_and_reject_dead_or_reused() {
        let me = std::process::id();
        let st = proc_starttime(me).expect("self has a start time");
        assert!(st > 0);
        assert!(proc_alive_at(me, st)); // same incarnation
        assert!(!proc_alive_at(me, st.wrapping_add(1))); // pid reuse ⇒ different start time
        assert_eq!(proc_starttime(0), None); // /proc/0 never exists
        assert!(!proc_alive_at(4_000_000_000, 1)); // implausible pid
    }

    #[test]
    fn adopt_exposes_fc_pid_and_paths() {
        let dir = std::env::temp_dir().join(format!("jkb-vm-adopt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vm = VmInstance::adopt("proj-x", &dir, 4242, 99);
        assert_eq!(vm.pid(), Some(4242)); // metering reads the adopted pid
        assert_eq!(vm.id, "proj-x");
        assert!(vm.socket_path().ends_with("proj-x/firecracker.sock"));
        assert!(matches!(
            vm.handle,
            FcHandle::Adopted {
                fc_pid: 4242,
                fc_starttime: 99
            }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn adopted_stop_is_ok_when_pid_already_gone() {
        let dir = std::env::temp_dir().join(format!("jkb-vm-stop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // A dead/implausible pid: SIGKILL is a no-op, proc_alive_at is immediately false, so
        // stop() confirms death on the first poll and returns Ok (no real FC needed).
        let mut vm = VmInstance::adopt("proj-y", &dir, 4_000_000_000, 12345);
        assert!(vm.stop().await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
