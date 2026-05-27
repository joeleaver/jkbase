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
    pub content_image_path: Option<PathBuf>,
    pub data_disk_path: Option<PathBuf>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub tap_device: Option<String>,
    pub guest_mac: Option<String>,
    pub guest_ip: Option<String>,
    pub gateway_ip: Option<String>,
    pub vsock_cid: Option<u32>,
}

pub struct VmInstance {
    pub id: String,
    socket_path: PathBuf,
    vsock_path: Option<PathBuf>,
    log_path: PathBuf,
    process: Child,
    client: FirecrackerClient,
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
        if let Some(ref vp) = vsock_path {
            if vp.exists() {
                tokio::fs::remove_file(vp).await?;
            }
        }

        let log_path = vm_dir.join("console.log");
        let log_file = std::fs::File::create(&log_path)
            .context("failed to create VM console log")?;
        let stderr_log = log_file
            .try_clone()
            .context("failed to clone log file handle")?;

        info!(id, log = %log_path.display(), "starting Firecracker process");
        let process = Command::new(&config.firecracker_bin)
            .arg("--api-sock")
            .arg(&socket_path)
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(stderr_log))
            .spawn()
            .context("failed to spawn Firecracker process")?;

        // Wait for the socket to appear
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !socket_path.exists() {
            anyhow::bail!("Firecracker socket did not appear at {}", socket_path.display());
        }

        let client = FirecrackerClient::new(&socket_path);

        info!(id, "configuring VM");
        client
            .set_machine_config(&MachineConfig {
                vcpu_count: config.vcpu_count,
                mem_size_mib: config.mem_size_mib,
            })
            .await?;

        let mut boot_args = "console=ttyS0 reboot=k panic=1 pci=off ro".to_string();
        if let (Some(guest_ip), Some(gateway_ip)) = (&config.guest_ip, &config.gateway_ip) {
            // Kernel IP autoconfiguration: ip=guest::gateway:netmask::iface:off
            boot_args.push_str(&format!(
                " ip={guest_ip}::{gateway_ip}:255.255.255.0::eth0:off"
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

        if let Some(content_path) = &config.content_image_path {
            client
                .set_drive(&Drive {
                    drive_id: "content".to_string(),
                    path_on_host: content_path.to_string_lossy().to_string(),
                    is_root_device: false,
                    is_read_only: false,
                })
                .await?;
        }

        if let Some(data_path) = &config.data_disk_path {
            info!(id, data_disk = %data_path.display(), "attaching data disk as /dev/vdc");
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
            process,
            client,
        })
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

    pub async fn stop(&mut self) -> Result<()> {
        info!(self.id, "stopping VM");
        self.process.kill().await.context("failed to kill Firecracker process")?;
        self.process.wait().await?;

        if self.socket_path.exists() {
            let _ = tokio::fs::remove_file(&self.socket_path).await;
        }
        if let Some(ref vp) = self.vsock_path {
            if vp.exists() {
                let _ = tokio::fs::remove_file(vp).await;
            }
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
        self.process.kill().await?;
        self.process.wait().await?;

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

        // Firecracker v1.15.1: snapshot must be loaded BEFORE any boot-specific
        // resources (drives, network). The snapshot contains the device config.
        info!(id, "loading snapshot");
        client
            .load_snapshot(
                snapshot_path.to_str().unwrap(),
                mem_file_path.to_str().unwrap(),
            )
            .await?;

        info!(id, "VM restored from snapshot");
        Ok(VmInstance {
            id: id.to_string(),
            socket_path,
            vsock_path: None,
            log_path,
            process,
            client,
        })
    }
}

impl Drop for VmInstance {
    fn drop(&mut self) {
        // Best-effort sync kill if the process is still running
        if let Ok(Some(_)) = self.process.try_wait() {
            return;
        }
        let _ = self.process.start_kill();
    }
}
