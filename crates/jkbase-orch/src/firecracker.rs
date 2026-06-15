use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;

pub struct FirecrackerClient {
    socket_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Serialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Serialize)]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
}

#[derive(Debug, Serialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub guest_mac: String,
    pub host_dev_name: String,
}

#[derive(Debug, Serialize)]
pub struct VsockConfig {
    pub guest_cid: u32,
    pub uds_path: String,
}

#[derive(Debug, Serialize)]
struct ActionBody {
    action_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub fault_message: Option<String>,
}

impl FirecrackerClient {
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
        }
    }

    async fn request(&self, method: &str, path: &str, body: Option<String>) -> Result<String> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to Firecracker socket at {}",
                    self.socket_path.display()
                )
            })?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake with Firecracker failed")?;

        tokio::spawn(conn);

        let body_bytes = body.unwrap_or_default();
        let req = Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .context("failed to build request")?;

        let resp = sender
            .send_request(req)
            .await
            .context("failed to send request to Firecracker")?;

        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .context("failed to read response body")?
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body).to_string();

        if !status.is_success() {
            let detail = serde_json::from_str::<ApiError>(&body_str)
                .ok()
                .and_then(|e| e.fault_message)
                .unwrap_or(body_str.clone());
            anyhow::bail!("Firecracker API error ({}): {}", status, detail);
        }

        Ok(body_str)
    }

    async fn put(&self, path: &str, body: &impl Serialize) -> Result<()> {
        let json = serde_json::to_string(body)?;
        self.request("PUT", path, Some(json)).await?;
        Ok(())
    }

    pub async fn set_machine_config(&self, config: &MachineConfig) -> Result<()> {
        self.put("/machine-config", config)
            .await
            .context("failed to set machine config")
    }

    pub async fn set_boot_source(&self, boot: &BootSource) -> Result<()> {
        self.put("/boot-source", boot)
            .await
            .context("failed to set boot source")
    }

    pub async fn set_drive(&self, drive: &Drive) -> Result<()> {
        self.put(&format!("/drives/{}", drive.drive_id), drive)
            .await
            .context("failed to set drive")
    }

    pub async fn set_network_interface(&self, iface: &NetworkInterface) -> Result<()> {
        self.put(&format!("/network-interfaces/{}", iface.iface_id), iface)
            .await
            .context("failed to set network interface")
    }

    pub async fn set_vsock(&self, vsock: &VsockConfig) -> Result<()> {
        self.put("/vsock", vsock)
            .await
            .context("failed to set vsock")
    }

    pub async fn start(&self) -> Result<()> {
        let action = ActionBody {
            action_type: "InstanceStart".to_string(),
        };
        let json = serde_json::to_string(&action)?;
        self.request("PUT", "/actions", Some(json))
            .await
            .context("failed to start instance")?;
        Ok(())
    }

    pub async fn pause_vm(&self) -> Result<()> {
        let json = serde_json::to_string(&serde_json::json!({"state": "Paused"}))?;
        self.request("PATCH", "/vm", Some(json))
            .await
            .context("failed to pause VM")?;
        Ok(())
    }

    pub async fn create_snapshot(&self, snapshot_path: &str, mem_file_path: &str) -> Result<()> {
        #[derive(Serialize)]
        struct SnapshotCreate {
            snapshot_type: String,
            snapshot_path: String,
            mem_file_path: String,
        }
        self.put(
            "/snapshot/create",
            &SnapshotCreate {
                snapshot_type: "Full".to_string(),
                snapshot_path: snapshot_path.to_string(),
                mem_file_path: mem_file_path.to_string(),
            },
        )
        .await
        .context("failed to create snapshot")
    }

    /// Load a snapshot. When `resume` is false the VM is loaded **paused**, so the
    /// caller can repoint drives ([`patch_drive`](Self::patch_drive)) — e.g. to a
    /// freshly-fenced data device — before [`resume_vm`](Self::resume_vm) lets the
    /// guest run again.
    pub async fn load_snapshot(
        &self,
        snapshot_path: &str,
        mem_file_path: &str,
        resume: bool,
    ) -> Result<()> {
        let body = serde_json::json!({
            "snapshot_path": snapshot_path,
            "mem_backend": {
                "backend_type": "File",
                "backend_path": mem_file_path
            },
            "resume_vm": resume
        });
        let json = serde_json::to_string(&body)?;
        self.request("PUT", "/snapshot/load", Some(json))
            .await
            .context("failed to load snapshot")?;
        Ok(())
    }

    /// Repoint a drive's host backing file (PATCH `/drives/{id}`). Valid post-restore
    /// while the VM is paused — used to bind the restored guest to the host device
    /// the data disk was just fenced+attached onto, instead of the path baked into
    /// the snapshot.
    pub async fn patch_drive(&self, drive_id: &str, path_on_host: &str) -> Result<()> {
        let body = serde_json::json!({
            "drive_id": drive_id,
            "path_on_host": path_on_host,
        });
        let json = serde_json::to_string(&body)?;
        self.request("PATCH", &format!("/drives/{drive_id}"), Some(json))
            .await
            .context("failed to patch drive")?;
        Ok(())
    }

    /// The drive ids currently configured on the VM, from `GET /vm/config`
    /// (`FullVmConfiguration.drives`). Used post-restore to verify a drive the
    /// snapshot was expected to carry is actually present before
    /// [`patch_drive`](Self::patch_drive) repoints it — a fail-closed check against
    /// a future Firecracker that might CREATE (rather than reject) a PATCH for an
    /// absent drive. Returns an empty list if the config reports no drives.
    pub async fn loaded_drive_ids(&self) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct DriveId {
            drive_id: String,
        }
        #[derive(Deserialize)]
        struct FullVmConfig {
            #[serde(default)]
            drives: Vec<DriveId>,
        }
        let body = self.request("GET", "/vm/config", None).await?;
        let cfg: FullVmConfig =
            serde_json::from_str(&body).context("failed to parse GET /vm/config")?;
        Ok(cfg.drives.into_iter().map(|d| d.drive_id).collect())
    }

    /// Resume a paused VM (PATCH `/vm` `{state: Resumed}`).
    pub async fn resume_vm(&self) -> Result<()> {
        let json = serde_json::to_string(&serde_json::json!({"state": "Resumed"}))?;
        self.request("PATCH", "/vm", Some(json))
            .await
            .context("failed to resume VM")?;
        Ok(())
    }
}
