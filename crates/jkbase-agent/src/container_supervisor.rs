use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerManifest {
    pub port: u16,
    pub cmd: Vec<String>,
    pub env: HashMap<String, String>,
    pub working_dir: Option<String>,
    pub health_check: Option<HealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub path: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
}

struct ManagedServer {
    name: String,
    manifest: ServerManifest,
    rootfs_dir: PathBuf,
    process: Option<Child>,
    healthy: bool,
}

pub struct ContainerSupervisor {
    servers: RwLock<Vec<ManagedServer>>,
    servers_dir: PathBuf,
    extract_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub name: String,
    pub port: u16,
    pub running: bool,
    pub healthy: bool,
}

impl ContainerSupervisor {
    pub fn new(servers_dir: PathBuf) -> Self {
        let extract_dir = PathBuf::from("/tmp/jkbase-servers");
        Self {
            servers: RwLock::new(Vec::new()),
            servers_dir,
            extract_dir,
        }
    }

    pub async fn start_all(&self) -> Result<()> {
        if !self.servers_dir.exists() {
            return Ok(());
        }

        let _ = std::fs::create_dir_all(&self.extract_dir);

        let mut entries: Vec<_> = Vec::new();
        for entry in std::fs::read_dir(&self.servers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                entries.push((name, path));
            }
        }

        if entries.is_empty() {
            return Ok(());
        }

        let mut servers = self.servers.write().await;

        for (name, manifest_path) in entries {
            let manifest_content = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("failed to read manifest for server '{name}'"))?;
            let manifest: ServerManifest = serde_json::from_str(&manifest_content)
                .with_context(|| format!("failed to parse manifest for server '{name}'"))?;

            let tarball = self.servers_dir.join(format!("{name}.tar.gz"));
            let rootfs_dir = self.extract_dir.join(&name);

            if tarball.exists() {
                info!(server = %name, "extracting server rootfs");
                extract_tarball(&tarball, &rootfs_dir)?;
            } else if !rootfs_dir.exists() {
                warn!(server = %name, "no tarball and no extracted rootfs, skipping");
                continue;
            }

            info!(server = %name, port = manifest.port, "starting server");
            let process = spawn_server(&name, &manifest, &rootfs_dir)?;

            servers.push(ManagedServer {
                name,
                manifest,
                rootfs_dir,
                process: Some(process),
                healthy: false,
            });
        }

        Ok(())
    }

    pub async fn status(&self) -> Vec<ServerStatus> {
        let servers = self.servers.read().await;
        servers
            .iter()
            .map(|s| {
                let running = s
                    .process
                    .as_ref()
                    .map(|p| p.id().is_some())
                    .unwrap_or(false);
                ServerStatus {
                    name: s.name.clone(),
                    port: s.manifest.port,
                    running,
                    healthy: s.healthy,
                }
            })
            .collect()
    }

    pub async fn run_health_checks(&self) {
        let mut servers = self.servers.write().await;
        for server in servers.iter_mut() {
            if let Some(ref mut process) = server.process {
                match process.try_wait() {
                    Ok(Some(status)) => {
                        warn!(
                            server = %server.name,
                            exit_code = ?status.code(),
                            "server process exited, restarting"
                        );
                        server.healthy = false;
                        match spawn_server(&server.name, &server.manifest, &server.rootfs_dir) {
                            Ok(new_process) => {
                                server.process = Some(new_process);
                            }
                            Err(e) => {
                                error!(server = %server.name, error = %e, "failed to restart server");
                                server.process = None;
                            }
                        }
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!(server = %server.name, error = %e, "failed to check server status");
                        continue;
                    }
                }
            }

            let check_path = server
                .manifest
                .health_check
                .as_ref()
                .map(|h| h.path.as_str())
                .unwrap_or("/");

            let addr = format!("127.0.0.1:{}", server.manifest.port);
            let was_healthy = server.healthy;
            server.healthy = tcp_health_check(&addr).await;

            if server.healthy && !was_healthy {
                info!(server = %server.name, port = server.manifest.port, path = %check_path, "server is healthy");
            } else if !server.healthy && was_healthy {
                warn!(server = %server.name, "server health check failed");
            }
        }
    }

    pub fn has_servers(&self) -> bool {
        self.servers_dir.exists()
            && std::fs::read_dir(&self.servers_dir)
                .map(|mut d| d.any(|e| e.is_ok()))
                .unwrap_or(false)
    }

    pub async fn get_server_for_route(&self, route_name: &str) -> Option<u16> {
        let servers = self.servers.read().await;
        servers
            .iter()
            .find(|s| s.name == route_name)
            .map(|s| s.manifest.port)
    }

    pub async fn stop_all(&self) {
        let mut servers = self.servers.write().await;
        for server in servers.iter_mut() {
            if let Some(ref mut process) = server.process {
                info!(server = %server.name, "stopping server");
                let _ = process.kill().await;
            }
        }
        servers.clear();
    }
}

fn extract_tarball(tarball: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        std::fs::remove_dir_all(target)?;
    }
    std::fs::create_dir_all(target)?;

    let file = std::fs::File::open(tarball)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(true);
    archive.unpack(target)?;

    Ok(())
}

fn spawn_server(name: &str, manifest: &ServerManifest, rootfs_dir: &Path) -> Result<Child> {
    use std::os::unix::process::CommandExt;

    if manifest.cmd.is_empty() {
        anyhow::bail!("server '{name}' has empty cmd");
    }

    let chroot_dir = rootfs_dir.to_path_buf();
    let working_dir = manifest
        .working_dir
        .clone()
        .unwrap_or_else(|| "/".to_string());

    let mut std_cmd = std::process::Command::new(&manifest.cmd[0]);
    if manifest.cmd.len() > 1 {
        std_cmd.args(&manifest.cmd[1..]);
    }

    std_cmd.env_clear();
    std_cmd.env("PORT", manifest.port.to_string());
    std_cmd.env("HOME", "/root");
    std_cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    for (key, value) in &manifest.env {
        std_cmd.env(key, value);
    }
    std_cmd.stdout(Stdio::piped());
    std_cmd.stderr(Stdio::piped());

    unsafe {
        std_cmd.pre_exec(move || {
            if libc::chroot(
                std::ffi::CString::new(chroot_dir.to_string_lossy().as_bytes())
                    .map_err(|_| std::io::Error::other("invalid chroot path"))?
                    .as_ptr(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let wd = std::ffi::CString::new(working_dir.as_bytes())
                .map_err(|_| std::io::Error::other("invalid working dir"))?;
            if libc::chdir(wd.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = Command::from(std_cmd)
        .spawn()
        .with_context(|| format!("failed to spawn server '{name}': {:?}", manifest.cmd))?;

    info!(server = %name, pid = ?child.id(), cmd = ?manifest.cmd, "server process started (chroot: {})", rootfs_dir.display());
    Ok(child)
}

async fn tcp_health_check(addr: &str) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}
