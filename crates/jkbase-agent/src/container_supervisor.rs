use crate::log_sink::LogSink;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Reserved supervised-server name of the managed database. It is loopback-only and must
/// NEVER be reachable via a tenant route: `get_server_for_route` excludes it, and the host
/// fences the name from `[routes.*]`/server/site names at deploy (validate_manifest).
const DB_SERVER_NAME: &str = "rhypedb";

/// Host-side path where a restore snapshot is staged (guest-written; the host never touches
/// it — [RB5]). Bound into the DB's namespace as `/restore` and pointed at by
/// `RHYPEDB_RESTORE_FROM=/restore/snapshot` when its `MANIFEST.json` is present. A complete
/// untar renames into place atomically, so a partial/interrupted restore is never visible.
const RHYPEDB_RESTORE_STAGING: &str = "/mnt/data/volumes/rhypedb-restore/snapshot";

/// True if `dir` holds a COMPLETE rhypedb snapshot: a parseable `MANIFEST.json` plus every
/// load-bearing file it vouches for (each listed SST under `sst/`, `wal.log`, `schema.rhype`).
/// Used to gate restore-on-boot ([RB5]/[RB8]): a truncated/incomplete staged snapshot (missing
/// SSTs) would make rhypedb fail-closed on open and, left armed, crash-loop the DB across
/// reboots — so we only arm `RHYPEDB_RESTORE_FROM` when the snapshot is provably complete.
pub(crate) fn snapshot_is_complete(dir: &Path) -> bool {
    let Ok(bytes) = std::fs::read(dir.join("MANIFEST.json")) else {
        return false;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    if !dir.join("wal.log").is_file() || !dir.join("schema.rhype").is_file() {
        return false;
    }
    if let Some(ssts) = v.get("ssts").and_then(|s| s.as_array()) {
        for s in ssts.iter().filter_map(|x| x.as_str()) {
            let base = Path::new(s).file_name().and_then(|n| n.to_str()).unwrap_or(s);
            if !dir.join("sst").join(base).is_file() {
                return false;
            }
        }
    }
    true
}

/// Build the managed-DB server manifest. Injects the per-deploy `RHYPEDB_ADMIN_TOKEN` (host-
/// only, from the reserved channel — [RB1]) and, when a complete restore snapshot is staged,
/// the `/restore` volume + `RHYPEDB_RESTORE_FROM(_FORCE)` so rhypedb restore-on-boots. rhypedb's
/// restore is idempotent + sentinel-guarded, so re-applying across a crash-respawn is safe;
/// [`ContainerSupervisor::finalize_restore`] clears the staging + resets this once healthy.
///
/// NB: rhypedb-server has no `--rules` flag yet (the security-rules engine is the upstream RBAC
/// epic). v1 is backend-only — the DB is reachable only by the tenant's own app over loopback +
/// the authenticated reach plane — so no rules are enforced; rules are staged for when the
/// engine gains them. The data plane (`/query`) is open on loopback by design; `/admin/*` is
/// gated by the admin token.
fn db_manifest(admin_token: Option<&str>) -> ServerManifest {
    let mut env = HashMap::new();
    if let Some(token) = admin_token {
        env.insert("RHYPEDB_ADMIN_TOKEN".to_string(), token.to_string());
    }
    let mut volumes = vec![
        VolumeMount {
            name: "rhypedb-data".into(),
            mount: "/data".into(),
        },
        VolumeMount {
            name: "rhypedb-meta".into(),
            mount: "/etc/rhypedb".into(),
        },
    ];
    if snapshot_is_complete(Path::new(RHYPEDB_RESTORE_STAGING)) {
        volumes.push(VolumeMount {
            name: "rhypedb-restore".into(),
            mount: "/restore".into(),
        });
        env.insert(
            "RHYPEDB_RESTORE_FROM".to_string(),
            "/restore/snapshot".to_string(),
        );
        env.insert("RHYPEDB_RESTORE_FROM_FORCE".to_string(), "1".to_string());
    }
    ServerManifest {
        port: 4200,
        cmd: vec![
            "/opt/rhypedb/bin/rhypedb-server".to_string(),
            "--data-dir".into(),
            "/data".into(),
            "--schema".into(),
            "/etc/rhypedb/schema.rhype".into(),
            "--listen".into(),
            "127.0.0.1:4200".into(),
            "--tcp-listen".into(),
            "127.0.0.1:4201".into(),
        ],
        env,
        working_dir: None,
        health_check: None,
        volumes,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub name: String,
    pub mount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerManifest {
    pub port: u16,
    pub cmd: Vec<String>,
    pub env: HashMap<String, String>,
    pub working_dir: Option<String>,
    pub health_check: Option<HealthCheck>,
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
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
    /// Chroot root for legacy flat servers. Ignored when `layers` is set.
    rootfs_dir: PathBuf,
    /// erofs overlay stack (lowerdir mountpoints, app first) for layered servers.
    /// `None` ⇒ legacy flat chroot server.
    layers: Option<Vec<PathBuf>>,
    process: Option<Child>,
    healthy: bool,
    /// Consecutive (re)spawn attempts since the server was last healthy. Reset to 0 once
    /// it passes a health check. Drives the exponential restart backoff so a crash-looping
    /// server doesn't hot-loop the supervisor (one respawn per health pass).
    restart_count: u32,
    /// Earliest instant the next (re)spawn may be attempted (the backoff gate). `None` ⇒
    /// respawn immediately on the next pass (a fresh server or a recovered one).
    next_restart_at: Option<Instant>,
}

pub struct ContainerSupervisor {
    servers: RwLock<Vec<ManagedServer>>,
    servers_dir: PathBuf,
    extract_dir: PathBuf,
    /// `server name` → its erofs overlay stack (lowerdir mountpoints, app first),
    /// resolved at boot from `_layers.json`. A server present here is layered
    /// (overlay + pivot_root); absent ⇒ legacy flat chroot.
    layer_map: HashMap<String, Vec<PathBuf>>,
    /// The process-wide shared log sink (owns the `seq` source + `boot_id`),
    /// constructed in `main` and handed to every log producer. See [`LogSink`].
    logs: Arc<LogSink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub name: String,
    pub port: u16,
    pub running: bool,
    pub healthy: bool,
}

impl ContainerSupervisor {
    pub fn new(
        servers_dir: PathBuf,
        layer_map: HashMap<String, Vec<PathBuf>>,
        logs: Arc<LogSink>,
    ) -> Self {
        let extract_dir = PathBuf::from("/tmp/jkbase-servers");
        Self {
            servers: RwLock::new(Vec::new()),
            servers_dir,
            extract_dir,
            layer_map,
            logs,
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

            let layers = self.layer_map.get(&name).cloned();

            let (rootfs_dir, process) = if let Some(ref lowerdirs) = layers {
                // Layered server: the erofs overlay stack (app:runtime:base) provides
                // the root; the server runs in its own mount namespace and pivots into
                // the composed view. Volumes are bound inside that namespace by
                // spawn_server_layered. No rootfs tree lives in the metadata image.
                info!(server = %name, port = manifest.port, layers = lowerdirs.len(), "starting layered server (overlay+pivot_root)");
                let process = spawn_server_layered(&name, &manifest, lowerdirs, &self.logs)?;
                (PathBuf::from("/"), process)
            } else {
                // Legacy flat server: chroot into a self-contained rootfs tree.
                let pre_extracted = self.servers_dir.join(&name);
                let tarball = self.servers_dir.join(format!("{name}.tar.gz"));
                let has_volumes = !manifest.volumes.is_empty();

                let rootfs_dir = if pre_extracted.is_dir() && !has_volumes {
                    info!(server = %name, "using pre-extracted rootfs (read-only)");
                    pre_extracted
                } else if pre_extracted.is_dir() && has_volumes {
                    remount_rw("/srv/www");
                    info!(server = %name, "using pre-extracted rootfs (remounted rw for volume mounts)");
                    pre_extracted
                } else if tarball.exists() {
                    let extract_to = self.extract_dir.join(&name);
                    info!(server = %name, "extracting server rootfs to tmpfs");
                    extract_tarball(&tarball, &extract_to)?;
                    extract_to
                } else {
                    warn!(server = %name, "no rootfs found, skipping");
                    continue;
                };

                // Bind-mount persistent volumes into the container rootfs
                for vol in &manifest.volumes {
                    let src = PathBuf::from("/mnt/data/volumes").join(&vol.name);
                    let dst = rootfs_dir.join(vol.mount.trim_start_matches('/'));
                    if std::path::Path::new("/mnt/data").exists() {
                        let _ = std::fs::create_dir_all(&src);
                        let _ = std::fs::create_dir_all(&dst);
                        bind_mount(&src, &dst);
                        info!(server = %name, volume = %vol.name, mount = %vol.mount, "volume mounted");
                    } else {
                        warn!(server = %name, volume = %vol.name, "no data disk, skipping volume");
                    }
                }

                info!(server = %name, port = manifest.port, "starting server (chroot)");
                let process = spawn_server_chroot(&name, &manifest, &rootfs_dir, &self.logs)?;
                (rootfs_dir, process)
            };

            servers.push(ManagedServer {
                name,
                manifest,
                rootfs_dir,
                layers,
                process: Some(process),
                healthy: false,
                restart_count: 0,
                next_restart_at: None,
            });
        }

        Ok(())
    }

    /// Start the managed database (RhypeDB) as a dedicated, loopback-only supervised
    /// server composed from the rhypedb runtime layer (`lowerdir=rhypedb:base`). This is
    /// NOT a tenant server: it never appears in `_servers/` or the route table, binds only
    /// 127.0.0.1:4200/4201, and is reachable solely by the project's own app over loopback.
    /// The schema (+ optional rules) are seeded into a meta volume bound at `/etc/rhypedb`;
    /// data lives on the persistent disk at `/data`. Runs through the same overlay+pivot,
    /// restart, health, and log machinery as every other layered server.
    pub async fn start_database(
        &self,
        admin_token: Option<&str>,
        schema: &[u8],
        rules: Option<&[u8]>,
        lowerdirs: Vec<PathBuf>,
    ) -> Result<()> {
        const NAME: &str = DB_SERVER_NAME;
        if lowerdirs.is_empty() {
            anyhow::bail!("managed DB has no layers");
        }
        // The DB MUST have a persistent disk (the host forces one when [database] is
        // declared); without /mnt/data its data would land on the ephemeral overlay
        // tmpfs and vanish on restart/hibernate — fail closed rather than lose data.
        if !Path::new("/mnt/data").exists() {
            anyhow::bail!(
                "no data disk mounted; refusing to start the managed DB on ephemeral storage"
            );
        }

        // Seed the schema (+ rules) into the meta volume BEFORE the bind — spawn binds
        // /mnt/data/volumes/rhypedb-meta → /etc/rhypedb, so the files must already exist.
        // Rewritten every boot from the current metadata image, so a redeploy's schema
        // takes effect on the next boot.
        let meta_src = PathBuf::from("/mnt/data/volumes/rhypedb-meta");
        std::fs::create_dir_all(&meta_src).context("create rhypedb meta volume dir")?;
        std::fs::write(meta_src.join("schema.rhype"), schema).context("seed DB schema")?;
        if let Some(r) = rules {
            std::fs::write(meta_src.join("rules.rhype"), r).context("seed DB rules")?;
        }
        let _ = std::fs::create_dir_all("/mnt/data/volumes/rhypedb-data");

        let manifest = db_manifest(admin_token);
        info!(
            port = manifest.port,
            layers = lowerdirs.len(),
            restore = manifest.env.contains_key("RHYPEDB_RESTORE_FROM"),
            "starting managed database (rhypedb, loopback-only)"
        );
        let process = spawn_server_layered(NAME, &manifest, &lowerdirs, &self.logs)?;
        let mut servers = self.servers.write().await;
        servers.push(ManagedServer {
            name: NAME.to_string(),
            manifest,
            rootfs_dir: PathBuf::from("/"),
            layers: Some(lowerdirs),
            process: Some(process),
            healthy: false,
            restart_count: 0,
            next_restart_at: None,
        });
        Ok(())
    }

    /// Respawn the managed DB so it restore-on-boots from the freshly-staged snapshot
    /// ([RB9]). The caller has already untarred a complete snapshot to [`RHYPEDB_RESTORE_STAGING`]
    /// (its `MANIFEST.json` present), so [`db_manifest`] now adds the `/restore` volume +
    /// `RHYPEDB_RESTORE_FROM`. Held under the servers write lock across kill→reap→respawn so
    /// the health loop can't race-respawn a plain (non-restoring) DB onto the same data dir,
    /// and rhypedb (single-writer) has released its data-dir lock before the restoring process
    /// starts.
    pub async fn restore_database(&self, admin_token: Option<&str>) -> Result<()> {
        let mut servers = self.servers.write().await;
        let srv = servers
            .iter_mut()
            .find(|s| s.name == DB_SERVER_NAME)
            .ok_or_else(|| anyhow::anyhow!("managed DB is not supervised"))?;
        let lowerdirs = srv
            .layers
            .clone()
            .ok_or_else(|| anyhow::anyhow!("managed DB has no layers"))?;
        if let Some(mut child) = srv.process.take() {
            let _ = child.start_kill();
            let _ = child.wait().await; // reap → release the single-writer data-dir lock
        }
        let manifest = db_manifest(admin_token); // sees the staged snapshot → restore env
        let process = spawn_server_layered(&srv.name, &manifest, &lowerdirs, &self.logs)?;
        srv.manifest = manifest;
        srv.process = Some(process);
        srv.healthy = false;
        srv.restart_count = 0;
        srv.next_restart_at = None;
        Ok(())
    }

    /// Called once a restore has completed (the DB is serving again): remove the staged
    /// snapshot and reset the DB's manifest to a normal (non-restoring) one, so a later
    /// health-loop respawn or cold boot doesn't re-point `RHYPEDB_RESTORE_FROM` at a
    /// now-deleted path. The running process is untouched (it already restored). Safe because
    /// "healthy" ⟹ rhypedb's own `RESTORE_DONE` sentinel is durable in the data dir, so the
    /// staging is no longer needed. Idempotent.
    pub async fn finalize_restore(&self, admin_token: Option<&str>) {
        let _ = std::fs::remove_dir_all(RHYPEDB_RESTORE_STAGING);
        let mut servers = self.servers.write().await;
        if let Some(srv) = servers.iter_mut().find(|s| s.name == DB_SERVER_NAME) {
            srv.manifest = db_manifest(admin_token);
        }
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
        let now = Instant::now();
        let mut servers = self.servers.write().await;
        for server in servers.iter_mut() {
            // Reap an exited process so the (re)spawn path below treats it like any other
            // server with no live process. Drop the handle (process = None) rather than
            // respawning inline — the backoff gate decides whether/when to respawn.
            if let Some(ref mut process) = server.process {
                match process.try_wait() {
                    Ok(Some(status)) => {
                        warn!(server = %server.name, exit_code = ?status.code(), "server process exited");
                        server.healthy = false;
                        server.process = None;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!(server = %server.name, error = %e, "failed to check server status");
                        continue;
                    }
                }
            }

            // (Re)spawn any server with no live process — whether it just exited OR a prior
            // respawn itself errored (which previously left `process = None` and was NEVER
            // retried). Gated by an exponential backoff so a crash-looping server respawns
            // at most once per capped interval instead of once per health pass.
            if server.process.is_none() {
                if server.next_restart_at.is_some_and(|at| now < at) {
                    continue; // still backing off — retry on a later pass
                }
                let respawn = match &server.layers {
                    Some(lowerdirs) => {
                        spawn_server_layered(&server.name, &server.manifest, lowerdirs, &self.logs)
                    }
                    None => spawn_server_chroot(
                        &server.name,
                        &server.manifest,
                        &server.rootfs_dir,
                        &self.logs,
                    ),
                };
                server.restart_count = server.restart_count.saturating_add(1);
                server.next_restart_at = Some(now + restart_backoff(server.restart_count));
                match respawn {
                    Ok(new_process) => {
                        info!(server = %server.name, attempt = server.restart_count, "restarted server");
                        server.process = Some(new_process);
                    }
                    Err(e) => {
                        error!(server = %server.name, attempt = server.restart_count, error = %e, "failed to restart server; retrying after backoff");
                    }
                }
                continue; // give the fresh (or still-absent) process a pass before probing
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

            // A healthy server clears its restart backoff so a later crash restarts promptly.
            if server.healthy {
                server.restart_count = 0;
                server.next_restart_at = None;
            }
        }
    }

    /// True when the supervisor manages at least one process — tenant servers AND/OR the
    /// managed DB. (Counts the DB, which is not a `_servers/` entry, so a DB-only project
    /// still gets the health/respawn loop.) Call after `start_all` + `start_database`.
    pub async fn is_supervising(&self) -> bool {
        !self.servers.read().await.is_empty()
    }

    pub async fn get_server_for_route(&self, route_name: &str) -> Option<u16> {
        let servers = self.servers.read().await;
        servers
            .iter()
            // The managed DB is loopback-only and never routed: exclude it so a stray
            // route named `rhypedb` can never be proxied to (defense in depth — the host
            // also rejects such a route at deploy). See DB_SERVER_NAME.
            .find(|s| s.name != DB_SERVER_NAME && s.name == route_name)
            .map(|s| s.manifest.port)
    }
}

/// Exponential restart backoff: the wait before the next (re)spawn after `attempt`
/// consecutive attempts. The first respawn is immediate (the `next_restart_at` gate is
/// `None`); thereafter 1s, 2s, 4s, … doubling, capped at 60s. Bounds a crash-looping
/// server to one respawn per capped interval instead of one per health-check pass.
fn restart_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6); // 2^0..=2^6 → 1..=64s, then capped
    Duration::from_secs((1u64 << shift).min(60))
}

fn remount_rw(target: &str) {
    use std::ffi::CString;
    use std::ptr;

    let tgt = CString::new(target).unwrap();
    let ret = unsafe {
        libc::mount(
            ptr::null(),
            tgt.as_ptr(),
            ptr::null(),
            libc::MS_REMOUNT,
            ptr::null(),
        )
    };
    if ret != 0 {
        tracing::warn!(
            target = target,
            error = %std::io::Error::last_os_error(),
            "remount rw failed"
        );
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

const BASE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Apply the per-server env every server process gets, plus its manifest env.
/// `extra_path` (e.g. the bun bin dir) is appended to PATH when set.
///
/// `image_self` marks a self-contained image server (the `builder = "dockerfile"`
/// escape hatch): it carries its own userland, so the image's own `PATH`/`HOME`/
/// `HOSTNAME` (from the OCI config, in `manifest.env`) must WIN — we only supply a
/// default when the image left one unset, and the `/opt/bun` PATH append is
/// irrelevant. `PORT` stays platform-authoritative in BOTH modes (the routing
/// contract), applied last so no manifest env can clobber it. For the normal
/// (layered) path, the platform sets PATH/HOME/HOSTNAME authoritatively as before.
fn apply_server_env(
    std_cmd: &mut std::process::Command,
    manifest: &ServerManifest,
    extra_path: &str,
    image_self: bool,
) {
    std_cmd.env_clear();
    // Tenant/build-supplied env FIRST (build-time `NODE_ENV` + host-injected project
    // secrets), so the platform-reserved vars below win where they apply. The host
    // already filters reserved keys (PORT/HOME/HOSTNAME/PATH) out of secret injection,
    // so a secret can never reach the reserved set — only the BUILD (e.g. an image's
    // OCI Env) populates PATH/HOME here, which is exactly what image_self honours.
    for (key, value) in &manifest.env {
        std_cmd.env(key, value);
    }
    // PORT is the routing contract — authoritative in every mode, applied last.
    std_cmd.env("PORT", manifest.port.to_string());

    if image_self {
        // Honour the image's own userland; default only what it didn't set.
        if !manifest.env.contains_key("HOME") {
            std_cmd.env("HOME", "/root");
        }
        if !manifest.env.contains_key("HOSTNAME") {
            std_cmd.env("HOSTNAME", "0.0.0.0");
        }
        if !manifest.env.contains_key("PATH") {
            std_cmd.env("PATH", BASE_PATH);
        }
    } else {
        std_cmd.env("HOME", "/root");
        std_cmd.env("HOSTNAME", "0.0.0.0");
        let path = if extra_path.is_empty() {
            BASE_PATH.to_string()
        } else {
            format!("{BASE_PATH}:{extra_path}")
        };
        std_cmd.env("PATH", path);
    }
    std_cmd.stdout(Stdio::piped());
    std_cmd.stderr(Stdio::piped());
}

/// Drain the child's stdout/stderr into the shared log sink.
fn attach_log_readers(child: &mut Child, name: &str, logs: &Arc<LogSink>) {
    let server_name = name.to_string();
    if let Some(stdout) = child.stdout.take() {
        let sink = logs.clone();
        let sname = server_name.clone();
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                sink.push(&sname, "stdout", line).await;
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let sink = logs.clone();
        let sname = server_name.clone();
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                sink.push(&sname, "stderr", line).await;
            }
        });
    }
}

/// Legacy flat server: chroot into a self-contained rootfs tree. Used only for
/// pre-layered deployments; new server builds are layered (see
/// [`spawn_server_layered`]).
fn spawn_server_chroot(
    name: &str,
    manifest: &ServerManifest,
    rootfs_dir: &Path,
    logs: &Arc<LogSink>,
) -> Result<Child> {
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
    apply_server_env(&mut std_cmd, manifest, "", false);

    unsafe {
        std_cmd.pre_exec(move || {
            if libc::chroot(
                CString::new(chroot_dir.to_string_lossy().as_bytes())
                    .map_err(|_| io::Error::other("invalid chroot path"))?
                    .as_ptr(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let wd = CString::new(working_dir.as_bytes())
                .map_err(|_| io::Error::other("invalid working dir"))?;
            if libc::chdir(wd.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = Command::from(std_cmd)
        .spawn()
        .with_context(|| format!("failed to spawn server '{name}': {:?}", manifest.cmd))?;

    attach_log_readers(&mut child, name, logs);
    info!(server = %name, pid = ?child.id(), cmd = ?manifest.cmd, "server process started (chroot: {})", rootfs_dir.display());
    Ok(child)
}

/// Where each layered server's overlay scratch (upper/work/merged) lives. On
/// tmpfs because the agent root is a read-only erofs/ext4 image.
const LAYER_RUN_BASE: &str = "/tmp/jkbase-run";

/// DNS resolver written into each runtime container's `/etc/resolv.conf`: the runtime
/// BRIDGE GATEWAY (172.16.0.1), where the host runs a DNS forwarder (systemd-resolved
/// exposed on the bridge IP; see tools/setup-bridge.sh). Without this an app can reach
/// literal IPs but cannot resolve hostnames. We point at the gateway rather than a
/// public resolver because many hosts (e.g. OVH) block outbound UDP/53 to public
/// resolvers — a UDP/53 query to the LOCAL gateway always works, and the host forwards
/// upstream however it can (provider-agnostic, works for every DNS client).
const RUNTIME_RESOLV_CONF: &str = "nameserver 172.16.0.1\noptions edns0\n";

/// Layered server: compose `lowerdir=app:runtime:base` over a tmpfs upper, then
/// run the server in its own mount namespace pivoted into that composed root.
/// This replaces chroot for the layered (erofs) runtime — each server gets a
/// private root assembled from the shared platform layers plus its own app layer.
/// The base/runtime layers are shared (RO) across every server in the VM; only
/// the tmpfs upper and the app layer differ.
fn spawn_server_layered(
    name: &str,
    manifest: &ServerManifest,
    lowerdirs: &[PathBuf],
    logs: &Arc<LogSink>,
) -> Result<Child> {
    use std::os::unix::process::CommandExt;

    if manifest.cmd.is_empty() {
        anyhow::bail!("server '{name}' has empty cmd");
    }
    if lowerdirs.is_empty() {
        anyhow::bail!("layered server '{name}' has no layers");
    }

    // Per-server overlay scratch on tmpfs. upper/work hold the container's runtime
    // writes; merged is the composed root the child pivots into.
    let run_dir = PathBuf::from(LAYER_RUN_BASE).join(name);
    let upper = run_dir.join("upper");
    let work = run_dir.join("work");
    let merged = run_dir.join("merged");
    for d in [&upper, &work, &merged] {
        std::fs::create_dir_all(d)
            .with_context(|| format!("create overlay scratch {}", d.display()))?;
    }

    // A single lowerdir is a self-contained image (image/self = the `builder =
    // "dockerfile"` / OCI case): it owns its full userland, possibly including a curated
    // /etc/resolv.conf (custom resolver / search / ndots).
    let image_self = lowerdirs.len() == 1;

    // Give the container working DNS: write /etc/resolv.conf into the overlay UPPER dir,
    // so it shadows the lower and appears in the merged root the child pivots into.
    // Best-effort — a missing resolver degrades to literal-IP-only egress, not a server
    // failure. EXCEPTION: for a self-contained image that ships its OWN resolv.conf,
    // honour it rather than clobbering it with our public resolvers.
    let lower_has_resolv = image_self
        && lowerdirs
            .first()
            .map(|l| l.join("etc/resolv.conf").exists())
            .unwrap_or(false);
    if lower_has_resolv {
        info!(server = %name, "image ships its own /etc/resolv.conf; not overriding");
    } else {
        let etc = upper.join("etc");
        if let Err(e) = std::fs::create_dir_all(&etc)
            .and_then(|()| std::fs::write(etc.join("resolv.conf"), RUNTIME_RESOLV_CONF))
        {
            warn!(server = %name, error = %e, "failed to write container resolv.conf; DNS may not resolve");
        }
    }

    let working_dir = manifest
        .working_dir
        .clone()
        .unwrap_or_else(|| "/".to_string());

    // Volumes (mirroring the flat chroot path's graceful degradation): only bind
    // when the data disk is mounted, and create the source dir host-side first.
    // Without this, a missing/failed data disk would hard-fail the server in the
    // post-fork child (an opaque exit + restart loop) instead of warn-and-skip.
    let volumes: Vec<VolumeMount> = if manifest.volumes.is_empty() {
        Vec::new()
    } else if std::path::Path::new("/mnt/data").exists() {
        manifest
            .volumes
            .iter()
            .filter_map(|v| {
                let src = PathBuf::from("/mnt/data/volumes").join(&v.name);
                match std::fs::create_dir_all(&src) {
                    Ok(()) => Some(v.clone()),
                    Err(e) => {
                        warn!(server = %name, volume = %v.name, error = %e, "cannot create volume source; skipping");
                        None
                    }
                }
            })
            .collect()
    } else {
        for v in &manifest.volumes {
            warn!(server = %name, volume = %v.name, "no data disk mounted; skipping volume");
        }
        Vec::new()
    };

    // Precompute the whole namespace recipe as CStrings before the fork — the
    // pre_exec closure runs between fork and exec and must not allocate.
    let setup = LayeredSetup::build(&merged, &upper, &work, lowerdirs, &volumes, &working_dir)
        .with_context(|| format!("build layered setup for '{name}'"))?;

    let mut std_cmd = std::process::Command::new(&manifest.cmd[0]);
    if manifest.cmd.len() > 1 {
        std_cmd.args(&manifest.cmd[1..]);
    }
    // image_self (a single self-contained lowerdir) computed above: no shared base/
    // runtime beneath it, so honour the image's own PATH/HOME and skip /opt/bun.
    let extra_path = if image_self { "" } else { "/opt/bun/bin" };
    apply_server_env(&mut std_cmd, manifest, extra_path, image_self);

    unsafe {
        std_cmd.pre_exec(move || setup.enter());
    }

    let mut child = Command::from(std_cmd).spawn().with_context(|| {
        format!(
            "failed to spawn layered server '{name}': {:?}",
            manifest.cmd
        )
    })?;

    attach_log_readers(&mut child, name, logs);
    info!(
        server = %name,
        pid = ?child.id(),
        cmd = ?manifest.cmd,
        layers = lowerdirs.len(),
        "layered server process started (overlay+pivot_root)"
    );
    Ok(child)
}

/// An allocation-free, pre-built recipe for composing one layered server's root
/// and pivoting into it from inside the post-fork child. All paths are CStrings
/// so [`enter`](Self::enter) only issues syscalls.
struct LayeredSetup {
    overlay_opts: CString, // lowerdir=...:...,upperdir=...,workdir=...
    merged: CString,       // overlay mountpoint == new root
    put_old: CString,      // merged/oldroot
    proc_target: CString,  // merged/proc
    sys_target: CString,   // merged/sys
    dev_target: CString,   // merged/dev
    oldroot_dir: CString,  // merged/oldroot (mkdir before pivot)
    volume_binds: Vec<(CString, CString)>, // (host src, merged/<mount>)
    working_dir: CString,  // chdir target inside the new root
    // constant fs labels, precomputed to keep enter() allocation-free
    c_slash: CString,
    c_overlay: CString,
    c_proc: CString,
    c_sysfs: CString,
    c_devtmpfs: CString,
    c_oldroot_abs: CString, // "/oldroot" after pivot
}

impl LayeredSetup {
    fn build(
        merged: &Path,
        upper: &Path,
        work: &Path,
        lowerdirs: &[PathBuf],
        volumes: &[VolumeMount],
        working_dir: &str,
    ) -> Result<Self> {
        let lower = lowerdirs
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":");
        let opts = format!(
            "lowerdir={lower},upperdir={},workdir={}",
            upper.to_string_lossy(),
            work.to_string_lossy()
        );
        let cstr = |s: &str| CString::new(s).context("path contains NUL");
        let cpath = |p: &Path| {
            CString::new(p.to_string_lossy().as_bytes().to_vec()).context("path contains NUL")
        };

        let volume_binds = volumes
            .iter()
            .map(|v| {
                let src = PathBuf::from("/mnt/data/volumes").join(&v.name);
                let dst = merged.join(v.mount.trim_start_matches('/'));
                Ok((cpath(&src)?, cpath(&dst)?))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            overlay_opts: cstr(&opts)?,
            merged: cpath(merged)?,
            put_old: cpath(&merged.join("oldroot"))?,
            proc_target: cpath(&merged.join("proc"))?,
            sys_target: cpath(&merged.join("sys"))?,
            dev_target: cpath(&merged.join("dev"))?,
            oldroot_dir: cpath(&merged.join("oldroot"))?,
            volume_binds,
            working_dir: cstr(working_dir)?,
            c_slash: cstr("/")?,
            c_overlay: cstr("overlay")?,
            c_proc: cstr("proc")?,
            c_sysfs: cstr("sysfs")?,
            c_devtmpfs: cstr("devtmpfs")?,
            c_oldroot_abs: cstr("/oldroot")?,
        })
    }

    /// Runs in the post-fork child. Builds the overlay root, mounts proc/sys/dev
    /// and volumes inside it, then `pivot_root`s in — all in a fresh, private
    /// mount namespace so nothing leaks back to the agent. Returns on the first
    /// failed syscall (the child's exec then aborts and the parent sees the error).
    fn enter(&self) -> io::Result<()> {
        unsafe {
            // Private mount namespace: pivot_root requires the new root and its
            // parent to not be shared, and keeps our mounts out of the agent's view.
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::mount(
                ptr::null(),
                self.c_slash.as_ptr(),
                ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Compose the overlay root (lower=app:runtime:base, upper=tmpfs).
            if libc::mount(
                self.c_overlay.as_ptr(),
                self.merged.as_ptr(),
                self.c_overlay.as_ptr(),
                0,
                self.overlay_opts.as_ptr().cast(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // proc/sys/dev inside the new root (mkdir best-effort — the base layer
            // already carries the skeleton; ignore EEXIST).
            libc::mkdir(self.proc_target.as_ptr(), 0o555);
            if libc::mount(
                self.c_proc.as_ptr(),
                self.proc_target.as_ptr(),
                self.c_proc.as_ptr(),
                0,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::mkdir(self.sys_target.as_ptr(), 0o555);
            if libc::mount(
                self.c_sysfs.as_ptr(),
                self.sys_target.as_ptr(),
                self.c_sysfs.as_ptr(),
                0,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::mkdir(self.dev_target.as_ptr(), 0o755);
            if libc::mount(
                self.c_devtmpfs.as_ptr(),
                self.dev_target.as_ptr(),
                self.c_devtmpfs.as_ptr(),
                0,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Bind persistent volumes (data disk) into the new root. Best-effort: a
            // volume that vanished between the host-side check and here must not kill
            // the server — it runs without that volume, matching the flat path's
            // graceful skip (the host-side check above is the observable warning).
            for (src, dst) in &self.volume_binds {
                libc::mkdir(dst.as_ptr(), 0o755);
                let _ = libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    ptr::null(),
                );
            }
            // pivot_root into the composed view.
            libc::mkdir(self.oldroot_dir.as_ptr(), 0o755);
            if libc::chdir(self.merged.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_pivot_root,
                self.merged.as_ptr(),
                self.put_old.as_ptr(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Now rooted at the overlay; detach the old root lazily.
            if libc::chdir(self.c_slash.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::umount2(self.c_oldroot_abs.as_ptr(), libc::MNT_DETACH);
            // Land in the app's working directory (e.g. /app).
            if libc::chdir(self.working_dir.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

fn bind_mount(src: &Path, dst: &Path) {
    use std::ffi::CString;
    use std::ptr;

    let src_c = CString::new(src.to_string_lossy().as_bytes()).unwrap();
    let dst_c = CString::new(dst.to_string_lossy().as_bytes()).unwrap();

    let ret = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            ptr::null(),
            libc::MS_BIND,
            ptr::null(),
        )
    };
    if ret != 0 {
        tracing::error!(
            src = %src.display(),
            dst = %dst.display(),
            error = %std::io::Error::last_os_error(),
            "bind mount failed"
        );
    }
}

async fn tcp_health_check(addr: &str) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_backoff_escalates_then_caps() {
        // First respawn is gated by next_restart_at=None (immediate); this is the wait
        // AFTER attempt N before attempt N+1: 1,2,4,8,16,32,64→capped 60, then steady 60.
        assert_eq!(restart_backoff(1), Duration::from_secs(1));
        assert_eq!(restart_backoff(2), Duration::from_secs(2));
        assert_eq!(restart_backoff(3), Duration::from_secs(4));
        assert_eq!(restart_backoff(4), Duration::from_secs(8));
        assert_eq!(restart_backoff(5), Duration::from_secs(16));
        assert_eq!(restart_backoff(6), Duration::from_secs(32));
        assert_eq!(restart_backoff(7), Duration::from_secs(60)); // 64 capped to 60
        assert_eq!(restart_backoff(100), Duration::from_secs(60));
        // Monotonic non-decreasing, never zero (the gate, not this fn, gives the immediate
        // first respawn) — so a crash loop can never hot-loop the supervisor.
        for n in 1..200u32 {
            assert!(restart_backoff(n) >= Duration::from_secs(1));
            assert!(restart_backoff(n + 1) >= restart_backoff(n));
        }
    }

    #[test]
    fn apply_server_env_reserved_vars_win_over_manifest_env() {
        let mut env = HashMap::new();
        env.insert("DOMAIN".to_string(), "forumall.jkbase.app".to_string());
        env.insert("NODE_ENV".to_string(), "production".to_string());
        // A hostile/buggy manifest (or a project secret) tries to clobber reserved vars.
        env.insert("PORT".to_string(), "9999".to_string());
        env.insert("PATH".to_string(), "/evil".to_string());
        let manifest = ServerManifest {
            port: 3000,
            cmd: vec!["/opt/bun/bin/bun".into(), "run".into(), "start".into()],
            env,
            working_dir: Some("/app".into()),
            health_check: None,
            volumes: vec![],
        };
        let mut cmd = std::process::Command::new("true");
        apply_server_env(&mut cmd, &manifest, "/opt/bun/bin", false);
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        // Injected env/secret reaches the container...
        assert_eq!(
            envs.get("DOMAIN").map(String::as_str),
            Some("forumall.jkbase.app")
        );
        assert_eq!(envs.get("NODE_ENV").map(String::as_str), Some("production"));
        // ...but the platform sets the reserved vars authoritatively (manifest loses).
        assert_eq!(
            envs.get("PORT").map(String::as_str),
            Some("3000"),
            "platform PORT wins"
        );
        assert_ne!(
            envs.get("PATH").map(String::as_str),
            Some("/evil"),
            "platform PATH wins"
        );
        assert!(envs.get("PATH").is_some_and(|p| p.contains("/opt/bun/bin")));
        assert_eq!(envs.get("HOME").map(String::as_str), Some("/root"));
    }

    #[test]
    fn apply_server_env_image_self_honours_image_path_home_but_forces_port() {
        // An image/self server's OCI Env (in manifest.env) owns PATH/HOME; PORT is
        // still platform-authoritative. (Secrets can't reach PATH/HOME — the host
        // filters reserved keys at injection — so manifest.env here is the image's.)
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/local/bin:/sbin:/bin".to_string());
        env.insert("HOME".to_string(), "/home/node".to_string());
        env.insert("NODE_ENV".to_string(), "production".to_string());
        env.insert("PORT".to_string(), "9999".to_string()); // image's EXPOSE/Env loses to platform
        let manifest = ServerManifest {
            port: 3000,
            cmd: vec!["/usr/local/bin/node".into(), "server.js".into()],
            env,
            working_dir: Some("/app".into()),
            health_check: None,
            volumes: vec![],
        };
        let mut cmd = std::process::Command::new("true");
        apply_server_env(&mut cmd, &manifest, "", true);
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        // The image's own PATH/HOME win (NOT clobbered, no /opt/bun appended).
        assert_eq!(
            envs.get("PATH").map(String::as_str),
            Some("/usr/local/bin:/sbin:/bin")
        );
        assert_eq!(envs.get("HOME").map(String::as_str), Some("/home/node"));
        assert!(
            !envs["PATH"].contains("/opt/bun"),
            "no bun PATH for an image server"
        );
        // PORT remains the routing contract regardless of mode.
        assert_eq!(
            envs.get("PORT").map(String::as_str),
            Some("3000"),
            "platform PORT wins"
        );
        assert_eq!(envs.get("NODE_ENV").map(String::as_str), Some("production"));

        // And when the image sets NO PATH/HOME, the platform defaults fill in.
        let manifest2 = ServerManifest {
            port: 3000,
            cmd: vec!["/server".into()],
            env: HashMap::new(),
            working_dir: None,
            health_check: None,
            volumes: vec![],
        };
        let mut cmd2 = std::process::Command::new("true");
        apply_server_env(&mut cmd2, &manifest2, "", true);
        let envs2: HashMap<String, String> = cmd2
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        assert_eq!(envs2.get("HOME").map(String::as_str), Some("/root"));
        assert_eq!(envs2.get("PATH").map(String::as_str), Some(BASE_PATH));
    }
}
