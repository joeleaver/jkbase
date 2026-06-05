use anyhow::{Context, Result};
use clap::Args;
use flate2::write::GzEncoder;
use flate2::Compression;
use jkbase_common::config::ProjectConfig;
use serde::Deserialize;
use std::path::Path;

#[derive(Args)]
pub struct DeployArgs {
    /// Target project (inferred from jkbase.toml if not specified)
    #[arg(long)]
    project: Option<String>,

    /// Platform API URL
    #[arg(long, default_value = "https://api.jkbase.app")]
    api: String,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Deserialize)]
struct DeployResponse {
    version: u64,
    project_id: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run(args: DeployArgs) -> Result<()> {
    let (config, config_path) = ProjectConfig::find_and_load()?;
    let project_dir = config_path.parent().unwrap();

    let project_name = args
        .project
        .or_else(|| config.project.as_ref()?.name.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no project specified — use --project or set project.name in jkbase.toml"
            )
        })?;

    let resolved_sites = config.resolved_sites();

    // Build WASM functions
    let mut wasm_files: Vec<(String, std::path::PathBuf)> = Vec::new();
    for (name, func_config) in &config.functions {
        let source = project_dir.join(&func_config.source);
        let wasm_path = build_function(name, &source)?;
        wasm_files.push((name.clone(), wasm_path));
    }

    // Build server containers
    let mut server_artifacts: Vec<ServerArtifact> = Vec::new();
    for (name, server_config) in &config.servers {
        let dockerfile_path = project_dir.join(&server_config.dockerfile);
        println!("  Server '{name}': building {}...", dockerfile_path.display());
        let artifact = build_server(name, &dockerfile_path, project_dir, server_config)?;
        server_artifacts.push(artifact);
    }

    // Serialize route config for the agent
    let route_config = if !config.routes.is_empty() {
        Some(serde_json::to_string_pretty(&config.routes)?)
    } else {
        None
    };

    // Serialize sites config for multi-site routing
    let sites_json = if config.sites.len() > 0 {
        Some(serde_json::to_string_pretty(&resolved_sites)?)
    } else {
        None
    };

    // Serialize domain aliases
    let domains_json = if !config.domains.is_empty() {
        Some(serde_json::to_string_pretty(&config.domains)?)
    } else {
        None
    };

    // Serialize function schedules (inline cron from [functions.NAME])
    let schedules_json = {
        let scheds: Vec<_> = config
            .functions
            .iter()
            .filter_map(|(name, f)| {
                f.schedule
                    .as_ref()
                    .map(|c| serde_json::json!({ "function": name, "cron": c }))
            })
            .collect();
        if scheds.is_empty() {
            None
        } else {
            Some(serde_json::to_string_pretty(&scheds)?)
        }
    };

    println!("Packaging...");
    let tarball = create_tarball(
        project_dir,
        &resolved_sites,
        &wasm_files,
        &server_artifacts,
        route_config.as_deref(),
        sites_json.as_deref(),
        domains_json.as_deref(),
        schedules_json.as_deref(),
    )
    .context("failed to create tarball")?;
    println!("  {} bytes compressed", tarball.len());

    let project_id = slug(&project_name);
    let url = format!("{}/projects/{}/deploy", args.api, project_id);

    println!("Deploying '{project_name}'...");
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated — run `jkbase init` or `jkbase login` first"))?;
    let client = crate::credentials::authenticated_client(&token);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/gzip")
        .body(tarball)
        .send()
        .await
        .context("failed to connect to platform API")?;

    if resp.status().is_success() {
        let deploy: DeployResponse = resp.json().await?;
        println!(
            "Deployed {} v{} successfully",
            deploy.project_id, deploy.version
        );
    } else {
        let status = resp.status();
        let err: ErrorResponse = resp
            .json()
            .await
            .unwrap_or(ErrorResponse {
                error: "unknown error".to_string(),
            });
        anyhow::bail!("deploy failed ({}): {}", status, err.error);
    }

    Ok(())
}

struct ServerArtifact {
    name: String,
    rootfs_tarball: std::path::PathBuf,
    manifest_json: String,
}

fn build_server(
    name: &str,
    dockerfile: &Path,
    context_dir: &Path,
    config: &jkbase_common::config::ServerConfig,
) -> Result<ServerArtifact> {
    let image_tag = format!("jkbase-server-{name}:build");
    let dockerfile_dir = dockerfile.parent().unwrap_or(context_dir);

    let status = std::process::Command::new("docker")
        .args(["build", "-t", &image_tag, "-f"])
        .arg(dockerfile)
        .arg(dockerfile_dir)
        .status()
        .context("failed to run docker build — is Docker installed?")?;

    if !status.success() {
        anyhow::bail!("docker build failed for server '{name}'");
    }

    let output = std::process::Command::new("docker")
        .args(["create", &image_tag])
        .output()
        .context("failed to create container for export")?;

    if !output.status.success() {
        anyhow::bail!("docker create failed for server '{name}'");
    }

    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let inspect_output = std::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Config}}", &image_tag])
        .output()
        .context("failed to inspect image")?;

    let inspect_json: serde_json::Value =
        serde_json::from_slice(&inspect_output.stdout).unwrap_or_default();

    let mut cmd: Vec<String> = Vec::new();
    if let Some(entrypoint) = inspect_json["Entrypoint"].as_array() {
        for v in entrypoint {
            if let Some(s) = v.as_str() {
                cmd.push(s.to_string());
            }
        }
    }
    if let Some(docker_cmd) = inspect_json["Cmd"].as_array() {
        for v in docker_cmd {
            if let Some(s) = v.as_str() {
                cmd.push(s.to_string());
            }
        }
    }
    if cmd.is_empty() {
        cmd = vec!["/bin/sh".to_string()];
    }

    let working_dir = inspect_json["WorkingDir"]
        .as_str()
        .unwrap_or("/")
        .to_string();

    let tarball_path = std::env::temp_dir().join(format!("jkbase-server-{name}.tar.gz"));
    let export_status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "docker export {} | gzip > {}",
            container_id,
            tarball_path.display()
        ))
        .status()
        .context("failed to export container filesystem")?;

    let _ = std::process::Command::new("docker")
        .args(["rm", &container_id])
        .status();

    if !export_status.success() {
        anyhow::bail!("docker export failed for server '{name}'");
    }

    let volumes: Vec<serde_json::Value> = config
        .volumes
        .iter()
        .map(|v| serde_json::json!({"name": v.name, "mount": v.mount}))
        .collect();

    let manifest = serde_json::json!({
        "port": config.port,
        "cmd": cmd,
        "env": {},
        "working_dir": working_dir,
        "health_check": config.health_check.as_ref().map(|h| serde_json::json!({
            "path": h.path.as_deref().unwrap_or("/"),
            "interval_secs": parse_duration_secs(h.interval.as_deref().unwrap_or("10s")),
            "timeout_secs": parse_duration_secs(h.timeout.as_deref().unwrap_or("5s")),
        })),
        "volumes": volumes,
    });

    println!(
        "  Server '{name}': image exported ({} bytes)",
        std::fs::metadata(&tarball_path)
            .map(|m| m.len())
            .unwrap_or(0)
    );

    Ok(ServerArtifact {
        name: name.to_string(),
        rootfs_tarball: tarball_path,
        manifest_json: serde_json::to_string_pretty(&manifest)?,
    })
}

fn parse_duration_secs(s: &str) -> u64 {
    let s = s.trim();
    if let Some(num) = s.strip_suffix('s') {
        num.parse().unwrap_or(10)
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().unwrap_or(1) * 60
    } else {
        s.parse().unwrap_or(10)
    }
}

fn build_function(name: &str, source: &Path) -> Result<std::path::PathBuf> {
    if source.extension().is_some_and(|e| e == "wasm") {
        if !source.exists() {
            anyhow::bail!("WASM file not found: {}", source.display());
        }
        println!("  Function '{name}': using pre-built {}", source.display());
        return Ok(source.to_owned());
    }

    if !source.join("Cargo.toml").exists() {
        anyhow::bail!(
            "function '{}' source at {} is not a Rust crate (no Cargo.toml) or .wasm file",
            name,
            source.display()
        );
    }

    println!("  Function '{name}': compiling {}...", source.display());
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--target",
            "wasm32-wasip1",
            "--release",
            "--manifest-path",
        ])
        .arg(source.join("Cargo.toml"))
        .status()
        .context("failed to run cargo build for function")?;

    if !status.success() {
        anyhow::bail!("failed to compile function '{name}'");
    }

    let target_dir = source.join("target/wasm32-wasip1/release");
    let crate_name = read_crate_name(&source.join("Cargo.toml"))?;
    let wasm_path = target_dir.join(format!("{crate_name}.wasm"));

    if !wasm_path.exists() {
        anyhow::bail!(
            "expected WASM output at {} but not found",
            wasm_path.display()
        );
    }

    Ok(wasm_path)
}

fn read_crate_name(cargo_toml: &Path) -> Result<String> {
    let content = std::fs::read_to_string(cargo_toml)?;
    let parsed: toml::Value = toml::from_str(&content)?;
    parsed["package"]["name"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "could not read package name from {}",
                cargo_toml.display()
            )
        })
}

const EXCLUDED_FILES: &[&str] = &["jkbase.toml", "Dockerfile"];
const EXCLUDED_DIRS: &[&str] = &["node_modules", ".git", "target"];

#[allow(clippy::too_many_arguments)] // threads several optional sidecar artifacts
fn create_tarball(
    project_dir: &Path,
    sites: &[jkbase_common::config::ResolvedSite],
    wasm_files: &[(String, std::path::PathBuf)],
    server_artifacts: &[ServerArtifact],
    route_config_json: Option<&str>,
    sites_json: Option<&str>,
    domains_json: Option<&str>,
    schedules_json: Option<&str>,
) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let enc = GzEncoder::new(buf, Compression::fast());
    let mut tar = tar::Builder::new(enc);

    let multi_site = sites.len() > 1 || sites.first().is_some_and(|s| s.name != "default");

    if multi_site {
        for site in sites {
            let site_dir = project_dir.join(&site.public);
            let tar_prefix = format!("_site_{}", site.name);
            if site_dir.is_dir() {
                println!("  Site '{}': {} -> /{}", site.name, site.public, site.prefix);
                append_dir_prefixed(&mut tar, &site_dir, &site_dir, &tar_prefix)?;
            }
        }
    } else if let Some(site) = sites.first() {
        let site_dir = project_dir.join(&site.public);
        if site_dir.is_dir() {
            append_dir_filtered(&mut tar, &site_dir, &site_dir)?;
        }
    }

    if !wasm_files.is_empty() {
        for (name, wasm_path) in wasm_files {
            let tar_path = Path::new("_functions").join(format!("{name}.wasm"));
            tar.append_path_with_name(wasm_path, &tar_path)?;
        }
    }

    for artifact in server_artifacts {
        let tar_path = Path::new("_servers").join(format!("{}.tar.gz", artifact.name));
        tar.append_path_with_name(&artifact.rootfs_tarball, &tar_path)?;

        let manifest_path = Path::new("_servers").join(format!("{}.json", artifact.name));
        let manifest_bytes = artifact.manifest_json.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, &manifest_path, manifest_bytes)?;
    }

    if let Some(routes_json) = route_config_json {
        append_json_file(&mut tar, "_routes.json", routes_json)?;
    }

    if let Some(sites_json) = sites_json {
        append_json_file(&mut tar, "_sites.json", sites_json)?;
    }

    if let Some(domains_json) = domains_json {
        append_json_file(&mut tar, "_domains.json", domains_json)?;
    }

    if let Some(schedules_json) = schedules_json {
        append_json_file(&mut tar, "_schedules.json", schedules_json)?;
    }

    let enc = tar.into_inner()?;
    let compressed = enc.finish()?;
    Ok(compressed)
}

fn append_json_file(
    tar: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    name: &str,
    content: &str,
) -> Result<()> {
    let bytes = content.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, name, bytes)?;
    Ok(())
}

fn append_dir_filtered(
    tar: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    root: &Path,
    dir: &Path,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root)?;
        let name = rel
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if EXCLUDED_FILES.contains(&name) {
            continue;
        }

        if path.is_dir() {
            if EXCLUDED_DIRS.contains(&name) {
                continue;
            }
            tar.append_dir(rel, &path)?;
            append_dir_filtered(tar, root, &path)?;
        } else {
            tar.append_path_with_name(&path, rel)?;
        }
    }
    Ok(())
}

fn append_dir_prefixed(
    tar: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    root: &Path,
    dir: &Path,
    prefix: &str,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root)?;
        let name = rel
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if EXCLUDED_FILES.contains(&name) {
            continue;
        }

        let tar_path = Path::new(prefix).join(rel);

        if path.is_dir() {
            if EXCLUDED_DIRS.contains(&name) {
                continue;
            }
            tar.append_dir(&tar_path, &path)?;
            append_dir_prefixed(tar, root, &path, prefix)?;
        } else {
            tar.append_path_with_name(&path, &tar_path)?;
        }
    }
    Ok(())
}

fn slug(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}
