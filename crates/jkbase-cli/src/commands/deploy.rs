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
    #[arg(long, default_value = "http://127.0.0.1:9090")]
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

    let public_dir = config
        .hosting
        .as_ref()
        .and_then(|h| h.public.as_deref())
        .unwrap_or(".");

    let serve_dir = project_dir.join(public_dir);

    // Build WASM functions
    let mut wasm_files: Vec<(String, std::path::PathBuf)> = Vec::new();
    for (name, func_config) in &config.functions {
        let source = project_dir.join(&func_config.source);
        let wasm_path = build_function(name, &source)?;
        wasm_files.push((name.clone(), wasm_path));
    }

    println!("Packaging...");
    let tarball = create_tarball(&serve_dir, &wasm_files).context("failed to create tarball")?;
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
        .ok_or_else(|| anyhow::anyhow!("could not read package name from {}", cargo_toml.display()))
}

const EXCLUDED_FILES: &[&str] = &["jkbase.toml"];

fn create_tarball(
    dir: &Path,
    wasm_files: &[(String, std::path::PathBuf)],
) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let enc = GzEncoder::new(buf, Compression::fast());
    let mut tar = tar::Builder::new(enc);

    if dir.is_dir() {
        append_dir_filtered(&mut tar, dir, dir)?;
    }

    if !wasm_files.is_empty() {
        for (name, wasm_path) in wasm_files {
            let tar_path = Path::new("_functions").join(format!("{name}.wasm"));
            tar.append_path_with_name(wasm_path, &tar_path)?;
        }
    }

    let enc = tar.into_inner()?;
    let compressed = enc.finish()?;
    Ok(compressed)
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
        let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if EXCLUDED_FILES.contains(&name) {
            continue;
        }

        if path.is_dir() {
            tar.append_dir(rel, &path)?;
            append_dir_filtered(tar, root, &path)?;
        } else {
            tar.append_path_with_name(&path, rel)?;
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
