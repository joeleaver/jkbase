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
    if !serve_dir.is_dir() {
        anyhow::bail!(
            "public directory '{}' does not exist",
            serve_dir.display()
        );
    }

    println!("Packaging {}...", serve_dir.display());
    let tarball = create_tarball(&serve_dir).context("failed to create tarball")?;
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

const EXCLUDED_FILES: &[&str] = &["jkbase.toml"];

fn create_tarball(dir: &Path) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let enc = GzEncoder::new(buf, Compression::fast());
    let mut tar = tar::Builder::new(enc);
    append_dir_filtered(&mut tar, dir, dir)?;
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
