//! `jkbase deploy` — server-side build + deploy.
//!
//! The platform builds, not the laptop: this tars the project **source** (no
//! `docker`/`cargo` locally), POSTs it to the build funnel, and streams the
//! resulting build job until the deployment goes live. One build VM is fanned
//! out per server/function server-side (design §12).

use anyhow::{Context, Result};
use clap::Args;
use flate2::write::GzEncoder;
use flate2::Compression;
use jkbase_common::config::ProjectConfig;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

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
struct BuildStarted {
    build_id: u64,
}

#[derive(Deserialize)]
struct BuildStatus {
    phase: String,
    #[serde(default)]
    targets: Vec<TargetStatus>,
    #[serde(default)]
    log_tail: String,
    #[serde(default)]
    deployed_version: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct TargetStatus {
    name: String,
    kind: String,
    phase: String,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Directories never shipped as source — build outputs and VCS metadata.
const EXCLUDED_DIRS: &[&str] = &["node_modules", ".git", "target"];

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
    let project_id = slug(&project_name);

    println!("Packaging source...");
    let tarball = tar_source(project_dir).context("failed to package source")?;
    println!("  {} bytes compressed", tarball.len());

    let token = crate::credentials::load_token()?.ok_or_else(|| {
        anyhow::anyhow!("not authenticated — run `jkbase init` or `jkbase login` first")
    })?;
    let client = crate::credentials::authenticated_client(&token);

    // Kick off the server-side build.
    let url = format!("{}/projects/{}/build", args.api, project_id);
    println!("Building '{project_name}' on the platform...");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/gzip")
        .body(tarball)
        .send()
        .await
        .context("failed to connect to platform API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
            error: "unknown error".to_string(),
        });
        anyhow::bail!("build request failed ({status}): {}", err.error);
    }
    let started: BuildStarted = resp.json().await.context("parse build response")?;

    // Stream the build job to completion.
    let status_url = format!(
        "{}/projects/{}/builds/{}",
        args.api, project_id, started.build_id
    );
    // Overall budget: the server caps a build at 600s; allow margin, then bail
    // rather than poll forever (e.g. if the server restarted mid-build).
    let deadline = std::time::Instant::now() + Duration::from_secs(720);
    let mut last_fingerprint = String::new();
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!(
                "build did not finish within 12 minutes; the server may have restarted — \
                 re-run `jkbase deploy` or check the build status later"
            );
        }
        let resp = client
            .get(&status_url)
            .send()
            .await
            .context("failed to poll build status")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "unknown error".to_string(),
            });
            anyhow::bail!("build status check failed ({status}): {}", err.error);
        }
        let status: BuildStatus = resp.json().await.context("parse build status")?;

        // Print per-target transitions as they change.
        let fingerprint = status
            .targets
            .iter()
            .map(|t| format!("{}:{}:{}", t.kind, t.name, t.phase))
            .collect::<Vec<_>>()
            .join(",");
        if fingerprint != last_fingerprint {
            for t in &status.targets {
                println!("  [{}] {} — {}", t.kind, t.name, t.phase);
            }
            last_fingerprint = fingerprint;
        }

        match status.phase.as_str() {
            "succeeded" => {
                let version = status.deployed_version.unwrap_or(0);
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({ "project_id": project_id, "version": version })
                    );
                } else {
                    println!("Deployed {project_id} v{version} successfully");
                }
                return Ok(());
            }
            "failed" => {
                for t in &status.targets {
                    if t.phase == "failed" {
                        println!(
                            "  [{}] {} FAILED: {}",
                            t.kind,
                            t.name,
                            t.detail.as_deref().unwrap_or("(no detail)")
                        );
                    }
                }
                if !status.log_tail.trim().is_empty() {
                    println!("--- build log ---\n{}", status.log_tail.trim_end());
                }
                anyhow::bail!(
                    "build failed: {}",
                    status.error.as_deref().unwrap_or("unknown error")
                );
            }
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

/// Tar+gzip the project source tree, paths relative to `project_dir`, excluding
/// build/VCS dirs. Keeps `jkbase.toml` + `Dockerfile` + all source — the platform
/// reads the manifest and builds each target from its declared subdir.
fn tar_source(project_dir: &Path) -> Result<Vec<u8>> {
    let enc = GzEncoder::new(Vec::new(), Compression::fast());
    let mut tar = tar::Builder::new(enc);
    append_source(&mut tar, project_dir, project_dir)?;
    let enc = tar.into_inner()?;
    Ok(enc.finish()?)
}

fn append_source(
    tar: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    root: &Path,
    dir: &Path,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            // Preserve symlinks AS symlinks. Skipping them silently dropped any
            // symlink in the source (so it never reached the build/deploy — symlinks
            // "didn't survive"); the server's untar already recreates them. Store the
            // literal target; the build/runtime resolves it.
            let rel = path.strip_prefix(root)?;
            let target = std::fs::read_link(&path)?;
            let mut header = tar::Header::new_gnu();
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                header.set_mtime(mtime);
            }
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            header.set_size(0);
            tar.append_link(&mut header, rel, &target)?;
        } else if ft.is_dir() {
            if EXCLUDED_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            append_source(tar, root, &path)?;
        } else if ft.is_file() {
            let rel = path.strip_prefix(root)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_source_preserves_symlinks() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let src = std::env::temp_dir().join(format!("jkb-tarsym-src-{nanos}"));
        let out = std::env::temp_dir().join(format!("jkb-tarsym-out-{nanos}"));
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("real.txt"), b"hello").unwrap();
        // A same-dir symlink and a relative (../) symlink — both must survive.
        std::os::unix::fs::symlink("real.txt", src.join("link.txt")).unwrap();
        std::os::unix::fs::symlink("../real.txt", src.join("sub").join("up.txt")).unwrap();

        let tarball = tar_source(&src).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let dec = flate2::read::GzDecoder::new(&tarball[..]);
        tar::Archive::new(dec).unpack(&out).unwrap();

        assert!(
            std::fs::symlink_metadata(out.join("link.txt"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "link.txt should round-trip as a symlink, not be dropped"
        );
        assert_eq!(
            std::fs::read_link(out.join("link.txt")).unwrap(),
            Path::new("real.txt")
        );
        assert_eq!(
            std::fs::read_link(out.join("sub").join("up.txt")).unwrap(),
            Path::new("../real.txt")
        );
        assert_eq!(std::fs::read(out.join("real.txt")).unwrap(), b"hello");

        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&out);
    }
}
