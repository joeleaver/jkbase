use anyhow::{Context, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Subcommand)]
pub enum ProjectCommand {
    /// Create a new project
    Create {
        /// Project name
        name: String,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// List all projects
    List {
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Delete a project
    Delete {
        /// Project name
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Show project info
    Info {
        /// Project name (inferred from jkbase.toml if not specified)
        name: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
}

#[derive(Serialize)]
struct CreateRequest {
    name: String,
}

#[derive(Deserialize)]
struct ProjectResponse {
    id: String,
    name: String,
    current_version: Option<u64>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run(command: ProjectCommand) -> Result<()> {
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated — run `jkbase init` or `jkbase login` first"))?;
    let client = crate::credentials::authenticated_client(&token);

    match command {
        ProjectCommand::Create { name, api } => {
            let resp = client
                .post(format!("{api}/projects"))
                .json(&CreateRequest { name: name.clone() })
                .send()
                .await
                .context("failed to connect to platform API")?;

            if resp.status().is_success() {
                let project: ProjectResponse = resp.json().await?;
                println!("Created project '{}' (id: {})", project.name, project.id);
            } else {
                let err: ErrorResponse = resp.json().await?;
                anyhow::bail!("failed to create project: {}", err.error);
            }
        }
        ProjectCommand::List { api } => {
            let resp = client
                .get(format!("{api}/projects"))
                .send()
                .await
                .context("failed to connect to platform API")?;

            let projects: Vec<ProjectResponse> = resp.json().await?;
            if projects.is_empty() {
                println!("No projects");
            } else {
                for p in &projects {
                    let version = p
                        .current_version
                        .map(|v| format!("v{v}"))
                        .unwrap_or_else(|| "not deployed".to_string());
                    println!("  {} ({}) — {}", p.name, p.id, version);
                }
            }
        }
        ProjectCommand::Delete { name, force: _, api } => {
            let id = slug(&name);
            let resp = client
                .delete(format!("{api}/projects/{id}"))
                .send()
                .await
                .context("failed to connect to platform API")?;

            if resp.status().is_success() {
                println!("Deleted project '{name}'");
            } else {
                let err: ErrorResponse = resp.json().await?;
                anyhow::bail!("failed to delete project: {}", err.error);
            }
        }
        ProjectCommand::Info { name, api } => {
            let id = name.unwrap_or_else(|| "unknown".to_string());
            let id = slug(&id);
            let resp = client
                .get(format!("{api}/projects/{id}"))
                .send()
                .await
                .context("failed to connect to platform API")?;

            if resp.status().is_success() {
                let project: ProjectResponse = resp.json().await?;
                println!("Name:    {}", project.name);
                println!("ID:      {}", project.id);
                println!(
                    "Version: {}",
                    project
                        .current_version
                        .map(|v| format!("v{v}"))
                        .unwrap_or_else(|| "not deployed".to_string())
                );
            } else {
                let err: ErrorResponse = resp.json().await?;
                anyhow::bail!("{}", err.error);
            }
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
