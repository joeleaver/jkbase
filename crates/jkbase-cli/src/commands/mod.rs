mod deploy;
mod project;

use anyhow::Context;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Deploy the current project
    Deploy(deploy::DeployArgs),
    /// Manage projects
    #[command(subcommand)]
    Project(project::ProjectCommand),
    /// Roll back to a previous deployment
    Rollback {
        /// Specific version to roll back to (defaults to the previous version)
        #[arg(long)]
        version: Option<u64>,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// List deployment history
    Deployments {
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Show month-to-date metered usage (CPU, bandwidth, storage)
    Usage {
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Show or set per-project resource quotas. Set values can only restrict
    /// (never raise above platform defaults).
    Quota {
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Set the storage cap, in GiB (clamped to the platform default)
        #[arg(long)]
        set_storage_gib: Option<f64>,
        /// Set the monthly bandwidth cap, in GiB (clamped to the platform default)
        #[arg(long)]
        set_bandwidth_gib: Option<f64>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Initialize the platform and create the first admin account
    Init {
        /// Your email address
        email: String,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Authenticate with the platform
    Login {
        /// API token (if not provided, reads from stdin)
        #[arg(long)]
        token: Option<String>,
    },
    /// View logs
    Logs {
        /// Follow log output
        #[arg(long, short)]
        follow: bool,
        /// Filter by service (container) name
        #[arg(long)]
        service: Option<String>,
        /// Number of recent lines to show
        #[arg(long, short = 'n', default_value = "200")]
        limit: usize,
        /// Output raw JSON lines
        #[arg(long)]
        json: bool,
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Manage secrets
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Manage custom domains
    #[command(subcommand)]
    Domain(DomainCommand),
    /// Start local development environment
    Dev,
}

#[derive(Subcommand)]
pub enum SecretCommand {
    /// Set a secret
    Set {
        /// KEY=value pair
        pair: String,
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// List secrets
    List {
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Remove a secret
    Rm {
        /// Secret key to remove
        key: String,
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
}

#[derive(Subcommand)]
pub enum DomainCommand {
    /// Attach a subdomain (`docs`) or custom domain (`docs.example.com`)
    Add {
        domain: String,
        /// Bind this domain to a specific site within the project
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Verify ownership of a custom domain (after adding its DNS TXT record)
    Verify {
        domain: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// List attached domains and their status
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Remove an attached domain
    Rm {
        domain: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
}

fn resolve_project_id(project: Option<String>) -> anyhow::Result<String> {
    if let Some(name) = project {
        return Ok(slug(&name));
    }
    let (config, _) = jkbase_common::config::ProjectConfig::find_and_load()?;
    let name = config
        .project
        .and_then(|p| p.name)
        .ok_or_else(|| anyhow::anyhow!("no project specified"))?;
    Ok(slug(&name))
}

fn slug(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

pub async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Deploy(args) => deploy::run(args).await,
        Command::Project(cmd) => project::run(cmd).await,
        Command::Rollback {
            version,
            force,
            project,
            api,
        } => run_rollback(version, force, project, api).await,
        Command::Deployments { project, api } => run_deployments(project, api).await,
        Command::Usage { project, api } => run_usage(project, api).await,
        Command::Quota {
            project,
            set_storage_gib,
            set_bandwidth_gib,
            api,
        } => run_quota(project, set_storage_gib, set_bandwidth_gib, api).await,
        Command::Init { email, api } => {
            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{api}/init"))
                .json(&serde_json::json!({ "email": email }))
                .send()
                .await
                .context("failed to connect to platform API")?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                let token = body["token"].as_str().unwrap_or("");
                let tenant_id = body["tenant_id"].as_str().unwrap_or("");

                crate::credentials::save_token(token)?;
                println!("Platform initialized!");
                println!("  Tenant ID: {tenant_id}");
                println!("  Token saved to ~/.jkbase/credentials");
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("init failed: {err}");
            }
            Ok(())
        }
        Command::Login { token } => {
            let token = match token {
                Some(t) => t,
                None => {
                    println!("Enter your API token:");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            if token.is_empty() {
                anyhow::bail!("no token provided");
            }

            crate::credentials::save_token(&token)?;
            println!("Token saved to ~/.jkbase/credentials");
            Ok(())
        }
        Command::Logs {
            follow,
            service,
            limit,
            json,
            project,
            api,
        } => run_logs(follow, service, limit, json, project, api).await,
        Command::Secret(cmd) => run_secret(cmd).await,
        Command::Domain(cmd) => run_domain(cmd).await,
        Command::Dev => {
            println!("Starting local development environment...");
            Ok(())
        }
    }
}

async fn run_logs(
    follow: bool,
    service: Option<String>,
    limit: usize,
    json: bool,
    project: Option<String>,
    api: String,
) -> anyhow::Result<()> {
    use jkbase_common::logs::LogLine;

    let project_id = resolve_project_id(project)?;
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);
    let url = format!("{api}/projects/{project_id}/logs");

    // Fetch one page of logs. `since` returns only lines newer than that store seq.
    let fetch = |since: Option<u64>| {
        let client = client.clone();
        let url = url.clone();
        let service = service.clone();
        async move {
            let mut req = client.get(&url);
            match since {
                Some(s) => req = req.query(&[("since", s.to_string())]),
                None => req = req.query(&[("limit", limit.to_string())]),
            }
            if let Some(ref svc) = service {
                req = req.query(&[("service", svc)]);
            }
            let resp = req.send().await.context("failed to connect to API")?;
            if !resp.status().is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("failed to fetch logs: {err}");
            }
            let lines: Vec<LogLine> = resp.json().await.context("invalid logs response")?;
            Ok::<Vec<LogLine>, anyhow::Error>(lines)
        }
    };

    let lines = fetch(None).await?;
    if lines.is_empty() && !follow {
        eprintln!("No logs for project '{project_id}'");
        return Ok(());
    }
    let mut cursor = lines.last().map(|l| l.seq).unwrap_or(0);
    for line in &lines {
        print_line(line, json);
    }

    if !follow {
        return Ok(());
    }

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let new_lines = fetch(Some(cursor)).await?;
        for line in &new_lines {
            print_line(line, json);
            cursor = cursor.max(line.seq);
        }
    }
}

fn print_line(line: &jkbase_common::logs::LogLine, json: bool) {
    if json {
        if let Ok(s) = serde_json::to_string(line) {
            println!("{s}");
        }
        return;
    }
    // stdout lines to stdout, stderr lines to stderr (so redirection works).
    let formatted = format!("{} [{}] {}", line.timestamp, line.server, line.line);
    if line.stream == "stderr" {
        eprintln!("{formatted}");
    } else {
        println!("{formatted}");
    }
}

#[derive(serde::Deserialize)]
struct Deployment {
    version: u64,
    created_at: u64,
    active: bool,
}

async fn fetch_deployments(
    client: &reqwest::Client,
    api: &str,
    project_id: &str,
) -> anyhow::Result<Vec<Deployment>> {
    let resp = client
        .get(format!("{api}/projects/{project_id}/deployments"))
        .send()
        .await
        .context("failed to connect to API")?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let err = body["error"].as_str().unwrap_or("unknown error");
        anyhow::bail!("failed to list deployments: {err}");
    }
    resp.json().await.context("invalid deployments response")
}

async fn run_deployments(project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);

    let deployments = fetch_deployments(&client, &api, &project_id).await?;
    if deployments.is_empty() {
        println!("No deployments for project '{project_id}'");
        return Ok(());
    }
    for d in &deployments {
        println!(
            "  v{:<5} {:<14} {}",
            d.version,
            human_age(d.created_at),
            if d.active { "(active)" } else { "" }
        );
    }
    Ok(())
}

fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.2} {}", U[i])
    }
}

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

async fn run_usage(project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);

    let resp = client
        .get(format!("{api}/projects/{project_id}/usage"))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("failed to fetch usage ({})", resp.status());
    }
    let v: serde_json::Value = resp.json().await?;
    let cpu = v["cpu_seconds"].as_f64().unwrap_or(0.0);
    let rx = v["rx_bytes"].as_u64().unwrap_or(0);
    let tx = v["tx_bytes"].as_u64().unwrap_or(0);
    let storage = v["storage_bytes"].as_u64().unwrap_or(0);

    println!("Usage for '{project_id}' (month-to-date):");
    println!("  CPU:       {cpu:.1} cpu-seconds");
    println!(
        "  Bandwidth: {} (rx {} + tx {})",
        fmt_bytes(rx + tx),
        fmt_bytes(rx),
        fmt_bytes(tx)
    );
    println!("  Storage:   {}", fmt_bytes(storage));
    Ok(())
}

async fn run_quota(
    project: Option<String>,
    set_storage_gib: Option<f64>,
    set_bandwidth_gib: Option<f64>,
    api: String,
) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);
    let url = format!("{api}/projects/{project_id}/quota");

    if set_storage_gib.is_some() || set_bandwidth_gib.is_some() {
        // Fill any unset field from the current values so a partial set is fine.
        let cur: serde_json::Value = client.get(&url).send().await?.json().await?;
        let storage = match set_storage_gib {
            Some(g) => (g * GIB) as u64,
            None => cur["storage_bytes_max"].as_u64().unwrap_or(0),
        };
        let bw = match set_bandwidth_gib {
            Some(g) => (g * GIB) as u64,
            None => cur["bandwidth_bytes_per_month"].as_u64().unwrap_or(0),
        };
        let resp = client
            .post(&url)
            .json(&serde_json::json!({
                "storage_bytes_max": storage,
                "bandwidth_bytes_per_month": bw,
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("failed to set quota ({})", resp.status());
        }
        println!("Quota updated (values are clamped to platform defaults).");
    }

    let v: serde_json::Value = client.get(&url).send().await?.json().await?;
    println!("Quota for '{project_id}':");
    println!(
        "  Storage cap:   {}",
        fmt_bytes(v["storage_bytes_max"].as_u64().unwrap_or(0))
    );
    println!(
        "  Bandwidth cap: {} / month",
        fmt_bytes(v["bandwidth_bytes_per_month"].as_u64().unwrap_or(0))
    );
    println!(
        "  Source:        {}",
        if v["overridden"].as_bool().unwrap_or(false) {
            "per-project override"
        } else {
            "platform default"
        }
    );
    if v["bandwidth_blocked"].as_bool().unwrap_or(false) {
        let reason = v["blocked_reason"].as_str().unwrap_or("over quota");
        println!("  STATUS:        BLOCKED — {reason}");
    }
    Ok(())
}

async fn run_rollback(
    version: Option<u64>,
    force: bool,
    project: Option<String>,
    api: String,
) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);

    // Resolve the target version: explicit, or the one just before the active deploy.
    let target = match version {
        Some(v) => v,
        None => {
            let deployments = fetch_deployments(&client, &api, &project_id).await?;
            let active_idx = deployments.iter().position(|d| d.active);
            match active_idx {
                Some(i) => deployments
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("no previous deployment to roll back to"))?
                    .version,
                None => deployments
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("no deployments to roll back to"))?
                    .version,
            }
        }
    };

    if !force {
        print!("Roll back '{project_id}' to v{target}? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("Rolling back '{project_id}' to v{target}...");
    let resp = client
        .post(format!("{api}/projects/{project_id}/rollback"))
        .json(&serde_json::json!({ "version": target }))
        .send()
        .await
        .context("failed to connect to API")?;

    if resp.status().is_success() {
        println!("Rolled back '{project_id}' to v{target}");
        Ok(())
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let err = body["error"].as_str().unwrap_or("unknown error");
        anyhow::bail!("rollback failed: {err}");
    }
}

/// Render a unix-seconds timestamp as a coarse relative age, dependency-free.
fn human_age(ts: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if ts == 0 || ts > now {
        return "just now".to_string();
    }
    let secs = now - ts;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

async fn run_domain(cmd: DomainCommand) -> anyhow::Result<()> {
    match cmd {
        DomainCommand::Add {
            domain,
            site,
            project,
            api,
        } => {
            let project_id = resolve_project_id(project)?;
            let client = auth_client()?;
            let resp = client
                .post(format!("{api}/projects/{project_id}/domains"))
                .json(&serde_json::json!({ "domain": domain, "site": site }))
                .send()
                .await
                .context("failed to connect to API")?;
            let body: serde_json::Value = api_json(resp).await?;
            let host = body["host"].as_str().unwrap_or(&domain);
            let status = body["status"].as_str().unwrap_or("");
            if let Some(v) = body.get("verification").filter(|v| !v.is_null()) {
                println!("Domain '{host}' added (pending verification).");
                println!("Add this DNS record, then run `jkbase domain verify {host}`:");
                println!(
                    "  {}  TXT  {}",
                    v["record"].as_str().unwrap_or(""),
                    v["value"].as_str().unwrap_or("")
                );
            } else {
                println!("Domain '{host}' added ({status}).");
            }
            Ok(())
        }
        DomainCommand::Verify {
            domain,
            project,
            api,
        } => {
            let project_id = resolve_project_id(project)?;
            let client = auth_client()?;
            let resp = client
                .post(format!("{api}/projects/{project_id}/domains/{domain}/verify"))
                .send()
                .await
                .context("failed to connect to API")?;
            let body: serde_json::Value = api_json(resp).await?;
            println!(
                "Domain '{}' is now {}.",
                body["host"].as_str().unwrap_or(&domain),
                body["status"].as_str().unwrap_or("active")
            );
            Ok(())
        }
        DomainCommand::List { project, api } => {
            let project_id = resolve_project_id(project)?;
            let client = auth_client()?;
            let resp = client
                .get(format!("{api}/projects/{project_id}/domains"))
                .send()
                .await
                .context("failed to connect to API")?;
            let domains: Vec<serde_json::Value> = api_json(resp).await?;
            if domains.is_empty() {
                println!("No domains attached to project '{project_id}'");
                return Ok(());
            }
            for d in &domains {
                let site = d["site"].as_str().map(|s| format!(" -> site {s}")).unwrap_or_default();
                println!(
                    "  {:<28} {:<8} {}{}",
                    d["host"].as_str().unwrap_or(""),
                    d["status"].as_str().unwrap_or(""),
                    d["kind"].as_str().unwrap_or(""),
                    site
                );
            }
            Ok(())
        }
        DomainCommand::Rm {
            domain,
            project,
            api,
        } => {
            let project_id = resolve_project_id(project)?;
            let client = auth_client()?;
            let resp = client
                .delete(format!("{api}/projects/{project_id}/domains/{domain}"))
                .send()
                .await
                .context("failed to connect to API")?;
            if resp.status().is_success() {
                println!("Removed domain '{domain}' from '{project_id}'");
                Ok(())
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                anyhow::bail!(
                    "failed to remove domain: {}",
                    body["error"].as_str().unwrap_or("unknown error")
                );
            }
        }
    }
}

fn auth_client() -> anyhow::Result<reqwest::Client> {
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    Ok(crate::credentials::authenticated_client(&token))
}

/// Parse a JSON response, turning a non-2xx into an error carrying the API's message.
async fn api_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> anyhow::Result<T> {
    if resp.status().is_success() {
        Ok(resp.json().await.context("invalid API response")?)
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        anyhow::bail!("{}", body["error"].as_str().unwrap_or("request failed"));
    }
}

async fn run_secret(cmd: SecretCommand) -> anyhow::Result<()> {
    match cmd {
        SecretCommand::Set { pair, project, api } => {
            let project_id = resolve_project_id(project)?;
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("expected KEY=value format"))?;

            let token = crate::credentials::load_token()?
                .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
            let client = crate::credentials::authenticated_client(&token);

            let resp = client
                .post(format!("{api}/projects/{project_id}/secrets"))
                .json(&serde_json::json!({ "key": key, "value": value }))
                .send()
                .await
                .context("failed to connect to API")?;

            if resp.status().is_success() {
                println!("Secret '{key}' set for project '{project_id}'");
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("failed to set secret: {err}");
            }
            Ok(())
        }
        SecretCommand::List { project, api } => {
            let project_id = resolve_project_id(project)?;

            let token = crate::credentials::load_token()?
                .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
            let client = crate::credentials::authenticated_client(&token);

            let resp = client
                .get(format!("{api}/projects/{project_id}/secrets"))
                .send()
                .await
                .context("failed to connect to API")?;

            if resp.status().is_success() {
                let secrets: Vec<serde_json::Value> = resp.json().await?;
                if secrets.is_empty() {
                    println!("No secrets set for project '{project_id}'");
                } else {
                    for secret in &secrets {
                        if let Some(key) = secret["key"].as_str() {
                            println!("  {key}");
                        }
                    }
                }
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("failed to list secrets: {err}");
            }
            Ok(())
        }
        SecretCommand::Rm { key, project, api } => {
            let project_id = resolve_project_id(project)?;

            let token = crate::credentials::load_token()?
                .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
            let client = crate::credentials::authenticated_client(&token);

            let resp = client
                .delete(format!("{api}/projects/{project_id}/secrets/{key}"))
                .send()
                .await
                .context("failed to connect to API")?;

            if resp.status().is_success() {
                println!("Secret '{key}' removed from project '{project_id}'");
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("failed to remove secret: {err}");
            }
            Ok(())
        }
    }
}
