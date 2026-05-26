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
        /// Specific version to roll back to
        #[arg(long)]
        version: Option<u64>,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Initialize the platform and create the first admin account
    Init {
        /// Your email address
        email: String,
        /// Platform API URL
        #[arg(long, default_value = "http://127.0.0.1:9090")]
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
        #[arg(long)]
        follow: bool,
        /// Filter by service name
        #[arg(long)]
        service: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
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
    },
    /// List secrets
    List,
    /// Remove a secret
    Rm {
        /// Secret key to remove
        key: String,
    },
}

#[derive(Subcommand)]
pub enum DomainCommand {
    /// Add a custom domain
    Add { domain: String },
    /// Verify domain ownership
    Verify { domain: String },
    /// List custom domains
    List,
    /// Remove a custom domain
    Rm { domain: String },
}

pub async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Deploy(args) => deploy::run(args).await,
        Command::Project(cmd) => project::run(cmd).await,
        Command::Rollback { version, force: _ } => {
            match version {
                Some(v) => println!("Rolling back to version {v}..."),
                None => println!("Rolling back to previous version..."),
            }
            Ok(())
        }
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
            json: _,
        } => {
            match (&service, follow) {
                (Some(s), true) => println!("Tailing logs for {s}..."),
                (Some(s), false) => println!("Fetching logs for {s}..."),
                (None, true) => println!("Tailing logs..."),
                (None, false) => println!("Fetching logs..."),
            }
            Ok(())
        }
        Command::Secret(cmd) => match cmd {
            SecretCommand::Set { pair } => {
                println!("Setting secret {pair}...");
                Ok(())
            }
            SecretCommand::List => {
                println!("Listing secrets...");
                Ok(())
            }
            SecretCommand::Rm { key } => {
                println!("Removing secret {key}...");
                Ok(())
            }
        },
        Command::Domain(cmd) => match cmd {
            DomainCommand::Add { domain } => {
                println!("Adding domain {domain}...");
                Ok(())
            }
            DomainCommand::Verify { domain } => {
                println!("Verifying domain {domain}...");
                Ok(())
            }
            DomainCommand::List => {
                println!("Listing domains...");
                Ok(())
            }
            DomainCommand::Rm { domain } => {
                println!("Removing domain {domain}...");
                Ok(())
            }
        },
        Command::Dev => {
            println!("Starting local development environment...");
            Ok(())
        }
    }
}
