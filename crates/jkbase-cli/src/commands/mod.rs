mod deploy;
mod project;

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
    /// Initialize the platform (admin)
    Init,
    /// Authenticate with the platform
    Login,
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
        Command::Init => {
            println!("Initializing jkbase platform...");
            Ok(())
        }
        Command::Login => {
            println!("Authenticating...");
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
