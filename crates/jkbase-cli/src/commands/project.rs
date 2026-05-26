use clap::Subcommand;

#[derive(Subcommand)]
pub enum ProjectCommand {
    /// Create a new project
    Create {
        /// Project name
        name: String,
    },
    /// List all projects
    List,
    /// Delete a project
    Delete {
        /// Project name
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Show project info
    Info {
        /// Project name (inferred from jkbase.toml if not specified)
        name: Option<String>,
    },
}

pub async fn run(command: ProjectCommand) -> anyhow::Result<()> {
    match command {
        ProjectCommand::Create { name } => {
            println!("Creating project '{name}'...");
        }
        ProjectCommand::List => {
            println!("Listing projects...");
        }
        ProjectCommand::Delete { name, force: _ } => {
            println!("Deleting project '{name}'...");
        }
        ProjectCommand::Info { name } => {
            let name = name.unwrap_or_else(|| "(current)".to_string());
            println!("Project info for '{name}'...");
        }
    }
    Ok(())
}
