use clap::Args;
use jkbase_common::config::ProjectConfig;

#[derive(Args)]
pub struct DeployArgs {
    /// Target project (inferred from jkbase.toml if not specified)
    #[arg(long)]
    project: Option<String>,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

pub async fn run(args: DeployArgs) -> anyhow::Result<()> {
    let (config, config_path) = ProjectConfig::find_and_load()?;

    let project_name = args
        .project
        .or_else(|| config.project.as_ref()?.name.clone())
        .ok_or_else(|| {
            anyhow::anyhow!("no project specified — use --project or set project.name in jkbase.toml")
        })?;

    println!(
        "Deploying project '{project_name}' (config: {})",
        config_path.display()
    );

    if config.hosting.is_some() {
        println!("  Static hosting: detected");
    }
    for (name, _) in &config.functions {
        println!("  Function: {name}");
    }
    for (name, server) in &config.servers {
        println!("  Server: {name} (port {})", server.port);
    }

    println!("Deploy not yet implemented");
    Ok(())
}
