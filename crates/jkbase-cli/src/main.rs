mod commands;
pub mod credentials;

use clap::Parser;

#[derive(Parser)]
#[command(name = "jkbase", about = "jkbase platform CLI")]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    commands::run(cli.command).await
}
