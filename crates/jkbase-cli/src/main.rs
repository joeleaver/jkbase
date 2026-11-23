mod commands;
pub mod credentials;
mod update_check;

use clap::Parser;

#[derive(Parser)]
#[command(name = "jkbase", about = "jkbase platform CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cli = Cli::parse();
    let checks = !matches!(cli.command, commands::Command::Upgrade(_));
    let result = commands::run(cli.command).await;
    if checks {
        update_check::maybe_notify(&update_check::api_from_args(&args)).await;
    }
    result
}
