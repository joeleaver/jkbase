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

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cli = Cli::parse();
    let checks = !matches!(cli.command, commands::Command::Upgrade(_));
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async move {
        let result = commands::run(cli.command).await;
        if checks {
            update_check::maybe_notify(&update_check::api_from_args(&args)).await;
        }
        result
    });
    // Don't wait on blocking-pool threads: a timed-out update check can leave a getaddrinfo
    // stuck on an unreachable resolver, which would otherwise hold the exit for many seconds.
    rt.shutdown_background();
    result
}
