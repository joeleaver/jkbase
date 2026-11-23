//! Post-command staleness notice. The API this invocation talked to advertises (unauthenticated
//! `GET /cli`) the CLI release matching it and the oldest CLI it still serves; we ask at most once
//! a day per API (cached in `~/.jkbase/cli-version.json`), with a short timeout, and never fail
//! or slow a command over it.
//!   * below `minimum` ⇒ a warning on EVERY run (the API may already be broken for this CLI);
//!   * below `latest`  ⇒ a one-line nudge, at most daily, only on an interactive stderr.
//!
//! `JKBASE_NO_UPDATE_CHECK=1` disables it. Advertised strings are printed only after parsing as
//! plain `x.y.z`, so a hostile/self-hosted API can't inject terminal output.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jkbase_common::cli_version::{self, CLI_VERSION, CliVersionInfo};

const DEFAULT_API: &str = "https://api.jkbase.app";
const CHECK_EVERY: u64 = 24 * 3600;
const NOTIFY_EVERY: u64 = 24 * 3600;

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Cache {
    api: String,
    checked_at: u64,
    #[serde(default)]
    info: Option<CliVersionInfo>,
    #[serde(default)]
    notified_at: u64,
}

fn cache_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".jkbase").join("cli-version.json"))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The `--api` this invocation used (every API subcommand takes one, defaulting to ours). Scanned
/// from argv rather than threaded through ~40 subcommands; clap has already validated it.
pub fn api_from_args(args: &[String]) -> String {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            break;
        }
        if a == "--api" {
            if let Some(v) = it.next() {
                return v.clone();
            }
        } else if let Some(v) = a.strip_prefix("--api=") {
            return v.to_string();
        }
    }
    DEFAULT_API.to_string()
}

/// What to print given the advertised info, our version, and the nudge throttle.
fn notice(info: &CliVersionInfo, ours: &str, may_nudge: bool) -> Option<String> {
    let (min, latest) = (cli_version::parse(&info.minimum), cli_version::parse(&info.latest));
    let fmt = |(a, b, c): (u64, u64, u64)| format!("{a}.{b}.{c}");
    if let Some(min) = min
        && cli_version::older(ours, &fmt(min))
    {
        return Some(format!(
            "warning: this jkbase CLI ({ours}) is older than the oldest this platform supports ({}). Run `jkbase upgrade`.",
            fmt(min)
        ));
    }
    if may_nudge
        && let Some(latest) = latest
        && cli_version::older(ours, &fmt(latest))
    {
        return Some(format!(
            "A newer jkbase CLI is available: {ours} → {}. Run `jkbase upgrade`.",
            fmt(latest)
        ));
    }
    None
}

pub async fn maybe_notify(api: &str) {
    if std::env::var_os("JKBASE_NO_UPDATE_CHECK").is_some() {
        return;
    }
    let Some(path) = cache_path() else { return };
    let mut cache: Cache = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let t = now();
    let api = api.trim_end_matches('/');

    if cache.api != api || t.saturating_sub(cache.checked_at) >= CHECK_EVERY {
        cache.info = fetch(api).await.or(if cache.api == api { cache.info } else { None });
        cache.api = api.to_string();
        cache.checked_at = t; // a failed check also waits a day: never hammer a down API
    }

    let interactive = std::io::stderr().is_terminal();
    let may_nudge = interactive && t.saturating_sub(cache.notified_at) >= NOTIFY_EVERY;
    if let Some(info) = &cache.info
        && let Some(msg) = notice(info, CLI_VERSION, may_nudge)
    {
        eprintln!("\n{msg}");
        if may_nudge {
            cache.notified_at = t;
        }
    }

    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(b) = serde_json::to_vec(&cache) {
        let _ = std::fs::write(&path, b);
    }
}

async fn fetch(api: &str) -> Option<CliVersionInfo> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("jkbase-cli/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let resp = client.get(format!("{api}/cli")).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.bytes().await.ok()?;
    if body.len() > 4096 {
        return None;
    }
    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(latest: &str, minimum: &str) -> CliVersionInfo {
        CliVersionInfo { latest: latest.into(), minimum: minimum.into() }
    }

    #[test]
    fn api_flag_forms() {
        let a = |v: &[&str]| api_from_args(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a(&["jkbase", "deploy"]), DEFAULT_API);
        assert_eq!(a(&["jkbase", "logs", "--api", "http://x:9090"]), "http://x:9090");
        assert_eq!(a(&["jkbase", "logs", "--api=http://y"]), "http://y");
        assert_eq!(a(&["jkbase", "x", "--", "--api", "z"]), DEFAULT_API);
    }

    #[test]
    fn below_minimum_always_warns_nudge_is_throttled() {
        assert!(notice(&info("0.3.0", "0.2.5"), "0.2.0", false).unwrap().starts_with("warning"));
        assert!(notice(&info("0.3.0", "0.1.0"), "0.2.0", false).is_none());
        assert!(notice(&info("0.3.0", "0.1.0"), "0.2.0", true).unwrap().contains("0.2.0 → 0.3.0"));
        assert!(notice(&info("0.2.0", "0.1.0"), "0.2.0", true).is_none());
    }

    #[test]
    fn hostile_advertisement_prints_nothing() {
        assert!(notice(&info("9.9.9\x1b[2J", "9.9.9\nrm -rf"), "0.2.0", true).is_none());
    }
}
