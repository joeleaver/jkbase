//! `jkbase upgrade` — replace this binary with a published CLI release.
//!
//! Releases are GitHub Releases tagged `cli-v<semver>` (`.github/workflows/release.yml`), one
//! `jkbase-<target>.tar.gz` per target plus `SHA256SUMS` and its signature `SHA256SUMS.sig`.
//! Trust, same as `install.sh`: `SHA256SUMS.sig` must verify against a release key compiled into
//! this binary (`release_sig`, fail-closed), THEN the archive must hash to its line in those exact
//! signed bytes. So a release someone uploads without the CI signing key is refused, not just a
//! corrupted download. The new binary must also report the expected version from `--version`
//! before it is renamed over the running one, so a wrong-arch or broken build never replaces a
//! working CLI, and an old signed release re-uploaded under a newer tag is refused.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use jkbase_common::cli_version::{self, CLI_VERSION};
use sha2::{Digest, Sha256};

use super::release_sig;

/// This binary's target triple (build.rs), naming its release asset.
pub const TARGET: &str = env!("JKBASE_TARGET");
const DEFAULT_REPO: &str = "joeleaver/jkbase";
const TAG_PREFIX: &str = "cli-v";
/// Caps on what we pull into memory: the CLI is ~10 MiB.
const MAX_ARCHIVE: u64 = 128 << 20;
const MAX_SUMS: u64 = 64 << 10;
const MAX_API: u64 = 4 << 20;

#[derive(Args)]
pub struct UpgradeArgs {
    /// Install this version (e.g. 0.2.0) instead of the latest release
    #[arg(long)]
    version: Option<String>,
    /// Only report whether a newer release exists
    #[arg(long)]
    check: bool,
    /// Reinstall even if already on that version
    #[arg(long)]
    force: bool,
}

/// `owner/name`, from `JKBASE_UPDATE_REPO` (forks, self-hosters) or ours. Its releases must still be
/// signed by a key in this binary's trust root: a fork ships a CLI built with its own
/// `release-keys/allowed_signers`.
fn repo() -> Result<String> {
    let r = std::env::var("JKBASE_UPDATE_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string());
    let ok = |s: &str| {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    };
    match r.split_once('/') {
        Some((o, n)) if ok(o) && ok(n) && !n.contains('/') => Ok(r),
        _ => bail!("JKBASE_UPDATE_REPO must be owner/name (got {r:?})"),
    }
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("jkbase-cli/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(300))
        .build()?)
}

/// GET into memory, refusing bodies over `cap` (declared or actual).
async fn fetch(client: &reqwest::Client, url: &str, cap: u64) -> Result<Vec<u8>> {
    let mut req = client.get(url);
    // Only the API host gets the token (the download redirects to a CDN that must not see it).
    if url.starts_with("https://api.github.com/")
        && let Ok(t) = std::env::var("GITHUB_TOKEN")
        && !t.is_empty()
    {
        req = req.bearer_auth(t);
    }
    let mut resp = req
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if resp.status() == reqwest::StatusCode::FORBIDDEN || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!(
            "GET {url}: HTTP {} — GitHub's anonymous rate limit (60/hour per IP) is probably \
             exhausted; retry later, set GITHUB_TOKEN, or pin a version with --version",
            resp.status()
        );
    }
    ensure!(resp.status().is_success(), "GET {url}: HTTP {}", resp.status());
    ensure!(resp.content_length().unwrap_or(0) <= cap, "GET {url}: response too large");
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        buf.extend_from_slice(&chunk);
        ensure!(buf.len() as u64 <= cap, "GET {url}: response too large");
    }
    Ok(buf)
}

/// Newest non-draft, non-prerelease `cli-v*` release (the repo may also carry other releases).
async fn latest_version(client: &reqwest::Client, repo: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Rel {
        tag_name: String,
        #[serde(default)]
        draft: bool,
        #[serde(default)]
        prerelease: bool,
    }
    let url = format!("https://api.github.com/repos/{repo}/releases?per_page=50");
    let rels: Vec<Rel> = serde_json::from_slice(&fetch(client, &url, MAX_API).await?)
        .context("unexpected GitHub releases response")?;
    rels.iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter_map(|r| r.tag_name.strip_prefix(TAG_PREFIX))
        .filter_map(|v| cli_version::parse(v).map(|p| (p, v)))
        .max_by_key(|(p, _)| *p)
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| anyhow::anyhow!("no {TAG_PREFIX}* release published on {repo}"))
}

/// The hex digest `SHA256SUMS` lists for `asset` (`<hex>  <name>` or `<hex> *<name>`).
fn expected_sha256(sums: &str, asset: &str) -> Result<String> {
    for line in sums.lines() {
        let mut it = line.split_whitespace();
        if let (Some(hex), Some(name), None) = (it.next(), it.next(), it.next())
            && name.trim_start_matches('*') == asset
            && hex.len() == 64
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Ok(hex.to_ascii_lowercase());
        }
    }
    bail!("SHA256SUMS has no entry for {asset}")
}

/// The `jkbase` binary at the archive root. Anything else (paths, links, devices) is ignored, so
/// the archive can't direct a write anywhere: we only ever read one regular file's bytes.
fn extract_binary(archive: &[u8]) -> Result<Vec<u8>> {
    let want = if cfg!(windows) { "jkbase.exe" } else { "jkbase" };
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries()? {
        let entry = entry?;
        if entry.header().entry_type().is_file() && entry.path()?.as_os_str() == want {
            ensure!(entry.size() <= MAX_ARCHIVE, "binary too large");
            let mut out = Vec::with_capacity(entry.size() as usize);
            entry.take(MAX_ARCHIVE).read_to_end(&mut out)?;
            return Ok(out);
        }
    }
    bail!("release archive has no top-level {want}")
}

/// Write `bin` beside `exe`, prove it runs and is `version`, then rename it over `exe`.
fn install(exe: &Path, bin: &[u8], version: &str) -> Result<()> {
    let dir = exe.parent().context("current executable has no parent directory")?;
    let tmp: PathBuf = dir.join(format!(".jkbase-upgrade-{}", std::process::id()));
    let res = (|| -> Result<()> {
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .with_context(|| {
                    format!(
                        "can't write to {} — re-run with permission to replace {}, or reinstall",
                        dir.display(),
                        exe.display()
                    )
                })?;
            f.write_all(bin)?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        let out = std::process::Command::new(&tmp)
            .arg("--version")
            .output()
            .context("the downloaded binary doesn't run on this machine")?;
        let reported = String::from_utf8_lossy(&out.stdout);
        ensure!(
            out.status.success() && reported.split_whitespace().nth(1) == Some(version),
            "the downloaded binary reports {:?}, expected jkbase {version}",
            reported.trim()
        );
        #[cfg(windows)]
        {
            // A running .exe can be renamed but not overwritten: move it aside, and put it BACK
            // if the new one can't take its place (AV scanners briefly lock a file they just
            // watched run), so a failed upgrade never leaves the user without a jkbase.exe.
            let old = exe.with_extension("exe.old");
            let _ = std::fs::remove_file(&old);
            std::fs::rename(exe, &old).context("move the running jkbase.exe aside")?;
            let mut last = None;
            for attempt in 0..5 {
                match std::fs::rename(&tmp, exe) {
                    Ok(()) => return Ok(()),
                    Err(e) => last = Some(e),
                }
                std::thread::sleep(std::time::Duration::from_millis(200 << attempt));
            }
            let _ = std::fs::rename(&old, exe);
            Err(last.unwrap()).with_context(|| format!("replace {}", exe.display()))
        }
        #[cfg(not(windows))]
        {
            std::fs::rename(&tmp, exe).with_context(|| format!("replace {}", exe.display()))?;
            Ok(())
        }
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

pub async fn run(args: UpgradeArgs) -> Result<()> {
    let repo = repo()?;
    let client = client()?;
    let version = match &args.version {
        Some(v) => {
            ensure!(cli_version::parse(v).is_some(), "--version must be major.minor.patch");
            v.trim_start_matches('v').to_string()
        }
        None => latest_version(&client, &repo).await?,
    };

    if args.check {
        if cli_version::older(CLI_VERSION, &version) {
            println!("jkbase {version} is available (you have {CLI_VERSION}) — run `jkbase upgrade`");
        } else {
            println!("jkbase {CLI_VERSION} is up to date (latest release: {version})");
        }
        return Ok(());
    }
    if version == CLI_VERSION && !args.force {
        println!("jkbase {CLI_VERSION} is already installed");
        return Ok(());
    }
    if args.version.is_none() && cli_version::older(&version, CLI_VERSION) {
        println!("jkbase {CLI_VERSION} is newer than the latest release ({version}); nothing to do");
        return Ok(());
    }

    let asset = format!("jkbase-{TARGET}.tar.gz");
    let base = format!("https://github.com/{repo}/releases/download/{TAG_PREFIX}{version}");
    println!("Downloading jkbase {version} for {TARGET}...");
    let sums = fetch(&client, &format!("{base}/SHA256SUMS"), MAX_SUMS).await?;
    let sig = fetch(&client, &format!("{base}/SHA256SUMS.sig"), release_sig::MAX_SIG)
        .await
        .with_context(|| format!("release {TAG_PREFIX}{version} has no signature"))?;
    // Verify before reading a single line of it: everything below trusts only these signed bytes.
    release_sig::verify_sums(&sums, &sig)
        .with_context(|| format!("release {TAG_PREFIX}{version} failed signature verification"))?;
    let sums = String::from_utf8(sums).context("SHA256SUMS is not text")?;
    let want = expected_sha256(&sums, &asset).with_context(|| {
        format!("no {TARGET} build in release {TAG_PREFIX}{version}")
    })?;
    let archive = fetch(&client, &format!("{base}/{asset}"), MAX_ARCHIVE).await?;
    let got = hex(&Sha256::digest(&archive));
    ensure!(got == want, "checksum mismatch for {asset}: expected {want}, got {got}");

    let bin = extract_binary(&archive)?;
    let exe = std::env::current_exe()?
        .canonicalize()
        .context("locate the running jkbase binary")?;
    // canonicalize() on Windows yields a `\\?\` verbatim path; fine for fs calls, ugly to print.
    #[cfg(windows)]
    let _ = std::fs::remove_file(exe.with_extension("exe.old"));
    install(&exe, &bin, &version)?;
    println!("Upgraded jkbase {CLI_VERSION} → {version} ({})", exe.display());
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_lookup_is_exact() {
        let h = "a".repeat(64);
        let sums = format!("{h}  jkbase-x86_64-unknown-linux-musl.tar.gz\n{}  jkbase-aarch64-apple-darwin.tar.gz\n", "b".repeat(64));
        assert_eq!(expected_sha256(&sums, "jkbase-x86_64-unknown-linux-musl.tar.gz").unwrap(), h);
        assert!(expected_sha256(&sums, "jkbase-x86_64-unknown-linux").is_err());
        assert!(expected_sha256("zz  jkbase.tar.gz", "jkbase.tar.gz").is_err());
    }

    fn targz(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        for (path, data, ty) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*ty);
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            if *ty == tar::EntryType::Symlink {
                h.set_link_name("/etc/passwd").unwrap();
                h.set_size(0);
            }
            h.set_cksum();
            b.append_data(&mut h, path, *data).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extracts_only_the_top_level_regular_binary() {
        let name = if cfg!(windows) { "jkbase.exe" } else { "jkbase" };
        let a = targz(&[
            ("sub/jkbase", b"nested", tar::EntryType::Regular),
            (name, b"", tar::EntryType::Symlink),
            (name, b"real", tar::EntryType::Regular),
        ]);
        assert_eq!(extract_binary(&a).unwrap(), b"real");
        let none = targz(&[("sub/jkbase", b"nested", tar::EntryType::Regular)]);
        assert!(extract_binary(&none).is_err());
    }

    #[test]
    fn repo_override_is_validated() {
        // SAFETY: test-local env mutation; no other test reads JKBASE_UPDATE_REPO.
        unsafe { std::env::set_var("JKBASE_UPDATE_REPO", "evil.com/x/y") };
        assert!(repo().is_err());
        unsafe { std::env::set_var("JKBASE_UPDATE_REPO", "someone/fork") };
        assert_eq!(repo().unwrap(), "someone/fork");
        unsafe { std::env::remove_var("JKBASE_UPDATE_REPO") };
    }
}
