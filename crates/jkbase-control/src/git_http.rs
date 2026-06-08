//! Smart-HTTP `git-receive-pack` server for the `git push jkbase main` build
//! trigger (build · D, design §4/§9/§10).
//!
//! This module is the protocol mechanics only — pkt-line framing, the bare-repo
//! per project, shelling to `git receive-pack --stateless-rpc`, the streamed
//! pack DoS limits, and archiving the pushed tip into the build funnel's source
//! tarball. Auth (per-project token, cross-project 403) and the build funnel
//! live in `api.rs`; the host kernel never mounts the pushed objects — `git`
//! parses them in-process, bounded by [`PACK_MAX_BYTES`] / [`PACK_MAX_OBJECTS`].
//!
//! Threat model: the endpoint is attacker-reachable and the pack is hostile
//! input. The HTTP body limit doesn't bound a streamed receive cleanly (§9), so
//! the caller reads the body with a hard byte cap and we additionally reject on
//! the pack header's object count before handing anything to `git`.

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Hard cap on a received packfile. Tight on purpose: the generous 2 GiB body
/// limit on `/build` would let a single push pin gigabytes (§9, pack-bomb DoS).
pub const PACK_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Hard cap on the object count declared in the pack header — a cheap, early
/// refs/objects-explosion guard checked before `git` unpacks anything.
pub const PACK_MAX_OBJECTS: u32 = 250_000;

/// Per-project bare repo on the control host: `{data_dir}/git/{project_id}.git`.
pub fn bare_repo_path(data_dir: &Path, project_id: &str) -> PathBuf {
    data_dir.join("git").join(format!("{project_id}.git"))
}

/// Frame a string as a git pkt-line: 4 hex length bytes (counting the 4) + the
/// payload. Computed, not hardcoded, so the service-advertisement length can't
/// drift.
pub fn pkt_line(payload: &str) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload.as_bytes());
    out
}

/// Create the bare repo on first push and pin defensive `receive` limits. Safe
/// to call repeatedly.
pub async fn ensure_bare_repo(repo: &Path) -> Result<()> {
    if repo.join("HEAD").exists() {
        return Ok(());
    }
    if let Some(parent) = repo.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create git parent dir {}", parent.display()))?;
    }
    run_git(&["init", "--bare", "-q", &repo.to_string_lossy()], None).await?;
    // Defense in depth alongside the streamed caps the caller enforces.
    let dir = repo.to_string_lossy().to_string();
    let _ = run_git(
        &[
            "--git-dir",
            &dir,
            "config",
            "receive.maxInputSize",
            &PACK_MAX_BYTES.to_string(),
        ],
        None,
    )
    .await;
    // Don't run fsck on every object set on the hot path (it's slow); the VM
    // boundary, not object well-formedness, is the security boundary (§9).
    let _ = run_git(&["--git-dir", &dir, "config", "receive.fsckObjects", "false"], None).await;
    Ok(())
}

/// The `GET /info/refs?service=git-receive-pack` body: the service pkt-line, a
/// flush, then `git receive-pack --advertise-refs` output.
pub async fn advertise_refs(repo: &Path) -> Result<Vec<u8>> {
    let out = run_git(
        &[
            "receive-pack",
            "--stateless-rpc",
            "--advertise-refs",
            &repo.to_string_lossy(),
        ],
        None,
    )
    .await
    .context("git receive-pack --advertise-refs")?;

    let mut body = pkt_line("# service=git-receive-pack\n");
    body.extend_from_slice(b"0000"); // flush-pkt
    body.extend_from_slice(&out);
    Ok(body)
}

/// Reject a pack whose declared object count exceeds [`PACK_MAX_OBJECTS`]. The
/// receive-pack request is pkt-line commands then the raw packfile; the pack
/// starts with `PACK` + a 4-byte version + a 4-byte big-endian object count.
/// A missing `PACK` (e.g. a ref-deletion-only push) is allowed through.
pub fn check_pack_object_count(body: &[u8]) -> Result<()> {
    let Some(pos) = find_subsequence(body, b"PACK") else {
        return Ok(()); // no packfile (command-only push)
    };
    let header = &body[pos..];
    if header.len() < 12 {
        bail!("truncated pack header");
    }
    let count = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    if count > PACK_MAX_OBJECTS {
        bail!("pack object count {count} exceeds limit {PACK_MAX_OBJECTS}");
    }
    Ok(())
}

/// Run `git receive-pack --stateless-rpc` over the (already size/object-capped)
/// request body, returning the report-status the git client expects. Takes the
/// pack by value so it's moved into the child's stdin, not copied.
pub async fn receive_pack(repo: &Path, input: Vec<u8>) -> Result<Vec<u8>> {
    run_git(
        &["receive-pack", "--stateless-rpc", &repo.to_string_lossy()],
        Some(input),
    )
    .await
    .context("git receive-pack --stateless-rpc")
}

/// The commit OID at `refs/heads/{branch}`, or `None` if that ref doesn't exist.
pub async fn branch_tip(repo: &Path, branch: &str) -> Option<String> {
    let dir = repo.to_string_lossy().to_string();
    let refname = format!("refs/heads/{branch}");
    let out = run_git(&["--git-dir", &dir, "rev-parse", "--verify", "-q", &refname], None)
        .await
        .ok()?;
    let oid = String::from_utf8_lossy(&out).trim().to_string();
    (!oid.is_empty()).then_some(oid)
}

/// `git archive` the pushed commit into the gzipped tar the build funnel
/// expects (jkbase.toml at the tar root; `.git` is intrinsically excluded).
pub async fn archive_commit_targz(repo: &Path, commit: &str) -> Result<Vec<u8>> {
    let dir = repo.to_string_lossy().to_string();
    let tar = run_git(
        &["--git-dir", &dir, "archive", "--format=tar", commit],
        None,
    )
    .await
    .context("git archive")?;
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar).context("gzip archive")?;
    gz.finish().context("finish gzip")
}

/// Run a `git` subprocess, optionally feeding `stdin` (taken by value, moved
/// into the child), returning stdout on success and surfacing stderr on failure.
/// `git` must be on the host PATH.
async fn run_git(args: &[&str], stdin: Option<Vec<u8>>) -> Result<Vec<u8>> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut cmd = Command::new("git");
    cmd.args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("spawn git (is it installed on the host?)")?;

    // Write stdin and read stdout concurrently so a large report doesn't
    // deadlock against a still-writing stdin pipe.
    let stdin_input = stdin;
    let writer = child.stdin.take();
    let write_task = tokio::spawn(async move {
        if let (Some(mut w), Some(buf)) = (writer, stdin_input) {
            let _ = w.write_all(&buf).await;
            let _ = w.shutdown().await;
        }
    });

    let out = child.wait_with_output().await.context("wait for git")?;
    let _ = write_task.await;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("git {:?} failed: {}", args.first().unwrap_or(&"?"), stderr.trim());
    }
    Ok(out.stdout)
}

/// First index of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_line_lengths() {
        // Computed length prefix (the receive-pack advertisement header).
        assert_eq!(pkt_line("# service=git-receive-pack\n").len(), 0x1f);
        assert!(pkt_line("# service=git-receive-pack\n").starts_with(b"001f"));
        assert_eq!(&pkt_line("a"), b"0005a");
    }

    #[test]
    fn pack_object_count_enforced() {
        // No PACK magic → allowed (command-only push).
        assert!(check_pack_object_count(b"0000").is_ok());

        // PACK + version 2 + object count.
        let mut ok = Vec::new();
        ok.extend_from_slice(b"some-commands\x00PACK");
        ok.extend_from_slice(&2u32.to_be_bytes());
        ok.extend_from_slice(&10u32.to_be_bytes());
        assert!(check_pack_object_count(&ok).is_ok());

        let mut bomb = Vec::new();
        bomb.extend_from_slice(b"PACK");
        bomb.extend_from_slice(&2u32.to_be_bytes());
        bomb.extend_from_slice(&(PACK_MAX_OBJECTS + 1).to_be_bytes());
        assert!(check_pack_object_count(&bomb).is_err());

        // Truncated header after the magic → rejected.
        assert!(check_pack_object_count(b"PACK\x00\x00").is_err());
    }

    #[test]
    fn bare_repo_path_is_namespaced() {
        let p = bare_repo_path(Path::new("/var/jkbase"), "my-app");
        assert_eq!(p, Path::new("/var/jkbase/git/my-app.git"));
    }
}
