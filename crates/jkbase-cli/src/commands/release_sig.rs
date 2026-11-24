//! Release signatures: `SHA256SUMS.sig` is an SSH signature (`ssh-keygen -Y sign`, Ed25519) over
//! the release's `SHA256SUMS`, made in CI with a key held only in the `cli-release` environment's
//! secret. The trust root is `release-keys/allowed_signers`, compiled in here and copied into both
//! install scripts. A release is accepted only if one of those keys signed exactly these bytes
//! under [`NAMESPACE`]; anything else (no keys, no signature, unparsable, wrong key or namespace)
//! is an error, never a warning. SHA256SUMS then binds each archive, so this is what stops a
//! tampered release that a checksum alone (same origin as the archive) cannot.
//!
//! SSH signatures rather than minisign: same Ed25519, but `ssh-keygen` already ships on macOS,
//! Windows 10+ and most Linux, so the install scripts can verify fail-closed without asking users
//! to install a tool first. Format + rotation: `docs/cli-release-signing.md`.

use anyhow::{Context, Result, bail, ensure};
use ssh_key::{Algorithm, PublicKey, SshSig};

/// SSHSIG namespace: a signature made for any other purpose (git commits are `git`, plain
/// `ssh-keygen -Y sign` defaults to `file`) never verifies as a release.
pub const NAMESPACE: &str = "jkbase-cli-release";
/// The one principal every `allowed_signers` line names (`ssh-keygen -Y verify -I`).
pub const PRINCIPAL: &str = "jkbase-release";
/// The embedded trust root.
pub const ALLOWED_SIGNERS: &str = include_str!("../../release-keys/allowed_signers");
/// An Ed25519 SSHSIG armors to ~300 bytes; anything far bigger isn't one.
pub const MAX_SIG: u64 = 4 << 10;

/// The keys in an `allowed_signers` text. Parsed strictly to the one shape we write (see the
/// file's header), so a malformed or widened line (another principal, no namespace restriction,
/// a non-Ed25519 key) is an error rather than silently trusted or silently skipped.
pub fn parse_allowed_signers(text: &str) -> Result<Vec<PublicKey>> {
    let options = format!("namespaces=\"{NAMESPACE}\"");
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let ctx = || format!("allowed_signers line {}", n + 1);
        ensure!(
            f.len() >= 4 && f[0] == PRINCIPAL && f[1] == options && f[2] == "ssh-ed25519",
            "{}: expected `{PRINCIPAL} {options} ssh-ed25519 <key> [comment]`",
            ctx()
        );
        let key = PublicKey::from_openssh(&format!("{} {}", f[2], f[3])).with_context(ctx)?;
        ensure!(key.algorithm() == Algorithm::Ed25519, "{}: not an Ed25519 key", ctx());
        keys.push(key);
    }
    Ok(keys)
}

/// Verify `sig` (an armored SSHSIG) over `msg` against `keys`. Fails closed on an empty key list.
pub fn verify_with(keys: &[PublicKey], msg: &[u8], sig: &[u8]) -> Result<()> {
    ensure!(!keys.is_empty(), "no release-signing keys are configured; refusing to trust any release");
    let sig = SshSig::from_pem(sig).context("SHA256SUMS.sig is not an SSH signature")?;
    // Each key's verify() checks the signature names that key and our namespace before checking
    // the Ed25519 signature itself.
    if keys.iter().any(|k| k.verify(NAMESPACE, msg, &sig).is_ok()) {
        return Ok(());
    }
    bail!("SHA256SUMS.sig is not a valid signature by a jkbase release key — refusing this release")
}

#[cfg(test)]
#[path = "release_sig_tests.rs"]
mod tests;
