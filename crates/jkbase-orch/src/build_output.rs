//! Reading a build VM's output drive **without mounting it** (threat-model P0-3).
//!
//! The output image is an ext4 filesystem written by untrusted, attacker-
//! controlled guest code. The host kernel must NEVER mount or parse it — a
//! hostile ext4 is an attack surface against the in-kernel fs driver. We instead
//! read individual, *known-named* files out of the image with
//! `debugfs -R "dump <src> <dest>"`: a userspace ext2/3/4 reader that never
//! invokes the host kernel filesystem driver, and writes only to host paths
//! **we** choose (never a guest-controlled path), so a hostile image cannot
//! traverse out of the destination directory. This is the sanctioned reader for
//! the move-out raw output image produced by [`crate::build_vm`].
//!
//! Unlike `mount`/`losetup`/`e2fsck` (which [`crate::build_vm::BuildVm::teardown`]
//! forbids), `debugfs` in `-R` mode is read-only and parses in userspace. The
//! residual risk is a `debugfs` parser bug on hostile input; for defence in depth
//! the caller may run this as the dropped build uid or inside a throwaway VM.
//!
//! IMPORTANT: `debugfs` exits 0 even when the requested file does not exist (it
//! prints `File not found by ext2_lookup` and creates no output). Success is
//! therefore determined by whether the destination file was actually written —
//! never by the process exit status.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Dump one known file from the untrusted ext4 `image` to `dest` on the host via
/// `debugfs` (no mount). `guest_path` is absolute within the image (e.g.
/// `/status`). Returns `Ok(true)` if the file existed and was written, `Ok(false)`
/// if it was absent in the image.
///
/// `guest_path` and `dest` must be whitespace-free: `debugfs -R` splits its
/// request string on whitespace. Callers control both (fixed output-contract
/// names; host paths under the data dir), so this is an invariant, not a guess.
pub fn dump_file(image: &Path, guest_path: &str, dest: &Path) -> Result<bool> {
    let dest_str = dest
        .to_str()
        .with_context(|| format!("non-UTF-8 dest path {}", dest.display()))?;
    if guest_path.contains(char::is_whitespace) || dest_str.contains(char::is_whitespace) {
        bail!("debugfs dump paths must be whitespace-free: {guest_path:?} -> {dest_str:?}");
    }
    if dest.exists() {
        std::fs::remove_file(dest)
            .with_context(|| format!("clear stale dump dest {}", dest.display()))?;
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let out = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("dump {guest_path} {dest_str}"))
        .arg(image)
        .output()
        .with_context(|| {
            format!(
                "run debugfs dump {guest_path} from {} (is e2fsprogs installed?)",
                image.display()
            )
        })?;
    // Note: exit status is unreliable (0 even on missing file). The destination
    // file's existence is the real signal. A spawn/exec failure is caught above.
    let _ = out;
    Ok(dest.exists())
}

/// Read a known file out of the untrusted `image`, capped at `max_bytes` (keeping
/// the *tail* when larger, since logs are most useful at the end). Returns `None`
/// if the file is absent. Uses a temp file alongside `image` (same dir, so same
/// filesystem) for the debugfs dump, then reads + removes it.
pub fn read_capped(image: &Path, guest_path: &str, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let stem = guest_path.trim_matches('/').replace('/', "_");
    let tmp = image.with_file_name(format!(
        ".dbgread-{}-{stem}",
        image.file_name().and_then(|s| s.to_str()).unwrap_or("img")
    ));
    let present = dump_file(image, guest_path, &tmp)?;
    if !present {
        return Ok(None);
    }
    let bytes = std::fs::read(&tmp).with_context(|| format!("read dumped {}", tmp.display()))?;
    let _ = std::fs::remove_file(&tmp);
    let bytes = if bytes.len() > max_bytes {
        bytes[bytes.len() - max_bytes..].to_vec()
    } else {
        bytes
    };
    Ok(Some(bytes))
}

/// Read and parse the build-runner's `/status` file (the build's exit code).
/// `None` if absent (e.g. the guest crashed before writing it) or unparseable.
pub fn read_status(image: &Path) -> Result<Option<i32>> {
    let Some(bytes) = read_capped(image, "/status", 32)? else {
        return Ok(None);
    };
    Ok(String::from_utf8_lossy(&bytes).trim().parse::<i32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips a real ext4 image — only runs where `mkfs.ext4` + `debugfs`
    /// exist (skips cleanly in a bare CI sandbox). Exercises the missing-file,
    /// binary-safety, and tail-cap behaviours the orchestrator relies on.
    #[test]
    fn reads_known_files_without_mounting() {
        fn have(bin: &str) -> bool {
            std::process::Command::new(bin)
                .arg("-V")
                .output()
                .map(|o| o.status.success() || !o.stderr.is_empty() || !o.stdout.is_empty())
                .unwrap_or(false)
        }
        if !have("debugfs") || std::process::Command::new("mkfs.ext4").arg("-V").output().is_err() {
            eprintln!("skipping: debugfs/mkfs.ext4 unavailable");
            return;
        }

        let dir = std::env::temp_dir().join(format!("jkb-bo-test-{}", std::process::id()));
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("status"), b"0\n").unwrap();
        let wasm: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(src.join("artifact.wasm"), &wasm).unwrap();
        std::fs::write(src.join("build.log"), vec![b'x'; 100_000]).unwrap();

        let img = dir.join("out.img");
        assert!(std::process::Command::new("truncate")
            .args(["-s", "16M"])
            .arg(&img)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("mkfs.ext4")
            .args(["-F", "-q", "-O", "^has_journal", "-d"])
            .arg(&src)
            .arg(&img)
            .status()
            .unwrap()
            .success());

        // status parses
        assert_eq!(read_status(&img).unwrap(), Some(0));
        // binary artifact round-trips byte-for-byte
        let got = dir.join("got.wasm");
        assert!(dump_file(&img, "/artifact.wasm", &got).unwrap());
        assert_eq!(std::fs::read(&got).unwrap(), wasm);
        // absent file → false, no dest created
        let absent = dir.join("nope");
        assert!(!dump_file(&img, "/does-not-exist", &absent).unwrap());
        assert!(!absent.exists());
        // oversized log is tail-capped
        let log = read_capped(&img, "/build.log", 16 * 1024).unwrap().unwrap();
        assert_eq!(log.len(), 16 * 1024);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
