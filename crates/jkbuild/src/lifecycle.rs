//! The in-VM lifecycle driver — what `jkbuild-init` (PID1) runs.
//!
//! It honours the exact drive/cmdline/seal contract the host's
//! `jkbase-orch::build_vm` sets (the same one `tools/build-runner.sh` implements
//! today), then runs our own detect→fetch→seal→compile→export instead of the
//! source's `build.sh`. The host jail is the security boundary; this binary just
//! drives the build and writes `/out`.
//!
//! Mounts/overlay/seal/reboot are shell-outs (busybox/util-linux in the toolchain
//! image), mirroring `build-runner.sh`. This path is exercised on the KVM box, not
//! in CI; the pure helpers ([`parse_cmdline_value`]) and the detect/build/export
//! logic are unit-tested.

use crate::buildpack::{BuildContext, BuildOutput, DetectContext};
use crate::env::BuildEnv;
use crate::{buildpacks, export};
use anyhow::{Context, Result};
use jkbuild_types::{CacheMeta, Index, FETCH_COMPLETE_MARKER};
use std::path::Path;
use std::process::Command;

const SRC: &str = "/src";
const OUT: &str = "/out";
const CACHE: &str = "/cache";
const WORKSPACE: &str = "/scratch/workspace";
const LAYERS: &str = "/scratch/layers";

/// Artifact shape the exporter emits. `Flat` is the transitional rung (a single
/// `rootfs.tar.gz` for the existing flat-chroot runtime); `Layered` is the target
/// (content-addressed erofs layers + index for the guest-side overlay runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportMode {
    Flat,
    Layered,
}

impl ExportMode {
    fn from_cmdline(cmdline: &str) -> Self {
        match parse_cmdline_value(cmdline, "jkbase.export").as_deref() {
            Some("layered") => ExportMode::Layered,
            _ => ExportMode::Flat,
        }
    }
}

/// Pull `key=value` from a kernel command line (space-separated tokens). Returns
/// the value of the first matching token, or `None`.
pub fn parse_cmdline_value(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(&prefix).map(str::to_string))
        .filter(|v| !v.is_empty())
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

fn read_cmdline() -> String {
    std::fs::read_to_string("/proc/cmdline").unwrap_or_default()
}

/// Run the whole build to completion, writing `/out`. Returns the build exit code
/// the caller should propagate. When running as PID1 it also writes `/out/status`
/// and reboots (the only way a Firecracker guest cleanly exits on x86).
pub fn run() -> Result<i32> {
    if is_pid1() {
        mount_early();
    }
    let cmdline = read_cmdline();
    let proxy = parse_cmdline_value(&cmdline, "jkbase.proxy");
    let lang = parse_cmdline_value(&cmdline, "jkbase.lang");
    let mode = ExportMode::from_cmdline(&cmdline);

    let result = drive(proxy, lang.as_deref(), mode);
    let code = match &result {
        Ok(()) => 0,
        Err(e) => {
            // Surface the failure in the build log the host ships to the tenant.
            let _ = append_log(&format!("jkbuild: build failed: {e:#}\n"));
            1
        }
    };

    if is_pid1() {
        let _ = std::fs::write(format!("{OUT}/status"), code.to_string());
        let _ = Command::new("sync").status();
        let _ = Command::new("reboot").arg("-f").status();
    }
    Ok(code)
}

/// The phase machine, independent of PID1/reboot scaffolding so it can be reasoned
/// about (and, later, driven from an on-box harness).
fn drive(proxy: Option<String>, lang: Option<&str>, mode: ExportMode) -> Result<()> {
    // 1. detect against /src (read-only source).
    let registry = buildpacks::registry();
    let chosen = registry
        .iter()
        .filter_map(|bp| {
            let d = bp.detect(&DetectContext {
                app_dir: Path::new(SRC),
                language_hint: lang,
            });
            if d.is_pass() {
                Some((d.confidence(), bp))
            } else {
                None
            }
        })
        .max_by_key(|(c, _)| *c)
        .map(|(_, bp)| bp)
        .context("no buildpack matched the source")?;
    append_log(&format!("jkbuild: matched buildpack {}\n", chosen.id()))?;

    // 2. copy source into a writable workspace (the build mutates it: node_modules,
    //    bun run build output). /src stays read-only.
    prepare_workspace()?;

    let mut ctx = BuildContext {
        app_dir: Path::new(WORKSPACE),
        layers_dir: Path::new(LAYERS),
        cache_dir: Path::new(CACHE),
        env: BuildEnv::new(),
        proxy: proxy.clone(),
    };
    std::fs::create_dir_all(LAYERS).ok();

    // 3. fetch (network up) → seal → compile (offline). Mirrors build-runner.sh.
    if proxy.is_some() {
        chosen.fetch(&mut ctx).context("fetch phase")?;
        // Tell the host it may seal the network now.
        println!("{FETCH_COMPLETE_MARKER}");
        wait_for_seal(proxy.as_deref());
        ctx.proxy = None; // network is gone; compile must be offline
    } else {
        // Offline build: no separate fetch window.
        chosen.fetch(&mut ctx).context("fetch phase (offline)")?;
    }
    let output = chosen.compile(&mut ctx).context("compile phase")?;

    // 4. export.
    export_artifact(&output, mode)
}

fn export_artifact(output: &BuildOutput, mode: ExportMode) -> Result<()> {
    let out_root = Path::new(OUT);
    let manifest = export::to_built_manifest(output);
    let cache = CacheMeta::default(); // populated once cache keying lands

    match mode {
        ExportMode::Flat => {
            export::pack_flat_tarball(output, &out_root.join("rootfs.tar.gz"))?;
            let index = Index {
                schema: Index::SCHEMA,
                target: "server".to_string(),
                layers: Vec::new(),
            };
            export::write_metadata(out_root, &index, &manifest, &cache)?;
        }
        ExportMode::Layered => {
            let layers_dir = out_root.join("layers");
            let mut refs = Vec::new();
            for layer in output.layers.iter().filter(|l| l.types.launch) {
                refs.push(export::pack_layer_erofs(
                    &layer.name,
                    layer.role,
                    &layer.path,
                    &layers_dir,
                )?);
            }
            let index = Index {
                schema: Index::SCHEMA,
                target: "server".to_string(),
                layers: refs,
            };
            export::write_metadata(out_root, &index, &manifest, &cache)?;
        }
    }
    Ok(())
}

fn prepare_workspace() -> Result<()> {
    std::fs::create_dir_all(WORKSPACE).ok();
    // `cp -a /src/. /scratch/workspace/` — preserve perms/symlinks, copy contents.
    let status = Command::new("cp")
        .arg("-a")
        .arg(format!("{SRC}/."))
        .arg(format!("{WORKSPACE}/"))
        .status()
        .context("copying source into workspace")?;
    if !status.success() {
        anyhow::bail!("failed to stage source into {WORKSPACE}");
    }
    Ok(())
}

/// Best-effort early mounts mirroring `build-runner.sh` (proc/sys/dev/tmp + the
/// drive set). Errors are ignored — a missing optional drive must not abort.
fn mount_early() {
    let _ = Command::new("mount").args(["-t", "proc", "proc", "/proc"]).status();
    let _ = Command::new("mount").args(["-t", "sysfs", "sysfs", "/sys"]).status();
    let _ = Command::new("mount").args(["-t", "devtmpfs", "devtmpfs", "/dev"]).status();
    let _ = Command::new("mount").args(["-t", "tmpfs", "tmpfs", "/tmp"]).status();
    for dir in ["/scratch", SRC, OUT, CACHE] {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = Command::new("mount").args(["/dev/vdb", "/scratch"]).status();
    let _ = Command::new("mount").args(["-t", "ext4", "-o", "ro", "/dev/vdc", SRC]).status();
    let _ = Command::new("mount").args(["/dev/vdd", OUT]).status();
    let _ = Command::new("mount").args(["/dev/vde", CACHE]).status(); // optional
}

/// Observe the host sealing the network (the proxy becoming unreachable). The host
/// owns the TAP; we cannot bring the network back — this is observation only.
fn wait_for_seal(proxy: Option<&str>) {
    let Some(proxy) = proxy else { return };
    let (host, port) = split_proxy(proxy);
    for _ in 0..30 {
        let reachable = Command::new("nc")
            .args(["-w", "1", &host, &port])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !reachable {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn split_proxy(proxy: &str) -> (String, String) {
    let no_scheme = proxy.split("://").last().unwrap_or(proxy);
    let authority = no_scheme.split('/').next().unwrap_or(no_scheme);
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (authority.to_string(), "80".to_string()),
    }
}

fn append_log(msg: &str) -> Result<()> {
    use std::io::Write;
    eprint!("{msg}");
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{OUT}/build.log"))
        .with_context(|| "opening /out/build.log")?;
    f.write_all(msg.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmdline_picks_value() {
        let c = "console=ttyS0 ro jkbase.proxy=http://10.0.0.1:3128 jkbase.lang=bun ipv6.disable=1";
        assert_eq!(
            parse_cmdline_value(c, "jkbase.proxy").as_deref(),
            Some("http://10.0.0.1:3128")
        );
        assert_eq!(parse_cmdline_value(c, "jkbase.lang").as_deref(), Some("bun"));
        assert_eq!(parse_cmdline_value(c, "jkbase.missing"), None);
    }

    #[test]
    fn parse_cmdline_ignores_empty_value() {
        assert_eq!(parse_cmdline_value("a= b=2", "a"), None);
    }

    #[test]
    fn export_mode_defaults_flat() {
        assert_eq!(ExportMode::from_cmdline("ro console=ttyS0"), ExportMode::Flat);
        assert_eq!(
            ExportMode::from_cmdline("jkbase.export=layered"),
            ExportMode::Layered
        );
        assert_eq!(
            ExportMode::from_cmdline("jkbase.export=flat"),
            ExportMode::Flat
        );
    }

    #[test]
    fn split_proxy_handles_scheme_and_default_port() {
        assert_eq!(
            split_proxy("http://10.0.0.1:3128"),
            ("10.0.0.1".to_string(), "3128".to_string())
        );
        assert_eq!(
            split_proxy("10.0.0.1"),
            ("10.0.0.1".to_string(), "80".to_string())
        );
    }
}
