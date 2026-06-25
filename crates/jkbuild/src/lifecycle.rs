//! The in-VM lifecycle driver — what `jkbuild-init` (PID1) runs.
//!
//! It honours the exact drive/cmdline/seal contract the host's
//! `jkbase-orch::build_vm` sets (the same one `tools/build-runner.sh` implements
//! today), then runs our own detect→fetch→seal→compile→export instead of the
//! source's `build.sh`. The host jail is the security boundary; this binary just
//! drives the build and writes `/out`.
//!
//! Early-boot mounts, the seal wait, and reboot use **libc/std directly** — NOT
//! shell-outs — because the Wolfi toolchain image's busybox does not ship the
//! `mount`/`reboot` applets. This path is exercised on the KVM box; the pure
//! helpers ([`parse_cmdline_value`]) and the detect/build/export logic are
//! unit-tested.

use crate::buildpack::{BuildContext, BuildOutput, DetectContext};
use crate::env::BuildEnv;
use crate::{buildpacks, export, function_build};
use anyhow::{Context, Result};
use jkbuild_types::{CacheMeta, Index, FETCH_COMPLETE_MARKER};
use std::ffi::CString;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

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

/// The build subdir within the mounted context (`jkbase.build_subdir=`), defaulting to
/// `"."` (build at the context root — the non-monorepo case). A value with a traversal
/// component (`..`), an absolute path, or a leading `-` is REJECTED (falls back to ".")
/// so a hostile/garbled cmdline token can't escape `/src` or the workspace — defence in
/// depth atop the host-side `is_safe_cmdline_path` guard that gates emission.
fn build_subdir(cmdline: &str) -> String {
    match parse_cmdline_value(cmdline, "jkbase.build_subdir") {
        Some(s) if is_safe_subdir(&s) => s,
        _ => ".".to_string(),
    }
}

/// Join a context-relative build subdir onto a base. `"."` returns the base UNCHANGED
/// (the common, non-monorepo case) so paths are byte-identical to the pre-`context`
/// build. The subdir is assumed already validated by [`is_safe_subdir`].
fn join_subdir(base: &Path, subdir: &str) -> std::path::PathBuf {
    if subdir == "." {
        base.to_path_buf()
    } else {
        base.join(subdir)
    }
}

/// A safe, context-relative subdir: non-empty, not absolute, no `-` flag prefix, no
/// `..` traversal, ordinary path chars only. (Mirrors the host's `is_safe_cmdline_path`.)
fn is_safe_subdir(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.starts_with('-')
        && !p.contains("..")
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
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
    let builder = parse_cmdline_value(&cmdline, "jkbase.builder");
    let dockerfile = parse_cmdline_value(&cmdline, "jkbase.dockerfile");
    let mode = ExportMode::from_cmdline(&cmdline);
    let kind = parse_cmdline_value(&cmdline, "jkbase.kind");
    // The build subdir WITHIN the mounted context (`/src`). Absent → `"."` (build at
    // the context root), the non-monorepo default. `build_subdir` validates the token
    // (no traversal/absolute) and falls back to "." on a bad value.
    let subdir = build_subdir(&cmdline);

    let result = match kind.as_deref() {
        Some("function") => {
            // Function target: the curated per-language function-builder →
            // /out/function.wasm, not the server detect/export path.
            drive_function(proxy, lang.as_deref(), &subdir)
        }
        Some("static") => {
            // Static target: run the normal buildpack pipeline (e.g. trunk), but export
            // the produced static tree as a plain `/out/static.tar.gz` the host untars
            // into the served site location — no erofs layer, no server manifest.
            drive_static(proxy, lang.as_deref(), builder.as_deref(), dockerfile, &subdir)
        }
        _ => drive(proxy, lang.as_deref(), builder.as_deref(), dockerfile, mode, &subdir),
    };
    let code = match &result {
        Ok(()) => 0,
        Err(e) => {
            let _ = append_log(&format!("jkbuild: build failed: {e:#}\n"));
            1
        }
    };

    if is_pid1() {
        let _ = std::fs::write(format!("{OUT}/status"), code.to_string());
        reboot();
    }
    Ok(code)
}

/// The phase machine, independent of PID1/reboot scaffolding so it can be reasoned
/// about (and, later, driven from an on-box harness).
fn drive(
    proxy: Option<String>,
    lang: Option<&str>,
    builder: Option<&str>,
    dockerfile: Option<String>,
    mode: ExportMode,
    subdir: &str,
) -> Result<()> {
    let output = run_buildpack_pipeline(proxy, lang, builder, dockerfile, subdir)?;
    export_artifact(&output, mode)
}

/// Static target: run the buildpack pipeline (e.g. trunk) and export the produced
/// static tree as a plain `/out/static.tar.gz`. This reuses the exact
/// detect→fetch→seal→compile machinery as the server path; only the EXPORT differs —
/// a flat tarball of the launch layers (the static bundle) instead of an erofs layer
/// + server manifest. The host untars it into the served site location.
fn drive_static(
    proxy: Option<String>,
    lang: Option<&str>,
    builder: Option<&str>,
    dockerfile: Option<String>,
    subdir: &str,
) -> Result<()> {
    let output = run_buildpack_pipeline(proxy, lang, builder, dockerfile, subdir)?;
    let dest = Path::new(OUT).join("static.tar.gz");
    export::pack_flat_tarball(&output, &dest).context("pack static tarball")?;
    let bytes = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    append_log(&format!("jkbuild: wrote static.tar.gz ({bytes} bytes)\n"))?;
    Ok(())
}

/// Shared detect→fetch→seal→compile for the server and static paths. Returns the
/// buildpack's [`BuildOutput`]; the caller picks the export shape.
fn run_buildpack_pipeline(
    proxy: Option<String>,
    lang: Option<&str>,
    builder: Option<&str>,
    dockerfile: Option<String>,
    subdir: &str,
) -> Result<BuildOutput> {
    // The build root WITHIN the mounted context: `/src/<subdir>` (subdir `"."` →
    // `/src`, today's behaviour). With a monorepo `context` mounted wider than the
    // target's source, the whole context is at `/src` so a `../sibling` path-dep
    // resolves, while detect + the buildpack app_dir stay scoped to the subdir.
    let src_root = join_subdir(Path::new(SRC), subdir);

    // 1. detect against the (read-only) build root.
    let registry = buildpacks::registry();
    let chosen = registry
        .iter()
        .filter_map(|bp| {
            let d = bp.detect(&DetectContext {
                app_dir: &src_root,
                language_hint: lang,
                builder_hint: builder,
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

    // 2. copy the WHOLE context into a writable workspace (the build mutates it:
    //    node_modules, bun run build output). /src stays read-only. Copying the whole
    //    context (not just the subdir) is what makes sibling path-deps available.
    prepare_workspace()?;
    let app_dir = join_subdir(Path::new(WORKSPACE), subdir);

    let mut ctx = BuildContext {
        app_dir: &app_dir,
        // The whole copied context. For a monorepo (`subdir` != "."), `app_dir` is the
        // member within it; bun/node install + ship from this root so hoisted
        // node_modules + sibling sources are present. Equal to `app_dir` otherwise.
        workspace_root: Path::new(WORKSPACE),
        layers_dir: Path::new(LAYERS),
        cache_dir: Path::new(CACHE),
        env: BuildEnv::new(),
        proxy: proxy.clone(),
        dockerfile,
    };
    std::fs::create_dir_all(LAYERS).ok();

    // 3. fetch (network up) → seal → compile (offline). Mirrors build-runner.sh.
    if proxy.is_some() {
        chosen.fetch(&mut ctx).context("fetch phase")?;
        // Tell the host it may seal the network now.
        println!("{FETCH_COMPLETE_MARKER}");
        let _ = std::io::stdout().flush();
        wait_for_seal(proxy.as_deref());
        ctx.proxy = None; // network is gone; compile must be offline
    } else {
        // Offline build: no separate fetch window.
        chosen.fetch(&mut ctx).context("fetch phase (offline)")?;
    }
    chosen.compile(&mut ctx).context("compile phase")
}

/// Build a WASM function: detect the language, fetch→seal→compile to ONE `wasi:http`
/// component, and write it to `/out/function.wasm` (the artifact the host collects). Same
/// host-enforced network boundary as the server path — network only during fetch.
fn drive_function(proxy: Option<String>, lang: Option<&str>, subdir: &str) -> Result<()> {
    let src_root = join_subdir(Path::new(SRC), subdir);
    let registry = function_build::registry();
    let chosen = function_build::select(&registry, &src_root, lang)
        .context("no function builder matched the source")?;
    append_log(&format!("jkbuild: matched function builder {}\n", chosen.id()))?;

    prepare_workspace()?;
    let app_dir = join_subdir(Path::new(WORKSPACE), subdir);
    let mut ctx = function_build::FunctionContext {
        app_dir: &app_dir,
        cache_dir: Path::new(CACHE),
        proxy: proxy.clone(),
    };

    if proxy.is_some() {
        chosen.fetch(&mut ctx).context("function fetch phase")?;
        // Tell the host it may seal the network now, then compile offline.
        println!("{FETCH_COMPLETE_MARKER}");
        let _ = std::io::stdout().flush();
        wait_for_seal(proxy.as_deref());
        ctx.proxy = None;
    } else {
        chosen.fetch(&mut ctx).context("function fetch phase (offline)")?;
    }

    let wasm = chosen.compile(&mut ctx).context("function compile phase")?;
    let out = Path::new(OUT).join("function.wasm");
    std::fs::copy(&wasm, &out)
        .with_context(|| format!("copy {} → {}", wasm.display(), out.display()))?;
    let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    append_log(&format!("jkbuild: wrote function.wasm ({bytes} bytes)\n"))?;
    Ok(())
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

/// Recursively copy `/src` into the writable workspace (preserving symlinks).
fn prepare_workspace() -> Result<()> {
    let ws = Path::new(WORKSPACE);
    std::fs::create_dir_all(ws).ok();
    copy_tree(Path::new(SRC), ws).context("staging source into workspace")?;
    // The source drive is an ext4 fs, so its mountpoint root carries a
    // `lost+found` — strip it so it never lands in the app layer.
    let _ = std::fs::remove_dir_all(ws.join("lost+found"));
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            let _ = std::fs::remove_file(&to);
            symlink(target, &to)?;
        } else if ft.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Best-effort early mounts mirroring `build-runner.sh`, via libc (the image's
/// busybox lacks a `mount` applet). Errors are logged, not fatal — a missing
/// optional drive (e.g. cache) must not abort the build.
fn mount_early() {
    let _ = std::fs::create_dir_all("/proc");
    mount_log("proc", "/proc", "proc", 0);
    mount_log("sysfs", "/sys", "sysfs", 0);
    mount_log("devtmpfs", "/dev", "devtmpfs", 0);
    mount_log("tmpfs", "/tmp", "tmpfs", 0);
    // Writable /run + /var: container tooling (buildah/crun/netavark) writes locks,
    // runtime state, and a blob cache under /run, /var/cache, /var/tmp, /var/lib —
    // but the toolchain root is mounted read-only. tmpfs over both gives the
    // dockerfile buildpack writable scratch there (its real storage is on the big
    // scratch drive via buildah --root). Harmless for the bun toolchain, which
    // doesn't touch them. The toolchain's own /var content isn't needed at build time.
    mount_log("tmpfs", "/run", "tmpfs", 0);
    let _ = std::fs::create_dir_all("/run/lock");
    mount_log("tmpfs", "/var", "tmpfs", 0);
    for d in ["/var/tmp", "/var/cache", "/var/lib"] {
        let _ = std::fs::create_dir_all(d);
    }
    // Writable HOME for root: some build tools (notably jco's wizer → wasmtime) write a
    // cache under `~/.cache`, and the toolchain root is read-only. componentize-js spawns
    // wizer with a minimal env (it drops HOME/XDG), so an env override doesn't reach it —
    // a tmpfs over /root is the robust fix. Harmless for the server toolchains, which key
    // their caches off CARGO_HOME / npm_config_cache, not ~.
    mount_log("tmpfs", "/root", "tmpfs", 0);
    for dir in [SRC, OUT, CACHE, "/scratch"] {
        let _ = std::fs::create_dir_all(dir);
    }
    // vdb scratch (RW), vdc source (RO), vdd output (RW), vde cache (RW, optional).
    mount_log("/dev/vdb", "/scratch", "ext4", 0);
    mount_log("/dev/vdc", SRC, "ext4", libc::MS_RDONLY);
    mount_log("/dev/vdd", OUT, "ext4", 0);
    // The cache drive (vde) is optional. When the orchestrator attaches none, the
    // ext4 mount fails and /cache would sit on the read-only toolchain root — but
    // buildpacks need a WRITABLE cache (npm/cargo/pnpm error hard on an unwritable
    // cache dir; bun silently falls back). Fall back to a tmpfs so /cache is always
    // writable (ephemeral, per-build; a persistent vde cache drive is the wired
    // follow-up). When vde IS attached the ext4 mount wins and the cache persists.
    if mount("/dev/vde", CACHE, "ext4", 0).is_err() {
        mount_log("tmpfs", CACHE, "tmpfs", 0);
    }
}

fn mount_log(src: &str, target: &str, fstype: &str, flags: libc::c_ulong) {
    if let Err(e) = mount(src, target, fstype, flags) {
        eprintln!("jkbuild: mount {src} -> {target} ({fstype}) failed: {e}");
    }
}

fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong) -> std::io::Result<()> {
    let src_c = CString::new(src).unwrap();
    let tgt_c = CString::new(target).unwrap();
    let fs_c = CString::new(fstype).unwrap();
    let r = unsafe {
        libc::mount(
            src_c.as_ptr(),
            tgt_c.as_ptr(),
            fs_c.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Flush + reboot. As PID1 this is how a Firecracker x86 guest cleanly exits.
fn reboot() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
    }
    // reboot only returns on failure; spin so PID1 never exits (which would panic
    // the kernel before the host reads /out).
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Observe the host sealing the network (the proxy becoming unreachable) via TCP
/// connect probes. The host owns the TAP; we cannot bring the network back.
fn wait_for_seal(proxy: Option<&str>) {
    let Some(proxy) = proxy else { return };
    let (host, port) = split_proxy(proxy);
    let authority = format!("{host}:{port}");
    for _ in 0..30 {
        let reachable = std::net::ToSocketAddrs::to_socket_addrs(&authority)
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|sa| TcpStream::connect_timeout(&sa, Duration::from_secs(1)).is_ok())
            .unwrap_or(false);
        if !reachable {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
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

    #[test]
    fn build_subdir_defaults_dot_and_rejects_traversal() {
        // Absent → "." (build at the context root; today's behaviour).
        assert_eq!(build_subdir("ro console=ttyS0"), ".");
        // A safe subdir is honoured.
        assert_eq!(build_subdir("jkbase.build_subdir=web"), "web");
        assert_eq!(build_subdir("jkbase.build_subdir=crates/api"), "crates/api");
        // Hostile/garbled tokens fall back to "." rather than escaping /src.
        assert_eq!(build_subdir("jkbase.build_subdir=../etc"), ".");
        assert_eq!(build_subdir("jkbase.build_subdir=/etc/passwd"), ".");
        assert_eq!(build_subdir("jkbase.build_subdir=-rf"), ".");
    }

    #[test]
    fn join_subdir_dot_is_identity() {
        // "." must NOT change the path — the regression guard for the default path.
        assert_eq!(join_subdir(Path::new("/scratch/workspace"), "."), Path::new("/scratch/workspace"));
        assert_eq!(
            join_subdir(Path::new("/scratch/workspace"), "web"),
            Path::new("/scratch/workspace/web")
        );
    }

    #[test]
    fn copy_tree_preserves_files_and_symlinks() {
        use std::os::unix::fs::symlink;
        let d = std::env::temp_dir().join(format!("jkbuild-copytree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let src = d.join("src");
        let dst = d.join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"world").unwrap();
        symlink("a.txt", src.join("link")).unwrap();
        copy_tree(&src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(dst.join("sub/b.txt")).unwrap(), b"world");
        assert!(std::fs::symlink_metadata(dst.join("link")).unwrap().file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&d);
    }
}
