//! The Rust buildpack — `cargo` over a glibc toolchain.
//!
//! detect keys off `Cargo.toml`; `fetch` runs `cargo fetch` (network up, via the
//! egress proxy) with `CARGO_HOME` on the per-project cache drive so the registry +
//! git caches survive across builds; `compile` runs `cargo build --release
//! --offline` and extracts the resulting binary into the app layer rooted at
//! `/app`; launch is the absolute binary path.
//!
//! Linking model: the default (glibc) target produces a dynamically-linked binary
//! needing glibc (from the shared BASE layer) + `libgcc_s` (from the small shared
//! `rust` RUNTIME layer). So a Rust app stacks `app:rust-runtime:base` exactly like
//! bun/node — no special-case in the host layer plan, and broad crate
//! compatibility (C-FFI crates like openssl-sys link the toolchain's system libs).
//! Static-musl is a deliberate future opt-in, not the default.

use crate::buildpack::{
    BuildContext, BuildOutput, Buildpack, Decision, DetectContext, Layer, LayerTypes, Process,
};
use anyhow::{Context, Result};
use jkbuild_types::LayerRole;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `PATH` for cargo + its linker/cc. The toolchain image puts cargo/rustc and the
/// C toolchain (build-base) under the FHS bins.
const BUILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub struct RustBuildpack;

impl Buildpack for RustBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/rust"
    }

    fn detect(&self, ctx: &DetectContext) -> Decision {
        // An explicit Dockerfile build claims the tree; language buildpacks stand down.
        if ctx.builder_hint == Some("dockerfile") {
            return Decision::Fail;
        }
        detect_decision(ctx.app_dir, ctx.language_hint)
    }

    fn fetch(&self, ctx: &mut BuildContext) -> Result<()> {
        let cargo_home = ctx.cache_dir.join("cargo");
        std::fs::create_dir_all(&cargo_home).ok();
        let has_lock = ctx.app_dir.join("Cargo.lock").exists();

        // Resolve + download every dependency through the proxy. The sparse registry
        // (index.crates.io) + the crate CDN (static.crates.io) are on the egress
        // allowlist; git deps use the CLI (which honours the proxy env) over the
        // allowlisted git hosts.
        let mut cmd = cargo_command("cargo", &cargo_home);
        cmd.arg("fetch");
        if has_lock {
            cmd.arg("--locked");
        }
        cmd.current_dir(ctx.app_dir);
        apply_proxy(&mut cmd, ctx);
        run(cmd, "cargo fetch")?;
        Ok(())
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        let cargo_home = ctx.cache_dir.join("cargo");
        let has_lock = ctx.app_dir.join("Cargo.lock").exists();

        // Offline (post-seal) release build. `--offline` makes a build that tries to
        // touch the network fail here by design (every dep was fetched above).
        let mut cmd = cargo_command("cargo", &cargo_home);
        cmd.arg("build").arg("--release").arg("--offline");
        if has_lock {
            cmd.arg("--locked");
        }
        cmd.current_dir(ctx.app_dir);
        run(cmd, "cargo build --release")?;

        // Locate the produced binary. The workspace target dir is at the build root
        // (we run cargo from /scratch/workspace); release bins land directly in
        // target/release (deps/build/examples are subdirs we skip).
        let target_release = ctx.app_dir.join("target").join("release");
        let preferred = preferred_bin(ctx.app_dir);
        let binary = discover_binary(&target_release, preferred.as_deref())?;
        let bin_name = binary
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("binary path has no filename: {}", binary.display()))?
            .to_string();

        // App layer = JUST the binary, rooted at /app (overlayfs can't relocate a
        // lowerdir, so it must physically live at /app). The binary is the whole
        // tenant artifact; glibc + libgcc_s come from the base/runtime layers.
        let app_layer_root = ctx.layers_dir.join("app");
        let app_at = app_layer_root.join("app");
        std::fs::create_dir_all(&app_at)
            .with_context(|| format!("creating app layer dir {}", app_at.display()))?;
        let dest = app_at.join(&bin_name);
        std::fs::copy(&binary, &dest)
            .with_context(|| format!("copy binary {} -> {}", binary.display(), dest.display()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&dest)?.permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&dest, perm)?;
        }

        let app_layer = Layer {
            name: "app".to_string(),
            path: app_layer_root,
            types: LayerTypes {
                build: false,
                launch: true,
                cache: false,
            },
            role: LayerRole::App,
        };

        Ok(BuildOutput {
            layers: vec![app_layer],
            processes: vec![Process {
                r#type: "web".to_string(),
                command: vec![format!("/app/{bin_name}")],
                default: true,
            }],
            env: std::collections::BTreeMap::new(),
            working_dir: Some("/app".to_string()),
        })
    }
}

/// Detect whether this is a Rust app. `Cargo.toml` is the signal; a committed
/// `Cargo.lock` raises confidence (reproducible, `--locked` builds).
pub fn detect_decision(app_dir: &Path, language_hint: Option<&str>) -> Decision {
    if language_hint == Some("rust") {
        return Decision::pass(100);
    }
    if matches!(language_hint, Some(h) if h != "rust") {
        return Decision::Fail;
    }
    if !app_dir.join("Cargo.toml").exists() {
        return Decision::Fail;
    }
    if app_dir.join("Cargo.lock").exists() {
        Decision::pass(90)
    } else {
        Decision::pass(80)
    }
}

/// The binary name to prefer when a build emits several: an explicit `[[bin]]`
/// name, else the `[package].name`. Returns `None` for a virtual workspace
/// manifest (no `[package]`) — the caller then falls back to single-binary
/// discovery.
pub fn preferred_bin(app_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(app_dir.join("Cargo.toml")).ok()?;
    let v: toml::Value = toml::from_str(&raw).ok()?;
    if let Some(name) = v
        .get("bin")
        .and_then(|b| b.as_array())
        .and_then(|a| a.first())
        .and_then(|b| b.get("name"))
        .and_then(|n| n.as_str())
    {
        return Some(name.to_string());
    }
    v.get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(str::to_string)
}

/// Find the single release binary in `target/release`, or the one matching
/// `preferred`. Skips cargo's bookkeeping (`*.d`, dotfiles) and the subdirectories
/// (`deps/`, `build/`, `examples/`, `incremental/`, `.fingerprint/`). Errors
/// actionably on zero (library-only crate) or an ambiguous multi-binary build.
fn discover_binary(target_release: &Path, preferred: Option<&str>) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if !target_release.is_dir() {
        anyhow::bail!(
            "no {} after `cargo build` — did the build produce a binary?",
            target_release.display()
        );
    }
    let mut bins: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(target_release)
        .with_context(|| format!("read {}", target_release.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || name.ends_with(".d") {
            continue;
        }
        if entry.metadata()?.permissions().mode() & 0o111 == 0 {
            continue; // not executable (e.g. a stray data file)
        }
        bins.push((name, entry.path()));
    }

    if let Some(pref) = preferred
        && let Some((_, p)) = bins.iter().find(|(n, _)| n == pref)
    {
        return Ok(p.clone());
    }
    match bins.len() {
        0 => anyhow::bail!(
            "`cargo build --release` produced no binary in {} — a library-only crate \
             has nothing to run; add a `[[bin]]` target (src/main.rs) or a server entrypoint",
            target_release.display()
        ),
        1 => Ok(bins.pop().unwrap().1),
        _ => {
            let mut names: Vec<&str> = bins.iter().map(|(n, _)| n.as_str()).collect();
            names.sort_unstable();
            anyhow::bail!(
                "`cargo build --release` produced multiple binaries ({}); pick one with a single \
                 `[[bin]]` in Cargo.toml or set `command = [\"/app/<name>\"]` under the server in jkbase.toml",
                names.join(", ")
            )
        }
    }
}

/// A cargo `Command` with a deterministic build `PATH` + `CARGO_HOME` on the cache
/// drive. `CARGO_NET_GIT_FETCH_WITH_CLI` makes git deps go through the system git
/// (which honours the proxy env) rather than libgit2.
fn cargo_command(bin: &str, cargo_home: &Path) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env("PATH", BUILD_PATH)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
        // Be explicit that the sparse protocol is in use (default since cargo 1.70,
        // but pinning it keeps the registry an HTTPS endpoint the proxy can pass).
        .env("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse");
    cmd
}

/// Run a build subprocess, capturing its output so a failure surfaces the actual
/// cargo/rustc error in the build log the tenant sees — not just an exit code.
fn run(mut cmd: Command, what: &str) -> Result<()> {
    let out = cmd.output().with_context(|| format!("spawning `{what}`"))?;
    if !out.status.success() {
        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
        let lines: Vec<&str> = combined.lines().collect();
        let tail = lines[lines.len().saturating_sub(40)..].join("\n");
        anyhow::bail!("`{what}` failed: {}\n--- output (tail) ---\n{}", out.status, tail);
    }
    Ok(())
}

/// Apply the egress-proxy env vars (fetch phase only). cargo honours
/// `CARGO_HTTP_PROXY` + the standard `*_proxy` forms for the sparse registry; the
/// git CLI honours `http_proxy`/`https_proxy`.
fn apply_proxy(cmd: &mut Command, ctx: &BuildContext) {
    if let Some(proxy) = &ctx.proxy {
        cmd.env("CARGO_HTTP_PROXY", proxy)
            .env("HTTP_PROXY", proxy)
            .env("HTTPS_PROXY", proxy)
            .env("http_proxy", proxy)
            .env("https_proxy", proxy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, contents: &str) {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, contents).unwrap();
    }

    fn write_exec(dir: &Path, name: &str) {
        let p = dir.join(name);
        fs::write(&p, b"\x7fELF").unwrap();
        let mut perm = fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&p, perm).unwrap();
    }

    #[test]
    fn detect_passes_on_cargo_toml() {
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        let dec = detect_decision(d.path(), None);
        assert!(dec.is_pass());
        assert_eq!(dec.confidence(), 80);

        write(d.path(), "Cargo.lock", "");
        assert_eq!(detect_decision(d.path(), None).confidence(), 90);
    }

    #[test]
    fn detect_fails_without_cargo_toml() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", "{}");
        assert!(!detect_decision(d.path(), None).is_pass());
    }

    #[test]
    fn explicit_rust_hint_wins_and_foreign_hint_stands_down() {
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        assert_eq!(detect_decision(d.path(), Some("rust")).confidence(), 100);
        // A hint for another language makes Rust stand down even with a Cargo.toml.
        assert!(!detect_decision(d.path(), Some("node")).is_pass());
    }

    #[test]
    fn preferred_bin_reads_package_then_bin_override() {
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname = \"my-app\"\nversion=\"0.1.0\"\n");
        assert_eq!(preferred_bin(d.path()).as_deref(), Some("my-app"));

        let d2 = tempdir().unwrap();
        write(
            d2.path(),
            "Cargo.toml",
            "[package]\nname = \"my-app\"\n\n[[bin]]\nname = \"server\"\npath = \"src/main.rs\"\n",
        );
        assert_eq!(preferred_bin(d2.path()).as_deref(), Some("server"));
    }

    #[test]
    fn preferred_bin_none_for_virtual_workspace() {
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[workspace]\nmembers = [\"a\", \"b\"]\n");
        assert_eq!(preferred_bin(d.path()), None);
    }

    #[test]
    fn discover_single_binary() {
        let d = tempdir().unwrap();
        let rel = d.path();
        write_exec(rel, "server");
        write(rel, "server.d", "deps");
        fs::create_dir_all(rel.join("deps")).unwrap();
        let got = discover_binary(rel, None).unwrap();
        assert_eq!(got.file_name().unwrap(), "server");
    }

    #[test]
    fn discover_prefers_named_binary() {
        let d = tempdir().unwrap();
        let rel = d.path();
        write_exec(rel, "server");
        write_exec(rel, "tool");
        let got = discover_binary(rel, Some("tool")).unwrap();
        assert_eq!(got.file_name().unwrap(), "tool");
    }

    #[test]
    fn discover_errors_on_ambiguous_multi_binary() {
        let d = tempdir().unwrap();
        let rel = d.path();
        write_exec(rel, "alpha");
        write_exec(rel, "beta");
        let err = discover_binary(rel, None).unwrap_err().to_string();
        assert!(err.contains("multiple binaries"), "got: {err}");
        assert!(err.contains("alpha") && err.contains("beta"));
    }

    #[test]
    fn discover_errors_on_library_only() {
        let d = tempdir().unwrap();
        let rel = d.path();
        write(rel, "libfoo.rlib", "x"); // not executable
        let err = discover_binary(rel, None).unwrap_err().to_string();
        assert!(err.contains("no binary"), "got: {err}");
    }
}
