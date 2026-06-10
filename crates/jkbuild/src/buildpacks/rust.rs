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
        // `--message-format=json-render-diagnostics` streams machine-readable artifact
        // records on stdout — so we learn the EXACT binary paths cargo produced, even
        // under a custom target/target-dir or a multi-binary workspace — while errors
        // still render to stderr for the build log.
        let mut cmd = cargo_command("cargo", &cargo_home);
        cmd.arg("build")
            .arg("--release")
            .arg("--offline")
            .arg("--message-format=json-render-diagnostics");
        if has_lock {
            cmd.arg("--locked");
        }
        cmd.current_dir(ctx.app_dir);
        let out = cmd
            .output()
            .context("spawning `cargo build --release`")?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let lines: Vec<&str> = err.lines().collect();
            let tail = lines[lines.len().saturating_sub(40)..].join("\n");
            anyhow::bail!(
                "`cargo build --release` failed: {}\n--- output (tail) ---\n{}",
                out.status,
                tail
            );
        }

        // Exactly the binaries cargo built (name → absolute path), from its own
        // artifact records — no filesystem guessing about where target/ lives.
        let bins = parse_bin_artifacts(&out.stdout);
        if bins.is_empty() {
            anyhow::bail!(
                "`cargo build --release` produced no binary — a library-only crate has \
                 nothing to run; add a `[[bin]]` target (src/main.rs) or a server entrypoint"
            );
        }

        // App layer rooted at /app (overlayfs can't relocate a lowerdir, so the
        // content must physically live at /app). Copy EVERY built binary in, so a
        // jkbase.toml `command = ["/app/<name>"]` override (which the in-VM buildpack
        // can't see) can name any of them; the DEFAULT launch is the preferred binary
        // (root [package].name / [[bin]]), else the only one, else the first by name.
        let app_layer_root = ctx.layers_dir.join("app");
        let app_at = app_layer_root.join("app");
        std::fs::create_dir_all(&app_at)
            .with_context(|| format!("creating app layer dir {}", app_at.display()))?;
        for (_name, src) in &bins {
            let fname = src.file_name().ok_or_else(|| {
                anyhow::anyhow!("binary path has no filename: {}", src.display())
            })?;
            let dest = app_at.join(fname);
            std::fs::copy(src, &dest)
                .with_context(|| format!("copy binary {} -> {}", src.display(), dest.display()))?;
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&dest)?.permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&dest, perm)?;
        }

        let default_bin = choose_default(&bins, preferred_bin(ctx.app_dir).as_deref());

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
                command: vec![format!("/app/{default_bin}")],
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

/// Parse cargo's `--message-format=json` stream (one JSON object per line) into the
/// set of `bin` artifacts it produced: `target.name` → the absolute `executable`
/// path. Deduplicated by name (a target can be reported more than once; the record
/// carrying `executable` wins). Non-bin / library artifacts (null `executable`) and
/// non-artifact messages are ignored.
fn parse_bin_artifacts(stdout: &[u8]) -> Vec<(String, PathBuf)> {
    let mut by_name: std::collections::BTreeMap<String, PathBuf> = std::collections::BTreeMap::new();
    for line in stdout.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        let is_bin = v
            .get("target")
            .and_then(|t| t.get("kind"))
            .and_then(|k| k.as_array())
            .is_some_and(|a| a.iter().any(|x| x.as_str() == Some("bin")));
        if !is_bin {
            continue;
        }
        let exe = v.get("executable").and_then(|e| e.as_str());
        let name = v.get("target").and_then(|t| t.get("name")).and_then(|n| n.as_str());
        if let (Some(exe), Some(name)) = (exe, name) {
            by_name.insert(name.to_string(), PathBuf::from(exe));
        }
    }
    by_name.into_iter().collect()
}

/// Pick the default launch binary among those built: the `preferred` name (root
/// `[package].name` / `[[bin]]`) when present, else the only one, else the first by
/// name (deterministic; a `command = [...]` override can still select any other,
/// since all built binaries are copied into the app layer).
fn choose_default(bins: &[(String, PathBuf)], preferred: Option<&str>) -> String {
    if let Some(p) = preferred
        && bins.iter().any(|(n, _)| n == p)
    {
        return p.to_string();
    }
    // `bins` is sorted by name (BTreeMap), so [0] is the deterministic first.
    bins[0].0.clone()
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
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, contents: &str) {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, contents).unwrap();
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
    fn parse_bin_artifacts_extracts_bins_ignores_libs_and_noise() {
        // A realistic cargo --message-format=json stream: a lib artifact (null
        // executable), a build-script message, then two bin artifacts.
        let stream = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"mylib","kind":["lib"]},"executable":null}"#, "\n",
            r#"{"reason":"build-script-executed","package_id":"x"}"#, "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"server","kind":["bin"]},"executable":"/scratch/workspace/target/release/server"}"#, "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"worker","kind":["bin"]},"executable":"/scratch/workspace/target/x86_64-unknown-linux-gnu/release/worker"}"#, "\n",
            r#"{"reason":"build-finished","success":true}"#, "\n",
        );
        let bins = parse_bin_artifacts(stream.as_bytes());
        assert_eq!(bins.len(), 2);
        let map: std::collections::BTreeMap<_, _> = bins.iter().cloned().collect();
        assert_eq!(map["server"], PathBuf::from("/scratch/workspace/target/release/server"));
        // The custom-target path is honoured verbatim (no FS guessing).
        assert_eq!(
            map["worker"],
            PathBuf::from("/scratch/workspace/target/x86_64-unknown-linux-gnu/release/worker")
        );
    }

    #[test]
    fn parse_bin_artifacts_empty_for_library_only() {
        let stream = r#"{"reason":"compiler-artifact","target":{"name":"mylib","kind":["lib"]},"executable":null}"#;
        assert!(parse_bin_artifacts(stream.as_bytes()).is_empty());
    }

    #[test]
    fn choose_default_prefers_named_then_first() {
        let bins = vec![
            ("alpha".to_string(), PathBuf::from("/app/alpha")),
            ("server".to_string(), PathBuf::from("/app/server")),
        ];
        // Preferred match wins.
        assert_eq!(choose_default(&bins, Some("server")), "server");
        // No preferred (virtual workspace) → first by name (deterministic).
        assert_eq!(choose_default(&bins, None), "alpha");
        // Preferred that wasn't built → fall back to first.
        assert_eq!(choose_default(&bins, Some("ghost")), "alpha");
    }
}
