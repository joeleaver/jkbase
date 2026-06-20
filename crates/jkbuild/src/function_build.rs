//! The in-VM **function builder**: source → ONE `wasi:http` component
//! (`/out/function.wasm`).
//!
//! Deliberately NOT the CNB [`Buildpack`](crate::buildpack::Buildpack) path — CNB
//! targets layered OCI server images, not a single `.wasm`. This is a small
//! jkbase-curated per-language toolchain matrix: each builder dispatches on the
//! declared/detected language to a pinned toolchain that emits one component exporting
//! `wasi:http/incoming-handler@0.2.0` (the universal function ABI). It reuses the same
//! fetch→seal→compile shape (network only during fetch, host-enforced offline compile).
//!
//! - **Rust** → `cargo build --release --target wasm32-wasip2`. The wasip2 target emits a
//!   component directly (via the `wasi` crate's `proxy::export!`), so no cargo-component
//!   ceremony is needed.
//! - **JS/TS** → ComponentizeJS (added in the JS phase).

use crate::buildpack::{apply_mirror_ca, Decision};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Deterministic build `PATH` (mirrors the server buildpacks).
const BUILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The wasip2 Rust target — emits a `wasi:http` component, not a core module.
const WASIP2_TARGET: &str = "wasm32-wasip2";

/// Inputs threaded through a function builder's fetch + compile.
pub struct FunctionContext<'a> {
    /// Writable workspace (a copy of `/src`).
    pub app_dir: &'a Path,
    /// Per-project persistent cache (`/cache`) for the toolchain's package store.
    pub cache_dir: &'a Path,
    /// Egress proxy URL during fetch; `None` once sealed (compile must be offline).
    pub proxy: Option<String>,
}

/// A per-language function builder. Registered in [`registry`].
pub trait FunctionBuilder {
    fn id(&self) -> &'static str;
    /// Does this builder claim the source? Higher confidence wins ties.
    fn detect(&self, app_dir: &Path, lang: Option<&str>) -> Decision;
    /// Network-up phase: resolve + fetch dependencies through the egress proxy.
    fn fetch(&self, ctx: &mut FunctionContext) -> Result<()>;
    /// Offline phase: compile, returning the path to the produced `wasi:http` component.
    fn compile(&self, ctx: &mut FunctionContext) -> Result<PathBuf>;
}

/// The function-builder roster. Rust today; JS/TS (ComponentizeJS) joins in the JS phase.
pub fn registry() -> Vec<Box<dyn FunctionBuilder>> {
    vec![Box::new(RustFunction)]
}

/// Pick the highest-confidence builder for the source (mirrors the server lifecycle).
pub fn select<'a>(
    registry: &'a [Box<dyn FunctionBuilder>],
    app_dir: &Path,
    lang: Option<&str>,
) -> Option<&'a dyn FunctionBuilder> {
    registry
        .iter()
        .filter_map(|fb| {
            let d = fb.detect(app_dir, lang);
            d.is_pass().then(|| (d.confidence(), fb.as_ref()))
        })
        .max_by_key(|(c, _)| *c)
        .map(|(_, fb)| fb)
}

/// Rust → `wasi:http` component via `cargo build --target wasm32-wasip2`.
struct RustFunction;

impl FunctionBuilder for RustFunction {
    fn id(&self) -> &'static str {
        "jkbase/function-rust"
    }

    fn detect(&self, app_dir: &Path, lang: Option<&str>) -> Decision {
        match lang {
            Some("rust") => Decision::pass(100),
            Some(_) => Decision::Fail,
            None if app_dir.join("Cargo.toml").exists() => Decision::pass(80),
            None => Decision::Fail,
        }
    }

    fn fetch(&self, ctx: &mut FunctionContext) -> Result<()> {
        let cargo_home = ctx.cache_dir.join("cargo");
        std::fs::create_dir_all(&cargo_home).ok();
        // Resolve + download every dependency through the proxy for the wasip2 target, so
        // the offline compile can run fully `--offline` after the host seals the network.
        let mut cmd = cargo_command(&cargo_home);
        cmd.current_dir(ctx.app_dir)
            .args(["fetch", "--target", WASIP2_TARGET]);
        apply_proxy(&mut cmd, ctx.proxy.as_deref());
        apply_mirror_ca(&mut cmd);
        run(cmd, "cargo fetch")
    }

    fn compile(&self, ctx: &mut FunctionContext) -> Result<PathBuf> {
        let cargo_home = ctx.cache_dir.join("cargo");
        // Offline (post-seal) release build to the wasip2 component target.
        let mut cmd = cargo_command(&cargo_home);
        cmd.current_dir(ctx.app_dir).args([
            "build",
            "--release",
            "--offline",
            "--target",
            WASIP2_TARGET,
        ]);
        run(cmd, "cargo build")?;

        let release = ctx
            .app_dir
            .join("target")
            .join(WASIP2_TARGET)
            .join("release");
        find_component(&release)
    }
}

/// Find the single `wasi:http` component cargo produced in the wasip2 release dir.
/// A cdylib function crate yields exactly one top-level `.wasm`; reject ambiguity rather
/// than guess.
fn find_component(release_dir: &Path) -> Result<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(release_dir).with_context(|| {
        format!(
            "no wasip2 build output at {} (did `cargo build --target {WASIP2_TARGET}` run?)",
            release_dir.display()
        )
    })?;
    for entry in entries {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "wasm") {
            found.push(path);
        }
    }
    match found.len() {
        0 => bail!(
            "function build produced no .wasm in {} — the crate must be a `cdylib` \
             exporting wasi:http/incoming-handler",
            release_dir.display()
        ),
        1 => Ok(found.pop().unwrap()),
        n => bail!(
            "function build produced {n} .wasm files in {}; expected exactly one component \
             (one cdylib function crate)",
            release_dir.display()
        ),
    }
}

/// A cargo `Command` matching the server Rust buildpack (deterministic PATH, cache-drive
/// `CARGO_HOME`, git-deps via the system git so they honour the proxy, sparse registry).
fn cargo_command(cargo_home: &Path) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.env("PATH", BUILD_PATH)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
        .env("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse");
    cmd
}

/// Apply the egress-proxy env vars (fetch phase only).
fn apply_proxy(cmd: &mut Command, proxy: Option<&str>) {
    if let Some(proxy) = proxy {
        cmd.env("CARGO_HTTP_PROXY", proxy)
            .env("HTTP_PROXY", proxy)
            .env("HTTPS_PROXY", proxy)
            .env("http_proxy", proxy)
            .env("https_proxy", proxy);
    }
}

/// Run a build subprocess, surfacing the actual toolchain error (not just an exit code)
/// in the build log the tenant sees.
fn run(mut cmd: Command, what: &str) -> Result<()> {
    let out = cmd.output().with_context(|| format!("spawning `{what}`"))?;
    if !out.status.success() {
        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
        let lines: Vec<&str> = combined.lines().collect();
        let tail = lines[lines.len().saturating_sub(40)..].join("\n");
        bail!("`{what}` failed: {}\n--- output (tail) ---\n{}", out.status, tail);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_detect_keys_off_language_then_cargo_toml() {
        let dir = std::env::temp_dir().join(format!("jkfb-detect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rust = RustFunction;
        // Explicit hint wins, max confidence.
        assert_eq!(rust.detect(&dir, Some("rust")).confidence(), 100);
        // A non-rust hint stands down (so the JS builder can claim it).
        assert!(!rust.detect(&dir, Some("javascript")).is_pass());
        // No hint: only claims a Cargo.toml tree.
        assert!(!rust.detect(&dir, None).is_pass());
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname=\"f\"\n").unwrap();
        assert!(rust.detect(&dir, None).is_pass());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_picks_highest_confidence() {
        let reg = registry();
        let dir = std::env::temp_dir().join(format!("jkfb-select-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname=\"f\"\n").unwrap();
        assert_eq!(
            select(&reg, &dir, Some("rust")).map(|b| b.id()),
            Some("jkbase/function-rust")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_component_requires_exactly_one_wasm() {
        let dir = std::env::temp_dir().join(format!("jkfb-find-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(find_component(&dir).is_err(), "no wasm → error");
        std::fs::write(dir.join("f.wasm"), b"\0asm").unwrap();
        assert_eq!(find_component(&dir).unwrap(), dir.join("f.wasm"));
        std::fs::write(dir.join("g.wasm"), b"\0asm").unwrap();
        assert!(find_component(&dir).is_err(), "two wasm → ambiguous error");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
