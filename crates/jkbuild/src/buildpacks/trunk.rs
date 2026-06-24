//! The Trunk buildpack — Rust/WASM frontends built with `trunk`.
//!
//! Trunk (<https://trunkrs.dev>) compiles a Rust `wasm32-unknown-unknown` crate to
//! a browser bundle: it runs `cargo build --target wasm32-unknown-unknown`, then
//! `wasm-bindgen` + (optionally) `wasm-opt`, and assembles a static `dist/` from an
//! `index.html` template. The output is a pure static site — HTML/JS/WASM/assets —
//! with NO server process, so this buildpack ships the produced `dist/` as a static
//! deploy artifact rather than a runnable server.
//!
//! Detect keys off `Trunk.toml` (zero-config opt-in): its presence is an
//! unambiguous "build me with trunk" signal, and it lets the buildpack win over the
//! plain `rust` server buildpack (which also sees the `Cargo.toml`). The two never
//! collide because `rust`'s detect stands down when a `Trunk.toml` is present (see
//! `rust.rs`).
//!
//! Phase split mirrors the rust buildpack:
//!   * `fetch` (network up) — `cargo fetch` (`--locked` when a `Cargo.lock` exists)
//!     over the sparse registry + git hosts, with `CARGO_HOME` on the persistent cache
//!     drive; THEN provision the exact `wasm-bindgen` CLI onto the build PATH. trunk runs
//!     wasm-bindgen after the offline cargo build but can only download it online, and
//!     the required version == the wasm-bindgen CRATE version (read from Cargo.lock, no
//!     code run) — so we fetch that exact CLI release from github (allow-listed) now.
//!     Crucially we do NOT run `trunk build` to warm tools: that would run the project's
//!     untrusted cargo build scripts/proc-macros with the network up, breaking the
//!     fetch-then-seal fence. `wasm-opt` is baked (binaryen), so no other tool download.
//!   * `compile` (offline, post-seal) — `trunk build --release --offline`: cargo builds
//!     offline, trunk picks the provisioned `wasm-bindgen` off PATH + the baked
//!     `wasm-opt`. The produced `dist/` becomes a single `launch` layer with NO processes
//!     (a static artifact, not a server). The host's static-output collection arm turns
//!     that launch tree into served content.

use crate::buildpack::{
    BuildContext, BuildOutput, Buildpack, Decision, DetectContext, Layer, LayerTypes,
};
use anyhow::{Context, Result};
use jkbuild_types::LayerRole;
use std::path::Path;
use std::process::Command;

/// `PATH` for cargo + trunk + their linker/cc. The toolchain image puts
/// cargo/rustc, `trunk`, and `wasm-opt` under the FHS bins (see
/// `images/apko/build-trunk.apko.yaml` + the `INJECT_TRUNK` step in
/// `tools/build-image.sh`).
const BUILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The directory `trunk build` writes its static bundle to (the default; a project
/// can override it in `Trunk.toml`, which `dist_dir` reads).
const DEFAULT_DIST: &str = "dist";

pub struct TrunkBuildpack;

impl Buildpack for TrunkBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/trunk"
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
        // trunk caches its downloaded build tools (the version-matched wasm-bindgen +
        // wasm-opt) under an XDG cache dir; point it at the persistent cache drive so
        // the tools survive across builds and the offline compile finds them.
        let trunk_cache = ctx.cache_dir.join("trunk");
        std::fs::create_dir_all(&trunk_cache).ok();
        let has_lock = ctx.app_dir.join("Cargo.lock").exists();

        // 1. Resolve + download every crate dependency through the proxy. Same registry
        //    + git egress as the rust server buildpack (index.crates.io / static.crates.io
        //    / github are allow-listed).
        let mut cmd = cargo_command("cargo", &cargo_home, &trunk_cache);
        cmd.arg("fetch");
        if has_lock {
            cmd.arg("--locked");
        }
        cmd.current_dir(ctx.app_dir);
        apply_proxy(&mut cmd, ctx);
        run(cmd, "cargo fetch")?;

        // 2. Provision the EXACT `wasm-bindgen` CLI offline-ready WITHOUT compiling.
        //    trunk runs wasm-bindgen AFTER the (offline) cargo build, downloading from
        //    github the version embedded in the compiled wasm — which the sealed compile
        //    cannot do. That required version == the wasm-bindgen CRATE version, which is
        //    pinned in Cargo.lock and needs NO code execution to read, so we resolve it now
        //    and fetch the matching CLI onto the build PATH (network up). The offline
        //    compile then finds it on PATH (trunk resolves tools via PATH and accepts a
        //    version-matched wasm-bindgen) and uses the baked binaryen `wasm-opt` — no
        //    network needed.
        //
        //    We deliberately do NOT run `trunk build` here to warm tools: that runs the
        //    project's (untrusted) cargo build scripts + proc-macros with the network UP,
        //    breaking the fetch-then-seal fence every other buildpack keeps (the actual
        //    compile is offline). `trunk` (0.21) has no tool-only install, so a real build
        //    would be the only trunk-driven warm — hence we fetch the binary ourselves.
        match wasm_bindgen_version(ctx.app_dir)? {
            Some(ver) => provision_wasm_bindgen(ctx, &trunk_cache, &ver)?,
            None => eprintln!(
                "jkbuild: no wasm-bindgen in Cargo.lock — skipping CLI provision; the offline \
                 compile will rely on trunk's own tool resolution"
            ),
        }
        Ok(())
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        let cargo_home = ctx.cache_dir.join("cargo");
        let trunk_cache = ctx.cache_dir.join("trunk");

        // Offline (post-seal) release build. `--offline` makes cargo fail rather than
        // touch the network (every crate was fetched above); the exact `wasm-bindgen` was
        // provisioned on PATH in fetch and `wasm-opt` is baked (binaryen), so trunk needs
        // no network. A build that still tries the network fails here by design.
        let mut cmd = trunk_command(&cargo_home, &trunk_cache);
        cmd.arg("build").arg("--release").arg("--offline");
        cmd.current_dir(ctx.app_dir);
        run(cmd, "trunk build --release --offline")?;

        // The produced static bundle. Trunk writes it to `dist/` (or the `dist`
        // configured in Trunk.toml). Ship it as a single launch layer rooted at the
        // layer root (the host's static collection arm untars the layer tree into the
        // served site location). NO processes — a static site has nothing to run.
        let dist_name = dist_dir(ctx.app_dir);
        let dist = ctx.app_dir.join(&dist_name);
        if !dist.is_dir() {
            anyhow::bail!(
                "`trunk build` produced no '{}' directory — check the Trunk.toml `dist` \
                 setting or the build output",
                dist_name
            );
        }

        // Move the dist tree into a fresh launch layer dir (cheap same-fs rename; both
        // are on /scratch). The layer's CONTENTS become the served site root, so the
        // bundle's `index.html` lands at the site root.
        let layer_root = ctx.layers_dir.join("static");
        let _ = std::fs::remove_dir_all(&layer_root);
        std::fs::create_dir_all(&layer_root)
            .with_context(|| format!("creating static layer root {}", layer_root.display()))?;
        move_tree_contents(&dist, &layer_root)
            .with_context(|| format!("ship dist tree from {}", dist.display()))?;

        let layer = Layer {
            name: "static".to_string(),
            path: layer_root,
            types: LayerTypes {
                build: false,
                launch: true,
                cache: false,
            },
            role: LayerRole::App,
        };

        Ok(BuildOutput {
            layers: vec![layer],
            // A static site has no launch process. The host's static-output path ignores
            // processes/env/working_dir; they are empty by construction here.
            processes: Vec::new(),
            env: std::collections::BTreeMap::new(),
            working_dir: None,
        })
    }
}

/// Detect whether this is a Trunk (Rust/WASM frontend) project. `Trunk.toml` is the
/// required, unambiguous signal (zero-config opt-in): a bare `Cargo.toml` is a
/// server crate (the `rust` buildpack's job), so we deliberately do NOT claim a tree
/// on `Cargo.toml` alone. A `language = "trunk"` hint is authoritative.
pub fn detect_decision(app_dir: &Path, language_hint: Option<&str>) -> Decision {
    if language_hint == Some("trunk") {
        return Decision::pass(100);
    }
    // Any other explicit language hint means "not me".
    if matches!(language_hint, Some(h) if h != "trunk") {
        return Decision::Fail;
    }
    // Require Trunk.toml — and a Cargo.toml, since trunk drives a cargo build.
    if app_dir.join("Trunk.toml").exists() && app_dir.join("Cargo.toml").exists() {
        // High confidence: Trunk.toml is purpose-specific, so beat the `rust` server
        // buildpack decisively even though it also sees the Cargo.toml.
        Decision::pass(95)
    } else {
        Decision::Fail
    }
}

/// The dist directory `trunk build` writes to: the `dist` key in `Trunk.toml` when
/// set, else trunk's default `dist`. Parsed leniently — a malformed/locked
/// Trunk.toml falls back to the default rather than failing the build here.
pub fn dist_dir(app_dir: &Path) -> String {
    let raw = match std::fs::read_to_string(app_dir.join("Trunk.toml")) {
        Ok(s) => s,
        Err(_) => return DEFAULT_DIST.to_string(),
    };
    let Ok(v) = toml::from_str::<toml::Value>(&raw) else {
        return DEFAULT_DIST.to_string();
    };
    // Trunk.toml shape: `[build] dist = "..."`.
    v.get("build")
        .and_then(|b| b.get("dist"))
        .and_then(|d| d.as_str())
        .filter(|s| !s.is_empty())
        // Trunk normalises `dist` relative to the project root; we only need the
        // leaf path under app_dir, so trim a leading `./`.
        .map(|s| s.trim_start_matches("./").to_string())
        .unwrap_or_else(|| DEFAULT_DIST.to_string())
}

/// Move every top-level entry of `src` into `dst` (cheap same-fs rename). The dist
/// tree has no build/VCS dirs to exclude (trunk writes only the bundle), so this is
/// an unconditional move. Pure filesystem ops (no trunk) → unit-testable.
fn move_tree_contents(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("creating dest {}", dst.display()))?;
    for entry in std::fs::read_dir(src)
        .with_context(|| format!("read dist dir {}", src.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        std::fs::rename(entry.path(), dst.join(&name))
            .with_context(|| format!("move {} into the static layer", entry.path().display()))?;
    }
    Ok(())
}

/// The wasm-bindgen version this project resolves to, read from `Cargo.lock` (written
/// by `cargo fetch`). `None` when the app doesn't depend on wasm-bindgen. The trunk
/// CLI version MUST match this crate version exactly (trunk enforces it from the schema
/// embedded in the compiled wasm), so this is the version we provision for the offline
/// compile. Reading the lock is pure data — NO build code runs.
fn wasm_bindgen_version(app_dir: &Path) -> Result<Option<String>> {
    let raw = match std::fs::read_to_string(app_dir.join("Cargo.lock")) {
        Ok(s) => s,
        Err(_) => return Ok(None), // no lock (cargo couldn't resolve) → let compile speak
    };
    let doc: toml::Value = raw.parse().context("parse Cargo.lock")?;
    let Some(pkgs) = doc.get("package").and_then(|p| p.as_array()) else {
        return Ok(None);
    };
    for p in pkgs {
        if p.get("name").and_then(|n| n.as_str()) == Some("wasm-bindgen")
            && let Some(v) = p.get("version").and_then(|v| v.as_str())
        {
            return Ok(Some(v.to_string()));
        }
    }
    Ok(None)
}

/// Download the EXACT `wasm-bindgen` CLI release matching the crate version and install
/// it on the build PATH (`<cache>/bin/wasm-bindgen`) so the offline compile can run it.
/// The musl release is statically linked → runs on the Wolfi (glibc) toolchain. Fetched
/// through the egress proxy from github's release CDN (allow-listed). No build code runs.
fn provision_wasm_bindgen(ctx: &BuildContext, trunk_cache: &Path, version: &str) -> Result<()> {
    let cache_dir = trunk_cache.parent().unwrap_or(trunk_cache);
    let bin_dir = cache_dir.join("bin");
    let dest = bin_dir.join("wasm-bindgen");
    // Cross-build cache hit: already provisioned at the right version → skip the download.
    if version_matches(&dest, version) {
        return Ok(());
    }
    std::fs::create_dir_all(&bin_dir).with_context(|| format!("creating {}", bin_dir.display()))?;
    let asset = format!("wasm-bindgen-{version}-x86_64-unknown-linux-musl");
    let url =
        format!("https://github.com/rustwasm/wasm-bindgen/releases/download/{version}/{asset}.tar.gz");
    let tgz = cache_dir.join("wasm-bindgen-dl.tar.gz");

    // curl through the egress proxy (HTTPS_PROXY set by apply_proxy); -L follows the
    // github → release-CDN redirect, which the proxy re-checks against the allowlist.
    let mut dl = Command::new("curl");
    dl.env("PATH", BUILD_PATH);
    apply_proxy(&mut dl, ctx);
    dl.arg("-fSL").arg("--retry").arg("3").arg("-o").arg(&tgz).arg(&url);
    run(dl, "curl wasm-bindgen release")?;

    // Extract just the `wasm-bindgen` binary (tar-rs refuses path escapes); the archive
    // top dir is `<asset>/`, so match on the file name.
    extract_named(&tgz, "wasm-bindgen", &dest)
        .with_context(|| format!("extract wasm-bindgen from {}", tgz.display()))?;
    let _ = std::fs::remove_file(&tgz);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod {}", dest.display()))?;
    }
    Ok(())
}

/// True if `bin` exists and `bin --version` reports `version` (e.g. the line
/// `wasm-bindgen 0.2.95 (hash)`). Used to skip re-downloading a cached CLI.
fn version_matches(bin: &Path, version: &str) -> bool {
    if !bin.exists() {
        return false;
    }
    let Ok(out) = Command::new(bin).arg("--version").output() else {
        return false;
    };
    out.status.success()
        && String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .any(|t| t == version)
}

/// Extract the single archive entry whose file name is `filename` from a `.tar.gz` into
/// `dest` (streamed; no shell-out). Errors if the entry is absent.
fn extract_named(tgz: &Path, filename: &str, dest: &Path) -> Result<()> {
    let f = std::fs::File::open(tgz).with_context(|| format!("open {}", tgz.display()))?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    for entry in ar.entries().context("read tar entries")? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
            let mut out =
                std::fs::File::create(dest).with_context(|| format!("create {}", dest.display()))?;
            std::io::copy(&mut entry, &mut out).context("write extracted binary")?;
            return Ok(());
        }
    }
    anyhow::bail!("{filename} not found in {}", tgz.display())
}

/// A cargo `Command` with a deterministic build `PATH`, `CARGO_HOME` on the cache
/// drive, and the same git-CLI/sparse-registry settings the rust buildpack uses.
fn cargo_command(bin: &str, cargo_home: &Path, trunk_cache: &Path) -> Command {
    let mut cmd = Command::new(bin);
    apply_common_env(&mut cmd, cargo_home, trunk_cache);
    cmd
}

/// A `trunk` `Command` with the same env as cargo plus trunk's cache pointed at the
/// persistent cache drive (so its warmed wasm-bindgen/wasm-opt survive the seal).
fn trunk_command(cargo_home: &Path, trunk_cache: &Path) -> Command {
    let mut cmd = Command::new("trunk");
    apply_common_env(&mut cmd, cargo_home, trunk_cache);
    cmd
}

/// Shared build env for cargo + trunk: PATH, CARGO_HOME, sparse-registry + git-CLI
/// fetch, and the XDG/trunk cache dirs on the persistent cache drive. The cache `bin`
/// dir is prepended to PATH: fetch provisions the exact-version `wasm-bindgen` there,
/// and trunk (which resolves tools via PATH) picks it up during the offline compile.
fn apply_common_env(cmd: &mut Command, cargo_home: &Path, trunk_cache: &Path) {
    let bin = trunk_cache.parent().unwrap_or(trunk_cache).join("bin");
    cmd.env("PATH", format!("{}:{BUILD_PATH}", bin.display()))
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
        .env("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse")
        // trunk reads XDG_CACHE_HOME for its tool cache; also set the explicit
        // TRUNK_TOOLS_* / cache hints so a trunk that ignores XDG still warms here.
        .env("XDG_CACHE_HOME", trunk_cache)
        // A writable HOME on the cache drive (the toolchain root is read-only; some
        // tools write ~/.cache or ~/.cargo state).
        .env("HOME", trunk_cache);
}

/// Run a build subprocess, capturing its output so a failure surfaces the actual
/// tool error (cargo / trunk / wasm-bindgen) in the build log the tenant sees — not
/// just an exit code. Mirrors the rust/node buildpacks' `run`.
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

/// Apply the egress-proxy env vars (fetch phase only; `ctx.proxy` is `None` once
/// sealed). cargo honours `CARGO_HTTP_PROXY` + the standard `*_proxy` forms; trunk
/// downloads its tools over reqwest, which honours `HTTPS_PROXY`/`HTTP_PROXY`.
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
    fn detect_passes_on_trunk_toml_with_cargo() {
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        write(d.path(), "Trunk.toml", "[build]\n");
        let dec = detect_decision(d.path(), None);
        assert!(dec.is_pass());
        assert_eq!(dec.confidence(), 95);
    }

    #[test]
    fn detect_fails_on_bare_cargo_toml() {
        // A Cargo.toml WITHOUT a Trunk.toml is a server crate — the rust buildpack's
        // job, not trunk's. Trunk must not steal it.
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        assert!(!detect_decision(d.path(), None).is_pass());
    }

    #[test]
    fn detect_fails_on_trunk_toml_without_cargo() {
        let d = tempdir().unwrap();
        write(d.path(), "Trunk.toml", "[build]\n");
        assert!(!detect_decision(d.path(), None).is_pass());
    }

    #[test]
    fn explicit_trunk_hint_wins_and_foreign_hint_stands_down() {
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        write(d.path(), "Trunk.toml", "[build]\n");
        assert_eq!(detect_decision(d.path(), Some("trunk")).confidence(), 100);
        // A hint for another language makes trunk stand down even with a Trunk.toml.
        assert!(!detect_decision(d.path(), Some("rust")).is_pass());
        assert!(!detect_decision(d.path(), Some("node")).is_pass());
    }

    #[test]
    fn explicit_trunk_hint_passes_without_files() {
        // The host's lang_hint is authoritative even before the file sniff (matches the
        // node/rust buildpacks' `Some(lang) => 100` arm).
        let d = tempdir().unwrap();
        assert_eq!(detect_decision(d.path(), Some("trunk")).confidence(), 100);
    }

    #[test]
    fn dist_dir_defaults_and_reads_trunk_toml() {
        let d = tempdir().unwrap();
        // No Trunk.toml → default.
        assert_eq!(dist_dir(d.path()), "dist");
        // Empty [build] → default.
        write(d.path(), "Trunk.toml", "[build]\n");
        assert_eq!(dist_dir(d.path()), "dist");
        // Explicit dist (with a leading ./ trimmed).
        write(d.path(), "Trunk.toml", "[build]\ndist = \"./public\"\n");
        assert_eq!(dist_dir(d.path()), "public");
        // Malformed Trunk.toml falls back to the default (never fails here).
        write(d.path(), "Trunk.toml", "this is = = not toml");
        assert_eq!(dist_dir(d.path()), "dist");
    }

    #[test]
    fn move_tree_contents_relocates_bundle() {
        let d = tempdir().unwrap();
        let dist = d.path().join("dist");
        write(&dist, "index.html", "<html>");
        write(&dist, "app-abc123.js", "console.log(1)");
        write(&dist, "app-abc123_bg.wasm", "\0asm");
        write(&dist, "assets/logo.svg", "<svg>");

        let layer = d.path().join("layer/static");
        move_tree_contents(&dist, &layer).unwrap();

        // The bundle lands at the layer root (index.html at the served site root).
        assert_eq!(fs::read_to_string(layer.join("index.html")).unwrap(), "<html>");
        assert!(layer.join("app-abc123.js").exists());
        assert!(layer.join("app-abc123_bg.wasm").exists());
        assert_eq!(fs::read_to_string(layer.join("assets/logo.svg")).unwrap(), "<svg>");
        // The source dist entries were moved out.
        assert!(!dist.join("index.html").exists());
    }

    #[test]
    fn id_is_namespaced() {
        assert_eq!(TrunkBuildpack.id(), "jkbase/trunk");
    }
}
