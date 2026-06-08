//! The Bun buildpack — the B2 lead language.
//!
//! Bun is the easiest target: a single self-contained glibc binary that is *also*
//! the package manager. detect keys off Bun's lockfiles/config; fetch runs
//! `bun install --frozen-lockfile` (network up, through the egress proxy) with
//! the global cache on the per-project cache drive; compile runs an optional
//! `bun run build` offline; launch derives an absolute `bun` command.
//!
//! The Bun binary itself is baked into the toolchain/base image at
//! [`BUN_BIN`] (not fetched), so it lives in the runtime/app layer and no
//! `bun.sh`/GitHub allowlist entry is needed — only `registry.npmjs.org`, which
//! the egress proxy already allows.

use crate::buildpack::{
    BuildContext, BuildOutput, Buildpack, Decision, DetectContext, Layer, LayerTypes, Process,
};
use anyhow::{Context, Result};
use jkbuild_types::LayerRole;
use std::path::Path;
use std::process::Command;

/// Absolute path to the baked Bun binary inside the build/runtime image. MUST be
/// absolute: the runtime chroots and clears the environment, and its `PATH` does
/// not include `/opt/bun/bin`, so the launch `cmd[0]` has to be absolute.
pub const BUN_BIN: &str = "/opt/bun/bin/bun";

pub struct BunBuildpack;

impl Buildpack for BunBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/bun"
    }

    fn detect(&self, ctx: &DetectContext) -> Decision {
        detect_decision(ctx.app_dir, ctx.language_hint)
    }

    fn fetch(&self, ctx: &mut BuildContext) -> Result<()> {
        // Bun's global install cache → the per-project cache drive, so a warm
        // cache survives across builds.
        let bun_cache = ctx.cache_dir.join("bun");
        std::fs::create_dir_all(&bun_cache).ok();

        let mut cmd = Command::new(BUN_BIN);
        cmd.arg("install");
        // `--frozen-lockfile` requires a lockfile to exist; only enforce it when
        // one is present (a lockfile-less project still installs reproducibly
        // enough offline since the seal forbids drift).
        if has_lockfile(ctx.app_dir) {
            cmd.arg("--frozen-lockfile");
        }
        cmd.current_dir(ctx.app_dir)
            .env("BUN_INSTALL_CACHE_DIR", &bun_cache);
        if let Some(proxy) = &ctx.proxy {
            // Bun honours the standard proxy env vars for registry.npmjs.org.
            cmd.env("HTTP_PROXY", proxy)
                .env("HTTPS_PROXY", proxy)
                .env("http_proxy", proxy)
                .env("https_proxy", proxy);
        }
        let status = cmd
            .status()
            .with_context(|| format!("spawning `{BUN_BIN} install`"))?;
        if !status.success() {
            anyhow::bail!("bun install failed: {status}");
        }
        Ok(())
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        // Offline (post-seal): run an optional build script. Network is gone, so
        // a `bun run build` that tries to fetch will fail here by design.
        if has_build_script(ctx.app_dir) {
            let status = Command::new(BUN_BIN)
                .arg("run")
                .arg("build")
                .current_dir(ctx.app_dir)
                .status()
                .with_context(|| format!("spawning `{BUN_BIN} run build`"))?;
            if !status.success() {
                anyhow::bail!("bun run build failed: {status}");
            }
        }

        let command = resolve_launch_command(ctx.app_dir).context(
            "could not determine a start command: add a `start` script to package.json \
             or a server entrypoint (server.ts/index.ts)",
        )?;

        let mut env = std::collections::BTreeMap::new();
        env.insert("NODE_ENV".to_string(), "production".to_string());

        // The app layer is the built source tree (+ node_modules). The Bun binary
        // and glibc come from the shared base/runtime layer, not here.
        //
        // Root the tree at /app (= working_dir): overlayfs cannot relocate a
        // lowerdir, so the app content must PHYSICALLY live at /app inside the app
        // layer image for the runtime overlay to land it there. Move the workspace
        // under <layers>/app/app (cheap same-fs rename; both are on /scratch).
        let app_layer_root = ctx.layers_dir.join("app");
        let app_at = app_layer_root.join("app");
        std::fs::create_dir_all(&app_layer_root)
            .with_context(|| format!("creating app layer root {}", app_layer_root.display()))?;
        std::fs::rename(ctx.app_dir, &app_at)
            .with_context(|| format!("rooting workspace at {}", app_at.display()))?;
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
                command,
                default: true,
            }],
            env,
            working_dir: Some("/app".to_string()),
        })
    }
}

/// Detect whether this is a Bun app, with a confidence the driver uses to resolve
/// ambiguity against other buildpacks (notably: a bare `package.json` with a
/// foreign lockfile must defer to Node, not claim Bun).
pub fn detect_decision(app_dir: &Path, language_hint: Option<&str>) -> Decision {
    // An explicit hint is authoritative (even over a foreign lockfile).
    if language_hint == Some("bun") {
        return Decision::pass(100);
    }
    if app_dir.join("bun.lockb").exists() || app_dir.join("bun.lock").exists() {
        return Decision::pass(90);
    }
    if app_dir.join("bunfig.toml").exists() {
        return Decision::pass(80);
    }
    // A bare package.json (npm/yarn/pnpm) is the Node buildpack's job.
    if let Some(pkg) = read_package_json(app_dir)
        && package_declares_bun(&pkg)
    {
        return Decision::pass(70);
    }
    Decision::Fail
}

/// Resolve the launch argv. Precedence: a `start` script → entrypoint from
/// `main`/`module` → a conventional server entry file. Always absolute `cmd[0]`.
/// Returns `None` if nothing usable is found (the caller errors — never an empty
/// cmd, which the host would substitute with `/bin/sh`).
pub fn resolve_launch_command(app_dir: &Path) -> Option<Vec<String>> {
    if let Some(pkg) = read_package_json(app_dir) {
        if pkg
            .get("scripts")
            .and_then(|s| s.get("start"))
            .and_then(|v| v.as_str())
            .is_some()
        {
            return Some(vec![BUN_BIN.into(), "run".into(), "start".into()]);
        }
        for key in ["module", "main"] {
            if let Some(entry) = pkg.get(key).and_then(|v| v.as_str())
                && !entry.is_empty()
            {
                return Some(vec![BUN_BIN.into(), entry.to_string()]);
            }
        }
    }
    for entry in [
        "server.ts",
        "src/server.ts",
        "index.ts",
        "src/index.ts",
        "server.js",
        "index.js",
    ] {
        if app_dir.join(entry).exists() {
            return Some(vec![BUN_BIN.into(), entry.to_string()]);
        }
    }
    None
}

/// Resolve a requested Bun version from `engines.bun` / `.bun-version` /
/// `packageManager`. v1 bakes a single version, so this is validation input (the
/// driver errors on a mismatch rather than silently building with the wrong
/// runtime). Returns the requested version string if any is declared.
pub fn resolve_bun_version(app_dir: &Path) -> Option<String> {
    if let Ok(s) = std::fs::read_to_string(app_dir.join(".bun-version")) {
        let v = s.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    let pkg = read_package_json(app_dir)?;
    if let Some(pm) = pkg.get("packageManager").and_then(|v| v.as_str())
        && let Some(rest) = pm.strip_prefix("bun@")
    {
        return Some(rest.to_string());
    }
    pkg.get("engines")
        .and_then(|e| e.get("bun"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn read_package_json(app_dir: &Path) -> Option<serde_json::Value> {
    let raw = std::fs::read_to_string(app_dir.join("package.json")).ok()?;
    serde_json::from_str(&raw).ok()
}

fn package_declares_bun(pkg: &serde_json::Value) -> bool {
    let pm_is_bun = pkg
        .get("packageManager")
        .and_then(|v| v.as_str())
        .map(|s| s.starts_with("bun@"))
        .unwrap_or(false);
    let engines_bun = pkg
        .get("engines")
        .and_then(|e| e.get("bun"))
        .is_some();
    pm_is_bun || engines_bun
}

fn has_lockfile(app_dir: &Path) -> bool {
    app_dir.join("bun.lock").exists() || app_dir.join("bun.lockb").exists()
}

fn has_build_script(app_dir: &Path) -> bool {
    read_package_json(app_dir)
        .and_then(|pkg| {
            pkg.get("scripts")
                .and_then(|s| s.get("build"))
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
        })
        .unwrap_or(false)
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
    fn detect_passes_on_bun_lockfiles() {
        let d = tempdir().unwrap();
        write(d.path(), "bun.lock", "");
        assert!(detect_decision(d.path(), None).is_pass());

        let d2 = tempdir().unwrap();
        write(d2.path(), "bun.lockb", "");
        assert!(detect_decision(d2.path(), None).is_pass());
    }

    #[test]
    fn detect_passes_on_bunfig_and_package_manager() {
        let d = tempdir().unwrap();
        write(d.path(), "bunfig.toml", "");
        assert!(detect_decision(d.path(), None).is_pass());

        let d2 = tempdir().unwrap();
        write(d2.path(), "package.json", r#"{"packageManager":"bun@1.1.34"}"#);
        assert!(detect_decision(d2.path(), None).is_pass());
    }

    #[test]
    fn detect_defers_bare_package_json_to_node() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"name":"x"}"#);
        write(d.path(), "package-lock.json", "{}");
        assert!(!detect_decision(d.path(), None).is_pass());
    }

    #[test]
    fn explicit_hint_overrides_even_with_foreign_lockfile() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"name":"x"}"#);
        write(d.path(), "yarn.lock", "");
        let dec = detect_decision(d.path(), Some("bun"));
        assert!(dec.is_pass());
        assert_eq!(dec.confidence(), 100);
    }

    #[test]
    fn launch_prefers_start_script_then_entry() {
        let d = tempdir().unwrap();
        write(
            d.path(),
            "package.json",
            r#"{"scripts":{"start":"bun server.ts"}}"#,
        );
        assert_eq!(
            resolve_launch_command(d.path()),
            Some(vec![BUN_BIN.into(), "run".into(), "start".into()])
        );

        let d2 = tempdir().unwrap();
        write(d2.path(), "package.json", r#"{"module":"app.ts"}"#);
        assert_eq!(
            resolve_launch_command(d2.path()),
            Some(vec![BUN_BIN.into(), "app.ts".into()])
        );

        let d3 = tempdir().unwrap();
        write(d3.path(), "src/index.ts", "");
        assert_eq!(
            resolve_launch_command(d3.path()),
            Some(vec![BUN_BIN.into(), "src/index.ts".into()])
        );
    }

    #[test]
    fn launch_cmd_is_absolute() {
        let d = tempdir().unwrap();
        write(d.path(), "index.ts", "");
        let cmd = resolve_launch_command(d.path()).unwrap();
        assert!(cmd[0].starts_with('/'), "cmd[0] must be absolute: {cmd:?}");
    }

    #[test]
    fn launch_none_when_no_entry() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"name":"x"}"#);
        assert_eq!(resolve_launch_command(d.path()), None);
    }

    #[test]
    fn version_resolution_precedence() {
        let d = tempdir().unwrap();
        write(d.path(), ".bun-version", "1.1.30\n");
        assert_eq!(resolve_bun_version(d.path()).as_deref(), Some("1.1.30"));

        let d2 = tempdir().unwrap();
        write(d2.path(), "package.json", r#"{"packageManager":"bun@1.1.34"}"#);
        assert_eq!(resolve_bun_version(d2.path()).as_deref(), Some("1.1.34"));

        let d3 = tempdir().unwrap();
        write(d3.path(), "package.json", r#"{"engines":{"bun":">=1.1"}}"#);
        assert_eq!(resolve_bun_version(d3.path()).as_deref(), Some(">=1.1"));
    }
}
