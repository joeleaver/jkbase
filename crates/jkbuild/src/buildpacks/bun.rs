//! The Bun buildpack.
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

/// Directory holding the baked bun binary.
const BUN_DIR: &str = "/opt/bun/bin";

/// A bun `Command` with `/opt/bun/bin` on `PATH`. The build VM's default `PATH`
/// does not include it, so a script run via `bun run build` that re-invokes a bare
/// `bun` (e.g. a monorepo `bun run --filter '*' build`, or any nested `bun` in a
/// package script) would otherwise fail with "command not found". We run bun by its
/// absolute path, but its CHILDREN inherit `PATH` — so it must carry the bun dir.
fn bun_command() -> Command {
    let mut cmd = Command::new(BUN_BIN);
    cmd.env(
        "PATH",
        format!("{BUN_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    );
    cmd
}

pub struct BunBuildpack;

impl Buildpack for BunBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/bun"
    }

    fn detect(&self, ctx: &DetectContext) -> Decision {
        // An explicit Dockerfile build claims the tree; language buildpacks stand
        // down so a repo with both a Dockerfile and a package.json builds the
        // Dockerfile the user asked for.
        if ctx.builder_hint == Some("dockerfile") {
            return Decision::Fail;
        }
        detect_decision(ctx.app_dir, ctx.language_hint)
    }

    fn fetch(&self, ctx: &mut BuildContext) -> Result<()> {
        // Bun's global install cache → the per-project cache drive, so a warm
        // cache survives across builds.
        let bun_cache = ctx.cache_dir.join("bun");
        std::fs::create_dir_all(&bun_cache).ok();

        // 1. Full install — the build (compile) needs the dev deps (vite, etc.).
        let mut cmd = bun_command();
        cmd.arg("install");
        // `--frozen-lockfile` requires a lockfile to exist; only enforce it when
        // one is present (a lockfile-less project still installs reproducibly
        // enough offline since the seal forbids drift).
        if has_lockfile(ctx.app_dir) {
            cmd.arg("--frozen-lockfile");
        }
        cmd.current_dir(ctx.app_dir)
            .env("BUN_INSTALL_CACHE_DIR", &bun_cache);
        apply_proxy(&mut cmd, ctx);
        let status = cmd
            .status()
            .with_context(|| format!("spawning `{BUN_BIN} install`"))?;
        if !status.success() {
            anyhow::bail!("bun install failed: {status}");
        }

        // 2. Pre-stage a PRODUCTION-only node_modules now, while the network is up,
        //    for the offline compile to swap in — so the runtime app layer doesn't
        //    carry dev/build tooling. We can't prune offline post-seal (bun can't
        //    reinstall from a proxy-warmed cache without the network), so we build the
        //    production tree here instead. No-op when there are no devDependencies.
        if has_dev_dependencies(ctx.app_dir) {
            stage_production_modules(ctx, &bun_cache)?;
        }
        Ok(())
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        // Offline (post-seal): run an optional build script. Network is gone, so
        // a `bun run build` that tries to fetch will fail here by design.
        if has_build_script(ctx.app_dir) {
            let status = bun_command()
                .arg("run")
                .arg("build")
                .current_dir(ctx.app_dir)
                .status()
                .with_context(|| format!("spawning `{BUN_BIN} run build`"))?;
            if !status.success() {
                anyhow::bail!("bun run build failed: {status}");
            }
        }

        // Lean runtime layer: swap the full (dev-incl.) node_modules the build needed
        // for the PRODUCTION-only tree the fetch phase pre-staged network-up, so the
        // app layer carries only production deps + the build output — not vite/test/
        // playwright/typescript tooling, which can dwarf the actual app.
        swap_in_production_modules(ctx)?;

        // May be empty when no start script / server entrypoint is derivable (e.g. a
        // monorepo whose start lives in a workspace). That is NOT fatal here: the host
        // can supply a `command = [...]` override from jkbase.toml — which the
        // in-VM buildpack can't see — and fails the deploy with a clear error there if
        // neither a derived nor an overridden command exists.
        let command = resolve_launch_command(ctx.app_dir).unwrap_or_default();

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

/// True when the app declares any `devDependencies` — the only case where pruning
/// to production actually shrinks the layer.
fn has_dev_dependencies(app_dir: &Path) -> bool {
    read_package_json(app_dir)
        .and_then(|pkg| {
            pkg.get("devDependencies")
                .and_then(|d| d.as_object())
                .map(|o| !o.is_empty())
        })
        .unwrap_or(false)
}

/// Apply the egress-proxy env vars (fetch phase only; `ctx.proxy` is `None` once the
/// network is sealed). Bun honours the standard proxy vars for registry.npmjs.org.
fn apply_proxy(cmd: &mut Command, ctx: &BuildContext) {
    if let Some(proxy) = &ctx.proxy {
        cmd.env("HTTP_PROXY", proxy)
            .env("HTTPS_PROXY", proxy)
            .env("http_proxy", proxy)
            .env("https_proxy", proxy);
        // Bun honours NODE_EXTRA_CA_CERTS; trust the mirror CA explicitly if baked.
        crate::buildpack::apply_mirror_ca(cmd);
    }
}

/// Sibling dir (next to the workspace, on the same scratch fs) holding the
/// pre-staged production `node_modules`. Both fetch and compile derive it identically.
fn prod_modules_dir(ctx: &BuildContext) -> std::path::PathBuf {
    ctx.app_dir.parent().unwrap_or(ctx.app_dir).join("jkbuild-prod-modules")
}

fn full_modules_dir(ctx: &BuildContext) -> std::path::PathBuf {
    ctx.app_dir.parent().unwrap_or(ctx.app_dir).join("jkbuild-full-modules")
}

/// Build a PRODUCTION-only `node_modules` while the network is up (fetch phase), so
/// the offline compile can swap it into the app layer. Runs the production install
/// **in-place in the real workspace** — NOT in an isolated dir — because a Bun
/// workspace monorepo (`"workspaces": [...]`) needs its member package.jsons present
/// or `bun install --production` aborts with `Workspace not found`. We rename the
/// full tree aside (it's needed for the offline build), do a clean production
/// install, save that, then restore the full tree. The cache is already warm from
/// the full install, so both moves + the reinstall are fast. (Bun hoists deps to the
/// root `node_modules`, so managing the root tree captures the bulk; member dirs are
/// symlinks/.bin.)
fn stage_production_modules(ctx: &BuildContext, bun_cache: &Path) -> Result<()> {
    let app_nm = ctx.app_dir.join("node_modules");
    let full_save = full_modules_dir(ctx);
    let prod_save = prod_modules_dir(ctx);
    let _ = std::fs::remove_dir_all(&full_save);
    let _ = std::fs::remove_dir_all(&prod_save);

    // 1. Set the full (dev-incl.) tree aside for the offline build.
    if app_nm.exists() {
        std::fs::rename(&app_nm, &full_save).context("save full node_modules")?;
    }
    // 2. Clean production install IN-PLACE (workspace members present → resolves).
    let mut cmd = bun_command();
    cmd.arg("install").arg("--production");
    if has_lockfile(ctx.app_dir) {
        cmd.arg("--frozen-lockfile");
    }
    cmd.current_dir(ctx.app_dir).env("BUN_INSTALL_CACHE_DIR", bun_cache);
    apply_proxy(&mut cmd, ctx);
    let status = cmd
        .status()
        .with_context(|| format!("spawning `{BUN_BIN} install --production` (in-place)"))?;
    if !status.success() {
        // Restore the full tree so the build can still proceed (degraded: a bloated
        // but correct layer) rather than leaving the workspace with no node_modules.
        if full_save.exists() && !app_nm.exists() {
            let _ = std::fs::rename(&full_save, &app_nm);
        }
        anyhow::bail!("production install failed: {status}");
    }
    // 3. Save the production tree, then restore the full tree for the build.
    if app_nm.exists() {
        std::fs::rename(&app_nm, &prod_save).context("save production node_modules")?;
    }
    if full_save.exists() {
        std::fs::rename(&full_save, &app_nm).context("restore full node_modules")?;
    }
    Ok(())
}

/// Swap the pre-staged production `node_modules` into the workspace, replacing the
/// full (dev-incl.) tree the build used. `prod_modules_dir` IS the saved production
/// `node_modules` (renamed aside during fetch). No-op when nothing was staged.
fn swap_in_production_modules(ctx: &BuildContext) -> Result<()> {
    let prod_save = prod_modules_dir(ctx);
    if !prod_save.exists() {
        return Ok(());
    }
    let app_nm = ctx.app_dir.join("node_modules");
    let _ = std::fs::remove_dir_all(&app_nm);
    std::fs::rename(&prod_save, &app_nm)
        .with_context(|| format!("swap production node_modules into {}", app_nm.display()))?;
    Ok(())
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
