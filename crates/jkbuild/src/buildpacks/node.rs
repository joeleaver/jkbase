//! The Node.js buildpack — npm / pnpm / yarn.
//!
//! Detect keys off `package.json` + the lockfile, which also picks the package
//! manager (`pnpm-lock.yaml` → pnpm, `yarn.lock` → yarn, else npm). `fetch` runs
//! the PM install (network up, through the egress proxy) with the PM cache on the
//! per-project cache drive; `compile` runs an optional build script offline and
//! prunes dev dependencies; launch derives a DIRECT, absolute `node` command.
//!
//! Why a direct `node` command and not `npm run start`: the shared runtime layer
//! ships only the `node` binary closure, NOT npm/pnpm/yarn — those live in the
//! build toolchain image, not at runtime. So the launch must resolve to
//! `/usr/bin/node <entry>`; a project whose start is not auto-derivable supplies a
//! `command = [...]` override in jkbase.toml (the host applies it, same as bun).
//!
//! Layer split mirrors bun: the app layer carries source + production
//! `node_modules` + build output (rooted at `/app`); `node` comes from the shared
//! per-language RUNTIME layer; both stack over the shared Wolfi base (glibc). A
//! Node-version bump re-ships only the runtime layer, never the base — dedup holds.

use crate::buildpack::{
    BuildContext, BuildOutput, Buildpack, Decision, DetectContext, Layer, LayerTypes, Process,
};
use anyhow::{Context, Result};
use jkbuild_types::LayerRole;
use std::path::Path;
use std::process::Command;

/// Absolute path to the node binary inside the runtime layer. MUST be absolute:
/// the runtime chroots + clears the environment, and its launch `PATH` may not
/// include `/usr/bin`, so `cmd[0]` has to be the full path.
pub const NODE_BIN: &str = "/usr/bin/node";

/// Launch + build `PATH`: the runtime/toolchain `node` + the FHS bins, so a server
/// (or a build script) that spawns `node`/child tools resolves them. `node` is run
/// by absolute path, but its CHILDREN inherit `PATH`.
const NODE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The supported Node package managers, selected from the lockfile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
}

impl PackageManager {
    fn bin(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Yarn => "yarn",
        }
    }

    /// Sub-directory on the persistent cache drive for this PM's global cache/store.
    fn cache_name(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Yarn => "yarn",
        }
    }

    /// Point the PM at a cache dir on the persistent cache drive (warm across builds).
    fn apply_cache(self, cmd: &mut Command, cache: &Path) {
        match self {
            PackageManager::Npm => {
                cmd.env("npm_config_cache", cache);
            }
            PackageManager::Pnpm => {
                cmd.env("PNPM_HOME", cache)
                    .env("npm_config_store_dir", cache.join("store"));
            }
            PackageManager::Yarn => {
                cmd.env("YARN_CACHE_FOLDER", cache);
            }
        }
    }

    /// Args for the FULL install (deps + devDeps — the build needs dev tooling).
    fn full_install_args(self, has_lock: bool) -> Vec<&'static str> {
        match self {
            PackageManager::Npm if has_lock => vec!["ci"],
            PackageManager::Npm => vec!["install"],
            PackageManager::Pnpm if has_lock => vec!["install", "--frozen-lockfile"],
            PackageManager::Pnpm => vec!["install"],
            // v1 `--frozen-lockfile` keeps the resolve deterministic; berry tolerates
            // it via the classic-flag shim. A lockfile-less project installs plainly.
            PackageManager::Yarn if has_lock => vec!["install", "--frozen-lockfile"],
            PackageManager::Yarn => vec!["install"],
        }
    }

    /// Args for the PRODUCTION-only install (network up, fetch phase) — feeds the
    /// prod-staging dance so the runtime app layer carries no dev tooling.
    fn prod_install_args(self, has_lock: bool) -> Vec<&'static str> {
        match self {
            PackageManager::Npm if has_lock => vec!["ci", "--omit=dev"],
            PackageManager::Npm => vec!["install", "--omit=dev"],
            PackageManager::Pnpm if has_lock => vec!["install", "--prod", "--frozen-lockfile"],
            PackageManager::Pnpm => vec!["install", "--prod"],
            // `--production` is the v1 prod-prune; keep the resolve deterministic with
            // `--frozen-lockfile` when a lockfile exists (same as the full install) so
            // the SHIPPED tree can't drift to a different graph than the audited one.
            PackageManager::Yarn if has_lock => vec!["install", "--production", "--frozen-lockfile"],
            PackageManager::Yarn => vec!["install", "--production"],
        }
    }
}

pub struct NodeBuildpack;

impl Buildpack for NodeBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/node"
    }

    fn detect(&self, ctx: &DetectContext) -> Decision {
        // An explicit Dockerfile build claims the tree; language buildpacks stand down.
        if ctx.builder_hint == Some("dockerfile") {
            return Decision::Fail;
        }
        detect_decision(ctx.app_dir, ctx.language_hint)
    }

    fn fetch(&self, ctx: &mut BuildContext) -> Result<()> {
        let pm = detect_pm(ctx.app_dir);
        let cache = ctx.cache_dir.join(pm.cache_name());
        std::fs::create_dir_all(&cache).ok();
        // A writable HOME for PM config/state (the toolchain root is read-only); on
        // the persistent cache drive so it survives across builds.
        let home = ctx.cache_dir.join("node-home");
        std::fs::create_dir_all(&home).ok();

        // 1. Full install — the build (compile) needs dev deps (bundlers, tsc, …).
        let mut cmd = node_command(pm.bin(), &home);
        for a in pm.full_install_args(has_lockfile(ctx.app_dir)) {
            cmd.arg(a);
        }
        cmd.current_dir(ctx.app_dir);
        pm.apply_cache(&mut cmd, &cache);
        apply_proxy(&mut cmd, ctx);
        run(cmd, &format!("{} install", pm.bin()))?;

        // 2. Pre-stage a PRODUCTION-only node_modules now, network up, for the offline
        //    compile to swap in — so the runtime app layer carries no dev tooling. We
        //    can't reinstall offline post-seal, so build the production tree here. No-op
        //    when there are no devDependencies (nothing to prune).
        if has_dev_dependencies(ctx.app_dir) {
            stage_production_modules(ctx, pm, &cache, &home)?;
        }
        Ok(())
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        let pm = detect_pm(ctx.app_dir);
        let home = ctx.cache_dir.join("node-home");

        // Offline (post-seal): run an optional build script. The network is gone, so a
        // build that tries to fetch fails here by design.
        if has_build_script(ctx.app_dir) {
            let mut cmd = node_command(pm.bin(), &home);
            cmd.arg("run").arg("build").current_dir(ctx.app_dir);
            run(cmd, &format!("{} run build", pm.bin()))?;
        }

        // Lean runtime layer: swap the full (dev-incl.) node_modules for the
        // production-only tree the fetch phase pre-staged network-up.
        swap_in_production_modules(ctx)?;

        // May be empty when no start is derivable — NOT fatal here: the host applies a
        // jkbase.toml `command = [...]` override (which the in-VM buildpack can't see)
        // and fails the deploy with a clear error if neither exists.
        let command = resolve_launch_command(ctx.app_dir).unwrap_or_default();

        let mut env = std::collections::BTreeMap::new();
        env.insert("NODE_ENV".to_string(), "production".to_string());
        // Children spawned by the server (`node`, native helpers) need `node` on PATH.
        env.insert("PATH".to_string(), NODE_PATH.to_string());

        // The app layer is the built source tree (+ production node_modules). `node`
        // and glibc come from the shared runtime/base layers, not here.
        //
        // Root the tree at /app (= working_dir): overlayfs cannot relocate a lowerdir,
        // so the content must PHYSICALLY live at /app inside the app layer image. Move
        // the workspace under <layers>/app/app (cheap same-fs rename; both on /scratch).
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

/// Detect whether this is a Node app, with a confidence the driver uses to resolve
/// ambiguity. A bun project (bun lockfile/`bunfig`/`packageManager: bun@`) is the
/// Bun buildpack's job — Node stands down so it never steals a bun tree.
pub fn detect_decision(app_dir: &Path, language_hint: Option<&str>) -> Decision {
    // An explicit hint is authoritative.
    if language_hint == Some("node") {
        return Decision::pass(100);
    }
    // Any other explicit language hint means "not me".
    if matches!(language_hint, Some(h) if h != "node") {
        return Decision::Fail;
    }
    // Defer to Bun when the tree is bun's (bun's detect claims these with confidence
    // >= ours, but be explicit so order/ties never matter).
    if is_bun_tree(app_dir) {
        return Decision::Fail;
    }
    if !app_dir.join("package.json").exists() {
        return Decision::Fail;
    }
    // A real Node lockfile is a strong signal; a bare package.json is weaker (but
    // still ours — bun already deferred above).
    if has_lockfile(app_dir) {
        Decision::pass(85)
    } else {
        Decision::pass(60)
    }
}

/// A tree that belongs to Bun (so Node defers). Mirrors the bun buildpack's own
/// markers; kept local so the two buildpacks don't couple at the type level.
fn is_bun_tree(app_dir: &Path) -> bool {
    if app_dir.join("bun.lockb").exists()
        || app_dir.join("bun.lock").exists()
        || app_dir.join("bunfig.toml").exists()
    {
        return true;
    }
    read_package_json(app_dir)
        .map(|pkg| {
            let pm_is_bun = pkg
                .get("packageManager")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("bun@"))
                .unwrap_or(false);
            let engines_bun = pkg.get("engines").and_then(|e| e.get("bun")).is_some();
            pm_is_bun || engines_bun
        })
        .unwrap_or(false)
}

/// Pick the package manager from the lockfile present (pnpm > yarn > npm). A bare
/// package.json defaults to npm.
fn detect_pm(app_dir: &Path) -> PackageManager {
    if app_dir.join("pnpm-lock.yaml").exists() {
        PackageManager::Pnpm
    } else if app_dir.join("yarn.lock").exists() {
        PackageManager::Yarn
    } else {
        PackageManager::Npm
    }
}

/// Resolve the launch argv. Precedence: a `start` script that is itself a bare
/// `node …` invocation (parsed to a direct argv) → entrypoint from `main`/`module`
/// → a conventional server entry file. Always absolute `cmd[0]` = [`NODE_BIN`].
/// Returns `None` if nothing usable is found (the host then requires a `command`
/// override — never an empty cmd, which would be substituted with `/bin/sh`).
pub fn resolve_launch_command(app_dir: &Path) -> Option<Vec<String>> {
    if let Some(pkg) = read_package_json(app_dir) {
        // A `"start": "node dist/index.js"` (the overwhelmingly common shape) is
        // safe to run directly — we can't run `npm run start` (npm isn't in the
        // runtime layer), but a bare-node start IS just a node invocation.
        if let Some(start) = pkg
            .get("scripts")
            .and_then(|s| s.get("start"))
            .and_then(|v| v.as_str())
            && let Some(argv) = parse_bare_node_command(start)
        {
            return Some(argv);
        }
        for key in ["main", "module"] {
            if let Some(entry) = pkg.get(key).and_then(|v| v.as_str())
                && !entry.is_empty()
            {
                return Some(vec![NODE_BIN.into(), entry.to_string()]);
            }
        }
    }
    for entry in [
        "server.js",
        "src/server.js",
        "index.js",
        "src/index.js",
        "dist/server.js",
        "dist/index.js",
        "build/index.js",
        "app.js",
    ] {
        if app_dir.join(entry).exists() {
            return Some(vec![NODE_BIN.into(), entry.to_string()]);
        }
    }
    None
}

/// Parse a start script that is a plain `node <args…>` invocation into a direct
/// argv rooted at [`NODE_BIN`]. Returns `None` for anything that delegates to a
/// package-manager bin (`next start`, `nest start`, `node --inspect`…with flags is
/// fine; a tool name is not). Conservative: only the literal `node` leader matches,
/// and only simple whitespace-split tokens (no shell operators).
fn parse_bare_node_command(script: &str) -> Option<Vec<String>> {
    let script = script.trim();
    // A package-manager `start` runs via `sh -c`, so the authored semantics include
    // quoting, globbing, comments, env-assignment, and substitution. We exec argv
    // DIRECTLY (no shell), so any token carrying shell-significant punctuation can't
    // be reproduced faithfully — bail (→ the caller falls through to the safe
    // entry-file heuristics / the `command =` override) rather than mis-split it
    // into a wrong argv. Only a plain `node <args…>` of bare tokens is accepted.
    const SHELL_META: &[char] = &[
        '&', '|', ';', '>', '<', '`', '$', '(', ')', // composition / redirection / subst
        '\'', '"', '\\', // quoting / escaping
        '#', // comment
        '*', '?', '[', ']', '{', '}', // globbing / brace expansion
        '~', '!', // home / history expansion
    ];
    if script.contains(SHELL_META) {
        return None;
    }
    let mut toks = script.split_whitespace();
    if toks.next()? != "node" {
        return None;
    }
    let mut argv = vec![NODE_BIN.to_string()];
    argv.extend(toks.map(str::to_string));
    // `node` with no script/eval would hang reading stdin — require at least one arg.
    if argv.len() < 2 {
        return None;
    }
    Some(argv)
}

/// Resolve a requested Node version from `engines.node` / `.nvmrc` /
/// `.node-version`. v1 bakes a single major, so this is validation input. Returns
/// the requested version string if any is declared.
pub fn resolve_node_version(app_dir: &Path) -> Option<String> {
    for f in [".nvmrc", ".node-version"] {
        if let Ok(s) = std::fs::read_to_string(app_dir.join(f)) {
            let v = s.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    read_package_json(app_dir)?
        .get("engines")
        .and_then(|e| e.get("node"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// A package-manager `Command` with a deterministic build `PATH` + a writable HOME.
fn node_command(bin: &str, home: &Path) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env("PATH", NODE_PATH).env("HOME", home);
    cmd
}

/// Run a build subprocess, capturing its output so a failure surfaces the actual
/// tool error (npm/pnpm/yarn) in the build log the tenant sees — not just an exit
/// code. The output is buffered in-VM and only the tail is kept on failure.
fn run(mut cmd: Command, what: &str) -> Result<()> {
    let out = cmd
        .output()
        .with_context(|| format!("spawning `{what}`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{what}` failed: {}\n--- output (tail) ---\n{}",
            out.status,
            output_tail(&out.stdout, &out.stderr)
        );
    }
    Ok(())
}

/// Last ~40 lines of combined stdout+stderr, line-based so it never slices a
/// multibyte char.
fn output_tail(stdout: &[u8], stderr: &[u8]) -> String {
    let mut combined = String::from_utf8_lossy(stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(stderr));
    let lines: Vec<&str> = combined.lines().collect();
    let start = lines.len().saturating_sub(40);
    lines[start..].join("\n")
}

fn read_package_json(app_dir: &Path) -> Option<serde_json::Value> {
    let raw = std::fs::read_to_string(app_dir.join("package.json")).ok()?;
    serde_json::from_str(&raw).ok()
}

fn has_lockfile(app_dir: &Path) -> bool {
    ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]
        .iter()
        .any(|f| app_dir.join(f).exists())
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

/// Apply the egress-proxy env vars (fetch phase only; `ctx.proxy` is `None` once
/// sealed). npm/pnpm/yarn all honour the standard proxy vars; npm also reads its
/// own `npm_config_*` forms.
fn apply_proxy(cmd: &mut Command, ctx: &BuildContext) {
    if let Some(proxy) = &ctx.proxy {
        cmd.env("HTTP_PROXY", proxy)
            .env("HTTPS_PROXY", proxy)
            .env("http_proxy", proxy)
            .env("https_proxy", proxy)
            .env("npm_config_proxy", proxy)
            .env("npm_config_https_proxy", proxy);
        // Node ignores the OpenSSL store, so trust the mirror CA explicitly if baked.
        crate::buildpack::apply_mirror_ca(cmd);
    }
}

/// Sibling dirs (next to the workspace, same scratch fs) holding the staged trees.
fn prod_modules_dir(ctx: &BuildContext) -> std::path::PathBuf {
    ctx.app_dir.parent().unwrap_or(ctx.app_dir).join("jkbuild-prod-modules")
}

fn full_modules_dir(ctx: &BuildContext) -> std::path::PathBuf {
    ctx.app_dir.parent().unwrap_or(ctx.app_dir).join("jkbuild-full-modules")
}

/// Build a PRODUCTION-only `node_modules` while the network is up (fetch phase), so
/// the offline compile can swap it into the app layer. Runs the production install
/// IN-PLACE in the real tree (workspace members present → monorepo installs
/// resolve): rename the full tree aside (the build still needs it), clean
/// production install, save that, restore the full tree. The cache is already warm,
/// so the moves + reinstall are fast.
fn stage_production_modules(
    ctx: &BuildContext,
    pm: PackageManager,
    cache: &Path,
    home: &Path,
) -> Result<()> {
    let app_nm = ctx.app_dir.join("node_modules");
    let full_save = full_modules_dir(ctx);
    let prod_save = prod_modules_dir(ctx);
    let _ = std::fs::remove_dir_all(&full_save);
    let _ = std::fs::remove_dir_all(&prod_save);

    // 1. Set the full (dev-incl.) tree aside for the offline build.
    if app_nm.exists() {
        std::fs::rename(&app_nm, &full_save).context("save full node_modules")?;
    }
    // 2. Clean production install IN-PLACE.
    let mut cmd = node_command(pm.bin(), home);
    for a in pm.prod_install_args(has_lockfile(ctx.app_dir)) {
        cmd.arg(a);
    }
    cmd.current_dir(ctx.app_dir);
    pm.apply_cache(&mut cmd, cache);
    apply_proxy(&mut cmd, ctx);
    let status = cmd
        .status()
        .with_context(|| format!("spawning `{} (production install)`", pm.bin()))?;
    if !status.success() {
        // Restore the full tree so the build can still proceed (degraded: a bloated
        // but correct layer) rather than leaving the tree with no node_modules.
        // `npm ci` deletes node_modules first and may leave a PARTIAL tree on
        // failure, so restore unconditionally (drop any partial, move the full back).
        if full_save.exists() {
            let _ = std::fs::remove_dir_all(&app_nm);
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

/// Swap the pre-staged production `node_modules` into the tree, replacing the full
/// (dev-incl.) tree the build used. No-op when nothing was staged.
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
    fn detect_passes_on_package_json_with_lockfile() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"name":"x"}"#);
        write(d.path(), "package-lock.json", "{}");
        let dec = detect_decision(d.path(), None);
        assert!(dec.is_pass());
        assert_eq!(dec.confidence(), 85);
    }

    #[test]
    fn detect_passes_low_on_bare_package_json() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"name":"x"}"#);
        let dec = detect_decision(d.path(), None);
        assert!(dec.is_pass());
        assert_eq!(dec.confidence(), 60);
    }

    #[test]
    fn detect_defers_to_bun() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"packageManager":"bun@1.1.34"}"#);
        write(d.path(), "bun.lock", "");
        assert!(!detect_decision(d.path(), None).is_pass());

        let d2 = tempdir().unwrap();
        write(d2.path(), "package.json", r#"{"engines":{"bun":">=1"}}"#);
        assert!(!detect_decision(d2.path(), None).is_pass());
    }

    #[test]
    fn detect_fails_without_package_json() {
        let d = tempdir().unwrap();
        write(d.path(), "yarn.lock", "");
        assert!(!detect_decision(d.path(), None).is_pass());
    }

    #[test]
    fn explicit_node_hint_wins_max_confidence() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"name":"x"}"#);
        let dec = detect_decision(d.path(), Some("node"));
        assert!(dec.is_pass());
        assert_eq!(dec.confidence(), 100);
    }

    #[test]
    fn other_language_hint_makes_node_stand_down() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"name":"x"}"#);
        assert!(!detect_decision(d.path(), Some("rust")).is_pass());
        assert!(!detect_decision(d.path(), Some("bun")).is_pass());
    }

    #[test]
    fn pm_detection_from_lockfile() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", "{}");
        assert_eq!(detect_pm(d.path()), PackageManager::Npm);
        write(d.path(), "yarn.lock", "");
        assert_eq!(detect_pm(d.path()), PackageManager::Yarn);
        write(d.path(), "pnpm-lock.yaml", "");
        // pnpm wins over yarn when both present (monorepos sometimes carry both).
        assert_eq!(detect_pm(d.path()), PackageManager::Pnpm);
    }

    #[test]
    fn install_args_track_lockfile_presence() {
        assert_eq!(PackageManager::Npm.full_install_args(true), vec!["ci"]);
        assert_eq!(PackageManager::Npm.full_install_args(false), vec!["install"]);
        assert_eq!(PackageManager::Npm.prod_install_args(true), vec!["ci", "--omit=dev"]);
        assert_eq!(
            PackageManager::Pnpm.full_install_args(true),
            vec!["install", "--frozen-lockfile"]
        );
        assert_eq!(PackageManager::Yarn.prod_install_args(false), vec!["install", "--production"]);
        assert_eq!(
            PackageManager::Yarn.prod_install_args(true),
            vec!["install", "--production", "--frozen-lockfile"]
        );
    }

    #[test]
    fn launch_parses_bare_node_start_script() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"scripts":{"start":"node dist/index.js"}}"#);
        assert_eq!(
            resolve_launch_command(d.path()),
            Some(vec![NODE_BIN.into(), "dist/index.js".into()])
        );
    }

    #[test]
    fn launch_rejects_non_node_start_and_falls_through() {
        let d = tempdir().unwrap();
        // `next start` is not a bare-node command; fall through to a conventional entry.
        write(d.path(), "package.json", r#"{"scripts":{"start":"next start"}}"#);
        write(d.path(), "server.js", "");
        assert_eq!(
            resolve_launch_command(d.path()),
            Some(vec![NODE_BIN.into(), "server.js".into()])
        );
    }

    #[test]
    fn launch_rejects_shell_composed_start() {
        // A start script with shell operators/expansion must NOT be parsed (we exec
        // argv directly, no shell) — bail so the caller falls through to a safe entry.
        assert_eq!(parse_bare_node_command("node a.js && node b.js"), None);
        assert_eq!(parse_bare_node_command("NODE_ENV=production node a.js"), None); // leader != node
        assert_eq!(parse_bare_node_command("node"), None); // no script ⇒ would hang
        // Quoting / comments / globs would be mis-split by naive whitespace tokenizing.
        assert_eq!(parse_bare_node_command("node \"my server.js\""), None);
        assert_eq!(parse_bare_node_command("node app.js # prod"), None);
        assert_eq!(parse_bare_node_command("node app.js --flag='a b'"), None);
        assert_eq!(parse_bare_node_command("node ./dist/*.js"), None);
        assert_eq!(parse_bare_node_command("node ~/app.js"), None);
        // Plain bare-token invocations (incl. `--flag=value` with no quotes) are fine.
        assert_eq!(
            parse_bare_node_command("node --enable-source-maps server.js"),
            Some(vec![NODE_BIN.into(), "--enable-source-maps".into(), "server.js".into()])
        );
        assert_eq!(
            parse_bare_node_command("node --max-old-space-size=512 dist/index.js"),
            Some(vec![NODE_BIN.into(), "--max-old-space-size=512".into(), "dist/index.js".into()])
        );
    }

    #[test]
    fn launch_prefers_main_then_entry_files() {
        let d = tempdir().unwrap();
        write(d.path(), "package.json", r#"{"main":"build/app.js"}"#);
        assert_eq!(
            resolve_launch_command(d.path()),
            Some(vec![NODE_BIN.into(), "build/app.js".into()])
        );

        let d2 = tempdir().unwrap();
        write(d2.path(), "src/index.js", "");
        assert_eq!(
            resolve_launch_command(d2.path()),
            Some(vec![NODE_BIN.into(), "src/index.js".into()])
        );
    }

    #[test]
    fn launch_cmd_is_absolute() {
        let d = tempdir().unwrap();
        write(d.path(), "index.js", "");
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
        write(d.path(), ".nvmrc", "20.11.0\n");
        assert_eq!(resolve_node_version(d.path()).as_deref(), Some("20.11.0"));

        let d2 = tempdir().unwrap();
        write(d2.path(), "package.json", r#"{"engines":{"node":">=20"}}"#);
        assert_eq!(resolve_node_version(d2.path()).as_deref(), Some(">=20"));
    }
}
