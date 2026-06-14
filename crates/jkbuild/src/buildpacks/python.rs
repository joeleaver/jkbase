//! The Python buildpack — `pip` over a glibc CPython toolchain.
//!
//! detect keys off `requirements.txt` / `pyproject.toml` / `setup.py` / `Pipfile`.
//! `fetch` runs `pip install` (network up, through the egress proxy + mirror — both
//! `pypi.org` and `files.pythonhosted.org` are mirror hosts, so wheels dedup across
//! tenants) into a **vendored deps dir inside the app tree** (`.jkbase-deps`), so the
//! runtime imports them via `PYTHONPATH` with no venv path-coupling. `compile` ships
//! the whole app tree (source + the vendored deps + any assets/entrypoint) into the
//! app layer rooted at `/app`; launch is a direct `python <entry>` (or a
//! `command = [...]` override for console-script servers like gunicorn/uvicorn).
//!
//! Layer split mirrors node: the app layer carries source + `.jkbase-deps`; the
//! CPython interpreter comes from the shared per-language RUNTIME layer; both stack
//! over the shared Wolfi base (glibc). `pip` itself is build-time only — never in the
//! runtime layer — so the launch resolves to the absolute interpreter, not a
//! console-script wrapper, unless the app supplies a `command` override.

use crate::buildpack::{
    BuildContext, BuildOutput, Buildpack, Decision, DetectContext, Layer, LayerTypes, Process,
};
use anyhow::{Context, Result};
use jkbuild_types::LayerRole;
use std::path::Path;
use std::process::Command;

/// Absolute path to the CPython interpreter inside the runtime layer. MUST be
/// absolute: the runtime chroots + clears the environment, so `cmd[0]` has to be the
/// full path (the runtime layer ships `python3` at this canonical location).
pub const PYTHON_BIN: &str = "/usr/bin/python3";

/// Launch + build `PATH`: the runtime/toolchain `python3` + the FHS bins.
const PYTHON_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Where vendored dependencies are installed — a dir INSIDE the app tree, so it
/// ships in the app layer automatically and is importable at `/app/.jkbase-deps`.
const VENDOR_DIR: &str = ".jkbase-deps";

/// The system trust bundle (real roots; the build-mirror bake appends the mirror CA
/// here too). pip/requests use certifi by default, NOT the OpenSSL store, so we point
/// them here explicitly when the mirror is active so the MITM'd registry is trusted
/// while real PyPI still validates on tunnel-fallback.
const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

pub struct PythonBuildpack;

impl Buildpack for PythonBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/python"
    }

    fn detect(&self, ctx: &DetectContext) -> Decision {
        // An explicit Dockerfile build claims the tree; language buildpacks stand down.
        if ctx.builder_hint == Some("dockerfile") {
            return Decision::Fail;
        }
        detect_decision(ctx.app_dir, ctx.language_hint)
    }

    fn fetch(&self, ctx: &mut BuildContext) -> Result<()> {
        let install = install_source(ctx.app_dir);
        if matches!(install, InstallSource::None) {
            // No declared dependencies — a single-file app is valid; nothing to fetch.
            return Ok(());
        }
        let cache = ctx.cache_dir.join("pip");
        std::fs::create_dir_all(&cache).ok();
        // A writable HOME for pip config/state (the toolchain root is read-only).
        let home = ctx.cache_dir.join("python-home");
        std::fs::create_dir_all(&home).ok();
        // Install into the vendored dir inside the app tree (clean slate each build).
        let vendor = ctx.app_dir.join(VENDOR_DIR);
        let _ = std::fs::remove_dir_all(&vendor);

        let mut cmd = python_command(&home);
        cmd.arg("-m")
            .arg("pip")
            .arg("install")
            .arg("--no-input")
            .arg("--no-compile") // .pyc are regenerated at runtime; keep the layer lean + reproducible
            .arg("--target")
            .arg(&vendor);
        match install {
            InstallSource::Requirements => {
                cmd.arg("-r").arg("requirements.txt");
            }
            // pyproject.toml (PEP 517/621) or legacy setup.py: install the project
            // itself (which pulls its declared deps) into the vendored dir.
            InstallSource::Project => {
                cmd.arg(".");
            }
            InstallSource::None => unreachable!(),
        }
        cmd.current_dir(ctx.app_dir);
        cmd.env("PIP_CACHE_DIR", &cache);
        apply_proxy(&mut cmd, ctx);
        run(cmd, "pip install")?;
        Ok(())
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        // Nothing to compile for CPython — pip already vendored the deps in `fetch`.
        // (A future hook could run a declared build step; v1 keeps it to the install.)
        let command = resolve_launch_command(ctx.app_dir).unwrap_or_default();

        let mut env = std::collections::BTreeMap::new();
        // Import the vendored deps; the app's own modules resolve from the /app CWD.
        env.insert("PYTHONPATH".to_string(), format!("/app/{VENDOR_DIR}"));
        // Unbuffered stdout/stderr so logs stream promptly; no .pyc clutter on the RO root.
        env.insert("PYTHONUNBUFFERED".to_string(), "1".to_string());
        env.insert("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string());
        env.insert("PATH".to_string(), PYTHON_PATH.to_string());

        // App layer rooted at /app: the whole app tree (source + the vendored
        // `.jkbase-deps` + assets/entrypoint). The interpreter + glibc come from the
        // shared runtime/base layers, not here. Overlayfs cannot relocate a lowerdir,
        // so the content must PHYSICALLY live at /app — move the workspace under
        // <layers>/app/app (cheap same-fs rename; both on /scratch).
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

/// Detect whether this is a Python app, with a confidence the driver uses to resolve
/// ambiguity. The markers (`requirements.txt`, `pyproject.toml`, `setup.py`,
/// `Pipfile`) are Python-specific, so a strong signal; a bare entry file alone is not
/// claimed (too ambiguous).
pub fn detect_decision(app_dir: &Path, language_hint: Option<&str>) -> Decision {
    if language_hint == Some("python") {
        return Decision::pass(100);
    }
    if matches!(language_hint, Some(h) if h != "python") {
        return Decision::Fail;
    }
    // A real dependency manifest is the authoritative signal.
    if app_dir.join("requirements.txt").exists()
        || app_dir.join("pyproject.toml").exists()
        || app_dir.join("setup.py").exists()
        || app_dir.join("setup.cfg").exists()
        || app_dir.join("Pipfile").exists()
    {
        return Decision::pass(85);
    }
    Decision::Fail
}

/// Where pip should install from. `requirements.txt` wins (the common app shape);
/// otherwise a PEP 517 project (`pyproject.toml` / `setup.py` / `setup.cfg`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstallSource {
    Requirements,
    Project,
    None,
}

fn install_source(app_dir: &Path) -> InstallSource {
    if app_dir.join("requirements.txt").exists() {
        InstallSource::Requirements
    } else if app_dir.join("pyproject.toml").exists()
        || app_dir.join("setup.py").exists()
        || app_dir.join("setup.cfg").exists()
    {
        InstallSource::Project
    } else {
        InstallSource::None
    }
}

/// Resolve the launch argv: a direct, runnable `python <entry>` for the conventional
/// server entry files. WSGI/ASGI exposers (`wsgi.py`/`asgi.py`) are intentionally NOT
/// auto-run — they expose an `app` object for gunicorn/uvicorn rather than serving on
/// import, so those apps supply a `command = [...]` override. Returns `None` if
/// nothing runnable is found (the host then requires the override — never an empty
/// cmd, which would be substituted with `/bin/sh`). Always absolute `cmd[0]`.
pub fn resolve_launch_command(app_dir: &Path) -> Option<Vec<String>> {
    for entry in [
        "app.py",
        "main.py",
        "server.py",
        "run.py",
        "src/app.py",
        "src/main.py",
        "src/server.py",
    ] {
        if app_dir.join(entry).exists() {
            return Some(vec![PYTHON_BIN.into(), entry.to_string()]);
        }
    }
    None
}

/// A python `Command` with a deterministic build `PATH` + a writable HOME. We invoke
/// `python3 -m pip` (not the `pip` console script) so it works regardless of where the
/// toolchain placed the wrapper.
fn python_command(home: &Path) -> Command {
    let mut cmd = Command::new(PYTHON_BIN);
    cmd.env("PATH", PYTHON_PATH).env("HOME", home);
    cmd
}

/// Run a build subprocess, capturing its output so a failure surfaces the actual pip
/// error in the build log the tenant sees — not just an exit code.
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

/// Apply the egress-proxy env vars (fetch phase only; `ctx.proxy` is `None` once
/// sealed). pip honours the standard proxy vars; when the build-mirror CA is baked
/// into the toolchain, point pip/requests at the system bundle (which then carries the
/// mirror CA) so the MITM'd registry TLS is trusted while real PyPI still validates on
/// tunnel-fallback. Never disables verification.
fn apply_proxy(cmd: &mut Command, ctx: &BuildContext) {
    if let Some(proxy) = &ctx.proxy {
        cmd.env("HTTP_PROXY", proxy)
            .env("HTTPS_PROXY", proxy)
            .env("http_proxy", proxy)
            .env("https_proxy", proxy)
            .env("PIP_PROXY", proxy);
        // pip/requests use certifi, not the OpenSSL store; trust the mirror CA via the
        // system bundle only when it has actually been baked (mirror active).
        if Path::new(crate::buildpack::BUILD_MIRROR_CA_PATH).exists() {
            cmd.env("PIP_CERT", SYSTEM_CA_BUNDLE)
                .env("REQUESTS_CA_BUNDLE", SYSTEM_CA_BUNDLE)
                .env("SSL_CERT_FILE", SYSTEM_CA_BUNDLE);
        }
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
    fn detect_passes_on_requirements() {
        let d = tempdir().unwrap();
        write(d.path(), "requirements.txt", "flask\n");
        let dec = detect_decision(d.path(), None);
        assert!(dec.is_pass());
        assert_eq!(dec.confidence(), 85);
    }

    #[test]
    fn detect_passes_on_pyproject_and_setup() {
        let d = tempdir().unwrap();
        write(d.path(), "pyproject.toml", "[project]\nname='x'\n");
        assert!(detect_decision(d.path(), None).is_pass());
        let d2 = tempdir().unwrap();
        write(d2.path(), "setup.py", "from setuptools import setup\n");
        assert!(detect_decision(d2.path(), None).is_pass());
    }

    #[test]
    fn detect_fails_without_manifest() {
        let d = tempdir().unwrap();
        write(d.path(), "app.py", "print('hi')\n");
        // A bare entry file with no manifest is too ambiguous to claim.
        assert!(!detect_decision(d.path(), None).is_pass());
    }

    #[test]
    fn explicit_python_hint_wins_and_foreign_hint_stands_down() {
        let d = tempdir().unwrap();
        // Hint is authoritative even with no manifest.
        assert_eq!(detect_decision(d.path(), Some("python")).confidence(), 100);
        // A hint for another language makes Python stand down even with a manifest.
        write(d.path(), "requirements.txt", "flask\n");
        assert!(!detect_decision(d.path(), Some("node")).is_pass());
    }

    #[test]
    fn install_source_precedence() {
        let d = tempdir().unwrap();
        assert_eq!(install_source(d.path()), InstallSource::None);
        write(d.path(), "pyproject.toml", "[project]\nname='x'\n");
        assert_eq!(install_source(d.path()), InstallSource::Project);
        // requirements.txt wins over a project manifest (the common app shape).
        write(d.path(), "requirements.txt", "flask\n");
        assert_eq!(install_source(d.path()), InstallSource::Requirements);
    }

    #[test]
    fn launch_resolves_conventional_entries() {
        let d = tempdir().unwrap();
        write(d.path(), "main.py", "");
        assert_eq!(
            resolve_launch_command(d.path()),
            Some(vec![PYTHON_BIN.into(), "main.py".into()])
        );
        // app.py wins over main.py (precedence order).
        write(d.path(), "app.py", "");
        assert_eq!(
            resolve_launch_command(d.path()),
            Some(vec![PYTHON_BIN.into(), "app.py".into()])
        );
    }

    #[test]
    fn launch_none_for_wsgi_only_or_no_entry() {
        // A WSGI/ASGI exposer is not directly runnable → require a command override.
        let d = tempdir().unwrap();
        write(d.path(), "wsgi.py", "app = make_app()\n");
        write(d.path(), "requirements.txt", "gunicorn\n");
        assert_eq!(resolve_launch_command(d.path()), None);
    }

    #[test]
    fn launch_cmd_is_absolute() {
        let d = tempdir().unwrap();
        write(d.path(), "server.py", "");
        let cmd = resolve_launch_command(d.path()).unwrap();
        assert!(cmd[0].starts_with('/'), "cmd[0] must be absolute: {cmd:?}");
    }
}
