//! The Go buildpack — `go build` over the Go toolchain.
//!
//! detect keys off `go.mod`; `fetch` runs `go mod download` (network up, via the
//! egress proxy — modules come from `proxy.golang.org`, checksums from
//! `sum.golang.org`, both on the egress allowlist) with the module + build caches on
//! the per-project cache drive; `compile` runs `CGO_ENABLED=0 go build` to produce a
//! **statically-linked** binary, then ships the app tree (assets/templates/an
//! entrypoint) plus the binary into the app layer rooted at `/app`; launch is the
//! absolute binary path (or a `command = [...]` override).
//!
//! Linking model: the default here is `CGO_ENABLED=0`, which yields a fully static
//! binary needing NO shared libraries — so the Go RUNTIME layer is intentionally
//! near-empty (like rust's) and the binary runs on the shared base alone. cgo (a C
//! toolchain + dynamic glibc) is a deliberate future opt-in, not the default, keeping
//! the common case maximally portable and the layer plan uniform (`app:go-runtime:base`).

use crate::buildpack::{
    BuildContext, BuildOutput, Buildpack, Decision, DetectContext, Layer, LayerTypes, Process,
};
use anyhow::{Context, Result};
use jkbuild_types::LayerRole;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `PATH` for the go toolchain + its tools.
const BUILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub struct GoBuildpack;

impl Buildpack for GoBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/go"
    }

    fn detect(&self, ctx: &DetectContext) -> Decision {
        // An explicit Dockerfile build claims the tree; language buildpacks stand down.
        if ctx.builder_hint == Some("dockerfile") {
            return Decision::Fail;
        }
        detect_decision(ctx.app_dir, ctx.language_hint)
    }

    fn fetch(&self, ctx: &mut BuildContext) -> Result<()> {
        let (modcache, buildcache, gopath) = cache_dirs(ctx);
        for d in [&modcache, &buildcache, &gopath] {
            std::fs::create_dir_all(d).ok();
        }
        // Download the module graph through the proxy. go.sum (when present) makes this
        // checksum-verified; GOFLAGS=-mod=mod tolerates a missing go.sum on first fetch.
        let mut cmd = go_command(ctx, &modcache, &buildcache, &gopath);
        cmd.arg("mod").arg("download").arg("all");
        cmd.current_dir(ctx.app_dir);
        apply_proxy(&mut cmd, ctx);
        run(cmd, "go mod download")?;
        Ok(())
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        let (modcache, buildcache, gopath) = cache_dirs(ctx);
        // Build all main packages into a sibling bin dir (on the same scratch fs).
        // `-o <dir>/` (trailing slash) makes go emit one executable per main package,
        // named after its directory — handles a root `main.go` AND a `cmd/<name>`
        // layout + multi-binary modules, mirroring the rust buildpack's discovery.
        let bindir = ctx
            .app_dir
            .parent()
            .unwrap_or(ctx.app_dir)
            .join("jkbuild-go-bin");
        let _ = std::fs::remove_dir_all(&bindir);
        std::fs::create_dir_all(&bindir).context("create go bin dir")?;

        let mut cmd = go_command(ctx, &modcache, &buildcache, &gopath);
        // CGO off → a static binary that runs on base alone. -trimpath drops absolute
        // build paths (reproducible + no scratch-path leak). GOPROXY=off forces the
        // build offline — every module was fetched above, so a build that reaches for
        // the network fails here by design (parity with `cargo build --offline`).
        cmd.env("CGO_ENABLED", "0").env("GOPROXY", "off");
        cmd.arg("build")
            .arg("-trimpath")
            .arg("-o")
            .arg(format!("{}/", bindir.display()))
            .arg("./...");
        cmd.current_dir(ctx.app_dir);
        run(cmd, "go build")?;

        let bins = collect_binaries(&bindir)?;
        if bins.is_empty() {
            anyhow::bail!(
                "`go build ./...` produced no executable — a library-only module has \
                 nothing to run; add a `package main` with a `func main()` (e.g. main.go \
                 or cmd/<name>/main.go)"
            );
        }

        // App layer rooted at /app: the app tree (source + assets + an entrypoint) plus
        // the built binaries. The binary is static, so no runtime libs are shipped.
        let default_bin = choose_default(&bins, module_name(ctx.app_dir).as_deref());
        let app_layer_root = ctx.layers_dir.join("app");
        let app_at = app_layer_root.join("app");
        assemble_app_layer(ctx.app_dir, &app_at, &bins)?;

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

/// Detect whether this is a Go app. `go.mod` is the signal; a committed `go.sum`
/// raises confidence (checksum-verified, reproducible builds).
pub fn detect_decision(app_dir: &Path, language_hint: Option<&str>) -> Decision {
    if language_hint == Some("go") {
        return Decision::pass(100);
    }
    if matches!(language_hint, Some(h) if h != "go") {
        return Decision::Fail;
    }
    if !app_dir.join("go.mod").exists() {
        return Decision::Fail;
    }
    if app_dir.join("go.sum").exists() {
        Decision::pass(90)
    } else {
        Decision::pass(80)
    }
}

/// The cache directories on the per-project cache drive: GOMODCACHE (module
/// downloads), GOCACHE (build cache), GOPATH (tool/install root).
fn cache_dirs(ctx: &BuildContext) -> (PathBuf, PathBuf, PathBuf) {
    let root = ctx.cache_dir.join("go");
    (root.join("mod"), root.join("build"), root.join("path"))
}

/// The module path's last element — the conventional binary name for a root
/// `main.go`. `module github.com/acme/widget` → `widget`. `None` if unreadable.
pub fn module_name(app_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(app_dir.join("go.mod")).ok()?;
    for line in raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("module ") {
            let path = rest.trim().trim_matches('"');
            return path.rsplit('/').next().map(str::to_string).filter(|s| !s.is_empty());
        }
    }
    None
}

/// The executables `go build -o <dir>/` produced (name → path), sorted by name for a
/// deterministic default pick.
fn collect_binaries(bindir: &Path) -> Result<Vec<(String, PathBuf)>> {
    use std::os::unix::fs::PermissionsExt;
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let rd = match std::fs::read_dir(bindir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).context("read go bin dir"),
    };
    for entry in rd {
        let entry = entry?;
        let md = entry.metadata()?;
        // A regular, executable file.
        if md.is_file() && md.permissions().mode() & 0o111 != 0 {
            out.push((entry.file_name().to_string_lossy().into_owned(), entry.path()));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Pick the default launch binary: the module-name binary when present, else the only
/// one, else the first by name (deterministic; a `command = [...]` override can select
/// any other, since all built binaries are copied into the app layer).
fn choose_default(bins: &[(String, PathBuf)], module: Option<&str>) -> String {
    if let Some(m) = module
        && bins.iter().any(|(n, _)| n == m)
    {
        return m.to_string();
    }
    bins[0].0.clone()
}

/// Ship the app tree + the built binaries into `app_at` (the layer's `/app`). Mirrors
/// the rust buildpack: the whole tree ships (assets, templates, an entrypoint) so a Go
/// service that reads baked files at runtime finds them; only VCS metadata is excluded
/// (Go has no in-tree build dir — binaries went to the sibling bin dir, the module
/// cache lives on the cache drive). Pure filesystem ops, so it is unit-testable.
fn assemble_app_layer(app_dir: &Path, app_at: &Path, bins: &[(String, PathBuf)]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(app_at)
        .with_context(|| format!("creating app layer dir {}", app_at.display()))?;
    const EXCLUDE: &[&str] = &[".git"];
    for entry in std::fs::read_dir(app_dir)
        .with_context(|| format!("read app dir {}", app_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        if EXCLUDE.iter().any(|e| name.as_os_str() == std::ffi::OsStr::new(e)) {
            continue;
        }
        std::fs::rename(entry.path(), app_at.join(&name))
            .with_context(|| format!("ship {} into the app layer", entry.path().display()))?;
    }
    for (name, src) in bins {
        let dest = app_at.join(name);
        let _ = std::fs::remove_file(&dest);
        std::fs::copy(src, &dest)
            .with_context(|| format!("copy binary {} -> {}", src.display(), dest.display()))?;
        let mut perm = std::fs::metadata(&dest)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&dest, perm)?;
    }
    Ok(())
}

/// A `go` `Command` with a deterministic build `PATH` + caches on the cache drive.
/// `GOFLAGS=-mod=mod` lets `go mod download` populate go.sum on a first build; the
/// compile step pins `GOPROXY=off` to force offline.
fn go_command(_ctx: &BuildContext, modcache: &Path, buildcache: &Path, gopath: &Path) -> Command {
    let mut cmd = Command::new("go");
    cmd.env("PATH", BUILD_PATH)
        .env("GOMODCACHE", modcache)
        .env("GOCACHE", buildcache)
        .env("GOPATH", gopath)
        .env("GOFLAGS", "-mod=mod")
        // No telemetry/toolchain auto-download from a sealed/offline build VM.
        .env("GOTOOLCHAIN", "local")
        .env("GOTELEMETRY", "off");
    cmd
}

/// Run a build subprocess, capturing its output so a failure surfaces the actual
/// go error in the build log the tenant sees — not just an exit code.
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

/// Apply the egress-proxy env vars (fetch phase only). The go module proxy + sum DB
/// are plain HTTPS the proxy passes; the git CLI (for VCS-direct deps) honours
/// `http_proxy`/`https_proxy`.
fn apply_proxy(cmd: &mut Command, ctx: &BuildContext) {
    if let Some(proxy) = &ctx.proxy {
        cmd.env("HTTP_PROXY", proxy)
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
    fn detect_passes_on_go_mod() {
        let d = tempdir().unwrap();
        write(d.path(), "go.mod", "module x\n\ngo 1.22\n");
        assert_eq!(detect_decision(d.path(), None).confidence(), 80);
        write(d.path(), "go.sum", "");
        assert_eq!(detect_decision(d.path(), None).confidence(), 90);
    }

    #[test]
    fn detect_fails_without_go_mod_and_foreign_hint_stands_down() {
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        assert!(!detect_decision(d.path(), None).is_pass());
        write(d.path(), "go.mod", "module x\n");
        assert_eq!(detect_decision(d.path(), Some("go")).confidence(), 100);
        assert!(!detect_decision(d.path(), Some("rust")).is_pass());
    }

    #[test]
    fn module_name_takes_last_path_element() {
        let d = tempdir().unwrap();
        write(d.path(), "go.mod", "module github.com/acme/widget\n\ngo 1.22\n");
        assert_eq!(module_name(d.path()).as_deref(), Some("widget"));
        let d2 = tempdir().unwrap();
        write(d2.path(), "go.mod", "module standalone\n");
        assert_eq!(module_name(d2.path()).as_deref(), Some("standalone"));
    }

    #[test]
    fn choose_default_prefers_module_then_first() {
        let bins = vec![
            ("alpha".to_string(), PathBuf::from("/b/alpha")),
            ("widget".to_string(), PathBuf::from("/b/widget")),
        ];
        assert_eq!(choose_default(&bins, Some("widget")), "widget");
        // Module binary not among those built (e.g. only cmd/* mains) → first by name.
        assert_eq!(choose_default(&bins, Some("ghost")), "alpha");
        assert_eq!(choose_default(&bins, None), "alpha");
    }

    #[test]
    fn collect_binaries_picks_executables_only() {
        let d = tempdir().unwrap();
        let bindir = d.path().join("bin");
        write(&bindir, "server", "\x7fELF");
        write(&bindir, "worker", "\x7fELF");
        write(&bindir, "readme.txt", "not a binary");
        // Mark the ELF files executable; leave the text file non-exec.
        use std::os::unix::fs::PermissionsExt;
        for b in ["server", "worker"] {
            let p = bindir.join(b);
            let mut perm = fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            fs::set_permissions(&p, perm).unwrap();
        }
        let bins = collect_binaries(&bindir).unwrap();
        let names: Vec<&str> = bins.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["server", "worker"]); // sorted; readme.txt excluded
    }

    #[test]
    fn assemble_app_layer_ships_tree_and_binary_excludes_git() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let app = d.path().join("workspace");
        write(&app, "go.mod", "module svc\n");
        write(&app, "main.go", "package main\nfunc main(){}");
        write(&app, "templates/index.html", "<h1>hi</h1>");
        write(&app, ".git/config", "[core]");
        // The built binary lives in the sibling bin dir.
        let bindir = d.path().join("bin");
        write(&bindir, "svc", "\x7fELF-binary");
        let bins = vec![("svc".to_string(), bindir.join("svc"))];

        let app_at = d.path().join("layer/app");
        assemble_app_layer(&app, &app_at, &bins).unwrap();

        assert_eq!(fs::read_to_string(app_at.join("templates/index.html")).unwrap(), "<h1>hi</h1>");
        assert!(app_at.join("main.go").exists());
        assert!(app_at.join("svc").exists());
        assert_eq!(fs::metadata(app_at.join("svc")).unwrap().permissions().mode() & 0o111, 0o111);
        assert!(!app_at.join(".git").exists(), ".git must not ship");
    }
}
