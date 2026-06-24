//! The Rust buildpack — `cargo` over a glibc toolchain.
//!
//! detect keys off `Cargo.toml`; `fetch` runs `cargo fetch` (network up, via the
//! egress proxy) with `CARGO_HOME` on the per-project cache drive so the registry +
//! git caches survive across builds; `compile` runs `cargo build --release
//! --offline`, then ships the app tree (data files, models, seed DBs, config, an
//! entrypoint script — everything except `target/` and `.git`) plus the built
//! binary into the app layer rooted at `/app`; launch is the absolute binary path
//! (or a `command = [...]` override such as an entrypoint script).
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

        // App layer rooted at /app: the app tree (assets + an entrypoint) plus the
        // built binary.
        let default_bin = choose_default(&bins, preferred_bin(ctx.app_dir).as_deref());
        let app_layer_root = ctx.layers_dir.join("app");
        let app_at = app_layer_root.join("app");
        assemble_app_layer(ctx.app_dir, &app_at, &bins)?;

        // Ship the binaries' native-lib closure (libstdc++, libssl/libcrypto, libz,
        // … — whatever the app's native crates dynamically link) into the layer's
        // /usr/lib, so a Rust app with C/C++ FFI deps runs WITHOUT polluting the
        // SHARED rust runtime layer. ABI-matched by construction: these ARE the build
        // toolchain's libs the binary linked against. glibc + libgcc_s come from the
        // base layer and are deliberately NOT shipped (shipping them would shadow base
        // and risk version skew).
        ship_native_lib_closure(&app_at, &bins, &app_layer_root.join("usr").join("lib"))?;

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
    // Defer to the Trunk buildpack when the tree is a Rust/WASM frontend: a trunk
    // project also carries a Cargo.toml, but Trunk.toml means it builds to a static
    // `dist/`, not a server binary. Stand down so the two never collide (the trunk
    // buildpack claims it at confidence 95). Mirrors node deferring to bun.
    if app_dir.join("Trunk.toml").exists() {
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

/// Ship the app's tree + the built binaries into `app_at` (the layer's `/app`).
///
/// Overlayfs can't relocate a lowerdir, so the runtime content must physically live
/// at `/app`. We ship the whole app tree — data files, models, seed DBs, templates,
/// config, an entrypoint script — alongside the binary, mirroring how the node
/// buildpack ships its tree. A real Rust service routinely reads baked assets at
/// runtime; a binary-only image would be missing them, and an entrypoint script
/// would have nowhere to live. Only build artifacts (`target/`, gigabytes) and VCS
/// metadata (`.git`) are excluded — never needed at runtime. With the tree shipped,
/// `command = ["/app/entrypoint.sh"]` (base ships `/bin/sh`) can seed a writable
/// `[volumes]` mount, export env, then exec the binary.
///
/// Pure filesystem ops (no cargo), so it is unit-testable.
fn assemble_app_layer(app_dir: &Path, app_at: &Path, bins: &[(String, PathBuf)]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(app_at)
        .with_context(|| format!("creating app layer dir {}", app_at.display()))?;
    // Move every top-level entry except the build/VCS dirs into /app (cheap same-fs
    // rename; both are on /scratch). Permissions, symlinks, and a committed-executable
    // entrypoint are preserved.
    const EXCLUDE: &[&str] = &["target", ".git"];
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
    // Place the built binaries (they live under the excluded `target/`). A binary
    // whose name collides with a shipped file overwrites it with the executable.
    for (_name, src) in bins {
        let fname = src
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("binary path has no filename: {}", src.display()))?;
        let dest = app_at.join(fname);
        let _ = std::fs::remove_file(&dest);
        std::fs::copy(src, &dest)
            .with_context(|| format!("copy binary {} -> {}", src.display(), dest.display()))?;
        let mut perm = std::fs::metadata(&dest)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&dest, perm)?;
    }
    Ok(())
}

/// Sonames provided by the shared BASE layer (the glibc closure + `libgcc_s` from
/// the `ld-linux` package). These must NOT be shipped in the app layer — shipping a
/// glibc `.so` would shadow base's and risk a version skew.
fn is_base_lib(soname: &str) -> bool {
    const BASE: &[&str] = &[
        "libc.so", "libm.so", "libdl.so", "libpthread.so", "librt.so", "libresolv.so",
        "libnsl.so", "libutil.so", "libcrypt.so", "libanl.so", "libnss_", "libgcc_s.so",
        "ld-linux", "linux-vdso",
    ];
    BASE.iter().any(|b| soname.starts_with(b))
}

/// Parse one `ldd` output line into `(soname, resolved-path)`. Returns `None` for
/// the loader line, the vDSO, and `not found`/unresolved entries.
/// e.g. `\tlibssl.so.3 => /usr/lib/libssl.so.3 (0x00007f…)` → `("libssl.so.3","/usr/lib/libssl.so.3")`.
fn parse_ldd_line(line: &str) -> Option<(&str, &str)> {
    let (soname, rest) = line.trim().split_once(" => ")?;
    let path = rest.split(" (").next().unwrap_or("").trim();
    if path.is_empty() || path == "not found" {
        return None;
    }
    Some((soname.trim(), path))
}

/// Read a dynamic ELF's `PT_INTERP` (the dynamic linker the binary uses). `None`
/// for a static binary or a malformed/foreign ELF. 64-bit little-endian only (our
/// only build target); a different arch just falls back to the fixed loader paths.
fn read_pt_interp(bin: &Path) -> Option<String> {
    let data = std::fs::read(bin).ok()?;
    // ELF64, little-endian (e_ident: magic + EI_CLASS=2 + EI_DATA=1).
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return None;
    }
    let rd_u16 = |o: usize| -> Option<usize> {
        Some(u16::from_le_bytes(data.get(o..o + 2)?.try_into().ok()?) as usize)
    };
    let rd_u32 = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
    };
    let rd_u64 = |o: usize| -> Option<usize> {
        Some(u64::from_le_bytes(data.get(o..o + 8)?.try_into().ok()?) as usize)
    };
    let e_phoff = rd_u64(0x20)?;
    let e_phentsize = rd_u16(0x36)?;
    let e_phnum = rd_u16(0x38)?;
    for i in 0..e_phnum {
        let ph = e_phoff + i * e_phentsize;
        if rd_u32(ph)? == 3 {
            // PT_INTERP: p_offset @ +8, p_filesz @ +32.
            let off = rd_u64(ph + 8)?;
            let sz = rd_u64(ph + 32)?;
            let raw = data.get(off..(off + sz).min(data.len()))?;
            let s = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// The dynamic-lib trace for `bin` in ldd's text format. Wolfi's minimal glibc ships
/// NO `ldd` script, but the dynamic linker has a `--list` mode that does the same;
/// invoke the binary's own `PT_INTERP` loader (then fixed fallbacks). `--list` lists
/// deps WITHOUT running the binary (safe for a hostile/server binary), and reports
/// "not a dynamic executable" for a static one.
fn lib_trace(bin: &Path) -> Vec<String> {
    if let Ok(out) = std::process::Command::new("ldd").arg(bin).output()
        && (out.status.success() || String::from_utf8_lossy(&out.stdout).contains(" => "))
    {
        return String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect();
    }
    let mut loaders: Vec<String> = Vec::new();
    if let Some(interp) = read_pt_interp(bin) {
        loaders.push(interp);
    }
    loaders.push("/lib/ld-linux-x86-64.so.2".into());
    loaders.push("/usr/lib/ld-linux-x86-64.so.2".into());
    for loader in loaders {
        if !Path::new(&loader).exists() {
            continue;
        }
        if let Ok(out) = std::process::Command::new(&loader).arg("--list").arg(bin).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains(" => ") || text.contains("not a dynamic") {
                return text.lines().map(String::from).collect();
            }
        }
    }
    Vec::new()
}

/// Ship each binary's non-base dynamic-lib closure into `lib_dir` (the layer's
/// `/usr/lib`), so a Rust app with C/C++ FFI deps runs without polluting the SHARED
/// rust runtime layer. The trace is transitive, so one pass per binary captures the
/// full closure (libstdc++ → its own deps, etc.). A static binary or an empty trace
/// ships nothing — that is correct, not an error. Runs inside the sealed build VM on
/// the tenant's own binary, within the existing VM trust boundary.
fn ship_native_lib_closure(app_at: &Path, bins: &[(String, PathBuf)], lib_dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut shipped: std::collections::BTreeSet<String> = Default::default();
    for (name, _) in bins {
        let bin = app_at.join(name);
        for line in lib_trace(&bin) {
            let Some((soname, path)) = parse_ldd_line(&line) else {
                continue;
            };
            if is_base_lib(soname) {
                continue; // base layer provides it; don't shadow
            }
            if !shipped.insert(soname.to_string()) {
                continue; // already shipped (shared across binaries)
            }
            // Copy the fully-resolved real file under the soname the binary NEEDs, so
            // the runtime linker finds it via the default /usr/lib search.
            let real = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
            std::fs::create_dir_all(lib_dir)
                .with_context(|| format!("create app lib dir {}", lib_dir.display()))?;
            let dest = lib_dir.join(soname);
            std::fs::copy(&real, &dest)
                .with_context(|| format!("ship native lib {soname} from {}", real.display()))?;
            let mut perm = std::fs::metadata(&dest)?.permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&dest, perm)?;
        }
    }
    if !shipped.is_empty() {
        eprintln!(
            "jkbuild: shipped native-lib closure into /usr/lib: {}",
            shipped.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
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
    fn detect_defers_to_trunk() {
        // A Cargo.toml + Trunk.toml is a Rust/WASM frontend — the trunk buildpack's
        // job. Rust stands down even though it sees the Cargo.toml.
        let d = tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        write(d.path(), "Trunk.toml", "[build]\n");
        assert!(!detect_decision(d.path(), None).is_pass());
        // An explicit rust hint still claims it (operator override).
        assert_eq!(detect_decision(d.path(), Some("rust")).confidence(), 100);
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
    fn assemble_app_layer_ships_assets_and_binary_excludes_build_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let app = d.path().join("workspace");
        // A realistic tree: source, a committed entrypoint, a data asset, plus the
        // build dir and VCS metadata that must NOT ship.
        write(&app, "Cargo.toml", "[package]\nname=\"svc\"\n");
        write(&app, "src/main.rs", "fn main() {}");
        write(&app, "data/seed.txt", "asset-payload");
        write(&app, "entrypoint.sh", "#!/bin/sh\nexec /app/svc\n");
        write(&app, "target/release/junk", "build artifact");
        write(&app, ".git/config", "[core]");
        // The built binary lives under the excluded target/ (cargo reports its path).
        write(&app, "target/release/svc", "\x7fELF-binary");
        let bins = vec![("svc".to_string(), app.join("target/release/svc"))];

        let app_at = d.path().join("layer/app");
        assemble_app_layer(&app, &app_at, &bins).unwrap();

        // Assets + source + entrypoint shipped.
        assert_eq!(fs::read_to_string(app_at.join("data/seed.txt")).unwrap(), "asset-payload");
        assert!(app_at.join("src/main.rs").exists());
        assert!(app_at.join("Cargo.toml").exists());
        assert!(app_at.join("entrypoint.sh").exists());
        // Binary placed + executable.
        assert!(app_at.join("svc").exists());
        assert_eq!(fs::metadata(app_at.join("svc")).unwrap().permissions().mode() & 0o111, 0o111);
        // Build artifacts + VCS metadata excluded.
        assert!(!app_at.join("target").exists(), "target/ must not ship");
        assert!(!app_at.join(".git").exists(), ".git must not ship");
    }

    #[test]
    fn parse_ldd_line_extracts_soname_and_path() {
        assert_eq!(
            parse_ldd_line("\tlibssl.so.3 => /usr/lib/libssl.so.3 (0x00007f1234)"),
            Some(("libssl.so.3", "/usr/lib/libssl.so.3"))
        );
        assert_eq!(
            parse_ldd_line("\tlibstdc++.so.6 => /usr/lib/libstdc++.so.6 (0x00007fabcd)"),
            Some(("libstdc++.so.6", "/usr/lib/libstdc++.so.6"))
        );
        // loader + vDSO (no " => ") and unresolved entries are skipped.
        assert_eq!(parse_ldd_line("\t/lib/ld-linux-x86-64.so.2 (0x00007f0000)"), None);
        assert_eq!(parse_ldd_line("\tlinux-vdso.so.1 (0x00007ffd)"), None);
        assert_eq!(parse_ldd_line("\tlibfoo.so.1 => not found"), None);
    }

    #[test]
    fn base_libs_excluded_native_libs_shipped() {
        // glibc closure + libgcc_s + loader come from the base layer (don't ship).
        for b in [
            "libc.so.6", "libm.so.6", "libgcc_s.so.1", "libpthread.so.0",
            "ld-linux-x86-64.so.2", "linux-vdso.so.1",
        ] {
            assert!(is_base_lib(b), "{b} should be base-provided");
        }
        // native-FFI libs are shipped per-app into the app layer's /usr/lib.
        for n in [
            "libstdc++.so.6", "libssl.so.3", "libcrypto.so.3", "libz.so.1",
            "libzstd.so.1", "libonnxruntime.so",
        ] {
            assert!(!is_base_lib(n), "{n} should be shipped");
        }
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
