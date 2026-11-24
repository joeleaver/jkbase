//! Honour the app's own Rust toolchain pin (`rust-toolchain.toml` / `rust-toolchain`)
//! in the cargo-based buildpacks (`rust`, `trunk`).
//!
//! WHY honour the pin instead of only bumping the baked compiler: a toolchain image
//! bakes ONE rustc, so every app whose dependency tree needs a newer `rust-version`
//! than the bake would be undeployable until the platform rebakes — and an app pinned
//! to an OLDER release would silently build with a compiler it never tested. The pin
//! is the app's own statement of the compiler it needs (the same file rustup, CI and
//! every dev box already obey), so the builder obeys it too. An app with NO pin keeps
//! the baked toolchain, byte-for-byte unchanged, and needs no extra network.
//!
//! Threat model (all tenants untrusted; fetch-then-seal):
//!   * The toolchain is installed by the BAKED `rustup` in the network-up FETCH phase,
//!     from the official dist server only: `static.rust-lang.org` is the single host
//!     added to the egress allowlist, the dist/update roots are forced (never taken
//!     from the tenant), and rustup sha256-verifies every component against the
//!     channel manifest it fetched over TLS. The compile then runs sealed/offline and
//!     never invokes rustup — it runs the installed toolchain's own binaries.
//!   * The pin is parsed HERE, not by rustup, and only a strict grammar of official
//!     channels/targets/components is accepted. A `path = …` custom toolchain is
//!     refused: it would run a tenant-supplied "cargo" with the network up, outside
//!     the fetch phase's no-dependency-code invariant. rustup itself runs with its cwd
//!     on the cache drive, so it never reads the tenant's toolchain file.
//!   * The toolchain lives on the per-project cache drive, which the host keeps only
//!     AS CAPTURED AT THE SEAL (`persist_cache_from_seal`): what a later build's fetch
//!     runs was written by rustup in an earlier fetch, never by a dependency's offline
//!     `build.rs`. Toolchains the app no longer pins are uninstalled, so the cache
//!     doesn't grow per upgrade.

use crate::buildpack::BuildContext;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The build VM's host triple (glibc x86_64; the only build arch). rustup names an
/// installed channel `<channel>-<host>` under `$RUSTUP_HOME/toolchains`.
const HOST: &str = "x86_64-unknown-linux-gnu";
/// The baked rustup (Wolfi `rustup`, in the rust + trunk toolchain images).
const RUSTUP: &str = "/usr/bin/rustup";
/// The only dist server a pin may install from (on the egress allowlist).
const DIST_SERVER: &str = "https://static.rust-lang.org";
/// Bounds on what a pin may ask for (each target/component is a full download).
const MAX_EXTRAS: usize = 16;
const MAX_NAME_LEN: usize = 64;
/// The pin files rustup reads, in its precedence order within one directory.
const PIN_FILES: &[&str] = &["rust-toolchain", "rust-toolchain.toml"];

/// An app's validated toolchain pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pin {
    /// An official channel: `stable`/`beta`/`nightly` (optionally `-YYYY-MM-DD`) or a
    /// release `X.Y[.Z]` (optionally `-beta[.N]`).
    pub channel: String,
    pub targets: Vec<String>,
    pub components: Vec<String>,
    /// The pin file it came from (for build-log messages).
    pub file: PathBuf,
}

/// An installed toolchain's `bin/` dir: the compile prepends it to `PATH` and points
/// `RUSTC`/`RUSTDOC` at it, so cargo (and trunk, which runs cargo off `PATH`) use it
/// instead of the baked one.
#[derive(Debug, Clone)]
pub(super) struct Toolchain {
    bin: PathBuf,
}

impl Toolchain {
    pub fn cargo(&self) -> PathBuf {
        self.bin.join("cargo")
    }

    /// Point `cmd` at this toolchain: its `bin/` first on `base_path`, plus explicit
    /// `RUSTC`/`RUSTDOC` (cargo would otherwise resolve `rustc` off `PATH` anyway, but
    /// being explicit keeps a baked `/usr/bin/rustc` from ever being picked).
    pub fn apply(&self, cmd: &mut Command, base_path: &str) {
        cmd.env("PATH", format!("{}:{base_path}", self.bin.display()))
            .env("RUSTC", self.bin.join("rustc"))
            .env("RUSTDOC", self.bin.join("rustdoc"));
    }
}

/// FETCH-phase entry point for a cargo buildpack: provision the app's pinned
/// toolchain (plus `extra_targets` the buildpack itself needs) and return it, or
/// `None` when the app pins nothing and the baked toolchain applies.
pub(super) fn for_fetch(ctx: &BuildContext, extra_targets: &[&str]) -> Result<Option<Toolchain>> {
    match find_pin(ctx.app_dir, ctx.root_dir())? {
        Some(pin) => provision(&pin, extra_targets, &rustup_home(ctx), ctx.proxy.as_deref()).map(Some),
        None => Ok(None),
    }
}

/// COMPILE-phase counterpart of [`for_fetch`]: the same pin resolved to the toolchain
/// the fetch installed (sealed — no rustup, no network).
pub(super) fn for_compile(ctx: &BuildContext, extra_targets: &[&str]) -> Result<Option<Toolchain>> {
    match find_pin(ctx.app_dir, ctx.root_dir())? {
        Some(pin) => installed(&pin, extra_targets, &rustup_home(ctx)).map(Some),
        None => Ok(None),
    }
}

fn rustup_home(ctx: &BuildContext) -> PathBuf {
    ctx.cache_dir.join("rustup")
}

/// Find the app's pin: the nearest pin file from `app_dir` up to (and including)
/// `root`, the way rustup searches from the build's cwd. `None` = no pin (or a pin
/// file that names no channel), i.e. use the baked toolchain.
pub(super) fn find_pin(app_dir: &Path, root: &Path) -> Result<Option<Pin>> {
    let mut dir = Some(app_dir);
    while let Some(d) = dir {
        for name in PIN_FILES {
            let file = d.join(name);
            // symlink_metadata: a pin file that is a symlink could point anywhere in the
            // build VM; the tree is the tenant's own, but there's no reason to follow it.
            let Ok(meta) = std::fs::symlink_metadata(&file) else {
                continue;
            };
            if !meta.is_file() {
                bail!("{} must be a regular file", file.display());
            }
            if meta.len() > 64 * 1024 {
                bail!("{} is too large to be a toolchain file", file.display());
            }
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            return parse_pin(&text, &file, *name == "rust-toolchain");
        }
        if d == root {
            break;
        }
        dir = d.parent().filter(|p| p.starts_with(root));
    }
    Ok(None)
}

/// Parse + validate a pin file's text: TOML `[toolchain]`, or (only for the legacy
/// extension-less `rust-toolchain`, as rustup) a bare one-line channel.
fn parse_pin(text: &str, file: &Path, legacy_allowed: bool) -> Result<Option<Pin>> {
    let trimmed = text.trim();
    let legacy = legacy_allowed
        && !trimmed.is_empty()
        && !trimmed.contains('\n')
        && !trimmed.contains('=')
        && !trimmed.starts_with('[');
    let (channel, targets, components) = if legacy {
        (Some(trimmed.to_string()), Vec::new(), Vec::new())
    } else {
        let doc: toml::Value =
            toml::from_str(text).with_context(|| format!("parsing {}", file.display()))?;
        let Some(tc) = doc.get("toolchain") else {
            bail!("{} has no [toolchain] table", file.display());
        };
        if tc.get("path").is_some() {
            bail!(
                "{}: a custom `path` toolchain is not supported by the jkbase builder — \
                 pin an official `channel` instead",
                file.display()
            );
        }
        let channel = match tc.get("channel") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .with_context(|| format!("{}: `channel` must be a string", file.display()))?
                    .to_string(),
            ),
        };
        (
            channel,
            string_list(tc, "targets", file)?,
            string_list(tc, "components", file)?,
        )
    };
    let Some(channel) = channel else {
        // rustup would apply targets/components to its default toolchain; the baked
        // toolchain IS the builder's default, so there is nothing to provision.
        eprintln!(
            "jkbuild: {} names no channel — using the builder's baked Rust toolchain",
            file.display()
        );
        return Ok(None);
    };
    if !valid_channel(&channel) {
        bail!(
            "{}: unsupported toolchain channel {channel:?} — use stable, beta, nightly \
             (optionally -YYYY-MM-DD), or a release like \"1.99.0\" (no host triple)",
            file.display()
        );
    }
    Ok(Some(Pin {
        channel,
        targets,
        components,
        file: file.to_path_buf(),
    }))
}

fn string_list(tc: &toml::Value, key: &str, file: &Path) -> Result<Vec<String>> {
    let Some(v) = tc.get(key) else {
        return Ok(Vec::new());
    };
    let arr = v
        .as_array()
        .with_context(|| format!("{}: `{key}` must be a list of strings", file.display()))?;
    if arr.len() > MAX_EXTRAS {
        bail!("{}: at most {MAX_EXTRAS} `{key}` are supported", file.display());
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .with_context(|| format!("{}: `{key}` must be a list of strings", file.display()))?;
        if !valid_name(s) {
            bail!("{}: invalid {key} entry {s:?}", file.display());
        }
        out.push(s.to_string());
    }
    Ok(out)
}

/// `stable|beta|nightly[-YYYY-MM-DD]` or `X.Y[.Z][-beta[.N]]`. Deliberately narrower
/// than rustup (no host-triple suffix, no custom names): the builder's host is fixed,
/// and anything else would be a toolchain name rustup resolves outside the dist server.
fn valid_channel(c: &str) -> bool {
    if c.len() > MAX_NAME_LEN {
        return false;
    }
    let digits = |s: &str| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit());
    let date = |s: &str| {
        let p: Vec<&str> = s.split('-').collect();
        p.len() == 3
            && p[0].len() == 4
            && p[1].len() == 2
            && p[2].len() == 2
            && p.iter().all(|x| digits(x))
    };
    for named in ["stable", "beta", "nightly"] {
        if c == named {
            return true;
        }
        if let Some(rest) = c.strip_prefix(named).and_then(|r| r.strip_prefix('-')) {
            return date(rest);
        }
    }
    let (ver, pre) = match c.split_once('-') {
        Some((v, p)) => (v, Some(p)),
        None => (c, None),
    };
    let parts: Vec<&str> = ver.split('.').collect();
    let ver_ok = (2..=3).contains(&parts.len()) && parts.iter().all(|p| digits(p));
    let pre_ok = match pre {
        None => true,
        Some("beta") => true,
        Some(p) => p.strip_prefix("beta.").is_some_and(digits),
    };
    ver_ok && pre_ok
}

/// A rustup target/component name: lowercase alnum plus `-_.` (e.g.
/// `wasm32-unknown-unknown`, `rust-src`, `llvm-tools-preview`).
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
        && s.as_bytes()[0].is_ascii_alphanumeric()
}

/// The toolchain dir rustup installs `channel` into.
fn toolchain_dir(rustup_home: &Path, channel: &str) -> PathBuf {
    rustup_home.join("toolchains").join(format!("{channel}-{HOST}"))
}

/// The targets a build needs installed: the pin's plus the buildpack's own (e.g.
/// trunk's `wasm32-unknown-unknown`), deduplicated.
fn wanted_targets(pin: &Pin, extra_targets: &[&str]) -> Vec<String> {
    let mut t = pin.targets.clone();
    for e in extra_targets {
        if !t.iter().any(|x| x == e) {
            t.push((*e).to_string());
        }
    }
    t
}

/// FETCH phase (network up): install the pinned toolchain via the baked rustup into
/// `rustup_home` (on the cache drive), then uninstall any toolchain the app no longer
/// pins. An already-installed release channel is a fast no-op re-verify.
pub(super) fn provision(
    pin: &Pin,
    extra_targets: &[&str],
    rustup_home: &Path,
    proxy: Option<&str>,
) -> Result<Toolchain> {
    std::fs::create_dir_all(rustup_home)
        .with_context(|| format!("creating {}", rustup_home.display()))?;
    eprintln!(
        "jkbuild: {} pins Rust {} — installing it via rustup",
        pin.file.display(),
        pin.channel
    );
    // A download an earlier, interrupted fetch left behind would make rustup resume it
    // with a Range request; start every install from clean scratch instead.
    for scratch in ["downloads", "tmp"] {
        let _ = std::fs::remove_dir_all(rustup_home.join(scratch));
    }
    let mut cmd = rustup_command(rustup_home);
    cmd.args(["toolchain", "install", &pin.channel])
        .args(["--profile", "minimal", "--no-self-update"]);
    for t in wanted_targets(pin, extra_targets) {
        cmd.args(["--target", &t]);
    }
    for c in &pin.components {
        cmd.args(["--component", c]);
    }
    if let Some(p) = proxy {
        cmd.env("HTTPS_PROXY", p)
            .env("https_proxy", p)
            .env("HTTP_PROXY", p)
            .env("http_proxy", p);
    }
    super::rust::run(cmd, &format!("rustup toolchain install {}", pin.channel))?;
    let tc = installed(pin, extra_targets, rustup_home)?;
    prune_other_toolchains(pin, rustup_home);
    Ok(tc)
}

/// COMPILE phase (sealed): the toolchain `provision` installed. Never runs rustup —
/// fails clearly if the fetch didn't leave a complete toolchain behind.
pub(super) fn installed(pin: &Pin, extra_targets: &[&str], rustup_home: &Path) -> Result<Toolchain> {
    let dir = toolchain_dir(rustup_home, &pin.channel);
    let bin = dir.join("bin");
    for tool in ["cargo", "rustc"] {
        if !bin.join(tool).is_file() {
            bail!(
                "Rust {} (pinned by {}) is not installed: {} is missing",
                pin.channel,
                pin.file.display(),
                bin.join(tool).display()
            );
        }
    }
    for t in wanted_targets(pin, extra_targets) {
        if !dir.join("lib/rustlib").join(&t).is_dir() {
            bail!("Rust {} is missing the `{t}` target std", pin.channel);
        }
    }
    Ok(Toolchain { bin })
}

/// Uninstall every toolchain except the pinned one (offline; best-effort — a leftover
/// only costs cache-drive space, never correctness).
fn prune_other_toolchains(pin: &Pin, rustup_home: &Path) {
    let keep = format!("{}-{HOST}", pin.channel);
    let Ok(entries) = std::fs::read_dir(rustup_home.join("toolchains")) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name == keep {
            continue;
        }
        let mut cmd = rustup_command(rustup_home);
        cmd.args(["toolchain", "uninstall", &name]);
        match cmd.output() {
            Ok(o) if o.status.success() => eprintln!("jkbuild: removed unpinned toolchain {name}"),
            _ => eprintln!("jkbuild: could not remove unpinned toolchain {name} (left in cache)"),
        }
    }
}

/// A rustup `Command` pinned to the official dist server with its state on the cache
/// drive. cwd is the rustup home (never the app dir) so rustup can't pick up the
/// tenant's toolchain file or a `RUSTUP_TOOLCHAIN` override on its own.
fn rustup_command(rustup_home: &Path) -> Command {
    let mut cmd = Command::new(RUSTUP);
    cmd.env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", rustup_home)
        .env("RUSTUP_HOME", rustup_home)
        .env("CARGO_HOME", rustup_home.join("cargo-home"))
        .env("RUSTUP_DIST_SERVER", DIST_SERVER)
        .env("RUSTUP_UPDATE_ROOT", format!("{DIST_SERVER}/rustup"))
        .env("RUSTUP_TERM_COLOR", "never")
        .env("RUSTUP_TERM_PROGRESS_WHEN", "never")
        .current_dir(rustup_home);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn pin_of(text: &str) -> Result<Option<Pin>> {
        parse_pin(text, Path::new("rust-toolchain.toml"), false)
    }

    #[test]
    fn parses_toml_pin_with_targets_and_components() {
        let p = pin_of(
            "[toolchain]\nchannel = \"1.99.0\"\ncomponents = [\"rustfmt\", \"clippy\"]\n\
             targets = [\"wasm32-unknown-unknown\"]\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(p.channel, "1.99.0");
        assert_eq!(p.components, ["rustfmt", "clippy"]);
        assert_eq!(p.targets, ["wasm32-unknown-unknown"]);
    }

    #[test]
    fn parses_legacy_one_line_pin() {
        let p = parse_pin("nightly-2026-10-01\n", Path::new("rust-toolchain"), true)
            .unwrap()
            .unwrap();
        assert_eq!(p.channel, "nightly-2026-10-01");
        assert!(p.targets.is_empty());
        // The `.toml` file must be TOML: a bare channel line there is an error.
        assert!(pin_of("1.99.0\n").is_err());
    }

    #[test]
    fn no_channel_means_baked_toolchain() {
        assert_eq!(pin_of("[toolchain]\ntargets = [\"wasm32-unknown-unknown\"]\n").unwrap(), None);
    }

    #[test]
    fn refuses_path_toolchains_and_bad_channels() {
        assert!(pin_of("[toolchain]\npath = \"/src/evil\"\n").is_err());
        for bad in [
            "1.99.0-x86_64-unknown-linux-gnu",
            "my-custom",
            "../../etc",
            "1.99.0;rm",
            "nightly-2026-1-01",
            "1",
            "1.2.3.4",
            "",
        ] {
            let text = format!("[toolchain]\nchannel = {bad:?}\n");
            assert!(pin_of(&text).is_err(), "{bad:?} must be refused");
        }
        assert!(pin_of("[toolchain]\nchannel = \"1.99\"\ntargets = [\"--evil\"]\n").is_err());
        assert!(pin_of("[toolchain]\nchannel = \"1.99\"\ncomponents = [\"A\"]\n").is_err());
    }

    #[test]
    fn accepts_official_channel_shapes() {
        for ok in [
            "stable",
            "beta",
            "nightly",
            "nightly-2026-10-01",
            "beta-2026-10-01",
            "1.99",
            "1.99.0",
            "1.100.0-beta",
            "1.100.0-beta.3",
        ] {
            assert!(valid_channel(ok), "{ok:?} must be accepted");
        }
    }

    #[test]
    fn caps_the_number_of_extras() {
        let many: Vec<String> = (0..=MAX_EXTRAS).map(|i| format!("\"c{i}\"")).collect();
        let text = format!("[toolchain]\nchannel = \"1.99\"\ncomponents = [{}]\n", many.join(","));
        assert!(pin_of(&text).is_err());
    }

    #[test]
    fn find_pin_walks_up_to_the_context_root_only() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path();
        let root = outside.join("repo");
        let member = root.join("admin-web");
        fs::create_dir_all(&member).unwrap();
        // A pin ABOVE the context root is not part of the build tree: ignored.
        fs::write(outside.join("rust-toolchain"), "1.80.0").unwrap();
        assert_eq!(find_pin(&member, &root).unwrap(), None);
        fs::write(root.join("rust-toolchain.toml"), "[toolchain]\nchannel = \"1.99.0\"\n").unwrap();
        assert_eq!(find_pin(&member, &root).unwrap().unwrap().channel, "1.99.0");
        // The nearest file wins, and `rust-toolchain` beats `.toml` in one dir (rustup order).
        fs::write(member.join("rust-toolchain.toml"), "[toolchain]\nchannel = \"beta\"\n").unwrap();
        fs::write(member.join("rust-toolchain"), "nightly").unwrap();
        assert_eq!(find_pin(&member, &root).unwrap().unwrap().channel, "nightly");
    }

    #[test]
    fn find_pin_refuses_a_symlinked_pin() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("elsewhere"), "1.99.0").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("elsewhere"), tmp.path().join("rust-toolchain"))
            .unwrap();
        assert!(find_pin(tmp.path(), tmp.path()).is_err());
    }

    #[test]
    fn installed_requires_the_toolchain_and_every_target() {
        let tmp = tempdir().unwrap();
        let pin = pin_of("[toolchain]\nchannel = \"1.99.0\"\n").unwrap().unwrap();
        assert!(installed(&pin, &[], tmp.path()).is_err());
        let dir = toolchain_dir(tmp.path(), "1.99.0");
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin/cargo"), "").unwrap();
        fs::write(dir.join("bin/rustc"), "").unwrap();
        let tc = installed(&pin, &[], tmp.path()).unwrap();
        assert_eq!(tc.cargo(), dir.join("bin/cargo"));
        assert!(installed(&pin, &["wasm32-unknown-unknown"], tmp.path()).is_err());
        fs::create_dir_all(dir.join("lib/rustlib/wasm32-unknown-unknown")).unwrap();
        assert!(installed(&pin, &["wasm32-unknown-unknown"], tmp.path()).is_ok());
    }
}
