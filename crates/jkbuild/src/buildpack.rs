//! The in-process `Buildpack` contract.
//!
//! Shape cribbed from `heroku/libcnb.rs` (Buildpack API ~0.10) — a `detect` that
//! claims a source tree and a build that produces layers + launch processes — but
//! WITHOUT libcnb's external protocol (no `buildpack.toml`, no `bin/detect`/
//! `bin/build` executables, no `/dev/fd` build-plan exchange, no exit-code detect
//! contract). We own both sides, so our buildpacks are ordinary Rust types and
//! the driver calls them directly.
//!
//! The seal is a hard, host-enforced wall-clock event, so the build splits into
//! two explicit methods: [`Buildpack::fetch`] (network up, via the egress proxy)
//! and [`Buildpack::compile`] (offline). That makes the network boundary
//! unambiguous and forces every buildpack author to be honest about what touches
//! the network.

use crate::env::BuildEnv;
use anyhow::Result;
use jkbuild_types::LayerRole;
use std::path::{Path, PathBuf};

/// Where the cross-tenant build-mirror CA cert is baked into a build toolchain (when
/// the mirror is active; see jkbase-server's `build_ca`). cargo/git/bun-on-Linux read
/// the OpenSSL system store (`ca-certificates.crt`, which the bake also appends the CA
/// to), but Node-family tools ignore it — so node/bun additionally point
/// `NODE_EXTRA_CA_CERTS` here. Absent when the mirror is dormant: then this is a no-op
/// and TLS trust falls back to the baked public-CA bundle.
pub const BUILD_MIRROR_CA_PATH: &str = "/etc/ssl/certs/jkbase-build-ca.crt";

/// Trust the baked build-mirror CA for Node-family package managers, if present. Call
/// only in a networked fetch phase (the CA is irrelevant offline). No-op when the file
/// is absent, so dormant-mirror and offline builds are unaffected.
pub fn apply_mirror_ca(cmd: &mut std::process::Command) {
    if Path::new(BUILD_MIRROR_CA_PATH).exists() {
        cmd.env("NODE_EXTRA_CA_CERTS", BUILD_MIRROR_CA_PATH);
    }
}

/// Outcome of [`Buildpack::detect`]. `confidence` (0–100) lets the driver resolve
/// ambiguous trees (e.g. a bare `package.json`): a higher-confidence buildpack
/// wins. An explicit `language=` hint should yield max confidence.
pub enum Decision {
    Pass { confidence: u8 },
    Fail,
}

impl Decision {
    pub fn pass(confidence: u8) -> Self {
        Decision::Pass { confidence }
    }
    pub fn is_pass(&self) -> bool {
        matches!(self, Decision::Pass { .. })
    }
    pub fn confidence(&self) -> u8 {
        match self {
            Decision::Pass { confidence } => *confidence,
            Decision::Fail => 0,
        }
    }
}

/// Read-only inputs to [`Buildpack::detect`].
pub struct DetectContext<'a> {
    /// The application source root (`/src` in the VM).
    pub app_dir: &'a Path,
    /// Optional `language=` hint from `jkbase.toml`, passed in via the kernel
    /// cmdline (`jkbase.lang=`). An explicit hint overrides heuristic detection.
    pub language_hint: Option<&'a str>,
    /// Explicit build strategy from `jkbase.toml` (`jkbase.builder=`):
    /// `Some("dockerfile")` forces the Dockerfile escape hatch (and language
    /// buildpacks must stand down); `None`/`Some("auto")` = normal buildpack
    /// detection.
    pub builder_hint: Option<&'a str>,
}

/// Mutable context threaded through [`Buildpack::fetch`] and
/// [`Buildpack::compile`]. The driver advances `offline`/`proxy` across the seal.
pub struct BuildContext<'a> {
    /// The build target's source dir — where detect matched and the build runs (the
    /// buildpack's working dir + launch dir). For a monorepo `context` this is the
    /// MEMBER subdir; equals [`Self::workspace_root`] for a normal build.
    pub app_dir: &'a Path,
    /// The build CONTEXT root: the whole mounted/copied tree. Equals `app_dir` for a
    /// normal build; for a monorepo `context` it's the WIDER workspace root, and
    /// `app_dir` is a member subdir within it. Interpreted-language buildpacks
    /// (bun/node) install + ship from HERE — package managers hoist `node_modules` to
    /// the workspace root and sibling package SOURCE lives above `app_dir`, so neither
    /// is reachable from `app_dir` alone. Compiled buildpacks (rust/go) ignore it: the
    /// sibling is linked into the self-contained artifact.
    pub workspace_root: &'a Path,
    /// Where the buildpack creates its layer directories (under the writable
    /// overlay root). Each becomes a content-addressed layer at export.
    pub layers_dir: &'a Path,
    /// Per-project persistent cache (`/cache`, the `vde` drive) — e.g. the Bun
    /// global install store. Survives across builds; never exported.
    pub cache_dir: &'a Path,
    /// Accumulated build/launch environment.
    pub env: BuildEnv,
    /// Egress proxy URL during the fetch phase (`None` once sealed / offline).
    pub proxy: Option<String>,
    /// Dockerfile path relative to `app_dir` for `builder = "dockerfile"`
    /// (`jkbase.dockerfile=`). `None` → the buildpack defaults to `Dockerfile`.
    pub dockerfile: Option<String>,
}

impl BuildContext<'_> {
    /// The install/ship ROOT: [`Self::workspace_root`] when `app_dir` is a member
    /// subdir of a monorepo `context`, else `app_dir` itself. node_modules (hoisted to
    /// the workspace root), the production-prune dance, and the shipped `/app` tree are
    /// all rooted here; the LAUNCH (start script + working dir) stays at `app_dir`.
    /// Equals `app_dir` for a normal build, so the non-monorepo path is byte-identical.
    pub fn root_dir(&self) -> &Path {
        if self.app_dir != self.workspace_root && self.app_dir.starts_with(self.workspace_root) {
            self.workspace_root
        } else {
            self.app_dir
        }
    }

    /// `app_dir` relative to [`Self::root_dir`] — empty for a normal build, the member
    /// subpath (e.g. `server`) for a monorepo member. Drives the launch working dir.
    pub fn member_subpath(&self) -> &Path {
        self.app_dir
            .strip_prefix(self.root_dir())
            .unwrap_or_else(|_| Path::new(""))
    }
}

/// What a buildpack's build produces. The exporter turns this into `/out`.
#[derive(Default)]
pub struct BuildOutput {
    pub layers: Vec<Layer>,
    /// Launch process types; the exporter picks the default (or `web`) → the
    /// `ServerManifest.cmd`.
    pub processes: Vec<Process>,
    /// Launch-time environment → `ServerManifest.env`.
    pub env: std::collections::BTreeMap<String, String>,
    /// Launch working directory → `ServerManifest.working_dir`.
    pub working_dir: Option<String>,
}

/// A populated layer directory plus its semantics.
pub struct Layer {
    pub name: String,
    /// Directory whose contents become the layer.
    pub path: PathBuf,
    pub types: LayerTypes,
    /// Role in the runtime overlay stack (only `launch` layers are exported).
    pub role: LayerRole,
}

/// libcnb-style layer semantics.
#[derive(Clone, Copy, Default)]
pub struct LayerTypes {
    /// Available to later buildpacks' build environment.
    pub build: bool,
    /// Part of the runtime artifact (exported as a content-addressed layer).
    pub launch: bool,
    /// Persisted into the per-project cache, not the launch artifact.
    pub cache: bool,
}

/// A launch process type (libcnb `Process`).
pub struct Process {
    pub r#type: String,
    /// argv; `command[0]` MUST be absolute (the runtime chroots + clears env).
    pub command: Vec<String>,
    pub default: bool,
}

/// A language buildpack. Implementations are ordinary Rust types registered in
/// [`crate::buildpacks::registry`].
pub trait Buildpack {
    /// Stable id, e.g. `"jkbase/bun"`.
    fn id(&self) -> &'static str;
    /// Does this buildpack claim `ctx.app_dir`?
    fn detect(&self, ctx: &DetectContext) -> Decision;
    /// Network-up phase: resolve + fetch dependencies through the egress proxy.
    fn fetch(&self, ctx: &mut BuildContext) -> Result<()>;
    /// Offline phase: compile, assemble layers, declare launch processes.
    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(app: &'a Path, root: &'a Path) -> BuildContext<'a> {
        BuildContext {
            app_dir: app,
            workspace_root: root,
            layers_dir: Path::new("/layers"),
            cache_dir: Path::new("/cache"),
            env: BuildEnv::new(),
            proxy: None,
            dockerfile: None,
        }
    }

    #[test]
    fn root_dir_and_member_subpath() {
        // Normal build (workspace_root == app_dir): root is the app, member empty —
        // bun/node behave byte-identically to before this field existed.
        let c = ctx(Path::new("/scratch/workspace"), Path::new("/scratch/workspace"));
        assert_eq!(c.root_dir(), Path::new("/scratch/workspace"));
        assert_eq!(c.member_subpath(), Path::new(""));

        // Monorepo member: app under the wider workspace root → root is the workspace,
        // member is the subpath (where launch/working-dir lands).
        let c = ctx(
            Path::new("/scratch/workspace/server"),
            Path::new("/scratch/workspace"),
        );
        assert_eq!(c.root_dir(), Path::new("/scratch/workspace"));
        assert_eq!(c.member_subpath(), Path::new("server"));

        // Nested member.
        let c = ctx(
            Path::new("/scratch/workspace/crates/api"),
            Path::new("/scratch/workspace"),
        );
        assert_eq!(c.root_dir(), Path::new("/scratch/workspace"));
        assert_eq!(c.member_subpath(), Path::new("crates/api"));
    }
}
