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
}

/// Mutable context threaded through [`Buildpack::fetch`] and
/// [`Buildpack::compile`]. The driver advances `offline`/`proxy` across the seal.
pub struct BuildContext<'a> {
    /// Application source root (`/src`).
    pub app_dir: &'a Path,
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
