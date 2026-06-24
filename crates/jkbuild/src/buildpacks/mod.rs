//! Per-language buildpack modules: Bun, Node, Trunk, Rust, Python and Go (plus a
//! Dockerfile escape hatch). Order matters only for detect disambiguation — Bun
//! is tried before Node since a Bun repo also carries `package.json`, and Trunk is
//! tried before Rust since a trunk frontend also carries a `Cargo.toml` (the Rust
//! buildpack stands down when a `Trunk.toml` is present).

pub mod bun;
pub mod dockerfile;
pub mod go;
pub mod node;
pub mod python;
pub mod rust;
pub mod trunk;

use crate::buildpack::Buildpack;

/// The ordered roster of buildpacks the lifecycle tries during detect. Detection
/// resolves ties by confidence (see [`crate::buildpack::Decision`]); the order here
/// is only a tiebreak fallback, so it does not have to encode precedence.
pub fn registry() -> Vec<Box<dyn Buildpack>> {
    vec![
        Box::new(bun::BunBuildpack),
        Box::new(node::NodeBuildpack),
        // Trunk before Rust: a trunk frontend also has a Cargo.toml, but Trunk.toml is
        // the deciding signal and rust defers to it (mirrors node → bun).
        Box::new(trunk::TrunkBuildpack),
        Box::new(rust::RustBuildpack),
        Box::new(python::PythonBuildpack),
        Box::new(go::GoBuildpack),
        Box::new(dockerfile::DockerfileBuildpack),
    ]
}
