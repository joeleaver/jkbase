//! Per-language buildpack modules: Bun, Node, Rust, Python and Go (plus a
//! Dockerfile escape hatch). Order matters only for detect disambiguation — Bun
//! is tried before Node since a Bun repo also carries `package.json`.

pub mod bun;
pub mod dockerfile;
pub mod go;
pub mod node;
pub mod python;
pub mod rust;

use crate::buildpack::Buildpack;

/// The ordered roster of buildpacks the lifecycle tries during detect. Detection
/// resolves ties by confidence (see [`crate::buildpack::Decision`]); the order here
/// is only a tiebreak fallback, so it does not have to encode precedence.
pub fn registry() -> Vec<Box<dyn Buildpack>> {
    vec![
        Box::new(bun::BunBuildpack),
        Box::new(node::NodeBuildpack),
        Box::new(rust::RustBuildpack),
        Box::new(python::PythonBuildpack),
        Box::new(go::GoBuildpack),
        Box::new(dockerfile::DockerfileBuildpack),
    ]
}
