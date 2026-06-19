//! Per-language buildpack modules — Bun, Node, Rust, Python and Go, all equal
//! first-class on one lifecycle (no lead language). The registry order is for
//! detect disambiguation (e.g. Bun is tried before Node because a Bun repo also
//! carries `package.json`), not a preference.

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
