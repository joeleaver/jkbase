//! Per-language buildpack modules. Bun is the lead language; Node and Rust follow
//! on the same lifecycle (Python/Go later).

pub mod bun;
pub mod dockerfile;
pub mod node;
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
        Box::new(dockerfile::DockerfileBuildpack),
    ]
}
