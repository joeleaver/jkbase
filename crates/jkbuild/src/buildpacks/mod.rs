//! Per-language buildpack modules. Bun is the lead language; Node/Python/Go
//! follow on the same lifecycle.

pub mod bun;
pub mod dockerfile;

use crate::buildpack::Buildpack;

/// The ordered roster of buildpacks the lifecycle tries during detect. Detection
/// resolves ties by confidence (see [`crate::buildpack::Decision`]).
pub fn registry() -> Vec<Box<dyn Buildpack>> {
    vec![
        Box::new(bun::BunBuildpack),
        Box::new(dockerfile::DockerfileBuildpack),
    ]
}
