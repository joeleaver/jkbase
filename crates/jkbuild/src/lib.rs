//! `jkbuild` — the jkbase build lifecycle (B2).
//!
//! A lean, CNB-spec-*aligned* detect→build→export engine that jkbase owns,
//! rather than vendoring the upstream Go lifecycle + Docker/pack + Paketo. It
//! runs inside the jailed, ephemeral build microVM (the host jail is the
//! security boundary), and emits jkbase's content-addressed *layered* artifact
//! natively to the `/out` drive.
//!
//! - [`buildpack`] — the in-process `Buildpack` trait + contexts (libcnb-shape,
//!   minus libcnb's on-disk TOML/exit-code protocol, since we own both sides).
//! - [`buildpacks`] — the per-language modules: Bun, Node, Rust, Python, Go.
//! - [`function_build`] — the function-builder matrix (NOT CNB): source → ONE
//!   `wasi:http` component (`/out/function.wasm`), language-dispatched.
//! - [`env`] — layer env accumulation.
//! - [`export`] — translate a build into the `/out` artifact (index + manifest
//!   + cache metadata; layer packing).
//! - [`lifecycle`] — the in-VM driver (PID1): mount, fetch-then-seal, run, export.

pub mod buildpack;
pub mod buildpacks;
pub mod env;
pub mod export;
pub mod function_build;
pub mod lifecycle;

pub use jkbuild_types as types;
