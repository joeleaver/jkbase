//! Shared wire types for the jkbase build subsystem (B2).
//!
//! These structs cross the build-VM boundary via the write-only `/out` drive,
//! which the host reads back WITHOUT mounting (debugfs; threat-model P0-3). The
//! in-VM [`jkbuild`](../jkbuild/index.html) lifecycle is the producer; the
//! host-side `jkbase-server`/`jkbase-control` is the consumer. Keeping the
//! definitions here gives the contract a single source of truth — notably
//! [`FETCH_COMPLETE_MARKER`], which the host's `build_vm` watches for on the
//! console and the guest must emit byte-for-byte.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Console marker the in-VM runner prints once dependency fetching is done,
/// signalling the host it may seal the network (tear the TAP) early. The host's
/// `jkbase-orch::build_vm` matches these exact bytes — do not change without
/// changing both sides (that is the whole reason this lives in a shared crate).
pub const FETCH_COMPLETE_MARKER: &str = "[seal] FETCH-COMPLETE";

/// Fixed `/out` filenames the in-VM lifecycle writes and the host reads by name
/// (the host never lists the untrusted guest fs — it dumps known paths only).
pub mod out {
    /// The build's exit code (decimal text).
    pub const STATUS: &str = "/status";
    /// Captured build log.
    pub const BUILD_LOG: &str = "/build.log";
    /// Build-derived `cmd`/`env`/`working_dir` ([`super::BuiltServerManifest`]).
    pub const MANIFEST: &str = "/manifest.json";
    /// Cache key + hit + per-phase timings ([`super::CacheMeta`]).
    pub const CACHE: &str = "/cache.json";
    /// The layered-artifact index ([`super::Index`]).
    pub const INDEX: &str = "/layers/index.json";
    /// Transitional flat-rootfs tarball (the de-risking rung before the layered
    /// runtime lands; consumed by the existing flat-chroot runtime).
    pub const ROOTFS_TARBALL: &str = "/rootfs.tar.gz";
}

/// Where a layer sits in the runtime overlay stack. `Base` and `Runtime` layers
/// are platform-built, shared/dedup'd across tenants, and integrity-pinned;
/// `App` is the single tenant-controlled (untrusted) layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerRole {
    Base,
    Runtime,
    App,
}

/// One content-addressed layer referenced by an [`Index`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerRef {
    /// Human label (e.g. `"wolfi-base"`, `"app"`).
    pub name: String,
    /// `"sha256:<hex>"` over the layer container bytes.
    pub digest: String,
    pub role: LayerRole,
    /// Container format, e.g. `"erofs"` (or `"flat-tar"` for the transitional rung).
    pub media: String,
    /// Filename under `/out/layers/`, e.g. `"sha256-<hex>.erofs"`. Empty when the
    /// blob is a shared base referenced by digest (the host already has it).
    #[serde(default)]
    pub file: String,
    pub size: u64,
}

/// The layered-artifact index emitted to `/out/layers/index.json`. `layers` is in
/// overlay stack order, lowest (base) first; the runtime stacks them as
/// `lowerdir=app:…:base`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub schema: u32,
    /// `"server"` (functions use the wasm path, not this).
    pub target: String,
    pub layers: Vec<LayerRef>,
}

impl Index {
    pub const SCHEMA: u32 = 1;
}

/// The build-derived half of a `ServerManifest` (`cmd`/`env`/`working_dir`). The
/// host overlays the authoritative `port`/`health_check`/`volumes` from
/// `jkbase.toml` via `ServerConfig::manifest_value`. Field names match the host's
/// reader so the existing deploy path stays wire-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltServerManifest {
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "root_dir")]
    pub working_dir: String,
}

fn root_dir() -> String {
    "/".to_string()
}

impl Default for BuiltServerManifest {
    fn default() -> Self {
        Self {
            cmd: Vec::new(),
            env: BTreeMap::new(),
            working_dir: root_dir(),
        }
    }
}

/// Build provenance + cache outcome emitted to `/out/cache.json`. The host folds
/// these into the build-job record (`cache_hit` becomes truthful; per-phase
/// timings surface in the build's duration breakdown).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheMeta {
    /// Platform-derivable cache key (toolchain + lockfile + source digests).
    #[serde(default)]
    pub cache_key: Option<String>,
    #[serde(default)]
    pub cache_hit: bool,
    /// Per-phase wall-clock timings (e.g. `detect`/`fetch`/`compile`/`export`).
    #[serde(default)]
    pub phases_ms: BTreeMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_stable() {
        // The host (jkbase-orch::build_vm) hard-codes the same bytes; if this
        // ever changes, both sides must change together.
        assert_eq!(FETCH_COMPLETE_MARKER, "[seal] FETCH-COMPLETE");
    }

    #[test]
    fn index_round_trips() {
        let idx = Index {
            schema: Index::SCHEMA,
            target: "server".into(),
            layers: vec![
                LayerRef {
                    name: "wolfi-base".into(),
                    digest: "sha256:aaaa".into(),
                    role: LayerRole::Base,
                    media: "erofs".into(),
                    file: String::new(),
                    size: 1024,
                },
                LayerRef {
                    name: "app".into(),
                    digest: "sha256:bbbb".into(),
                    role: LayerRole::App,
                    media: "erofs".into(),
                    file: "sha256-bbbb.erofs".into(),
                    size: 2048,
                },
            ],
        };
        let json = serde_json::to_string(&idx).unwrap();
        let back: Index = serde_json::from_str(&json).unwrap();
        assert_eq!(back.layers.len(), 2);
        assert_eq!(back.layers[0].role, LayerRole::Base);
        assert_eq!(back.layers[1].file, "sha256-bbbb.erofs");
    }

    #[test]
    fn role_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&LayerRole::Runtime).unwrap(),
            "\"runtime\""
        );
    }

    #[test]
    fn built_manifest_defaults_and_is_host_wire_compatible() {
        // Host reads {cmd, env, working_dir}; absent fields default sanely.
        let m: BuiltServerManifest = serde_json::from_str("{}").unwrap();
        assert!(m.cmd.is_empty());
        assert_eq!(m.working_dir, "/");

        let m = BuiltServerManifest {
            cmd: vec!["/opt/bun/bin/bun".into(), "run".into(), "start".into()],
            env: BTreeMap::from([("NODE_ENV".into(), "production".into())]),
            working_dir: "/app".into(),
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(v["cmd"][0], "/opt/bun/bin/bun");
        assert_eq!(v["working_dir"], "/app");
        assert_eq!(v["env"]["NODE_ENV"], "production");
    }
}
