//! Host-side layered-runtime wiring: resolve a deployment's erofs layer blobs and
//! build the per-project **metadata** image the runtime VM boots with.
//!
//! A layered server's root is an overlay of `lowerdir=app:runtime:base`:
//! `base` is the shared Wolfi/glibc platform layer (`baselayers/platform.json`),
//! `runtime` the shared per-language runtime layer (e.g. bun) from the same store,
//! and `app` the per-server tenant layer — built in the build VM and dumped to
//! `deployments/v{N}/_layers/sha256-<hex>.erofs`.
//!
//! [`compute_layer_plan`] resolves these to host blob paths (verifying sha256 — all
//! tenants are untrusted) and computes the Firecracker device assignment that
//! [`crate::`]`vm` attaches (rootfs=vda, metadata=vdb, layers=vdc.., data last).
//! [`build_metadata_image`] bakes the resulting `_layers.json` device map plus the
//! deployment's manifests/static-sites/functions into a read-only ext4 image (no
//! mount, no root — `mkfs.ext4 -d`, threat-model P0-3).

use anyhow::{ensure, Context, Result};
use jkbase_common::layers::{RuntimeLayers, ServerLayers, VerityParams};
use jkbase_orch::build_image::build_ro_ext4_from_dir;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The resolved attach order + the device map the agent reads.
#[derive(Debug, Clone)]
pub struct LayerPlan {
    /// erofs blob host paths to attach RO as `vdc..`, in this exact order
    /// (base, distinct runtimes, per-server apps).
    pub layer_paths: Vec<PathBuf>,
    /// The host→agent device map baked into the metadata image as `_layers.json`.
    pub runtime_layers: RuntimeLayers,
}

impl LayerPlan {
    /// A plan with no layers (static/function-only project), optionally with a data
    /// disk at the first post-metadata slot.
    pub fn empty(has_data_disk: bool) -> Self {
        let mut rl = RuntimeLayers::new();
        if has_data_disk {
            rl.data_device = Some(device_node(2));
        }
        Self { layer_paths: Vec::new(), runtime_layers: rl }
    }
}

/// `platform.json` shape (subset we consume): the shared base + per-language runtime
/// layer descriptors in `baselayers/`.
#[derive(Debug, Deserialize)]
struct PlatformManifest {
    base: LayerDesc,
    #[serde(default)]
    runtimes: BTreeMap<String, LayerDesc>,
}

#[derive(Debug, Deserialize)]
struct LayerDesc {
    digest: String,
    file: String,
    /// dm-verity parameters for this shared layer's blob, present when the build
    /// appended a hash tree (the base + per-language runtimes — a poisoned shared layer
    /// would hit every tenant). Absent ⇒ no tree; the agent mounts the layer directly
    /// (it remains host-sha256-verified at attach via `digest`).
    #[serde(default)]
    verity: Option<VerityParams>,
}

/// The layer-relevant fields the build orchestrator augments each server manifest
/// with. The runtime agent's `ServerManifest` ignores them (extra fields).
#[derive(Debug, Deserialize)]
struct ServerLayerInfo {
    #[serde(default)]
    app_layer: Option<String>,
    #[serde(default)]
    app_digest: Option<String>,
    #[serde(default)]
    runtime: Option<String>,
}

struct BlobRef {
    path: PathBuf,
    digest: String,
    /// dm-verity params for this blob — `Some` only for the shared base/runtime layers
    /// (carried through to `_layers.json`); `None` for per-tenant app and image/self
    /// layers, which the agent mounts directly.
    verity: Option<VerityParams>,
}

/// Sentinel `runtime` value marking a server whose App layer is a self-contained
/// rootfs (the `builder = "dockerfile"` escape hatch). Such a server runs as a
/// SINGLE overlay lowerdir with no shared base/runtime beneath it — it carries its
/// own libc, init, and entrypoint. The build orchestrator stamps this into the
/// server manifest's `runtime` field; the agent keys non-clobbering env on it.
pub const IMAGE_SELF_RUNTIME: &str = "image/self";

/// Whether a server's App layer is self-contained (single-layer image/self mode).
fn is_self_contained(s: &ServerLayerInfo) -> bool {
    s.runtime.as_deref() == Some(IMAGE_SELF_RUNTIME)
}

/// Guest device node for the i-th virtio-blk drive (PUT order): 0→vda, 1→vdb, ….
/// Single-letter only (vda..vdz); the caller bounds the layer count so this never
/// overflows.
fn device_node(i: usize) -> String {
    debug_assert!(i < 26, "device index {i} exceeds vdz");
    format!("/dev/vd{}", (b'a' + (i as u8 % 26)) as char)
}

/// `sha256-<64hex>.erofs`, no path separators — the filename becomes a dest path.
pub(crate) fn is_safe_layer_filename(f: &str) -> bool {
    const PRE: &str = "sha256-";
    const SUF: &str = ".erofs";
    f.len() == PRE.len() + 64 + SUF.len()
        && f.starts_with(PRE)
        && f.ends_with(SUF)
        && f[PRE.len()..f.len() - SUF.len()]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
}

fn filename_to_digest(f: &str) -> String {
    let hex = f
        .strip_prefix("sha256-")
        .and_then(|s| s.strip_suffix(".erofs"))
        .unwrap_or(f);
    format!("sha256:{hex}")
}

fn sha256_hex(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher).with_context(|| format!("hash {}", path.display()))?;
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

fn read_platform(store_dir: &Path) -> Result<PlatformManifest> {
    let path = store_dir.join("platform.json");
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read layer store manifest {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Resolve a deployment's layered servers into an ordered list of erofs blob paths
/// to attach plus the per-server device map. `has_data_disk` reserves the post-layer
/// device for the (RW) data disk. When `verify`, every blob's sha256 is checked
/// against its digest before it can be attached to a tenant VM (do this on cold-boot
/// deploy; skip it on wake, where the blobs were already verified and are immutable).
///
/// A deployment with no layered servers (static/function-only) yields an empty plan.
pub fn compute_layer_plan(
    deployment_dir: &Path,
    store_dir: &Path,
    has_data_disk: bool,
    verify: bool,
) -> Result<LayerPlan> {
    // Gather layered servers, sorted by name for a deterministic device assignment
    // (so cold-boot deploy and wake agree on the same `_layers.json`).
    let servers_dir = deployment_dir.join("_servers");
    let mut servers: Vec<(String, ServerLayerInfo)> = Vec::new();
    if servers_dir.is_dir() {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&servers_dir)
            .with_context(|| format!("read {}", servers_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        for p in paths {
            let name = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let info: ServerLayerInfo = serde_json::from_slice(&std::fs::read(&p)?)
                .with_context(|| format!("parse server manifest {}", p.display()))?;
            if info.app_layer.is_some() {
                servers.push((name, info));
            }
        }
    }

    if servers.is_empty() {
        return Ok(LayerPlan::empty(has_data_disk));
    }

    // Self-contained "image/self" servers (the dockerfile escape hatch) are a single
    // App layer that IS the whole rootfs — its own libc/init/entrypoint — so they
    // skip the shared base + per-language runtime layers entirely. Layered servers
    // (bun &c.) stack `app:runtime:base`.
    let any_layered = servers.iter().any(|(_, s)| !is_self_contained(s));

    // Only read/require the platform base+runtime store when a layered server needs
    // it — an all-image/self deployment has no platform dependency at all.
    let platform = if any_layered {
        Some(read_platform(store_dir)?)
    } else {
        None
    };

    // Ordered, deduplicated blob list: base, distinct runtimes (sorted), apps.
    let mut order: Vec<BlobRef> = Vec::new();
    let mut runtime_idx: BTreeMap<String, usize> = BTreeMap::new();
    let mut app_idx: BTreeMap<String, usize> = BTreeMap::new();

    let mut base_dev_idx: Option<usize> = None;
    if let Some(platform) = &platform {
        base_dev_idx = Some(order.len());
        order.push(BlobRef {
            path: store_dir.join(&platform.base.file),
            digest: platform.base.digest.clone(),
            verity: platform.base.verity.clone(),
        });

        // Runtimes are keyed only by LAYERED servers' languages — an image/self
        // server's `runtime` sentinel must never be looked up as a platform runtime.
        let mut langs: Vec<String> = servers
            .iter()
            .filter(|(_, s)| !is_self_contained(s))
            .map(|(_, s)| s.runtime.clone().unwrap_or_else(|| "bun".to_string()))
            .collect();
        langs.sort();
        langs.dedup();
        for lang in &langs {
            let desc = platform
                .runtimes
                .get(lang)
                .ok_or_else(|| anyhow::anyhow!("no platform runtime layer for language '{lang}'"))?;
            runtime_idx.insert(lang.clone(), order.len());
            order.push(BlobRef {
                path: store_dir.join(&desc.file),
                digest: desc.digest.clone(),
                verity: desc.verity.clone(),
            });
        }
    }

    for (name, s) in &servers {
        let file = s.app_layer.as_ref().expect("filtered to Some above");
        ensure!(
            is_safe_layer_filename(file),
            "unsafe app layer filename {file:?} for server '{name}'"
        );
        let digest = s
            .app_digest
            .clone()
            .unwrap_or_else(|| filename_to_digest(file));
        app_idx.insert(name.clone(), order.len());
        order.push(BlobRef {
            path: deployment_dir.join("_layers").join(file),
            digest,
            // Per-tenant app layer: self-affecting, host-sha256-verified at attach, no
            // verity tree → mounted directly by the agent.
            verity: None,
        });
    }

    // Bound the device assignment to single-letter nodes (vda..vdz): rootfs(0),
    // metadata(1), the blobs, then the data disk.
    let needed = 2 + order.len() + usize::from(has_data_disk);
    ensure!(
        needed <= 26,
        "deployment needs {needed} virtio drives (>26); too many layers for single-letter device nodes"
    );

    // Resolve + verify, building the attach order.
    let mut layer_paths = Vec::with_capacity(order.len());
    for b in &order {
        ensure!(b.path.exists(), "layer blob missing: {}", b.path.display());
        if verify {
            let want = b.digest.strip_prefix("sha256:").unwrap_or(&b.digest);
            let got = sha256_hex(&b.path)?;
            ensure!(
                got.eq_ignore_ascii_case(want),
                "layer digest mismatch for {}: want {want}, got {got}",
                b.path.display()
            );
        }
        layer_paths.push(b.path.clone());
    }

    // Device map: blob order_idx → vd[c+order_idx] (rootfs=vda, metadata=vdb).
    let dev = |order_idx: usize| device_node(2 + order_idx);
    let mut runtime_layers = RuntimeLayers::new();
    for (name, s) in &servers {
        let app_dev = dev(app_idx[name]);
        let layers = if is_self_contained(s) {
            // Single self-contained lowerdir — the image is the whole tree.
            vec![app_dev]
        } else {
            // overlay lowerdir order: app first, base last.
            let lang = s.runtime.clone().unwrap_or_else(|| "bun".to_string());
            let runtime_dev = dev(runtime_idx[&lang]);
            let base_dev = dev(base_dev_idx.expect("layered server requires a base layer"));
            vec![app_dev, runtime_dev, base_dev]
        };
        runtime_layers.servers.insert(name.clone(), ServerLayers { layers });
    }
    // Carry the shared layers' dm-verity params into the device map, keyed by the SAME
    // device strings the server overlay stacks reference (the agent activates a verity
    // mapping for any device present here and mounts erofs from it, fail-closed). Only
    // base + runtime blobs carry params; app/image-self blobs are absent → mounted
    // directly. `order` is the attach order, so blob i lands on device vd(c+i) = dev(i).
    for (i, b) in order.iter().enumerate() {
        if let Some(v) = &b.verity {
            runtime_layers.verity.insert(dev(i), v.clone());
        }
    }
    if has_data_disk {
        runtime_layers.data_device = Some(device_node(2 + layer_paths.len()));
    }

    Ok(LayerPlan { layer_paths, runtime_layers })
}

/// Host-only file embedded in the metadata image holding the ordered erofs layer
/// host paths (`layer_paths`) the cold-boot fallback must attach, in the SAME order
/// as the image's `_layers.json` device map. Embedded INSIDE the image (not an
/// external sibling) so the single image rename publishes it ATOMICALLY with the
/// device map — two separate files can't be published atomically, so a sibling
/// sidecar could desync (image present, paths missing → silent device mismatch).
/// The agent never reads it (it's a host concern); a static-serve guard keeps it,
/// and the other `_`-prefixed control files, off the public surface.
const LAYER_PATHS_FILE: &str = "_layerpaths.json";

/// Read the `layer_paths` embedded in a metadata image via debugfs (no mount —
/// P0-3), or an empty vec when absent (legacy flat image / static-only project).
/// Swallows extraction errors as empty — callers that must distinguish a genuine
/// failure from "no layers" (e.g. the boot-time baselayers GC, which has to fail
/// safe) use [`try_read_layer_paths`].
pub fn read_layer_paths(metadata_image: &Path) -> Vec<PathBuf> {
    try_read_layer_paths(metadata_image).unwrap_or_default()
}

/// Like [`read_layer_paths`] but returns `Err` on a genuine extraction/parse
/// failure, distinct from `Ok(empty)` for an absent image / no-layers project. The
/// boot-time baselayers GC relies on this distinction: an unreadable layer map must
/// NOT be treated as "references nothing" (that could reap a blob still in use).
pub(crate) fn try_read_layer_paths(metadata_image: &Path) -> Result<Vec<PathBuf>> {
    if !metadata_image.exists() {
        return Ok(Vec::new());
    }
    // Unique temp dest so two reads can't race on the same path.
    let dest = metadata_image.with_extension(format!(
        "layerpaths.{}.{}.tmp",
        std::process::id(),
        BUILD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&dest);
    // Remove the dump on EVERY return path (incl. the read/parse `?` below).
    let _cleanup = TempCleanup(vec![dest.clone()]);
    let found =
        jkbase_orch::build_output::dump_file(metadata_image, &format!("/{LAYER_PATHS_FILE}"), &dest)
            .with_context(|| format!("extract {LAYER_PATHS_FILE} from {}", metadata_image.display()))?;
    if !found {
        return Ok(Vec::new());
    }
    let bytes =
        std::fs::read(&dest).with_context(|| format!("read extracted {}", dest.display()))?;
    let v: Vec<String> = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {LAYER_PATHS_FILE} from {}", metadata_image.display()))?;
    Ok(v.into_iter().map(PathBuf::from).collect())
}

/// Monotonic suffix so concurrent / orphaned builds use distinct temp paths.
static BUILD_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Best-effort cleanup of temp build artifacts on every return path.
struct TempCleanup(Vec<PathBuf>);
impl Drop for TempCleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_dir_all(p);
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Build the per-project metadata image: the deployment tree (manifests, routes,
/// sites, functions) **minus the erofs blobs** (those attach as drives), plus the
/// host-written `_layers.json` device map AND the host-only `_layerpaths.json`
/// attach order. Read-only ext4, built mount-free (`mkfs.ext4 -d`, P0-3). Built into
/// UNIQUE temp paths and published by a SINGLE atomic rename, so a concurrent or
/// orphaned build can never leave a half-written or stage-colliding image, and the
/// device map + attach order are always published together (no desync window).
pub fn build_metadata_image(
    deployment_dir: &Path,
    plan: &LayerPlan,
    secrets: &BTreeMap<String, String>,
    out: &Path,
) -> Result<()> {
    let parent = out.parent().unwrap_or_else(|| Path::new("."));
    let base = out.file_name().and_then(|n| n.to_str()).unwrap_or("metadata.ext4");
    let uniq = format!(
        "{base}.{}.{}",
        std::process::id(),
        BUILD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let stage = parent.join(format!("{uniq}.stage"));
    let tmp_img = parent.join(format!("{uniq}.tmp"));
    // Removed on every return (success or error) — no leaked .stage / .tmp.
    let _cleanup = TempCleanup(vec![stage.clone(), tmp_img.clone()]);

    std::fs::create_dir_all(&stage)?;
    // Copy the deployment tree except `_layers/` (the erofs blobs are attached as
    // drives, not carried in the metadata filesystem).
    copy_dir_except(deployment_dir, &stage, "_layers")
        .with_context(|| format!("stage metadata from {}", deployment_dir.display()))?;

    // Inject the project's runtime secrets into each layered server's env — in the
    // PER-VM metadata image ONLY (the on-disk deployment artifact stays secret-free).
    // This image is rebuilt on deploy; wake/restore reuse the existing image, so the
    // injected secrets are as of the last deploy. The `_servers/*.json` files are
    // never static-servable (the agent's serve_dir fallthrough blocks `_`-prefixed
    // entries), and the agent applies PORT/HOME/HOSTNAME/PATH authoritatively, so a
    // secret can never reach those reserved vars.
    if !secrets.is_empty() {
        inject_secrets(&stage.join("_servers"), secrets)
            .context("inject project secrets into server manifests")?;
    }

    // Bake the device map the agent reads at boot...
    std::fs::write(
        stage.join(RuntimeLayers::FILE),
        serde_json::to_vec_pretty(&plan.runtime_layers)?,
    )?;
    // ...and the host-only attach order (read back at wake via debugfs), so both are
    // published atomically by the single image rename below.
    let paths: Vec<String> = plan
        .layer_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    std::fs::write(stage.join(LAYER_PATHS_FILE), serde_json::to_vec_pretty(&paths)?)?;

    build_ro_ext4_from_dir(&stage, &tmp_img, 8)
        .with_context(|| format!("mkfs metadata image for {}", out.display()))?;

    // Publish atomically: one rename of the finished image (with both control files
    // already inside it).
    std::fs::rename(&tmp_img, out)
        .with_context(|| format!("publish metadata image {}", out.display()))?;
    Ok(())
}

/// Recursively copy `src` → `dst`, skipping a top-level entry named `skip_top`.
fn copy_dir_except(src: &Path, dst: &Path, skip_top: &str) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_name() == std::ffi::OsStr::new(skip_top) {
            continue;
        }
        copy_entry(&entry.path(), &dst.join(entry.file_name()))?;
    }
    Ok(())
}

fn copy_entry(from: &Path, to: &Path) -> Result<()> {
    let ft = std::fs::symlink_metadata(from)?.file_type();
    if ft.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_entry(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else if ft.is_symlink() {
        let target = std::fs::read_link(from)?;
        let _ = std::fs::remove_file(to);
        std::os::unix::fs::symlink(target, to)?;
    } else {
        std::fs::copy(from, to)?;
    }
    Ok(())
}

/// Env vars the platform sets authoritatively per server (see the agent's
/// `apply_server_env`). A project secret must never override these — `PORT` would
/// break routing, `PATH`/`HOME`/`HOSTNAME` the runtime — so they are filtered out at
/// injection (defense-in-depth; the agent also re-applies them last).
const RESERVED_ENV: &[&str] = &["PORT", "HOME", "HOSTNAME", "PATH"];

/// Merge project `secrets` into every `_servers/*.json` manifest's `env`, in place on
/// the staged copy. Secrets override build-time env (e.g. `NODE_ENV`) on conflict;
/// reserved platform keys are skipped. A manifest lacking an `env` object gets one.
fn inject_secrets(servers_dir: &Path, secrets: &BTreeMap<String, String>) -> Result<()> {
    if !servers_dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(servers_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let mut manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("parse server manifest {}", path.display()))?;
        let Some(obj) = manifest.as_object_mut() else {
            continue;
        };
        let env = obj.entry("env").or_insert_with(|| serde_json::json!({}));
        let Some(env) = env.as_object_mut() else {
            continue;
        };
        for (k, v) in secrets {
            // Skip reserved platform keys, and any key/value that would make the
            // agent's `Command::env` fail at spawn (a NUL anywhere, or an empty key /
            // a key containing '='). A bad secret must degrade to "that one var is
            // dropped", never abort the VM's server startup (which is shared by every
            // server in the project). The set_secret API also rejects these, but this
            // is the load-bearing guard for already-stored or future inputs.
            if RESERVED_ENV.contains(&k.as_str())
                || k.is_empty()
                || k.contains('=')
                || k.contains('\0')
                || v.contains('\0')
            {
                continue;
            }
            env.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename() {
        let hex = "a".repeat(64);
        assert!(is_safe_layer_filename(&format!("sha256-{hex}.erofs")));
        assert!(!is_safe_layer_filename("sha256-xyz.erofs"));
        assert!(!is_safe_layer_filename("../escape.erofs"));
        assert!(!is_safe_layer_filename(&format!("sha256-{hex}.tar")));
        assert!(!is_safe_layer_filename("sha256-/etc/passwd.erofs"));
    }

    #[test]
    fn inject_secrets_merges_env_and_filters_reserved() {
        let dir = std::env::temp_dir().join(format!("ls-secrets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let servers = dir.join("_servers");
        std::fs::create_dir_all(&servers).unwrap();
        // A server manifest as the buildpack writes it (env = NODE_ENV only).
        std::fs::write(
            servers.join("app.json"),
            r#"{"port":3000,"cmd":["/opt/bun/bin/bun","run","start"],"env":{"NODE_ENV":"production"}}"#,
        )
        .unwrap();

        let mut secrets = BTreeMap::new();
        secrets.insert("DOMAIN".to_string(), "forumall.jkbase.app".to_string());
        secrets.insert("NODE_ENV".to_string(), "staging".to_string()); // overrides build env
        secrets.insert("PORT".to_string(), "9999".to_string()); // reserved → filtered
        secrets.insert("PATH".to_string(), "/evil".to_string()); // reserved → filtered
        secrets.insert("BAD=KEY".to_string(), "x".to_string()); // '=' in key → skipped
        secrets.insert(String::new(), "x".to_string()); // empty key → skipped
        secrets.insert("NUL_VAL".to_string(), "a\0b".to_string()); // NUL value → skipped
        secrets.insert("NUL\0KEY".to_string(), "x".to_string()); // NUL key → skipped

        inject_secrets(&servers, &secrets).unwrap();

        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(servers.join("app.json")).unwrap()).unwrap();
        let env = v["env"].as_object().unwrap();
        assert_eq!(env["DOMAIN"], "forumall.jkbase.app");
        assert_eq!(env["NODE_ENV"], "staging", "secret overrides build-time env");
        assert!(!env.contains_key("PORT"), "reserved PORT must be filtered");
        assert!(!env.contains_key("PATH"), "reserved PATH must be filtered");
        // Spawn-breaking keys/values are dropped (never reach the agent's Command::env).
        assert!(!env.contains_key("BAD=KEY"), "key with '=' must be skipped");
        assert!(!env.contains_key("NUL_VAL"), "value with NUL must be skipped");
        assert!(
            env.keys().all(|k| !k.is_empty() && !k.contains('\0')),
            "empty/NUL keys must be skipped"
        );
        // cmd/port preserved.
        assert_eq!(v["port"], 3000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inject_secrets_creates_env_and_noops_without_dir() {
        // Missing _servers dir is a no-op, not an error.
        let missing = std::env::temp_dir().join(format!("ls-nosrv-{}", std::process::id()));
        let mut secrets = BTreeMap::new();
        secrets.insert("X".to_string(), "y".to_string());
        inject_secrets(&missing.join("_servers"), &secrets).unwrap();

        // A manifest with no `env` gets one created.
        let dir = std::env::temp_dir().join(format!("ls-noenv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let servers = dir.join("_servers");
        std::fs::create_dir_all(&servers).unwrap();
        std::fs::write(servers.join("app.json"), r#"{"port":3000,"cmd":["x"]}"#).unwrap();
        inject_secrets(&servers, &secrets).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(servers.join("app.json")).unwrap()).unwrap();
        assert_eq!(v["env"]["X"], "y");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_nodes() {
        assert_eq!(device_node(0), "/dev/vda");
        assert_eq!(device_node(1), "/dev/vdb");
        assert_eq!(device_node(2), "/dev/vdc");
        assert_eq!(device_node(4), "/dev/vde");
    }

    #[test]
    fn filename_digest_roundtrip() {
        let hex = "b".repeat(64);
        let f = format!("sha256-{hex}.erofs");
        assert_eq!(filename_to_digest(&f), format!("sha256:{hex}"));
    }

    #[test]
    fn device_map_matches_attach_order() {
        // Fabricate a store (base + bun runtime) and a one-server deployment, then
        // assert the baked device map (`runtime_layers`) lines up with the attach
        // order (`layer_paths`) that vm.rs PUTs as vdc.. — the load-bearing contract.
        let root = std::env::temp_dir().join(format!("lp-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = root.join("store");
        let deploy = root.join("deploy");
        std::fs::create_dir_all(store.join("x")).unwrap();
        std::fs::create_dir_all(deploy.join("_servers")).unwrap();
        std::fs::create_dir_all(deploy.join("_layers")).unwrap();

        let base_f = format!("sha256-{}.erofs", "a".repeat(64));
        let rt_f = format!("sha256-{}.erofs", "b".repeat(64));
        let app_f = format!("sha256-{}.erofs", "c".repeat(64));
        std::fs::write(store.join(&base_f), b"base").unwrap();
        std::fs::write(store.join(&rt_f), b"rt").unwrap();
        std::fs::write(deploy.join("_layers").join(&app_f), b"app").unwrap();
        std::fs::write(
            store.join("platform.json"),
            format!(
                r#"{{"base":{{"digest":"sha256:{a}","file":"{base_f}"}},"runtimes":{{"bun":{{"digest":"sha256:{b}","file":"{rt_f}"}}}}}}"#,
                a = "a".repeat(64),
                b = "b".repeat(64),
            ),
        )
        .unwrap();
        std::fs::write(
            deploy.join("_servers/api.json"),
            format!(r#"{{"app_layer":"{app_f}","runtime":"bun","port":3000}}"#),
        )
        .unwrap();

        let plan = compute_layer_plan(&deploy, &store, true, false).unwrap();

        // Attach order vm.rs uses for vdc.. : [base, runtime, app].
        assert_eq!(plan.layer_paths.len(), 3);
        assert!(plan.layer_paths[0].ends_with(&base_f), "vdc = base");
        assert!(plan.layer_paths[1].ends_with(&rt_f), "vdd = runtime");
        assert!(plan.layer_paths[2].ends_with(&app_f), "vde = app");

        // The server's overlay (app:runtime:base) must name the devices the attach
        // order produces: app=vde(idx2), runtime=vdd(idx1), base=vdc(idx0).
        let s = &plan.runtime_layers.servers["api"];
        assert_eq!(s.layers, vec!["/dev/vde", "/dev/vdd", "/dev/vdc"]);

        // Cross-check: each server-layer device letter indexes back to the right
        // blob in layer_paths (device vd(c+i) ↔ layer_paths[i]).
        for dev in &s.layers {
            let letter = dev.chars().last().unwrap();
            let idx = (letter as u8 - b'c') as usize;
            assert!(idx < plan.layer_paths.len(), "{dev} maps into layer_paths");
        }

        // Data disk attaches after the 3 layers: vd(c+3) = vdf.
        assert_eq!(plan.runtime_layers.data_device.as_deref(), Some("/dev/vdf"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn single_layer_for_image_self_server() {
        // An image/self server is a single self-contained App layer: no base, no
        // runtime, no platform.json dependency. The device map is [app] only, and
        // the data disk attaches right after the lone app layer.
        let root = std::env::temp_dir().join(format!("lp-self-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = root.join("store"); // intentionally has NO platform.json
        let deploy = root.join("deploy");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(deploy.join("_servers")).unwrap();
        std::fs::create_dir_all(deploy.join("_layers")).unwrap();

        let app_f = format!("sha256-{}.erofs", "c".repeat(64));
        std::fs::write(deploy.join("_layers").join(&app_f), b"app").unwrap();
        std::fs::write(
            deploy.join("_servers/web.json"),
            format!(r#"{{"app_layer":"{app_f}","runtime":"image/self","port":8080}}"#),
        )
        .unwrap();

        // No platform.json is read because there are no layered servers.
        let plan = compute_layer_plan(&deploy, &store, true, false).unwrap();

        // Exactly one blob attaches (the app), at vdc.
        assert_eq!(plan.layer_paths.len(), 1);
        assert!(plan.layer_paths[0].ends_with(&app_f), "vdc = app");

        // The overlay is a single lowerdir — the whole image rootfs.
        let s = &plan.runtime_layers.servers["web"];
        assert_eq!(s.layers, vec!["/dev/vdc"]);

        // Data disk attaches right after: vd(c+1) = vdd.
        assert_eq!(plan.runtime_layers.data_device.as_deref(), Some("/dev/vdd"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mixed_layered_and_image_self_servers() {
        // A bun (layered) server and an image/self server in one deployment: base +
        // runtime are present (the bun server needs them); the image/self server is
        // app-only; both app layers attach after the shared base/runtime.
        let root = std::env::temp_dir().join(format!("lp-mixed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = root.join("store");
        let deploy = root.join("deploy");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(deploy.join("_servers")).unwrap();
        std::fs::create_dir_all(deploy.join("_layers")).unwrap();

        let base_f = format!("sha256-{}.erofs", "a".repeat(64));
        let rt_f = format!("sha256-{}.erofs", "b".repeat(64));
        let api_app = format!("sha256-{}.erofs", "c".repeat(64));
        let web_app = format!("sha256-{}.erofs", "d".repeat(64));
        std::fs::write(store.join(&base_f), b"base").unwrap();
        std::fs::write(store.join(&rt_f), b"rt").unwrap();
        std::fs::write(deploy.join("_layers").join(&api_app), b"api").unwrap();
        std::fs::write(deploy.join("_layers").join(&web_app), b"web").unwrap();
        std::fs::write(
            store.join("platform.json"),
            format!(
                r#"{{"base":{{"digest":"sha256:{a}","file":"{base_f}"}},"runtimes":{{"bun":{{"digest":"sha256:{b}","file":"{rt_f}"}}}}}}"#,
                a = "a".repeat(64),
                b = "b".repeat(64),
            ),
        )
        .unwrap();
        // Sorted by name: api (bun) then web (image/self).
        std::fs::write(
            deploy.join("_servers/api.json"),
            format!(r#"{{"app_layer":"{api_app}","runtime":"bun","port":3000}}"#),
        )
        .unwrap();
        std::fs::write(
            deploy.join("_servers/web.json"),
            format!(r#"{{"app_layer":"{web_app}","runtime":"image/self","port":8080}}"#),
        )
        .unwrap();

        let plan = compute_layer_plan(&deploy, &store, false, false).unwrap();

        // Attach order: base(vdc), bun-rt(vdd), api-app(vde), web-app(vdf).
        assert_eq!(plan.layer_paths.len(), 4);
        assert!(plan.layer_paths[0].ends_with(&base_f));
        assert!(plan.layer_paths[1].ends_with(&rt_f));
        assert!(plan.layer_paths[2].ends_with(&api_app));
        assert!(plan.layer_paths[3].ends_with(&web_app));

        // api stacks app:runtime:base; web is app-only.
        assert_eq!(
            plan.runtime_layers.servers["api"].layers,
            vec!["/dev/vde", "/dev/vdd", "/dev/vdc"]
        );
        assert_eq!(plan.runtime_layers.servers["web"].layers, vec!["/dev/vdf"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verity_params_propagate_to_device_map() {
        // platform.json carrying dm-verity params on base + runtime must surface in the
        // baked `_layers.json` verity map, keyed by the SAME device the overlay stack
        // references. The per-tenant app layer carries no verity entry (mounted directly).
        let root = std::env::temp_dir().join(format!("lp-verity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = root.join("store");
        let deploy = root.join("deploy");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(deploy.join("_servers")).unwrap();
        std::fs::create_dir_all(deploy.join("_layers")).unwrap();

        let base_f = format!("sha256-{}.erofs", "a".repeat(64));
        let rt_f = format!("sha256-{}.erofs", "b".repeat(64));
        let app_f = format!("sha256-{}.erofs", "c".repeat(64));
        std::fs::write(store.join(&base_f), b"base").unwrap();
        std::fs::write(store.join(&rt_f), b"rt").unwrap();
        std::fs::write(deploy.join("_layers").join(&app_f), b"app").unwrap();

        let base_root = "1".repeat(64);
        let rt_root = "2".repeat(64);
        let salt = "ab".repeat(32);
        std::fs::write(
            store.join("platform.json"),
            format!(
                r#"{{"base":{{"digest":"sha256:{a}","file":"{base_f}","verity":{{"root_hash":"{br}","salt":"{s}","data_size":8192}}}},"runtimes":{{"bun":{{"digest":"sha256:{b}","file":"{rt_f}","verity":{{"root_hash":"{rr}","salt":"{s}","data_size":4096}}}}}}}}"#,
                a = "a".repeat(64),
                b = "b".repeat(64),
                br = base_root,
                rr = rt_root,
                s = salt,
            ),
        )
        .unwrap();
        std::fs::write(
            deploy.join("_servers/api.json"),
            format!(r#"{{"app_layer":"{app_f}","runtime":"bun","port":3000}}"#),
        )
        .unwrap();

        let plan = compute_layer_plan(&deploy, &store, false, false).unwrap();

        // Attach order [base(vdc), runtime(vdd), app(vde)] ⇒ verity keyed by vdc/vdd only.
        let verity = &plan.runtime_layers.verity;
        assert_eq!(verity.len(), 2, "base + runtime have verity; the app layer does not");
        assert_eq!(verity["/dev/vdc"].root_hash, base_root);
        assert_eq!(verity["/dev/vdc"].data_size, 8192);
        assert_eq!(verity["/dev/vdd"].root_hash, rt_root);
        assert_eq!(verity["/dev/vdd"].data_size, 4096);
        assert!(!verity.contains_key("/dev/vde"), "app layer mounts directly (no verity)");

        // Every verity key must be a device the server overlay actually stacks.
        let stacked: std::collections::BTreeSet<&str> = plan
            .runtime_layers
            .servers["api"]
            .layers
            .iter()
            .map(|s| s.as_str())
            .collect();
        for dev in verity.keys() {
            assert!(stacked.contains(dev.as_str()), "{dev} must be in the overlay stack");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn image_self_has_no_verity_map() {
        // A self-contained image/self deployment reads no platform.json and so the baked
        // device map carries no verity entries — the single app layer mounts directly.
        let root = std::env::temp_dir().join(format!("lp-self-noverity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = root.join("store");
        let deploy = root.join("deploy");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(deploy.join("_servers")).unwrap();
        std::fs::create_dir_all(deploy.join("_layers")).unwrap();
        let app_f = format!("sha256-{}.erofs", "c".repeat(64));
        std::fs::write(deploy.join("_layers").join(&app_f), b"app").unwrap();
        std::fs::write(
            deploy.join("_servers/web.json"),
            format!(r#"{{"app_layer":"{app_f}","runtime":"image/self","port":8080}}"#),
        )
        .unwrap();
        let plan = compute_layer_plan(&deploy, &store, false, false).unwrap();
        assert!(plan.runtime_layers.verity.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_plan_for_no_servers() {
        let dir = std::env::temp_dir().join(format!("lp-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("_servers")).unwrap();
        let plan = compute_layer_plan(&dir, &dir, false, false).unwrap();
        assert!(plan.layer_paths.is_empty());
        assert!(plan.runtime_layers.servers.is_empty());
        assert!(plan.runtime_layers.data_device.is_none());

        let plan = compute_layer_plan(&dir, &dir, true, false).unwrap();
        assert_eq!(plan.runtime_layers.data_device.as_deref(), Some("/dev/vdc"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
