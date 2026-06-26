//! Export: turn a [`BuildOutput`] into the `/out` artifact the host reads back.
//!
//! Two output shapes share the manifest/cache metadata:
//! - **layered** (the target): each `launch` layer is packed into a
//!   content-addressed erofs blob + an [`Index`]; the runtime composes them
//!   guest-side (overlay + pivot_root).
//! - **flat tarball** (the transitional de-risking rung): all `launch` layers are
//!   flattened into `/out/rootfs.tar.gz`, consumed by the existing flat-chroot
//!   runtime — proves the lifecycle end-to-end before the runtime rewrite lands.
//!
//! The host reads every emitted file by its fixed name via `debugfs` (no mount),
//! and verifies each layer blob's sha256 against the digest in the index.

use crate::buildpack::BuildOutput;
use anyhow::{Context, Result};
use jkbuild_types::{BuiltServerManifest, CacheMeta, Index, LayerRef};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Translate the build's launch process/env/working_dir into the manifest half
/// the host overlays onto `jkbase.toml`'s `port`/`health_check`/`volumes`.
pub fn to_built_manifest(out: &BuildOutput) -> BuiltServerManifest {
    let cmd = out
        .processes
        .iter()
        .find(|p| p.default)
        .or_else(|| out.processes.iter().find(|p| p.r#type == "web"))
        .or_else(|| out.processes.first())
        .map(|p| p.command.clone())
        .unwrap_or_default();
    BuiltServerManifest {
        cmd,
        env: out.env.clone(),
        working_dir: out.working_dir.clone().unwrap_or_else(|| "/".to_string()),
    }
}

/// Write `manifest.json`, `layers/index.json`, and `cache.json` under the mounted
/// output root (`/out`). The host dumps these by name.
pub fn write_metadata(
    out_root: &Path,
    index: &Index,
    manifest: &BuiltServerManifest,
    cache: &CacheMeta,
) -> Result<()> {
    write_json(&out_root.join("manifest.json"), manifest)?;
    let layers_dir = out_root.join("layers");
    std::fs::create_dir_all(&layers_dir).context("creating /out/layers")?;
    write_json(&layers_dir.join("index.json"), index)?;
    write_json(&out_root.join("cache.json"), cache)?;
    Ok(())
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Flatten all `launch` layers into a single gzipped tar at `dest`. Lower layers
/// are written first so higher (app) layers override — matching overlay
/// semantics for the flat runtime.
pub fn pack_flat_tarball(out: &BuildOutput, dest: &Path) -> Result<()> {
    let file = File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for layer in out.layers.iter().filter(|l| l.types.launch) {
        tar.append_dir_all(".", &layer.path).with_context(|| {
            format!("taring layer {} from {}", layer.name, layer.path.display())
        })?;
    }
    let gz = tar.into_inner()?;
    gz.finish()?.flush()?;
    Ok(())
}

/// `sha256:<hex>` over the bytes of a file (streamed; no full read into memory).
pub fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Pack one layer directory into a content-addressed erofs blob under
/// `out_layers_dir`, returning its [`LayerRef`]. Shells out to `mkfs.erofs`
/// (baked into the toolchain image); on-box path, not exercised in CI.
pub fn pack_layer_erofs(
    name: &str,
    role: jkbuild_types::LayerRole,
    layer_path: &Path,
    out_layers_dir: &Path,
) -> Result<LayerRef> {
    std::fs::create_dir_all(out_layers_dir).context("creating /out/layers")?;
    let tmp = out_layers_dir.join(format!(".{name}.erofs.tmp"));
    let status = std::process::Command::new("mkfs.erofs")
        // -zlz4hc keeps random-read fast; the kernel has erofs-zip. Reproducible
        // metadata flags are validated on-box (SOURCE_DATE_EPOCH etc.).
        .arg("-zlz4hc")
        .arg(&tmp)
        .arg(layer_path)
        .status()
        .context("spawning mkfs.erofs (is erofs-utils baked into the image?)")?;
    if !status.success() {
        anyhow::bail!("mkfs.erofs failed for layer {name}: {status}");
    }
    let digest = sha256_file(&tmp)?;
    let hex = digest.strip_prefix("sha256:").unwrap_or(&digest);
    let file = format!("sha256-{hex}.erofs");
    let final_path = out_layers_dir.join(&file);
    std::fs::rename(&tmp, &final_path)?;
    let size = std::fs::metadata(&final_path)?.len();
    Ok(LayerRef {
        name: name.to_string(),
        digest,
        role,
        media: "erofs".to_string(),
        file,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buildpack::{Layer, LayerTypes, Process};
    use jkbuild_types::{Index, LayerRole};
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn sample_output(app: &Path) -> BuildOutput {
        BuildOutput {
            layers: vec![Layer {
                name: "app".into(),
                path: app.to_path_buf(),
                types: LayerTypes {
                    build: false,
                    launch: true,
                    cache: false,
                },
                role: LayerRole::App,
            }],
            processes: vec![Process {
                r#type: "web".into(),
                command: vec!["/opt/bun/bin/bun".into(), "run".into(), "start".into()],
                default: true,
            }],
            env: BTreeMap::from([("NODE_ENV".into(), "production".into())]),
            working_dir: Some("/app".into()),
        }
    }

    #[test]
    fn translate_picks_default_process() {
        let d = tempdir().unwrap();
        let m = to_built_manifest(&sample_output(d.path()));
        assert_eq!(m.cmd, vec!["/opt/bun/bin/bun", "run", "start"]);
        assert_eq!(m.working_dir, "/app");
        assert_eq!(
            m.env.get("NODE_ENV").map(String::as_str),
            Some("production")
        );
    }

    #[test]
    fn translate_empty_when_no_process() {
        let out = BuildOutput::default();
        let m = to_built_manifest(&out);
        assert!(m.cmd.is_empty());
        assert_eq!(m.working_dir, "/");
    }

    #[test]
    fn write_metadata_emits_three_files() {
        let d = tempdir().unwrap();
        let out_root = d.path().join("out");
        std::fs::create_dir_all(&out_root).unwrap();
        let index = Index {
            schema: Index::SCHEMA,
            target: "server".into(),
            layers: vec![],
        };
        let manifest = to_built_manifest(&sample_output(d.path()));
        write_metadata(&out_root, &index, &manifest, &CacheMeta::default()).unwrap();
        assert!(out_root.join("manifest.json").exists());
        assert!(out_root.join("layers/index.json").exists());
        assert!(out_root.join("cache.json").exists());
        // manifest.json is wire-readable as the host's built-manifest shape.
        let raw = std::fs::read_to_string(out_root.join("manifest.json")).unwrap();
        let back: BuiltServerManifest = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.cmd[0], "/opt/bun/bin/bun");
    }

    #[test]
    fn flat_tarball_packs_launch_layers() {
        let d = tempdir().unwrap();
        let app = d.path().join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("index.ts"), b"console.log(1)").unwrap();
        let dest = d.path().join("rootfs.tar.gz");
        pack_flat_tarball(&sample_output(&app), &dest).unwrap();
        assert!(dest.exists());
        let bytes = std::fs::read(&dest).unwrap();
        // gzip magic
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
        assert!(bytes.len() > 20);
    }

    #[test]
    fn sha256_is_stable_and_prefixed() {
        let d = tempdir().unwrap();
        let p = d.path().join("blob");
        std::fs::write(&p, b"hello").unwrap();
        let h = sha256_file(&p).unwrap();
        assert_eq!(
            h,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
