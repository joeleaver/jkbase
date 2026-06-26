//! The Dockerfile buildpack — the gated "bring your own Dockerfile" escape hatch.
//!
//! Unlike the language buildpacks (which emit a THIN app layer composed over the
//! shared Wolfi base + a platform runtime layer), this buildpack builds a
//! user-authored Dockerfile *server-side* with `buildah` and emits ONE
//! self-contained `App` layer that is the whole merged image rootfs. The runtime
//! runs it in single-layer "image/self" mode (no base/runtime stacking) — see
//! `jkbase-server::layer_plan`.
//!
//! Phase split, dictated by the host-enforced network seal:
//! - [`fetch`](DockerfileBuildpack::fetch) runs the ENTIRE `buildah build`
//!   (`FROM` pull + every `RUN`) while the network is up, through the egress
//!   proxy. A Dockerfile build is monolithic — it cannot be decomposed into our
//!   fetch/compile phases — so the whole thing lives in the network-up window and
//!   the host seals afterwards (P0-3: the export/unpack is offline + the host
//!   never parses the image; `mkfs.erofs` runs in-VM and the host reads the blob
//!   back via debugfs + sha256).
//! - [`compile`](DockerfileBuildpack::compile) is offline: `buildah mount` yields
//!   the already-flattened rootfs (buildah applies whiteouts/opaque dirs itself —
//!   we never hand-roll an OCI layer parser) and `buildah inspect` yields the OCI
//!   image config, which [`oci_config_to_launch`] translates into the launch
//!   command/env/working_dir.
//!
//! `buildah`/`crun` are baked into the dockerfile toolchain image and run as root
//! inside the build VM (the VM is the security boundary — CNB's untrusted-builder
//! mode is not our boundary). The orchestration shells out and is exercised
//! on-box; the OCI-config translation is pure and unit-tested.

use crate::buildpack::{
    BuildContext, BuildOutput, Buildpack, Decision, DetectContext, Layer, LayerTypes, Process,
};
use anyhow::{Context, Result};
use jkbuild_types::LayerRole;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Image tag built into the in-VM container store, then mounted/inspected.
const IMAGE_TAG: &str = "jkbuild-app:latest";
/// Working-container name created from the built image in `compile`.
const WORK_CTR: &str = "jkbuild-ctr";

pub struct DockerfileBuildpack;

impl Buildpack for DockerfileBuildpack {
    fn id(&self) -> &'static str {
        "jkbase/dockerfile"
    }

    fn detect(&self, ctx: &DetectContext) -> Decision {
        // An explicit `builder = "dockerfile"` is authoritative.
        if ctx.builder_hint == Some("dockerfile") {
            return Decision::pass(100);
        }
        // In auto mode, a lone Dockerfile is a low-confidence fallback: a real
        // language buildpack (higher confidence) wins when both are present, so a
        // Node app that happens to ship a Dockerfile still gets the buildpack.
        if ctx.app_dir.join("Dockerfile").exists() {
            return Decision::pass(15);
        }
        Decision::Fail
    }

    fn fetch(&self, ctx: &mut BuildContext) -> Result<()> {
        // Whole build runs network-up: FROM pull + every RUN. Storage lives on
        // the scratch drive (the big RW drive), alongside the layers/workspace.
        let (root, runroot) = storage_dirs(ctx);
        std::fs::create_dir_all(&root).ok();
        std::fs::create_dir_all(&runroot).ok();

        let dockerfile = ctx.dockerfile.as_deref().unwrap_or("Dockerfile");
        let dockerfile_abs = ctx.app_dir.join(dockerfile);
        if !dockerfile_abs.exists() {
            anyhow::bail!(
                "Dockerfile not found at {} (set `dockerfile = \"<path>\"` in jkbase.toml)",
                dockerfile_abs.display()
            );
        }

        let mut cmd = buildah(&root, &runroot);
        cmd.arg("build")
            // chroot isolation: no nested pid/user-ns gymnastics for RUN steps in
            // the constrained guest; we are already root inside the sealed VM.
            .arg("--isolation")
            .arg("chroot")
            // host networking: RUN steps share the VM's net namespace and reach the
            // egress proxy via HTTP_PROXY — no netavark/CNI bridge (which needs the
            // read-only /run/lock + a netavark binary we don't ship).
            .arg("--network")
            .arg("host")
            // native overlay (the guest kernel has OVERLAY_FS); buildah falls back
            // to fuse-overlayfs (also baked in) if the driver rejects it.
            .arg("--storage-driver")
            .arg("overlay")
            .arg("-f")
            .arg(&dockerfile_abs)
            .arg("-t")
            .arg(IMAGE_TAG)
            .arg(ctx.app_dir);
        apply_proxy(&mut cmd, ctx);
        run("buildah build", cmd)
    }

    fn compile(&self, ctx: &mut BuildContext) -> Result<BuildOutput> {
        // Offline: flatten + read config from the image built during fetch.
        let (root, runroot) = storage_dirs(ctx);

        // Working container from the built image, then mount its merged rootfs.
        // `buildah mount` applies every layer's whiteouts/opaque-dirs for us, so
        // we ingest one already-merged tree — no hand-rolled OCI layer assembly.
        let mut from = buildah(&root, &runroot);
        from.arg("from").arg("--name").arg(WORK_CTR).arg(IMAGE_TAG);
        run("buildah from", from)?;

        let mut mount = buildah(&root, &runroot);
        mount.arg("mount").arg(WORK_CTR);
        let mountpoint = capture("buildah mount", mount)?;
        let mountpoint = PathBuf::from(mountpoint.trim());
        if !mountpoint.is_dir() {
            anyhow::bail!(
                "buildah mount returned a non-directory: {}",
                mountpoint.display()
            );
        }

        // OCI image config → launch command/env/working_dir.
        let mut inspect = buildah(&root, &runroot);
        inspect
            .arg("inspect")
            .arg("--type")
            .arg("image")
            .arg("--format")
            .arg("{{json .OCIv1.Config}}")
            .arg(IMAGE_TAG);
        let config_json = capture("buildah inspect", inspect)?;
        let launch = oci_config_to_launch(&config_json)
            .context("translating OCI image config into a launch spec")?;

        // The single self-contained App layer is the whole merged rootfs (its own
        // libc, /bin/sh, entrypoint) — NOT rooted under /app like the bun layer.
        let app_layer = Layer {
            name: "app".to_string(),
            path: mountpoint,
            types: LayerTypes {
                build: false,
                launch: true,
                cache: false,
            },
            role: LayerRole::App,
        };

        Ok(BuildOutput {
            layers: vec![app_layer],
            processes: vec![Process {
                r#type: "web".to_string(),
                command: launch.argv,
                default: true,
            }],
            env: launch.env,
            working_dir: Some(launch.working_dir),
        })
    }
}

/// A launch spec distilled from an OCI image config.
#[derive(Debug, PartialEq, Eq)]
pub struct Launch {
    /// Effective argv: `Entrypoint` ++ `Cmd` (OCI semantics).
    pub argv: Vec<String>,
    /// Launch env from the image's `Env` (`KEY=VALUE` pairs).
    pub env: BTreeMap<String, String>,
    /// `WorkingDir`, defaulting to `/`.
    pub working_dir: String,
}

/// The OCI image config subset we honour (`buildah inspect .OCIv1.Config`). All
/// fields are optional and may be JSON `null` — hence `Option`.
#[derive(Debug, Default, Deserialize)]
struct OciConfig {
    #[serde(default, rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(default, rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    working_dir: Option<String>,
}

/// Translate an OCI image-config JSON string into a [`Launch`]. Pure (no I/O) so
/// it is unit-tested without buildah.
///
/// OCI semantics: the effective command is `Entrypoint` followed by `Cmd`.
/// Dockerfile shell-form (`CMD foo bar`) is normalised by buildah to exec-form
/// (`["/bin/sh","-c","foo bar"]`) in the stored config, so reading the arrays is
/// faithful. An empty result is an error — the host would otherwise substitute
/// `/bin/sh`, which is never what a deployed server wants.
pub fn oci_config_to_launch(config_json: &str) -> Result<Launch> {
    let cfg: OciConfig = serde_json::from_str(config_json)
        .with_context(|| format!("parsing OCI image config: {config_json}"))?;

    let mut argv = cfg.entrypoint.unwrap_or_default();
    argv.extend(cfg.cmd.unwrap_or_default());
    if argv.is_empty() {
        anyhow::bail!(
            "image declares no ENTRYPOINT or CMD — add one to the Dockerfile, or set `command = [...]` in jkbase.toml"
        );
    }

    let mut env = BTreeMap::new();
    for kv in cfg.env.unwrap_or_default() {
        if let Some((k, v)) = kv.split_once('=') {
            env.insert(k.to_string(), v.to_string());
        }
    }

    let working_dir = match cfg.working_dir {
        Some(d) if !d.is_empty() => d,
        _ => "/".to_string(),
    };

    Ok(Launch {
        argv,
        env,
        working_dir,
    })
}

/// Container storage on the scratch drive (sibling of the layers dir), so it
/// draws from the build's scratch budget rather than the small output drive.
fn storage_dirs(ctx: &BuildContext) -> (PathBuf, PathBuf) {
    let scratch = ctx.layers_dir.parent().unwrap_or(ctx.layers_dir);
    (
        scratch.join("containers/storage"),
        scratch.join("containers/run"),
    )
}

/// A `buildah` command pinned to the in-VM scratch storage root/runroot, with
/// TMPDIR/HOME redirected onto the scratch drive: the toolchain rootfs is mounted
/// READ-ONLY, so buildah's default `/var/tmp` build-context overlay (and any
/// $HOME state) must live on the writable scratch fs instead.
fn buildah(root: &Path, runroot: &Path) -> Command {
    // root = <scratch>/containers/storage → scratch is two parents up.
    let scratch = root.parent().and_then(|p| p.parent()).unwrap_or(root);
    let tmp = scratch.join("tmp");
    let home = scratch.join("home");
    let _ = std::fs::create_dir_all(&tmp);
    let _ = std::fs::create_dir_all(&home);
    let mut cmd = Command::new("buildah");
    cmd.arg("--root").arg(root).arg("--runroot").arg(runroot);
    cmd.env("TMPDIR", &tmp).env("HOME", &home);
    cmd
}

/// Apply the egress-proxy env so `FROM`/`RUN` reach the network through the proxy
/// (fetch phase only). `BUILDAH_*`/standard proxy vars are honoured by buildah and
/// inherited by `RUN` steps under chroot isolation.
fn apply_proxy(cmd: &mut Command, ctx: &BuildContext) {
    if let Some(proxy) = &ctx.proxy {
        cmd.env("HTTP_PROXY", proxy)
            .env("HTTPS_PROXY", proxy)
            .env("http_proxy", proxy)
            .env("https_proxy", proxy);
    }
}

/// Run a command to completion, capturing combined output so a failure surfaces
/// the tool's actual error (buildah's stderr otherwise vanishes to the VM console).
fn run(what: &str, mut cmd: Command) -> Result<()> {
    use std::io::Write;
    let out = cmd.output().with_context(|| format!("spawning `{what}`"))?;
    // Stream output to the console too (so a successful build still logs progress).
    let _ = std::io::stderr().write_all(&out.stderr);
    if !out.status.success() {
        let tail: String = {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            combined
                .lines()
                .rev()
                .take(40)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        };
        anyhow::bail!("{what} failed: {}\n{}", out.status, tail);
    }
    Ok(())
}

/// Run a command, returning its stdout (trimmed by the caller). Fails on non-zero.
fn capture(what: &str, mut cmd: Command) -> Result<String> {
    let out = cmd.output().with_context(|| format!("spawning `{what}`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{what} failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entrypoint_and_cmd_concatenate() {
        let cfg = r#"{"Entrypoint":["docker-entrypoint.sh"],"Cmd":["node","server.js"]}"#;
        let l = oci_config_to_launch(cfg).unwrap();
        assert_eq!(l.argv, vec!["docker-entrypoint.sh", "node", "server.js"]);
        assert_eq!(l.working_dir, "/");
    }

    #[test]
    fn cmd_only_and_env_and_workdir() {
        let cfg = r#"{"Cmd":["/app/server"],"Env":["PATH=/usr/bin:/bin","PORT=3000"],"WorkingDir":"/app"}"#;
        let l = oci_config_to_launch(cfg).unwrap();
        assert_eq!(l.argv, vec!["/app/server"]);
        assert_eq!(l.env.get("PATH").map(String::as_str), Some("/usr/bin:/bin"));
        assert_eq!(l.env.get("PORT").map(String::as_str), Some("3000"));
        assert_eq!(l.working_dir, "/app");
    }

    #[test]
    fn shell_form_cmd_is_already_normalised_by_buildah() {
        // Dockerfile `CMD npm start` → buildah stores exec-form with /bin/sh -c.
        let cfg = r#"{"Cmd":["/bin/sh","-c","npm start"]}"#;
        let l = oci_config_to_launch(cfg).unwrap();
        assert_eq!(l.argv, vec!["/bin/sh", "-c", "npm start"]);
    }

    #[test]
    fn null_fields_default_cleanly() {
        // buildah emits explicit nulls for unset fields.
        let cfg = r#"{"Entrypoint":null,"Cmd":["/server"],"Env":null,"WorkingDir":null}"#;
        let l = oci_config_to_launch(cfg).unwrap();
        assert_eq!(l.argv, vec!["/server"]);
        assert!(l.env.is_empty());
        assert_eq!(l.working_dir, "/");
    }

    #[test]
    fn empty_entrypoint_and_cmd_is_an_error() {
        let cfg = r#"{"Env":["FOO=bar"]}"#;
        assert!(oci_config_to_launch(cfg).is_err());
        // Empty arrays too.
        assert!(oci_config_to_launch(r#"{"Entrypoint":[],"Cmd":[]}"#).is_err());
    }

    #[test]
    fn env_without_equals_is_skipped() {
        let cfg = r#"{"Cmd":["/s"],"Env":["GOOD=1","MALFORMED","ALSO=2"]}"#;
        let l = oci_config_to_launch(cfg).unwrap();
        assert_eq!(l.env.len(), 2);
        assert_eq!(l.env.get("GOOD").map(String::as_str), Some("1"));
        assert_eq!(l.env.get("ALSO").map(String::as_str), Some("2"));
    }
}
