//! Per-target build reuse: a deploy rebuilds only the targets whose build inputs changed.
//!
//! Every build target gets a host-computed **build key** — a sha256 over everything that
//! determines its artifact: a format version, the target's build-affecting config, the
//! resolved toolchain image digest (a toolchain rebake changes it), the agent digest for a
//! function (its `.cwasm` is agent-compiled), and a canonical digest of the exact tree the
//! build VM mounts. When a previous build of the same target produced the same key, its
//! artifact is reused from the host-owned cache instead of booting a build VM.
//!
//! **Input = mount, by construction.** The key hashes the materialized input directory, and
//! that same directory is what becomes the RO source image. Anything excluded — other sites'
//! committed `public` dirs and `jkbase.toml` automatically, plus the target's own `exclude`
//! globs — is absent from BOTH, so a change there can't be missed by the key AND can't
//! influence the build. That is what lets a `context = "."` monorepo edit its static site
//! without rebuilding its Rust servers, with no way for a reuse to be stale.
//!
//! **Trust.** The cache lives on the host (`buildcache/<project>/targets/`), is written only
//! by the host after the artifact passed the same collection checks as a fresh build, is
//! per-project (never shared across tenants), and is re-verified (sha256 of every cached
//! file against its entry) before reuse. A tenant's build VM never sees it. Reuse only ever
//! hands a project back an artifact its own earlier build produced from identical inputs.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use jkbase_common::config::ProjectConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bump whenever the key's inputs, the cache entry format, or host-side artifact
/// collection change what a reused artifact would mean — every existing entry then misses.
pub(crate) const BUILD_KEY_VERSION: u32 = 1;

/// Cache entries kept per target (the live build plus the one before it).
const KEEP_ENTRIES_PER_TARGET: usize = 2;

/// Bounds on a target's `exclude` list (tenant input).
pub(crate) const MAX_EXCLUDE_PATTERNS: usize = 64;
pub(crate) const MAX_EXCLUDE_PATTERN_LEN: usize = 256;

/// `./a/b/` → `a/b`; empty → `.`.
fn norm(p: &str) -> String {
    let t = p.trim_start_matches("./").trim_end_matches('/');
    if t.is_empty() { ".".to_string() } else { t.to_string() }
}

/// Whether normalized `child` is `parent` or lives under it.
fn inside(child: &str, parent: &str) -> bool {
    parent == "." || child == parent || child.starts_with(&format!("{parent}/"))
}

/// Compile `exclude` patterns: anchored at the context root, `*`/`?` within one segment,
/// `**` across segments, `\` escapes.
fn compile_globs(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let glob = GlobBuilder::new(p)
            .literal_separator(true)
            .backslash_escape(true)
            .build()
            .with_context(|| format!("invalid exclude pattern {p:?}"))?;
        b.add(glob);
    }
    b.build().context("compile exclude patterns")
}

/// Intake validation of a target's `exclude` list (fully tenant-controlled): bounded, relative,
/// no `..`, compilable, and never matching the target's own source dir (or an ancestor of it)
/// — which would remove the very tree the build runs in.
pub(crate) fn validate_exclude(what: &str, patterns: &[String], build_subdir: &str) -> Result<()> {
    if patterns.len() > MAX_EXCLUDE_PATTERNS {
        bail!("{what} has {} exclude patterns; max {MAX_EXCLUDE_PATTERNS}", patterns.len());
    }
    for p in patterns {
        if p.trim().is_empty() || p.len() > MAX_EXCLUDE_PATTERN_LEN {
            bail!("{what} exclude pattern {p:?} must be 1-{MAX_EXCLUDE_PATTERN_LEN} bytes");
        }
        if p.starts_with('/') || p.split('/').any(|seg| seg == "..") {
            bail!("{what} exclude pattern {p:?} must be relative to the build context (no leading '/' or '..')");
        }
    }
    let set = compile_globs(patterns).with_context(|| what.to_string())?;
    let bs = norm(build_subdir);
    if bs != "." {
        let mut prefix = String::new();
        for seg in bs.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(seg);
            if set.is_match(&prefix) {
                bail!("{what} exclude patterns remove {prefix:?}, which contains the target's own source {bs:?}");
            }
        }
    }
    Ok(())
}

/// The automatic exclusions for a target building from `context` with source `source` (both
/// relative to the project root), as literal paths relative to the context:
/// - `jkbase.toml` when the context is the project root — the platform's manifest, never a
///   build input (the target's build-affecting config is keyed separately);
/// - every COMMITTED site's `public` dir inside the context — unless the target's source lives
///   inside it, or it is the context itself. Served as-is; not what a server or a built site
///   compiles. (A build that reads it anyway fails loudly, since the dir isn't mounted.)
pub(crate) fn auto_excludes(config: &ProjectConfig, context: &str, source: &str) -> Vec<String> {
    let (c, s) = (norm(context), norm(source));
    let mut out = BTreeSet::new();
    if c == "." {
        out.insert("jkbase.toml".to_string());
    }
    for site in config.resolved_sites().iter().filter(|site| !site.built) {
        let p = norm(&site.public);
        if p == "." || p == c || !inside(&p, &c) || inside(&s, &p) {
            continue;
        }
        out.insert(jkbase_common::config::rel_within(&c, &p));
    }
    out.into_iter().collect()
}

/// What to leave out of one target's build input.
pub(crate) struct Exclusions {
    paths: BTreeSet<String>,
    globs: GlobSet,
}

impl Exclusions {
    pub(crate) fn new(paths: &[String], patterns: &[String]) -> Result<Self> {
        Ok(Self {
            paths: paths.iter().map(|p| norm(p)).collect(),
            globs: compile_globs(patterns)?,
        })
    }

    fn excluded(&self, rel: &str) -> bool {
        self.paths.contains(rel) || self.globs.is_match(rel)
    }
}

/// Materialize a target's build input at `dest`: `context` minus `ex`, hard-linked (falling
/// back to a copy) so it costs no data. Symlinks are recreated verbatim, never followed; an
/// excluded directory drops its whole subtree. Returns how many entries were excluded.
pub(crate) fn materialize_input(context: &Path, ex: &Exclusions, dest: &Path) -> Result<usize> {
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest).with_context(|| format!("create build input {}", dest.display()))?;
    let root_mode = std::fs::metadata(context)?.mode() & 0o7777;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(root_mode))?;
    let mut dropped = 0usize;
    fn walk(src: &Path, dst: &Path, rel: &str, ex: &Exclusions, dropped: &mut usize) -> Result<()> {
        for entry in sorted_entries(src)? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let child_rel = if rel.is_empty() { name_str.to_string() } else { format!("{rel}/{name_str}") };
            if ex.excluded(&child_rel) {
                *dropped += 1;
                continue;
            }
            let from = entry.path();
            let to = dst.join(&name);
            let md = std::fs::symlink_metadata(&from)?;
            let ft = md.file_type();
            if ft.is_symlink() {
                std::os::unix::fs::symlink(std::fs::read_link(&from)?, &to)?;
            } else if ft.is_dir() {
                std::fs::create_dir(&to)?;
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(md.mode() & 0o7777))?;
                walk(&from, &to, &child_rel, ex, dropped)?;
            } else if ft.is_file() && std::fs::hard_link(&from, &to).is_err() {
                std::fs::copy(&from, &to)?;
            }
            // Anything else (fifo, device) is neither mounted nor hashed.
        }
        Ok(())
    }
    walk(context, dest, "", ex, &mut dropped)?;
    Ok(dropped)
}

fn sorted_entries(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    Ok(entries)
}

/// File content digests memoized by `(dev, ino)` for one build: every target's input is
/// hard-linked from the same unpacked source, so a file shared by several targets is read once.
#[derive(Default)]
pub(crate) struct DigestMemo(std::sync::Mutex<HashMap<(u64, u64), [u8; 32]>>);

/// Canonical digest of a tree: every entry in byte order of its relative path, framed with its
/// type — directories with their mode, files with mode + size + content sha256, symlinks with
/// their target. Mtimes and ownership are ignored (they don't change what a build produces).
pub(crate) fn tree_digest(dir: &Path, memo: &DigestMemo) -> Result<String> {
    let mut h = Sha256::new();
    fn frame(h: &mut Sha256, bytes: &[u8]) {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    fn walk(h: &mut Sha256, dir: &Path, rel: &[u8], memo: &DigestMemo) -> Result<()> {
        for entry in sorted_entries(dir)? {
            let name = entry.file_name();
            // Raw name bytes, so two non-UTF-8 names can never frame identically.
            let mut child_rel = rel.to_vec();
            if !child_rel.is_empty() {
                child_rel.push(b'/');
            }
            child_rel.extend_from_slice(std::os::unix::ffi::OsStrExt::as_bytes(name.as_os_str()));
            let path = entry.path();
            let md = std::fs::symlink_metadata(&path)?;
            let ft = md.file_type();
            if ft.is_symlink() {
                h.update(b"L");
                frame(h, &child_rel);
                frame(h, std::os::unix::ffi::OsStrExt::as_bytes(std::fs::read_link(&path)?.as_os_str()));
            } else if ft.is_dir() {
                h.update(b"D");
                frame(h, &child_rel);
                h.update((md.mode() & 0o7777).to_le_bytes());
                walk(h, &path, &child_rel, memo)?;
            } else if ft.is_file() {
                h.update(b"F");
                frame(h, &child_rel);
                h.update((md.mode() & 0o7777).to_le_bytes());
                h.update(md.len().to_le_bytes());
                h.update(file_sha256(&path, &md, memo)?);
            }
        }
        Ok(())
    }
    walk(&mut h, dir, b"", memo)?;
    Ok(hex(&h.finalize()))
}

fn file_sha256(path: &Path, md: &std::fs::Metadata, memo: &DigestMemo) -> Result<[u8; 32]> {
    let id = (md.dev(), md.ino());
    if let Some(d) = memo.0.lock().unwrap_or_else(|p| p.into_inner()).get(&id) {
        return Ok(*d);
    }
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let d: [u8; 32] = h.finalize().into();
    memo.0.lock().unwrap_or_else(|p| p.into_inner()).insert(id, d);
    Ok(d)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Everything a target's artifact is a function of. Serialized (field order fixed) and hashed
/// into the build key.
#[derive(Serialize)]
pub(crate) struct KeyInputs<'a> {
    pub version: u32,
    pub kind: &'a str,
    pub name: &'a str,
    pub context_subdir: &'a str,
    pub build_subdir: &'a str,
    pub language: Option<&'a str>,
    pub builder: &'a str,
    pub dockerfile: Option<&'a str>,
    pub exclude_paths: &'a [String],
    pub exclude_globs: &'a [String],
    /// The resolved toolchain image's file name and `sha256:` digest.
    pub toolchain: (&'a str, &'a str),
    /// The agent binary digest (functions only: it AOT-compiles the `.cwasm`).
    pub agent: Option<&'a str>,
    /// [`tree_digest`] of the materialized build input.
    pub tree: &'a str,
}

pub(crate) fn build_key(inputs: &KeyInputs<'_>) -> String {
    let json = serde_json::to_vec(inputs).expect("key inputs serialize");
    hex(&Sha256::digest(json))
}

/// A cached artifact's metadata; the files sit beside it in the entry dir.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct CacheEntry {
    pub version: u32,
    pub key: String,
    pub artifact: CachedArtifact,
    /// `file name in the entry dir → sha256 hex`, verified before reuse.
    pub files: BTreeMap<String, String>,
}

/// What a reuse needs to re-create the target's staged output exactly as its build did,
/// with the CURRENT jkbase.toml applied on top (port, health check, volumes, command).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CachedArtifact {
    /// A layered server: its app erofs layer (`app.erofs`) + the build-derived launch fields.
    Server {
        app_file: String,
        app_digest: String,
        cmd: Vec<String>,
        env: HashMap<String, String>,
        working_dir: String,
        resolved_language: Option<String>,
    },
    /// A built static site: the flat tarball its build exported (`static.tar.gz`).
    Static,
    /// A function: `function.wasm` (+ `function.cwasm` when precompiled).
    Function,
}

/// The cache of one target of one project.
pub(crate) struct TargetCache {
    dir: PathBuf,
}

impl TargetCache {
    /// `tag` is the orchestrator's `<kind>-<sanitized name>`.
    pub(crate) fn new(data_dir: &Path, project_id: &str, tag: &str) -> Self {
        Self {
            dir: data_dir.join("buildcache").join(project_id).join("targets").join(tag),
        }
    }

    /// The verified entry for `key`, or `None` (absent, unreadable, a different format or key,
    /// or any file failing its recorded sha256 — a miss, never an error).
    pub(crate) fn lookup(&self, key: &str) -> Option<(CacheEntry, PathBuf)> {
        let dir = self.dir.join(key);
        let entry: CacheEntry = serde_json::from_slice(&std::fs::read(dir.join("entry.json")).ok()?).ok()?;
        if entry.version != BUILD_KEY_VERSION || entry.key != key {
            return None;
        }
        for (file, want) in &entry.files {
            if !safe_entry_file(file) {
                return None;
            }
            let md = std::fs::symlink_metadata(dir.join(file)).ok()?;
            if !md.is_file() {
                return None;
            }
            let got = hex(&file_sha256(&dir.join(file), &md, &DigestMemo::default()).ok()?);
            if &got != want {
                tracing::warn!(dir = %dir.display(), file, "build cache entry failed verification; rebuilding");
                return None;
            }
        }
        Some((entry, dir))
    }

    /// Record `artifact` under `key`, linking (or copying) `files` (`name → source path`) into
    /// the entry. Written to a temp dir and renamed into place, then older entries are pruned.
    pub(crate) fn store(&self, key: &str, artifact: CachedArtifact, files: &[(&str, &Path)], build_id: u64) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join(format!(".tmp-{key}-{build_id}"));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let mut hashes = BTreeMap::new();
        for (name, src) in files {
            debug_assert!(safe_entry_file(name));
            let dst = tmp.join(name);
            if std::fs::hard_link(src, &dst).is_err() {
                std::fs::copy(src, &dst).with_context(|| format!("copy {} into build cache", src.display()))?;
            }
            let md = std::fs::metadata(&dst)?;
            hashes.insert(name.to_string(), hex(&file_sha256(&dst, &md, &DigestMemo::default())?));
        }
        let entry = CacheEntry { version: BUILD_KEY_VERSION, key: key.to_string(), artifact, files: hashes };
        std::fs::write(tmp.join("entry.json"), serde_json::to_vec_pretty(&entry)?)?;
        let final_dir = self.dir.join(key);
        let _ = std::fs::remove_dir_all(&final_dir);
        std::fs::rename(&tmp, &final_dir)?;
        self.prune(key);
        Ok(())
    }

    /// Keep the `KEEP_ENTRIES_PER_TARGET` most recently written entries (always `current`), and
    /// reap abandoned temp dirs.
    fn prune(&self, current: &str) {
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return };
        let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for e in rd.flatten() {
            let path = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(".tmp-") {
                let _ = std::fs::remove_dir_all(&path);
                continue;
            }
            if name == current {
                continue;
            }
            let mtime = std::fs::metadata(path.join("entry.json"))
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            entries.push((mtime, path));
        }
        entries.sort_by_key(|e| std::cmp::Reverse(e.0));
        for (_, path) in entries.into_iter().skip(KEEP_ENTRIES_PER_TARGET.saturating_sub(1)) {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

/// Entry file names are fixed by the host; refuse anything else a corrupted entry might name.
fn safe_entry_file(name: &str) -> bool {
    matches!(name, "app.erofs" | "static.tar.gz" | "function.wasm" | "function.cwasm")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("jkb-bc-{tag}-{nanos}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn config(toml: &str) -> ProjectConfig {
        let dir = tmp("cfg");
        write(&dir.join("jkbase.toml"), toml);
        ProjectConfig::load(&dir.join("jkbase.toml")).unwrap()
    }

    const PIMBLE: &str = r#"
[project]
name = "pimble"
[sites.site]
public = "site"
prefix = "/"
[sites.app]
source = "web"
context = "."
build = "trunk"
prefix = "/app"
[servers.cloud]
source = "crates/pimble-cloud"
context = "."
port = 8080
[routes]
"/api/*" = { service = "server", name = "cloud" }
"#;

    #[test]
    fn auto_excludes_drop_committed_sites_and_the_manifest_from_wide_contexts() {
        let cfg = config(PIMBLE);
        assert_eq!(auto_excludes(&cfg, ".", "crates/pimble-cloud"), vec!["jkbase.toml", "site"]);
        assert_eq!(auto_excludes(&cfg, "./", "web"), vec!["jkbase.toml", "site"]);
        // A narrow context contains neither.
        assert!(auto_excludes(&cfg, "crates/pimble-cloud", "crates/pimble-cloud").is_empty());
        // A target whose source lives inside the site dir keeps it.
        assert_eq!(auto_excludes(&cfg, ".", "site/tool"), vec!["jkbase.toml"]);
        // A root-served site (`public = "."`) is never excluded, and a context under the site
        // dir keeps it too.
        let root_site = config("[project]\nname = \"x\"\n[hosting]\npublic = \".\"\n[servers.api]\nsource = \".\"\nport = 3000\n");
        assert_eq!(auto_excludes(&root_site, ".", "."), vec!["jkbase.toml"]);
        assert!(auto_excludes(&cfg, "site", "site").is_empty());
        // Relative to a context that isn't the root.
        let nested = config("[project]\nname = \"x\"\n[sites.docs]\npublic = \"mono/docs\"\n[servers.api]\nsource = \"mono/api\"\ncontext = \"mono\"\nport = 3000\n");
        assert_eq!(auto_excludes(&nested, "mono", "mono/api"), vec!["docs"]);
    }

    #[test]
    fn exclude_validation_bounds_tenant_patterns() {
        let ok = |p: &[&str], bs: &str| validate_exclude("server 'x'", &p.iter().map(|s| s.to_string()).collect::<Vec<_>>(), bs);
        assert!(ok(&["docs", "*.pimble", "**/fixtures", "screens/*.png"], "crates/app").is_ok());
        for bad in ["/etc", "../x", "a/../b", "", "   ", "[unclosed"] {
            assert!(ok(&[bad], ".").is_err(), "{bad:?}");
        }
        assert!(ok(&[&"x".repeat(MAX_EXCLUDE_PATTERN_LEN + 1)], ".").is_err());
        let many: Vec<String> = (0..=MAX_EXCLUDE_PATTERNS).map(|i| format!("d{i}")).collect();
        assert!(validate_exclude("t", &many, ".").is_err());
        // Never the target's own source or an ancestor of it.
        for bad in ["crates", "crates/*", "**/app", "crates/app"] {
            assert!(ok(&[bad], "crates/app").is_err(), "{bad:?}");
        }
        assert!(ok(&["crates/other", "crates/app/tests"], "crates/app").is_ok());
    }

    #[test]
    fn materialized_input_and_its_digest_see_exactly_the_same_tree() {
        let src = tmp("src");
        write(&src.join("Cargo.toml"), "[workspace]");
        write(&src.join("crates/app/src/main.rs"), "fn main() {}");
        write(&src.join("site/index.html"), "<h1>hi</h1>");
        write(&src.join("docs/notes.md"), "notes");
        write(&src.join("store.pimble"), "blob");
        write(&src.join("jkbase.toml"), "[project]");
        std::os::unix::fs::symlink("crates/app", src.join("app-link")).unwrap();
        let ex = Exclusions::new(&["jkbase.toml".into(), "site".into()], &["docs".into(), "*.pimble".into()]).unwrap();
        let out = tmp("out");
        let dest = out.join("input");
        assert_eq!(materialize_input(&src, &ex, &dest).unwrap(), 4);
        assert!(dest.join("crates/app/src/main.rs").is_file());
        for gone in ["site", "docs", "store.pimble", "jkbase.toml"] {
            assert!(!dest.join(gone).exists(), "{gone}");
        }
        assert_eq!(std::fs::read_link(dest.join("app-link")).unwrap(), PathBuf::from("crates/app"));

        let memo = DigestMemo::default();
        let d0 = tree_digest(&dest, &memo).unwrap();
        // An excluded change: the materialized tree — and so the key — is unchanged.
        write(&src.join("site/index.html"), "<h1>changed</h1>");
        write(&src.join("docs/notes.md"), "changed");
        let dest2 = out.join("input2");
        materialize_input(&src, &ex, &dest2).unwrap();
        assert_eq!(tree_digest(&dest2, &DigestMemo::default()).unwrap(), d0);
        // Any included change moves it: content, a new file, a mode bit, a symlink target.
        let fresh = |f: &dyn Fn()| {
            f();
            let d = out.join(format!("in-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            materialize_input(&src, &ex, &d).unwrap();
            tree_digest(&d, &DigestMemo::default()).unwrap()
        };
        let d1 = fresh(&|| write(&src.join("crates/app/src/main.rs"), "fn main() { 1; }"));
        assert_ne!(d1, d0);
        let d2 = fresh(&|| write(&src.join("crates/app/src/lib.rs"), ""));
        assert_ne!(d2, d1);
        let d3 = fresh(&|| std::fs::set_permissions(src.join("Cargo.toml"), std::fs::Permissions::from_mode(0o755)).unwrap());
        assert_ne!(d3, d2);
        let d4 = fresh(&|| {
            std::fs::remove_file(src.join("app-link")).unwrap();
            std::os::unix::fs::symlink("crates", src.join("app-link")).unwrap();
        });
        assert_ne!(d4, d3);
        // A rename is a change even with identical bytes.
        let d5 = fresh(&|| std::fs::rename(src.join("crates/app/src/lib.rs"), src.join("crates/app/src/lib2.rs")).unwrap());
        assert_ne!(d5, d4);
    }

    #[test]
    fn every_key_input_moves_the_key() {
        let paths = vec!["site".to_string()];
        let globs = vec!["docs".to_string()];
        let base = KeyInputs {
            version: BUILD_KEY_VERSION,
            kind: "server",
            name: "cloud",
            context_subdir: ".",
            build_subdir: "crates/cloud",
            language: Some("rust"),
            builder: "auto",
            dockerfile: None,
            exclude_paths: &paths,
            exclude_globs: &globs,
            toolchain: ("rust.ext4", "sha256:aa"),
            agent: None,
            tree: "t0",
        };
        let k = build_key(&base);
        assert_eq!(k, build_key(&KeyInputs { ..base }), "deterministic");
        let other_paths = vec!["site2".to_string()];
        let variants = [
            KeyInputs { version: BUILD_KEY_VERSION + 1, ..base },
            KeyInputs { kind: "static", ..base },
            KeyInputs { name: "cloud2", ..base },
            KeyInputs { context_subdir: "crates", ..base },
            KeyInputs { build_subdir: "crates/other", ..base },
            KeyInputs { language: None, ..base },
            KeyInputs { builder: "dockerfile", ..base },
            KeyInputs { dockerfile: Some("Dockerfile"), ..base },
            KeyInputs { exclude_paths: &other_paths, ..base },
            KeyInputs { exclude_globs: &other_paths, ..base },
            KeyInputs { toolchain: ("rust.ext4", "sha256:bb"), ..base },
            KeyInputs { agent: Some("sha256:cc"), ..base },
            KeyInputs { tree: "t1", ..base },
        ];
        for v in &variants {
            assert_ne!(build_key(v), k);
        }
    }

    #[test]
    fn cache_entries_verify_prune_and_miss_on_tamper() {
        let data = tmp("data");
        let cache = TargetCache::new(&data, "proj", "server-cloud");
        let art = tmp("art");
        write(&art.join("layer"), "erofs bytes");
        let artifact = CachedArtifact::Server {
            app_file: format!("sha256-{}.erofs", "a".repeat(64)),
            app_digest: "sha256:x".into(),
            cmd: vec!["/app/cloud".into()],
            env: HashMap::new(),
            working_dir: "/app".into(),
            resolved_language: Some("rust".into()),
        };
        assert!(cache.lookup("k1").is_none());
        cache.store("k1", artifact.clone(), &[("app.erofs", &art.join("layer"))], 1).unwrap();
        let (entry, dir) = cache.lookup("k1").unwrap();
        assert_eq!(entry.artifact, artifact);
        assert_eq!(std::fs::read_to_string(dir.join("app.erofs")).unwrap(), "erofs bytes");
        // A different key misses.
        assert!(cache.lookup("k2").is_none());

        // Tampered bytes (a new inode, as a rewrite would be) fail verification → miss.
        std::fs::remove_file(dir.join("app.erofs")).unwrap();
        std::fs::write(dir.join("app.erofs"), "evil").unwrap();
        assert!(cache.lookup("k1").is_none());
        // A forged file name in the entry → miss.
        cache.store("k1", artifact.clone(), &[("app.erofs", &art.join("layer"))], 2).unwrap();
        let mut forged = cache.lookup("k1").unwrap().0;
        forged.files.insert("../../escape".into(), "00".into());
        std::fs::write(cache.dir.join("k1/entry.json"), serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(cache.lookup("k1").is_none());

        // Pruning keeps the newest two entries.
        for (i, k) in ["k3", "k4", "k5"].iter().enumerate() {
            std::thread::sleep(std::time::Duration::from_millis(15));
            cache.store(k, artifact.clone(), &[("app.erofs", &art.join("layer"))], 10 + i as u64).unwrap();
        }
        let mut left: Vec<String> = std::fs::read_dir(&cache.dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        left.sort();
        assert_eq!(left, vec!["k4", "k5"]);
    }
}
