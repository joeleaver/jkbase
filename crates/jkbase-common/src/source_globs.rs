//! The one path-glob dialect for tenant source filtering, and the project-level deploy
//! `ignore` list built on it.
//!
//! **Dialect** (shared with a target's build-input `exclude`): anchored at a root, `*`/`?`
//! stay within one path segment, `**` crosses them, `\` escapes. A match on a directory
//! drops its whole subtree.
//!
//! **Deploy ignore** (`[project] ignore = [...]`): paths that are never part of a deployment.
//! It is enforced twice from this one matcher — by the CLI, so an ignored file never leaves
//! the tenant's machine, and by the host right after it unpacks the source, so a git-push
//! deploy (archived server-side) or an older CLI gets the same tree, and an ignored path can
//! neither be served by a committed site nor reach a build mount or build key. `jkbase.toml`
//! is never ignored: the host reads the manifest before it can know the list.
//!
//! The patterns are tenant input evaluated on the host, so they are bounded and confined
//! (relative, no `..`), and [`DeployIgnore::prune`] never follows a symlink.

use std::path::Path;

use anyhow::{Context, Result, bail};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// Bounds on one tenant-authored pattern list.
pub const MAX_PATTERNS: usize = 64;
pub const MAX_PATTERN_LEN: usize = 256;

/// Always shipped, whatever the ignore list says.
const MANIFEST: &str = "jkbase.toml";

/// Compile `patterns` in the shared dialect.
pub fn compile_globs(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let glob = GlobBuilder::new(p)
            .literal_separator(true)
            .backslash_escape(true)
            .build()
            .with_context(|| format!("invalid pattern {p:?}"))?;
        b.add(glob);
    }
    b.build().context("compile patterns")
}

/// Bound + confine a tenant pattern list (count, length, relative, no `..`), then compile it.
/// A leading `./` and a trailing `/` are dropped first: matching is against bare relative
/// paths, so the gitignore-habit spellings `secrets/` / `./secrets` would otherwise silently
/// match nothing — and an "ignored" file would still ship.
pub fn validate_globs(what: &str, patterns: &[String]) -> Result<GlobSet> {
    if patterns.len() > MAX_PATTERNS {
        bail!("{what} has {} patterns; max {MAX_PATTERNS}", patterns.len());
    }
    let mut normalized = Vec::with_capacity(patterns.len());
    for p in patterns {
        if p.trim().is_empty() || p.len() > MAX_PATTERN_LEN {
            bail!("{what} pattern {p:?} must be 1-{MAX_PATTERN_LEN} bytes");
        }
        if p.starts_with('/') || p.split('/').any(|seg| seg == "..") {
            bail!("{what} pattern {p:?} must be relative (no leading '/' or '..')");
        }
        let n = p.trim_start_matches("./").trim_end_matches('/');
        if n.is_empty() || n == "." {
            bail!("{what} pattern {p:?} names the whole root");
        }
        normalized.push(n.to_string());
    }
    compile_globs(&normalized).with_context(|| what.to_string())
}

/// The project-level deploy ignore list, anchored at the project root.
pub struct DeployIgnore {
    globs: GlobSet,
}

impl DeployIgnore {
    pub fn new(patterns: &[String]) -> Result<Self> {
        Ok(Self { globs: validate_globs("[project] ignore", patterns)? })
    }

    /// Whether the entry at root-relative `rel` (`/`-separated) is left out of the deployment.
    pub fn ignored(&self, rel: &str) -> bool {
        rel != MANIFEST && self.globs.is_match(rel)
    }

    /// Remove every ignored entry under `root` in place; returns how many were removed. A
    /// symlink is removed as a link and never followed; only real directories are descended.
    pub fn prune(&self, root: &Path) -> Result<usize> {
        if self.globs.is_empty() {
            return Ok(0);
        }
        fn walk(ig: &DeployIgnore, dir: &Path, rel: &str, removed: &mut usize) -> Result<()> {
            for entry in std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let child_rel = if rel.is_empty() { name_str.to_string() } else { format!("{rel}/{name_str}") };
                let path = entry.path();
                // `DirEntry::file_type` does not follow symlinks.
                let ft = entry.file_type()?;
                if ig.ignored(&child_rel) {
                    if ft.is_dir() {
                        std::fs::remove_dir_all(&path)
                    } else {
                        std::fs::remove_file(&path)
                    }
                    .with_context(|| format!("remove ignored {child_rel}"))?;
                    *removed += 1;
                } else if ft.is_dir() {
                    walk(ig, &path, &child_rel, removed)?;
                }
            }
            Ok(())
        }
        let mut removed = 0;
        walk(self, root, "", &mut removed)?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ig(p: &[&str]) -> DeployIgnore {
        DeployIgnore::new(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn dialect_is_anchored_and_segment_bounded() {
        let i = ig(&["docs", "*.log", "**/fixtures", ".env*"]);
        assert!(i.ignored("docs"));
        assert!(!i.ignored("site/docs"), "anchored at the root");
        assert!(i.ignored("debug.log"));
        assert!(!i.ignored("logs/debug.log"), "`*` stays within one segment");
        assert!(i.ignored("a/b/fixtures"));
        assert!(i.ignored(".env.local"));
        assert!(!i.ignored("src/main.rs"));
    }

    #[test]
    fn gitignore_spellings_still_match() {
        let i = ig(&["secrets/", "./data", "./logs/"]);
        assert!(i.ignored("secrets"));
        assert!(i.ignored("data"));
        assert!(i.ignored("logs"));
        for root in ["./", ".", "./."] {
            assert!(DeployIgnore::new(&[root.to_string()]).is_err(), "should reject {root:?}");
        }
    }

    #[test]
    fn manifest_is_never_ignored() {
        let i = ig(&["*.toml", "*"]);
        assert!(!i.ignored("jkbase.toml"));
        assert!(i.ignored("Cargo.toml"));
    }

    #[test]
    fn rejects_unbounded_or_escaping_patterns() {
        for bad in ["", "/etc", "../x", "a/../b", "[unclosed"] {
            assert!(DeployIgnore::new(&[bad.to_string()]).is_err(), "should reject {bad:?}");
        }
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert!(DeployIgnore::new(&[long]).is_err());
        let many = vec!["a".to_string(); MAX_PATTERNS + 1];
        assert!(DeployIgnore::new(&many).is_err());
    }

    #[test]
    fn prune_removes_matches_and_never_follows_symlinks() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("jkb-ignore-{nanos}"));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("data/nested")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), b"x").unwrap();
        std::fs::write(root.join("data/nested/big.bin"), b"x").unwrap();
        std::fs::write(root.join("src/main.rs"), b"x").unwrap();
        std::fs::write(root.join(".env"), b"SECRET=1").unwrap();
        std::fs::write(root.join("jkbase.toml"), b"").unwrap();
        // An ignored symlink to a directory outside the root: the LINK goes, the target stays.
        std::os::unix::fs::symlink(&outside, root.join("data-link")).unwrap();
        // A kept symlink to a directory is not descended into.
        std::os::unix::fs::symlink(&outside, root.join("src/out")).unwrap();

        let i = ig(&["data", "data-link", ".env", "*.toml", "src/out/keep.txt"]);
        assert_eq!(i.prune(&root).unwrap(), 3);
        assert!(!root.join("data").exists());
        assert!(std::fs::symlink_metadata(root.join("data-link")).is_err());
        assert!(!root.join(".env").exists());
        assert!(root.join("jkbase.toml").exists());
        assert!(root.join("src/main.rs").exists());
        assert!(outside.join("keep.txt").exists(), "must not follow symlinks out of the root");

        let _ = std::fs::remove_dir_all(&base);
    }
}
