//! Layer environment accumulation. A trimmed analogue of libcnb's `LayerEnv`:
//! buildpacks contribute env (overrides + `PATH`-style prepends) that flows to
//! subprocesses at build time and into the launch manifest at runtime. We only
//! implement the operations our buildpacks actually use.

use std::collections::BTreeMap;

/// An ordered, deterministic environment map. `BTreeMap` keeps serialization and
/// `PATH` composition stable across runs (reproducibility matters for the cache
/// key and SBOM).
#[derive(Debug, Default, Clone)]
pub struct BuildEnv {
    vars: BTreeMap<String, String>,
}

impl BuildEnv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override `key` with `value`.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.vars.insert(key.into(), value.into());
    }

    /// Prepend `dir` to `PATH` (colon-separated), creating it if absent.
    pub fn prepend_path(&mut self, dir: &str) {
        let entry = self.vars.entry("PATH".to_string()).or_default();
        *entry = if entry.is_empty() {
            dir.to_string()
        } else {
            format!("{dir}:{entry}")
        };
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.vars.iter()
    }

    /// The underlying map (e.g. to seed a launch manifest's `env`).
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepend_path_builds_colon_list_newest_first() {
        let mut e = BuildEnv::new();
        e.prepend_path("/opt/bun/bin");
        assert_eq!(e.get("PATH"), Some("/opt/bun/bin"));
        e.prepend_path("/usr/local/bin");
        assert_eq!(e.get("PATH"), Some("/usr/local/bin:/opt/bun/bin"));
    }

    #[test]
    fn set_overrides() {
        let mut e = BuildEnv::new();
        e.set("NODE_ENV", "development");
        e.set("NODE_ENV", "production");
        assert_eq!(e.get("NODE_ENV"), Some("production"));
    }
}
