use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub project: Option<ProjectMeta>,
    #[serde(default)]
    pub routes: HashMap<String, RouteTarget>,
    #[serde(default)]
    pub functions: HashMap<String, FunctionConfig>,
    #[serde(default)]
    pub servers: HashMap<String, ServerConfig>,
    pub hosting: Option<HostingConfig>,
    #[serde(default)]
    pub sites: HashMap<String, SiteConfig>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteTarget {
    pub service: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionConfig {
    pub source: String,
    pub runtime: Option<String>,
    /// 5-field UNIX cron, e.g. "*/5 * * * *". When set, the host invokes this
    /// function on the schedule (waking the project if hibernated).
    #[serde(default)]
    pub schedule: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub dockerfile: String,
    pub port: u16,
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub volumes: Vec<VolumeConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub path: Option<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeConfig {
    pub name: String,
    pub mount: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostingConfig {
    pub public: Option<String>,
    pub spa: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteConfig {
    pub public: String,
    pub spa: Option<bool>,
    pub prefix: Option<String>,
    /// Optional hostname binding: a bare label (`docs` → `docs.jkbase.app`) or a
    /// full custom domain (`docs.example.com`). When set, this site is served on
    /// that host rather than (only) by path prefix.
    pub domain: Option<String>,
}

impl ProjectConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn find_and_load() -> Result<(Self, std::path::PathBuf)> {
        let mut dir = std::env::current_dir()?;
        loop {
            let candidate = dir.join("jkbase.toml");
            if candidate.exists() {
                let config = Self::load(&candidate)?;
                return Ok((config, candidate));
            }
            if !dir.pop() {
                anyhow::bail!("no jkbase.toml found in current directory or any parent");
            }
        }
    }

    pub fn resolved_sites(&self) -> Vec<ResolvedSite> {
        let mut sites = Vec::new();

        for (name, site) in &self.sites {
            sites.push(ResolvedSite {
                name: name.clone(),
                public: site.public.clone(),
                spa: site.spa.unwrap_or(false),
                prefix: site.prefix.clone().unwrap_or_else(|| "/".to_string()),
                domain: site.domain.clone(),
            });
        }

        if sites.is_empty() {
            let public = self
                .hosting
                .as_ref()
                .and_then(|h| h.public.as_deref())
                .unwrap_or(".")
                .to_string();
            let spa = self
                .hosting
                .as_ref()
                .and_then(|h| h.spa)
                .unwrap_or(false);
            sites.push(ResolvedSite {
                name: "default".to_string(),
                public,
                spa,
                prefix: "/".to_string(),
                domain: None,
            });
        }

        // Sort by prefix length descending (longest match first)
        sites.sort_by_key(|s| std::cmp::Reverse(s.prefix.len()));
        sites
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedSite {
    pub name: String,
    pub public: String,
    pub spa: bool,
    pub prefix: String,
    #[serde(default)]
    pub domain: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_domain_round_trips_and_resolves() {
        let toml = r#"
            [project]
            name = "demo"
            [sites.docs]
            public = "./docs"
            domain = "docs"
            [sites.blog]
            public = "./blog"
            domain = "blog.example.com"
            spa = true
        "#;
        let cfg: ProjectConfig = toml::from_str(toml).unwrap();
        let sites = cfg.resolved_sites();
        let docs = sites.iter().find(|s| s.name == "docs").unwrap();
        assert_eq!(docs.domain.as_deref(), Some("docs"));
        let blog = sites.iter().find(|s| s.name == "blog").unwrap();
        assert_eq!(blog.domain.as_deref(), Some("blog.example.com"));
        assert!(blog.spa);

        // Round-trips through the _sites.json wire format.
        let json = serde_json::to_string(&sites).unwrap();
        let back: Vec<ResolvedSite> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.iter().any(|s| s.domain.as_deref() == Some("docs")));
    }
}
