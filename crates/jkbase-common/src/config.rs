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
    /// Connected-repo build trigger ([build.repo]) — used by git-push / webhooks.
    pub build: Option<BuildConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildConfig {
    /// The git remote a push to which triggers a build of this project.
    pub repo: Option<RepoConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    /// Git remote URL to build from on push.
    pub url: String,
    /// Branch to build (default `main`).
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_branch() -> String {
    "main".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteTarget {
    pub service: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionConfig {
    /// Source directory (server-side build) or a pre-built `.wasm` path. Builds
    /// run on the platform from this subdir of the uploaded source tree.
    pub source: String,
    /// Declared toolchain runtime: `wasi-http` (default) or `wasip1` (legacy
    /// Rust build path). Drives toolchain selection in the build pipeline.
    pub runtime: Option<String>,
    /// Source language hint (`rust`|`javascript`|`python`|`tinygo`|`cpp`); the
    /// build pipeline auto-detects when omitted.
    #[serde(default)]
    pub language: Option<String>,
    /// 5-field UNIX cron, e.g. "*/5 * * * *". When set, the host invokes this
    /// function on the schedule (waking the project if hibernated).
    #[serde(default)]
    pub schedule: Option<String>,
    /// Per-function PUBLIC-internet egress policy. The OWN-stuff and platform-internals
    /// zones are classified independently and are NOT governed by this. Three states:
    ///   absent        => default (allow public + observe/meter; zero config)
    ///   ["host", ...] => enforced allowlist (preventive; connect-time, IP-pinned)
    ///   false         => sandbox (deny public egress; OWN stuff still reachable)
    #[serde(default)]
    pub egress: Option<EgressPolicy>,
}

/// A declared per-function (or project-default) PUBLIC-egress policy. TOML has no native
/// union, so this is an untagged enum: `egress = false`/`true` → `Toggle`; `egress =
/// ["host", ...]` → `Allowlist`. OWN-stuff and platform-internals are zone-classified
/// independently and are NOT governed by this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EgressPolicy {
    /// `false` => sandbox (deny public). `true` => "default within the ceiling" (documents
    /// intent; never widens past a project allowlist — see [`resolve_egress`]).
    Toggle(bool),
    /// `["api.stripe.com", ...]` => enforced allowlist.
    Allowlist(Vec<String>),
}

/// The concrete PUBLIC-egress capability after collapsing project-default × per-function
/// precedence host-side at deploy (the agent never re-derives it — it receives exactly one
/// of these states, immutable for the VM's life).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedEgress {
    /// Allow public + observe/meter (the zero-config default).
    Default,
    /// Deny all public egress (own-stuff still reachable).
    Sandbox,
    /// Allow ONLY these exact hosts (preventive; connect-time, IP-pinned). Normalized
    /// (lowercased, trailing dot stripped, deduped).
    Allowlist(Vec<String>),
}

/// Collapse a project-default policy and a per-function policy into one concrete
/// [`ResolvedEgress`]. The project policy is a **CEILING**: a function may NARROW it but
/// never WIDEN past it — else a function `egress = true` would punch through a marketplace
/// floor (adversarial-review HIGH-1). `egress = true` therefore means "the default, but no
/// wider than the ceiling", never "allow-all".
pub fn resolve_egress(
    project: Option<&EgressPolicy>,
    function: Option<&EgressPolicy>,
) -> ResolvedEgress {
    use EgressPolicy::{Allowlist, Toggle};
    match (project, function) {
        // No ceiling (absent / allow-all project): the function policy applies verbatim.
        (None | Some(Toggle(true)), None | Some(Toggle(true))) => ResolvedEgress::Default,
        (None | Some(Toggle(true)), Some(Toggle(false))) => ResolvedEgress::Sandbox,
        (None | Some(Toggle(true)), Some(Allowlist(f))) => {
            ResolvedEgress::Allowlist(dedup_hosts(f))
        }
        // Sandbox ceiling: nothing can widen it.
        (Some(Toggle(false)), _) => ResolvedEgress::Sandbox,
        // Allowlist ceiling P: narrow freely; a widening request is intersected against P.
        (Some(Allowlist(p)), None | Some(Toggle(true))) => ResolvedEgress::Allowlist(dedup_hosts(p)),
        (Some(Allowlist(_)), Some(Toggle(false))) => ResolvedEgress::Sandbox,
        (Some(Allowlist(p)), Some(Allowlist(f))) => ResolvedEgress::Allowlist(intersect_hosts(p, f)),
    }
}

fn norm_host(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

fn dedup_hosts(hosts: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in hosts {
        let n = norm_host(h);
        if !n.is_empty() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

fn intersect_hosts(ceiling: &[String], req: &[String]) -> Vec<String> {
    let c = dedup_hosts(ceiling);
    dedup_hosts(req).into_iter().filter(|h| c.contains(h)).collect()
}

#[cfg(test)]
mod egress_policy_tests {
    use super::*;

    #[test]
    fn function_cannot_widen_past_an_allowlist_ceiling() {
        let p = EgressPolicy::Allowlist(vec!["api.stripe.com".into()]);
        // `egress = true` under a ceiling stays the ceiling — NOT allow-all.
        assert_eq!(
            resolve_egress(Some(&p), Some(&EgressPolicy::Toggle(true))),
            ResolvedEgress::Allowlist(vec!["api.stripe.com".into()])
        );
        // A wider function allowlist is intersected (evil.com dropped).
        let f = EgressPolicy::Allowlist(vec!["api.stripe.com".into(), "evil.com".into()]);
        assert_eq!(
            resolve_egress(Some(&p), Some(&f)),
            ResolvedEgress::Allowlist(vec!["api.stripe.com".into()])
        );
        // Narrowing to sandbox is always allowed.
        assert_eq!(
            resolve_egress(Some(&p), Some(&EgressPolicy::Toggle(false))),
            ResolvedEgress::Sandbox
        );
    }

    #[test]
    fn sandbox_ceiling_cannot_be_widened() {
        let p = EgressPolicy::Toggle(false);
        for f in [
            None,
            Some(EgressPolicy::Toggle(true)),
            Some(EgressPolicy::Allowlist(vec!["x.com".into()])),
        ] {
            assert_eq!(resolve_egress(Some(&p), f.as_ref()), ResolvedEgress::Sandbox);
        }
    }

    #[test]
    fn defaults_and_normalization_without_a_ceiling() {
        assert_eq!(resolve_egress(None, None), ResolvedEgress::Default);
        assert_eq!(
            resolve_egress(None, Some(&EgressPolicy::Toggle(false))),
            ResolvedEgress::Sandbox
        );
        // Hosts normalized (case + trailing dot) and deduped.
        assert_eq!(
            resolve_egress(
                None,
                Some(&EgressPolicy::Allowlist(vec!["A.com.".into(), "a.com".into()]))
            ),
            ResolvedEgress::Allowlist(vec!["a.com".into()])
        );
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Source directory the platform builds (zero-config buildpacks). The
    /// default path; preferred over `dockerfile`.
    #[serde(default)]
    pub source: Option<String>,
    /// Build strategy: `auto` (buildpack detect, default) or `dockerfile` (the
    /// gated escape hatch). Auto-detected when omitted.
    #[serde(default)]
    pub builder: Option<String>,
    /// Source language hint for buildpack selection; auto-detected when omitted.
    #[serde(default)]
    pub language: Option<String>,
    /// Optional Dockerfile path (the BYO escape hatch). No longer required now
    /// that buildpacks are the default; kept for the `builder = "dockerfile"`
    /// path and for backward-compatible parsing of older manifests.
    #[serde(default)]
    pub dockerfile: Option<String>,
    pub port: u16,
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub volumes: Vec<VolumeConfig>,
    /// Explicit launch command override (argv). When set, it REPLACES the
    /// buildpack-derived start command — for monorepos (whose start may live in a
    /// workspace) or any app whose start isn't auto-derivable without a root `start`
    /// script. `cmd[0]` must be absolute (e.g. `/opt/bun/bin/bun`); the runtime
    /// clears the environment, so it can't rely on `PATH`.
    #[serde(default)]
    pub command: Option<Vec<String>>,
}

/// Resolved build strategy for a `[servers.*]` target. `Auto` runs zero-config
/// buildpack detection; `Dockerfile` is the gated escape hatch — the platform
/// builds a user-supplied Dockerfile *server-side* (in the build VM) and runs the
/// resulting image as a single self-contained runtime layer (`image/self`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builder {
    Auto,
    Dockerfile,
}

impl ServerConfig {
    /// The build source subdir: explicit `source`, else the Dockerfile's parent
    /// directory (legacy manifests), else the project root (`.`).
    pub fn source_dir(&self) -> &str {
        if let Some(s) = self.source.as_deref() {
            return s;
        }
        if let Some(df) = self.dockerfile.as_deref() {
            return Path::new(df).parent().and_then(|p| p.to_str()).unwrap_or(".");
        }
        "."
    }

    /// Resolve the `builder` field to a [`Builder`]. Defaults to `Auto` when
    /// omitted; errors on an unrecognised value (previously this was silently
    /// ignored — a footgun where `builder = "dockerfile"` got a buildpack build).
    pub fn builder(&self) -> Result<Builder> {
        match self.builder.as_deref().map(str::trim) {
            None | Some("") | Some("auto") => Ok(Builder::Auto),
            Some("dockerfile") => Ok(Builder::Dockerfile),
            Some(other) => anyhow::bail!(
                "unknown builder {other:?} (expected \"auto\" or \"dockerfile\")"
            ),
        }
    }

    /// The Dockerfile path (relative to the source tree root) for
    /// `builder = "dockerfile"`: the explicit `dockerfile` field, else
    /// `<source_dir>/Dockerfile`.
    pub fn dockerfile_path(&self) -> String {
        if let Some(df) = self.dockerfile.as_deref() {
            return df.to_string();
        }
        match self.source_dir() {
            "." => "Dockerfile".to_string(),
            dir => format!("{}/Dockerfile", dir.trim_end_matches('/')),
        }
    }

    /// Validate the build-strategy fields for this server. Run at deploy
    /// preflight. File existence (the Dockerfile actually being present) is
    /// checked where the source tree is available — the CLI and the build VM.
    pub fn validate(&self, server_name: &str) -> Result<()> {
        let builder = self.builder()?;
        if builder == Builder::Dockerfile && self.language.is_some() {
            // A Dockerfile carries its own runtime; a language hint would key a
            // platform runtime layer that the single self-contained image must
            // not stack. Mutually exclusive — almost certainly a misconfig.
            anyhow::bail!(
                "[servers.{server_name}]: `language` is not valid with `builder = \"dockerfile\"` (the image carries its own runtime)"
            );
        }
        Ok(())
    }
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
    /// Project-default PUBLIC-egress policy for every function that omits its own
    /// `egress`. A CEILING, not merely a default: a function may narrow it but never
    /// widen past it (see [`resolve_egress`]).
    #[serde(default)]
    pub function_egress: Option<EgressPolicy>,
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
            // Synthesize a default static site from [hosting]. With NO [hosting] AND no
            // [sites], a SERVER app (declares [servers]) has no static site of its own —
            // every path is routed to the container, and defaulting `public` to "."
            // would package the entire source tree as a static image. A static-only
            // deploy (no servers) keeps the zero-config default: serve the repo root.
            let synthesize = self.hosting.is_some() || self.servers.is_empty();
            if synthesize {
                let public = self
                    .hosting
                    .as_ref()
                    .and_then(|h| h.public.as_deref())
                    .unwrap_or(".")
                    .to_string();
                let spa = self.hosting.as_ref().and_then(|h| h.spa).unwrap_or(false);
                sites.push(ResolvedSite {
                    name: "default".to_string(),
                    public,
                    spa,
                    prefix: "/".to_string(),
                    domain: None,
                });
            }
        }

        // Sort by prefix length descending (longest match first)
        sites.sort_by_key(|s| std::cmp::Reverse(s.prefix.len()));
        sites
    }

    /// True when the deploy serves more than one named site (so each site's
    /// content is packaged under its own `_site_<name>/` prefix rather than at
    /// the artifact root). The single synthesized `default` site is not "multi".
    pub fn is_multi_site(&self) -> bool {
        let sites = self.resolved_sites();
        sites.len() > 1 || sites.first().is_some_and(|s| s.name != "default")
    }

    /// `_routes.json` sidecar (explicit host route table), or `None`.
    pub fn routes_json(&self) -> Option<String> {
        if self.routes.is_empty() {
            return None;
        }
        serde_json::to_string_pretty(&self.routes).ok()
    }

    /// `_sites.json` sidecar (multi-site routing). Emitted only when the manifest
    /// declares explicit `[sites.*]` — the synthesized default site is implicit.
    pub fn sites_json(&self) -> Option<String> {
        if self.sites.is_empty() {
            return None;
        }
        serde_json::to_string_pretty(&self.resolved_sites()).ok()
    }

    /// `_domains.json` sidecar (legacy domain aliases), or `None`.
    pub fn domains_json(&self) -> Option<String> {
        if self.domains.is_empty() {
            return None;
        }
        serde_json::to_string_pretty(&self.domains).ok()
    }

    /// `_schedules.json` sidecar: the inline `schedule = "<cron>"` from each
    /// `[functions.<name>]`, as `[{function, cron}]`. `None` when none declared.
    pub fn schedules_json(&self) -> Option<String> {
        let mut scheds: Vec<_> = self
            .functions
            .iter()
            .filter_map(|(name, f)| {
                f.schedule
                    .as_ref()
                    .map(|c| (name.clone(), c.clone()))
            })
            .collect();
        if scheds.is_empty() {
            return None;
        }
        // Stable output regardless of HashMap iteration order.
        scheds.sort();
        let json: Vec<_> = scheds
            .into_iter()
            .map(|(function, cron)| serde_json::json!({ "function": function, "cron": cron }))
            .collect();
        serde_json::to_string_pretty(&json).ok()
    }
}

impl ServerConfig {
    /// Assemble the on-disk `ServerManifest` JSON for this server: build-derived
    /// `cmd`/`env`/`working_dir` overlaid with the manifest-authoritative
    /// `port`/`health_check`/`volumes` from jkbase.toml. This is the §5a
    /// OCI-config → ServerManifest translate, performed host-side after the build.
    pub fn manifest_value(
        &self,
        cmd: Vec<String>,
        env: HashMap<String, String>,
        working_dir: &str,
    ) -> serde_json::Value {
        let volumes: Vec<serde_json::Value> = self
            .volumes
            .iter()
            .map(|v| serde_json::json!({ "name": v.name, "mount": v.mount }))
            .collect();
        serde_json::json!({
            "port": self.port,
            "cmd": if cmd.is_empty() { vec!["/bin/sh".to_string()] } else { cmd },
            "env": env,
            "working_dir": working_dir,
            "health_check": self.health_check.as_ref().map(|h| serde_json::json!({
                "path": h.path.as_deref().unwrap_or("/"),
                "interval_secs": parse_duration_secs(h.interval.as_deref().unwrap_or("10s")),
                "timeout_secs": parse_duration_secs(h.timeout.as_deref().unwrap_or("5s")),
            })),
            "volumes": volumes,
        })
    }
}

/// Parse a short duration like `10s`, `2m`, or a bare number of seconds.
pub fn parse_duration_secs(s: &str) -> u64 {
    let s = s.trim();
    if let Some(num) = s.strip_suffix('s') {
        num.parse().unwrap_or(10)
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().unwrap_or(1) * 60
    } else {
        s.parse().unwrap_or(10)
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
    fn server_command_override_parses_and_defaults_none() {
        let cfg: ProjectConfig = toml::from_str(
            r#"
            [project]
            name = "demo"
            [servers.web]
            source = "."
            language = "bun"
            port = 3000
            command = ["/opt/bun/bin/bun", "run", "--filter", "web", "start"]
            [servers.api]
            source = "./api"
            language = "bun"
            port = 4000
        "#,
        )
        .unwrap();
        assert_eq!(
            cfg.servers["web"].command.as_deref(),
            Some(&["/opt/bun/bin/bun".to_string(), "run".into(), "--filter".into(), "web".into(), "start".into()][..])
        );
        assert!(cfg.servers["api"].command.is_none(), "command defaults to None");
    }

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

    #[test]
    fn build_repo_block_parses_with_default_branch() {
        let cfg: ProjectConfig = toml::from_str(
            "[project]\nname = \"x\"\n[build.repo]\nurl = \"https://github.com/u/r.git\"\n",
        )
        .unwrap();
        let repo = cfg.build.unwrap().repo.unwrap();
        assert_eq!(repo.url, "https://github.com/u/r.git");
        assert_eq!(repo.branch, "main"); // defaulted
        // Explicit branch.
        let cfg2: ProjectConfig =
            toml::from_str("[build.repo]\nurl = \"u\"\nbranch = \"release\"\n").unwrap();
        assert_eq!(cfg2.build.unwrap().repo.unwrap().branch, "release");
        // No [build] block -> None.
        let bare: ProjectConfig = toml::from_str("[project]\nname = \"x\"\n").unwrap();
        assert!(bare.build.is_none());
    }

    #[test]
    fn server_app_without_hosting_has_no_default_static_site() {
        // A server app with NO [hosting]/[sites]: no static site is synthesized, so the
        // source tree is never packaged as a static image (the catch-all route sends
        // everything to the container).
        let server: ProjectConfig =
            toml::from_str("[project]\nname = \"app\"\n[servers.app]\nport = 3000\n").unwrap();
        assert!(server.resolved_sites().is_empty(), "server app gets no default static site");
        assert!(!server.is_multi_site());
        assert!(server.sites_json().is_none());

        // A static-only deploy (no servers, no hosting) KEEPS the zero-config default:
        // serve the repo root.
        let static_only: ProjectConfig = toml::from_str("[project]\nname = \"s\"\n").unwrap();
        let sites = static_only.resolved_sites();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].public, ".");
        assert_eq!(sites[0].name, "default");

        // Explicit [hosting] always synthesizes the default site, even with servers
        // present (so existing www/console/forumall configs are unaffected).
        let with_hosting: ProjectConfig = toml::from_str(
            "[project]\nname = \"h\"\n[servers.app]\nport = 3000\n[hosting]\npublic = \"./public\"\n",
        )
        .unwrap();
        let sites = with_hosting.resolved_sites();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].public, "./public");
    }

    #[test]
    fn sidecars_emit_only_when_declared() {
        // Bare project: no routes/sites/domains/schedules → no sidecars.
        let bare: ProjectConfig = toml::from_str("[project]\nname = \"x\"\n").unwrap();
        assert!(bare.routes_json().is_none());
        assert!(bare.sites_json().is_none());
        assert!(bare.domains_json().is_none());
        assert!(bare.schedules_json().is_none());
        assert!(!bare.is_multi_site());

        let cfg: ProjectConfig = toml::from_str(
            r#"
            domains = ["alias.example.com"]
            [project]
            name = "demo"
            [routes."api.example.com"]
            service = "function"
            name = "api"
            [functions.api]
            source = "./functions/api"
            schedule = "*/5 * * * *"
            [functions.beat]
            source = "./functions/beat"
            schedule = "0 * * * *"
            [sites.docs]
            public = "./docs"
            "#,
        )
        .unwrap();

        assert!(cfg.is_multi_site());
        assert!(cfg.routes_json().unwrap().contains("api.example.com"));
        assert!(cfg.sites_json().unwrap().contains("docs"));
        assert!(cfg.domains_json().unwrap().contains("alias.example.com"));

        // Schedules are sorted by function name regardless of HashMap order.
        let sched = cfg.schedules_json().unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&sched).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["function"], "api");
        assert_eq!(parsed[1]["function"], "beat");
    }

    #[test]
    fn server_manifest_translate_overlays_toml() {
        let cfg: ProjectConfig = toml::from_str(
            r#"
            [project]
            name = "demo"
            [servers.web]
            source = "./server"
            port = 8000
            [servers.web.health_check]
            path = "/healthz"
            interval = "2m"
            timeout = "5s"
            [[servers.web.volumes]]
            name = "data"
            mount = "/data"
            "#,
        )
        .unwrap();
        let web = &cfg.servers["web"];
        assert_eq!(web.source_dir(), "./server");

        let mut env = HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        let m = web.manifest_value(vec!["./app".to_string()], env, "/srv");
        assert_eq!(m["port"], 8000); // jkbase.toml authoritative
        assert_eq!(m["cmd"][0], "./app"); // build-derived
        assert_eq!(m["working_dir"], "/srv");
        assert_eq!(m["env"]["FOO"], "bar");
        assert_eq!(m["health_check"]["path"], "/healthz");
        assert_eq!(m["health_check"]["interval_secs"], 120); // 2m
        assert_eq!(m["health_check"]["timeout_secs"], 5);
        assert_eq!(m["volumes"][0]["mount"], "/data");

        // Legacy dockerfile manifests still parse and resolve a source dir.
        let legacy: ProjectConfig = toml::from_str(
            "[servers.api]\ndockerfile = \"./api/Dockerfile\"\nport = 3000\n",
        )
        .unwrap();
        assert_eq!(legacy.servers["api"].source_dir(), "./api");
    }

    #[test]
    fn builder_resolves_and_validates() {
        // Default (omitted) and explicit "auto" both resolve to Auto.
        let cfg: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"./web\"\nport = 8000\n").unwrap();
        let web = &cfg.servers["web"];
        assert_eq!(web.builder().unwrap(), Builder::Auto);
        web.validate("web").unwrap();

        // Explicit dockerfile builder.
        let cfg: ProjectConfig = toml::from_str(
            "[servers.api]\nbuilder = \"dockerfile\"\ndockerfile = \"./api/Dockerfile\"\nport = 3000\n",
        )
        .unwrap();
        let api = &cfg.servers["api"];
        assert_eq!(api.builder().unwrap(), Builder::Dockerfile);
        assert_eq!(api.dockerfile_path(), "./api/Dockerfile");
        api.validate("api").unwrap();

        // Dockerfile path defaults to <source_dir>/Dockerfile when unspecified.
        let cfg: ProjectConfig =
            toml::from_str("[servers.api]\nbuilder = \"dockerfile\"\nsource = \"./svc\"\nport = 3000\n")
                .unwrap();
        assert_eq!(cfg.servers["api"].dockerfile_path(), "./svc/Dockerfile");
        let cfg: ProjectConfig =
            toml::from_str("[servers.api]\nbuilder = \"dockerfile\"\nport = 3000\n").unwrap();
        assert_eq!(cfg.servers["api"].dockerfile_path(), "Dockerfile");

        // Unknown builder is rejected (no longer silently ignored).
        let cfg: ProjectConfig =
            toml::from_str("[servers.api]\nbuilder = \"podman\"\nport = 3000\n").unwrap();
        assert!(cfg.servers["api"].builder().is_err());

        // builder = "dockerfile" + language hint is mutually exclusive.
        let cfg: ProjectConfig = toml::from_str(
            "[servers.api]\nbuilder = \"dockerfile\"\nlanguage = \"node\"\nport = 3000\n",
        )
        .unwrap();
        assert!(cfg.servers["api"].validate("api").is_err());
    }
}
