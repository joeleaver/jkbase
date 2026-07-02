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
    /// `[database]` — a managed RhypeDB instance for this project. See
    /// `docs/managed-rhypedb-design.md`. v1 boots one rhypedb-server co-located in
    /// the project VM, reachable only by the project's own app/functions over
    /// loopback (no end-user identity yet).
    pub database: Option<DatabaseConfig>,
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
        (Some(Allowlist(p)), None | Some(Toggle(true))) => {
            ResolvedEgress::Allowlist(dedup_hosts(p))
        }
        (Some(Allowlist(_)), Some(Toggle(false))) => ResolvedEgress::Sandbox,
        (Some(Allowlist(p)), Some(Allowlist(f))) => {
            ResolvedEgress::Allowlist(intersect_hosts(p, f))
        }
    }
}

/// Host-asserted platform egress facts, delivered to the in-VM agent via the per-VM
/// metadata image as `_platform.json` — a host-written region the tenant CANNOT author
/// (NEVER `jkbase.toml`-derived, P0-EGRESS-OWN-HOST-ASSERTED). The agent reads exactly
/// this to (a) recognize its OWN object-store host as Zone-1 OWN-stuff (allowed even under
/// sandbox), and (b) deny the platform's own public IP(s) as Zone-2 PLATFORM (the
/// control-plane / proxy / object-store ingress), defeating IP-literal + domain-fronting
/// to `api.{domain}` (P0-EGRESS-PLATFORM-BY-IP). Absent ⇒ the agent falls back to the
/// netfilter fence alone for Zone-2 and treats no host as OWN-storage (fail-closed:
/// stricter, never wider).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformEgress {
    /// The platform object-store host, e.g. `"storage.jkbase.app"`. A request to this
    /// EXACT host whose resolved IP is in `platform_ips` is OWN-stuff (Zone 1) — allowed
    /// regardless of the per-function policy, so it survives `egress = false`.
    #[serde(default)]
    pub storage_host: Option<String>,
    /// The platform's own public/uplink IP(s) — where api/proxy/object-store terminate.
    /// Any resolved destination IP in this set is Zone-2 PLATFORM (DENY) UNLESS the request
    /// host is `storage_host`. String form; the agent parses to `IpAddr` (a malformed entry
    /// is dropped, never silently treated as "allow"). Multi-homed hosts (e.g. OVH failover
    /// IPs) list every uplink global IP.
    #[serde(default)]
    pub platform_ips: Vec<String>,
}

impl PlatformEgress {
    /// Metadata-image filename. Host-written into the per-VM image; the agent's static
    /// server refuses to serve `_`-prefixed entries, so it never leaks to the public.
    pub const FILE: &'static str = "_platform.json";
}

/// Host-authored managed-DB reach-plane facts, baked into the per-VM metadata image
/// (`_db_reach.json`) for projects that declare a `[database]`. Written LAST into the
/// image (like [`PlatformEgress`]) so a tenant `jkbase.toml`/source file of the same
/// name can't forge it — it is genuinely host-authored and tenant-unforgeable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbReachFacts {
    /// The per-deploy host→agent splice secret. The edge presents it on the
    /// `/_jkbase/db` upgrade and the agent verifies it before splicing to the loopback
    /// DB ([R3]) — defense-in-depth so one isolation slip isn't a full DB compromise.
    #[serde(default)]
    pub splice_secret: String,
    /// The per-deploy rhypedb admin bearer (`RHYPEDB_ADMIN_TOKEN`). Host-minted, injected
    /// ONLY into the DB's own process env by the agent — it gates `/admin/*` (backup stream
    /// = full data exfil) on loopback:4200. It rides THIS reserved channel, never the
    /// tenant-influenced `_database.json` ([RB1]). Empty (old images / no managed DB) ⇒
    /// backups disabled, fail-closed, never a crash.
    #[serde(default)]
    pub admin_token: String,
}

impl DbReachFacts {
    /// Metadata-image filename. `_`-prefixed, so the agent's static server never serves it.
    pub const FILE: &'static str = "_db_reach.json";
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
    dedup_hosts(req)
        .into_iter()
        .filter(|h| c.contains(h))
        .collect()
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
            assert_eq!(
                resolve_egress(Some(&p), f.as_ref()),
                ResolvedEgress::Sandbox
            );
        }
    }

    #[test]
    fn platform_egress_round_trips_and_defaults_empty() {
        // Default (absent file shape) → no OWN host, empty deny-set: fail-closed (the agent
        // treats no host as OWN-storage and relies on the netfilter fence for Zone 2).
        let empty: PlatformEgress = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, PlatformEgress::default());
        assert!(empty.storage_host.is_none() && empty.platform_ips.is_empty());

        let p = PlatformEgress {
            storage_host: Some("storage.jkbase.app".into()),
            platform_ips: vec!["203.0.113.7".into(), "203.0.113.8".into()],
        };
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<PlatformEgress>(&j).unwrap(), p);
        assert_eq!(PlatformEgress::FILE, "_platform.json");
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
                Some(&EgressPolicy::Allowlist(vec![
                    "A.com.".into(),
                    "a.com".into()
                ]))
            ),
            ResolvedEgress::Allowlist(vec!["a.com".into()])
        );
    }
}

/// Normalise a build-context path: strip a leading `./`, drop a trailing `/`, and
/// treat the empty string as the project root `"."`. Pure string hygiene — traversal
/// safety (`..`/absolute) is enforced by `validate_manifest`.
fn norm_ctx(p: &str) -> &str {
    let p = p.trim_start_matches("./").trim_end_matches('/');
    if p.is_empty() { "." } else { p }
}

/// Express `source` RELATIVE TO `context` (both project-root-relative). Returns `"."`
/// when they denote the same directory (the common case: `context` unset → equals
/// `source`). When `source` is `<context>/<rest>` the result is `<rest>`. When
/// `source` is NOT under `context` (a misconfig that `validate_manifest` rejects),
/// the un-stripped `source` is returned so callers still produce a deterministic,
/// traversal-free token (the in-VM build then fails with a clear "dir not found").
pub fn rel_within(context: &str, source: &str) -> String {
    let ctx = norm_ctx(context);
    let src = norm_ctx(source);
    if ctx == "." {
        return src.to_string();
    }
    if ctx == src {
        return ".".to_string();
    }
    match src.strip_prefix(ctx).and_then(|r| r.strip_prefix('/')) {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ => src.to_string(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Source directory the platform builds (zero-config buildpacks). The
    /// default path; preferred over `dockerfile`.
    #[serde(default)]
    pub source: Option<String>,
    /// Build CONTEXT directory (relative to the project root) mounted as the build
    /// root, Docker-context style. Defaults to `source` when omitted, so unset
    /// behaviour is byte-identical to before this field existed. Set it WIDER than
    /// `source` (e.g. the workspace root) so a `source` crate that path-depends on an
    /// in-repo sibling (`plotweb-common = { path = "../crates/plotweb-common" }`)
    /// builds: the sibling is now inside the mounted context. `source` must be inside
    /// `context` (validated at deploy). See `docs/monorepo-build-context.md`.
    #[serde(default)]
    pub context: Option<String>,
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
            return Path::new(df)
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or(".");
        }
        "."
    }

    /// The build CONTEXT subdir mounted as the build root. Explicit `context`,
    /// else the `source_dir()` (so unset → identical to mounting just the source).
    pub fn context_dir(&self) -> &str {
        match self.context.as_deref() {
            Some(c) => c,
            None => self.source_dir(),
        }
    }

    /// The source path interpreted RELATIVE TO [`Self::context_dir`] — i.e. where,
    /// inside the mounted context, this target's build root lives. `"."` when
    /// `context` is unset (or equals `source`), preserving today's behaviour.
    pub fn build_subdir(&self) -> String {
        rel_within(self.context_dir(), self.source_dir())
    }

    /// Resolve the `builder` field to a [`Builder`]. Defaults to `Auto` when
    /// omitted; errors on an unrecognised value (previously this was silently
    /// ignored — a footgun where `builder = "dockerfile"` got a buildpack build).
    pub fn builder(&self) -> Result<Builder> {
        match self.builder.as_deref().map(str::trim) {
            None | Some("") | Some("auto") => Ok(Builder::Auto),
            Some("dockerfile") => Ok(Builder::Dockerfile),
            Some(other) => {
                anyhow::bail!("unknown builder {other:?} (expected \"auto\" or \"dockerfile\")")
            }
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
    /// The static directory served for this site. For a COMMITTED site (no `build`)
    /// this is REQUIRED — the pre-built content (the historical behaviour). `None`
    /// (omitted) is only legal for a BUILT site (`build` set), where it is ignored:
    /// the platform builds the content from `source` and serves the produced tree.
    /// Left `Option` (not defaulted to ".") on purpose: a blanket "." default would
    /// silently serve the entire source tree for a committed site that forgot
    /// `public` — `validate_manifest` rejects that instead.
    #[serde(default)]
    pub public: Option<String>,
    pub spa: Option<bool>,
    pub prefix: Option<String>,
    /// Optional hostname binding: a bare label (`docs` → `docs.jkbase.app`) or a
    /// full custom domain (`docs.example.com`). When set, this site is served on
    /// that host rather than (only) by path prefix.
    pub domain: Option<String>,
    /// Source directory the platform BUILDS this site from when `build` is set
    /// (e.g. a Rust/WASM frontend crate). Relative to the project root. Required
    /// when `build` is set; ignored otherwise.
    #[serde(default)]
    pub source: Option<String>,
    /// Build CONTEXT directory mounted as the build root for a BUILT site (Docker-context
    /// style). Defaults to `source` when omitted, so unset behaviour is byte-identical.
    /// Set it wider than `source` (e.g. the workspace root) so a `trunk` frontend crate
    /// that path-depends on an in-repo sibling builds. `source` must be inside `context`
    /// (validated at deploy). Ignored for a committed site (no `build`). See
    /// `docs/monorepo-build-context.md`.
    #[serde(default)]
    pub context: Option<String>,
    /// Build strategy for this site: `"trunk"` to build a Rust/WASM frontend with
    /// the trunk buildpack server-side and serve the produced static tree. Absent
    /// (the default) → a committed static site served from `public`, unchanged.
    #[serde(default)]
    pub build: Option<String>,
}

/// Resolved build strategy for a `[sites.*]` target. `None` (committed content) is
/// the default; `Trunk` builds a Rust/WASM frontend server-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteBuild {
    /// A Rust/WASM frontend built with the `trunk` buildpack.
    Trunk,
}

impl SiteConfig {
    /// Resolve the `build` field. `None` → a committed static site (no build).
    /// Errors on an unrecognised value so a typo doesn't silently ship un-built
    /// source as static content.
    pub fn build_strategy(&self) -> Result<Option<SiteBuild>> {
        match self.build.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some("trunk") => Ok(Some(SiteBuild::Trunk)),
            Some(other) => anyhow::bail!("unknown site build {other:?} (expected \"trunk\")"),
        }
    }

    /// The source directory the platform builds this site from (built sites only).
    /// Defaults to the project root when `build` is set but `source` is omitted.
    pub fn build_source(&self) -> &str {
        self.source.as_deref().unwrap_or(".")
    }

    /// The build CONTEXT subdir mounted as the build root. Explicit `context`, else
    /// the `build_source()` (so unset → identical to mounting just the source).
    pub fn context_dir(&self) -> &str {
        self.context
            .as_deref()
            .unwrap_or_else(|| self.build_source())
    }

    /// The source path relative to [`Self::context_dir`]; `"."` when `context` is
    /// unset (or equals `source`), preserving today's behaviour.
    pub fn build_subdir(&self) -> String {
        rel_within(self.context_dir(), self.build_source())
    }
}

/// `[database]` — a managed RhypeDB instance for the project. Mirrors the
/// `[servers.*]`/`[sites.*]` typed-section pattern: an `engine` resolver that fails
/// closed on an unknown value (a typo must abort the deploy, never silently skip
/// provisioning). See `docs/managed-rhypedb-design.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database engine. Only `rhypedb` is supported today; an unknown value is
    /// rejected at preflight (mirrors [`SiteConfig::build_strategy`]). Omitted →
    /// the default (and only) engine.
    #[serde(default)]
    pub engine: Option<String>,
    /// Schema file (RhypeDB SDL) in the uploaded source tree, e.g. `"schema.rhype"`.
    /// REQUIRED — a managed DB with no schema has nothing to serve.
    pub schema: String,
    /// Security-rules file (RhypeDB rules) in the source tree. OPTIONAL for v1
    /// ("managed RhypeDB for your own backend": the DB is reachable only by the
    /// project's own app, trusted by the tenant). REQUIRED before the DB is exposed
    /// to untrusted clients (the Firestore-style tier).
    #[serde(default)]
    pub rules: Option<String>,
    /// Persistent data-disk size for the DB, e.g. `"4GiB"`. The platform default
    /// data disk is too small for a real DB; this sizes the DB's own volume,
    /// parsed host-side at deploy. Omitted → the platform default.
    #[serde(default)]
    pub size: Option<String>,
}

/// Resolved database engine. Only RhypeDB exists today; the enum is the fail-closed
/// boundary so the deploy path rejects an unknown `engine` rather than provisioning
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseEngine {
    Rhypedb,
}

/// Parse a human data-disk size (`"4GiB"`, `"512MiB"`, `"1GB"`, `"2G"`, `"1048576"`)
/// into bytes. Binary (`KiB`/`MiB`/`GiB`/`TiB`) and decimal (`KB`/`MB`/`GB`/`TB`, or a
/// bare `K`/`M`/`G`/`T` = decimal) suffixes, case-insensitive; a bare number is bytes.
/// Fails closed on a malformed value so a typo aborts the deploy.
fn parse_size_bytes(s: &str) -> Result<u64> {
    let t = s.trim();
    if t.is_empty() {
        anyhow::bail!("empty size");
    }
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let num: f64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid size number in {s:?}"))?;
    if !num.is_finite() || num < 0.0 {
        anyhow::bail!("invalid size {s:?}");
    }
    let kib = 1024.0_f64;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "ki" | "kib" => kib,
        "m" | "mb" => 1e6,
        "mi" | "mib" => kib.powi(2),
        "g" | "gb" => 1e9,
        "gi" | "gib" => kib.powi(3),
        "t" | "tb" => 1e12,
        "ti" | "tib" => kib.powi(4),
        other => anyhow::bail!("unknown size unit {other:?} in {s:?}"),
    };
    Ok((num * mult).ceil() as u64)
}

impl DatabaseConfig {
    /// Resolve the `engine` field. Omitted/empty → RhypeDB (the only engine);
    /// errors on an unrecognised value so `engine = "rhypdb"` fails the deploy
    /// instead of quietly provisioning no database.
    pub fn engine(&self) -> Result<DatabaseEngine> {
        match self.engine.as_deref().map(str::trim) {
            None | Some("") | Some("rhypedb") => Ok(DatabaseEngine::Rhypedb),
            Some(other) => {
                anyhow::bail!("unknown database engine {other:?} (expected \"rhypedb\")")
            }
        }
    }

    /// Validate the `[database]` section at deploy preflight: resolve the engine
    /// (reject unknown), reject an empty `schema` path, and reject a malformed `size`.
    /// File existence (the schema/rules files actually being present) is checked where
    /// the source tree is available — the CLI and the build VM.
    pub fn validate(&self) -> Result<()> {
        self.engine()?;
        if self.schema.trim().is_empty() {
            anyhow::bail!("[database]: `schema` must not be empty (path to the RhypeDB SDL file)");
        }
        self.size_mib()
            .context("[database]: `size` is not a valid data-disk size (e.g. \"4GiB\")")?;
        Ok(())
    }

    /// Resolve `size` to whole MiB (rounded up), or `None` when unset. The data disk
    /// is sized in MiB host-side (`DATA_DISK_MIB`), so this is the unit the host wants.
    /// Errors on a malformed value (surfaced at preflight by [`Self::validate`]).
    pub fn size_mib(&self) -> Result<Option<u64>> {
        match self.size.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some(s) => {
                const MIB: u64 = 1024 * 1024;
                let mib = parse_size_bytes(s)?.div_ceil(MIB);
                if mib == 0 {
                    anyhow::bail!("[database]: `size` {s:?} rounds to 0 MiB (too small)");
                }
                Ok(Some(mib))
            }
        }
    }
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
                // A committed site always has `public` (enforced by validate_manifest at
                // intake); a built site ignores it, so `None` → "." is a harmless filler.
                public: site.public.clone().unwrap_or_else(|| ".".to_string()),
                spa: site.spa.unwrap_or(false),
                prefix: site.prefix.clone().unwrap_or_else(|| "/".to_string()),
                domain: site.domain.clone(),
                // A built site's served content comes from the build output, not a
                // committed `public` dir. Carry the flag so assemble_sites skips the
                // committed-copy and the static build fills the slot instead.
                built: site
                    .build
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|b| !b.is_empty()),
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
                    built: false,
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
            .filter_map(|(name, f)| f.schedule.as_ref().map(|c| (name.clone(), c.clone())))
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

    /// `_database.json` sidecar: the resolved managed-DB facts the host/agent need
    /// to provision + boot the DB — engine, schema path, rules path, and the parsed
    /// data-disk `size_mib` (the host sizes the RWO disk from it; `null`/absent → the
    /// platform default). `None` when no `[database]` is declared. The admin credential
    /// is NEVER in this sidecar: it is host-minted per deploy and delivered over the
    /// reserved metadata channel, never tenant-authored and never derived from
    /// `jkbase.toml`.
    pub fn database_json(&self) -> Option<String> {
        let db = self.database.as_ref()?;
        // Preflight `validate()` already rejects an unknown engine + a malformed size;
        // if either somehow doesn't resolve here, emit nothing (engine) or drop the
        // field (size) rather than a half-formed sidecar.
        let engine = match db.engine() {
            Ok(DatabaseEngine::Rhypedb) => "rhypedb",
            Err(_) => return None,
        };
        serde_json::to_string_pretty(&serde_json::json!({
            "engine": engine,
            "schema": db.schema,
            "rules": db.rules,
            "size_mib": db.size_mib().ok().flatten(),
        }))
        .ok()
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
    /// True when this site's content is BUILT server-side (a `[sites.<name>]` with
    /// `build = "..."`) rather than copied from a committed `public` dir. The build
    /// orchestrator fills the served slot from the build output; `assemble_sites`
    /// skips the committed-copy for it. Not part of the `_sites.json` routing wire
    /// shape (it's a build-time concern), so it is skipped when serializing.
    #[serde(default, skip)]
    pub built: bool,
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
            Some(
                &[
                    "/opt/bun/bin/bun".to_string(),
                    "run".into(),
                    "--filter".into(),
                    "web".into(),
                    "start".into()
                ][..]
            )
        );
        assert!(
            cfg.servers["api"].command.is_none(),
            "command defaults to None"
        );
    }

    #[test]
    fn rel_within_expresses_source_relative_to_context() {
        // Context unset/equal-to-source semantics collapse to ".".
        assert_eq!(rel_within(".", "."), ".");
        assert_eq!(rel_within("web", "web"), ".");
        assert_eq!(rel_within("./web/", "web"), ".");
        // A wider context yields the source's path within it.
        assert_eq!(rel_within(".", "web"), "web");
        assert_eq!(rel_within(".", "./crates/api"), "crates/api");
        assert_eq!(rel_within("apps", "apps/web"), "web");
        // Source NOT under context → returned unchanged (validate_manifest rejects it;
        // the token stays deterministic and traversal-free regardless).
        assert_eq!(rel_within("apps", "services/api"), "services/api");
    }

    #[test]
    fn context_unset_is_identical_to_mounting_source() {
        // Regression guard for the #1 review concern: when `context` is omitted, the
        // context subdir IS the source and the build subdir is "." — byte-identical to
        // the pre-`context` build path (mount the source, build at its root).
        let server: ServerConfig = toml::from_str("source = \"./web\"\nport = 3000\n").unwrap();
        assert_eq!(server.context_dir(), "./web");
        assert_eq!(server.build_subdir(), ".");

        let site: SiteConfig = toml::from_str("source = \"./web\"\nbuild = \"trunk\"\n").unwrap();
        assert_eq!(site.context_dir(), "./web");
        assert_eq!(site.build_subdir(), ".");
    }

    #[test]
    fn context_set_widens_root_and_keeps_source_as_build_subdir() {
        // `context = "."`, `source = "web"`: mount the repo root, build in web/.
        let server: ServerConfig =
            toml::from_str("source = \"web\"\ncontext = \".\"\nport = 3000\n").unwrap();
        assert_eq!(server.context_dir(), ".");
        assert_eq!(server.build_subdir(), "web");

        let site: SiteConfig =
            toml::from_str("source = \"web\"\ncontext = \".\"\nbuild = \"trunk\"\n").unwrap();
        assert_eq!(site.context_dir(), ".");
        assert_eq!(site.build_subdir(), "web");
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
        assert!(
            server.resolved_sites().is_empty(),
            "server app gets no default static site"
        );
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
        let legacy: ProjectConfig =
            toml::from_str("[servers.api]\ndockerfile = \"./api/Dockerfile\"\nport = 3000\n")
                .unwrap();
        assert_eq!(legacy.servers["api"].source_dir(), "./api");
    }

    #[test]
    fn site_build_strategy_resolves_and_marks_resolved_site() {
        // A built site: `build = "trunk"` resolves to Trunk; `source` is the build dir;
        // `public` is omitted (legal only for a built site → `None`, not defaulted to ".").
        let cfg: ProjectConfig =
            toml::from_str("[sites.app]\nsource = \"./web\"\nbuild = \"trunk\"\n").unwrap();
        let site = &cfg.sites["app"];
        assert_eq!(site.build_strategy().unwrap(), Some(SiteBuild::Trunk));
        assert_eq!(site.build_source(), "./web");
        assert_eq!(
            site.public, None,
            "omitted `public` must be None, never defaulted to \".\""
        );
        // resolved_sites carries the `built` flag so assemble_sites skips its copy.
        let resolved = cfg.resolved_sites();
        let app = resolved.iter().find(|s| s.name == "app").unwrap();
        assert!(app.built);

        // A committed site: no `build` → None, not built; `public` is carried as Some.
        let cfg: ProjectConfig = toml::from_str("[sites.docs]\npublic = \"./docs\"\n").unwrap();
        assert_eq!(cfg.sites["docs"].build_strategy().unwrap(), None);
        assert_eq!(cfg.sites["docs"].public.as_deref(), Some("./docs"));
        assert!(!cfg.resolved_sites().iter().any(|s| s.built));

        // An unknown strategy is rejected (typo → never ship un-built source).
        let cfg: ProjectConfig =
            toml::from_str("[sites.app]\nsource = \"./web\"\nbuild = \"webpack\"\n").unwrap();
        assert!(cfg.sites["app"].build_strategy().is_err());

        // `build` defaults `source` to the project root when omitted.
        let cfg: ProjectConfig = toml::from_str("[sites.app]\nbuild = \"trunk\"\n").unwrap();
        assert_eq!(cfg.sites["app"].build_source(), ".");

        // The `built` flag is NOT serialized into the _sites.json routing wire shape.
        let json = serde_json::to_string(&cfg.resolved_sites()).unwrap();
        assert!(!json.contains("built"));
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
        let cfg: ProjectConfig = toml::from_str(
            "[servers.api]\nbuilder = \"dockerfile\"\nsource = \"./svc\"\nport = 3000\n",
        )
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

    #[test]
    fn database_section_parses_resolves_and_emits_sidecar() {
        // Full section: engine omitted defaults to rhypedb; schema required; rules + size optional.
        let cfg: ProjectConfig = toml::from_str(
            "[project]\nname = \"d\"\n[database]\nschema = \"schema.rhype\"\nrules = \"rules.rhype\"\nsize = \"4GiB\"\n",
        )
        .unwrap();
        let db = cfg.database.as_ref().unwrap();
        assert_eq!(db.engine().unwrap(), DatabaseEngine::Rhypedb);
        assert_eq!(db.schema, "schema.rhype");
        assert_eq!(db.rules.as_deref(), Some("rules.rhype"));
        assert_eq!(db.size.as_deref(), Some("4GiB"));
        assert_eq!(db.size_mib().unwrap(), Some(4096));
        db.validate().unwrap();

        // Sidecar emits engine/schema/rules/size_mib and NEVER a credential.
        let sidecar = cfg.database_json().unwrap();
        assert!(sidecar.contains("rhypedb"));
        assert!(sidecar.contains("schema.rhype"));
        assert!(sidecar.contains("rules.rhype"));
        assert!(sidecar.contains("\"size_mib\": 4096"));
        assert!(!sidecar.to_lowercase().contains("token"));

        // Explicit engine = "rhypedb" is accepted.
        let cfg: ProjectConfig =
            toml::from_str("[database]\nengine = \"rhypedb\"\nschema = \"s.rhype\"\n").unwrap();
        assert_eq!(
            cfg.database.as_ref().unwrap().engine().unwrap(),
            DatabaseEngine::Rhypedb
        );

        // Unknown engine is rejected (typo must fail the deploy, not silently skip).
        let cfg: ProjectConfig =
            toml::from_str("[database]\nengine = \"rhypdb\"\nschema = \"s.rhype\"\n").unwrap();
        assert!(cfg.database.as_ref().unwrap().engine().is_err());
        assert!(cfg.database.as_ref().unwrap().validate().is_err());

        // Empty schema is rejected by validate().
        let cfg: ProjectConfig = toml::from_str("[database]\nschema = \"\"\n").unwrap();
        assert!(cfg.database.as_ref().unwrap().validate().is_err());

        // No [database] → no sidecar, no field.
        let bare: ProjectConfig = toml::from_str("[project]\nname = \"x\"\n").unwrap();
        assert!(bare.database.is_none());
        assert!(bare.database_json().is_none());
    }

    #[test]
    fn database_size_parses_units_rounds_and_fails_closed() {
        // Binary + decimal units, case-insensitive; rounds UP to whole MiB.
        for (s, want) in [
            ("4GiB", 4096_u64),
            ("512MiB", 512),
            ("1mib", 1),
            ("1GB", 954),        // 1e9 bytes → ceil(/MiB) = 954
            ("2G", 1908),        // bare G = decimal
            ("1048576", 1),      // bare number = bytes = exactly 1 MiB
            ("1048577", 2),      // one byte over → rounds up
            ("  8 GiB  ", 8192), // surrounding + inner whitespace tolerated
        ] {
            let db = DatabaseConfig {
                engine: None,
                schema: "s.rhype".into(),
                rules: None,
                size: Some(s.into()),
            };
            assert_eq!(db.size_mib().unwrap(), Some(want), "size {s:?}");
            db.validate().unwrap();
        }

        // Unset → None (the host falls back to the platform default).
        let db = DatabaseConfig {
            engine: None,
            schema: "s.rhype".into(),
            rules: None,
            size: None,
        };
        assert_eq!(db.size_mib().unwrap(), None);
        // Sidecar carries an explicit null so the host reads Option::None.
        let bare_size: ProjectConfig =
            toml::from_str("[database]\nschema = \"s.rhype\"\n").unwrap();
        assert!(
            bare_size
                .database_json()
                .unwrap()
                .contains("\"size_mib\": null")
        );

        // Malformed sizes fail closed (a typo must abort the deploy). An empty/
        // whitespace `size` is treated as unset (Ok(None)), like an omitted field.
        for bad in ["banana", "4 quux", "GiB", "-1MiB", "1 2 3"] {
            let db = DatabaseConfig {
                engine: None,
                schema: "s.rhype".into(),
                rules: None,
                size: Some(bad.into()),
            };
            assert!(db.size_mib().is_err(), "size {bad:?} should be rejected");
            assert!(db.validate().is_err(), "validate should reject {bad:?}");
        }
    }
}
