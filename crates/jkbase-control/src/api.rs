use crate::auth::{self, ApiToken, Tenant};
use crate::logstore::LogStore;
use crate::store::{
    BuildPhase, BuildRecord, DomainKind, DomainRecord, DomainStatus, Project, Store,
};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use http_body_util::BodyExt;
use jkbase_common::routing::DomainTarget;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

pub type DeployCallback = Box<
    dyn Fn(String, u64) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync,
>;

/// Fully reap a deleted project's runtime resources — stop its VM, free the
/// IP/TAP allocation, and remove its on-disk artifacts. Mirrors `DeployCallback`
/// (control owns no orch dependency); the server binary provides the impl.
pub type TeardownCallback =
    Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync>;

/// Inputs handed to the server-provided build orchestrator for one build job.
pub struct BuildContext {
    pub project_id: String,
    pub build_id: u64,
    /// The uploaded source tree as a gzipped tar (jkbase.toml + per-target source
    /// dirs + site content; `.git`/`node_modules`/`target` excluded by the CLI).
    pub source_tar_gz: Vec<u8>,
}

/// Drives the per-target build fan-out (design §12) and returns a fully-assembled
/// artifact directory (the `_functions/*`, `_servers/*`, `*.json` layout) ready
/// for [`activate_deployment`]. Provided by the server binary, which owns
/// jkbase-orch and the jailer privilege — control has no orch dependency, exactly
/// mirroring [`DeployCallback`]. The orchestrator reports per-target progress by
/// writing the build record through its own `Store` handle (the same redb the API
/// reads), so `GET /builds/{id}` reflects live sub-status.
pub type BuildCallback = Arc<
    dyn Fn(BuildContext) -> Pin<Box<dyn Future<Output = anyhow::Result<PathBuf>> + Send>>
        + Send
        + Sync,
>;

pub type RoutingTable = Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>;
/// host-key → owner/site, mirror of all Active domains (see jkbase-proxy::DomainMap).
pub type DomainMap = Arc<tokio::sync::RwLock<std::collections::HashMap<String, DomainTarget>>>;
/// Fire-and-forget request to (proactively) issue a TLS cert for a verified
/// custom domain. Wired by the server to the proxy's CertManager.
pub type CertRequest = Arc<dyn Fn(String) + Send + Sync>;
/// Query whether a per-host TLS cert has been issued for a custom domain.
pub type CertStatusFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

pub struct AppState {
    pub store: Store,
    pub log_store: LogStore,
    pub deploy_dir: PathBuf,
    pub deploy_callback: Option<DeployCallback>,
    /// Tears down a deleted project's VM + IP/TAP + on-disk artifacts (mirrors
    /// `deploy_callback`). `None` leaves cleanup to the boot-time orphan sweep.
    pub teardown_callback: Option<TeardownCallback>,
    /// Server-provided per-target build orchestrator (mirrors `deploy_callback`).
    /// `None` disables the server-side build pipeline (`POST /build` → 501).
    pub build_callback: Option<BuildCallback>,
    pub routing_table: Option<RoutingTable>,
    pub domain_map: Option<DomainMap>,
    pub cert_request: Option<CertRequest>,
    pub cert_status: Option<CertStatusFn>,
    /// Platform apex (e.g. `jkbase.app`), for classifying subdomains vs custom domains.
    pub platform_domain: String,
    /// Optional platform-operator admin token (jkbase-server `--admin-token`).
    /// When `Some` and a request presents a matching `X-Admin-Token`, the quota
    /// endpoint may raise limits above defaults. `None` = no admin path at all.
    pub admin_token: Option<String>,
    /// Per-project serialization for deploy/build/rollback. A plain
    /// `std::sync::Mutex` (critical sections never await) so [`DeployLockGuard`]
    /// can release on `Drop` — a panicking spawned build task can't leak the lock.
    deploy_locks: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Bounds concurrent in-flight `git-receive-pack` bodies (each buffers up to
    /// `PACK_MAX_BYTES`) so the unauthenticated-at-the-router git endpoint can't
    /// be used to OOM the shared control plane.
    git_pack_permits: Arc<tokio::sync::Semaphore>,
    /// Projects whose git-push build was deferred because a build was already
    /// running; drained (rebuilding the latest tip) when the deploy lock frees.
    pending_git_pushes: std::sync::Mutex<std::collections::HashSet<String>>,
}

#[derive(Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct ProjectResponse {
    pub id: String,
    pub name: String,
    pub current_version: Option<u64>,
    pub url: Option<String>,
    pub domains: Vec<String>,
}

#[derive(Serialize)]
pub struct DeployResponse {
    pub version: u64,
    pub project_id: String,
}

/// 202 response to `POST /build`: the build runs asynchronously; poll the
/// build-job resource at `GET /projects/{id}/builds/{build_id}` for status.
#[derive(Serialize)]
pub struct BuildStartedResponse {
    pub build_id: u64,
    pub project_id: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Typed deploy error carried inside `anyhow::Error` so `do_deploy` keeps its
/// `anyhow::Result` (and all its `?`), while the handler can downcast this case
/// to HTTP 402. Everything else stays 500.
#[derive(Debug)]
struct QuotaExceeded(String);

impl std::fmt::Display for QuotaExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for QuotaExceeded {}

impl AppState {
    pub fn new(store: Store, log_store: LogStore, deploy_dir: PathBuf) -> Self {
        Self {
            store,
            log_store,
            deploy_dir,
            deploy_callback: None,
            teardown_callback: None,
            build_callback: None,
            routing_table: None,
            domain_map: None,
            cert_request: None,
            cert_status: None,
            platform_domain: "jkbase.app".to_string(),
            admin_token: None,
            deploy_locks: std::sync::Mutex::new(std::collections::HashSet::new()),
            git_pack_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PACKS)),
            pending_git_pushes: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// True if the request carries a valid platform-admin token. Always false
    /// unless the server was started with `--admin-token`, so a tenant can never
    /// self-elevate above the platform default quotas.
    fn is_admin_request(&self, headers: &axum::http::HeaderMap) -> bool {
        let Some(configured) = self.admin_token.as_deref() else {
            return false;
        };
        let Some(presented) = headers.get("x-admin-token").and_then(|v| v.to_str().ok()) else {
            return false;
        };
        ct_eq(configured.as_bytes(), presented.as_bytes())
    }
}

/// Length-checked constant-time byte comparison, so a near-miss admin token isn't
/// distinguishable by how long the comparison takes.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// RAII guard for the per-project deploy/build/rollback lock. Acquiring fails if
/// the project is already locked; the guard releases the lock on `Drop` —
/// including when the holder unwinds. That matters most for the build path, which
/// moves the guard into a detached task running a multi-minute, attacker-
/// influenced fan-out: a panic there must not wedge the project forever.
struct DeployLockGuard {
    state: Arc<AppState>,
    id: String,
}

impl DeployLockGuard {
    /// Lock `id`, or `None` if a deploy/build/rollback is already in progress.
    fn try_acquire(state: &Arc<AppState>, id: &str) -> Option<Self> {
        let mut locks = state.deploy_locks.lock().unwrap_or_else(|p| p.into_inner());
        if locks.insert(id.to_string()) {
            Some(Self {
                state: state.clone(),
                id: id.to_string(),
            })
        } else {
            None
        }
    }
}

impl Drop for DeployLockGuard {
    fn drop(&mut self) {
        let mut locks = self
            .state
            .deploy_locks
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        locks.remove(&self.id);
    }
}

pub fn router(state: Arc<AppState>, platform_domain: String) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            format!("https://console.{platform_domain}")
                .parse::<HeaderValue>()
                .unwrap(),
            format!("https://{platform_domain}")
                .parse::<HeaderValue>()
                .unwrap(),
            format!("https://www.{platform_domain}")
                .parse::<HeaderValue>()
                .unwrap(),
            "http://localhost:3000".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([hyper::header::AUTHORIZATION, hyper::header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(86400));

    let authenticated = Router::new()
        .route("/projects", get(list_projects).post(create_project))
        .route("/projects/{id}", get(get_project).delete(delete_project))
        .route("/projects/{id}/deploy", post(deploy))
        .route("/projects/{id}/build", post(build))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024))
        .route("/projects/{id}/builds", get(list_builds))
        .route("/projects/{id}/builds/{build_id}", get(get_build))
        .route("/projects/{id}/secrets", get(list_secrets).post(set_secret))
        .route(
            "/projects/{id}/secrets/{key}",
            axum::routing::delete(delete_secret),
        )
        .route(
            "/projects/{id}/access-keys",
            get(list_access_keys).post(issue_access_key),
        )
        .route(
            "/projects/{id}/access-keys/{akid}",
            axum::routing::delete(revoke_access_key),
        )
        .route("/projects/{id}/repo", get(get_repo_trigger_status))
        .route(
            "/projects/{id}/repo/git-token",
            post(mint_git_token).delete(revoke_git_token),
        )
        .route("/projects/{id}/logs", get(get_project_logs))
        .route("/projects/{id}/deployments", get(list_deployments))
        .route("/projects/{id}/rollback", post(rollback))
        .route("/projects/{id}/status", get(get_project_status))
        .route("/projects/{id}/usage", get(get_project_usage))
        .route(
            "/projects/{id}/quota",
            get(get_project_quota).post(set_project_quota),
        )
        .route("/projects/{id}/domains", get(list_domains).post(add_domain))
        .route(
            "/projects/{id}/domains/{domain}/verify",
            post(verify_domain),
        )
        .route(
            "/projects/{id}/domains/{domain}",
            axum::routing::delete(remove_domain),
        )
        .route("/me", get(get_me))
        .route("/me/token", post(generate_new_token))
        .route("/me/password", post(change_password))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let public = Router::new()
        .route("/init", post(init_platform))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/health", get(api_health));

    // Connected-repo build trigger (build · D). Self-authenticates via an HTTP
    // Basic per-project git-push token, so it must NOT sit behind the Bearer
    // `require_auth` layer, and it carries no `DefaultBodyLimit` —
    // `git-receive-pack` enforces its own streamed pack cap + concurrency bound.
    let triggers = Router::new()
        .route("/git/{id}/info/refs", get(git_info_refs))
        .route("/git/{id}/git-receive-pack", post(git_receive_pack));

    Router::new()
        .merge(authenticated)
        .merge(public)
        .merge(triggers)
        .layer(cors)
        .with_state(state)
}

#[derive(Deserialize)]
pub struct InitRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct InitResponse {
    pub tenant_id: String,
    pub token: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub tenant_id: String,
    pub token: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub tenant_id: String,
    pub token: String,
}

async fn api_health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn get_me(Extension(tenant): Extension<Tenant>) -> impl IntoResponse {
    Json(serde_json::json!({
        "id": tenant.id,
        "email": tenant.email,
    }))
}

async fn init_platform(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitRequest>,
) -> impl IntoResponse {
    let has_tenants = state
        .store
        .list_tenants()
        .map(|t| !t.is_empty())
        .unwrap_or(false);

    if has_tenants {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "platform already initialized".to_string(),
            }),
        )
            .into_response();
    }

    match create_tenant_and_token(&state.store, &req.email, None) {
        Ok((tenant_id, raw_token)) => {
            info!(tenant_id = %tenant_id, email = %req.email, "platform initialized");
            (
                StatusCode::CREATED,
                Json(InitResponse {
                    tenant_id,
                    token: raw_token,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    if req.email.is_empty() || !req.email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid email address".to_string(),
            }),
        )
            .into_response();
    }

    if req.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "password must be at least 8 characters".to_string(),
            }),
        )
            .into_response();
    }

    if let Ok(Some(_)) = state.store.find_tenant_by_email(&req.email) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "an account with this email already exists".to_string(),
            }),
        )
            .into_response();
    }

    let password_hash = match auth::hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    match create_tenant_and_token(&state.store, &req.email, Some(&password_hash)) {
        Ok((tenant_id, raw_token)) => {
            info!(tenant_id = %tenant_id, email = %req.email, "new tenant registered");
            (
                StatusCode::CREATED,
                Json(RegisterResponse {
                    tenant_id,
                    token: raw_token,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let tenant = match state.store.find_tenant_by_email(&req.email) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid email or password".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(ref password_hash) = tenant.password_hash else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "this account does not have a password — use token auth".to_string(),
            }),
        )
            .into_response();
    };

    if !auth::verify_password(&req.password, password_hash) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid email or password".to_string(),
            }),
        )
            .into_response();
    }

    let raw_token = auth::generate_token();
    let token_hash = match auth::hash_token(&raw_token) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    let api_token = auth::ApiToken {
        id: auth::generate_id(),
        tenant_id: tenant.id.clone(),
        name: "web-login".to_string(),
        token_hash,
        created_at: auth::timestamp(),
    };

    if let Err(e) = state.store.save_api_token(&api_token) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    info!(tenant_id = %tenant.id, email = %req.email, "tenant logged in");
    (
        StatusCode::OK,
        Json(LoginResponse {
            tenant_id: tenant.id,
            token: raw_token,
        }),
    )
        .into_response()
}

fn create_tenant_and_token(
    store: &Store,
    email: &str,
    password_hash: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let tenant_id = auth::generate_id();
    let tenant = Tenant {
        id: tenant_id.clone(),
        email: email.to_string(),
        password_hash: password_hash.map(|h| h.to_string()),
        created_at: auth::timestamp(),
    };
    store.create_tenant(&tenant)?;

    let raw_token = auth::generate_token();
    let token_hash = auth::hash_token(&raw_token)?;
    let api_token = ApiToken {
        id: auth::generate_id(),
        tenant_id: tenant_id.clone(),
        name: "default".to_string(),
        token_hash,
        created_at: auth::timestamp(),
    };
    store.save_api_token(&api_token)?;

    Ok((tenant_id, raw_token))
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let Some(token) = token else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "missing Authorization header".to_string(),
            }),
        )
            .into_response();
    };

    match state.store.authenticate(token) {
        Ok(Some(tenant)) => {
            req.extensions_mut().insert(tenant);
            next.run(req).await.into_response()
        }
        Ok(None) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid token".to_string(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn create_project(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Json(req): Json<CreateProjectRequest>,
) -> impl IntoResponse {
    let id = slug(&req.name);

    // The slug becomes a filesystem path component for per-project state (object-store
    // root, content image, data disk, hosting dir). slug() can collapse to "" (e.g.
    // ".", "/", "---") or otherwise diverge, and an empty id would resolve the
    // object-store root to the SHARED `objectstore/` parent — a cross-tenant breach.
    // Enforce the same `[a-z0-9-]` (1-63) invariant every downstream path-join assumes.
    if !is_valid_project_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "invalid project name: must reduce to [a-z0-9-] (1-63 chars); got '{id}'"
                ),
            }),
        )
            .into_response();
    }

    if crate::store::host_is_reserved(&id) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!("'{id}' is a reserved name"),
            }),
        )
            .into_response();
    }

    if state.store.get_project(&id).ok().flatten().is_some() {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!("project '{id}' already exists"),
            }),
        )
            .into_response();
    }

    // Defense-in-depth: a crashed/interrupted teardown of a prior same-slug project
    // could have left orphaned per-id state — tenant env secrets, S3 access keys, or
    // the object-store root — that the deploy/auth paths would otherwise serve to the
    // NEW owner (cross-tenant inheritance). Purge it before the slug is reused.
    let _ = state.store.delete_all_secrets(&id);
    let _ = state.store.delete_all_access_keys(&id);
    let _ = state.store.delete_all_db_access_keys(&id);
    let _ = tokio::fs::remove_dir_all(data_dir(&state).join("objectstore").join(&id)).await;

    // Claim the project's primary subdomain (host-key == project id). This also
    // reserves the name in the unified hostname namespace.
    let primary = DomainRecord {
        host: id.clone(),
        project_id: id.clone(),
        tenant_id: tenant.id.clone(),
        site: None,
        kind: DomainKind::Subdomain,
        status: DomainStatus::Active,
        token: String::new(),
        created_at: auth::timestamp(),
    };
    match state.store.claim_domain(&primary) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: format!("'{id}' is already in use"),
                }),
            )
                .into_response();
        }
        Err(e) => return internal_error(e),
    }

    let project = Project {
        id: id.clone(),
        name: req.name,
        tenant_id: Some(tenant.id),
        current_version: None,
        vm_ip: None,
        state: crate::store::ProjectState::Stopped,
        domains: Vec::new(),
    };

    if let Err(e) = state.store.create_project(&project) {
        let _ = state.store.remove_domain(&id); // roll back the claim
        return internal_error(e);
    }

    // Register the primary in the live map so the subdomain resolves (waking the
    // VM on first hit once deployed).
    activate_domain(&state, &primary).await;

    info!(project_id = %id, "project created");
    (StatusCode::CREATED, Json(to_response(&project))).into_response()
}

async fn list_projects(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
) -> impl IntoResponse {
    match state.store.list_projects_for_tenant(&tenant.id) {
        Ok(projects) => {
            let resp: Vec<ProjectResponse> = projects.iter().map(to_response).collect();
            Json(resp).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn get_project(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(project)) if project.tenant_id.as_deref() == Some(&tenant.id) => {
            Json(to_response(&project)).into_response()
        }
        Ok(Some(_)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("project '{id}' not found"),
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("project '{id}' not found"),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn delete_project(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(project)) if project.tenant_id.as_deref() == Some(&tenant.id) => {
            // Serialize against an in-flight deploy/build/rollback for this project
            // so teardown can't race a deployment that is mid-activation.
            let Some(_guard) = DeployLockGuard::try_acquire(&state, &id) else {
                return (
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        error: "a deploy/build/rollback is in progress for this project"
                            .to_string(),
                    }),
                )
                    .into_response();
            };
            match state.store.delete_project(&id) {
                Ok(_) => {
                    if let Err(e) = state.log_store.clear(&id) {
                        tracing::warn!(project_id = %id, error = %e, "failed to clear project logs");
                    }
                    if let Ok(deployments) = state.store.list_deployments(&id) {
                        for d in deployments {
                            let _ = state.store.remove_deployment(&id, d.version);
                        }
                    }
                    // Drop any cron schedules so the host scheduler stops firing.
                    if let Ok(schedules) = state.store.list_schedules_for_project(&id) {
                        for s in schedules {
                            let _ = state.store.remove_schedule(&id, &s.function);
                        }
                    }
                    // Drop metering buckets + quota override + enforcement state.
                    let _ = state.store.purge_usage(&id);
                    let _ = state.store.remove_quota(&id);
                    let _ = state.store.remove_quota_status(&id);
                    // Purge the project's secrets so a recreated project of the same
                    // slug can't inherit them — the deploy path injects secrets into the
                    // container env, so a stale secret would leak to a new tenant.
                    let _ = state.store.delete_all_secrets(&id);
                    // Revoke all object-store access keys + purge the project's
                    // object-store root, same reasoning as secrets: a recreated
                    // same-slug project must not inherit a prior tenant's S3
                    // credentials or stored objects (keys gate cross-tenant access).
                    let _ = state.store.delete_all_access_keys(&id);
                    // Same reasoning for the managed-DB reach-plane keys: a recreated
                    // same-slug project must not inherit a prior tenant's DB credential.
                    let _ = state.store.delete_all_db_access_keys(&id);
                    let _ =
                        tokio::fs::remove_dir_all(data_dir(&state).join("objectstore").join(&id))
                            .await;
                    // Reap the git-push credential + bare repo so a recreated
                    // project of the same slug can't inherit a prior tenant's
                    // token or pushed objects (the auth tenant-check is the
                    // primary guard; this is cleanup + disk reclaim).
                    let _ = state.store.delete_repo_trigger(&id);
                    let _ = tokio::fs::remove_dir_all(crate::git_http::bare_repo_path(
                        data_dir(&state),
                        &id,
                    ))
                    .await;
                    // Release all claimed hostnames so they can't be taken over
                    // or left dangling in the routing maps.
                    if let Ok(domains) = state.store.list_domains_for_project(&id) {
                        for d in domains {
                            let _ = state.store.remove_domain(&d.host);
                            deactivate_host(&state, &d.host).await;
                        }
                    }
                    // Stop the VM, free the IP/TAP, and remove on-disk artifacts.
                    // Best-effort: a failure is reconciled by the boot-time orphan
                    // sweep, so it must not fail the delete.
                    if let Some(cb) = &state.teardown_callback
                        && let Err(e) = cb(id.clone()).await
                    {
                        tracing::warn!(project_id = %id, error = %e, "project teardown failed; boot-time orphan sweep will reconcile");
                    }
                    info!(project_id = %id, "project deleted");
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
                    .into_response(),
            }
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("project '{id}' not found"),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn deploy(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let mut project = match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => p,
        Ok(Some(_)) | Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    // Serialize against concurrent deploy/build/rollback; the guard releases the
    // lock on drop, even if `do_deploy` unwinds.
    let Some(_guard) = DeployLockGuard::try_acquire(&state, &id) else {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "deploy already in progress".to_string(),
            }),
        )
            .into_response();
    };

    let result = do_deploy(&state, &mut project, &body).await;

    match result {
        Ok(version) => (
            StatusCode::OK,
            Json(DeployResponse {
                version,
                project_id: id,
            }),
        )
            .into_response(),
        Err(e) => {
            let (status, msg) = match e.downcast_ref::<QuotaExceeded>() {
                Some(q) => (StatusCode::PAYMENT_REQUIRED, q.to_string()),
                None => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            };
            (status, Json(ErrorResponse { error: msg })).into_response()
        }
    }
}

/// Authorize that `tenant` owns project `id`, returning the project or a ready
/// HTTP error response (404 if missing/foreign, 500 on store error).
type ApiError = (StatusCode, Json<ErrorResponse>);

fn require_project_owner(state: &AppState, tenant: &Tenant, id: &str) -> Result<Project, ApiError> {
    match state.store.get_project(id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => Ok(p),
        Ok(Some(_)) | Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("project '{id}' not found"),
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

// -- Connected-repo build trigger: git-push credential management (build · D) --

/// The control-plane API origin (`https://api.{apex}`), where the `/git/{id}`
/// push endpoint lives.
fn api_base_url(state: &AppState) -> String {
    format!("https://api.{}", state.platform_domain)
}

#[derive(Serialize)]
struct GitTokenResponse {
    /// The plaintext push token — shown ONCE; jkbase keeps only its fingerprint.
    token: String,
    /// Ready-to-use remote with the token embedded: `git push <push_url> main`.
    push_url: String,
}

#[derive(Serialize)]
struct RepoTriggerStatusResponse {
    git_token_configured: bool,
    git_token_created_at: Option<u64>,
    /// Token-less push URL (the tenant supplies the token via Basic auth).
    push_url: String,
}

/// `POST /projects/{id}/repo/git-token` — mint (or rotate) the per-project
/// git-push token. The plaintext is returned once; only its SHA-256 fingerprint
/// is stored. Rotating invalidates the previous token immediately.
async fn mint_git_token(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let project = match require_project_owner(&state, &tenant, &id) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let token = auth::generate_git_token();
    let mut cfg = state
        .store
        .get_repo_trigger(&id)
        .ok()
        .flatten()
        .unwrap_or_default();
    cfg.project_id = id.clone();
    cfg.tenant_id = project.tenant_id;
    cfg.git_token_fingerprint = Some(auth::token_fingerprint(&token));
    cfg.git_token_created_at = auth::timestamp();
    if let Err(e) = state.store.save_repo_trigger(&cfg) {
        return internal_error(e);
    }
    let push_url = format!(
        "{}/git/{id}",
        api_base_url(&state).replace("https://", &format!("https://jkbase:{token}@"))
    );
    (
        StatusCode::CREATED,
        Json(GitTokenResponse { token, push_url }),
    )
        .into_response()
}

/// `DELETE /projects/{id}/repo/git-token` — revoke the git-push token.
async fn revoke_git_token(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    let mut cfg = state
        .store
        .get_repo_trigger(&id)
        .ok()
        .flatten()
        .unwrap_or_default();
    cfg.project_id = id.clone();
    cfg.git_token_fingerprint = None;
    cfg.git_token_created_at = 0;
    if let Err(e) = state.store.save_repo_trigger(&cfg) {
        return internal_error(e);
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /projects/{id}/repo` — report whether the git-push token is configured
/// (never returns the token itself).
async fn get_repo_trigger_status(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    let cfg = state
        .store
        .get_repo_trigger(&id)
        .ok()
        .flatten()
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(RepoTriggerStatusResponse {
            git_token_configured: cfg.git_token_fingerprint.is_some(),
            git_token_created_at: (cfg.git_token_created_at != 0)
                .then_some(cfg.git_token_created_at),
            push_url: format!("{}/git/{id}", api_base_url(&state)),
        }),
    )
        .into_response()
}

// -- Smart-HTTP git server: `git push jkbase main` build trigger (build · D) --

/// The branch whose pushes trigger a build. Pushing any other branch updates the
/// bare repo but is a no-op for the build pipeline (design §9 / map gotcha).
const GIT_PUSH_TRIGGER_BRANCH: &str = "main";

/// Max concurrent `git-receive-pack` bodies in flight across the control plane.
/// Each can buffer up to `PACK_MAX_BYTES`, so this caps git-push memory; excess
/// pushes get a fast 503 rather than queueing (and holding) more memory.
const MAX_CONCURRENT_PACKS: usize = 4;

/// Per-project on-host state root (`{deploy_dir}/..`), where the git bare repos
/// live under `git/`. Mirrors the derivation in `get_project_usage`.
fn data_dir(state: &AppState) -> &FsPath {
    state.deploy_dir.parent().unwrap_or(&state.deploy_dir)
}

/// Extract the token a git client sends as the HTTP Basic password (any
/// username; git puts the credential in the password field).
fn basic_auth_token(headers: &HeaderMap) -> Option<String> {
    use base64::Engine as _;
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let b64 = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (_user, pass) = creds.split_once(':')?;
    Some(pass.to_string())
}

/// True if `id` is a well-formed project slug (the invariant `create_project`
/// enforces). Rejecting anything else keeps a crafted `{id}` (`..`, encoded `/`)
/// from ever reaching the bare-repo path join, independent of the auth gate.
fn is_valid_project_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validate the presented git-push token for `project_id`. Three gates, in order:
/// the project must currently exist, its current owner must match the tenant that
/// minted the token (so a credential record outliving a delete/recreate of the
/// same slug can't authenticate a different tenant — cross-tenant takeover), and
/// the token fingerprint must match (constant-time). Looking up by the path `{id}`
/// (not by token) is O(1) and rejects a token minted for a different project.
fn git_authenticated(state: &AppState, project_id: &str, headers: &HeaderMap) -> bool {
    if !is_valid_project_id(project_id) {
        return false;
    }
    let Some(cfg) = state.store.get_repo_trigger(project_id).ok().flatten() else {
        return false;
    };
    let Some(stored_fp) = cfg.git_token_fingerprint else {
        return false;
    };
    // The project must exist now and still be owned by the token's tenant.
    let Ok(Some(project)) = state.store.get_project(project_id) else {
        return false;
    };
    if project.tenant_id.is_none() || project.tenant_id != cfg.tenant_id {
        return false;
    }
    let Some(token) = basic_auth_token(headers) else {
        return false;
    };
    ct_eq(
        auth::token_fingerprint(&token).as_bytes(),
        stored_fp.as_bytes(),
    )
}

/// 401 with `WWW-Authenticate` so a git client (re)sends Basic credentials.
fn git_unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            "Basic realm=\"jkbase\"",
        )],
        "git authentication required",
    )
        .into_response()
}

/// 500 for the git endpoints that logs the real cause (which can include the
/// host `data_dir` path or git stderr) but returns a generic body, so a failing
/// push doesn't disclose host internals to an authenticated tenant.
fn git_internal_error(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "git endpoint internal error");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

enum BodyReadError {
    TooLarge,
    Io,
}

/// Read a request body fully but abort past `cap` bytes (pack-bomb DoS — §9:
/// the generous `/build` body limit doesn't bound a streamed receive). If the
/// body is `Content-Encoding: gzip`, decompress with the SAME cap on the output
/// so a gzip bomb can't expand past the limit either.
async fn read_body_capped(
    headers: &HeaderMap,
    body: Body,
    cap: usize,
) -> Result<Vec<u8>, BodyReadError> {
    let mut collected = Vec::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyReadError::Io)?;
        if let Ok(data) = frame.into_data() {
            if collected.len() + data.len() > cap {
                return Err(BodyReadError::TooLarge);
            }
            collected.extend_from_slice(&data);
        }
    }

    let is_gzip = headers
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("gzip"))
        .unwrap_or(false);
    if !is_gzip {
        return Ok(collected);
    }

    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(&collected[..])
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| BodyReadError::Io)?;
    if out.len() > cap {
        return Err(BodyReadError::TooLarge);
    }
    Ok(out)
}

/// `GET /git/{id}/info/refs?service=git-receive-pack` — the push handshake. We
/// only serve `git-receive-pack` (pushes); clone/fetch (`git-upload-pack`) is not
/// offered.
async fn git_info_refs(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // Auth first, so every unauthorized request gets a uniform 401 (and git's
    // initial unauthenticated probe is challenged into retrying with creds).
    if !git_authenticated(&state, &id, &headers) {
        return git_unauthorized();
    }
    if params.get("service").map(String::as_str) != Some("git-receive-pack") {
        return (
            StatusCode::FORBIDDEN,
            "only git-receive-pack (push) is supported",
        )
            .into_response();
    }
    let repo = crate::git_http::bare_repo_path(data_dir(&state), &id);
    if let Err(e) = crate::git_http::ensure_bare_repo(&repo).await {
        return git_internal_error(e);
    }
    match crate::git_http::advertise_refs(&repo).await {
        Ok(body) => (
            StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/x-git-receive-pack-advertisement",
                ),
                (axum::http::header::CACHE_CONTROL, "no-cache"),
            ],
            body,
        )
            .into_response(),
        Err(e) => internal_error(e),
    }
}

/// `POST /git/{id}/git-receive-pack` — receive the push, then (if the trigger
/// branch advanced) snapshot its tip and funnel it into a build.
async fn git_receive_pack(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !git_authenticated(&state, &id, &headers) {
        return git_unauthorized();
    }
    // Bound concurrent in-flight packs (each buffers up to PACK_MAX_BYTES) before
    // reading anything, so a flood of pushes can't OOM the shared control plane.
    let Ok(_permit) = state.git_pack_permits.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "5")],
            "too many concurrent pushes, retry shortly",
        )
            .into_response();
    };
    let repo = crate::git_http::bare_repo_path(data_dir(&state), &id);
    if let Err(e) = crate::git_http::ensure_bare_repo(&repo).await {
        return git_internal_error(e);
    }

    let input = match read_body_capped(&headers, body, crate::git_http::PACK_MAX_BYTES).await {
        Ok(b) => b,
        Err(BodyReadError::TooLarge) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "pack exceeds the {} byte limit",
                    crate::git_http::PACK_MAX_BYTES
                ),
            )
                .into_response();
        }
        Err(BodyReadError::Io) => {
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };
    if let Err(e) = crate::git_http::check_pack_object_count(&input) {
        return (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response();
    }

    // Trigger a build only if this push advances the configured branch. The pack
    // bytes are moved into `receive_pack` (no extra copy) and dropped after.
    let before = crate::git_http::branch_tip(&repo, GIT_PUSH_TRIGGER_BRANCH).await;
    let result = match crate::git_http::receive_pack(&repo, input).await {
        Ok(r) => r,
        Err(e) => return git_internal_error(e),
    };
    if let Some(commit) = crate::git_http::branch_tip(&repo, GIT_PUSH_TRIGGER_BRANCH).await
        && before.as_deref() != Some(commit.as_str())
    {
        spawn_git_push_build(state.clone(), id.clone(), repo.clone(), commit);
    }

    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/x-git-receive-pack-result",
            ),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        result,
    )
        .into_response()
}

/// Archive the pushed tip and start a build, off the git response path. A push
/// always succeeds at the git layer; the build runs asynchronously.
///
/// If a build is already running (`Locked`), the push is *not* dropped: the
/// project is marked pending and [`drain_pending_git_push`] rebuilds the latest
/// tip when that build finishes. Without this, the ref has already advanced, so
/// re-pushing the same commit would be a no-op (`before == commit`) and prod
/// would silently stay on the old build.
fn spawn_git_push_build(state: Arc<AppState>, id: String, repo: PathBuf, commit: String) {
    tokio::spawn(async move {
        let targz = match crate::git_http::archive_commit_targz(&repo, &commit).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(project = %id, error = %e, "git-push: archive failed");
                return;
            }
        };
        match start_build_job(&state, &id, targz) {
            Ok(build_id) => {
                tracing::info!(project = %id, build_id, commit = %commit, "git-push triggered build")
            }
            Err(StartBuildError::Locked) => {
                state
                    .pending_git_pushes
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(id.clone());
                tracing::info!(project = %id, commit = %commit, "git-push: build in progress; queued a rebuild of the latest tip")
            }
            Err(StartBuildError::OverQuota(m)) => {
                tracing::warn!(project = %id, reason = %m, "git-push: build skipped (over quota)")
            }
            Err(StartBuildError::NotEnabled) => {
                tracing::warn!(project = %id, "git-push: build pipeline not enabled")
            }
            Err(StartBuildError::Internal(m)) => {
                tracing::error!(project = %id, error = %m, "git-push: failed to start build")
            }
        }
    });
}

/// After a build finishes (deploy lock now free), if a git push was deferred for
/// this project, rebuild its current tip — coalescing any pushes that arrived
/// while the lock was held into a single rebuild of the newest commit.
async fn drain_pending_git_push(state: Arc<AppState>, id: String) {
    let pending = state
        .pending_git_pushes
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id);
    if !pending {
        return;
    }
    let repo = crate::git_http::bare_repo_path(data_dir(&state), &id);
    if let Some(commit) = crate::git_http::branch_tip(&repo, GIT_PUSH_TRIGGER_BRANCH).await {
        // spawn_git_push_build re-queues if it's *still* locked (a new build
        // grabbed the lock first); that build will drain again on completion.
        spawn_git_push_build(state, id, repo, commit);
    }
}

/// `POST /projects/{id}/build` — the one build-pipeline intake funnel. Accepts a
/// gzipped source tarball, registers a build job, and fans out per-target build
/// VMs asynchronously (design §4/§12). Returns 202 immediately; the client polls
/// the build-job resource. Reuses `deploy_locks` (serialize per project), the
/// 2 GiB body limit, and the storage-quota 402 in the shared deploy tail.
async fn build(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    match start_build_job(&state, &id, body.to_vec()) {
        Ok(build_id) => (
            StatusCode::ACCEPTED,
            Json(BuildStartedResponse {
                build_id,
                project_id: id,
            }),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Why the shared build funnel refused to start a job.
enum StartBuildError {
    /// The server-side build pipeline isn't enabled (`build_callback` is None).
    NotEnabled,
    /// The project is at its build-minute cap (pre-build 402 gate).
    OverQuota(String),
    /// A deploy/build/rollback is already running for this project.
    Locked,
    /// A store error allocating/persisting the build record.
    Internal(String),
}

impl StartBuildError {
    fn into_response(self) -> axum::response::Response {
        match self {
            StartBuildError::NotEnabled => (
                StatusCode::NOT_IMPLEMENTED,
                Json(ErrorResponse {
                    error: "server-side build pipeline is not enabled".to_string(),
                }),
            )
                .into_response(),
            StartBuildError::OverQuota(msg) => (
                StatusCode::PAYMENT_REQUIRED,
                Json(ErrorResponse { error: msg }),
            )
                .into_response(),
            StartBuildError::Locked => (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "a deploy or build is already in progress".to_string(),
                }),
            )
                .into_response(),
            StartBuildError::Internal(msg) => internal_error(msg),
        }
    }
}

/// The one build-pipeline funnel shared by every trigger (CLI `POST /build`,
/// git-push): enforce the pre-build 402 gate, serialize per project,
/// allocate a build id, persist a `Queued` record, and spawn the background job.
/// Ownership/authentication is the caller's responsibility. Returns the new
/// build id. The `DeployLockGuard` is moved into the spawned task and releases
/// on drop — including on panic-unwind, so a wedged build can't lock the project
/// forever.
fn start_build_job(
    state: &Arc<AppState>,
    id: &str,
    source_tar_gz: Vec<u8>,
) -> Result<u64, StartBuildError> {
    if state.build_callback.is_none() {
        return Err(StartBuildError::NotEnabled);
    }

    // Pre-build 402 gate: a project already at its build-minute cap can't launch
    // (prevents launch-storms — threat-model P1-4; the build VM is metered on
    // exit, but the gate must debit before launch). deploy_locks already
    // serializes builds per project, so this MTD check can't be raced past.
    {
        let month_start = crate::store::month_start_epoch(auth::timestamp());
        let used = state
            .store
            .sum_month_to_date(id, month_start)
            .map(|m| m.build_seconds)
            .unwrap_or(0);
        let cap = state
            .store
            .get_quota(id)
            .map(|q| q.build_seconds_per_month)
            .unwrap_or(crate::store::DEFAULT_QUOTA.build_seconds_per_month);
        if used >= cap {
            return Err(StartBuildError::OverQuota(format!(
                "build-minute quota exceeded: {used} of {cap} build-seconds used this month"
            )));
        }
    }

    let guard = DeployLockGuard::try_acquire(state, id).ok_or(StartBuildError::Locked)?;

    let build_id = state
        .store
        .next_build_id(id)
        .map_err(|e| StartBuildError::Internal(e.to_string()))?;
    let now = auth::timestamp();
    let rec = BuildRecord {
        project_id: id.to_string(),
        build_id,
        phase: BuildPhase::Queued,
        targets: Vec::new(),
        log_tail: String::new(),
        phase_timings_ms: Default::default(),
        deployed_version: None,
        error: None,
        source_commit: None,
        created_at: now,
        updated_at: now,
    };
    state
        .store
        .save_build(&rec)
        .map_err(|e| StartBuildError::Internal(e.to_string()))?;

    let state_bg = state.clone();
    let id_bg = id.to_string();
    tokio::spawn(async move {
        {
            // Released on completion OR panic-unwind of the build task.
            let _guard = guard;
            run_build_job(state_bg.clone(), &id_bg, build_id, source_tar_gz).await;
        }
        // Lock is free now: rebuild the latest tip if a git push was deferred
        // while this build held the lock (coalesced; no-op otherwise).
        drain_pending_git_push(state_bg, id_bg).await;
    });

    Ok(build_id)
}

/// Re-read the latest build record, apply `f`, stamp `updated_at`, and persist.
/// Re-reading each time preserves concurrent per-target writes from the server
/// orchestrator — control only mutates at phase boundaries, so they don't overlap.
fn update_build(
    state: &AppState,
    project_id: &str,
    build_id: u64,
    f: impl FnOnce(&mut BuildRecord),
) {
    match state.store.get_build(project_id, build_id) {
        Ok(Some(mut r)) => {
            f(&mut r);
            r.updated_at = auth::timestamp();
            if let Err(e) = state.store.save_build(&r) {
                tracing::warn!(project_id, build_id, error = %e, "failed to persist build record");
            }
        }
        Ok(None) => tracing::warn!(project_id, build_id, "build record vanished mid-update"),
        Err(e) => tracing::warn!(project_id, build_id, error = %e, "failed to read build record"),
    }
}

/// Drive one build job to a terminal state: fan out per-target build VMs (via the
/// server-provided callback), then on success hand the assembled artifacts to the
/// shared deploy tail. Atomic — any target failure fails the whole build and no
/// `live` swap happens (design §12). Always leaves the record Succeeded or Failed.
async fn run_build_job(
    state: Arc<AppState>,
    project_id: &str,
    build_id: u64,
    source_tar_gz: Vec<u8>,
) {
    update_build(&state, project_id, build_id, |r| {
        r.phase = BuildPhase::Building
    });

    let Some(cb) = state.build_callback.clone() else {
        update_build(&state, project_id, build_id, |r| {
            r.phase = BuildPhase::Failed;
            r.error = Some("build pipeline not enabled".to_string());
        });
        return;
    };

    let fanout_start = std::time::Instant::now();
    let ctx = BuildContext {
        project_id: project_id.to_string(),
        build_id,
        source_tar_gz,
    };
    let staged = match cb(ctx).await {
        Ok(p) => p,
        Err(e) => {
            update_build(&state, project_id, build_id, |r| {
                r.phase = BuildPhase::Failed;
                r.error = Some(format!("build failed: {e:#}"));
            });
            return;
        }
    };
    let fanout_ms = fanout_start.elapsed().as_millis() as u64;

    let mut project = match state.store.get_project(project_id) {
        Ok(Some(p)) => p,
        _ => {
            update_build(&state, project_id, build_id, |r| {
                r.phase = BuildPhase::Failed;
                r.error = Some("project not found at activation".to_string());
            });
            return;
        }
    };

    let activate_start = std::time::Instant::now();
    match activate_deployment(&state, &mut project, &staged).await {
        Ok(version) => {
            let activate_ms = activate_start.elapsed().as_millis() as u64;
            update_build(&state, project_id, build_id, |r| {
                r.phase = BuildPhase::Succeeded;
                r.deployed_version = Some(version);
                r.phase_timings_ms.insert("fanout".to_string(), fanout_ms);
                r.phase_timings_ms
                    .insert("activate".to_string(), activate_ms);
            });
            info!(
                project_id,
                build_id, version, "build succeeded; deployment activated"
            );
        }
        Err(e) => {
            update_build(&state, project_id, build_id, |r| {
                r.phase = BuildPhase::Failed;
                r.error = Some(format!("activation failed: {e:#}"));
                r.phase_timings_ms.insert("fanout".to_string(), fanout_ms);
            });
        }
    }

    let _ = state.store.prune_builds(project_id, 20);
}

/// `GET /projects/{id}/builds/{build_id}` — one build job's terminal/in-flight
/// status, per-target sub-status, captured log tail, and per-phase timings.
async fn get_build(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path((id, build_id)): Path<(String, u64)>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    match state.store.get_build(&id, build_id) {
        Ok(Some(rec)) => (StatusCode::OK, Json(rec)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("build {build_id} not found"),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// `GET /projects/{id}/builds` — build history, newest first.
async fn list_builds(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_project_owner(&state, &tenant, &id) {
        return e.into_response();
    }
    match state.store.list_builds(&id) {
        Ok(builds) => (StatusCode::OK, Json(builds)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn do_deploy(state: &AppState, project: &mut Project, tarball: &[u8]) -> anyhow::Result<u64> {
    // Unpack the uploaded artifact tarball into a staging dir on the same
    // filesystem as the deployment tree, then activate it via the shared tail.
    let staged = state.deploy_dir.join(&project.id).join(".staging-deploy");
    let _ = tokio::fs::remove_dir_all(&staged).await;
    tokio::fs::create_dir_all(&staged).await?;

    let tar = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(&staged)?;

    activate_deployment(state, project, &staged).await
}

/// Recursively copy `src` into `dst` (used only when a staged dir lands on a
/// different filesystem than `deploy_dir`, so the atomic rename can't be used).
/// Symlinks are recreated as symlinks (not dereferenced) to match `tar::unpack`.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            std::os::unix::fs::symlink(&target, &to)?;
        } else if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Activate a fully-assembled artifact directory as the project's next
/// deployment version. `staged` holds the `_functions/*`, `_servers/*`, and
/// `*.json` layout; it is MOVED into `deployments/v{N}` (so it must live on the
/// same filesystem as `deploy_dir`). Shared verbatim by the artifact-upload path
/// (`do_deploy`) and the build pipeline, so both get the identical tail: server
/// rootfs pre-extract → storage-quota gate → atomic `live` swap → reconcile
/// domains/schedules → record history + prune → deploy callback (boot runtime).
/// Collect the distinct app-layer digests (`sha256:<hex>`) a deployment references,
/// from each `_servers/<name>.json`'s `app_digest` field (written by the layered
/// build collection). Recorded on the deployment so a future content-store GC knows
/// what each retained version pins.
fn collect_app_layer_digests(deploy_path: &std::path::Path) -> Vec<String> {
    let servers_dir = deploy_path.join("_servers");
    let mut digests: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&servers_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && let Ok(bytes) = std::fs::read(&path)
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && let Some(d) = v.get("app_digest").and_then(|d| d.as_str())
            {
                let d = d.to_string();
                if !digests.contains(&d) {
                    digests.push(d);
                }
            }
        }
    }
    digests.sort();
    digests
}

async fn activate_deployment(
    state: &AppState,
    project: &mut Project,
    staged: &std::path::Path,
) -> anyhow::Result<u64> {
    let version = project.current_version.unwrap_or(0) + 1;

    let deploy_path = state
        .deploy_dir
        .join(&project.id)
        .join("deployments")
        .join(format!("v{version}"));
    if let Some(parent) = deploy_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let _ = tokio::fs::remove_dir_all(&deploy_path).await;
    // Same-filesystem move (staging lives under deploy_dir); recursive-copy
    // fallback covers the rare cross-filesystem case, cleaning a partial v{N} if
    // it fails mid-copy.
    if tokio::fs::rename(staged, &deploy_path).await.is_err() {
        if let Err(e) = copy_dir_recursive(staged, &deploy_path) {
            let _ = tokio::fs::remove_dir_all(&deploy_path).await;
            return Err(anyhow::anyhow!("cross-filesystem stage copy failed: {e}"));
        }
        let _ = tokio::fs::remove_dir_all(staged).await;
    }

    // Extract server rootfs tarballs so the VM doesn't have to (saves tmpfs RAM)
    let servers_dir = deploy_path.join("_servers");
    if servers_dir.exists() {
        for entry in std::fs::read_dir(&servers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "gz") {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.strip_suffix(".tar"))
                    .unwrap_or("unknown");
                let extract_dir = servers_dir.join(name);
                info!(server = %name, "extracting server rootfs on host");
                std::fs::create_dir_all(&extract_dir)?;
                let file = std::fs::File::open(&path)?;
                let gz = flate2::read::GzDecoder::new(file);
                let mut archive = tar::Archive::new(gz);
                archive.set_preserve_permissions(true);
                archive.unpack(&extract_dir)?;
                std::fs::remove_file(&path)?;
            }
        }
    }

    // Storage hard cap: bill the would-be-live footprint — content image + data
    // disk + THIS version only, NOT the retained rollback history (bounded by a
    // deployment count, not the cap). Measured before the `live` symlink is
    // repointed, so a deploy whose live footprint fits is never refused by old
    // versions still on disk. Reject + remove the just-unpacked artifacts so a
    // rejected deploy leaves no orphan bytes.
    let cap = state.store.get_quota(&project.id)?.storage_bytes_max;
    let data_dir = state.deploy_dir.parent().unwrap_or(&state.deploy_dir);
    let footprint =
        jkbase_common::storage::project_storage_bytes_for(data_dir, &project.id, &deploy_path);
    if footprint > cap {
        let _ = tokio::fs::remove_dir_all(&deploy_path).await;
        return Err(QuotaExceeded(format!(
            "storage quota exceeded: deploy would use {footprint} bytes, cap is {cap}"
        ))
        .into());
    }

    // Atomically repoint `live`: symlink to a temp name then rename over it (rename is
    // atomic on the same dir). A plain remove+symlink leaves a window where `live` is
    // absent, which a concurrent wake reads as "no deployed content" and would wrongly
    // mark the project NeedsRedeploy.
    let proj_dir = state.deploy_dir.join(&project.id);
    let live_link = proj_dir.join("live");
    let tmp_link = proj_dir.join(".live.swap");
    let _ = tokio::fs::remove_file(&tmp_link).await;
    tokio::fs::symlink(&deploy_path, &tmp_link).await?;
    tokio::fs::rename(&tmp_link, &live_link).await?;

    project.current_version = Some(version);
    project.state = crate::store::ProjectState::Active;
    state.store.update_project(project)?;

    // Reconcile domains declared in the deploy into the registry (subdomains we
    // own go Active; custom domains start Pending until DNS-TXT verified). Never
    // routes an unverified host. Best-effort: a taken/foreign host is skipped.
    reconcile_deploy_domains(state, project, &deploy_path).await;
    let _ = refresh_domain_cache(state, &project.id);

    // Reconcile function cron schedules declared in the deploy into the durable
    // registry (replace-on-redeploy, preserving last_run so cadence/catch-up
    // survive). The host scheduler reads this registry as source of truth.
    reconcile_deploy_schedules(state, project, &deploy_path);

    // Record version history and prune old artifacts so disk usage stays bounded.
    // `layer_digests` pins the tenant app-layer digests this version references (for
    // future content-store GC; shared base/runtime layers are platform-owned).
    state.store.save_deployment(&crate::store::DeploymentMeta {
        project_id: project.id.clone(),
        version,
        created_at: auth::timestamp(),
        layer_digests: collect_app_layer_digests(&deploy_path),
    })?;
    prune_deployments(state, &project.id, version);

    info!(
        project_id = %project.id,
        version,
        "deployment activated"
    );

    if let Some(cb) = &state.deploy_callback {
        cb(project.id.clone(), version).await?;
    }

    Ok(version)
}

/// Keep only the most recent `MAX_DEPLOYMENTS` deployments on disk + in history.
/// Never removes the currently-live version (`keep_version`). Best-effort: a
/// failure to prune one old version is logged, not fatal to the deploy.
fn prune_deployments(state: &AppState, project_id: &str, keep_version: u64) {
    const MAX_DEPLOYMENTS: usize = 10;

    let deployments = match state.store.list_deployments(project_id) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(project_id, error = %e, "failed to list deployments for pruning");
            return;
        }
    };
    if deployments.len() <= MAX_DEPLOYMENTS {
        return;
    }

    for old in deployments.into_iter().skip(MAX_DEPLOYMENTS) {
        if old.version == keep_version {
            continue;
        }
        let dir = state
            .deploy_dir
            .join(project_id)
            .join("deployments")
            .join(format!("v{}", old.version));
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(project_id, version = old.version, error = %e, "failed to remove old deployment dir");
            }
        }
        let _ = state.store.remove_deployment(project_id, old.version);
        info!(project_id, version = old.version, "pruned old deployment");
    }
}

#[derive(Serialize)]
struct DeploymentResponse {
    version: u64,
    created_at: u64,
    active: bool,
}

async fn list_deployments(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let project = match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => p,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    };

    match state.store.list_deployments(&id) {
        Ok(list) => {
            let resp: Vec<DeploymentResponse> = list
                .into_iter()
                .map(|d| DeploymentResponse {
                    version: d.version,
                    created_at: d.created_at,
                    active: Some(d.version) == project.current_version,
                })
                .collect();
            Json(resp).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
pub struct UsageResponse {
    /// Month-to-date CPU seconds (cpu_jiffies / USER_HZ).
    pub cpu_seconds: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub storage_bytes: u64,
    /// Month-to-date server-side build-VM seconds.
    pub build_seconds: u64,
    pub month_start: u64,
}

#[derive(Serialize)]
pub struct QuotaResponse {
    pub storage_bytes_max: u64,
    pub bandwidth_bytes_per_month: u64,
    pub build_seconds_per_month: u64,
    pub max_objects: u64,
    pub max_buckets: u64,
    /// True if this project has a per-project override (vs platform defaults).
    pub overridden: bool,
    pub bandwidth_blocked: bool,
    pub blocked_reason: Option<String>,
}

fn default_build_seconds_quota() -> u64 {
    crate::store::DEFAULT_QUOTA.build_seconds_per_month
}
fn default_max_objects_quota() -> u64 {
    crate::store::DEFAULT_QUOTA.max_objects
}
fn default_max_buckets_quota() -> u64 {
    crate::store::DEFAULT_QUOTA.max_buckets
}

#[derive(Deserialize)]
pub struct SetQuotaRequest {
    pub storage_bytes_max: u64,
    pub bandwidth_bytes_per_month: u64,
    #[serde(default = "default_build_seconds_quota")]
    pub build_seconds_per_month: u64,
    #[serde(default = "default_max_objects_quota")]
    pub max_objects: u64,
    #[serde(default = "default_max_buckets_quota")]
    pub max_buckets: u64,
}

/// Month-to-date metered usage for a project. Works while hibernated (store-only).
async fn get_project_usage(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }
    let month_start = crate::store::month_start_epoch(auth::timestamp());
    match state.store.sum_month_to_date(&id, month_start) {
        Ok(mtd) => Json(UsageResponse {
            cpu_seconds: mtd.cpu_jiffies as f64 / 100.0,
            rx_bytes: mtd.rx_bytes,
            tx_bytes: mtd.tx_bytes,
            storage_bytes: mtd.storage_bytes,
            build_seconds: mtd.build_seconds,
            month_start,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn get_project_quota(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }
    let limits = state
        .store
        .get_quota(&id)
        .unwrap_or(crate::store::DEFAULT_QUOTA);
    let overridden = state.store.get_quota_override(&id).ok().flatten().is_some();
    let status = state.store.get_quota_status(&id).ok().flatten();
    Json(QuotaResponse {
        storage_bytes_max: limits.storage_bytes_max,
        bandwidth_bytes_per_month: limits.bandwidth_bytes_per_month,
        build_seconds_per_month: limits.build_seconds_per_month,
        max_objects: limits.max_objects,
        max_buckets: limits.max_buckets,
        overridden,
        bandwidth_blocked: status
            .as_ref()
            .map(|s| s.bandwidth_blocked)
            .unwrap_or(false),
        blocked_reason: status.and_then(|s| s.blocked_reason),
    })
    .into_response()
}

/// Set a per-project quota override. Owner-scoped and CLAMPED to the platform
/// defaults for tenants: a tenant can only *restrict* their own limits, never
/// raise them above [`DEFAULT_QUOTA`] (untrusted-tenant threat model). A platform
/// operator presenting a valid `X-Admin-Token` (server `--admin-token`) bypasses
/// both the owner-scoping and the clamp, so it can grant a specific project a
/// higher limit. No admin token configured ⇒ no admin path: every set is clamped.
async fn set_project_quota(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SetQuotaRequest>,
) -> impl IntoResponse {
    let is_admin = state.is_admin_request(&headers);
    // Owner-scoped for tenants; a platform admin may target any project.
    let permitted = match state.store.get_project(&id) {
        Ok(Some(p)) => is_admin || p.tenant_id.as_deref() == Some(&tenant.id),
        _ => false,
    };
    if !permitted {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("project '{id}' not found"),
            }),
        )
            .into_response();
    }
    // Tenants may only self-restrict (clamp to defaults); a platform-admin
    // override may raise a limit ABOVE the default.
    let limit = |requested: u64, default: u64| {
        if is_admin {
            requested
        } else {
            requested.min(default)
        }
    };
    let limits = crate::store::QuotaLimits {
        storage_bytes_max: limit(
            req.storage_bytes_max,
            crate::store::DEFAULT_QUOTA.storage_bytes_max,
        ),
        bandwidth_bytes_per_month: limit(
            req.bandwidth_bytes_per_month,
            crate::store::DEFAULT_QUOTA.bandwidth_bytes_per_month,
        ),
        build_seconds_per_month: limit(
            req.build_seconds_per_month,
            crate::store::DEFAULT_QUOTA.build_seconds_per_month,
        ),
        max_objects: limit(req.max_objects, crate::store::DEFAULT_QUOTA.max_objects),
        max_buckets: limit(req.max_buckets, crate::store::DEFAULT_QUOTA.max_buckets),
    };
    match state.store.set_quota(&id, &limits) {
        Ok(()) => Json(QuotaResponse {
            storage_bytes_max: limits.storage_bytes_max,
            bandwidth_bytes_per_month: limits.bandwidth_bytes_per_month,
            build_seconds_per_month: limits.build_seconds_per_month,
            max_objects: limits.max_objects,
            max_buckets: limits.max_buckets,
            overridden: true,
            bandwidth_blocked: false,
            blocked_reason: None,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct RollbackRequest {
    pub version: u64,
}

async fn rollback(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<RollbackRequest>,
) -> impl IntoResponse {
    let mut project = match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => p,
        Ok(Some(_)) | Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    let target = req.version;
    let deploy_path = state
        .deploy_dir
        .join(&id)
        .join("deployments")
        .join(format!("v{target}"));
    if !deploy_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("deployment v{target} not found for project '{id}'"),
            }),
        )
            .into_response();
    }
    if project.current_version == Some(target) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("v{target} is already the active deployment"),
            }),
        )
            .into_response();
    }

    // Reuse the deploy lock so a rollback can't race a concurrent deploy/build/
    // rollback; the guard releases on drop, even if `do_rollback` unwinds.
    let Some(_guard) = DeployLockGuard::try_acquire(&state, &id) else {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "a deploy or rollback is already in progress".to_string(),
            }),
        )
            .into_response();
    };

    let result = do_rollback(&state, &mut project, &deploy_path, target).await;

    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(DeployResponse {
                version: target,
                project_id: id,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn do_rollback(
    state: &AppState,
    project: &mut Project,
    deploy_path: &std::path::Path,
    target: u64,
) -> anyhow::Result<()> {
    // Atomically repoint `live` at the target version: symlink to a temp name then
    // rename over it (rename is atomic; a remove+symlink leaves a no-`live` window
    // that a concurrent wake would misread as "no deployed content").
    let proj_dir = state.deploy_dir.join(&project.id);
    let live_link = proj_dir.join("live");
    let tmp_link = proj_dir.join(".live.swap");
    let _ = tokio::fs::remove_file(&tmp_link).await;
    tokio::fs::symlink(deploy_path, &tmp_link).await?;
    tokio::fs::rename(&tmp_link, &live_link).await?;

    project.current_version = Some(target);
    project.state = crate::store::ProjectState::Active;
    state.store.update_project(project)?;

    info!(project_id = %project.id, version = target, "rolled back");

    // Rebuild the content image from the now-current `live` and restart the VM.
    if let Some(cb) = &state.deploy_callback {
        cb(project.id.clone(), target).await?;
    }

    Ok(())
}

fn slug(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

async fn get_project_status(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    let Some(ref routing_table) = state.routing_table else {
        return Json(serde_json::json!({"status": "no routing"})).into_response();
    };

    let backend_ip = {
        let table = routing_table.read().await;
        table.get(&id).cloned()
    };

    let Some(ip) = backend_ip else {
        return Json(serde_json::json!({"status": "not running"})).into_response();
    };

    let url = format!("http://{}:80/_jkbase/health", ip);
    match proxy_to_vm(&ip, &url).await {
        Ok(body) => (
            StatusCode::OK,
            [(hyper::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(_) => Json(serde_json::json!({"status": "unreachable"})).into_response(),
    }
}

async fn get_project_logs(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    req: Request,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    // Served from the host-persisted log store (populated by the server's log
    // shipper), so logs remain available even while the VM is hibernated.
    let query = req.uri().query().unwrap_or("");
    let param = |key: &str| -> Option<&str> { query.split('&').find_map(|p| p.strip_prefix(key)) };
    let limit: usize = param("limit=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
        .min(5000);
    let since: Option<u64> = param("since=").and_then(|v| v.parse().ok());
    let service = param("service=").map(|s| s.to_string());

    match state.log_store.read(&id, limit, service.as_deref(), since) {
        Ok(lines) => (
            StatusCode::OK,
            [(hyper::header::CONTENT_TYPE, "application/json")],
            Json(lines),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn proxy_to_vm(ip: &str, url: &str) -> anyhow::Result<String> {
    let stream = tokio::net::TcpStream::connect(format!("{ip}:80")).await?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let req = hyper::Request::builder()
        .uri(url)
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;

    let resp = sender.send_request(req).await?;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await?
        .to_bytes();
    Ok(String::from_utf8_lossy(&body).to_string())
}

async fn generate_new_token(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
) -> impl IntoResponse {
    let raw_token = auth::generate_token();
    let token_hash = match auth::hash_token(&raw_token) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    let api_token = auth::ApiToken {
        id: auth::generate_id(),
        tenant_id: tenant.id.clone(),
        name: "generated".to_string(),
        token_hash,
        created_at: auth::timestamp(),
    };

    if let Err(e) = state.store.save_api_token(&api_token) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    Json(serde_json::json!({ "token": raw_token })).into_response()
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let Some(ref current_hash) = tenant.password_hash else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "account has no password set".to_string(),
            }),
        )
            .into_response();
    };

    if !auth::verify_password(&req.current_password, current_hash) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "current password is incorrect".to_string(),
            }),
        )
            .into_response();
    }

    if req.new_password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "new password must be at least 8 characters".to_string(),
            }),
        )
            .into_response();
    }

    let new_hash = match auth::hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    let mut updated_tenant = tenant.clone();
    updated_tenant.password_hash = Some(new_hash);
    if let Err(e) = state.store.create_tenant(&updated_tenant) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    Json(serde_json::json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct SetSecretRequest {
    pub key: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct SecretResponse {
    pub key: String,
}

async fn set_secret(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<SetSecretRequest>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    // Validate before storing: secrets become container env vars, so the key must be a
    // conventional env-var name and neither field may contain a NUL (which would make
    // the runtime's `Command::env` fail at spawn). The runtime also defends itself
    // (inject_secrets skips bad keys), but reject here so the caller gets a clear error.
    let key = req.key.as_str();
    let key_ok = !key.is_empty()
        && key
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !key_ok {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("invalid secret key '{key}': must match [A-Za-z_][A-Za-z0-9_]*"),
            }),
        )
            .into_response();
    }
    if req.value.contains('\0') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "secret value must not contain a NUL byte".to_string(),
            }),
        )
            .into_response();
    }

    match state.store.set_secret(&id, &req.key, &req.value) {
        Ok(()) => {
            info!(project = %id, key = %req.key, "secret set");
            (StatusCode::OK, Json(SecretResponse { key: req.key })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn list_secrets(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    match state.store.list_secrets(&id) {
        Ok(secrets) => {
            let keys: Vec<SecretResponse> = secrets
                .iter()
                .map(|s| SecretResponse { key: s.key.clone() })
                .collect();
            Json(keys).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn delete_secret(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    match state.store.delete_secret(&id, &key) {
        Ok(true) => {
            info!(project = %id, key = %key, "secret deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("secret '{key}' not found"),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateAccessKeyRequest {
    /// Optional human label (e.g. "ci", "backups"). Defaults to empty.
    #[serde(default)]
    pub label: String,
}

/// Returned ONCE, at creation — the only time the secret is ever exposed.
#[derive(Serialize)]
pub struct AccessKeyCreatedResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub label: String,
    pub created_unix: u64,
}

/// Listing view of an access key — the secret is NEVER included.
#[derive(Serialize)]
pub struct AccessKeyResponse {
    pub access_key_id: String,
    pub label: String,
    pub created_unix: u64,
}

/// `POST /projects/{id}/access-keys` — mint an S3 access key for the project's
/// object store. Owner-scoped. The secret is shown once in the response and is not
/// retrievable afterwards.
async fn issue_access_key(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<CreateAccessKeyRequest>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    // The label is cosmetic, but it's tenant-controlled and shown back in the
    // console, so keep it short and free of control characters.
    let label = req.label.trim();
    if label.len() > 64 || label.bytes().any(|b| b.is_ascii_control()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "label must be <= 64 chars and contain no control characters".to_string(),
            }),
        )
            .into_response();
    }

    match state.store.create_access_key(&id, &tenant.id, label) {
        Ok(key) => {
            info!(project = %id, access_key_id = %key.access_key_id, "object-store access key issued");
            (
                StatusCode::CREATED,
                Json(AccessKeyCreatedResponse {
                    access_key_id: key.access_key_id,
                    secret_access_key: key.secret_key,
                    label: key.label,
                    created_unix: key.created_unix,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// `GET /projects/{id}/access-keys` — list the project's access keys (ids + labels,
/// never secrets). Owner-scoped.
async fn list_access_keys(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    match state.store.list_access_keys(&id) {
        Ok(keys) => {
            let out: Vec<AccessKeyResponse> = keys
                .into_iter()
                .map(|k| AccessKeyResponse {
                    access_key_id: k.access_key_id,
                    label: k.label,
                    created_unix: k.created_unix,
                })
                .collect();
            Json(out).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// `DELETE /projects/{id}/access-keys/{akid}` — revoke one access key. Owner-scoped
/// and key-scoped (the store only removes it if it belongs to this project).
async fn revoke_access_key(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path((id, akid)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {}
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response();
        }
    }

    match state.store.delete_access_key(&id, &akid) {
        Ok(true) => {
            info!(project = %id, access_key_id = %akid, "object-store access key revoked");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("access key '{akid}' not found"),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct DomainResponse {
    host: String,
    kind: DomainKind,
    status: DomainStatus,
    site: Option<String>,
    /// DNS TXT challenge the user must publish to verify a custom domain.
    verification: Option<DomainChallenge>,
    /// HTTPS status: `active` (cert serving), `provisioning` (verified custom
    /// domain awaiting issuance), or `None` (not applicable / unverified).
    tls: Option<String>,
}

#[derive(Serialize)]
struct DomainChallenge {
    record: String,
    value: String,
}

/// HTTPS state for a domain. Subdomains are covered by the wildcard cert;
/// custom domains get a per-host cert issued after verification.
fn tls_status(state: &AppState, r: &crate::store::DomainRecord) -> Option<String> {
    if r.status != DomainStatus::Active {
        return None;
    }
    match r.kind {
        DomainKind::Subdomain => Some("active".to_string()),
        DomainKind::Custom => {
            let has_cert = state
                .cert_status
                .as_ref()
                .map(|f| f(&r.host))
                .unwrap_or(false);
            Some(if has_cert { "active" } else { "provisioning" }.to_string())
        }
    }
}

fn domain_response(state: &AppState, r: crate::store::DomainRecord) -> DomainResponse {
    let verification = if r.kind == DomainKind::Custom && r.status == DomainStatus::Pending {
        Some(DomainChallenge {
            record: format!("_jkbase-challenge.{}", r.host),
            value: r.token.clone(),
        })
    } else {
        None
    };
    let tls = tls_status(state, &r);
    DomainResponse {
        host: r.host,
        kind: r.kind,
        status: r.status,
        site: r.site,
        verification,
        tls,
    }
}

async fn list_domains(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !owns_project(&state, &tenant, &id) {
        return project_not_found(&id);
    }
    match state.store.list_domains_for_project(&id) {
        Ok(list) => {
            let resp: Vec<DomainResponse> = list
                .into_iter()
                .map(|r| domain_response(&state, r))
                .collect();
            Json(resp).into_response()
        }
        Err(e) => internal_error(e),
    }
}

#[derive(Deserialize)]
pub struct AddDomainRequest {
    pub domain: String,
    /// Optional site within the project this domain should serve.
    #[serde(default)]
    pub site: Option<String>,
}

async fn add_domain(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<AddDomainRequest>,
) -> impl IntoResponse {
    if !owns_project(&state, &tenant, &id) {
        return project_not_found(&id);
    }

    let (host, kind) = match derive_host_key(&req.domain, &state.platform_domain) {
        Ok(v) => v,
        Err(msg) => return bad_request(msg),
    };

    // Global uniqueness: a host owned by anyone else (or reserved) is rejected.
    match state.store.get_domain(&host) {
        Ok(Some(existing)) => {
            if existing.project_id == id {
                return bad_request(format!("'{host}' is already attached to this project"));
            }
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: format!("'{host}' is already in use"),
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => return internal_error(e),
    }
    if crate::store::host_is_reserved(&host) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!("'{host}' is a reserved name"),
            }),
        )
            .into_response();
    }

    // Platform subdomains are owned by us → Active immediately (wildcard cert
    // covers them). Custom domains start Pending until DNS-TXT verified.
    let status = match kind {
        DomainKind::Subdomain => DomainStatus::Active,
        DomainKind::Custom => DomainStatus::Pending,
    };
    let record = DomainRecord {
        host: host.clone(),
        project_id: id.clone(),
        tenant_id: tenant.id.clone(),
        site: req.site.clone(),
        kind,
        status,
        token: auth::generate_token(),
        created_at: auth::timestamp(),
    };

    match state.store.claim_domain(&record) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: format!("'{host}' was just claimed by someone else"),
                }),
            )
                .into_response();
        }
        Err(e) => return internal_error(e),
    }

    if record.status == DomainStatus::Active {
        activate_domain(&state, &record).await;
    }
    let _ = refresh_domain_cache(&state, &id);
    info!(project = %id, host = %host, ?status, "domain claimed");
    Json(domain_response(&state, record)).into_response()
}

async fn verify_domain(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path((id, host)): Path<(String, String)>,
) -> impl IntoResponse {
    let host = host.to_lowercase();
    let mut record = match state.store.get_domain(&host) {
        Ok(Some(r)) if r.project_id == id && r.tenant_id == tenant.id => r,
        _ => return project_not_found(&host),
    };

    if record.status == DomainStatus::Active {
        return Json(domain_response(&state, record)).into_response();
    }

    if !dns_txt_contains(&record.host, &record.token).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "TXT record _jkbase-challenge.{} not found or doesn't match (DNS may take a few minutes to propagate)",
                    record.host
                ),
            }),
        )
            .into_response();
    }

    record.status = DomainStatus::Active;
    if let Err(e) = state.store.save_domain(&record) {
        return internal_error(e);
    }
    activate_domain(&state, &record).await;
    let _ = refresh_domain_cache(&state, &id);
    // Proactively request a TLS cert for the now-verified custom domain.
    if let (DomainKind::Custom, Some(req)) = (record.kind, &state.cert_request) {
        req(record.host.clone());
    }
    info!(project = %id, host = %record.host, "custom domain verified");
    Json(domain_response(&state, record)).into_response()
}

async fn remove_domain(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path((id, domain)): Path<(String, String)>,
) -> impl IntoResponse {
    let host = domain.to_lowercase();
    match state.store.get_domain(&host) {
        Ok(Some(r)) if r.project_id == id && r.tenant_id == tenant.id => {}
        _ => return project_not_found(&host),
    }

    if let Err(e) = state.store.remove_domain(&host) {
        return internal_error(e);
    }
    deactivate_host(&state, &host).await;
    let _ = refresh_domain_cache(&state, &id);
    info!(project = %id, host = %host, "domain removed");
    StatusCode::NO_CONTENT.into_response()
}

// -- domain helpers --

fn owns_project(state: &AppState, tenant: &Tenant, id: &str) -> bool {
    matches!(state.store.get_project(id), Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id))
}

fn project_not_found(id: &str) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: format!("'{id}' not found"),
        }),
    )
        .into_response()
}

fn bad_request(msg: impl Into<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg.into() }),
    )
        .into_response()
}

fn internal_error(e: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: e.to_string(),
        }),
    )
        .into_response()
}

/// Normalize a user-supplied domain to its routing host-key and classify it.
/// Accepts a bare label (`docs`), a platform host (`docs.jkbase.app`), or a full
/// custom domain (`docs.example.com`). Nested platform subdomains and the apex
/// are rejected (flat scheme only).
fn derive_host_key(input: &str, platform_domain: &str) -> Result<(String, DomainKind), String> {
    let d = input.trim().trim_end_matches('.').to_lowercase();
    if d.is_empty() {
        return Err("domain cannot be empty".to_string());
    }
    let suffix = format!(".{platform_domain}");
    if d == platform_domain {
        return Err("cannot attach the platform apex domain".to_string());
    }
    if let Some(label) = d.strip_suffix(&suffix) {
        if label.is_empty() || label.contains('.') {
            return Err("only flat subdomains (<label>.{platform}) are supported"
                .replace("{platform}", platform_domain));
        }
        return Ok((label.to_string(), DomainKind::Subdomain));
    }
    if d.contains('.') {
        Ok((d, DomainKind::Custom))
    } else {
        // bare label → platform subdomain
        Ok((d, DomainKind::Subdomain))
    }
}

/// Insert an Active domain into the in-memory maps. Adds to `routes` only when
/// the owning project is already running (its primary key is present), so we
/// never point traffic at a hibernated VM's stale IP.
async fn activate_domain(state: &AppState, record: &DomainRecord) {
    if let Some(ref dm) = state.domain_map {
        dm.write().await.insert(
            record.host.clone(),
            DomainTarget {
                project_id: record.project_id.clone(),
                site: record.site.clone(),
            },
        );
    }
    if let Some(ref rt) = state.routing_table {
        let mut table = rt.write().await;
        if let Some(ip) = table.get(&record.project_id).cloned() {
            table.insert(record.host.clone(), ip);
        }
    }
}

async fn deactivate_host(state: &AppState, host: &str) {
    if let Some(ref dm) = state.domain_map {
        dm.write().await.remove(host);
    }
    if let Some(ref rt) = state.routing_table {
        rt.write().await.remove(host);
    }
}

/// Keep `project.domains` as a denormalized cache (used by ProjectResponse) of
/// the project's claimed hosts. Best-effort.
fn refresh_domain_cache(state: &AppState, project_id: &str) -> anyhow::Result<()> {
    if let Some(mut project) = state.store.get_project(project_id)? {
        let mut hosts: Vec<String> = state
            .store
            .list_domains_for_project(project_id)?
            .into_iter()
            .filter(|d| d.host != project_id) // exclude the primary label
            .map(|d| d.host)
            .collect();
        hosts.sort();
        if project.domains != hosts {
            project.domains = hosts;
            state.store.update_project(&project)?;
        }
    }
    Ok(())
}

/// Reconcile domains declared in a deploy (per-site `domain` in `_sites.json`
/// and legacy project-level `_domains.json`) into the DOMAINS registry. Owned
/// subdomains become Active; custom domains are claimed Pending (never routed
/// until verified). Hosts already owned by another project are left untouched.
#[derive(serde::Deserialize)]
struct DeclaredSchedule {
    function: String,
    cron: String,
}

/// Reconcile inline `[functions.NAME] schedule` crons (shipped as `_schedules.json`)
/// into the durable registry. Replace-on-redeploy: upsert declared schedules
/// (preserving `last_run` so we don't replay catch-up or reset cadence), and prune
/// schedules for functions removed/renamed in this deploy. Invalid cron expressions
/// are rejected at write time so the scheduler loop never holds an unparseable cron.
fn reconcile_deploy_schedules(state: &AppState, project: &Project, deploy_path: &std::path::Path) {
    use std::str::FromStr;

    let declared: Vec<DeclaredSchedule> =
        std::fs::read_to_string(deploy_path.join("_schedules.json"))
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();

    let existing = state
        .store
        .list_schedules_for_project(&project.id)
        .unwrap_or_default();
    let declared_names: std::collections::HashSet<&str> =
        declared.iter().map(|d| d.function.as_str()).collect();

    for d in &declared {
        // The `cron` crate is 6-field (field 0 = seconds); a 5-field UNIX expr is
        // left-padded with "0 " to fire at second 0. Must match the loop's parser.
        if cron::Schedule::from_str(&format!("0 {}", d.cron)).is_err() {
            tracing::warn!(project = %project.id, function = %d.function, cron = %d.cron,
                "skipping invalid cron expression");
            continue;
        }

        // Preserve last_run on an unchanged redeploy; reseed to now when the cron
        // changes or the schedule is new (so we never replay from epoch 0).
        let prior = existing.iter().find(|e| e.function == d.function);
        let last_run = match prior {
            Some(p) if p.cron == d.cron => p.last_run,
            _ => Some(auth::timestamp()),
        };

        let rec = crate::store::ScheduleRecord {
            project_id: project.id.clone(),
            function: d.function.clone(),
            cron: d.cron.clone(),
            last_run,
        };
        if let Err(e) = state.store.save_schedule(&rec) {
            tracing::warn!(project = %project.id, function = %d.function, error = %e,
                "failed to persist schedule");
        }
    }

    // Prune schedules for functions no longer declared.
    for e in &existing {
        if !declared_names.contains(e.function.as_str()) {
            let _ = state.store.remove_schedule(&project.id, &e.function);
        }
    }
}

async fn reconcile_deploy_domains(
    state: &AppState,
    project: &Project,
    deploy_path: &std::path::Path,
) {
    let Some(tenant_id) = project.tenant_id.clone() else {
        return;
    };

    // (raw host, optional site name)
    let mut declared: Vec<(String, Option<String>)> = Vec::new();

    let sites: Vec<jkbase_common::config::ResolvedSite> =
        std::fs::read_to_string(deploy_path.join("_sites.json"))
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();
    for s in sites {
        if let Some(domain) = s.domain {
            declared.push((domain, Some(s.name)));
        }
    }
    let legacy: Vec<String> = std::fs::read_to_string(deploy_path.join("_domains.json"))
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or_default();
    for d in legacy {
        declared.push((d, None));
    }

    for (raw, site) in declared {
        let (host, kind) = match derive_host_key(&raw, &state.platform_domain) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(project = %project.id, domain = %raw, error = %e, "skipping invalid declared domain");
                continue;
            }
        };
        match state.store.get_domain(&host) {
            Ok(Some(existing)) if existing.project_id == project.id => continue, // already ours
            Ok(Some(_)) => {
                tracing::warn!(project = %project.id, host = %host, "declared domain owned by another project, skipping");
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(project = %project.id, host = %host, error = %e, "domain lookup failed");
                continue;
            }
        }
        if crate::store::host_is_reserved(&host) {
            tracing::warn!(project = %project.id, host = %host, "declared domain is reserved, skipping");
            continue;
        }
        let status = match kind {
            DomainKind::Subdomain => DomainStatus::Active,
            DomainKind::Custom => DomainStatus::Pending,
        };
        let record = DomainRecord {
            host: host.clone(),
            project_id: project.id.clone(),
            tenant_id: tenant_id.clone(),
            site,
            kind,
            status,
            token: auth::generate_token(),
            created_at: auth::timestamp(),
        };
        match state.store.claim_domain(&record) {
            Ok(true) => {
                if record.status == DomainStatus::Active {
                    activate_domain(state, &record).await;
                }
                info!(project = %project.id, host = %host, ?status, "declared domain reconciled");
            }
            Ok(false) => {} // lost a race; leave it
            Err(e) => {
                tracing::warn!(project = %project.id, host = %host, error = %e, "failed to claim declared domain");
            }
        }
    }
}

/// Look up `_jkbase-challenge.<host>` TXT via DNS-over-HTTPS and check the token
/// is present. Returns false (retryable) on any network/parse error.
async fn dns_txt_contains(host: &str, expected: &str) -> bool {
    let name = format!("_jkbase-challenge.{host}");
    let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type=TXT");
    let client = reqwest::Client::new();
    let resp = match client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(_) => return false,
    };
    let Some(answers) = json["Answer"].as_array() else {
        return false;
    };
    for a in answers {
        if let Some(data) = a["data"].as_str() {
            // TXT data is returned quoted, and may be chunked: "abc" "def".
            let joined: String = data
                .split_whitespace()
                .map(|chunk| chunk.trim_matches('"'))
                .collect();
            if joined == expected || data.trim_matches('"') == expected {
                return true;
            }
        }
    }
    false
}

fn to_response(p: &Project) -> ProjectResponse {
    ProjectResponse {
        id: p.id.clone(),
        name: p.name.clone(),
        current_version: p.current_version,
        url: if p.current_version.is_some() {
            Some(format!("https://{}.jkbase.app", p.id))
        } else {
            None
        },
        domains: p.domains.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_matches_only_identical_bytes() {
        assert!(ct_eq(b"s3cr3t-admin-token", b"s3cr3t-admin-token"));
        assert!(!ct_eq(b"s3cr3t-admin-token", b"s3cr3t-admin-toker")); // last byte
        assert!(!ct_eq(b"s3cr3t-admin-token", b"S3cr3t-admin-token")); // first byte
        assert!(!ct_eq(b"short", b"longer-token")); // length mismatch
        assert!(!ct_eq(b"", b"x"));
        assert!(ct_eq(b"", b"")); // both empty
    }
}
