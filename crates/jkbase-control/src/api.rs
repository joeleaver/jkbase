use crate::auth::{self, ApiToken, Tenant};
use crate::logstore::LogStore;
use crate::store::{Project, Store};
use axum::body::Bytes;
use axum::extract::{Path, State, Request};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::extract::DefaultBodyLimit;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::info;

pub type DeployCallback = Box<
    dyn Fn(String, u64) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

pub type RoutingTable = Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>;

pub struct AppState {
    pub store: Store,
    pub log_store: LogStore,
    pub deploy_dir: PathBuf,
    pub deploy_callback: Option<DeployCallback>,
    pub routing_table: Option<RoutingTable>,
    deploy_locks: Mutex<std::collections::HashSet<String>>,
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

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl AppState {
    pub fn new(store: Store, log_store: LogStore, deploy_dir: PathBuf) -> Self {
        Self {
            store,
            log_store,
            deploy_dir,
            deploy_callback: None,
            routing_table: None,
            deploy_locks: Mutex::new(std::collections::HashSet::new()),
        }
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
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            hyper::header::AUTHORIZATION,
            hyper::header::CONTENT_TYPE,
        ])
        .max_age(std::time::Duration::from_secs(86400));

    let authenticated = Router::new()
        .route("/projects", get(list_projects).post(create_project))
        .route(
            "/projects/{id}",
            get(get_project).delete(delete_project),
        )
        .route("/projects/{id}/deploy", post(deploy))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024))
        .route(
            "/projects/{id}/secrets",
            get(list_secrets).post(set_secret),
        )
        .route("/projects/{id}/secrets/{key}", axum::routing::delete(delete_secret))
        .route("/projects/{id}/logs", get(get_project_logs))
        .route("/projects/{id}/deployments", get(list_deployments))
        .route("/projects/{id}/rollback", post(rollback))
        .route("/projects/{id}/status", get(get_project_status))
        .route("/projects/{id}/domains", get(list_domains).post(add_domain))
        .route("/projects/{id}/domains/{domain}", axum::routing::delete(remove_domain))
        .route("/me", get(get_me))
        .route("/me/token", post(generate_new_token))
        .route("/me/password", post(change_password))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    let public = Router::new()
        .route("/init", post(init_platform))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/health", get(api_health));

    Router::new()
        .merge(authenticated)
        .merge(public)
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
                .into_response()
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
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
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
                .into_response()
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

    if state.store.get_project(&id).ok().flatten().is_some() {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!("project '{id}' already exists"),
            }),
        )
            .into_response();
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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

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
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    };

    // Acquire deploy lock
    {
        let mut locks = state.deploy_locks.lock().await;
        if !locks.insert(id.clone()) {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "deploy already in progress".to_string(),
                }),
            )
                .into_response();
        }
    }

    let result = do_deploy(&state, &mut project, &body).await;

    // Release deploy lock
    {
        let mut locks = state.deploy_locks.lock().await;
        locks.remove(&id);
    }

    match result {
        Ok(version) => (
            StatusCode::OK,
            Json(DeployResponse {
                version,
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

async fn do_deploy(
    state: &AppState,
    project: &mut Project,
    tarball: &[u8],
) -> anyhow::Result<u64> {
    let version = project.current_version.unwrap_or(0) + 1;

    let deploy_path = state
        .deploy_dir
        .join(&project.id)
        .join("deployments")
        .join(format!("v{version}"));
    tokio::fs::create_dir_all(&deploy_path).await?;

    let tar = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(&deploy_path)?;

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

    let live_link = state.deploy_dir.join(&project.id).join("live");
    let _ = tokio::fs::remove_file(&live_link).await;
    tokio::fs::symlink(&deploy_path, &live_link).await?;

    // Read domain aliases from deploy
    let domains_path = deploy_path.join("_domains.json");
    if domains_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&domains_path) {
            if let Ok(domains) = serde_json::from_str::<Vec<String>>(&content) {
                project.domains = domains;
            }
        }
    }

    project.current_version = Some(version);
    project.state = crate::store::ProjectState::Active;
    state.store.update_project(project)?;

    // Record version history and prune old artifacts so disk usage stays bounded.
    state.store.save_deployment(&crate::store::DeploymentMeta {
        project_id: project.id.clone(),
        version,
        created_at: auth::timestamp(),
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
                .into_response()
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
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
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

    // Reuse the deploy lock so a rollback can't race a concurrent deploy/rollback.
    {
        let mut locks = state.deploy_locks.lock().await;
        if !locks.insert(id.clone()) {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "a deploy or rollback is already in progress".to_string(),
                }),
            )
                .into_response();
        }
    }

    let result = do_rollback(&state, &mut project, &deploy_path, target).await;

    {
        let mut locks = state.deploy_locks.lock().await;
        locks.remove(&id);
    }

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
    // Atomically repoint `live` at the target version (same swap as a deploy).
    let live_link = state.deploy_dir.join(&project.id).join("live");
    let _ = tokio::fs::remove_file(&live_link).await;
    tokio::fs::symlink(deploy_path, &live_link).await?;

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
                .into_response()
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
                .into_response()
        }
    }

    // Served from the host-persisted log store (populated by the server's log
    // shipper), so logs remain available even while the VM is hibernated.
    let query = req.uri().query().unwrap_or("");
    let param = |key: &str| -> Option<&str> {
        query.split('&').find_map(|p| p.strip_prefix(key))
    };
    let limit: usize = param("limit=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
        .min(5000);
    let since: Option<u64> = param("since=").and_then(|v| v.parse().ok());
    let service = param("service=").map(|s| s.to_string());

    match state
        .log_store
        .read(&id, limit, service.as_deref(), since)
    {
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
                .into_response()
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
                .into_response()
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
                .into_response()
        }
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
                .into_response()
        }
    }

    match state.store.list_secrets(&id) {
        Ok(secrets) => {
            let keys: Vec<SecretResponse> = secrets
                .iter()
                .map(|s| SecretResponse {
                    key: s.key.clone(),
                })
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
                .into_response()
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

async fn list_domains(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => {
            Json(p.domains).into_response()
        }
        _ => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("project '{id}' not found"),
            }),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct AddDomainRequest {
    pub domain: String,
}

async fn add_domain(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(req): Json<AddDomainRequest>,
) -> impl IntoResponse {
    let mut project = match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => p,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response()
        }
    };

    let domain = req.domain.to_lowercase().trim().to_string();
    if domain.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "domain cannot be empty".to_string(),
            }),
        )
            .into_response();
    }

    if !project.domains.contains(&domain) {
        project.domains.push(domain.clone());
        if let Err(e) = state.store.update_project(&project) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }

        // Register in routing table if project is deployed
        if let Some(ref rt) = state.routing_table {
            if let Ok(Some(alloc)) = state.store.get_vm_allocation(&id) {
                let mut table = rt.write().await;
                table.insert(domain.clone(), alloc.ip.clone());
            }
        }

        info!(project = %id, domain = %domain, "domain alias added");
    }

    Json(project.domains).into_response()
}

async fn remove_domain(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path((id, domain)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut project = match state.store.get_project(&id) {
        Ok(Some(p)) if p.tenant_id.as_deref() == Some(&tenant.id) => p,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("project '{id}' not found"),
                }),
            )
                .into_response()
        }
    };

    project.domains.retain(|d| d != &domain);
    if let Err(e) = state.store.update_project(&project) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    // Remove from routing table
    if let Some(ref rt) = state.routing_table {
        let mut table = rt.write().await;
        table.remove(&domain);
    }

    info!(project = %id, domain = %domain, "domain alias removed");
    StatusCode::NO_CONTENT.into_response()
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
