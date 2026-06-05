use crate::auth::{self, ApiToken, Tenant};
use crate::logstore::LogStore;
use crate::store::{
    DomainKind, DomainRecord, DomainStatus, Project, Store,
};
use jkbase_common::routing::DomainTarget;
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
    pub routing_table: Option<RoutingTable>,
    pub domain_map: Option<DomainMap>,
    pub cert_request: Option<CertRequest>,
    pub cert_status: Option<CertStatusFn>,
    /// Platform apex (e.g. `jkbase.app`), for classifying subdomains vs custom domains.
    pub platform_domain: String,
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
            domain_map: None,
            cert_request: None,
            cert_status: None,
            platform_domain: "jkbase.app".to_string(),
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
        .route("/projects/{id}/domains/{domain}/verify", post(verify_domain))
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
                .into_response()
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
                    // Release all claimed hostnames so they can't be taken over
                    // or left dangling in the routing maps.
                    if let Ok(domains) = state.store.list_domains_for_project(&id) {
                        for d in domains {
                            let _ = state.store.remove_domain(&d.host);
                            deactivate_host(&state, &d.host).await;
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
                .into_response()
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
            return Err("only flat subdomains (<label>.{platform}) are supported".replace(
                "{platform}",
                platform_domain,
            ));
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

async fn reconcile_deploy_domains(state: &AppState, project: &Project, deploy_path: &std::path::Path) {
    let Some(tenant_id) = project.tenant_id.clone() else {
        return;
    };

    // (raw host, optional site name)
    let mut declared: Vec<(String, Option<String>)> = Vec::new();

    let sites: Vec<jkbase_common::config::ResolvedSite> = std::fs::read_to_string(deploy_path.join("_sites.json"))
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
