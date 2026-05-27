use crate::auth::{self, ApiToken, Tenant};
use crate::store::{Project, Store};
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
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

pub struct AppState {
    pub store: Store,
    pub deploy_dir: PathBuf,
    pub deploy_callback: Option<DeployCallback>,
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
    pub fn new(store: Store, deploy_dir: PathBuf) -> Self {
        Self {
            store,
            deploy_dir,
            deploy_callback: None,
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
        .route(
            "/projects/{id}/secrets",
            get(list_secrets).post(set_secret),
        )
        .route("/projects/{id}/secrets/{key}", axum::routing::delete(delete_secret))
        .route("/me", get(get_me))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    let public = Router::new()
        .route("/init", post(init_platform))
        .route("/register", post(register))
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
}

#[derive(Serialize)]
pub struct RegisterResponse {
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

    match create_tenant_and_token(&state.store, &req.email) {
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

    if let Ok(Some(_)) = state.store.find_tenant_by_email(&req.email) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "an account with this email already exists".to_string(),
            }),
        )
            .into_response();
    }

    match create_tenant_and_token(&state.store, &req.email) {
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

fn create_tenant_and_token(store: &Store, email: &str) -> anyhow::Result<(String, String)> {
    let tenant_id = auth::generate_id();
    let tenant = Tenant {
        id: tenant_id.clone(),
        email: email.to_string(),
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

    let live_link = state.deploy_dir.join(&project.id).join("live");
    let _ = tokio::fs::remove_file(&live_link).await;
    tokio::fs::symlink(&deploy_path, &live_link).await?;

    project.current_version = Some(version);
    project.state = crate::store::ProjectState::Active;
    state.store.update_project(project)?;

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

fn slug(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
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

fn to_response(p: &Project) -> ProjectResponse {
    ProjectResponse {
        id: p.id.clone(),
        name: p.name.clone(),
        current_version: p.current_version,
        url: Some(format!("https://{}.jkbase.app", p.id)),
    }
}
