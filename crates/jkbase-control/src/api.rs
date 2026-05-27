use crate::auth::{self, ApiToken, Tenant};
use crate::store::{Project, Store};
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
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

pub fn router(state: Arc<AppState>) -> Router {
    let authenticated = Router::new()
        .route("/projects", get(list_projects).post(create_project))
        .route("/projects/{id}", get(get_project).delete(delete_project))
        .route("/projects/{id}/deploy", post(deploy))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    let public = Router::new().route("/init", post(init_platform));

    Router::new()
        .merge(authenticated)
        .merge(public)
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

async fn init_platform(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitRequest>,
) -> impl IntoResponse {
    // Only allow init if no tenants exist yet
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

    let tenant_id = auth::generate_id();
    let tenant = Tenant {
        id: tenant_id.clone(),
        email: req.email,
        created_at: auth::timestamp(),
    };

    if let Err(e) = state.store.create_tenant(&tenant) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
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

    let api_token = ApiToken {
        id: auth::generate_id(),
        tenant_id: tenant_id.clone(),
        name: "default".to_string(),
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

    info!(tenant_id = %tenant_id, email = %tenant.email, "platform initialized");
    (
        StatusCode::CREATED,
        Json(InitResponse {
            tenant_id,
            token: raw_token,
        }),
    )
        .into_response()
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
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
        Ok(Some(_tenant)) => next.run(req).await.into_response(),
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

async fn list_projects(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.store.list_projects() {
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
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_project(&id) {
        Ok(Some(project)) => Json(to_response(&project)).into_response(),
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
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.delete_project(&id) {
        Ok(true) => {
            info!(project_id = %id, "project deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
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
    Path(id): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    // Check project exists
    let mut project = match state.store.get_project(&id) {
        Ok(Some(p)) => p,
        Ok(None) => {
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

    // Create deployment directory
    let deploy_path = state
        .deploy_dir
        .join(&project.id)
        .join("deployments")
        .join(format!("v{version}"));
    tokio::fs::create_dir_all(&deploy_path).await?;

    // Extract tarball
    let tar = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(&deploy_path)?;

    // Update live symlink
    let live_link = state.deploy_dir.join(&project.id).join("live");
    let _ = tokio::fs::remove_file(&live_link).await;
    tokio::fs::symlink(&deploy_path, &live_link).await?;

    // Update project state
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

fn to_response(p: &Project) -> ProjectResponse {
    ProjectResponse {
        id: p.id.clone(),
        name: p.name.clone(),
        current_version: p.current_version,
    }
}
