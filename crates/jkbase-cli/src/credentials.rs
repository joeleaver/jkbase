use anyhow::{Context, Result};
use std::path::PathBuf;

fn credentials_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".jkbase")
        .join("credentials")
}

pub fn load_token() -> Result<Option<String>> {
    if let Ok(token) = std::env::var("JKBASE_TOKEN") {
        return Ok(Some(token));
    }

    let path = credentials_path();
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let token = content.trim().to_string();
    if token.is_empty() {
        return Ok(None);
    }
    Ok(Some(token))
}

pub fn save_token(token: &str) -> Result<()> {
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&path, token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub fn authenticated_client(token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}
