//! `jkbase quota`: show or set a project's resource quotas.
//!
//! Tenant sets are clamped to the platform defaults server-side; an operator's
//! `--admin-token` may raise them. Build memory (`--set-build-mem-mib`) is operator-only —
//! it sizes a shared-host build VM — so a tenant attempt is refused by the server, and the
//! server's reason is printed rather than a bare status.

use super::{GIB, fmt_bytes, resolve_project_id};

/// The caps a `jkbase quota` invocation asked to set. Only the passed ones are sent.
pub(super) struct QuotaSet {
    pub storage_gib: Option<f64>,
    pub bandwidth_gib: Option<f64>,
    pub build_minutes: Option<f64>,
    pub build_mem_mib: Option<u32>,
}

impl QuotaSet {
    /// The partial JSON body: ONLY the caps the operator actually passed. The server merges
    /// them onto the project's current values (an omitted cap is preserved, never zeroed).
    /// Sending a full body with defaulted-to-0 caps used to silently zero an untouched cap
    /// under --admin-token (the clamp that would have masked it is skipped for admins).
    fn body(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut body = serde_json::Map::new();
        if let Some(g) = self.storage_gib {
            body.insert("storage_bytes_max".into(), ((g * GIB) as u64).into());
        }
        if let Some(g) = self.bandwidth_gib {
            body.insert(
                "bandwidth_bytes_per_month".into(),
                ((g * GIB) as u64).into(),
            );
        }
        if let Some(m) = self.build_minutes {
            // Quota is stored in build-SECONDS; the CLI takes minutes for parity with the
            // 200-build-minute default. Non-admin sets are clamped to that default server-side.
            body.insert("build_seconds_per_month".into(), ((m * 60.0) as u64).into());
        }
        if let Some(mib) = self.build_mem_mib {
            body.insert("build_mem_mib".into(), mib.into());
        }
        body
    }
}

pub(super) async fn run_quota(
    project: Option<String>,
    set: QuotaSet,
    admin_token: Option<String>,
    api: String,
) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token =
        crate::credentials::load_token()?.ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);
    let url = format!("{api}/projects/{project_id}/quota");

    let body = set.body();
    if !body.is_empty() {
        let mut post = client.post(&url).json(&serde_json::Value::Object(body));
        if let Some(tok) = &admin_token {
            post = post.header("X-Admin-Token", tok);
        }
        let resp = post.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let reason = resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_owned));
            match reason {
                Some(r) => anyhow::bail!("failed to set quota ({status}): {r}"),
                None => anyhow::bail!("failed to set quota ({status})"),
            }
        }
        println!(
            "{}",
            if admin_token.is_some() {
                "Quota updated (admin override)."
            } else {
                "Quota updated (values are clamped to platform defaults)."
            }
        );
    }

    // Pass the admin token on the read too, so an operator setting a quota on a tenant's
    // project sees the real values back (the GET is owner-scoped otherwise → 404→default).
    let mut get = client.get(&url);
    if let Some(tok) = &admin_token {
        get = get.header("X-Admin-Token", tok);
    }
    let resp = get.send().await?;
    if !resp.status().is_success() {
        // Don't parse an error body as a quota — its missing fields would print as an
        // all-zero "platform default" quota, hiding the not-found/authorization failure.
        anyhow::bail!("failed to read quota ({})", resp.status());
    }
    let v: serde_json::Value = resp.json().await?;
    println!("Quota for '{project_id}':");
    println!(
        "  Storage cap:   {}",
        fmt_bytes(v["storage_bytes_max"].as_u64().unwrap_or(0))
    );
    println!(
        "  Bandwidth cap: {} / month",
        fmt_bytes(v["bandwidth_bytes_per_month"].as_u64().unwrap_or(0))
    );
    println!(
        "  Build cap:     {:.0} build-minutes / month",
        v["build_seconds_per_month"].as_u64().unwrap_or(0) as f64 / 60.0
    );
    println!("  Build memory:  {}", build_mem_line(&v["build_mem_mib"]));
    println!(
        "  Source:        {}",
        if v["overridden"].as_bool().unwrap_or(false) {
            "per-project override"
        } else {
            "platform default"
        }
    );
    if v["bandwidth_blocked"].as_bool().unwrap_or(false) {
        let reason = v["blocked_reason"].as_str().unwrap_or("over quota");
        println!("  STATUS:        BLOCKED — {reason}");
    }
    Ok(())
}

/// `build_mem_mib` is `null` (or absent, from a server predating it) when the project uses
/// the server's default build-VM size, which the control API doesn't know.
fn build_mem_line(v: &serde_json::Value) -> String {
    match v.as_u64() {
        Some(mib) => format!("{mib} MiB per build VM"),
        None => "server default per build VM".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_carries_only_the_passed_caps() {
        let set = QuotaSet {
            storage_gib: None,
            bandwidth_gib: None,
            build_minutes: Some(3000.0),
            build_mem_mib: Some(8192),
        };
        let body = set.body();
        assert_eq!(body.len(), 2);
        assert_eq!(body["build_seconds_per_month"], 180000);
        assert_eq!(body["build_mem_mib"], 8192);
        let none = QuotaSet {
            storage_gib: None,
            bandwidth_gib: None,
            build_minutes: None,
            build_mem_mib: None,
        };
        assert!(none.body().is_empty());
    }

    #[test]
    fn build_mem_line_distinguishes_override_from_default() {
        assert_eq!(build_mem_line(&8192.into()), "8192 MiB per build VM");
        assert_eq!(
            build_mem_line(&serde_json::Value::Null),
            "server default per build VM"
        );
    }
}
