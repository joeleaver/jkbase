//! `jkbase db …` — the project's managed database: access keys, the local reach-plane proxy,
//! backups + restore, the dedicated-tier drop, and the `rewrite-covers` maintenance pass.

use super::{db_proxy, resolve_project_id};
use anyhow::Context;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum DbCommand {
    /// Manage managed-DB access keys (the reach-plane credential)
    #[command(subcommand)]
    Key(DbKeyCommand),
    /// Run a local proxy that tunnels plaintext `@rhypedb/client` connections to the
    /// project's managed DB over the authenticated TLS reach plane.
    Proxy(db_proxy::ProxyArgs),
    /// Trigger a backup of the project's managed DB to platform storage
    Backup {
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// List the project's managed-DB backups (id, time, size, status)
    Backups {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Destroy the project's dedicated-tier database and its disk (DESTRUCTIVE, irreversible).
    /// Frees the storage it reserves, e.g. after leaving the dedicated tier. A co-located
    /// database is not affected.
    Drop {
        /// Skip the confirmation prompt
        #[arg(long)]
        force: bool,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Restore the managed DB from a backup (DESTRUCTIVE — overwrites current data)
    Restore {
        /// Backup id (from `jkbase db backups`)
        backup_id: String,
        /// Skip the confirmation prompt
        #[arg(long)]
        force: bool,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Rewrite the database's stored covers to the current engine's rules. Repairs a store
    /// written by an older engine (`cover_peers_sound: false` in its status). Safe to run on a
    /// live database, to interrupt, and to rerun; it can take a while on a large store.
    RewriteCovers {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
}

#[derive(Subcommand)]
pub enum DbKeyCommand {
    /// Create a new managed-DB access key (the secret is shown ONCE)
    Create {
        /// Optional label (e.g. ci, prod-app)
        #[arg(long, default_value = "")]
        label: String,
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// List managed-DB access keys (ids + labels; secrets are never shown)
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Revoke a managed-DB access key
    #[command(alias = "revoke")]
    Rm {
        /// Access key id to revoke
        access_key_id: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
}

pub(super) async fn run_db(cmd: DbCommand) -> anyhow::Result<()> {
    match cmd {
        DbCommand::Key(cmd) => run_db_key(cmd).await,
        DbCommand::Proxy(args) => db_proxy::run(args).await,
        DbCommand::Backup { project, api } => run_db_backup(project, api).await,
        DbCommand::Backups { project, api } => run_db_backups(project, api).await,
        DbCommand::Drop {
            force,
            project,
            api,
        } => run_db_drop(force, project, api).await,
        DbCommand::Restore {
            backup_id,
            force,
            project,
            api,
        } => run_db_restore(backup_id, force, project, api).await,
        DbCommand::RewriteCovers { project, api } => run_db_rewrite_covers(project, api).await,
    }
}

/// Client-side ceiling on one rewrite-covers call: the server bounds the pass at 1h, so this only
/// stops the CLI hanging past that on a dead connection.
const REWRITE_COVERS_CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(65 * 60);

async fn run_db_rewrite_covers(project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token =
        crate::credentials::load_token()?.ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);
    println!("Rewriting covers for project '{project_id}' (this can take a while)...");
    let resp = client
        .post(format!("{api}/projects/{project_id}/db/rewrite-covers"))
        .timeout(REWRITE_COVERS_CLIENT_TIMEOUT)
        .send()
        .await
        .context("failed to connect to API")?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "rewrite-covers failed: {}",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
    println!("{}", describe_rewrite_covers(&body)?);
    Ok(())
}

/// Render the engine's rewrite-covers stats, or the engine's own failure as an error.
fn describe_rewrite_covers(body: &serde_json::Value) -> anyhow::Result<String> {
    if body["ok"].as_bool() != Some(true) {
        anyhow::bail!(
            "rewrite-covers failed in the database: {} (rerunning it is safe)",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
    let n = |k: &str| body[k].as_u64().unwrap_or(0);
    let sound = match body["cover_peers_sound"].as_bool() {
        Some(true) => "yes",
        Some(false) => "NO (rerun it)",
        None => "unknown",
    };
    Ok(format!(
        "Rewrite complete in {:.1}s: {} objects visited, {} reverse edges and {} index entries \
         rewritten. Covers sound: {sound}.",
        n("ms") as f64 / 1000.0,
        n("objects"),
        n("rev_edges_rewritten"),
        n("index_entries_rewritten"),
    ))
}

/// Format a unix-ms timestamp as a compact UTC string without pulling in chrono.
fn fmt_ms(ms: u64) -> String {
    let secs = ms / 1000;
    // Days since epoch → y/m/d via a civil-from-days conversion (Howard Hinnant's algorithm).
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn fmt_size(bytes: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

async fn run_db_backup(project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token =
        crate::credentials::load_token()?.ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);

    let resp = client
        .post(format!("{api}/projects/{project_id}/db/backups"))
        .send()
        .await
        .context("failed to connect to API")?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        anyhow::bail!(
            "failed to start backup: {}",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
    let body: serde_json::Value = resp.json().await?;
    let backup_id = body["backup_id"].as_str().unwrap_or("").to_string();
    println!("Backup started for project '{project_id}': {backup_id}");
    print!("Waiting for completion");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // Poll the catalog until the backup is Complete/Failed (or we give up).
    for _ in 0..600 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        print!(".");
        let _ = std::io::stdout().flush();
        let list = client
            .get(format!("{api}/projects/{project_id}/db/backups"))
            .send()
            .await
            .context("failed to poll backups")?;
        if !list.status().is_success() {
            continue;
        }
        let rows: Vec<serde_json::Value> = list.json().await.unwrap_or_default();
        let Some(row) = rows
            .iter()
            .find(|r| r["backup_id"].as_str() == Some(backup_id.as_str()))
        else {
            continue;
        };
        match row["status"].as_str() {
            Some("complete") => {
                let size = row["size_bytes"].as_u64().unwrap_or(0);
                println!("\nBackup complete: {backup_id} ({})", fmt_size(size));
                return Ok(());
            }
            Some("failed") => {
                println!();
                anyhow::bail!("backup failed (see server logs)");
            }
            _ => {}
        }
    }
    println!();
    anyhow::bail!("backup did not complete in time (still pending — check `jkbase db backups`)");
}

async fn run_db_backups(project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token =
        crate::credentials::load_token()?.ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);

    let resp = client
        .get(format!("{api}/projects/{project_id}/db/backups"))
        .send()
        .await
        .context("failed to connect to API")?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        anyhow::bail!(
            "failed to list backups: {}",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
    let rows: Vec<serde_json::Value> = resp.json().await?;
    if rows.is_empty() {
        println!("No backups for project '{project_id}'");
        return Ok(());
    }
    println!(
        "{:<28} {:<21} {:>10}  {:<9} SUMMARY",
        "BACKUP ID", "CREATED", "SIZE", "STATUS"
    );
    for r in &rows {
        let id = r["backup_id"].as_str().unwrap_or("");
        let created = fmt_ms(r["created_at_ms"].as_u64().unwrap_or(0));
        let size = fmt_size(r["size_bytes"].as_u64().unwrap_or(0));
        let status = r["status"].as_str().unwrap_or("");
        let summary = r["manifest_summary"].as_str().unwrap_or("");
        println!("{id:<28} {created:<21} {size:>10}  {status:<9} {summary}");
    }
    Ok(())
}

async fn run_db_restore(
    backup_id: String,
    force: bool,
    project: Option<String>,
    api: String,
) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    if !force {
        eprint!(
            "This will OVERWRITE the current data of project '{project_id}' with backup \
             '{backup_id}'.\nType the project name to confirm: "
        );
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim() != project_id {
            anyhow::bail!("confirmation did not match; restore aborted");
        }
    }
    let token =
        crate::credentials::load_token()?.ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);

    let resp = client
        .post(format!("{api}/projects/{project_id}/db/restore"))
        .json(&serde_json::json!({ "backup_id": backup_id }))
        .send()
        .await
        .context("failed to connect to API")?;
    if resp.status().is_success() {
        println!(
            "Restore of '{backup_id}' started for project '{project_id}'. The database will \
             briefly restart; check `jkbase db backups` / your app once it's back."
        );
        Ok(())
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        anyhow::bail!(
            "failed to start restore: {}",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
}

async fn run_db_drop(force: bool, project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    if !force {
        eprint!(
            "This will PERMANENTLY DELETE the dedicated-tier database of project '{project_id}' \
             and its disk. Back it up first (`jkbase db backup`) if you need the data.\n\
             Type the project id to confirm: "
        );
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim() != project_id {
            anyhow::bail!("confirmation did not match; drop aborted");
        }
    }
    let token =
        crate::credentials::load_token()?.ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
    let client = crate::credentials::authenticated_client(&token);

    let resp = client
        .delete(format!("{api}/projects/{project_id}/db/dedicated"))
        .json(&serde_json::json!({ "confirm": project_id }))
        .send()
        .await
        .context("failed to connect to API")?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        anyhow::bail!(
            "failed to drop database: {}",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .context("the drop request succeeded but its response was unreadable")?;
    let dropped = body["dropped"]
        .as_bool()
        .context("the drop request succeeded but its response had no `dropped` field")?;
    if dropped {
        println!(
            "Dropped the dedicated database of project '{project_id}'. If jkbase.toml still \
             declares `tier = \"dedicated\"`, the next deploy starts a fresh, empty one."
        );
    } else {
        println!(
            "Project '{project_id}' has no dedicated-tier database to drop (a co-located \
             database lives on the app's own disk and was not touched)."
        );
    }
    Ok(())
}

async fn run_db_key(cmd: DbKeyCommand) -> anyhow::Result<()> {
    match cmd {
        DbKeyCommand::Create {
            label,
            project,
            api,
        } => {
            let project_id = resolve_project_id(project)?;
            let token = crate::credentials::load_token()?
                .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
            let client = crate::credentials::authenticated_client(&token);

            let resp = client
                .post(format!("{api}/projects/{project_id}/db-keys"))
                .json(&serde_json::json!({ "label": label }))
                .send()
                .await
                .context("failed to connect to API")?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                let akid = body["access_key_id"].as_str().unwrap_or("");
                let secret = body["secret"].as_str().unwrap_or("");
                println!("Managed-DB access key created for project '{project_id}':");
                println!("  Access Key ID: {akid}");
                println!("  Secret:        {secret}");
                println!("\n  Save the secret now — it is not shown again.");
                println!("  It authenticates managed-DB connections via the reach-plane.");
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("failed to create db key: {err}");
            }
            Ok(())
        }
        DbKeyCommand::List { project, api } => {
            let project_id = resolve_project_id(project)?;
            let token = crate::credentials::load_token()?
                .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
            let client = crate::credentials::authenticated_client(&token);

            let resp = client
                .get(format!("{api}/projects/{project_id}/db-keys"))
                .send()
                .await
                .context("failed to connect to API")?;

            if resp.status().is_success() {
                let keys: Vec<serde_json::Value> = resp.json().await?;
                if keys.is_empty() {
                    println!("No managed-DB keys for project '{project_id}'");
                } else {
                    for k in &keys {
                        let akid = k["access_key_id"].as_str().unwrap_or("");
                        let label = k["label"].as_str().unwrap_or("");
                        if label.is_empty() {
                            println!("  {akid}");
                        } else {
                            println!("  {akid}  ({label})");
                        }
                    }
                }
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("failed to list db keys: {err}");
            }
            Ok(())
        }
        DbKeyCommand::Rm {
            access_key_id,
            project,
            api,
        } => {
            let project_id = resolve_project_id(project)?;
            let token = crate::credentials::load_token()?
                .ok_or_else(|| anyhow::anyhow!("not authenticated"))?;
            let client = crate::credentials::authenticated_client(&token);

            let resp = client
                .delete(format!(
                    "{api}/projects/{project_id}/db-keys/{access_key_id}"
                ))
                .send()
                .await
                .context("failed to connect to API")?;

            if resp.status().is_success() {
                println!("Managed-DB key '{access_key_id}' revoked from project '{project_id}'");
            } else {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let err = body["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("failed to revoke db key: {err}");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::describe_rewrite_covers;
    use serde_json::json;

    #[test]
    fn rewrite_covers_stats_are_described() {
        let out = describe_rewrite_covers(&json!({
            "ok": true, "ms": 2500, "objects": 40, "rev_edges_rewritten": 7,
            "index_entries_rewritten": 0, "cover_peers_sound": true
        }))
        .unwrap();
        assert_eq!(
            out,
            "Rewrite complete in 2.5s: 40 objects visited, 7 reverse edges and 0 index entries \
             rewritten. Covers sound: yes."
        );
        let out =
            describe_rewrite_covers(&json!({ "ok": true, "cover_peers_sound": false })).unwrap();
        assert!(out.ends_with("Covers sound: NO (rerun it)."));
    }

    #[test]
    fn an_engine_failure_is_an_error() {
        let err = describe_rewrite_covers(&json!({ "ok": false, "error": "write conflict" }))
            .unwrap_err()
            .to_string();
        assert!(err.contains("write conflict") && err.contains("rerunning it is safe"));
        assert!(
            describe_rewrite_covers(&json!({})).is_err(),
            "no `ok` is not success"
        );
    }
}
