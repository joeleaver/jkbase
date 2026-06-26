//! `jkbase repo` — wire up push-to-deploy (build · D, connected-repo via CI).
//!
//! Two deliberately-separate concerns:
//!
//! - `connect` — mint a per-project git-push token + add a local `jkbase` git
//!   remote. LOCAL ONLY: it touches `.git/config` and the platform, nothing
//!   tracked. `git push jkbase main` then deploys.
//! - `github` — scaffold a GitHub Actions workflow (a TRACKED file under
//!   `.github/workflows/`). Opt-in by design: writing CD config that a routine
//!   `git add -A` would commit + activate must be an explicit request, never a
//!   side effect of `connect`.

use anyhow::Context;
use clap::Subcommand;
use std::path::Path;
use std::process::Command;

use super::resolve_project_id;

#[derive(Subcommand)]
pub enum RepoCommand {
    /// Mint a git-push token + add a local `jkbase` git remote (local only —
    /// touches .git/config + the platform, nothing tracked). Then
    /// `git push jkbase main` deploys. For GitHub Actions CI, see `jkbase repo github`.
    Connect {
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
        /// Don't add/update the local `jkbase` git remote (just mint + print the token).
        #[arg(long)]
        no_remote: bool,
    },
    /// Scaffold a GitHub Actions push-to-deploy workflow. Writes a TRACKED file
    /// (.github/workflows/jkbase-deploy.yml) — opt-in by design; commit it yourself.
    Github {
        /// Project name (inferred from jkbase.toml if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Platform API URL
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
        /// Print the workflow to stdout instead of writing it into the repo.
        #[arg(long)]
        print: bool,
    },
    /// Re-mint the git-push token (immediately revokes the previous one).
    Token {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
    /// Revoke the git-push token, disabling pushes to jkbase.
    Disconnect {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "https://api.jkbase.app")]
        api: String,
    },
}

pub async fn run(cmd: RepoCommand) -> anyhow::Result<()> {
    match cmd {
        RepoCommand::Connect {
            project,
            api,
            no_remote,
        } => connect(project, api, no_remote).await,
        RepoCommand::Github {
            project,
            api,
            print,
        } => github(project, api, print),
        RepoCommand::Token { project, api } => rotate_token(project, api).await,
        RepoCommand::Disconnect { project, api } => disconnect(project, api).await,
    }
}

/// Split `https://api.jkbase.app` into (`https`, `api.jkbase.app`).
fn split_origin(api: &str) -> anyhow::Result<(&str, &str)> {
    let (scheme, host) = api
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("invalid --api URL: {api}"))?;
    Ok((scheme, host.trim_end_matches('/')))
}

/// POST to mint a git token; returns the one-time plaintext token.
async fn mint_token(api: &str, project_id: &str) -> anyhow::Result<String> {
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated — run `jkbase login` first"))?;
    let client = crate::credentials::authenticated_client(&token);
    let resp = client
        .post(format!("{api}/projects/{project_id}/repo/git-token"))
        .send()
        .await
        .context("failed to connect to API")?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        anyhow::bail!(
            "failed to mint git token: {}",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
    let body: serde_json::Value = resp.json().await.context("invalid API response")?;
    body["token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("API response missing token"))
}

async fn connect(project: Option<String>, api: String, no_remote: bool) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let (scheme, host) = split_origin(&api)?;
    let push_token = mint_token(&api, &project_id).await?;

    // Local `jkbase` remote (token embedded for frictionless `git push jkbase main`).
    // This is the ONLY filesystem effect, and it's confined to .git/config — never
    // a tracked file.
    if !no_remote && in_git_repo() {
        let remote_url = format!("{scheme}://jkbase:{push_token}@{host}/git/{project_id}");
        set_remote("jkbase", &remote_url)?;
        println!("✓ local git remote `jkbase` → {scheme}://{host}/git/{project_id}");
        println!("  (token stored in .git/config; deploy with: git push jkbase main)");
    } else {
        println!("git-push token for '{project_id}' (shown once):\n  {push_token}");
        println!(
            "  remote URL: {scheme}://jkbase:<token>@{host}/git/{project_id}  (deploy: git push <remote> HEAD:main)"
        );
    }

    println!(
        "\nThis token is shown once — save it if you'll need it again (`jkbase repo token` re-mints)."
    );
    println!(
        "Want GitHub Actions push-to-deploy? Run `jkbase repo github` to scaffold the workflow"
    );
    println!("(it writes a tracked file, so it's opt-in), and set the token above as the");
    println!("JKBASE_GIT_TOKEN repo secret.");
    Ok(())
}

/// Scaffold the GitHub Actions deploy workflow. Opt-in + offline: it writes a
/// tracked file (`.github/workflows/jkbase-deploy.yml`) the user then commits;
/// the token comes from the `JKBASE_GIT_TOKEN` repo secret (set from `repo connect`),
/// never inlined here.
fn github(project: Option<String>, api: String, print: bool) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let (scheme, host) = split_origin(&api)?;
    let workflow = render_workflow(scheme, host, &project_id);

    if print {
        println!("--- .github/workflows/jkbase-deploy.yml ---\n{workflow}");
    } else if in_git_repo() {
        let path = Path::new(".github/workflows/jkbase-deploy.yml");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context("create .github/workflows")?;
        }
        std::fs::write(path, &workflow).context("write workflow file")?;
        println!(
            "✓ wrote {} (review + commit it to activate CI)",
            path.display()
        );
    } else {
        println!(
            "(not in a git repo) add this as .github/workflows/jkbase-deploy.yml:\n\n{workflow}"
        );
    }

    println!("\nFinish setup in GitHub:");
    println!("  1. Repo → Settings → Secrets and variables → Actions → New repository secret");
    println!("     Name:  JKBASE_GIT_TOKEN");
    println!("     Value: the token from `jkbase repo connect` (or `jkbase repo token`)");
    println!("  2. Commit .github/workflows/jkbase-deploy.yml and push.");
    Ok(())
}

async fn rotate_token(project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let (scheme, host) = split_origin(&api)?;
    let push_token = mint_token(&api, &project_id).await?;
    if in_git_repo() {
        let remote_url = format!("{scheme}://jkbase:{push_token}@{host}/git/{project_id}");
        set_remote("jkbase", &remote_url)?;
    }
    println!("New git-push token (the previous one is now revoked):\n  {push_token}");
    println!("\nUpdate the JKBASE_GIT_TOKEN secret in GitHub with this value.");
    Ok(())
}

async fn disconnect(project: Option<String>, api: String) -> anyhow::Result<()> {
    let project_id = resolve_project_id(project)?;
    let token = crate::credentials::load_token()?
        .ok_or_else(|| anyhow::anyhow!("not authenticated — run `jkbase login` first"))?;
    let client = crate::credentials::authenticated_client(&token);
    let resp = client
        .delete(format!("{api}/projects/{project_id}/repo/git-token"))
        .send()
        .await
        .context("failed to connect to API")?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        anyhow::bail!(
            "failed to revoke git token: {}",
            body["error"].as_str().unwrap_or("unknown error")
        );
    }
    if in_git_repo() {
        let _ = Command::new("git")
            .args(["remote", "remove", "jkbase"])
            .output();
    }
    println!("Revoked the git-push token for '{project_id}'. Pushes to jkbase are now disabled.");
    Ok(())
}

fn render_workflow(scheme: &str, host: &str, project_id: &str) -> String {
    // Token-less URL; CI supplies it from the JKBASE_GIT_TOKEN secret.
    format!(
        r#"name: Deploy to jkbase
# Pushes this repo's default branch to jkbase, which builds + deploys it.
# Triggers on main OR master; HEAD is always pushed to jkbase's `main`
# (the branch jkbase builds), so a master-default repo still deploys.
on:
  push:
    branches: [main, master]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history so the push to jkbase isn't shallow
      - name: Push to jkbase
        run: git push {scheme}://jkbase:${{{{ secrets.JKBASE_GIT_TOKEN }}}}@{host}/git/{project_id} HEAD:main
"#
    )
}

fn in_git_repo() -> bool {
    Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Add (or replace) a git remote, idempotently.
fn set_remote(name: &str, url: &str) -> anyhow::Result<()> {
    let _ = Command::new("git")
        .args(["remote", "remove", name])
        .output();
    let out = Command::new("git")
        .args(["remote", "add", name, url])
        .output()
        .context("run git remote add")?;
    if !out.status.success() {
        anyhow::bail!(
            "git remote add failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_has_valid_actions_syntax() {
        let wf = render_workflow("https", "api.jkbase.app", "my-app");
        // The secret expansion must render as GitHub Actions `${{ ... }}`, not the
        // doubled braces that `format!` escaping could leave behind.
        assert!(
            wf.contains("${{ secrets.JKBASE_GIT_TOKEN }}"),
            "bad actions expr in:\n{wf}"
        );
        assert!(!wf.contains("${{{{") && !wf.contains("}}}}"));
        // Token-less host in the URL; no plaintext token committed.
        assert!(wf.contains("@api.jkbase.app/git/my-app HEAD:main"));
        assert!(wf.contains("fetch-depth: 0"));
        assert!(wf.contains("branches: [main, master]"));
    }

    #[test]
    fn split_origin_parses_scheme_and_host() {
        assert_eq!(
            split_origin("https://api.jkbase.app").unwrap(),
            ("https", "api.jkbase.app")
        );
        assert_eq!(
            split_origin("http://127.0.0.1:9090/").unwrap(),
            ("http", "127.0.0.1:9090")
        );
        assert!(split_origin("not-a-url").is_err());
    }
}
