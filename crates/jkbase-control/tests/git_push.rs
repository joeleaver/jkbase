//! End-to-end check of the smart-HTTP git-push build trigger (build · D): a real
//! `git push` over the public `router()` must authenticate by per-project token,
//! land the objects in the per-project bare repo, and funnel the pushed tip into
//! the build pipeline as a gzipped source tar. Also covers token rejection.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use jkbase_control::api::{AppState, BuildContext, router};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{Project, ProjectState, RepoTriggerConfig, Store};
use jkbase_control::auth;

/// Unique temp dir for one test run (no `Date::now`-free clock needed — pid +
/// the OS temp dir is enough isolation between concurrent test binaries).
fn scratch(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("jkbase-gitpush-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Run `git` in `dir` with a hermetic environment (no user/system gitconfig, no
/// credential prompt), returning the raw output.
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir) // isolate from the developer's ~/.gitconfig
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("spawn git")
}

fn git_ok(dir: &Path, args: &[&str]) {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn targz_entry_names(data: &[u8]) -> Vec<String> {
    let gz = flate2::read::GzDecoder::new(data);
    let mut ar = tar::Archive::new(gz);
    ar.entries()
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path().unwrap().to_string_lossy().to_string())
        .collect()
}

// Multi-thread: the test drives `git push` via a BLOCKING `Command::output()`,
// which would starve the in-process server task on a current-thread runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_push_authenticates_lands_and_triggers_build() {
    let base = scratch("e2e");
    let store = Store::open(&base.join("db.redb")).unwrap();
    let logs = LogStore::new(base.join("logs"));
    // data_dir = deploy_dir.parent(); bare repos live under {data_dir}/git/.
    let deploy_dir = base.join("data").join("hosting");
    std::fs::create_dir_all(&deploy_dir).unwrap();

    let project_id = "demo";
    store
        .create_project(&Project {
            id: project_id.to_string(),
            name: "demo".to_string(),
            tenant_id: Some("tenant-1".to_string()),
            current_version: None,
            state: ProjectState::Active,
            vm_ip: None,
            domains: vec![],
        })
        .unwrap();

    // Mint a per-project git-push token (store only its fingerprint).
    let token = auth::generate_git_token();
    store
        .save_repo_trigger(&RepoTriggerConfig {
            project_id: project_id.to_string(),
            git_token_fingerprint: Some(auth::token_fingerprint(&token)),
            git_token_created_at: 1,
            webhook_secrets: vec![],
        })
        .unwrap();

    // A build callback that captures the funnelled source tarball, then fails so
    // we don't drive the full deploy tail — we only assert the git→archive→funnel
    // hand-off delivered the right source.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut state = AppState::new(store, logs, deploy_dir);
    state.build_callback = Some(Arc::new(move |ctx: BuildContext| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.send(ctx.source_tar_gz);
            anyhow::bail!("test stub: source captured")
        })
    }));
    let state = Arc::new(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone(), "jkbase.app".to_string());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("axum serve");
    });

    // Wait for the server to accept connections before pushing.
    tokio::time::timeout(Duration::from_secs(5), reqwest::get(format!("http://{addr}/health")))
        .await
        .expect("server did not come up")
        .expect("health request failed");

    // Build a local repo with a jkbase.toml and push it.
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git_ok(&work, &["init", "-q", "-b", "main"]);
    git_ok(&work, &["config", "user.email", "t@example.com"]);
    git_ok(&work, &["config", "user.name", "Tester"]);
    std::fs::write(work.join("jkbase.toml"), "[project]\nname = \"demo\"\n").unwrap();
    std::fs::write(work.join("index.html"), "<h1>hi</h1>").unwrap();
    git_ok(&work, &["add", "."]);
    git_ok(&work, &["commit", "-q", "-m", "init"]);

    // `timeout` guards against a server-side hang wedging CI.
    let good_url = format!("http://jkbase:{token}@{addr}/git/{project_id}");
    let push = Command::new("timeout")
        .args(["30", "git", "push", "-q", &good_url, "HEAD:main"])
        .current_dir(&work)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", &work)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("spawn git push");
    assert!(
        push.status.success(),
        "authenticated git push failed (status {:?}): {}",
        push.status.code(),
        String::from_utf8_lossy(&push.stderr)
    );

    // The objects landed in the per-project bare repo at refs/heads/main.
    let bare = base.join("data").join("git").join("demo.git");
    let tip = git(&work, &["--git-dir", bare.to_str().unwrap(), "rev-parse", "refs/heads/main"]);
    assert!(tip.status.success(), "bare repo has no refs/heads/main");

    // The push triggered a build whose source tar carries jkbase.toml.
    let source = tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("build was not triggered within 15s")
        .expect("build callback channel closed");
    let names = targz_entry_names(&source);
    assert!(
        names.iter().any(|n| n.ends_with("jkbase.toml")),
        "funnelled source tar is missing jkbase.toml: {names:?}"
    );

    // A wrong token is rejected at info/refs (401), so the push fails.
    let bad_url = format!("http://jkbase:not-the-token@{addr}/git/{project_id}");
    let bad = git(&work, &["push", "-q", &bad_url, "HEAD:main"]);
    assert!(
        !bad.status.success(),
        "git push with a wrong token must be rejected"
    );
}
