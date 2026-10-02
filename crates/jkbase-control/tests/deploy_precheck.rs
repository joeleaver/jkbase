//! A deploy (or rollback) the server's `deploy_precheck_callback` refuses must leave the project
//! WHOLLY on its previous version. The refusal used to fire inside `deploy_callback`, after
//! `live` had already been swapped: the old VM kept running, but the next wake/restart/resume
//! booted the refused tree (for the [R4] tier-flip guard: an empty co-located DB beside the real
//! dedicated one). Covered here:
//!   1. the precheck sees the NEW deployment dir, not `live`;
//!   2. a refused deploy is a 409, `live` + `current_version` + history are untouched, the
//!      refused tree is removed, and the deploy callback (VM teardown/boot) never runs;
//!   3. a refused rollback likewise leaves `live` + `current_version` on the current version.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jkbase_control::api::{AppState, router};
use jkbase_control::auth::{self, ApiToken};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{Project, ProjectState, Store};

/// Marker a test tree carries to make the fake precheck refuse it.
const REFUSE: &str = "REFUSE";

struct Harness {
    addr: std::net::SocketAddr,
    token: String,
    store: Store,
    deploy_dir: PathBuf,
    /// Dirs the precheck was called with, in order.
    prechecked: Arc<Mutex<Vec<PathBuf>>>,
    /// Versions the deploy callback was called with, in order.
    deployed: Arc<Mutex<Vec<u64>>>,
}

async fn spawn(tag: &str) -> Harness {
    let mut base = std::env::temp_dir();
    base.push(format!("jkbase-precheck-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let store = Store::open(&base.join("db.redb")).unwrap();
    let logs = LogStore::new(base.join("logs"));
    let deploy_dir = base.join("data").join("hosting");
    std::fs::create_dir_all(&deploy_dir).unwrap();

    let tenant_id = "tenant-1".to_string();
    store
        .create_tenant(&auth::Tenant {
            id: tenant_id.clone(),
            email: "t@example.com".to_string(),
            password_hash: None,
            created_at: 1,
        })
        .unwrap();
    let raw_token = auth::generate_token();
    store
        .save_api_token(&ApiToken {
            id: auth::generate_id(),
            tenant_id: tenant_id.clone(),
            name: "default".to_string(),
            token_hash: auth::hash_token(&raw_token).unwrap(),
            created_at: 1,
        })
        .unwrap();
    store
        .create_project(&Project {
            id: "app".to_string(),
            name: "app".to_string(),
            tenant_id: Some(tenant_id),
            current_version: None,
            state: ProjectState::Stopped,
            vm_ip: None,
            domains: vec![],
        })
        .unwrap();

    let prechecked = Arc::new(Mutex::new(Vec::new()));
    let deployed = Arc::new(Mutex::new(Vec::new()));
    let mut state = AppState::new(store.clone(), logs, deploy_dir.clone());
    let pc = prechecked.clone();
    state.deploy_precheck_callback = Some(Box::new(move |_id: String, dir: PathBuf| {
        let pc = pc.clone();
        Box::pin(async move {
            let refuse = dir.join(REFUSE).exists();
            pc.lock().unwrap().push(dir);
            if refuse {
                anyhow::bail!("tier flip refused (test)");
            }
            Ok(())
        })
    }));
    let dc = deployed.clone();
    state.deploy_callback = Some(Box::new(move |_id: String, version: u64| {
        let dc = dc.clone();
        Box::pin(async move {
            dc.lock().unwrap().push(version);
            Ok(())
        })
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::new(state), "jkbase.app".to_string());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        reqwest::get(format!("http://{addr}/health")),
    )
    .await
    .expect("server did not come up")
    .expect("health request failed");

    Harness {
        addr,
        token: raw_token,
        store,
        deploy_dir,
        prechecked,
        deployed,
    }
}

/// A gzipped artifact tarball holding `files` (name → contents).
fn artifact(files: &[(&str, &str)]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    for (name, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, name, body.as_bytes()).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

/// Like [`artifact`], plus symlink entries (name → link target).
fn artifact_with_links(files: &[(&str, &str)], links: &[(&str, &str)]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    for (name, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, name, body.as_bytes()).unwrap();
    }
    for (name, target) in links {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        tar.append_link(&mut h, name, target).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

impl Harness {
    async fn deploy(&self, files: &[(&str, &str)]) -> reqwest::Response {
        self.deploy_raw(artifact(files)).await
    }

    async fn deploy_raw(&self, body: Vec<u8>) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("http://{}/projects/app/deploy", self.addr))
            .bearer_auth(&self.token)
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn rollback(&self, version: u64) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("http://{}/projects/app/rollback", self.addr))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "version": version }))
            .send()
            .await
            .unwrap()
    }

    fn version_dir(&self, v: u64) -> PathBuf {
        self.deploy_dir
            .join("app")
            .join("deployments")
            .join(format!("v{v}"))
    }

    fn live_target(&self) -> PathBuf {
        std::fs::read_link(self.deploy_dir.join("app").join("live")).unwrap()
    }

    fn current_version(&self) -> Option<u64> {
        self.store
            .get_project("app")
            .unwrap()
            .unwrap()
            .current_version
    }

    fn history(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .store
            .list_deployments("app")
            .unwrap()
            .into_iter()
            .map(|d| d.version)
            .collect();
        v.sort();
        v
    }
}

fn same(a: &Path, b: &Path) -> bool {
    a.canonicalize().unwrap() == b.canonicalize().unwrap()
}

#[tokio::test]
async fn refused_deploy_leaves_the_previous_version_live() {
    let h = spawn("deploy").await;

    let ok = h.deploy(&[("index.html", "v1")]).await;
    assert_eq!(ok.status().as_u16(), 200, "{}", ok.text().await.unwrap());
    assert!(same(&h.live_target(), &h.version_dir(1)));
    assert_eq!(*h.deployed.lock().unwrap(), vec![1]);

    let refused = h.deploy(&[("index.html", "v2"), (REFUSE, "")]).await;
    assert_eq!(
        refused.status().as_u16(),
        409,
        "a refusal is a conflict, not a 500"
    );
    let body = refused.text().await.unwrap();
    assert!(
        body.contains("tier flip refused"),
        "the reason reaches the tenant: {body}"
    );

    // The precheck judged the NEW tree, not `live`.
    let seen = h.prechecked.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[1],
        h.version_dir(2),
        "precheck must see deployments/v2, not live"
    );

    // Nothing moved: `live`, the version, history — and no VM teardown/boot was attempted.
    assert!(
        same(&h.live_target(), &h.version_dir(1)),
        "live must stay on v1"
    );
    assert_eq!(h.current_version(), Some(1));
    assert_eq!(h.history(), vec![1]);
    assert_eq!(
        *h.deployed.lock().unwrap(),
        vec![1],
        "deploy callback must not run"
    );
    assert!(
        !h.version_dir(2).exists(),
        "the refused tree leaves no orphan bytes"
    );

    // The next accepted deploy reuses the refused version number cleanly.
    let ok = h.deploy(&[("index.html", "v2 fixed")]).await;
    assert_eq!(ok.status().as_u16(), 200, "{}", ok.text().await.unwrap());
    assert!(same(&h.live_target(), &h.version_dir(2)));
    assert_eq!(h.current_version(), Some(2));
    assert_eq!(h.history(), vec![1, 2]);
}

#[tokio::test]
async fn refused_rollback_leaves_the_current_version_live() {
    let h = spawn("rollback").await;

    for body in ["v1", "v2"] {
        let r = h.deploy(&[("index.html", body)]).await;
        assert_eq!(r.status().as_u16(), 200, "{}", r.text().await.unwrap());
    }
    assert_eq!(h.current_version(), Some(2));

    // v1 is now refusable (e.g. it sits at the other managed-DB tier).
    std::fs::write(h.version_dir(1).join(REFUSE), "").unwrap();

    let refused = h.rollback(1).await;
    assert_eq!(refused.status().as_u16(), 409);
    assert_eq!(
        h.prechecked.lock().unwrap().last().unwrap(),
        &h.version_dir(1),
        "rollback prechecks its target tree"
    );
    assert!(
        same(&h.live_target(), &h.version_dir(2)),
        "live must stay on v2"
    );
    assert_eq!(h.current_version(), Some(2));
    assert_eq!(
        *h.deployed.lock().unwrap(),
        vec![1, 2],
        "deploy callback must not run"
    );
    assert!(
        h.version_dir(1).exists(),
        "a refused rollback keeps its retained target"
    );

    // An unrefused rollback still works.
    std::fs::remove_file(h.version_dir(1).join(REFUSE)).unwrap();
    let ok = h.rollback(1).await;
    assert_eq!(ok.status().as_u16(), 200, "{}", ok.text().await.unwrap());
    assert!(same(&h.live_target(), &h.version_dir(1)));
    assert_eq!(h.current_version(), Some(1));
}

/// A raw deploy tarball may carry symlinks with ANY target. In a platform sidecar
/// (`_`-prefixed) one would aim the host's root-privileged reads/rewrites (secrets injection,
/// credential binding, drive attach, DB-image staging) at another tenant's or the host's files,
/// so activation refuses it before anything reads the tree. Links inside a `_servers/<name>/`
/// rootfs or in static-site content ship to the guest link-for-link and stay allowed.
#[tokio::test]
async fn deploy_refuses_symlinks_in_platform_sidecars() {
    let h = spawn("symlinks").await;
    let ok = h.deploy(&[("index.html", "v1")]).await;
    assert_eq!(ok.status().as_u16(), 200, "{}", ok.text().await.unwrap());

    let victim = "/var/lib/jkbase/hosting/victim/live";
    for (name, target) in [
        (
            "_servers/api.json",
            "/var/lib/jkbase/hosting/victim/live/_servers/api.json",
        ),
        ("_functions/f.json", "/etc/passwd"),
        ("_database", "/var/lib/jkbase/hosting/victim/live/_database"),
        ("_database.json", "/tmp/tenant-writable.json"),
        (
            "_layers/sha256-x.erofs",
            "/var/lib/jkbase/data-disks/victim.img",
        ),
        (
            "_servers/api.tar.gz",
            "/var/lib/jkbase/db-backups/victim/b.tar.gz",
        ),
        ("_sites.json", victim),
    ] {
        let body = artifact_with_links(&[("index.html", "v2")], &[(name, target)]);
        let r = h.deploy_raw(body).await;
        assert_eq!(
            r.status().as_u16(),
            409,
            "symlink at {name} must be refused"
        );
        let text = r.text().await.unwrap();
        assert!(text.contains("symlink"), "{name}: {text}");
        assert!(
            same(&h.live_target(), &h.version_dir(1)),
            "{name}: live must stay on v1"
        );
        assert_eq!(h.current_version(), Some(1));
        assert!(!h.version_dir(2).exists(), "{name}: refused tree removed");
    }
    assert_eq!(
        h.prechecked.lock().unwrap().len(),
        1,
        "refused before the precheck"
    );

    // Guest-only links: a server rootfs and static-site content.
    let body = artifact_with_links(
        &[("index.html", "v2"), ("_servers/web/etc/hostname", "web")],
        &[
            ("_servers/web/bin/sh", "/bin/busybox"),
            ("assets/latest.js", "app.js"),
        ],
    );
    let r = h.deploy_raw(body).await;
    assert_eq!(r.status().as_u16(), 200, "{}", r.text().await.unwrap());
    assert_eq!(h.current_version(), Some(2));
}

/// Retained versions may predate the activation check, so a rollback re-validates its target.
#[tokio::test]
async fn rollback_refuses_a_target_with_sidecar_symlinks() {
    let h = spawn("rollback-symlink").await;
    for body in ["v1", "v2"] {
        let r = h.deploy(&[("index.html", body)]).await;
        assert_eq!(r.status().as_u16(), 200, "{}", r.text().await.unwrap());
    }
    std::os::unix::fs::symlink("/etc/passwd", h.version_dir(1).join("_database.json")).unwrap();

    let r = h.rollback(1).await;
    assert_eq!(r.status().as_u16(), 409);
    assert!(same(&h.live_target(), &h.version_dir(2)));
    assert_eq!(h.current_version(), Some(2));
    assert_eq!(*h.deployed.lock().unwrap(), vec![1, 2]);
}
