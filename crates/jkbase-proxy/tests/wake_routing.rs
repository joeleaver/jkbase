//! The proxy's two wake seams stay apart: an HTTP request for a hibernated (unrouted) host wakes
//! through `wake_callback` — the APP VM, which the request is then forwarded to — and NEVER through
//! `db_wake_callback`, which for a dedicated-DB project resolves the sibling DB VM. Regression
//! guard for both seams sharing one DB-targeted callback, which sent a dedicated project's HTTP
//! traffic to its DB VM and left the app VM hibernated.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use jkbase_proxy::{
    DomainTarget, ProxyConfig, WakeCallback, new_domain_map, new_routing_table, serve,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Answers every request `200 app-vm`.
async fn spawn_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\napp-vm",
                    )
                    .await;
            });
        }
    });
    port
}

/// A wake callback that records each project id it is asked to wake and answers `ip`.
fn recording_wake(ip: &'static str, calls: Arc<Mutex<Vec<String>>>) -> WakeCallback {
    Arc::new(move |project_id: String| {
        calls.lock().unwrap().push(project_id);
        Box::pin(async move { Ok(ip.to_string()) })
    })
}

async fn get(proxy_port: u16, host: &str) -> (String, String) {
    let mut sock = None;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", proxy_port)).await {
            sock = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut sock = sock.expect("proxy never came up");
    sock.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut all = Vec::new();
    timeout(Duration::from_secs(5), sock.read_to_end(&mut all))
        .await
        .expect("timed out reading response")
        .unwrap();
    let text = String::from_utf8_lossy(&all).to_string();
    let status = text.lines().next().unwrap_or_default().to_string();
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
}

#[tokio::test]
async fn http_wake_uses_the_app_seam_never_the_db_seam() {
    let backend_port = spawn_backend().await;
    let proxy_port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    // A known host with NO route = a hibernated project the proxy must wake.
    let domains = new_domain_map();
    domains.write().await.insert(
        "shop.example.com".to_string(),
        DomainTarget {
            project_id: "ded".to_string(),
            site: None,
            acme_delegation: None,
        },
    );
    let app_calls = Arc::new(Mutex::new(Vec::new()));
    let db_calls = Arc::new(Mutex::new(Vec::new()));
    let cfg = ProxyConfig {
        http_port: proxy_port,
        https_port: None,
        platform_domain: "test.local".to_string(),
        cert_manager: None,
        api_addr: None,
        storage_addr: None,
        auth_addr: None,
        domains: Some(domains),
        activity_tracker: None,
        // The app VM answers on loopback; the "DB VM" address is unroutable, so a misdirected
        // forward would surface as a 502 rather than silently passing.
        wake_callback: Some(recording_wake("127.0.0.1", app_calls.clone())),
        db_wake_callback: Some(recording_wake("192.0.2.1", db_calls.clone())),
        backend_port,
        relay_idle_timeout: Duration::from_secs(600),
        max_concurrent_upgrades: 64,
        http_listener: None,
        https_listener: None,
        db_auth_callback: None,
        db_relay_registry: None,
        db_max_concurrent: 1024,
        db_preauth_max: 256,
        db_preauth_per_ip_max: 32,
        db_max_per_project: 64,
    };
    let routes = new_routing_table();
    tokio::spawn(async move {
        let _ = serve(cfg, routes, tokio_util::sync::CancellationToken::new()).await;
    });

    let (status, body) = get(proxy_port, "shop.example.com").await;
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "app-vm");
    assert_eq!(*app_calls.lock().unwrap(), vec!["ded".to_string()]);
    assert!(
        db_calls.lock().unwrap().is_empty(),
        "HTTP routing must never wake through the DB seam"
    );
}
