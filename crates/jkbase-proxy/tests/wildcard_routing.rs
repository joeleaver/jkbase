//! End-to-end wildcard routing on the plain-HTTP proxy port (local dev / no TLS): a real
//! `serve()` in front of a local backend that echoes the `Host` it received and the
//! site the proxy stamped. Proves the wildcard is a single-label fallback behind exact
//! hosts (including one registered after it), that the ORIGINAL `Host` reaches the app
//! (DevelUp routes builds by it), and that deeper / base / literal-`*` hosts 404.

use std::time::Duration;

use jkbase_proxy::{DomainTarget, ProxyConfig, new_domain_map, new_routing_table, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Answers every request `200` with body `host=<Host>;site=<x-jkbase-site>`.
async fn spawn_host_echo_backend() -> u16 {
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
                let head = String::from_utf8_lossy(&seen).to_string();
                let header = |name: &str| {
                    head.lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                        })
                        .unwrap_or_default()
                };
                let body = format!("host={};site={}", header("host"), header("x-jkbase-site"));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

fn config(proxy_port: u16, backend_port: u16) -> ProxyConfig {
    ProxyConfig {
        http_port: proxy_port,
        https_port: None,
        platform_domain: "test.local".to_string(),
        cert_manager: None,
        api_addr: None,
        storage_addr: None,
        auth_addr: None,
        domains: None,
        activity_tracker: None,
        wake_callback: None,
        db_wake_callback: None,
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
    }
}

fn site(project: &str, site: &str) -> DomainTarget {
    DomainTarget {
        project_id: project.to_string(),
        site: Some(site.to_string()),
        acme_delegation: None,
    }
}

/// One request → (status line, body).
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
async fn wildcard_routes_one_label_behind_exact_hosts_over_plain_http() {
    let backend_port = spawn_host_echo_backend().await;
    let proxy_port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    // Two projects (both "running" on the echo backend); sites tell them apart.
    let domains = new_domain_map();
    let routes = new_routing_table();
    for (key, target) in [
        ("*.play.develup.win", site("develup", "games")),
        ("special.play.develup.win", site("other", "special")),
    ] {
        domains.write().await.insert(key.to_string(), target);
        routes
            .write()
            .await
            .insert(key.to_string(), "127.0.0.1".to_string());
    }
    let mut cfg = config(proxy_port, backend_port);
    cfg.domains = Some(domains.clone());
    let r = routes.clone();
    tokio::spawn(async move {
        let _ = serve(cfg, r, tokio_util::sync::CancellationToken::new()).await;
    });

    // Any single label → the wildcard's project, original Host (case, port, dot) intact.
    let (status, body) = get(proxy_port, "Build-42.Play.DevelUp.win.:8080").await;
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "host=Build-42.Play.DevelUp.win.:8080;site=games");

    // Exact beats wildcard.
    let (status, body) = get(proxy_port, "special.play.develup.win").await;
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "host=special.play.develup.win;site=special");

    // Single-level only; the base and a literal `*` are not covered.
    for host in [
        "a.b.play.develup.win",
        "play.develup.win",
        "*.play.develup.win",
    ] {
        let (status, _) = get(proxy_port, host).await;
        assert!(status.contains("404"), "{host}: {status}");
    }

    // An exact host another tenant registers AFTER the wildcard takes over at once.
    let (_, body) = get(proxy_port, "late.play.develup.win").await;
    assert_eq!(body, "host=late.play.develup.win;site=games");
    domains.write().await.insert(
        "late.play.develup.win".to_string(),
        site("latecomer", "late"),
    );
    routes
        .write()
        .await
        .insert("late.play.develup.win".to_string(), "127.0.0.1".to_string());
    let (_, body) = get(proxy_port, "late.play.develup.win").await;
    assert_eq!(body, "host=late.play.develup.win;site=late");

    // Removing the wildcard unroutes every host under it.
    domains.write().await.remove("*.play.develup.win");
    routes.write().await.remove("*.play.develup.win");
    let (status, _) = get(proxy_port, "build-42.play.develup.win").await;
    assert!(status.contains("404"), "{status}");
}
