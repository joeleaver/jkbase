//! End-to-end checks for the proxy's HTTP/WebSocket forwarding: it relays an
//! `Upgrade` handshake (both the `api.{domain}` infra route and the tenant project
//! path) and pipes raw bytes both ways; a non-upgrade response is buffered and its
//! headers sanitized; and an unsolicited backend `101` becomes a `502`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use jkbase_proxy::{
    DomainTarget, ProxyConfig, RoutingTable, new_domain_map, new_routing_table, serve,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, oneshot};
use tokio::time::timeout;

/// A minimal backend that answers `101 Switching Protocols` once it has seen the
/// request headers, then echoes every subsequent byte — the smallest thing that
/// looks like a WS server. (It 101s regardless of whether the client asked to
/// upgrade, which the unsolicited-101 test relies on.)
async fn spawn_echo_upgrade_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    seen.extend_from_slice(&buf[..n]);
                    if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\n\
                          Connection: Upgrade\r\n\r\n",
                    )
                    .await;
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// A plain HTTP/1.1 backend that returns `200` with a body plus headers a proxy must
/// sanitize: an apex-scoped `Set-Cookie`, an HSTS policy, and a hop-by-hop
/// `Connection` header.
async fn spawn_http_200_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    seen.extend_from_slice(&buf[..n]);
                    if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = b"hello-body";
                let head = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {}\r\n\
                     Content-Type: text/plain\r\n\
                     Set-Cookie: sid=secret; Domain=.test.local; Path=/\r\n\
                     Strict-Transport-Security: max-age=63072000\r\n\
                     Connection: keep-alive\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
            });
        }
    });
    port
}

/// Bind to port 0 and release it. There is a small race before `serve()` re-binds —
/// see [`spawn_proxy`], which surfaces the real bind error if it loses that race.
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn base_config(proxy_port: u16) -> ProxyConfig {
    ProxyConfig {
        http_port: proxy_port,
        https_port: None,
        platform_domain: "test.local".to_string(),
        cert_manager: None,
        api_addr: None,
        storage_addr: None,
        domains: None,
        activity_tracker: None,
        wake_callback: None,
        backend_port: 80,
        relay_idle_timeout: Duration::from_secs(600),
        max_concurrent_upgrades: 64,
        http_listener: None,
        https_listener: None,
        db_auth_callback: None,
        db_relay_registry: None,
        db_max_concurrent: 1024,
        db_preauth_max: 256,
        db_max_per_project: 64,
    }
}

/// Spawn `serve()` and return a receiver that yields its error string if it ever
/// returns `Err` (e.g. a bind failure when `free_port`'s port was taken in the race
/// window). [`connect_proxy`] consults it so a startup failure reports the REAL error
/// instead of a misleading "proxy never came up".
fn spawn_proxy(config: ProxyConfig, routes: RoutingTable) -> oneshot::Receiver<String> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        // Never-cancelled token: these tests don't exercise graceful drain, only the serve path.
        let shutdown = tokio_util::sync::CancellationToken::new();
        if let Err(e) = serve(config, routes, shutdown).await {
            let _ = tx.send(e.to_string());
        }
    });
    rx
}

async fn connect_proxy(port: u16, err: &mut oneshot::Receiver<String>) -> TcpStream {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)).await {
            return s;
        }
        if let Ok(e) = err.try_recv() {
            panic!("proxy serve() failed to start: {e}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if let Ok(e) = err.try_recv() {
        panic!("proxy serve() failed: {e}");
    }
    panic!("proxy never came up on port {port}");
}

/// Read until the response header block (`\r\n\r\n`) is seen, returning the bytes.
async fn read_head(sock: &mut TcpStream) -> String {
    let mut buf = [0u8; 4096];
    let mut seen = Vec::new();
    loop {
        let n = timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .expect("timed out reading response")
            .expect("read error");
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&seen).into_owned()
}

#[tokio::test]
async fn proxy_relays_websocket_upgrade_via_api() {
    let backend_port = spawn_echo_upgrade_backend().await;
    let proxy_port = free_port().await;

    let routes: RoutingTable = Arc::new(RwLock::new(HashMap::new()));
    let mut config = base_config(proxy_port);
    config.api_addr = Some(format!("127.0.0.1:{backend_port}"));
    let mut err = spawn_proxy(config, routes);
    let mut client = connect_proxy(proxy_port, &mut err).await;

    client
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: api.test.local\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();

    let head = read_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101, got: {head:?}"
    );
    let lower = head.to_ascii_lowercase();
    // The switch headers must survive sanitization (preserve_upgrade).
    assert!(
        lower.contains("upgrade: websocket"),
        "missing Upgrade: {head:?}"
    );
    assert!(
        lower.contains("connection: upgrade"),
        "missing Connection: {head:?}"
    );

    client.write_all(b"hello-ws").await.unwrap();
    let mut echo = [0u8; 8];
    timeout(Duration::from_secs(5), client.read_exact(&mut echo))
        .await
        .expect("timed out waiting for echo")
        .unwrap();
    assert_eq!(&echo, b"hello-ws");
}

#[tokio::test]
async fn proxy_relays_websocket_upgrade_via_tenant_path() {
    // The tenant path (forward_request) hard-coded `:80` before; backend_port makes it
    // testable against a local echo server.
    let backend_port = spawn_echo_upgrade_backend().await;
    let proxy_port = free_port().await;

    let domains = new_domain_map();
    domains.write().await.insert(
        "myapp".to_string(),
        DomainTarget {
            project_id: "myapp".to_string(),
            site: None,
        },
    );
    let routes = new_routing_table();
    routes
        .write()
        .await
        .insert("myapp".to_string(), "127.0.0.1".to_string());

    let mut config = base_config(proxy_port);
    config.domains = Some(domains);
    config.backend_port = backend_port;
    let mut err = spawn_proxy(config, routes.clone());
    let mut client = connect_proxy(proxy_port, &mut err).await;

    client
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: myapp.test.local\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();

    let head = read_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101 on tenant path, got: {head:?}"
    );

    client.write_all(b"tenant-ws").await.unwrap();
    let mut echo = [0u8; 9];
    timeout(Duration::from_secs(5), client.read_exact(&mut echo))
        .await
        .expect("timed out waiting for tenant echo")
        .unwrap();
    assert_eq!(&echo, b"tenant-ws");
}

#[tokio::test]
async fn non_upgrade_response_is_buffered_and_sanitized() {
    let backend_port = spawn_http_200_backend().await;
    let proxy_port = free_port().await;

    let domains = new_domain_map();
    domains.write().await.insert(
        "myapp".to_string(),
        DomainTarget {
            project_id: "myapp".to_string(),
            site: None,
        },
    );
    let routes = new_routing_table();
    routes
        .write()
        .await
        .insert("myapp".to_string(), "127.0.0.1".to_string());

    let mut config = base_config(proxy_port);
    config.domains = Some(domains);
    config.backend_port = backend_port;
    let mut err = spawn_proxy(config, routes);
    let mut client = connect_proxy(proxy_port, &mut err).await;

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: myapp.test.local\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // Read the whole response (head + body).
    let mut all = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        let n = timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("timed out reading buffered response")
            .unwrap();
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
        if all.windows(10).any(|w| w == b"hello-body") {
            break;
        }
    }
    let resp = String::from_utf8_lossy(&all);
    let lower = resp.to_ascii_lowercase();
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200, got: {resp:?}"
    );
    assert!(
        resp.contains("hello-body"),
        "body must pass through: {resp:?}"
    );
    // Sanitization: apex Domain stripped, HSTS stripped, hop-by-hop not forwarded.
    assert!(
        lower.contains("set-cookie"),
        "the cookie itself is kept: {resp:?}"
    );
    assert!(
        !lower.contains("domain=.test.local") && !lower.contains("domain=test.local"),
        "apex-scoped cookie Domain must be stripped: {resp:?}"
    );
    assert!(
        !lower.contains("strict-transport-security"),
        "tenant HSTS must be stripped: {resp:?}"
    );
}

#[tokio::test]
async fn unsolicited_backend_101_becomes_502() {
    // The echo backend 101s regardless; a NON-upgrade client request means there is
    // no client upgrade to splice to, so the proxy must answer 502 (not a spurious 101).
    let backend_port = spawn_echo_upgrade_backend().await;
    let proxy_port = free_port().await;

    let domains = new_domain_map();
    domains.write().await.insert(
        "myapp".to_string(),
        DomainTarget {
            project_id: "myapp".to_string(),
            site: None,
        },
    );
    let routes = new_routing_table();
    routes
        .write()
        .await
        .insert("myapp".to_string(), "127.0.0.1".to_string());

    let mut config = base_config(proxy_port);
    config.domains = Some(domains);
    config.backend_port = backend_port;
    let mut err = spawn_proxy(config, routes);
    let mut client = connect_proxy(proxy_port, &mut err).await;

    // Plain GET — no Connection/Upgrade headers.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: myapp.test.local\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let head = read_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 502"),
        "an unsolicited backend 101 must become 502, got: {head:?}"
    );
}
