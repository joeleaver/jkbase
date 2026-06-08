//! End-to-end check that the proxy relays an HTTP `Upgrade` (WebSocket-style)
//! handshake and then pipes raw bytes both ways, instead of buffering the
//! response. Exercises the public `serve()` path through the `api.{domain}`
//! route, which is the one tenant-independent backend whose address is
//! configurable (the project path hard-codes `:80`, so it can't bind in a test).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use jkbase_proxy::{ProxyConfig, RoutingTable, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::timeout;

/// A minimal backend that accepts one connection, answers `101 Switching
/// Protocols` once it has seen the request headers, then echoes every
/// subsequent byte — i.e. the smallest thing that looks like a WS server.
async fn spawn_echo_upgrade_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                // Read until end-of-headers.
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
                // Echo the upgraded byte stream.
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

/// Grab a free TCP port by binding to 0 and releasing it. Small race window,
/// fine for a test.
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn proxy_relays_websocket_upgrade() {
    let backend_port = spawn_echo_upgrade_backend().await;
    let proxy_port = free_port().await;

    let routes: RoutingTable = Arc::new(RwLock::new(HashMap::new()));
    let config = ProxyConfig {
        http_port: proxy_port,
        https_port: None,
        platform_domain: "test.local".to_string(),
        cert_manager: None,
        api_addr: Some(format!("127.0.0.1:{backend_port}")),
        domains: None,
        activity_tracker: None,
        wake_callback: None,
    };
    tokio::spawn(async move {
        let _ = serve(config, routes).await;
    });

    // Wait for the proxy to come up.
    let mut client = None;
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", proxy_port)).await {
            client = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = client.expect("proxy never came up");

    // `api.test.local` routes to the control-plane backend (our echo server).
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

    // Expect a 101 from the proxy (relayed from the backend), not a buffered 200.
    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("timed out waiting for 101")
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected a 101 upgrade, got: {head:?}"
    );
    // hyper performs the server-side switch on the 101 status alone, so a status
    // check is not enough: a regression that dropped the upgrade-header copy
    // would still 101 (and still echo) yet emit a handshake a real WebSocket
    // client rejects. Assert the relayed `Upgrade`/`Connection` headers survive.
    // (A real handshake also carries `Sec-WebSocket-Accept`; the echo backend
    // omits it, so we don't assert it here.)
    let head_lower = head.to_ascii_lowercase();
    assert!(
        head_lower.contains("upgrade: websocket"),
        "101 missing relayed `Upgrade` header, got: {head:?}"
    );
    assert!(
        head_lower.contains("connection: upgrade"),
        "101 missing relayed `Connection` header, got: {head:?}"
    );

    // The byte stream is now spliced end-to-end: what we send is echoed back.
    client.write_all(b"hello-ws").await.unwrap();
    let mut echo = [0u8; 8];
    timeout(Duration::from_secs(5), client.read_exact(&mut echo))
        .await
        .expect("timed out waiting for echo")
        .unwrap();
    assert_eq!(&echo, b"hello-ws");
}
