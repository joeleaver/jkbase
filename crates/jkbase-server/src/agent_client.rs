//! Host → guest-agent calls over the runtime bridge: liveness and protocol probes, the post-restore
//! sync and clock re-sync, and waiting for a freshly booted agent to answer.

use anyhow::Result;
use std::time::Duration;
use tracing::info;

/// Application-level liveness probe. Returns true only if the agent answers HTTP
/// within the budget. A wedged agent (kernel up, userspace stuck) completes the
/// TCP handshake but never answers, so a bare TCP connect is NOT sufficient — we
/// must hit `/_jkbase/health` and bound it with a timeout.
pub(crate) async fn agent_alive(ip: &str) -> bool {
    let probe = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80"))
            .await
            .ok()?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri(format!("http://{ip}:80/_jkbase/health"))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        Some(resp.status().is_success())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), probe).await,
        Ok(Some(true))
    )
}

/// The agent's reported protocol version from the `X-Jkbase-Agent-Proto` header on
/// `/_jkbase/health`. `None` if unreachable OR the header is absent/unparseable — a
/// pre-versioning agent (every survivor during this rollout), which the caller treats as
/// compatible. See [`jkbase_common::AGENT_PROTOCOL_VERSION`].
pub(crate) async fn agent_protocol_version(ip: &str) -> Option<u32> {
    let probe = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80"))
            .await
            .ok()?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri(format!("http://{ip}:80/_jkbase/health"))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        resp.headers()
            .get(jkbase_common::AGENT_PROTOCOL_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
    };
    tokio::time::timeout(Duration::from_secs(2), probe)
        .await
        .ok()
        .flatten()
}

pub(crate) async fn sync_agent(ip: &str) -> Result<()> {
    if let Ok(stream) = tokio::net::TcpStream::connect(format!("{ip}:80")).await {
        let io = hyper_util::rt::TokioIo::new(stream);
        if let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(io).await {
            tokio::spawn(conn);
            let req = hyper::Request::builder()
                .uri(format!("http://{ip}:80/_jkbase/sync"))
                .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
            let _ = sender.send_request(req).await;
        }
    }
    Ok(())
}

/// Ask the agent to step the guest wall clock to its PTP reference now (the agent
/// runs `chronyc makestep`). Used after wake/restore so a restored snapshot — whose
/// clock is frozen at snapshot time — corrects instantly instead of on chrony's
/// next poll. Best-effort and bounded: a clock nudge must never block a wake.
pub(crate) async fn resync_clock_agent(ip: &str) {
    let send = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80"))
            .await
            .ok()?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{ip}:80/_jkbase/resync-clock"))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let _ = sender.send_request(req).await;
        Some(())
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), send).await;
}

pub(crate) async fn wait_for_agent(ip: &str) -> Result<()> {
    for i in 0..50 {
        if let Ok(stream) = tokio::net::TcpStream::connect(format!("{ip}:80")).await {
            drop(stream);
            info!(ip, attempts = i + 1, "agent is ready");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!("agent at {ip} did not become ready within 10 seconds");
}
