//! Shared HTTP/WebSocket **upgrade relay** and **untrusted-backend response-header
//! sanitization** for the jkbase edge proxy (`jkbase-proxy`) and the in-VM agent
//! (`jkbase-agent`).
//!
//! Both forward responses from untrusted backends and splice
//! `101 Switching Protocols` upgrades, so the security-relevant helpers live here
//! ONCE — a verbatim copy in each crate drifts, and these are exactly the helpers a
//! drift would silently weaken (a sanitization that lapses on one path is a
//! cross-tenant hole).

use hyper::Response;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue, SET_COOKIE};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{error, info};

/// Default idle-reap window for a spliced upgrade (WebSocket &c.) — torn down after
/// this long with no bytes in either direction. Active traffic (incl. WS keepalives)
/// resets it, so only abandoned/stalled sockets are reaped.
pub const DEFAULT_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Did the client ask to switch protocols (e.g. a WebSocket handshake)?
/// `Connection: Upgrade` + an `Upgrade:` token, per RFC 9110 §7.8. Full-token match
/// (not substring) so `Connection: upgrade-insecure-requests` does NOT count.
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
        .unwrap_or(false);
    connection_upgrade && headers.contains_key(hyper::header::UPGRADE)
}

/// Hop-by-hop headers (RFC 9110 §7.6.1) a proxy must not forward end-to-end.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Sanitize an UNTRUSTED backend's response headers before they reach the client.
///
/// - **Hop-by-hop** headers are stripped: the proxy re-frames the response, so
///   forwarding the backend's `Transfer-Encoding`/`Connection` verbatim is both
///   wrong (double framing) and a knob a tenant could use to meddle with the shared
///   edge connection. On a `101` relay, `connection` + `upgrade` MUST survive (they
///   carry the protocol switch) — pass `preserve_upgrade = true` there.
/// - **`Set-Cookie` with `Domain={platform_domain}`** (the apex, with or without a
///   leading dot) has that attribute dropped, making the cookie host-only. Otherwise
///   a tenant at `a.{domain}` could set a cookie the browser ALSO sends to
///   `b.{domain}` — cross-tenant cookie injection. Cookies scoped to the tenant's own
///   host, or to a custom domain it owns, are left untouched.
/// - **HSTS** is stripped when `strip_hsts`: the platform owns transport-security
///   policy for `*.{domain}`, a tenant must not dictate it. Infra hosts pass `false`.
pub fn sanitize_response_headers(
    headers: &mut HeaderMap,
    platform_domain: &str,
    strip_hsts: bool,
    preserve_upgrade: bool,
) {
    for name in HOP_BY_HOP {
        if preserve_upgrade && (*name == "connection" || *name == "upgrade") {
            continue;
        }
        headers.remove(*name);
    }
    if strip_hsts {
        headers.remove("strict-transport-security");
    }
    sanitize_set_cookies(headers, platform_domain);
}

/// Drop an apex-scoping `Domain=` from every `Set-Cookie` (a response can carry many).
fn sanitize_set_cookies(headers: &mut HeaderMap, platform_domain: &str) {
    if !headers.contains_key(SET_COOKIE) {
        return;
    }
    let cookies: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    headers.remove(SET_COOKIE);
    for c in cookies {
        match c.to_str() {
            Ok(s) => {
                let cleaned = strip_apex_domain(s, platform_domain);
                match HeaderValue::from_str(&cleaned) {
                    // We only ever removed a `Domain=` token, so re-parse can't fail;
                    // fall back to the original if it somehow does.
                    Ok(hv) => headers.append(SET_COOKIE, hv),
                    Err(_) => headers.append(SET_COOKIE, c),
                };
            }
            // A non-UTF-8 Set-Cookie can't carry a Domain we'd recognize anyway; pass
            // it through rather than dropping a (possibly load-bearing) cookie.
            Err(_) => {
                headers.append(SET_COOKIE, c);
            }
        }
    }
}

/// Remove a `Domain=` attribute whose host equals `platform_domain` (the apex),
/// leaving the rest of the cookie intact. Case-insensitive on the attribute name and
/// the host; tolerant of a leading `.` on the value.
fn strip_apex_domain(set_cookie: &str, platform_domain: &str) -> String {
    let apex = platform_domain.trim().to_ascii_lowercase();
    set_cookie
        .split(';')
        .filter(|attr| {
            let a = attr.trim();
            match a.get(..7) {
                Some(prefix) if prefix.eq_ignore_ascii_case("domain=") => {
                    let val = a[7..].trim().trim_start_matches('.').to_ascii_lowercase();
                    // Keep everything except a Domain scoped to the platform apex.
                    val != apex
                }
                _ => true,
            }
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Splice two upgraded byte streams together once both ends complete, reaping the
/// relay if it goes idle for `idle_timeout`. Replaces a bare `copy_bidirectional`,
/// which only returns once *both* directions close and so never reaps a wedged
/// half-open connection on the shared edge.
pub async fn relay_bidirectional<A, B>(client: A, backend: B, idle_timeout: Duration)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut backend_rd, mut backend_wr) = tokio::io::split(backend);
    let activity = Arc::new(tokio::sync::Notify::new());

    let to_backend = {
        let activity = activity.clone();
        async move {
            let mut buf = [0u8; 8192];
            loop {
                match client_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if backend_wr.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        activity.notify_one();
                    }
                }
            }
            // Propagate the half-close so the other side sees EOF.
            let _ = backend_wr.shutdown().await;
        }
    };

    let to_client = {
        let activity = activity.clone();
        async move {
            let mut buf = [0u8; 8192];
            loop {
                match backend_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if client_wr.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        activity.notify_one();
                    }
                }
            }
            let _ = client_wr.shutdown().await;
        }
    };

    // The idle watchdog: resets whenever either pump signals traffic, and fires only
    // after a full idle window with no activity.
    let idle = async {
        loop {
            tokio::select! {
                _ = activity.notified() => {}
                _ = tokio::time::sleep(idle_timeout) => break,
            }
        }
    };

    tokio::select! {
        _ = async { tokio::join!(to_backend, to_client) } => {}
        _ = idle => info!("upgrade relay idle timeout; closing"),
    }
}

/// Outcome of attempting to relay a backend's `101 Switching Protocols`.
pub enum UpgradeOutcome {
    /// Spliced: a relay task was spawned (holding a permit for its lifetime). The
    /// caller returns the `101` to the client.
    Relayed,
    /// The backend sent `101` with no client upgrade request to splice to — the
    /// caller should reply `502` rather than forward a spurious switch.
    Unsolicited,
    /// The in-flight-upgrade cap is full — the caller should reply `503` (and NOT
    /// forward the `101`, since no relay backs it).
    CapReached,
}

/// Splice an upgraded client↔backend once both [`OnUpgrade`]s resolve, reaping the
/// relay after `idle_timeout` of no traffic. Concurrency is bounded by
/// `relay_permits` — a permit is acquired up front and held for the relay's whole
/// lifetime, so the *shared* edge can't be pinned by unbounded spliced upgrades.
///
/// The caller builds the `101` response itself (its body type differs) and only on
/// [`UpgradeOutcome::Relayed`]; on the other arms it returns the mapped error status.
pub fn spawn_upgrade_relay(
    client_upgrade: Option<OnUpgrade>,
    backend_resp: &mut Response<Incoming>,
    idle_timeout: Duration,
    relay_permits: &Arc<Semaphore>,
) -> UpgradeOutcome {
    let Some(client_upgrade) = client_upgrade else {
        return UpgradeOutcome::Unsolicited;
    };
    let Ok(permit) = relay_permits.clone().try_acquire_owned() else {
        return UpgradeOutcome::CapReached;
    };
    let backend_upgrade = hyper::upgrade::on(backend_resp);
    tokio::spawn(async move {
        let _permit = permit; // released when the relay ends
        match tokio::join!(client_upgrade, backend_upgrade) {
            (Ok(client), Ok(backend)) => {
                relay_bidirectional(TokioIo::new(client), TokioIo::new(backend), idle_timeout).await;
            }
            (c, b) => error!(
                client_err = ?c.err(),
                backend_err = ?b.err(),
                "protocol upgrade failed; dropping connection"
            ),
        }
    });
    UpgradeOutcome::Relayed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn detects_and_rejects_upgrades() {
        assert!(is_upgrade_request(&headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket")
        ])));
        assert!(is_upgrade_request(&headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "WebSocket")
        ])));
        // Connection token present but no Upgrade header.
        assert!(!is_upgrade_request(&headers(&[("connection", "Upgrade")])));
        // Full-token match, not substring.
        assert!(!is_upgrade_request(&headers(&[
            ("connection", "upgrade-insecure-requests"),
            ("upgrade", "websocket")
        ])));
    }

    #[test]
    fn strips_apex_domain_only() {
        // Apex Domain (with leading dot) → dropped, cookie becomes host-only.
        assert_eq!(
            strip_apex_domain("sid=abc; Domain=.jkbase.app; Path=/; HttpOnly", "jkbase.app"),
            "sid=abc; Path=/; HttpOnly"
        );
        // Apex Domain, no dot, mixed case → dropped.
        assert_eq!(
            strip_apex_domain("sid=abc; domain=JKBASE.APP", "jkbase.app"),
            "sid=abc"
        );
        // Tenant's own subdomain Domain → kept.
        assert_eq!(
            strip_apex_domain("sid=abc; Domain=a.jkbase.app", "jkbase.app"),
            "sid=abc; Domain=a.jkbase.app"
        );
        // Custom-domain tenant's own Domain → kept.
        assert_eq!(
            strip_apex_domain("sid=abc; Domain=example.com; Secure", "jkbase.app"),
            "sid=abc; Domain=example.com; Secure"
        );
        // No Domain attribute → unchanged.
        assert_eq!(
            strip_apex_domain("sid=abc; Path=/", "jkbase.app"),
            "sid=abc; Path=/"
        );
    }

    #[test]
    fn sanitize_strips_hop_by_hop_hsts_and_apex_cookie() {
        let mut h = headers(&[
            ("transfer-encoding", "chunked"),
            ("connection", "keep-alive"),
            ("strict-transport-security", "max-age=63072000; includeSubDomains"),
            ("set-cookie", "sid=abc; Domain=.jkbase.app; Path=/"),
            ("content-type", "text/html"),
        ]);
        sanitize_response_headers(&mut h, "jkbase.app", true, false);
        assert!(!h.contains_key("transfer-encoding"));
        assert!(!h.contains_key("connection"));
        assert!(!h.contains_key("strict-transport-security"));
        assert_eq!(h.get("content-type").unwrap(), "text/html");
        assert_eq!(h.get(SET_COOKIE).unwrap(), "sid=abc; Path=/");
    }

    #[test]
    fn sanitize_preserves_upgrade_headers_on_101() {
        let mut h = headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("transfer-encoding", "chunked"),
        ]);
        sanitize_response_headers(&mut h, "jkbase.app", true, true);
        // The switch headers survive; other hop-by-hop is still stripped.
        assert_eq!(h.get("connection").unwrap(), "Upgrade");
        assert_eq!(h.get("upgrade").unwrap(), "websocket");
        assert!(!h.contains_key("transfer-encoding"));
    }

    #[test]
    fn sanitize_keeps_infra_hsts_when_not_stripping() {
        let mut h = headers(&[("strict-transport-security", "max-age=31536000")]);
        sanitize_response_headers(&mut h, "jkbase.app", false, false);
        assert!(h.contains_key("strict-transport-security"));
    }

    #[test]
    fn sanitize_handles_multiple_set_cookies() {
        let mut h = HeaderMap::new();
        h.append(SET_COOKIE, HeaderValue::from_static("a=1; Domain=.jkbase.app"));
        h.append(SET_COOKIE, HeaderValue::from_static("b=2; Domain=a.jkbase.app"));
        sanitize_response_headers(&mut h, "jkbase.app", true, false);
        let got: Vec<&str> = h.get_all(SET_COOKIE).iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(got, vec!["a=1", "b=2; Domain=a.jkbase.app"]);
    }
}
