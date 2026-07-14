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
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Default idle-reap window for a spliced upgrade (WebSocket &c.) — torn down after
/// this long with no bytes in either direction. Active traffic (incl. WS keepalives)
/// resets it, so only abandoned/stalled sockets are reaped.
pub const DEFAULT_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// How often a busy managed-DB relay re-stamps the activity tracker. Throttled so a
/// chatty connection keeps its VM warm (§5 liveness) without taking the tracker's
/// write-lock on every 8 KiB read.
pub const ACTIVITY_STAMP_INTERVAL: Duration = Duration::from_secs(30);

/// Optional hooks for [`relay_bidirectional_hooked`]. The managed-DB reach plane and the
/// tenant WebSocket splice ([`spawn_upgrade_relay`]) both use `on_activity`; callers that
/// need neither pass [`RelayHooks::default`] via [`relay_bidirectional`].
#[derive(Default)]
pub struct RelayHooks {
    /// Force-close BOTH directions when this fires. A raw DB relay never EOFs on its
    /// own, so the edge passes its drain token to tear the relay down at the
    /// `DRAIN_GRACE` deadline ([R-drain]); the same token (per-relay) is how a key
    /// revocation drops a LIVE relay ([R5]).
    pub cancel: Option<CancellationToken>,
    /// Invoked (throttled to [`ACTIVITY_STAMP_INTERVAL`]) on byte flow in either
    /// direction. The reach plane stamps the `ActivityTracker` through this — a raw
    /// relay never passes through `proxy_request`, so without this a busy-but-quiet
    /// connection's VM would be hibernated out from under it (§5).
    pub on_activity: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// Enable TCP keepalive so a dead half-open peer is reaped by the OS even when the
/// app-level idle watchdog can't tell it's dead (a realtime subscription can be open
/// but byte-silent for minutes). [R9]: without it a wedged socket would pin the
/// per-project connection gauge and hold a VM warm forever — a standing cost-DoS.
pub fn set_relay_keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(20));
    socket2::SockRef::from(stream).set_tcp_keepalive(&ka)
}

/// Did the client ask to switch protocols (e.g. a WebSocket handshake)?
/// `Connection: Upgrade` + an `Upgrade:` token, per RFC 9110 §7.8. Full-token match
/// (not substring) so `Connection: upgrade-insecure-requests` does NOT count.
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
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
/// leaving the rest of the cookie intact.
///
/// Attributes are parsed the way a user-agent does (RFC 6265 §5.2): split each
/// `;`-part on its FIRST `=` and trim both sides — so `Domain =.JKBASE.APP.` (stray
/// space, leading/trailing dot, any case), which browsers still honour as the apex,
/// cannot slip an apex-scoped cookie past us. Only attributes are inspected; the
/// leading `name=value` pair is kept verbatim (a cookie literally named `domain` is
/// not the Domain attribute).
fn strip_apex_domain(set_cookie: &str, platform_domain: &str) -> String {
    let apex = platform_domain
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();
    let mut parts = set_cookie.split(';');
    let mut out = match parts.next() {
        Some(name_value) => name_value.to_string(),
        None => return set_cookie.to_string(),
    };
    for attr in parts {
        let is_apex_domain = match attr.split_once('=') {
            Some((name, value)) => {
                name.trim().eq_ignore_ascii_case("domain")
                    && value.trim().trim_matches('.').eq_ignore_ascii_case(&apex)
            }
            None => false, // valueless attribute (Secure, HttpOnly, …)
        };
        if is_apex_domain {
            continue;
        }
        out.push(';');
        out.push_str(attr);
    }
    out
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
    relay_bidirectional_hooked(client, backend, idle_timeout, RelayHooks::default()).await
}

/// [`relay_bidirectional`] plus the managed-DB reach-plane [`RelayHooks`]: a
/// force-close `cancel` token ([R-drain]/[R5]) and a throttled `on_activity` stamp (§5).
/// With [`RelayHooks::default`] it behaves identically to `relay_bidirectional`.
pub async fn relay_bidirectional_hooked<A, B>(
    client: A,
    backend: B,
    idle_timeout: Duration,
    hooks: RelayHooks,
) where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let RelayHooks {
        cancel,
        on_activity,
    } = hooks;

    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut backend_rd, mut backend_wr) = tokio::io::split(backend);
    let activity = Arc::new(tokio::sync::Notify::new());

    // Wrap `on_activity` in a shared throttle so a busy relay stamps at most once per
    // ACTIVITY_STAMP_INTERVAL (the first byte stamps immediately). Cloned into both pumps.
    let stamp: Option<Arc<dyn Fn() + Send + Sync>> = on_activity.map(|cb| {
        let last: Arc<std::sync::Mutex<Option<Instant>>> = Arc::new(std::sync::Mutex::new(None));
        let f: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let mut g = last.lock().unwrap();
            let due = g
                .map(|t| t.elapsed() >= ACTIVITY_STAMP_INTERVAL)
                .unwrap_or(true);
            if due {
                *g = Some(Instant::now());
                drop(g);
                cb();
            }
        });
        f
    });

    let to_backend = {
        let activity = activity.clone();
        let stamp = stamp.clone();
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
                        if let Some(s) = &stamp {
                            s();
                        }
                    }
                }
            }
            // Propagate the half-close so the other side sees EOF.
            let _ = backend_wr.shutdown().await;
        }
    };

    let to_client = {
        let activity = activity.clone();
        let stamp = stamp.clone();
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
                        if let Some(s) = &stamp {
                            s();
                        }
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

    // Force-close: fires on drain/revocation. `pending()` when no token is supplied so
    // this arm simply never wins (identical to the un-hooked relay).
    let cancelled = async {
        match cancel {
            Some(token) => token.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };

    tokio::select! {
        _ = async { tokio::join!(to_backend, to_client) } => {}
        _ = idle => info!("upgrade relay idle timeout; closing"),
        _ = cancelled => info!("relay force-closed (drain or revocation)"),
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
///
/// `on_activity` (throttled to [`ACTIVITY_STAMP_INTERVAL`]) is stamped on byte flow in
/// either direction. A spliced upgrade never re-enters the edge's `proxy_request`, so
/// without it a byte-active but request-quiet WebSocket's VM would be hibernated out from
/// under the live socket (wake-on-WS, §5). Callers with no tracker (the in-VM agent,
/// tests) pass `None` — behaviour is then identical to the un-hooked relay.
pub fn spawn_upgrade_relay(
    client_upgrade: Option<OnUpgrade>,
    backend_resp: &mut Response<Incoming>,
    idle_timeout: Duration,
    relay_permits: &Arc<Semaphore>,
    on_activity: Option<Arc<dyn Fn() + Send + Sync>>,
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
                relay_bidirectional_hooked(
                    TokioIo::new(client),
                    TokioIo::new(backend),
                    idle_timeout,
                    RelayHooks {
                        cancel: None,
                        on_activity,
                    },
                )
                .await;
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
            strip_apex_domain(
                "sid=abc; Domain=.jkbase.app; Path=/; HttpOnly",
                "jkbase.app"
            ),
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
    fn strip_apex_domain_resists_parsing_bypasses() {
        // Stray space before '=' (a UA still honours it as Domain) → still dropped.
        assert_eq!(
            strip_apex_domain("sid=x; Domain =jkbase.app", "jkbase.app"),
            "sid=x"
        );
        // Trailing-dot apex → dropped.
        assert_eq!(
            strip_apex_domain("sid=x; Domain=jkbase.app.", "jkbase.app"),
            "sid=x"
        );
        // Leading dot + trailing dot + odd case → dropped.
        assert_eq!(
            strip_apex_domain("sid=x; domain = .JKBASE.APP.", "jkbase.app"),
            "sid=x"
        );
        // A cookie literally NAMED "domain" with the apex value is NOT the Domain
        // attribute (it's the name=value pair) → kept verbatim.
        assert_eq!(
            strip_apex_domain("domain=jkbase.app; Path=/", "jkbase.app"),
            "domain=jkbase.app; Path=/"
        );
        // A non-apex Domain attribute is still kept even with whitespace.
        assert_eq!(
            strip_apex_domain("sid=x; Domain = a.jkbase.app", "jkbase.app"),
            "sid=x; Domain = a.jkbase.app"
        );
    }

    #[test]
    fn sanitize_strips_hop_by_hop_hsts_and_apex_cookie() {
        let mut h = headers(&[
            ("transfer-encoding", "chunked"),
            ("connection", "keep-alive"),
            (
                "strict-transport-security",
                "max-age=63072000; includeSubDomains",
            ),
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
        h.append(
            SET_COOKIE,
            HeaderValue::from_static("a=1; Domain=.jkbase.app"),
        );
        h.append(
            SET_COOKIE,
            HeaderValue::from_static("b=2; Domain=a.jkbase.app"),
        );
        sanitize_response_headers(&mut h, "jkbase.app", true, false);
        let got: Vec<&str> = h
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(got, vec!["a=1", "b=2; Domain=a.jkbase.app"]);
    }

    #[tokio::test]
    async fn hooked_relay_forwards_stamps_and_force_closes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Two in-memory pipes; the relay owns one end of each, the test drives the other.
        let (mut c_test, c_relay) = tokio::io::duplex(1024);
        let (mut b_test, b_relay) = tokio::io::duplex(1024);

        let hits = Arc::new(AtomicUsize::new(0));
        let on_hit = {
            let hits = hits.clone();
            Arc::new(move || {
                hits.fetch_add(1, Ordering::SeqCst);
            }) as Arc<dyn Fn() + Send + Sync>
        };
        let cancel = CancellationToken::new();

        let relay = tokio::spawn(relay_bidirectional_hooked(
            c_relay,
            b_relay,
            Duration::from_secs(600),
            RelayHooks {
                cancel: Some(cancel.clone()),
                on_activity: Some(on_hit),
            },
        ));

        // Byte-transparent forwarding client -> backend, and the first byte stamps.
        c_test.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b_test.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert!(
            hits.load(Ordering::SeqCst) >= 1,
            "activity must be stamped on byte flow"
        );

        // Neither side closed and the idle window is long — only the cancel token can
        // end it. [R-drain]/[R5]: a live relay must force-close promptly.
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("relay must force-close on cancel")
            .unwrap();
    }
}
