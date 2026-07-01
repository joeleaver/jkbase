//! `jkbase db proxy` — the managed-DB reach-plane **sidecar**.
//!
//! RhypeDB's TCP wire is plaintext with zero auth, and the official `@rhypedb/client`
//! (incl. its subscription dialers) is plaintext-only — it cannot reach a TLS+authed
//! endpoint. So this sidecar is the cloud-sql-proxy / Supabase-CLI-style bridge: it
//! listens on a local plaintext port, and for **every** local connection opens its own
//! TLS 1.3 tunnel to `<project>.db.<domain>:443`, negotiating the `jkbase-db` ALPN and
//! sending the reach-plane preamble (`{akid, secret, tls-exporter}`) before splicing the
//! raw byte stream. Subscriptions "just work" because they open their own local
//! connection, which gets its own tunnel (D1/§1-§2 of the ingress design).
//!
//! Security posture (client side of the seam):
//! - **TLS is verified against public roots and SNI-pinned** to the DB host — never an
//!   insecure/`rejectUnauthorized:false` mode. This runs on owner/corp machines where
//!   TLS-intercepting middleboxes live; skipping verification would hand the bearer
//!   preamble to a MITM ([R-sidecar]).
//! - The **`tls-exporter` channel binding** is computed from *this* session and mixed
//!   into the preamble, so a captured preamble can't be replayed on another TLS session
//!   ([R-replay]). The edge re-derives the same value and const-time compares.
//! - The credential is **owner-held** and prefers the env var so it isn't left in shell
//!   history. The sidecar never persists it.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use jkbase_common::db_preamble::{
    DB_ALPN, EXPORTER_LABEL, EXPORTER_LEN, encode_preamble,
};

#[derive(clap::Args)]
pub struct ProxyArgs {
    /// Local address to listen on — point your `@rhypedb/client` at this address.
    #[arg(long, default_value = "127.0.0.1:4200")]
    pub listen: String,
    /// Project name (inferred from jkbase.toml if not specified).
    #[arg(long)]
    pub project: Option<String>,
    /// Managed-DB access key id (from `jkbase db key create`).
    #[arg(long, env = "JKBASE_DB_ACCESS_KEY_ID")]
    pub access_key_id: String,
    /// Managed-DB secret. Prefer the env var so the secret isn't left in your shell
    /// history or process table.
    #[arg(long, env = "JKBASE_DB_SECRET")]
    pub secret: String,
    /// Override the DB host (used for BOTH the SNI and the cert-name pin). Defaults to
    /// `<project>.db.<domain>`, where `<domain>` is derived from `--api`. Set this for
    /// BYO custom-domain DB hosts.
    #[arg(long)]
    pub db_host: Option<String>,
    /// TCP port to connect to on the DB host (the shared `:443` ALPN-demux edge).
    #[arg(long, default_value_t = 443)]
    pub port: u16,
    /// Platform API URL — used only to derive the default DB host's domain.
    #[arg(long, default_value = "https://api.jkbase.app")]
    pub api: String,
}

/// Everything one accepted local connection needs to open its own upstream tunnel.
/// Cheap to clone-by-Arc; shared across all connections for the sidecar's lifetime.
struct Tunnel {
    connector: TlsConnector,
    /// TCP dial target host (equals `server_name` for the public path; may differ in
    /// tests that dial `127.0.0.1` while presenting the cert's SNI).
    connect_host: String,
    connect_port: u16,
    /// SNI + server-cert name pin.
    server_name: ServerName<'static>,
    akid: String,
    secret: String,
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let project_id = super::resolve_project_id(args.project.clone())?;
    let db_host = match args.db_host {
        Some(h) => h,
        None => {
            let domain = platform_domain(&args.api)
                .with_context(|| format!("could not derive DB host domain from --api {}", args.api))?;
            format!("{project_id}.db.{domain}")
        }
    };
    let listen: SocketAddr = args
        .listen
        .parse()
        .with_context(|| format!("invalid --listen address '{}'", args.listen))?;
    let server_name = ServerName::try_from(db_host.clone())
        .with_context(|| format!("invalid DB host '{db_host}' for TLS SNI"))?;

    let tunnel = Arc::new(Tunnel {
        connector: TlsConnector::from(build_client_config()),
        connect_host: db_host.clone(),
        connect_port: args.port,
        server_name,
        akid: args.access_key_id,
        secret: args.secret,
    });

    eprintln!(
        "jkbase db proxy: {listen}  ->  {db_host}:{}  (project {project_id})",
        args.port
    );
    eprintln!("  Point @rhypedb/client at {listen}. Ctrl-C to stop.");
    serve(listen, tunnel).await
}

/// The reusable client TLS config: public webpki roots + the `jkbase-db` ALPN. Pins the
/// `ring` provider EXPLICITLY (the workspace also pulls `aws-lc-rs`, so `builder()`'s
/// auto-detect is ambiguous and panics — `builder_with_provider` is deterministic).
fn build_client_config() -> Arc<tokio_rustls::rustls::ClientConfig> {
    let roots = tokio_rustls::rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    build_client_config_with_roots(roots)
}

fn build_client_config_with_roots(
    roots: tokio_rustls::rustls::RootCertStore,
) -> Arc<tokio_rustls::rustls::ClientConfig> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![DB_ALPN.to_vec()];
    Arc::new(cfg)
}

/// Accept loop. Each local connection is tunneled independently (so subscriptions, which
/// dial their own loopback connection, each get their own TLS+authed upstream). A single
/// connection failing never takes down the listener.
async fn serve(listen: SocketAddr, tunnel: Arc<Tunnel>) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind local listener on {listen}"))?;
    loop {
        let (local, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // Back off briefly so a persistent errno (e.g. EMFILE/ENFILE from fd
                // exhaustion under many open subscription tunnels) doesn't turn the loop
                // into a 100%-CPU busy-spin + stderr flood; it self-clears as fds free.
                eprintln!("jkbase db proxy: accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let tunnel = tunnel.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(local, &tunnel).await {
                eprintln!("jkbase db proxy: connection from {peer} closed: {e:#}");
            }
        });
    }
}

/// Bridge one local plaintext connection to its own upstream TLS tunnel.
async fn handle_conn(mut local: TcpStream, tunnel: &Tunnel) -> Result<()> {
    // Low latency for the interactive request/response wire; the edge sets keepalive on
    // its side of the relay, so a dead upstream is reaped there ([R9]).
    let _ = local.set_nodelay(true);
    let mut upstream = open_upstream(tunnel).await?;
    // Byte-transparent full-duplex splice; propagates half-close either way. The DB wire
    // has server-initiated pushes, so this must NEVER assume request/response.
    tokio::io::copy_bidirectional(&mut local, &mut upstream)
        .await
        .context("relay error")?;
    Ok(())
}

/// Open the TLS tunnel: connect → handshake → assert `jkbase-db` ALPN → derive this
/// session's `tls-exporter` → send the preamble. Returns the ready-to-splice stream.
async fn open_upstream(
    tunnel: &Tunnel,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect((tunnel.connect_host.as_str(), tunnel.connect_port))
        .await
        .with_context(|| {
            format!(
                "failed to connect to {}:{}",
                tunnel.connect_host, tunnel.connect_port
            )
        })?;
    let _ = tcp.set_nodelay(true);
    let mut tls = tunnel
        .connector
        .connect(tunnel.server_name.clone(), tcp)
        .await
        .context("TLS handshake to the DB edge failed (cert/SNI verification)")?;

    // Pull the negotiated ALPN + derive the exporter off the completed handshake.
    let exporter: [u8; EXPORTER_LEN] = {
        let (_io, conn) = tls.get_ref();
        if conn.alpn_protocol() != Some(DB_ALPN) {
            anyhow::bail!(
                "server did not negotiate the jkbase-db ALPN — is this a managed-DB host?"
            );
        }
        conn.export_keying_material([0u8; EXPORTER_LEN], EXPORTER_LABEL, None)
            .map_err(|e| anyhow::anyhow!("failed to derive tls-exporter binding: {e}"))?
    };

    // Encode + send the reach-plane preamble; the edge authenticates on it before it
    // ever touches the backend.
    let preamble = encode_preamble(&tunnel.akid, &tunnel.secret, &exporter)
        .context("access key id / secret is empty or too long for the preamble")?;
    tls.write_all(&preamble)
        .await
        .context("failed to send reach-plane preamble")?;
    tls.flush().await.context("failed to flush preamble")?;
    Ok(tls)
}

/// Derive the platform apex domain from the control-API URL:
/// `https://api.jkbase.app` -> `jkbase.app` (strip scheme, path, port, and a leading
/// `api.` label). The DB host is then `<project>.db.<domain>`.
fn platform_domain(api: &str) -> Result<String> {
    let no_scheme = api.split_once("://").map(|(_, r)| r).unwrap_or(api);
    let host = no_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(no_scheme);
    let host = host.split(':').next().unwrap_or(host);
    let domain = host.strip_prefix("api.").unwrap_or(host);
    if domain.is_empty() || !domain.contains('.') {
        anyhow::bail!("'{api}' does not look like a platform API URL");
    }
    Ok(domain.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_common::db_preamble::{Preamble, ct_eq, parse_preamble, PreambleParse};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    #[test]
    fn platform_domain_strips_scheme_api_prefix_and_port() {
        assert_eq!(platform_domain("https://api.jkbase.app").unwrap(), "jkbase.app");
        assert_eq!(platform_domain("http://api.jkbase.app:8080").unwrap(), "jkbase.app");
        assert_eq!(platform_domain("https://api.jkbase.app/v1/x").unwrap(), "jkbase.app");
        // Already bare (no api. label) is passed through.
        assert_eq!(platform_domain("https://jkbase.app").unwrap(), "jkbase.app");
        // A single-label / dotless host is rejected (would produce a bogus DB host).
        assert!(platform_domain("https://localhost").is_err());
    }

    /// What the fake edge captured while validating an incoming tunnel.
    struct Observed {
        preamble: Preamble,
        alpn_ok: bool,
        sni: Option<String>,
        exporter_matched: bool,
    }

    /// Full-stack proof: stand up a real local rustls server that behaves like the edge
    /// (advertise `jkbase-db`, read + validate the preamble, channel-bind check, then echo
    /// the tenant's bytes), run the sidecar in front of it, and drive a plaintext client
    /// through the local listener. Proves ALPN + SNI pin + preamble wire + the
    /// **client-side tls-exporter matches the server's** + full-duplex relay.
    #[tokio::test]
    async fn sidecar_tunnels_preamble_alpn_exporter_and_relays() {
        // --- self-signed cert for the DB host name ---
        let host = "sidecar.db.test";
        let ck = rcgen::generate_simple_self_signed(vec![host.to_string()]).unwrap();
        let cert_der = CertificateDer::from(ck.cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());

        // --- fake edge: rustls server that mimics the reach-plane auth + echoes ---
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut server_cfg = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
            .unwrap();
        server_cfg.alpn_protocols = vec![DB_ALPN.to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let edge = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_addr = edge.local_addr().unwrap();

        let want_akid = "JKBD0123456789ABCDEF".to_string();
        let want_secret = "jkbd_super-secret-value".to_string();
        let (obs_tx, obs_rx) = tokio::sync::oneshot::channel::<Observed>();

        let want_akid_srv = want_akid.clone();
        let want_secret_srv = want_secret.clone();
        tokio::spawn(async move {
            let (tcp, _) = edge.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();

            let (alpn_ok, sni, edge_exporter) = {
                let (_io, conn) = tls.get_ref();
                let alpn_ok = conn.alpn_protocol() == Some(DB_ALPN);
                let sni = conn.server_name().map(|s| s.to_string());
                let exp: [u8; EXPORTER_LEN] = conn
                    .export_keying_material([0u8; EXPORTER_LEN], EXPORTER_LABEL, None)
                    .unwrap();
                (alpn_ok, sni, exp)
            };

            // Read + parse the preamble off the wire (same accumulate the edge does).
            let mut buf = Vec::new();
            let mut chunk = [0u8; 256];
            let (preamble, leftover) = loop {
                if let PreambleParse::Complete { preamble, consumed } =
                    parse_preamble(&buf).unwrap()
                {
                    break (preamble, buf[consumed..].to_vec());
                }
                let n = tls.read(&mut chunk).await.unwrap();
                assert!(n > 0, "edge got EOF before a complete preamble");
                buf.extend_from_slice(&chunk[..n]);
            };

            let exporter_matched = ct_eq(&edge_exporter, &preamble.exporter);
            // Auth the way the edge does: exact akid + const-time secret compare.
            let authed = preamble.akid == want_akid_srv
                && ct_eq(preamble.secret.as_bytes(), want_secret_srv.as_bytes());
            assert!(authed, "fake edge rejected the sidecar's credential");

            obs_tx
                .send(Observed {
                    preamble: preamble.clone(),
                    alpn_ok,
                    sni,
                    exporter_matched,
                })
                .ok();

            // Behave like the spliced backend: echo any pipelined bytes, then anything
            // else the tenant sends (proves full-duplex relay through the sidecar).
            if !leftover.is_empty() {
                tls.write_all(&leftover).await.unwrap();
                tls.flush().await.unwrap();
            }
            let mut more = [0u8; 256];
            if let Ok(n) = tls.read(&mut more).await
                && n > 0
            {
                tls.write_all(&more[..n]).await.unwrap();
                tls.flush().await.unwrap();
            }
        });

        // --- sidecar in front of the fake edge, trusting the self-signed cert ---
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let tunnel = Arc::new(Tunnel {
            connector: TlsConnector::from(build_client_config_with_roots(roots)),
            connect_host: "127.0.0.1".to_string(), // dial the ephemeral test port...
            connect_port: edge_addr.port(),
            server_name: ServerName::try_from(host).unwrap(), // ...but present the DB SNI
            akid: want_akid.clone(),
            secret: want_secret.clone(),
        });

        let local_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        // Drive one accept through the real handler.
        tokio::spawn(async move {
            let (local, _) = local_listener.accept().await.unwrap();
            handle_conn(local, &tunnel).await.unwrap();
        });

        // --- act as the tenant app: connect plaintext, round-trip a message ---
        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"PING-over-the-wire").await.unwrap();
        app.flush().await.unwrap();
        let mut echo = vec![0u8; 18];
        app.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"PING-over-the-wire", "bytes did not relay round-trip");

        // --- assert what the edge observed ---
        let obs = obs_rx.await.unwrap();
        assert!(obs.alpn_ok, "server did not see the jkbase-db ALPN");
        assert_eq!(obs.sni.as_deref(), Some(host), "SNI pin not presented");
        assert_eq!(obs.preamble.akid, want_akid);
        assert_eq!(obs.preamble.secret, want_secret);
        assert!(
            obs.exporter_matched,
            "client-side tls-exporter did NOT match the server's — channel binding broken"
        );
    }
}
