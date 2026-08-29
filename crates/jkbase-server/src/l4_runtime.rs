//! L4 UDP runtime seam — the reconcile loop that MATERIALIZES `PortAllocation` records into live
//! edge sockets + the datagram pump (`jkbase_proxy::l4_ingress::L4Ingress`), plus the `JKL4`
//! host-firewall inbound-open. The control plane RECORDS allocations at deploy/teardown; this loop
//! is their runtime OWNER (design §3(b) "runtime socket-reconcile loop" / §8 item 7).
//!
//! Single-host is the only production config today, so this is a periodic reconcile: every tick it
//! diffs THIS host's UDP `PortAllocation`s (`host_id`-filtered — an HA peer's allocations are
//! ignored, [R3]) against the live socket set, binding new ports (edge bind-probe already ran at
//! `allocate_port`, so a fresh `bind()` normally succeeds; `EADDRINUSE` is surfaced + retried) and
//! tearing down removed ones. Port stickiness means a redeploy keeps the same `external_port`, so
//! the edge socket persists across redeploys (no rebind, no ingress gap); only a genuinely-new or
//! genuinely-removed allocation moves a socket. Host-process restart re-binds by a plain in-process
//! bind (NOT socket-activation — D8; the L4 port set is dynamic). A freed port's quarantine
//! (control plane) covers the reuse window that the ≤tick teardown lag opens.

use crate::vm_identity;
use jkbase_control::store::{PortAllocation, Store};
use jkbase_proxy::l4_ingress::{L4Ingress, L4PortSpec, ResolveVmIp};
use jkbase_proxy::l4_plane::L4Plane;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// How often to reconcile allocations → sockets. Bind-new/drop-old is idempotent, so a coarse tick
/// is fine; the freed-port quarantine covers the ≤tick window before a torn-down port's socket
/// closes (a stale datagram in that window hits a project with no VM → wake fails → drop).
const RECONCILE_TICK: Duration = Duration::from_secs(5);

/// Live L4 ports, shared with `main` so an upgrade shutdown can snapshot their flow identities.
pub type L4PortRegistry = Arc<tokio::sync::Mutex<HashMap<(String, String), Arc<L4Ingress>>>>;

/// Snapshot every live port's flow identities into a hand-off for the upgrade successor.
pub async fn snapshot_handover(registry: &L4PortRegistry, data_dir: &Path) {
    let ports: Vec<_> = {
        let reg = registry.lock().await;
        reg.iter()
            .map(|((proj, name), ing)| (proj.clone(), name.clone(), ing.export_identities()))
            .filter(|(_, _, v)| !v.is_empty())
            .collect()
    };
    if ports.is_empty() {
        return;
    }
    let flows: usize = ports.iter().map(|(_, _, v)| v.len()).sum();
    info!(ports = ports.len(), flows, "l4 handover: snapshotting flow identities for the successor");
    handover::write(
        data_dir,
        &handover::Handover {
            written_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            ports,
        },
    );
}

/// Flow identities handed from one host process to its upgrade successor.
///
/// Written on an UPGRADE shutdown (never a real one — a real shutdown hibernates the VMs, so there
/// is no surviving agent to resume against) and consumed exactly once at startup. A plain file
/// beside `.upgrading` rather than control-plane state: it is host-local, worthless after seconds,
/// and must not outlive the process pair that shares it.
pub mod handover {
    use super::*;
    use jkbase_proxy::l4_ingress::FlowIdentity;
    use std::net::SocketAddr;

    /// Discard a hand-off older than this. Matches the identity memo's own TTL — an identity the
    /// memo would have dropped is not one to resurrect, and an upgrade restart takes seconds, so a
    /// file this old means the successor did not come up promptly and the agent's own flow entries
    /// may be gone too.
    const MAX_AGE: Duration = Duration::from_secs(45);

    /// One port's worth of hand-off: `(project_id, port_name, [(client 5-tuple, identity)])`.
    pub type PortIdentities = (String, String, Vec<(SocketAddr, FlowIdentity)>);

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Handover {
        /// UNIX seconds at write, for the staleness check.
        pub written_at: u64,
        /// `(project_id, port_name) -> [(client 5-tuple, identity)]`.
        pub ports: Vec<PortIdentities>,
    }

    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("l4-identity-handover.json")
    }

    /// Write the hand-off. Best-effort by design: a failure costs tuple continuity across this one
    /// upgrade, never correctness, and must never delay or fail the shutdown.
    pub fn write(data_dir: &Path, h: &Handover) {
        let p = path(data_dir);
        let Ok(json) = serde_json::to_vec(h) else {
            return;
        };
        // `data_dir` is owned by the DEPLOY USER (`provision.sh` chowns /var/jkbase), while we run
        // as root — so this path is attacker-influenceable and must be created, not written into.
        // Unlink first (which removes a planted symlink), then `create_new` so we fail rather than
        // follow anything that reappears in between. Mode 0600 at creation, never after: these are
        // the client addresses of every live UDP session.
        let _ = std::fs::remove_file(&p);
        let opened = {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(&p)
        };
        let res = opened.and_then(|mut f| std::io::Write::write_all(&mut f, &json));
        if let Err(e) = res {
            warn!(error = %e, path = %p.display(), "l4 handover: write failed (sessions will churn)");
            let _ = std::fs::remove_file(&p);
        }
    }

    /// Read and CONSUME the hand-off: the file is removed whether or not it was usable, so a stale
    /// one can never be applied twice or linger into an unrelated restart.
    pub fn take(data_dir: &Path) -> Vec<PortIdentities> {
        let p = path(data_dir);
        // Open BEFORE the ownership check and stat the handle, so the thing we validate is the
        // thing we read — a path re-pointed between check and open would otherwise slip through.
        let Ok(f) = std::fs::File::open(&p) else {
            return Vec::new();
        };
        // Only a file ROOT wrote is ours. `data_dir` is deploy-user-owned, so anyone with write
        // access there can plant one — and its contents choose which `(flow_id, epoch, out_nonce)`
        // a given client resumes, i.e. which agent socket a chosen `src` attaches to. Chowning to
        // root needs root, so this check is what makes the file trustworthy rather than merely
        // present. A rejected file is still removed below so it cannot wedge every future upgrade.
        #[cfg(unix)]
        let ok = {
            use std::os::unix::fs::MetadataExt;
            match f.metadata() {
                Ok(m) => {
                    let good = m.uid() == 0 && m.mode() & 0o177 == 0;
                    if !good {
                        warn!(
                            uid = m.uid(), mode = format!("{:o}", m.mode() & 0o777),
                            "l4 handover: not root-owned 0600 — ignoring (planted?)"
                        );
                    }
                    good
                }
                Err(_) => false,
            }
        };
        #[cfg(not(unix))]
        let ok = true;
        let bytes = if ok {
            std::io::read_to_string(f).map(String::into_bytes).unwrap_or_default()
        } else {
            Vec::new()
        };
        drop(std::fs::remove_file(&p));
        if bytes.is_empty() {
            return Vec::new();
        }
        let Ok(h) = serde_json::from_slice::<Handover>(&bytes) else {
            warn!("l4 handover: unparseable, ignoring");
            return Vec::new();
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let age = now.saturating_sub(h.written_at);
        if age > MAX_AGE.as_secs() {
            warn!(age_secs = age, "l4 handover: stale, ignoring");
            return Vec::new();
        }
        let flows: usize = h.ports.iter().map(|(_, _, v)| v.len()).sum();
        info!(ports = h.ports.len(), flows, age_secs = age, "l4 handover: resuming flow identities");
        h.ports
    }
}

/// One live L4 port this host is currently serving.
struct LivePort {
    cancel: CancellationToken,
    external_port: u16,
    proto: String,
    /// Kept so an admin limits change can be pushed to an ALREADY-BOUND port. `resolve_spec` runs
    /// only for a port that is not yet live, and `allocate_port` is sticky (a redeploy updates the
    /// allocation row in place rather than removing it), so without this a port's limits would be
    /// frozen from first bind until teardown or a host restart.
    ingress: Arc<L4Ingress>,
}

/// Reconcile loop entry — spawned once at startup beside the DB gateway. Owns the L4 socket
/// lifecycle for `host_id`'s UDP allocations. `plane` is shared with the idle + metering loops
/// (they read its gauges/counters); `resolve_vm_ip` is built here over the routing table for the
/// pump's cross-port coalesced-wait path.
pub async fn serve(
    store: Store,
    routing: jkbase_proxy::RoutingTable,
    plane: Arc<L4Plane>,
    host_id: String,
    data_dir: PathBuf,
    // `registry` is shared with `main` so an upgrade shutdown can snapshot live flow identities.
    registry: L4PortRegistry,
) {
    // Consume the previous process's hand-off ONCE, before any port binds.
    let mut seeds: HashMap<(String, String), Vec<(std::net::SocketAddr, jkbase_proxy::l4_ingress::FlowIdentity)>> =
        handover::take(&data_dir)
            .into_iter()
            .map(|(p, n, v)| ((p, n), v))
            .collect();
    // The current backend IP for an already-woken project (the pump's `BootWait` path polls this
    // while a sibling port's boot is in flight). L4 targets the tenant's APP VM, which is in the
    // routing table once running; `None` until then.
    let resolve_vm_ip: ResolveVmIp = {
        let routing = routing.clone();
        Arc::new(move |project_id: String| {
            let routing = routing.clone();
            Box::pin(async move { routing.read().await.get(&project_id).cloned() })
        })
    };

    let fw = L4Firewall::new();
    // Best-effort: create + hook the JKL4 chain once. A failure here (iptables absent on a dev box)
    // is non-fatal — the per-port ACCEPT is a belt-and-suspenders open over the host's inbound
    // default-deny (provisioned out-of-band); a bind that can't be reached fails CLOSED, never open.
    fw.ensure_chain().await;

    let mut live: HashMap<(String, String), LivePort> = HashMap::new();

    loop {
        let allocs: Vec<PortAllocation> = match store.list_port_allocations() {
            Ok(a) => a
                .into_iter()
                // This host's UDP allocations only (empty host_id = single-node, matches all).
                .filter(|a| a.proto == "udp" && (a.host_id.is_empty() || a.host_id == host_id))
                .collect(),
            Err(e) => {
                warn!(error = %e, "l4 reconcile: list_port_allocations failed");
                tokio::time::sleep(RECONCILE_TICK).await;
                continue;
            }
        };

        // --- Bind newly-appeared allocations. ---
        for alloc in &allocs {
            let key = (alloc.project_id.clone(), alloc.name.clone());
            if live.contains_key(&key) {
                continue;
            }
            let Some(spec) = resolve_spec(&store, &data_dir, &plane, alloc) else {
                // No transit secret yet / unresolved — skip THIS tick, retry next (fail-closed:
                // an empty HMAC key is forgeable, so we never bind without one).
                debug!(
                    project = %alloc.project_id, l4_port = %alloc.name,
                    "l4 reconcile: spec unresolved (no transit secret?); will retry"
                );
                continue;
            };
            let external_port = spec.external_port;
            let cancel = CancellationToken::new();
            match L4Ingress::bind(spec, plane.clone(), resolve_vm_ip.clone(), cancel.clone()).await
            {
                Ok(ingress) => {
                    // Open the host firewall for this port BEFORE we start pumping (idempotent).
                    fw.allow(external_port).await;
                    let handle = ingress.clone();
                    // Seed BEFORE the pump starts: a datagram processed ahead of the memo would
                    // mint a fresh id and move the very tuple this exists to keep still.
                    // The agent is still running and still holds its loopback sockets, so a
                    // resumed `(flow_id, epoch)` lands on `Decision::Forward` and the app sees
                    // nothing at all.
                    if let Some(entries) = seeds.remove(&key)
                        && !entries.is_empty()
                    {
                        info!(
                            project = %key.0, port = %key.1, flows = entries.len(),
                            "l4 handover: seeding resumed flow identities"
                        );
                        handle.seed_identities(entries, std::time::Instant::now());
                    }
                    registry.lock().await.insert(key.clone(), handle.clone());
                    tokio::spawn(ingress.run());
                    live.insert(
                        key,
                        LivePort {
                            cancel,
                            external_port,
                            proto: alloc.proto.clone(),
                            ingress: handle,
                        },
                    );
                    info!(
                        project = %alloc.project_id, l4_port = %alloc.name, external_port,
                        "l4 reconcile: edge socket bound + pumping"
                    );
                }
                Err(e) => {
                    // Fail-closed + surfaced: EADDRINUSE (contended port) or an empty secret. Not
                    // inserted into `live`, so the next tick retries — a transient contention clears
                    // itself; a persistent one is a loud, recurring error (never a silent no-ingress).
                    error!(
                        project = %alloc.project_id, l4_port = %alloc.name, external_port,
                        error = %e, "l4 reconcile: edge bind failed (will retry)"
                    );
                }
            }
        }

        // --- Push egress-limit changes to ALREADY-LIVE ports. ---
        // `resolve_spec` above runs only for a port that is not yet live, and `allocate_port` is
        // sticky, so without this an admin grant (or, worse, a mid-incident TIGHTENING) would sit
        // in the store with no effect on the running socket until teardown or a host restart —
        // the API would return 200 OK and change nothing. Cold path: one control-store read per
        // live port per tick, never on the datagram path.
        for (key, lp) in live.iter() {
            let want = resolve_egress_limits(&store, &plane, &key.0);
            if lp.ingress.update_egress_limits(want) {
                info!(
                    project = %key.0, l4_port = %key.1,
                    per_source_bps = want.per_source_bps,
                    per_source_burst = want.per_source_burst,
                    per_project_bps = want.per_project_bps,
                    "l4 reconcile: egress limits updated on a live port"
                );
            }
        }

        // --- Tear down allocations that disappeared (teardown / reconcile-removed). ---
        let allocated: std::collections::HashSet<(String, String)> = allocs
            .iter()
            .map(|a| (a.project_id.clone(), a.name.clone()))
            .collect();
        {
            let mut reg = registry.lock().await;
            reg.retain(|k, _| live.contains_key(k));
        }
        live.retain(|key, lp| {
            if allocated.contains(key) {
                return true;
            }
            // Gone: cancel the pump (closes the edge + guest sockets) and close the firewall. The
            // control plane already quarantined the port, so a stale client can't be admitted into a
            // reused port's new owner in the meantime [threat M1].
            lp.cancel.cancel();
            let fw = fw.clone();
            let port = lp.external_port;
            let is_udp = lp.proto == "udp";
            tokio::spawn(async move {
                if is_udp {
                    fw.clear(port).await;
                }
            });
            info!(project = %key.0, l4_port = %key.1, external_port = port, "l4 reconcile: port torn down");
            false
        });

        tokio::time::sleep(RECONCILE_TICK).await;
    }
}

/// The egress limits in force for `project_id`: an admin override layered over the platform
/// defaults FIELD BY FIELD. An override that omits a field leaves the default in place rather than
/// zeroing it — a zero-rate bucket admits nothing, and that failure would present as total packet
/// loss rather than as the config mistake it is.
///
/// Cheap and pure, so the reconcile loop can call it every tick for live ports (see `serve`) as
/// well as once at bind. It reads the control store, so it must stay on the reconcile path and
/// never move to the per-datagram path.
fn resolve_egress_limits(
    store: &Store,
    plane: &L4Plane,
    project_id: &str,
) -> jkbase_proxy::l4_plane::L4PortEgressLimits {
    let mut egress = plane.default_port_egress_limits();
    if let Ok(Some(o)) = store.get_l4_egress_limits(project_id) {
        if let Some(v) = o.per_source_bps {
            egress.per_source_bps = v;
        }
        if let Some(v) = o.per_source_burst {
            egress.per_source_burst = v;
        }
        if let Some(v) = o.per_project_bps {
            egress.per_project_bps = v;
        }
    }
    egress
}

/// Resolve a `PortAllocation` (host-recorded ports) into the full `L4PortSpec` the pump needs:
/// the base-project throttle key, the owning tenant (fair-share key), the per-port tunables (read
/// from the tenant's baked `_l4_ports.json` sidecar — completeness M1), and the per-VM transit
/// secret (from the store; `None`/empty ⇒ `None` ⇒ skip, fail-closed).
fn resolve_spec(
    store: &Store,
    data_dir: &std::path::Path,
    plane: &L4Plane,
    alloc: &PortAllocation,
) -> Option<L4PortSpec> {
    let transit_secret = store
        .get_l4_transit_secret(&alloc.project_id)
        .ok()
        .flatten()?;
    if transit_secret.is_empty() {
        return None;
    }
    let tenant_id = store
        .get_project(&alloc.project_id)
        .ok()
        .flatten()
        .and_then(|p| p.tenant_id);

    // Per-port tunables from the sidecar; default (60s idle; amp clamp OFF = 0) if the stanza isn't
    // found (e.g. an in-flight redeploy that already removed it — the port is being torn down
    // anyway). The `0` fallback MUST match `L4PortConfig::amp_k()`'s clamp-off default: a stale `1`
    // here would re-arm the retired ratio clamp on any port whose decl momentarily can't be read.
    let (idle_timeout_secs, amp_k) = crate::read_l4_port_decls(data_dir, &alloc.project_id)
        .into_iter()
        .find(|d| d.name == alloc.name)
        .map(|d| (d.idle_timeout_secs, d.amp_k))
        .unwrap_or((60, 0));

    // Resolve the project's egress limits ONCE, here on the cold path, layering any admin
    // override over the platform defaults field-by-field. An override that omits a field leaves
    // the default in place rather than zeroing it — a zero-rate bucket admits nothing, and that
    // failure would present as total packet loss rather than as the config mistake it is.
    let egress = resolve_egress_limits(store, plane, &alloc.project_id);

    Some(L4PortSpec {
        base_project: vm_identity::base_project_id(&alloc.project_id).to_string(),
        project_id: alloc.project_id.clone(),
        tenant_id,
        name: alloc.name.clone(),
        proto: alloc.proto.clone(),
        external_port: alloc.external_port,
        agent_udp_port: alloc.agent_udp_port,
        guest_port: alloc.guest_port,
        idle_timeout: Duration::from_secs(idle_timeout_secs),
        amp_k,
        transit_secret,
        egress,
    })
}

// ---------------------------------------------------------------------------------------------
// JKL4 host firewall — per-external-port inbound UDP ACCEPT, mirroring the build orchestrator's
// JKBUILD iptables helpers (this repo uses iptables, NOT nftables). The host inbound default-deny
// is provisioned out-of-band (systemd/tools); JKL4 is where the runtime opens exactly the allocated
// UDP ports and closes them on teardown — symmetric, idempotent, xtables-lock-serialized.
// ---------------------------------------------------------------------------------------------

const JKL4_CHAIN: &str = "JKL4";

#[derive(Clone)]
struct L4Firewall {
    /// Serializes THIS process's JKL4 edits; `iptables -w` serializes against other processes.
    fw_lock: Arc<tokio::sync::Mutex<()>>,
}

impl L4Firewall {
    fn new() -> Self {
        Self {
            fw_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Rule spec (sans verb) for one UDP dport ACCEPT — kept EXACT so `-C`/`-I`/`-D` match the same
    /// rule.
    fn allow_rule(port: u16) -> Vec<String> {
        vec![
            "-p".into(),
            "udp".into(),
            "--dport".into(),
            port.to_string(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    }

    /// Idempotently create the JKL4 chain and hook it into INPUT. Best-effort: logs (does not bail)
    /// if iptables is unavailable — the socket still binds; unreachable ⇒ fail-closed, never open.
    async fn ensure_chain(&self) {
        let _g = self.fw_lock.lock().await;
        // -N fails if the chain exists; ignore that.
        let _ = tokio::process::Command::new("iptables")
            .args(["-w", "-N", JKL4_CHAIN])
            .status()
            .await;
        // Hook into INPUT only if not already hooked (-C check first).
        let hooked = tokio::process::Command::new("iptables")
            .args(["-w", "-C", "INPUT", "-j", JKL4_CHAIN])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if !hooked {
            let st = tokio::process::Command::new("iptables")
                .args(["-w", "-I", "INPUT", "1", "-j", JKL4_CHAIN])
                .status()
                .await;
            if st.map(|s| !s.success()).unwrap_or(true) {
                warn!(
                    "l4 firewall: could not hook JKL4 into INPUT (iptables absent?); per-port opens are best-effort"
                );
            }
        }
    }

    /// Open one UDP external port (idempotent: `-C` first, `-I` only if absent).
    async fn allow(&self, port: u16) {
        let _g = self.fw_lock.lock().await;
        let rule = Self::allow_rule(port);
        let mut check = vec!["-w".to_string(), "-C".to_string(), JKL4_CHAIN.to_string()];
        check.extend(rule.iter().cloned());
        let present = tokio::process::Command::new("iptables")
            .args(&check)
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if present {
            return;
        }
        let mut args = vec![
            "-w".to_string(),
            "-I".to_string(),
            JKL4_CHAIN.to_string(),
            "1".to_string(),
        ];
        args.extend(rule);
        if let Ok(st) = tokio::process::Command::new("iptables")
            .args(&args)
            .status()
            .await
            && !st.success()
        {
            warn!(
                port,
                "l4 firewall: iptables -I JKL4 (udp allow) failed; port may be unreachable"
            );
        }
    }

    /// Close one UDP external port — idempotent `-D` loop until no matching rule remains. `-w`
    /// makes the "no match" verdict trustworthy (a lost xtables lock returns the same nonzero exit
    /// as "absent", which would leave a stale open — a fail-open in the revoke path).
    async fn clear(&self, port: u16) {
        let _g = self.fw_lock.lock().await;
        let rule = Self::allow_rule(port);
        for _ in 0..64 {
            let mut args = vec!["-w".to_string(), "-D".to_string(), JKL4_CHAIN.to_string()];
            args.extend(rule.iter().cloned());
            let removed = tokio::process::Command::new("iptables")
                .args(&args)
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if !removed {
                break;
            }
        }
    }
}
