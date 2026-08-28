//! `l4_pump_harness` — drive the REAL host-side L4 datagram path at conference rates, with no VM.
//!
//! ## Why this exists
//!
//! `tools/l4-load` measures the plane end to end, but that needs a booted microVM — and on a box
//! where the guest kernel doesn't boot (see the 6.12/Firecracker ACPI issue) the question "does the
//! pump hold at SFU media rates?" is unanswerable. It is also the *slowest* way to iterate on a
//! question that is mostly about host-side cost.
//!
//! So this stands up everything on the host side of the transit seam and stubs only the guest:
//!
//! ```text
//!   l4-load  ─udp─>  edge socket ─┐
//!                                 │  REAL L4Ingress: flow table, wake gate, HMAC seal,
//!                                 │  guest-facing socket, egress bucket chain, counters
//!                                 └─> 127.0.0.1:agent_port
//!                                        │  stub agent (this file): REAL l4_transit::open,
//!                                        │  per-flow loopback socket, land-forward
//!                                        └─> 127.0.0.1:guest_port  (l4-sfu-sim)
//! ```
//!
//! ## What it does and does not cover
//!
//! COVERS, in real code: the edge recv loop, flow admission and the wake gate, per-datagram
//! `l4_transit` seal AND open (both directions, so both HMACs), the reply-demux by
//! `(flow_id, epoch)`, the nonce anti-replay window, the whole egress bucket chain
//! (per-source → per-victim → per-project → global), and every drop counter.
//!
//! DOES NOT cover: the TAP/virtio crossing, Firecracker, and the real `jkbase-agent`
//! land-forward (a bin-only crate, so it cannot be linked — the stub below speaks the same wire
//! but is not the same implementation). Loopback is also faster than a TAP, so latency here is a
//! floor, not a prediction.
//!
//! A pass here does NOT prove the end-to-end plane works. A failure here proves it cannot.
//!
//! ## Use
//!
//! ```text
//! cargo run -p jkbase-proxy --release --example l4_pump_harness -- --edge-port 40000
//! # then, from tools/l4-load:
//! ./target/release/l4-sfu-sim --port 9300 --http-port 8081 &
//! ./target/release/l4-load --target 127.0.0.1:40000 --participants 50 \
//!     --visible-streams 9 --audio-streams 3 --video-kbps 180 --speaker-kbps 800 --duration 60
//! ```
//!
//! Unprivileged: no KVM, no root, no jailer. Ports above 1024 only.

use jkbase_common::l4_transit::{self, L4Dir, L4TransitHeader};
use jkbase_proxy::WakeError;
use jkbase_proxy::l4_ingress::{L4Ingress, L4PortSpec, ResolveVmIp};
use jkbase_proxy::l4_plane::{L4Plane, L4PlaneLimits};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Transit secret for the host↔stub-agent leg. A fixed non-empty value: `L4Ingress::bind` refuses
/// an empty secret (an empty HMAC key would accept a forged tag), and this harness is loopback-only
/// so the value itself carries no security weight — it just has to match on both sides.
const HARNESS_SECRET: &str = "jkbl_pump_harness_loopback_only_not_a_production_secret";

/// One admitted flow, from the stub agent's point of view: the loopback socket that carries this
/// flow's datagrams to the guest, plus the state needed to seal replies back.
struct AgentFlow {
    /// Per-flow socket toward the guest, so the guest sees a distinct source per flow — exactly how
    /// the real agent's land-forward behaves, and why an SFU behind this plane sees loopback tuples
    /// rather than client addresses.
    guest: Arc<UdpSocket>,
    /// Monotonic per-`(flow_id, epoch)` nonce for the agent→host leg. The host drops any nonce at
    /// or below its high-water mark, so this must never repeat or go backwards.
    nonce: AtomicU64,
}

fn arg_u16(args: &[String], key: &str, default: u16) -> u16 {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!(
            "l4_pump_harness [--edge-port 40000] [--agent-port 40500] [--guest-port 9300] \
             [--report-secs 5]\n\n\
             Runs the real L4 pump with a stub agent on loopback. Point `l4-load` at the edge port \
             and `l4-sfu-sim` at the guest port."
        );
        return Ok(());
    }
    let edge_port = arg_u16(&args, "--edge-port", 40000);
    let agent_port = arg_u16(&args, "--agent-port", 40500);
    let guest_port = arg_u16(&args, "--guest-port", 9300);
    let report_secs = arg_u16(&args, "--report-secs", 5).max(1);

    // The pump only forwards to a WARM VM, so `resolve_vm_ip` answers immediately and the wake gate
    // is never exercised as a cold boot. That is deliberate: this harness measures steady-state
    // media throughput, not boot behaviour.
    let resolve: ResolveVmIp = Arc::new(|_project: String| {
        Box::pin(async move { Some("127.0.0.1".to_string()) })
    });
    let wake: jkbase_proxy::WakeCallback = Arc::new(|_project: String| {
        Box::pin(async move { Ok::<String, WakeError>("127.0.0.1".to_string()) })
    });

    let plane = L4Plane::new(L4PlaneLimits::default(), wake);
    let spec = L4PortSpec {
        project_id: "pump-harness".into(),
        base_project: "pump-harness".into(),
        tenant_id: None,
        name: "media".into(),
        proto: "udp".into(),
        external_port: edge_port,
        agent_udp_port: agent_port,
        guest_port,
        // Long enough that a paused generator doesn't tear flows down mid-measurement.
        idle_timeout: Duration::from_secs(600),
        // Clamp OFF, matching the shipped default (W-econ): an SFU is legitimately asymmetric, so
        // the ratio shaper would measure a limiter production does not apply.
        amp_k: 0,
        transit_secret: HARNESS_SECRET.into(),
        egress: plane.default_port_egress_limits(),
    };

    let cancel = CancellationToken::new();
    // `bind` only constructs the port (and claims the edge socket); `run` is what drives the reach,
    // return and sweep loops. Binding without running gives a socket that silently absorbs every
    // datagram — no traffic, no counters, no clue.
    let ingress = L4Ingress::bind(spec, plane.clone(), resolve, cancel.clone()).await?;
    tokio::spawn(ingress.clone().run());
    println!("edge      udp/{edge_port}  (point l4-load here)");
    println!("stub agent 127.0.0.1:{agent_port} -> guest 127.0.0.1:{guest_port}");
    println!("limits    {:?}", plane.default_port_egress_limits());

    let secret = Arc::new(HARNESS_SECRET.to_string());
    tokio::spawn({
        let secret = secret.clone();
        async move {
            if let Err(e) = run_stub_agent(agent_port, guest_port, secret).await {
                eprintln!("stub agent died: {e}");
            }
        }
    });

    // Counters are read-and-reset, so each line is the delta for that window.
    let started = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(report_secs as u64)).await;
        let c = plane.drain_counters();
        // Read the counters' own enumeration — hand-listing here once omitted three reasons
        // (`unknown_flow`, `c0_grant_rejected`, `edge_bind_eaddrinuse`), so a run that blackholed
        // return frames still printed `drops=0` and passed.
        let drops = c.total_drops();
        print!("[{:>5.0}s] drops={drops}", started.elapsed().as_secs_f64());
        if drops > 0 {
            // Name only what actually fired: a line of twenty zeroes hides the one that matters.
            for (label, v) in c.drop_reasons() {
                if v > 0 {
                    print!(" {label}={v}");
                }
            }
        }
        println!(
            " | wakes={} promotions={} provisional_expired={}",
            c.wakes_admitted, c.promotions, c.provisional_expired
        );
    }
}

/// The stub agent: verifies the real transit wire and land-forwards to the guest on loopback.
///
/// Not the real `jkbase-agent` (bin-only, cannot be linked), but it speaks the identical wire —
/// `l4_transit::open` for host→agent and `seal` for agent→host — so the HMAC cost and the
/// `(flow_id, epoch, nonce)` discipline in the measurement are genuine.
async fn run_stub_agent(
    agent_port: u16,
    guest_port: u16,
    secret: Arc<String>,
) -> std::io::Result<()> {
    let sock = Arc::new(UdpSocket::bind(("127.0.0.1", agent_port)).await?);
    let flows: Arc<Mutex<HashMap<u32, Arc<AgentFlow>>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, host_addr) = sock.recv_from(&mut buf).await?;
        let Some((hdr, payload)) = l4_transit::open(secret.as_bytes(), L4Dir::HostToAgent, &buf[..n])
        else {
            // Fail closed exactly as the real agent does: an unauthenticated frame reaches no
            // loopback socket. Silent because a hostile L2 neighbour could otherwise spam stderr.
            continue;
        };

        let existing = flows.lock().unwrap().get(&hdr.flow_id).cloned();
        let flow = match existing {
            Some(f) => f,
            None => {
                let guest = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
                guest.connect(("127.0.0.1", guest_port)).await?;
                let flow = Arc::new(AgentFlow {
                    guest: guest.clone(),
                    nonce: AtomicU64::new(0),
                });
                flows.lock().unwrap().insert(hdr.flow_id, flow.clone());
                spawn_reply_pump(
                    sock.clone(),
                    guest,
                    host_addr,
                    hdr.flow_id,
                    hdr.epoch,
                    flow.clone(),
                    secret.clone(),
                );
                flow
            }
        };
        let _ = flow.guest.send(payload).await;
    }
}

/// One task per flow, draining the guest's replies and sealing them back to the host.
///
/// Per-flow rather than a shared reader because the reply must carry the `flow_id` the host uses to
/// demux back to a client, and a single socket could not tell the flows apart.
fn spawn_reply_pump(
    agent_sock: Arc<UdpSocket>,
    guest: Arc<UdpSocket>,
    host_addr: SocketAddr,
    flow_id: u32,
    epoch: u32,
    flow: Arc<AgentFlow>,
    secret: Arc<String>,
) {
    tokio::spawn(async move {
        let mut rbuf = vec![0u8; 65535];
        let mut out = Vec::with_capacity(65535 + l4_transit::L4_HEADER_LEN);
        loop {
            let Ok(n) = guest.recv(&mut rbuf).await else {
                return;
            };
            let hdr = L4TransitHeader {
                flow_id,
                epoch,
                // Pre-increment so the first nonce is 1: the host's high-water starts at 0 and
                // rejects anything at or below it, which would silently drop the first reply.
                nonce: flow.nonce.fetch_add(1, Ordering::Relaxed) + 1,
            };
            l4_transit::seal(
                secret.as_bytes(),
                L4Dir::AgentToHost,
                hdr,
                &rbuf[..n],
                &mut out,
            );
            if agent_sock.send_to(&out, host_addr).await.is_err() {
                return;
            }
        }
    });
}
