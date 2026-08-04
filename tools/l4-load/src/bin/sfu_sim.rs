//! `l4-sfu-sim` — the **guest** half of the L4 load harness: a stand-in for a mediasoup SFU's
//! media plane, deployable as a jkbase project behind an `[l4.*]` UDP port.
//!
//! It is deliberately *not* an echo server. An echo can never trip the plane's reflection
//! controls (`egress_per_source`, `egress_per_24`, `egress_per_project`, `RatioCredit`) because
//! those only fire when egress outruns ingress — the defining shape of an SFU and the opposite of
//! an echo. So each admitted flow gets an **unsolicited downstream** at the rate its JOIN asked
//! for, which is what a real conference server does when it fans `(N-1)` peers' streams back at
//! one participant.
//!
//! Binds **guest loopback only** by default (P0-L4-1: the tenant service never touches eth0 — the
//! agent's land-forward is the sole path in). `--bind` exists solely so the same binary can serve
//! the no-plane baseline run on a plain host; a deployed run must leave it at the default.
//!
//! Because the agent land-forwards from a per-flow loopback socket, every flow arrives from a
//! distinct `127.0.0.1:<ephemeral>` — which is also precisely why mediasoup behind this plane
//! would see loopback tuples instead of client addresses. The simulator keys flows on that source
//! address, mirroring how mediasoup's ICE tuple bookkeeping would.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use l4wire::{
    fmt_bps, now_nanos, parse_header, put_header, Args, Class, Header, JoinProfile, Kind,
    MAX_DATAGRAM,
};

/// A flow with no traffic in either direction for this long is reaped: its emitter stops and its
/// slot frees. Deliberately shorter than the plane's own `idle_timeout` floor (15s) so the
/// simulator is never the reason a flow looks alive to the plane.
const FLOW_IDLE: Duration = Duration::from_secs(10);

/// Hard ceiling on concurrent flows. One thread per flow is fine at conference scale and keeps
/// the emitter's pacing honest, but an unbounded map plus unbounded threads would make the
/// *simulator* the bottleneck and misattribute its collapse to the plane.
const MAX_FLOWS: usize = 512;

struct Flow {
    stop: Arc<AtomicBool>,
    last_seen: Instant,
    /// Uplink accounting, written by the recv loop, read by the reporter.
    up_packets: u64,
    up_bytes: u64,
    /// Highest uplink seq seen per class, for span-based uplink loss.
    up_first: [Option<u32>; 3],
    up_high: [u32; 3],
    profile: JoinProfile,
}

#[derive(Default)]
struct Totals {
    down_packets: AtomicU64,
    down_bytes: AtomicU64,
    /// Datagrams the OS refused to accept (ENOBUFS and friends) — the simulator's own shortfall,
    /// which must be visible or it would be misread as plane loss.
    send_errors: AtomicU64,
}

fn main() {
    let args = Args::parse();
    args.reject_unknown(&["bind", "port", "http-port", "report-secs", "help"]);
    if args.flag("help") {
        eprintln!(
            "l4-sfu-sim --port <p> [--bind 127.0.0.1] [--http-port 8080] [--report-secs 2]\n\
             \n\
             Simulated SFU media plane. Admits a flow per JOIN and fans an unsolicited\n\
             downstream back at it at the JOIN's requested rate."
        );
        return;
    }

    let bind = args.get("bind").unwrap_or("127.0.0.1").to_string();
    let port: u16 = args.num("port", 9300);
    let http_port: u16 = args.num("http-port", 8080);
    let report_secs: u64 = args.num("report-secs", 2);

    let sock = match UdpSocket::bind((bind.as_str(), port)) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("l4-sfu-sim: bind {bind}:{port} failed: {e}");
            std::process::exit(1);
        }
    };
    // Generous buffers: a starved socket buffer would show up as "the plane lost packets". The
    // comment used to sit here with no code under it — the socket ran at the default ~208 KiB,
    // which at fan-out rates is well under a second of queue, so an ordinary scheduling hiccup
    // inside the microVM overflowed the kernel queue and every dropped datagram was attributed to
    // the plane.
    let (rcv, snd) = l4wire::set_socket_buffers(&sock, l4wire::SOCK_BUF_BYTES);
    if rcv < l4wire::SOCK_BUF_BYTES / 2 || snd < l4wire::SOCK_BUF_BYTES / 2 {
        eprintln!(
            "l4-sfu-sim: warning — requested {}B socket buffers, kernel granted rcv={rcv}B \
             snd={snd}B (net.core.rmem_max/wmem_max clamping). Queue overflow inside the guest \
             is indistinguishable from plane loss; raise the sysctls before trusting a result.",
            l4wire::SOCK_BUF_BYTES
        );
    }
    let origin = Instant::now();
    println!("l4-sfu-sim listening on {bind}:{port}");

    let flows: Arc<Mutex<HashMap<SocketAddr, Flow>>> = Arc::new(Mutex::new(HashMap::new()));
    let totals = Arc::new(Totals::default());

    spawn_reaper(Arc::clone(&flows));
    spawn_reporter(Arc::clone(&flows), Arc::clone(&totals), report_secs);
    spawn_http(http_port, Arc::clone(&flows), Arc::clone(&totals));

    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("l4-sfu-sim: recv error: {e}");
                continue;
            }
        };
        let Some(hdr) = parse_header(&buf[..n]) else {
            continue; // Not ours. Drop silently — the port is public-facing by construction.
        };

        match hdr.kind {
            Kind::Join => {
                let Some(profile) = JoinProfile::decode(&buf[l4wire::HDR_LEN..n]) else {
                    continue;
                };
                admit(&flows, &totals, &sock, src, profile, origin);
            }
            Kind::Up => {
                let mut map = flows.lock().unwrap();
                if let Some(f) = map.get_mut(&src) {
                    f.last_seen = Instant::now();
                    f.up_packets += 1;
                    f.up_bytes += n as u64;
                    let c = hdr.class as usize;
                    if f.up_first[c].is_none() {
                        f.up_first[c] = Some(hdr.seq);
                        f.up_high[c] = hdr.seq;
                    } else if hdr.seq > f.up_high[c] {
                        f.up_high[c] = hdr.seq;
                    }
                }
            }
            Kind::Ping => {
                // Echo the client's own stamp back untouched: RTT is then a single-clock
                // measurement and needs no synchronisation between the two boxes.
                let mut out = [0u8; l4wire::HDR_LEN];
                put_header(
                    &mut out,
                    Header {
                        kind: Kind::Pong,
                        class: Class::Ctl,
                        seq: hdr.seq,
                        stamp: hdr.stamp,
                    },
                );
                if sock.send_to(&out, src).is_err() {
                    totals.send_errors.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(f) = flows.lock().unwrap().get_mut(&src) {
                    f.last_seen = Instant::now();
                }
            }
            Kind::Leave => {
                if let Some(f) = flows.lock().unwrap().remove(&src) {
                    f.stop.store(true, Ordering::Relaxed);
                }
            }
            Kind::Down | Kind::Pong => {} // Server-origin kinds; ignore if reflected back.
        }
    }
}

/// Admit (or re-admit) a flow and start its downstream emitter.
///
/// A repeat JOIN from the same source replaces the flow wholesale — a client that restarts
/// mid-run must not end up with two emitters racing on one socket, which would read as duplicate
/// delivery rather than the client bug it is.
fn admit(
    flows: &Arc<Mutex<HashMap<SocketAddr, Flow>>>,
    totals: &Arc<Totals>,
    sock: &Arc<UdpSocket>,
    src: SocketAddr,
    profile: JoinProfile,
    origin: Instant,
) {
    let mut map = flows.lock().unwrap();
    if let Some(old) = map.remove(&src) {
        old.stop.store(true, Ordering::Relaxed);
    }
    if map.len() >= MAX_FLOWS {
        eprintln!("l4-sfu-sim: flow table full ({MAX_FLOWS}), refusing {src}");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    map.insert(
        src,
        Flow {
            stop: Arc::clone(&stop),
            last_seen: Instant::now(),
            up_packets: 0,
            up_bytes: 0,
            up_first: [None; 3],
            up_high: [0; 3],
            profile,
        },
    );
    drop(map);

    println!(
        "l4-sfu-sim: admit {src} v={}pps/{}B a={}pps/{}B offered={}",
        profile.v_pps,
        profile.v_bytes,
        profile.a_pps,
        profile.a_bytes,
        fmt_bps(profile.offered_bps() as f64)
    );

    // One emitter thread per class so the two series are paced independently — interleaving them
    // on one pacer would couple audio's cadence to video's and blur which class a cap starved.
    for (class, pps, size) in [
        (Class::Video, profile.v_pps, profile.v_bytes),
        (Class::Audio, profile.a_pps, profile.a_bytes),
    ] {
        if pps == 0 {
            continue;
        }
        let sock = Arc::clone(sock);
        let stop = Arc::clone(&stop);
        let totals = Arc::clone(totals);
        std::thread::spawn(move || {
            emit(sock, src, class, pps, size as usize, stop, totals, origin);
        });
    }
}

/// Paced downstream emitter for one (flow, class).
// Eight plain parameters read better here than a struct that exists only to carry them one call
// deep into a thread body.
#[allow(clippy::too_many_arguments)]
fn emit(
    sock: Arc<UdpSocket>,
    dst: SocketAddr,
    class: Class,
    pps: u32,
    size: usize,
    stop: Arc<AtomicBool>,
    totals: Arc<Totals>,
    origin: Instant,
) {
    // Half the per-source burst each: the video and audio emitters for one participant send to the
    // same destination and so share one per-source token bucket. Sizing both at the full burst
    // lets coincident batches overshoot it by 2x, and the resulting drops are the plane correctly
    // shaping the HARNESS — indistinguishable, downstream, from the pump losing packets.
    let mut pacer = l4wire::Pacer::new(
        pps,
        size as u32,
        l4wire::PER_SOURCE_BURST_BYTES / 2,
        Instant::now(),
    );
    let mut buf = vec![0u8; size];
    let mut seq: u32 = 0;
    while !stop.load(Ordering::Relaxed) {
        let batch = pacer.wait_batch();
        if batch == 0 {
            return;
        }
        for _ in 0..batch {
            put_header(
                &mut buf,
                Header {
                    kind: Kind::Down,
                    class,
                    seq,
                    // Stamped per packet, not per batch: a shared stamp would make a batch look
                    // like it arrived with zero inter-packet delay and flatten the jitter figure.
                    stamp: now_nanos(origin),
                },
            );
            match sock.send_to(&buf, dst) {
                Ok(_) => {
                    totals.down_packets.fetch_add(1, Ordering::Relaxed);
                    totals.down_bytes.fetch_add(size as u64, Ordering::Relaxed);
                }
                Err(_) => {
                    totals.send_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            seq = seq.wrapping_add(1);
        }
    }
}

/// Reap flows gone quiet in both directions, so a killed client can't strand an emitter that
/// keeps offering load into the next run.
fn spawn_reaper(flows: Arc<Mutex<HashMap<SocketAddr, Flow>>>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = Instant::now();
        let mut map = flows.lock().unwrap();
        map.retain(|src, f| {
            let alive = now.duration_since(f.last_seen) < FLOW_IDLE;
            if !alive {
                f.stop.store(true, Ordering::Relaxed);
                println!("l4-sfu-sim: reap {src} (idle)");
            }
            alive
        });
    });
}

/// A minimal HTTP face on the declared `[servers.*] port`, for two reasons that both matter when
/// this runs as a real deployment: the platform's health check needs *something* listening on the
/// authoritative port, and `/stats` gives the harness a guest-side view over the ordinary HTTPS
/// route while a load run is in flight — the only way to tell "the plane dropped it" from "the
/// simulator never sent it".
///
/// Hand-rolled HTTP/1.1 because the whole crate is dependency-free by design; it answers two
/// paths and closes the connection, which is the entire contract.
fn spawn_http(port: u16, flows: Arc<Mutex<HashMap<SocketAddr, Flow>>>, totals: Arc<Totals>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("l4-sfu-sim: http bind :{port} failed: {e} (health check will fail)");
            return;
        }
    };
    println!("l4-sfu-sim: http on :{port} (/health, /stats)");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            // Serial accept loop with a blocking read: one peer that opens a connection and sends
            // nothing would wedge /health and /stats permanently, and the platform health check
            // would then hibernate the project mid-run. A deadline on both directions bounds it.
            // This is deployed as an ordinary untrusted tenant workload, so "the only client is
            // our own harness" is not an assumption available to us.
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();

            let body = if path.starts_with("/stats") {
                let map = flows.lock().unwrap();
                let (up_p, up_b): (u64, u64) = map
                    .values()
                    .fold((0, 0), |(p, b), f| (p + f.up_packets, b + f.up_bytes));
                let offered: u64 = map.values().map(|f| f.profile.offered_bps()).sum();
                format!(
                    "{{\"flows\":{},\"offered_down_bps\":{offered},\
                     \"down_packets\":{},\"down_bytes\":{},\"send_errors\":{},\
                     \"up_packets\":{up_p},\"up_bytes\":{up_b}}}",
                    map.len(),
                    totals.down_packets.load(Ordering::Relaxed),
                    totals.down_bytes.load(Ordering::Relaxed),
                    totals.send_errors.load(Ordering::Relaxed),
                )
            } else {
                "ok".to_string()
            };

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
}

/// Periodic aggregate line. Deployed, this lands in the project's shipped logs, which is the only
/// view of the guest side during an e2e run.
fn spawn_reporter(
    flows: Arc<Mutex<HashMap<SocketAddr, Flow>>>,
    totals: Arc<Totals>,
    report_secs: u64,
) {
    if report_secs == 0 {
        return;
    }
    std::thread::spawn(move || {
        let mut last = (0u64, 0u64);
        loop {
            std::thread::sleep(Duration::from_secs(report_secs));
            let dp = totals.down_packets.load(Ordering::Relaxed);
            let db = totals.down_bytes.load(Ordering::Relaxed);
            let (up_p, up_b, flow_n, up_lost) = {
                let map = flows.lock().unwrap();
                let mut p = 0;
                let mut b = 0;
                let mut lost = 0i64;
                for f in map.values() {
                    p += f.up_packets;
                    b += f.up_bytes;
                    for c in 0..3 {
                        if let Some(first) = f.up_first[c] {
                            lost += (f.up_high[c] - first) as i64 + 1;
                        }
                    }
                }
                lost -= p as i64;
                (p, b, map.len(), lost.max(0))
            };
            let secs = report_secs as f64;
            println!(
                "l4-sfu-sim: flows={flow_n} down={} ({:.0} pps) up_pkts={up_p} up_bytes={up_b} up_lost≈{up_lost} send_err={}",
                fmt_bps((db - last.1) as f64 / secs),
                (dp - last.0) as f64 / secs,
                totals.send_errors.load(Ordering::Relaxed)
            );
            last = (dp, db);
        }
    });
}
