//! `l4-load` — the **client** half of the harness: K virtual conference participants driving a
//! deployed `l4-sfu-sim` through the L4 UDP plane (or straight at it, for the no-plane baseline).
//!
//! Each virtual participant is one UDP flow: uplink of one video + one audio stream, downlink of
//! the `(N-1)` fan-out streams the SFU would send it. That asymmetry is the point — the plane's
//! egress controls are what an SFU will meet first, and they are keyed on the **destination IP**,
//! i.e. one token bucket per participant.
//!
//! ## The source-address trap
//!
//! Run K participants from one box with no `--bind-ips` and all K share a single source IP, so
//! all K downstreams share **one** `per_source_bps` bucket (1 MiB/s by default) instead of K of
//! them. The result looks like catastrophic plane loss and means nothing. Give each participant
//! its own address (`--bind-ips`, see the README's alias setup) or the run is not modelling a
//! conference — it is modelling one very unlucky client. The reporter refuses to draw conclusions
//! when it detects this.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use l4wire::{
    fmt_bps, fmt_ms, now_nanos, parse_header, percentile, put_header, Args, Class, Header,
    JoinProfile, Kind, Pacer, SeriesStats, HDR_LEN, JOIN_BODY_LEN, MAX_DATAGRAM,
};

// The plane's shipped defaults (`crates/jkbase-proxy/src/l4_plane.rs`, `L4PlaneLimits::default`).
// Mirrored here only so the report can say *which* ceiling a run appears to have hit; the plane
// remains the source of truth, and a run against a patched plane should pass `--limits-*`.
const DEF_PER_SOURCE_BPS: f64 = 1024.0 * 1024.0;
const DEF_PER_24_BPS: f64 = 8.0 * 1024.0 * 1024.0;
const DEF_PER_PROJECT_BPS: f64 = 16.0 * 1024.0 * 1024.0;

/// A ceiling is called "hit" when throughput lands within this fraction of it. Token buckets
/// admit a burst before settling, so an exactly-equal reading is not expected.
const CEILING_TOLERANCE: f64 = 0.12;

struct Shared {
    stop: AtomicBool,
    /// Flips once after warm-up; the receive thread resets its accumulators so cold-start effects
    /// (flow admission, the plane's provisional→established promotion, the first-packet replay
    /// buffer) never contaminate the steady-state numbers.
    measuring: AtomicBool,
}

#[derive(Default)]
struct RxStats {
    video: SeriesStats,
    audio: SeriesStats,
    rtt_nanos: Vec<u64>,
    /// Set once, when the warm-up boundary is crossed and the accumulators are cleared. Rates are
    /// reported against the run's measured window, not this — it exists to make the one-shot
    /// nature of the reset explicit.
    reset_done: bool,
}

struct Participant {
    idx: usize,
    local: SocketAddr,
    stats: Arc<Mutex<RxStats>>,
}

fn main() {
    let args = Args::parse();
    args.reject_unknown(&[
        "target",
        "participants",
        "duration",
        "warmup",
        "video-kbps",
        "audio-kbps",
        "video-bytes",
        "audio-bytes",
        "visible-streams",
        "bind-ips",
        "limits-per-source-bps",
        "limits-per-project-bps",
        "baseline",
        "json",
        "help",
    ]);
    if args.flag("help") {
        eprintln!(
            "l4-load --target <host:port> [options]\n\
             \n\
             --participants N       virtual participants (default 10)\n\
             --duration SECS        measured seconds after warm-up (default 60)\n\
             --warmup SECS          discarded seconds (default 5)\n\
             --video-kbps K         per-stream video rate (default 1500)\n\
             --audio-kbps K         per-stream audio rate (default 40)\n\
             --video-bytes B        video packet size (default 1200)\n\
             --audio-bytes B        audio packet size (default 160)\n\
             --visible-streams N    cap video fan-out per participant (0 = all N-1).\n\
             \x20                      Large meetings do NOT send every camera at full rate;\n\
             \x20                      see the README before running 20+ without this.\n\
             --bind-ips A,B,C       source IPs, round-robin per participant\n\
             --limits-per-source-bps N   plane's per-source ceiling, for diagnosis\n\
             --limits-per-project-bps N  plane's per-project ceiling, for diagnosis\n\
             --baseline             no plane in the path: skip ceiling diagnosis (control run)\n\
             --json                 emit a machine-readable summary line"
        );
        return;
    }

    let Some(target_arg) = args.get("target") else {
        eprintln!("l4-load: --target <host:port> is required");
        std::process::exit(2);
    };
    let target: SocketAddr = match target_arg.to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => {
                eprintln!("l4-load: --target {target_arg} resolved to nothing");
                std::process::exit(2);
            }
        },
        Err(e) => {
            eprintln!("l4-load: --target {target_arg}: {e}");
            std::process::exit(2);
        }
    };

    let n: usize = args.num("participants", 10);
    let duration = Duration::from_secs(args.num("duration", 60));
    let warmup = Duration::from_secs(args.num("warmup", 5));
    let video_kbps: u32 = args.num("video-kbps", 1500);
    let audio_kbps: u32 = args.num("audio-kbps", 40);
    let video_bytes: u16 = args.num("video-bytes", 1200);
    let audio_bytes: u16 = args.num("audio-bytes", 160);
    let per_source_bps: f64 = args.num("limits-per-source-bps", DEF_PER_SOURCE_BPS);
    let per_project_bps: f64 = args.num("limits-per-project-bps", DEF_PER_PROJECT_BPS);
    let baseline = args.flag("baseline");
    let json = args.flag("json");

    if n == 0 {
        eprintln!("l4-load: --participants must be > 0");
        std::process::exit(2);
    }
    if video_bytes as usize > MAX_DATAGRAM || audio_bytes as usize > MAX_DATAGRAM {
        eprintln!("l4-load: packet sizes must stay under {MAX_DATAGRAM}B — above the MTU the\n\
                   transit leg fragments and the loss numbers stop meaning what they say");
        std::process::exit(2);
    }

    let bind_ips: Vec<IpAddr> = match args.get("bind-ips") {
        Some(list) => list
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| match s.trim().parse() {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("l4-load: bad --bind-ips entry {s:?}: {e}");
                    std::process::exit(2);
                }
            })
            .collect(),
        None => vec![],
    };

    // Per-stream pps derived from the requested bitrate and packet size. Integer division floors,
    // so the offered rate is at or just under the nominal bitrate — never above it, which would
    // let the harness over-drive and blame the plane.
    let v_pps_stream = (video_kbps as u64 * 1000 / 8 / video_bytes.max(1) as u64).max(1) as u32;
    let a_pps_stream = (audio_kbps as u64 * 1000 / 8 / audio_bytes.max(1) as u64).max(1) as u32;

    // Video fan-out is capped separately from audio because that is what SFUs actually do: a
    // 50-way meeting decodes a handful of visible videos, not 49, while audio stays mixed or
    // forwarded for everyone. Modelling video as N-1 full-rate streams at that size doesn't
    // stress-test the plane — it invents a workload no conference product ships.
    let visible: u32 = args.num("visible-streams", 0);
    let audio_fanout = (n - 1) as u32;
    let video_fanout = if visible == 0 {
        audio_fanout
    } else {
        visible.min(audio_fanout)
    };

    let down_profile = JoinProfile {
        v_pps: v_pps_stream * video_fanout,
        v_bytes: video_bytes,
        a_pps: a_pps_stream * audio_fanout,
        a_bytes: audio_bytes,
    };

    let offered_per_participant = down_profile.offered_bps() as f64;
    let offered_total = offered_per_participant * n as f64;

    println!("── L4 load harness ─────────────────────────────────────────");
    println!("target                {target}");
    println!(
        "participants          {n} (fan-out: {video_fanout} video, {audio_fanout} audio per participant)"
    );
    println!("per-stream            video {video_kbps}kbps/{video_bytes}B  audio {audio_kbps}kbps/{audio_bytes}B");
    println!(
        "offered downstream    {} per participant, {} aggregate",
        fmt_bps(offered_per_participant),
        fmt_bps(offered_total)
    );
    println!(
        "offered uplink        {} per participant",
        fmt_bps((v_pps_stream * video_bytes as u32 + a_pps_stream * audio_bytes as u32) as f64)
    );
    if audio_fanout == 0 {
        println!("note                  1 participant ⇒ zero fan-out; downstream is idle by construction");
    }

    // Two sanity gates before a big run, because both failure modes look like "the plane is
    // broken" and neither is.
    if visible == 0 && n >= 20 {
        println!(
            "!! every participant is receiving all {audio_fanout} videos at {video_kbps}kbps. No SFU\n\
             \x20  ships that at this size — real ones send a few visible streams plus simulcast\n\
             \x20  low layers. Pass --visible-streams (and/or a lower --video-kbps) or this run\n\
             \x20  measures a workload unrambler will never generate."
        );
    }
    let nic_mbps = offered_total * 8.0 / 1e6;
    if nic_mbps > 900.0 {
        println!(
            "!! offered aggregate is {nic_mbps:.0} Mbps — past a 1GbE path. Saturating the NIC or\n\
             \x20  the loopback stack would be measured as plane loss. Check the baseline run\n\
             \x20  reaches this rate before believing anything the plane run says."
        );
    }
    println!("warm-up {}s, measure {}s", warmup.as_secs(), duration.as_secs());
    println!();

    let shared = Arc::new(Shared {
        stop: AtomicBool::new(false),
        measuring: AtomicBool::new(false),
    });
    let origin = Instant::now();

    let mut participants = Vec::with_capacity(n);
    let mut handles = Vec::new();

    for idx in 0..n {
        let bind_ip = if bind_ips.is_empty() {
            "0.0.0.0".parse().unwrap()
        } else {
            bind_ips[idx % bind_ips.len()]
        };
        let sock = match UdpSocket::bind(SocketAddr::new(bind_ip, 0)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("l4-load: participant {idx} bind {bind_ip}:0 failed: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = sock.connect(target) {
            eprintln!("l4-load: participant {idx} connect {target} failed: {e}");
            std::process::exit(1);
        }
        // Bounded so the receive loop can observe the stop flag even when the plane goes silent.
        sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let local = sock.local_addr().expect("bound socket has a local address");
        let sock = Arc::new(sock);
        let stats = Arc::new(Mutex::new(RxStats::default()));

        // JOIN first: the flow must exist before the downstream can be asked for.
        let mut join = [0u8; HDR_LEN + JOIN_BODY_LEN];
        put_header(
            &mut join,
            Header {
                kind: Kind::Join,
                class: Class::Ctl,
                seq: 0,
                stamp: now_nanos(origin),
            },
        );
        down_profile.encode(&mut join[HDR_LEN..]);
        if sock.send(&join).is_err() {
            eprintln!("l4-load: participant {idx} JOIN send failed");
        }

        handles.push(spawn_rx(
            Arc::clone(&sock),
            Arc::clone(&stats),
            Arc::clone(&shared),
            origin,
        ));
        handles.push(spawn_tx(
            Arc::clone(&sock),
            Arc::clone(&shared),
            Class::Video,
            v_pps_stream,
            video_bytes as usize,
            origin,
        ));
        handles.push(spawn_tx(
            Arc::clone(&sock),
            Arc::clone(&shared),
            Class::Audio,
            a_pps_stream,
            audio_bytes as usize,
            origin,
        ));
        handles.push(spawn_ping(Arc::clone(&sock), Arc::clone(&shared), origin));

        participants.push(Participant { idx, local, stats });
    }

    std::thread::sleep(warmup);
    shared.measuring.store(true, Ordering::Relaxed);
    let measure_start = Instant::now();
    std::thread::sleep(duration);
    shared.stop.store(true, Ordering::Relaxed);
    let measured = measure_start.elapsed();

    for h in handles {
        let _ = h.join();
    }

    report(
        &participants,
        measured,
        Ceilings {
            offered_per_participant,
            offered_total,
            per_source_bps,
            per_project_bps,
            baseline,
        },
        &bind_ips,
        n,
        json,
    );
}

fn spawn_rx(
    sock: Arc<UdpSocket>,
    stats: Arc<Mutex<RxStats>>,
    shared: Arc<Shared>,
    origin: Instant,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; MAX_DATAGRAM];
        while !shared.stop.load(Ordering::Relaxed) {
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(_) => continue, // Timeout or transient error; re-check the stop flag.
            };
            let Some(hdr) = parse_header(&buf[..n]) else {
                continue;
            };
            let arrival = now_nanos(origin);
            let mut s = stats.lock().unwrap();

            // Warm-up boundary: discard everything seen before it, in one shot, so the
            // steady-state series starts at a real sequence origin rather than mid-stream.
            if shared.measuring.load(Ordering::Relaxed) && !s.reset_done {
                *s = RxStats {
                    reset_done: true,
                    ..Default::default()
                };
            }

            match hdr.kind {
                Kind::Down => match hdr.class {
                    Class::Video => s.video.record(hdr.seq, n, hdr.stamp, arrival),
                    Class::Audio => s.audio.record(hdr.seq, n, hdr.stamp, arrival),
                    Class::Ctl => {}
                },
                Kind::Pong => {
                    // The stamp is our own clock, echoed — subtract directly for RTT.
                    s.rtt_nanos.push(arrival.saturating_sub(hdr.stamp));
                }
                _ => {}
            }
        }
    })
}

fn spawn_tx(
    sock: Arc<UdpSocket>,
    shared: Arc<Shared>,
    class: Class,
    pps: u32,
    size: usize,
    origin: Instant,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut pacer = Pacer::new(pps, Instant::now());
        let mut buf = vec![0u8; size];
        let mut seq: u32 = 0;
        while !shared.stop.load(Ordering::Relaxed) {
            let batch = pacer.wait_batch();
            if batch == 0 {
                return;
            }
            for _ in 0..batch {
                put_header(
                    &mut buf,
                    Header {
                        kind: Kind::Up,
                        class,
                        seq,
                        stamp: now_nanos(origin),
                    },
                );
                let _ = sock.send(&buf);
                seq = seq.wrapping_add(1);
            }
        }
    })
}

/// RTT probe + flow keepalive. 5/s is frequent enough for a usable latency distribution and far
/// below anything that would perturb the rate measurement.
fn spawn_ping(
    sock: Arc<UdpSocket>,
    shared: Arc<Shared>,
    origin: Instant,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut seq: u32 = 0;
        while !shared.stop.load(Ordering::Relaxed) {
            let mut buf = [0u8; HDR_LEN];
            put_header(
                &mut buf,
                Header {
                    kind: Kind::Ping,
                    class: Class::Ctl,
                    seq,
                    stamp: now_nanos(origin),
                },
            );
            let _ = sock.send(&buf);
            seq = seq.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(200));
        }
        // Clean teardown so the simulator frees the emitter immediately rather than at its reaper
        // interval — otherwise back-to-back runs overlap and the second one starts polluted.
        let mut bye = [0u8; HDR_LEN];
        put_header(
            &mut bye,
            Header {
                kind: Kind::Leave,
                class: Class::Ctl,
                seq: 0,
                stamp: now_nanos(origin),
            },
        );
        let _ = sock.send(&bye);
    })
}

/// What the run offered and what the plane is expected to allow — everything the diagnosis needs
/// to say *which* ceiling a number landed on.
struct Ceilings {
    offered_per_participant: f64,
    offered_total: f64,
    per_source_bps: f64,
    per_project_bps: f64,
    /// No plane in the path. The ceilings below belong to the plane, so applying them to a
    /// control run would invent findings the run cannot possibly support.
    baseline: bool,
}

fn report(
    participants: &[Participant],
    measured: Duration,
    c: Ceilings,
    bind_ips: &[IpAddr],
    n: usize,
    json: bool,
) {
    let Ceilings {
        offered_per_participant,
        offered_total,
        per_source_bps,
        per_project_bps,
        baseline,
    } = c;
    println!("── per participant ─────────────────────────────────────────");
    println!(
        "{:>4}  {:>20}  {:>8}  {:>8}  {:>9}  {:>9}  {:>9}",
        "#", "downstream", "v-loss", "a-loss", "jitter", "rtt p50", "rtt p95"
    );

    let mut total_bytes = 0u64;
    let mut worst_loss: f64 = 0.0;
    let mut all_rtt: Vec<u64> = Vec::new();
    let mut throttled = 0usize;
    let mut silent = 0usize;
    let mut per_ip_bytes: HashMap<IpAddr, u64> = HashMap::new();

    for p in participants {
        let s = p.stats.lock().unwrap();
        let bytes = s.video.bytes + s.audio.bytes;
        total_bytes += bytes;
        *per_ip_bytes.entry(p.local.ip()).or_default() += bytes;

        let bps = bytes as f64 / measured.as_secs_f64();
        let v_loss = s.video.loss_pct();
        let a_loss = s.audio.loss_pct();
        worst_loss = worst_loss.max(v_loss).max(a_loss);
        if bytes == 0 {
            silent += 1;
        }

        let mut rtt = s.rtt_nanos.clone();
        rtt.sort_unstable();
        all_rtt.extend_from_slice(&rtt);
        let jitter = (s.video.jitter_nanos.max(s.audio.jitter_nanos)) as u64;

        // "Throttled" = delivered materially less than offered while the plane's per-source
        // ceiling sits right about where delivery landed. That coincidence is the signature of a
        // token bucket, not of a saturated CPU.
        if !baseline
            && offered_per_participant > 0.0
            && bps < offered_per_participant * 0.9
            && (bps - per_source_bps).abs() < per_source_bps * CEILING_TOLERANCE
        {
            throttled += 1;
        }

        println!(
            "{:>4}  {:>20}  {:>7.2}%  {:>7.2}%  {:>9}  {:>9}  {:>9}",
            p.idx,
            fmt_bps(bps),
            v_loss,
            a_loss,
            fmt_ms(jitter),
            fmt_ms(percentile(&rtt, 0.5)),
            fmt_ms(percentile(&rtt, 0.95)),
        );
    }

    all_rtt.sort_unstable();
    let agg_bps = total_bytes as f64 / measured.as_secs_f64();
    let delivered_pct = if offered_total > 0.0 {
        agg_bps * 100.0 / offered_total
    } else {
        0.0
    };

    println!("── aggregate ───────────────────────────────────────────────");
    println!("measured window       {:.1}s", measured.as_secs_f64());
    println!(
        "delivered downstream  {} of {} offered ({delivered_pct:.1}%)",
        fmt_bps(agg_bps),
        fmt_bps(offered_total)
    );
    println!(
        "rtt                   p50 {}  p95 {}  p99 {}  max {}",
        fmt_ms(percentile(&all_rtt, 0.5)),
        fmt_ms(percentile(&all_rtt, 0.95)),
        fmt_ms(percentile(&all_rtt, 0.99)),
        fmt_ms(all_rtt.last().copied().unwrap_or(0)),
    );
    println!("worst per-class loss  {worst_loss:.2}%");

    println!("── diagnosis ───────────────────────────────────────────────");

    if baseline {
        println!(
            "control run — no plane in the path. These numbers are the harness, the kernel and\n\
             \x20  this box; subtract them from the plane run rather than reading them alone."
        );
    }

    // Source-address sanity first: every other conclusion is void if the participants collapsed
    // onto one egress bucket. Irrelevant without a plane — nothing is keying on the address.
    if !baseline && bind_ips.len() < n {
        let shared_ips = per_ip_bytes.len();
        println!(
            "!! {n} participants share {shared_ips} source IP(s). The plane's per-source egress\n\
             \x20  bucket is keyed on the destination IP, so those participants share ONE\n\
             \x20  {} ceiling instead of getting one each. Real clients have distinct\n\
             \x20  addresses — rerun with --bind-ips (see README) before drawing conclusions.",
            fmt_bps(per_source_bps)
        );
    }

    if silent > 0 {
        println!(
            "!! {silent}/{n} participants received nothing. Check the sim is running, the L4 port\n\
             \x20  is allocated (`jkbase l4 ls`), and the plane's flow/wake gates admitted them."
        );
    }

    if throttled > 0 {
        println!(
            "→  {throttled}/{n} participants landed within {:.0}% of the per-source ceiling {}.\n\
             \x20  That is the token bucket shaping conference media, not congestion. A 720p\n\
             \x20  fan-out needs more than the shipped default.",
            CEILING_TOLERANCE * 100.0,
            fmt_bps(per_source_bps)
        );
    }

    if !baseline
        && (agg_bps - per_project_bps).abs() < per_project_bps * CEILING_TOLERANCE
        && offered_total > per_project_bps
    {
        println!(
            "→  aggregate landed within {:.0}% of the per-project ceiling {} — the meeting is\n\
             \x20  capped platform-side, independent of per-participant shaping.",
            CEILING_TOLERANCE * 100.0,
            fmt_bps(per_project_bps)
        );
    }

    if !baseline && offered_total > DEF_PER_24_BPS && bind_ips.len() > 1 {
        println!(
            "note: offered aggregate exceeds the per-/24 backstop {}. If the bind IPs share a\n\
             \x20  /24 they also share that bucket — spread them across /24s to separate the two\n\
             \x20  effects.",
            fmt_bps(DEF_PER_24_BPS)
        );
    }

    if throttled == 0 && silent == 0 && delivered_pct >= 98.0 && worst_loss < 0.5 {
        println!("✓  clean run: no ceiling reached, loss under 0.5%, full offered rate delivered.");
    } else if throttled == 0 && silent == 0 && worst_loss >= 0.5 {
        println!(
            "→  loss {worst_loss:.2}% without a ceiling signature. Suspect the pump itself (CPU\n\
             \x20  per datagram) or the transit leg — compare against the no-plane baseline run\n\
             \x20  and check `l4-pump-bench` for the per-datagram cost."
        );
    }

    if json {
        println!(
            "{{\"participants\":{n},\"measured_secs\":{:.2},\"offered_bps\":{:.0},\
             \"delivered_bps\":{:.0},\"delivered_pct\":{delivered_pct:.2},\
             \"worst_loss_pct\":{worst_loss:.3},\"rtt_p50_ns\":{},\"rtt_p95_ns\":{},\
             \"rtt_p99_ns\":{},\"throttled\":{throttled},\"silent\":{silent},\
             \"distinct_source_ips\":{}}}",
            measured.as_secs_f64(),
            offered_total,
            agg_bps,
            percentile(&all_rtt, 0.5),
            percentile(&all_rtt, 0.95),
            percentile(&all_rtt, 0.99),
            per_ip_bytes.len(),
        );
    }
}
