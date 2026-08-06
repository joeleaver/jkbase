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
//! conference — it is modelling one very unlucky client.
//!
//! The reporter detects this from the addresses actually bound (not from the length of the list
//! the operator typed — a list with a duplicate is still one bucket) and, when it fires, draws NO
//! verdict at all rather than warning and then printing one anyway.

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
        "audio-streams",
        "speaker-kbps",
        "bind-ips",
        "limits-per-source-bps",
        "limits-per-24-bps",
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
             --visible-streams N    video tiles received per participant (0 = all N-1)\n\
             --audio-streams N      audio streams forwarded per participant (0 = all N-1).\n\
             \x20                      Default 3: real SFUs forward only the loudest few.\n\
             --speaker-kbps K       rate for ONE active-speaker tile (0 = all tiles equal).\n\
             \x20                      With simulcast the rest take the low layer, which is\n\
             \x20                      what --video-kbps should then be (~180).\n\
             \x20                      Large meetings do NOT send every camera at full rate;\n\
             \x20                      see the README before running 20+ without this.\n\
             --bind-ips A,B,C       source IPs, round-robin per participant\n\
             --limits-per-source-bps N   plane's per-source ceiling, for diagnosis\n\
             --limits-per-24-bps N       plane's per-/24 ceiling, for diagnosis\n\
             --limits-per-project-bps N  plane's per-project ceiling, for diagnosis\n\
             \x20                      (pass all three when the project has a limits override,\n\
             \x20                       or the diagnosis is made against stale defaults)\n\
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
    let per_24_bps: f64 = args.num("limits-per-24-bps", DEF_PER_24_BPS);
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
    // Lower bound: the sequence/stamp fields live in the first HDR_LEN bytes, so a smaller
    // datagram panics the writer mid-run. Only the upper bound was checked.
    if (video_bytes as usize) < l4wire::HDR_LEN || (audio_bytes as usize) < l4wire::HDR_LEN {
        eprintln!(
            "l4-load: packet sizes must be at least {}B (the wire header); got video={video_bytes} audio={audio_bytes}",
            l4wire::HDR_LEN
        );
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

    // BOTH fan-outs are capped, because a real SFU caps both.
    //
    // AUDIO is the one a naive model gets most wrong. mediasoup, Janus and Jitsi forward only the
    // loudest few streams (Jitsi calls it "last-N") and pause the rest server-side — ~3 streams at
    // any size, not N-1. At 50 participants the naive model is 16x too many, and because audio is
    // high-rate/small-packet it then dominates the packet count.
    //
    // VIDEO: simulcast exists so a gallery of thumbnails takes the LOW layer (~150-200kbps), with
    // one active-speaker tile at a higher one. Full quality to a postage stamp is precisely what
    // the encoder ladder avoids.
    let visible: u32 = args.num("visible-streams", 0);
    let audio_streams: u32 = args.num("audio-streams", 3);
    let speaker_kbps: u32 = args.num("speaker-kbps", 0);
    let peers = (n - 1) as u32;
    let video_fanout = if visible == 0 { peers } else { visible.min(peers) };
    let audio_fanout = if audio_streams == 0 {
        peers
    } else {
        audio_streams.min(peers)
    };

    // One tile at the speaker rate, the remainder at the (low-layer) tile rate.
    let speaker_pps = if speaker_kbps == 0 || video_fanout == 0 {
        0
    } else {
        (speaker_kbps as u64 * 1000 / 8 / video_bytes.max(1) as u64).max(1) as u32
    };
    let thumb_count = if speaker_pps > 0 { video_fanout - 1 } else { video_fanout };

    let down_profile = JoinProfile {
        v_pps: v_pps_stream * thumb_count + speaker_pps,
        v_bytes: video_bytes,
        a_pps: a_pps_stream * audio_fanout,
        a_bytes: audio_bytes,
    };

    let offered_per_participant = down_profile.offered_bps() as f64;
    let offered_total = offered_per_participant * n as f64;

    println!("── L4 load harness ─────────────────────────────────────────");
    println!("target                {target}");
    println!(
        "participants          {n} (fan-out per participant: {video_fanout} video, {audio_fanout} audio of {peers} peers)"
    );
    if speaker_pps > 0 {
        println!(
            "video layers          1 speaker tile @ {speaker_kbps}kbps + {thumb_count} tiles @ {video_kbps}kbps"
        );
    }
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
    if peers == 0 {
        println!("note                  1 participant ⇒ zero fan-out; downstream is idle by construction");
    }

    // Two sanity gates before a big run, because both failure modes look like "the plane is
    // broken" and neither is.
    if visible == 0 && n >= 20 {
        println!(
            "!! every participant is receiving all {peers} videos at {video_kbps}kbps. No SFU ships\n\
             \x20  that at this size — real ones send a few tiles at the simulcast LOW layer\n\
             \x20  (~150-200kbps). Pass --visible-streams with a low --video-kbps, or this run\n\
             \x20  measures a workload no conference product generates."
        );
    }
    if audio_streams == 0 && n >= 20 {
        println!(
            "!! forwarding all {peers} audio streams to every participant. Real SFUs forward only\n\
             \x20  the loudest few (typically 3) and pause the rest server-side — at this size\n\
             \x20  that difference alone is most of the packet count."
        );
    }
    if video_kbps >= 500 && video_fanout > 4 {
        println!(
            "note: {video_kbps}kbps per tile across {video_fanout} tiles is full-quality video for\n\
             \x20  thumbnails. With simulcast a gallery takes the low layer: --video-kbps 180 plus\n\
             \x20  --speaker-kbps for the one tile that is actually large."
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
            // The overwhelmingly common cause, and one a bare EINVAL does not explain: the kernel
            // refuses to route from a loopback source to a non-loopback destination. Following the
            // README's source-IP setup (127.0.1.x aliases) and then targeting a remote host lands
            // here at participant 0, before any traffic, and the raw errno reads like a bug in the
            // plane rather than a setup mistake.
            if bind_ip.is_loopback() && !target.ip().is_loopback() {
                eprintln!(
                    "\n\
                     l4-load: the source IP {bind_ip} is on loopback but the target {} is not.\n\
                     Linux will not route a loopback source off-box, so this can never connect.\n\
                     \n\
                     Loopback source IPs only work against a loopback target (the --baseline\n\
                     control run). For a run through the plane on a remote host you need N REAL\n\
                     addresses on a routable interface:\n\
                     \n\
                     \x20   sudo BASE=<your-subnet-prefix> DEV=<your-nic> ./setup-source-ips.sh add {n}\n\
                     \x20   ./run.sh plane <host> <port>\n\
                     \n\
                     Distinct sources matter because the plane's per-source egress bucket is keyed\n\
                     on the destination IP: without them all {n} participants share ONE bucket and\n\
                     the run measures that bucket instead of the pump.",
                    target.ip()
                );
            }
            std::process::exit(1);
        }
        // Sized so a scheduling hiccup doesn't overflow the kernel queue and get counted as plane
        // loss. Checked once, on participant 0, since the sysctl ceiling is process-wide.
        let (rcv, _snd) = l4wire::set_socket_buffers(&sock, l4wire::SOCK_BUF_BYTES);
        if idx == 0 && rcv < l4wire::SOCK_BUF_BYTES / 2 {
            eprintln!(
                "l4-load: warning — asked for {}B of socket receive buffer, kernel granted {rcv}B.\n\
                 \x20 net.core.rmem_max is clamping it. At conference rates a receive-queue\n\
                 \x20 overflow is indistinguishable from plane loss, so raise it before trusting\n\
                 \x20 a loss number:  sudo sysctl -w net.core.rmem_max={}",
                l4wire::SOCK_BUF_BYTES,
                l4wire::SOCK_BUF_BYTES
            );
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
    // Clear every participant's accumulators HERE, in one place, rather than lazily on each
    // participant's next arrival. The lazy reset only ran when a datagram showed up after the
    // boundary, so a participant that received NOTHING in the measured window never reset and
    // reported its WARM-UP bytes as measurement-window results: a total delivery blackout printed
    // as `0.00% loss`, `silent = 0`, and — because delivered% was below the clean bar while loss
    // was below the pump bar — no diagnosis line at all. That is the one failure mode a load
    // harness must never have.
    for p in &participants {
        *p.stats.lock().unwrap() = RxStats {
            reset_done: true,
            ..Default::default()
        };
    }
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
            per_24_bps,
            baseline,
        },
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
        // Half the per-source burst each: this participant's video and audio series send to the
        // same destination, so they share ONE token bucket and coincident batches would otherwise
        // overshoot it by 2x — manufacturing drops the reporter would then have to explain.
        let mut pacer = Pacer::new(
            pps,
            size as u32,
            l4wire::PER_SOURCE_BURST_BYTES / 2,
            Instant::now(),
        );
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
    per_24_bps: f64,
    /// No plane in the path. The ceilings below belong to the plane, so applying them to a
    /// control run would invent findings the run cannot possibly support.
    baseline: bool,
}

fn report(
    participants: &[Participant],
    measured: Duration,
    c: Ceilings,
    n: usize,
    json: bool,
) {
    let Ceilings {
        offered_per_participant,
        offered_total,
        per_source_bps,
        per_project_bps,
        per_24_bps,
        baseline,
    } = c;
    println!("── per participant ─────────────────────────────────────────");
    println!(
        "{:>4}  {:>20}  {:>8}  {:>8}  {:>9}  {:>9}  {:>9}",
        "#", "downstream", "v-loss", "a-loss", "jitter pk", "rtt p50", "rtt p95"
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
        // PEAK, not the terminal EWMA sample: at conference packet rates the 1/16 gain has
        // ~5ms of memory, so the final reading describes the end of the run rather than the run.
        let jitter = (s.video.jitter_peak_nanos.max(s.audio.jitter_peak_nanos)) as u64;

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

    // Every ceiling that could explain a shortfall feeds ONE verdict chain. Keeping these as
    // independent `if`s is how the reporter used to announce a per-project ceiling AND a pump
    // finding for the same run, and how the README's own 50-way profile — two ceilings deep —
    // reported "suspect the pump".
    let mut ceiling_hit = false;
    // Set when the run's premise is broken, so no verdict at all may be drawn from it.
    let mut attribution_void = false;

    // Source-address sanity first: every other conclusion is void if the participants collapsed
    // onto one egress bucket. Irrelevant without a plane — nothing is keying on the address.
    //
    // Gate on the addresses actually BOUND, not on how many strings the operator typed. The old
    // `bind_ips.len() < n` test was satisfied by `--bind-ips 127.0.0.1,127.0.0.1,127.0.0.1`, which
    // is three entries and one bucket — any list containing a duplicate silently disabled the
    // whole check while the run's own JSON reported `distinct_source_ips: 1`.
    let distinct_sources = per_ip_bytes.len();
    if !baseline && distinct_sources < n {
        let shared_ips = distinct_sources;
        attribution_void = true;
        println!(
            "!! {n} participants share {shared_ips} source IP(s). The plane's per-source egress\n\
             \x20  bucket is keyed on the destination IP, so those participants share ONE\n\
             \x20  {} ceiling instead of getting one each. Real clients have distinct\n\
             \x20  addresses — rerun with --bind-ips (see README) before drawing conclusions.\n\
             \x20  NO verdict is drawn below: this run cannot separate shaping from pump loss.",
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
        ceiling_hit = true;
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
        ceiling_hit = true;
        println!(
            "→  aggregate landed within {:.0}% of the per-project ceiling {} — the meeting is\n\
             \x20  capped platform-side, independent of per-participant shaping.",
            CEILING_TOLERANCE * 100.0,
            fmt_bps(per_project_bps)
        );
    }

    // Per-/24 is a real gate, not a footnote. Every source IP sharing a /24 shares ONE bucket, so
    // compare each /24's DELIVERED aggregate against the ceiling — the previous code only warned
    // that the OFFERED total exceeded it and never detected a hit, which is how a run shaped by
    // this bucket fell through to the pump branch.
    if !baseline {
        let mut per_24: HashMap<[u8; 4], u64> = HashMap::new();
        for (ip, bytes) in &per_ip_bytes {
            if let IpAddr::V4(v4) = ip {
                let o = v4.octets();
                *per_24.entry([o[0], o[1], o[2], 0]).or_default() += bytes;
            }
        }
        let shaped: Vec<_> = per_24
            .iter()
            .filter(|(_, &b)| {
                let bps = b as f64 / measured.as_secs_f64();
                (bps - per_24_bps).abs() < per_24_bps * CEILING_TOLERANCE
            })
            .collect();
        if !shaped.is_empty() && offered_total > per_24_bps {
            ceiling_hit = true;
            println!(
                "→  {} /24 block(s) landed within {:.0}% of the per-/24 ceiling {}. Source IPs\n\
                 \x20  sharing a /24 share that bucket — spread them across /24s to separate this\n\
                 \x20  from per-source shaping.",
                shaped.len(),
                CEILING_TOLERANCE * 100.0,
                fmt_bps(per_24_bps)
            );
        }
    }

    // The verdict. Gated on EVERY ceiling detector, not just per-source, and suppressed entirely
    // when the run's premise is void — a pump finding is the one conclusion that would send
    // someone hunting a bug in production code, so it must be the hardest to reach.
    if attribution_void {
        // Already explained above; drawing a verdict here would contradict that warning.
    } else if ceiling_hit {
        println!(
            "→  config finding: the run met at least one platform ceiling above. Raise the\n\
             \x20  relevant limit and re-run before concluding anything about the pump."
        );
    } else if silent == 0 && delivered_pct >= 98.0 && worst_loss < 0.5 {
        println!("✓  clean run: no ceiling reached, loss under 0.5%, full offered rate delivered.");
    } else if silent == 0 && worst_loss < 0.5 && delivered_pct < 98.0 {
        // The arm that was missing, and the reason a blackout could pass silently: delivery well
        // under what was offered, yet almost no LOSS. Loss is derived from the sequence span of
        // what arrived, so a stream that is simply slower — or absent — is internally consistent
        // and scores ~0%. Both plausible causes are the harness's own, not the plane's, so this
        // must never be read as a pump finding.
        println!(
            "!! delivered only {delivered_pct:.1}% of the offered rate, but per-class loss is\n\
             \x20  {worst_loss:.2}% — the sequence stream is intact, just short. Loss cannot see\n\
             \x20  this: a generator that never sent, or a sim whose emitter was starved, produces\n\
             \x20  a CONTIGUOUS stream at a lower rate and scores 0%.\n\
             \x20  Check the sim's /stats (down_packets, send_errors) against what arrived before\n\
             \x20  concluding anything about the plane. NO verdict is drawn from this run."
        );
    } else if silent == 0 && worst_loss >= 0.5 {
        println!(
            "→  loss {worst_loss:.2}% with NO ceiling signature{}. Suspect the pump itself (CPU\n\
             \x20  per datagram) or the transit leg — compare against the no-plane baseline run\n\
             \x20  and check the `l4_pump_cpu_cost` probe for the per-datagram cost.\n\
             \x20  Confirm against the plane's own counters before acting: a drop no\n\
             \x20  `egress_*` counter explains is the pump finding; one they do explain is not.",
            if baseline {
                " (baseline run — no plane in the path, so this is the harness or this box)"
            } else {
                ""
            }
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
