# L4 UDP load harness

Answers one question the L4 plane has never been asked: **does the datagram pump hold at SFU
media rates?**

Every workload the plane was designed and tested against — a voice server, a game server — is
tens of packets per second across a handful of flows. A conference SFU behind mediasoup's
`WebRtcServer` is a different animal: one UDP port, one flow per participant, and an *egress* leg
carrying `K × (K−1)` fan-out streams. At 10 participants that is roughly **17k packets/s and
19 MiB/s outbound**; at 20, **71k pps and 79 MiB/s**. Everything the pump does per datagram — the
transit HMAC seal/open, the flow-table lookup, the four-level egress token-bucket chain — runs at
that rate, and the plane's shipped ceilings sit *below* it.

## What it will tell you before you run it

From `L4PlaneLimits::default()` in `crates/jkbase-proxy/src/l4_plane.rs`:

| Ceiling | Default | What a conference offers |
|---|---|---|
| `per_source_bps` (per **destination IP**, i.e. per participant) | 1 MiB/s | ~1.7 MiB/s for 9 × 720p fan-out |
| `egress_per_24_bps` | 8 MiB/s | exceeded by ~5 participants in one /24 |
| `egress_per_project_bps` | 16 MiB/s | exceeded by ~10 participants |
| `egress_global_bps` | 64 MiB/s | ~1 medium meeting, platform-wide |
| `flow_per_project_max` | 256 | 1 flow per participant — never the binding constraint |

So the harness is expected to hit ceilings. That is a **configuration** finding with an obvious
fix (per-project limits, in the shape of the existing `QuotaLimits` override). The finding worth
the effort is the other one: **loss or latency with no ceiling signature**, which means the pump
itself. The reporter separates the two and says which it saw.

## Two halves

- **`l4-sfu-sim`** — the guest. Deployed as a jkbase project behind an `[l4.*]` UDP port. Admits
  a flow per `JOIN` and fans an **unsolicited** downstream back at it at the requested rate.
  Deliberately not an echo: an echo can never trip `egress_per_source`, `egress_per_24`,
  `egress_per_project` or `RatioCredit`, because those only fire when egress outruns ingress —
  the defining shape of an SFU and the exact opposite of an echo.
- **`l4-load`** — the client. K virtual participants, each one flow: uplink of one video + one
  audio stream, downlink of the `(K−1)` fan-out. Measures per-class loss (span-based, so
  reordering is not miscounted as loss), RFC 3550 jitter, RTT percentiles and delivered
  throughput, then diagnoses the result against the ceilings above.

Plus a CPU-cost probe living with the code it measures:

```bash
cargo test -p jkbase-proxy --release -- --ignored --nocapture l4_pump_cpu_cost
```

It reports ns/datagram for the transit crypto and the egress chain, a single-core pps ceiling,
and the pps a conference actually needs. It measures the **pure-CPU** portion only — the real
pump adds two syscalls and a TAP crossing per datagram, which usually dominate. If this probe
alone can't clear the requirement, the end-to-end run cannot either; that is the only inference
it supports.

## Running it

### 1. Source addresses (read this first)

The per-source egress bucket is keyed on the **destination IP of the reply** — one bucket per
client address. K participants from one address share **one** 1 MiB/s bucket instead of getting K
of them, which manufactures catastrophic loss that means nothing. Real clients have distinct
addresses; the harness must too.

```bash
sudo ./setup-source-ips.sh add 24      # 127.0.1.1 .. 127.0.1.24
./setup-source-ips.sh list 24          # the --bind-ips list
sudo ./setup-source-ips.sh del 24      # afterwards
```

Those aliases share a /24, so they still share the per-/24 backstop. That is right for isolating
the per-source cap and wrong for isolating the per-project one — to separate those, spread
aliases across several /24s on a dummy interface. `l4-load` refuses to draw conclusions when it
detects participants collapsed onto one address.

### 2. Baseline first

```bash
./run.sh baseline
```

Generator straight at the simulator, no plane. This is the control: it measures the harness, the
kernel and the box. Any loss here is yours, not the plane's, and a plane run without a baseline
to subtract is uninterpretable.

### 3. Deploy the guest and run through the plane

```bash
cd tools/l4-load
jkbase project create l4-load-sim
jkbase deploy
jkbase l4 ls --project l4-load-sim     # → the public external_port
./run.sh plane <platform-host> <external_port>
```

Or `./run.sh both <host> <port>` to run baseline and plane back to back and print the delta.

While a run is in flight, the guest's own view is at `/stats` over the ordinary HTTPS route —
the only way to distinguish "the plane dropped it" from "the simulator never sent it".

### 4. Attribute the drops

The plane's per-reason counters (`L4Counters` in `l4_plane.rs`) are drained on the metering tick
in `jkbase-server`. Watch the server log across the run: `egress_per_source`, `egress_per_24`,
`egress_per_project`, `egress_global` and `egress_amp_clamp` each name a specific ceiling, while
`flow_full_*`, `rate_cap` and `budget_full` mean the run never got admitted in the first place.
A drop the harness sees and no counter explains is the interesting case.

## Reading a result

- **`✓ clean run`** — no ceiling reached, <0.5% loss, full offered rate. The pump held at this
  scale. Raise `--participants` until something gives.
- **`→ N participants landed within 12% of the per-source ceiling`** — a token bucket shaping
  conference media. Config finding: the SFU needs a per-project limits override.
- **`→ loss without a ceiling signature`** — the pump or the transit leg. Compare against the
  baseline and check the CPU probe. This is the finding that would block putting an SFU here.
- **`!! participants received nothing`** — never admitted. Check `jkbase l4 ls`, the wake gates
  and the health check, not the media path.

## Scale knobs

```bash
PARTICIPANTS=20 DURATION=120 VIDEO_KBPS=2500 ./run.sh both <host> <port>
```

`--video-bytes` / `--audio-bytes` set packet sizes (both must stay under the 1500B MTU — above
it the transit leg fragments and the loss numbers stop meaning what they say; the agent lowers
the guest loopback MTU for exactly this reason).

### Running 40–50 participants

Set `VISIBLE`. Video fan-out defaults to *every* camera, which is right at 10 and fiction at 50:
50 × 49 × 1500kbps is **3.8 Gbps**, a number that measures your NIC and nothing else. Real SFUs
send a few visible videos plus simulcast low layers, while forwarding everyone's audio — so
video fan-out is capped and audio fan-out is not.

```bash
sudo ./setup-source-ips.sh add 50
PARTICIPANTS=50 VISIBLE=9 VIDEO_KBPS=600 DURATION=120 ./run.sh both <host> <port>
```

That profile (9 visible at a 600kbps simulcast layer, 49 audio) is what a 50-way meeting really
offers, and it lands here:

| | Per participant | Aggregate |
|---|---|---|
| Offered | 891 KiB/s | 43.5 MiB/s, ~104k pps |
| vs `per_source_bps` (1 MiB/s) | **87% of the cap** | — |
| vs `egress_per_project_bps` (16 MiB/s) | — | **2.7× over** |
| vs `egress_global_bps` (64 MiB/s) | — | **68% of the whole platform** |

So a single 50-way meeting is over the per-project ceiling by 2.7× and eats two thirds of the
platform-wide budget, while each participant sits just under the per-source cap — one bad tile
layout or a bitrate bump puts them over it too. Raising those limits is a prerequisite for this
workload, not a tuning exercise.

The CPU side is comfortable at that scale: ~104k pps against 738k pps/core (video) means the
transit crypto costs well under a tenth of a core. Syscalls and the TAP crossing are what the
end-to-end run is actually there to measure.

The harness itself has been verified to 50 participants at 449 MiB/s (3.8 Gbps) on loopback with
zero loss, so it will not be the bottleneck — but always confirm the baseline reaches your target
rate before believing a plane run at the same settings.

## Design notes

Zero dependencies, on purpose: `l4-sfu-sim` builds inside a network-fenced build VM, so no
crates.io fetch and no buildpack surprises. Standalone workspace (like `tools/rhypedb-probe`), so
it never resolves for `cargo build --workspace` or CI.

The harness paces from a fixed origin rather than `now + interval`, so a slow send never lets the
offered rate drift quietly below target — a load generator that under-offers and then reports the
shortfall as the plane's fault is worse than no harness at all. Above 2k pps it spins rather than
sleeps, because `thread::sleep` granularity exceeds the interval there.
