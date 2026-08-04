# jkbase — Smarter L4 UDP limiting (arc design)

> Status: **design (v2 — re-centered for arbitrary workloads)**. Follow-on arc to the L4 UDP
> scale-to-zero ingress seam (`docs/managed-l4-udp-ingress-design.md`). Triggered by the first real
> external UDP consumer — a TeamSpeak 3 (TS3) voice server in `corporate-legion-ts3-staging` — whose
> server→client channel sync was silently clamped to death by the per-flow anti-reflection amp-clamp.
>
> **Design goal (load-bearing):** the platform must support **arbitrary user-generated UDP
> workloads** from untrusted tenants — bursty or sustained, symmetric or wildly asymmetric,
> unicast or high-fan-out broadcast — *without* per-tenant admin babysitting and *without* becoming
> a reflection amplifier. We do **not** design for a predicted traffic shape.
>
> Produced via recon → multi-agent diagnosis (4 lenses + adversarial refuter) → fix-candidate design
> (3 approaches, each with a re-derived reflection bound) → adversarial probe → re-center on the
> arbitrary-workload mandate. Each implementing PR on this untrusted seam gets the multi-agent
> adversarial pre-merge review (`CLAUDE.md`).

## 0. TL;DR

- **Root cause (empirically confirmed on prod):** the per-flow amplification clamp
  (`RatioCredit`, `amp_k` default 1, single-datagram `C0`≈1500 B) drops TS3's asymmetric
  server→client sync as `egress_amp_clamp`. Prod `l4_metrics` during the failure:
  `egress_amp_clamp=82, c0_grants=1, promotions=1`, **every absolute cap 0**. Not socket/demux/lifecycle.
- **The correction:** you **cannot** distinguish a legit asymmetric app from a reflection spoofer
  with any *in-band* signal (design §1.1) — and this **generalizes to fan-out**: a real broadcast
  server spraying 200 clients is byte-for-byte indistinguishable from a booter spraying 200 victims
  (high ratio, high destination entropy). So neither the per-flow ratio clamp nor the dest-entropy
  arm is a sound *default gate* for arbitrary workloads.
- **The re-centered model:** protect third parties with **workload-agnostic** levers only —
  **absolute per-victim/-24/global rate caps** (bound *concentration*, never *ratio*, so they never
  break a legit app) + **per-tenant egress metering + budget + accountability** (the economic
  deterrent that removes "free + anonymous"). **Retire the per-flow ratio amp-clamp as the default
  gate** — it adds almost no third-party protection over the absolute caps, and its only marginal
  effect ("attacker must spend 1× their own bandwidth") is served better by *billing egress*
  (attacker pays money, and is attributable) without breaking every asymmetric app.
- **The economic bound already exists (corrected by the pre-merge review):** L4 transit crosses the
  tenant VM's **TAP** (the host↔guest legs go over the VM NIC), so `read_tap_bytes` **already meters
  L4 traffic** toward the per-project monthly bandwidth cap — over-cap hibernates the project and
  `wake_project` refuses re-wake (`WakeError::OverQuota`). An earlier draft of this arc wrongly
  believed L4 "bypasses the TAP" and added a second per-payload accrual — that **double-counted**
  and doubled an attacker-controllable quota-DoS (the un-rate-capped ingress leg), and was reverted.
  So W-econ is **not** "add L4 metering"; it is **retire the clamp** — the existing TAP metering is
  the metered economic bound that replaces it.

## 1. The principle — you cannot shape-gate arbitrary workloads

The L4 doc's §1.1 proves return-routability is impossible for stock UDP: an off-path spoofer has
full send / zero receive, and **the guest app replies to the spoofer's own flood**, so every
host-observable "two-way / kept-sending / ping-pong" signal is free to fake. This arc's mandate
forces the same conclusion one step further: for **arbitrary** workloads, the *shape* signals the
current design leans on — the egress:ingress **ratio** and the destination **entropy** — are *also*
exactly what a legitimate high-fan-out app produces. A game server broadcasting world-state to 300
players and a booter spraying 300 victims are in-band identical. **There is no in-band discriminator,
and there is no traffic shape we can assume.**

So the reflection bound for arbitrary workloads can rest only on levers that do **not** inspect
shape:

- **(a) Absolute rate caps, keyed on the reply destination** — per-source(IP) 1 MB/s / 64 KiB
  burst, per-/24 8 MB/s, global 64 MB/s (`L4PlaneLimits`, `l4_plane.rs:133-139`). These cap the
  *rate at any victim/network/platform*, never the *ratio* — so a legit asymmetric app is never
  broken (a genuinely large broadcaster just needs more egress **budget**, i.e. pays more), while
  no third party can be flooded faster than the cap **regardless of what any tenant runs**. Prod
  proves these never fire for a normal app (all 0 during the TS3 failure).
- **(b) Metered per-project budget + accountability** — L4 traffic already crosses the tenant VM's
  TAP, so it is **already metered** toward the per-project **monthly bandwidth cap** (over-cap ⇒
  hibernate + `wake_project` `OverQuota` refuses re-wake), and every tenant is identified, so abuse
  is **attributable + terminable**. This is the economic deterrent: a booter is worth building only
  because reflection is *free* and *anonymous*; metered, capped, attributable, terminable egress is
  neither. *Honest limitation:* the bound is per-**project** (16 MB/s rate + monthly cap) + global
  (64 MB/s), not a real-time per-**tenant** ceiling — a tenant with N clamp-off projects can source
  up to `min(N×16, 64)` MB/s until the monthly cap trips (see §5). Adding a per-tenant real-time
  egress dimension is a follow-on.

The per-flow **ratio amp-clamp** — the thing that broke TS3 — is redundant with (a) for third-party
protection (the absolute caps already bound every victim/network/global rate) and uniquely
incompatible with arbitrary asymmetric workloads. Its *only* marginal contribution is forcing the
attacker to spend 1× their own upstream bandwidth — a goal that **egress billing** (b) achieves
better (money, not bandwidth) without collateral damage. **Retire it as the default gate.**

### Two harm categories (still the organizing split)

- **(A) Self-protection** (wake/warm/RAM/flow): harm is our own RAM/CPU/boots, observable +
  reversible → make it **pressure-adaptive** (W4).
- **(B) Third-party reflection** (egress): harm is externalized + irreversible → keep the bound
  **provable via absolute caps + economics**, never via in-band shape.

## 2. The confirmed root cause (and why the return-leg hypothesis was off)

Decisive argument: **size-selectivity.** For TS3 to log `client connected`, the client had to
*receive* the small `TS3INIT`/command-channel replies — so the return leg **works for small
datagrams** and fails only on the **large** channel/permission sync. Every gate in `return_decide`
(`l4_ingress.rs:551-627`) except the byte-metered `RatioCredit` (`l4_egress.rs:123`) is
**size-agnostic** — a demux/epoch/nonce/lifecycle break would have killed the handshake replies too.
Only a byte-credit gate passes 34-byte replies and starves a 500-byte-×-N burst. Prod corroborates:
`egress_amp_clamp` spikes (82, 77, 196…) while `header_auth_fail/nonce_replay/stale_epoch/flow_full_*`
stay 0. The reporter's socket/demux/lifecycle subsystems are **silent**. (`C0` is spent on the first
reply exceeding accrued credit — the first large sync datagram; the multi-KB sync then clamps to ~1×
the client's small forward traffic → TS3 ~22 s resend timeout. Reconnect within 60 s is worse:
`c0_used` carries over, so the reconnect gets no `C0` at all — prod `c0_grant_rejected=26`.)

The reporter's return-leg instinct wasn't wrong in general — see the W0 latent bug of exactly that
shape. It just isn't TS3's cause.

## 3. Why an in-band "smarter" gate is unsound (the correction that reshaped this arc)

The tempting idea — relax the ratio once a flow proves *bidirectional liveness* — **does not work**.
A blind spoofer (`src=victim`) has full send / zero receive; the guest replies to its *own* injected
ingress, so `bytes_out>0`, "ingress continues after egress," and ping-pong timing are all satisfied
*without the attacker receiving a byte*. The only true discriminator (ingress content proving receipt
of a prior reply) is proof-of-reception = parsing the app wire = out of scope + §1.1-impossible.
Any in-band gate that opens a larger allowance opens it for the spoofed victim-flow too (100%
false-accept). The harmless case (a **non-spoofed** real client) genuinely exists but is
**in-band-indistinguishable** from the spoofed one. Trust for anything beyond the absolute caps must
come from **outside the packet stream**: economic accountability (W-econ) or, as a narrow escape
hatch, a human (W-admin).

## 4. The arc

### W0 — Latent return-leg bug fixes (small, ship first, independent of the re-architecture)

1. **`FLOW_IDLE_TTL` < host idle ceiling → `NonceReplay` blackout.** Agent reaps a flow at
   `FLOW_IDLE_TTL=120 s` (`l4_forward.rs:80`); host keeps flows live to `idle_timeout` ceiling
   **600 s** (`config.rs:894`). A port with `idle_timeout ∈ (120,600]` that goes bidirectionally
   quiet 120–600 s: agent evicts while host stays live at the same epoch → on re-wake the new
   `ReplyPump` restarts `out_nonce=1` into host `in_nonce_hw`≈N → ~N-datagram return-leg blackout
   (`l4_ingress.rs:585`) + app session reset (mech H4). **Fix:** drive `FLOW_IDLE_TTL` from the
   per-port `idle_timeout` (or ≥600 s + headroom); e2e it. *This is the exact return-leg shape the
   reporter hypothesized — real, just not TS3's.* Agent-side (agent-rootfs, no toolchain rebake).
2. **Sticky edge socket won't hot-apply an egress-policy change.** `amp_k` / any egress policy only
   takes effect on a fresh bind, not a redeploy (`…-design.md` §10). Reconcile-loop rebind on
   `PortAllocation` change, bind-new-before-drop-old (no ingress gap). Prereq for any live
   egress-policy change (W-econ budget, W-admin grant).

### W-econ — Retire the ratio clamp; the existing TAP metering is the economic bound (**CENTERPIECE**)

The heart of the re-architecture. Makes arbitrary asymmetric workloads work by default while keeping
the reflection bound provable. **As-built (post-review):**

- **L4 egress is ALREADY metered — no new metering code.** L4 transit crosses the tenant VM's TAP,
  so `read_tap_bytes` already counts it toward the per-project monthly bandwidth cap + over-quota
  hibernation (`main.rs`), and `wake_db_reach → wake_project` refuses re-wake of an over-quota
  project (`WakeError::OverQuota`). *(An earlier attempt to add a second per-payload accrual
  double-counted and doubled an attacker-controllable quota-DoS via the un-rate-capped ingress leg;
  it was reverted — the TAP already does this wire-accurately.)*
- **Retire the per-flow `RatioCredit` amp-clamp + one-shot `C0` as the default gate.** `amp_k`
  omitted/0 ⇒ clamp OFF (`config.rs`); `1..=3` ⇒ opt-in shaper. `return_decide` runs the
  `RatioCredit`+`C0` gate only when `amp_k != 0`; the absolute aggregate caps
  (`try_egress_aggregate`) run **unconditionally**. Third-party protection is now: absolute
  per-victim/-24/-project/global caps (concentration) + the metered per-project monthly cap
  (economics) + accountability. **Load-bearing:** the readback seams (`read_l4_port_decls`,
  `resolve_spec`) must resolve `amp_k` with the SAME 0-default as the bake, or the retirement is a
  runtime no-op (review BLOCKER — fixed + regression-tested).
- **Kill-switch:** auto-hibernate fires only for `amp_k != 0` ports (opt-in shaper); a clamp-off
  port's shape signal is attributed + alerted (`reflection_shape_flagged` counter + `warn!`), never
  auto-killed (§1.1). The `RefWindow` `amp_k` is sticky-**max** over the window (a base mixing a
  clamp-off and a shaped port keeps the shaper's kill-switch armed; defeats the trickle-to-evade
  attack).
- **Reviewed** (multi-agent adversarial pass): P0-L4-6 ceiling confirmed byte-for-byte unchanged;
  BLOCKER (no-op retirement) + HIGH (double-count) + 2 MEDIUM fixed. See §5 for the re-derived bound.

### W-killswitch — Re-scope the kill-switch from auto-hibernate to alert + clamp + attribute

The current kill-switch force-hibernates a base on sustained-ratio **or** dest-entropy
(`l4_plane.rs:870-883`, `main.rs:6571`). For arbitrary workloads that **auto-kills a legit
high-fan-out app** (entropy) or a legit asymmetric app (ratio). Re-scope: on the signature, **clamp
that base to its absolute caps + per-tenant budget, attribute it, alert a human/policy engine, and
(for a metered+identified tenant) let it keep running within budget** — reserve force-hibernate for
the unattributable/over-budget/flagged-abuse case. The signature stops being "definitely an attack"
and becomes "needs a human/economic decision."

### W-admin — Admin per-port egress ceiling / budget override (**escape hatch, demoted**)

Was the v1 centerpiece; now a narrow escape hatch: an admin raises a *specific vetted* tenant/port's
egress budget above the plan default (or exempts an optional per-port soft clamp). Same trust
boundary (grant on the `PortAllocation` store record, **never** the tenant sidecar; admin-token
gated; audit-logged). Useful for a known big-broadcast tenant; **not** the mechanism arbitrary
self-serve workloads rely on.

### W-C0 (conditional) — Windowed one-shot allowance, only if a soft default clamp is retained

If (per the accountability answer, §7) a hard-ish default bound must persist for anonymous/free
tenants, the least-harmful form is a **per-account egress budget** (W-econ), **not** the ratio clamp.
The windowed-`C0` idea (generalize the single-datagram one-shot to a bounded handshake window)
only matters if a *ratio* default is kept — largely mooted by retiring the clamp. Keep on the
shelf; do not build unless the clamp is retained as the default.

### W4 — Pressure-adaptive self-resource limits + observability loop (category A + visibility)

- **Adaptive self-limits:** make wake/warm/RAM/flow caps adapt to real host pressure
  (`/proc/meminfo`, loadavg, boot latency, warm count) instead of static guesses; conservative
  static floor as failsafe. Untouched by §1.1 (not a reflection surface) → pure win.
- **Observability:** the counters exist but nobody watches them (how the TS3 breakage was found).
  Alert a human on the **attack/over-budget signature** *and* — post-clamp-retirement — on a
  base repeatedly hitting its **absolute caps / egress budget** (a real app that needs a bigger
  plan, or an attacker to review). Output is a human/economic decision, never a code self-grant.

## 5. Reflection bound — what changes, what never does

**Invariant: no THIRD-PARTY cap changes.** Every per-source(IP)/-24/global ceiling is byte-for-byte
unchanged, so no victim, network, or the platform can be made to receive more than today —
independent of workload. Note what this invariant does and does not cover: it is about what a third
party RECEIVES. The **per-project** aggregate is not in it, because it bounds how much one tenant
may EMIT in total, across all destinations — raising it cannot concentrate any more traffic on a
victim, a /24, or the platform, since those three still bind afterwards.

| Lever | Sustained ratio / victim | Absolute rate / victim IP | Per-/24 | Per-project | Global |
|---|---|---|---|---|---|
| **Today (ratio clamp on)** | ≤ 1× (attacker pays 1× bandwidth) | ≤ 1 MB/s | ≤ 8 MB/s | ≤ 16 MB/s | ≤ 64 MB/s |
| **Re-centered (clamp retired)** | unbounded *ratio* (any asymmetric app works) | ≤ 1 MB/s (**unchanged**) | ≤ 8 MB/s (**unchanged**) | ≤ 16 MB/s (**unchanged**) | ≤ 64 MB/s (**unchanged**) |
| **+ per-project limits (W-admin)** | unbounded *ratio* | ≤ 1 MB/s (**unchanged**) | ≤ 8 MB/s (**unchanged**) | ≤ 16 MB/s default (**unchanged**); an admin grant may raise a NAMED project | ≤ 64 MB/s (**unchanged**) |

The honest trade: retiring the ratio clamp raises the reflection **factor** (an attacker no longer
spends 1× bandwidth) but **not** the reflection **ceiling** at any victim/network/project/platform —
those were always the absolute caps, which prod shows are the real (and never-firing-for-legit)
bound. The "attacker pays" deterrent moves from *their bandwidth* to *their money + identity*
(existing per-project monthly bandwidth cap via the TAP + terminate-on-abuse). Platform-wide
reflection stays hard-capped at the global 64 MB/s and ≤8 MB/s at any one victim network, regardless
of workload or account count.

**Two honest regressions the review surfaced (ceiling intact, but):** (i) **duration** — a clamp-off
port has no ~60 s auto-hibernate, so a victim can be held at the ≤1 MB/s ceiling for the attack's
duration; mitigated by the `reflection_shape_flagged` alert → human/terminate, not by auto-kill
(which would strangle legit broadcasters). (ii) **per-tenant real-time** — aggregate caps stop at
per-project (16 MB/s), so an identified tenant with ≥4 clamp-off projects can source the full
global 64 MB/s until the monthly cap trips (hours). **Each admin grant that raises a project's
aggregate lowers that project count**, which is the cost an operator accepts when issuing one.
Compounding it, global is a single first-come-first-served bucket with **no per-tenant fair
share** (unlike `flow_global_fair_share` / `wake_fair_share`) — and because refusal is
arrival-order, a heavier sender issues proportionally more attempts and wins the refill race, so
starvation is self-reinforcing toward the largest tenant. A per-tenant real-time egress dimension
(≤ global) and a global fair share are the follow-on; for now the bound is per-project + global +
monthly cap + attribution.

**Open, deliberately not changed here:** `egress_global_bps` is a hardcoded 64 MB/s with **no
configuration path at all** — production constructs the plane with `L4PlaneLimits::default()`
(`main.rs`), and outside `l4_plane.rs` every reference is a test. It is neither derived from the
host's link (prod's uplink is 1000 Mbps, so 64 MB/s ≈ 54% of it) nor validated against one, and it
has never fired in production. Deriving it from the real uplink would be more honest than either
constant, but it IS one of the three third-party ceilings above, so it gets its own change and its
own residual argument rather than riding along with this one.

**The residual that the accountability model governs (§7 — RESOLVED):** jkbase has **no anonymous
accounts** (every tenant is identified; "unlimited" = a trusted super-user class only), so an
attacker pays for and is de-anonymized by their own reflection → booter economics collapse, and the
account-spraying attack that would otherwise defeat the per-tenant budget **does not apply.** No
signup-friction prerequisite; retire the clamp by default.

## 6. Build order, review, deploy

1. **W0** — smallest, independent, ships first. (Agent + host.)
2. **W-econ** — the centerpiece: meter L4 egress into the per-project budget, add the per-tenant
   egress budget, retire the ratio clamp as the default gate. Host-binary-only (agent leg untouched).
   Confirm on prod: `egress_amp_clamp` flat on a TS3 reconnect + L4 bytes now appearing in the
   project's bandwidth meter.
3. **W-killswitch** — re-scope alongside W-econ (they share the enforcement seam).
4. **W-admin** — escape hatch; small; land with or after W-econ.
5. **W4** — adaptive self-limits + observability; independent, parallelizable.
6. **W-C0** — only if §7 says a ratio default is retained.

Each PR on this untrusted seam gets the multi-agent adversarial pre-merge review; it must re-derive
P0-L4-2 (cost) and P0-L4-6 (reflection) under the new model and specifically probe: no absolute cap
changed; L4 egress metering can't be evaded (source-port rotation, flow churn); the per-tenant
budget is the binding reflection ceiling and is attributable; the kill-switch re-scope can't be used
to *evade* the absolute caps; W-admin's grant stays store-only (never tenant sidecar).

## 7. Accountability model — RESOLVED (2026-07-13)

**Every jkbase tenant has an identity; there are no anonymous accounts.** "Unlimited" accounts exist
only for a trusted **super-user class** (internal/platform), not public signup. This puts us
squarely in the **identity + accountable** branch:

- **Retire the ratio clamp by default now** — no signup-friction prerequisite is needed, because the
  account-spraying threat (which required friction) does not exist without anonymous/free-unlimited
  accounts.
- The economic deterrent is real: every reflected byte is **attributable to an identified tenant**,
  **billable** (once L4 egress is metered, W-econ), and **terminable** on abuse. That collapses
  booter economics (reflection is neither free nor anonymous here).
- The **super-user "unlimited" class** is exactly the home for the demoted **W-admin** escape hatch:
  a trusted account gets a raised per-tenant egress budget (or an exempt per-port soft-clamp), granted
  through the admin/store channel — never self-served.

Residual (accepted, "contained not removed"): a *malicious-but-identified* tenant can still source
reflection up to their egress budget, bounded by the unchanged absolute caps (≤1 MB/s/victim, ≤8
MB/s//24, ≤64 MB/s global) — but it is attributable, billed, terminable, and platform-catastrophe-
proof by the global cap. That is the correct posture for a public offering.

**Still to pick (numbers, not architecture):** the default per-plan L4 egress budget (bytes/sec +
monthly) and the super-user raised budget — set alongside the W-econ implementation.
