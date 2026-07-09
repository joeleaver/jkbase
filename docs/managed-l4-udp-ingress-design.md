# jkbase — L4 UDP/TCP scale-to-zero ingress design

> Status: design (L4-P0 — first external **non-HTTP** reach plane). Companion to `docs/managed-rhypedb-tcp-ingress-design.md` (closest sibling: same edge-auth/register/wake/relay spine) and `docs/zero-bounce-phase2-design.md` (the `:80`/`:443` socket hand-off this doc deliberately does **NOT** match).
> Scope: raw L4 ingress with scale-to-zero — a tenant hosts a UDP service behind an **always-on host edge socket** (like `:443`) while the guest VM still hibernates to zero and wakes on a datagram (~125ms after return-routability is proven). v1 = UDP; first tenant = **TeamSpeak 3, voice UDP `9987`**. TCP L4 is a follow-on whose *control* plane is shared but whose *data* plane is different (§3(e)).
> Threat model: **all tenants untrusted**; this is a NEW external L4 seam whose trigger — a UDP datagram — is **source-spoofable and carries no completed handshake**. Unlike the HTTP plane (whose wake fires only after the kernel completes a TCP 3-way handshake, so the source is verified) a bare datagram proves nothing about its origin. **That single fact — the source is unverified until we make it prove itself — shapes every defense.**
> Produced via recon → design-synthesis → adversarial-probe (3 reviewers). `[R#]`/`[P0-L4-#]` findings folded in.
> Decisions — PROPOSED (awaiting Joe's sign-off; see §9): (D1) UDP first, TCP different-data-path follow-on. (D2) guest binds **loopback + agent land-forward proxy**, NOT eth0-bind + firewall. (D3) **wake is gated by a stateless return-routability challenge** (the UDP analog of the TCP handshake), then a per-project throttle — the source is *verified return-routable*, not identity-authenticated. (D4) load-bearing rate axes are **per-project (aggregate)** and **per-return-routable-IP** (meaningful only *after* the challenge). (D5) admin-**pinned** external port for TS3 (`9987`), random-alloc default + SRV fallback for others. (D6) new datagram pump — `relay_bidirectional` is NOT reused. (D7) new `UDP_RELAY_IDLE_TIMEOUT` (tens of seconds) on an **un-throttled per-datagram clock**; reuse `idle_detection_loop`. (D8) **NOT gapless across host-process restart** — clients reconnect.

## Hard constraints (honored throughout)

- (a) The guest L4 service binds **guest loopback only** (TS3 on `127.0.0.1:9987/udp`); the `jkbase-agent` is the sole in-VM mediator, exactly as rhypedb binds `127.0.0.1:4200/4201` (`crates/jkbase-agent/src/container_supervisor.rs:322-323`) and is reached only through the secret-gated splice (`crates/jkbase-agent/src/main.rs:1218-1223`). The service **never** binds eth0.
- (b) All tenants untrusted; this is a new external L4 UDP seam whose trigger is **source-spoofable and unverified** until the return-routability challenge (§3(c)) forces the source to prove it can receive at its claimed address.
- (c) Scale-to-zero holds. The host edge `UdpSocket` per allocated port is always up; the VM still hibernates to zero and resumes on the first **return-routability-proven** admitted datagram.
- (d) **Additive only.** A `#[serde(default)]` config table + one new store table; zero migration; zero change to the DB (`db_ingress.rs`) or HTTP (`lib.rs`) plane semantics — the UDP plane gets its **own** wake budget and does not couple to theirs.

---

## 1. Summary — what & why (the two central facts)

**Fact one (wire shape):** UDP is connectionless, so there is no socket to pin liveness on, no byte-stream we can hand to `relay_bidirectional`, and — critically — **no completed handshake that proves who sent the trigger.** Everything below is a consequence of manufacturing a *session*, and a *verified source*, out of a stream of datagrams that are individually forgeable.

**Fact two (why this is not "HTTP parity"):** the HTTP wake plane looks like it also "wakes on an unauthenticated `Host` match" (`lib.rs:603-642`), but its trigger rides *inside* an already-established TCP connection — the client had to receive the server's SYN-ACK and echo the correct ISN, which is only possible from (or on-path to) the claimed source IP. **So on the HTTP plane the source address is verified; on a bare UDP datagram it is not.** A design that wakes a VM (or emits a reply) on an unverified datagram is a **strict downgrade**, not parity: it hands an off-path spoofer a boot-per-packet resource amplifier and a traffic reflector against any victim IP it names. We therefore do **not** claim source-parity with HTTP. We **manufacture** the missing return-routability with a stateless cookie challenge (§3(c), P0-L4-10) — the UDP analog of the TCP handshake — and only *then* spend a boot or emit a stream. Per-source rate limiting, which the HTTP plane leans on precisely because its IP is verified, regains meaning on our plane only downstream of that challenge.

We already ship a reach plane that wakes a hibernated VM and splices a caller through the agent into a guest service: the managed-DB `:443` edge (`crates/jkbase-proxy/src/db_ingress.rs:131`) and its source-IP-authed host twin (`crates/jkbase-server/src/db_gateway.rs:271`). That plane's control half — edge caps, `register-before-wake`, `WakeCallback`, the relay registry that keeps the idle loop informed, RAII drain — is **transport-agnostic and reused as-is**. Note the DB spine is explicitly *auth-before-wake* (TLS+ALPN+bearer preamble); we inherit its `register-before-wake` scaffolding but **not** its authenticating property, so we install a different gate (return-routability) in the same slot rather than pointing at a weaker sibling. Only the *data path* is new: the DB splice rides TLS-over-TCP on the edge and HTTP/1.1-Upgrade over TCP on the agent leg. `relay_bidirectional` (`crates/jkbase-wsproxy/src/lib.rs:185`) is a pure byte-stream pump — `split` + `read` + `write_all` — with **no message framing and no per-packet `SocketAddr`**, so it coalesces/splits datagrams and loses the reply-demux key. It is fundamentally TCP-shaped and cannot be reused for UDP.

So v1 builds five things and reuses the rest: (a) a **stateless return-routability challenge** before any boot or >1x reply, (b) a datagram relay with a **framed, flow-id-multiplexed** host↔guest transit leg (one host guest-facing socket per port, not per flow), (c) port-per-project L4 routing (no `Host`/SNI on UDP — routing is purely `external_port → project`), (d) unverified-wake hardening (throttle + budget on the UDP plane's own semaphore), (e) un-throttled-timer idle detection. The `api.`/`storage.`/`console.` reserved-host short-circuits are HTTP-`Host`-based and **irrelevant here**.

## 2. Topology & data flow

```
      (untrusted clients — src SPOOFABLE, source UNVERIFIED until step 4)
   TS3 client A ─┐    TS3 client B ─┐    spoofed→victim / junk ─┐
      udp/9987   │       udp/9987   │       udp/9987            │
════════════════╪═══════════════════╪═══════════════════════════╪═══ public uplink ═══
                ▼                   ▼                            ▼
  ┌────────────────────────────────────────────────────────────────────┐
  │ HOST edge — always-on UdpSocket per allocated external_port         │
  │ jkbase-proxy  L4Ingress   (sibling of DbIngress :131)               │
  │                                                                     │
  │  1  recv_from(src)                                                  │
  │  2  magic PRE-filter: first 8 bytes == b"TS3INIT1"? no ─▶ DROP        [P0-L4-3]
  │        (noise rejection ONLY — worthless vs an attacker; NOT a gate) │
  │  3  flow_table.get(src) ── HIT (already proven) ─▶ jump to 8         │
  │  4  RETURN-ROUTABILITY (stateless HMAC cookie, NO per-src state):     [P0-L4-10]
  │        unproven src ─▶ emit ONE small challenge (≤1x), rate-capped,   [P0-L4-6]
  │                        NO wake, NO flow entry ─▶ await echo          │
  │        src echoes valid unexpired cookie ─▶ PROVEN return-routable ──▶│
  │  5  wake gate: per-BASE-PROJECT cap + per-proven-IP cap               [P0-L4-2]
  │        + UDP-plane concurrent-wake budget (non-blocking) ─ over ─▶ DROP
  │  6  registry.try_register(project)  BEFORE wake ──▶ Rejected ─▶ DROP  │
  │  7  WakeCallback(project) ── resume ~125ms ──▶ vm_ip                 │
  │  8  admit flow F=flow_id(src); stamp UN-THROTTLED last-seen;         │
  │        bump live-flow gauge; enforce per-project & GLOBAL flow caps   [P0-L4-5]
  └────────────────────────────────────────────────────────────────────┘
        │  ONE guest-facing UdpSocket per port; per datagram send:        [P0-L4-11]
        │     { auth-hdr(secret ⊕ nonce ⊕ F) ‖ datagram }  (framed, 1:1)  [P0-L4-7]
════════╪══════════════════════════ host↔guest TAP (L2 source-guarded) ═══
        ▼   → vm_ip:agent_udp_port  (host-set, ≠ guest_port)              [H1-fix]
  jkbase-agent  UDP land-forward   (const-time header verify + strip; L2 pin)
        │  demux F ─▶ per-flow loopback socket ─▶ send_to 127.0.0.1:9987  │
        ▼   (agent flow map has its OWN bound ≤ host cap)                  [P0-L4-5]
  TeamSpeak 3 server   (binds 127.0.0.1:9987/udp ONLY — never eth0)        [P0-L4-1]

  idle loop (main.rs:4297): per-flow un-throttled idle timer fires ─▶ drop
      RelayGuard ─▶ conn_count(project)==0 ─▶ FORCE-AGE ActivityTracker    [M2-fix]
      ─▶ grace window ─▶ hibernate to zero
```

The invariant this diagram exists to prove: **the guest TS3 server is reachable only through the host edge socket and the agent's header-authenticated, L2-source-guarded land-forward — never directly on eth0 — and no boot or reply is spent until the source has proven return-routability.** A datagram that bypasses the host path (an isolation slip onto the L2 segment) still hits nothing, because the engine binds loopback only (`container_supervisor.rs:322-323`) and the agent land-forward verifies a host-authenticated header before touching loopback.

## 3. Design detail

### 3(a) UDP datagram relay — new listener + flow-id-multiplexed transit

**BUILD NEW.** A `L4Ingress` struct (the UDP analogue of `DbIngress`, `db_ingress.rs:100`) owns, per allocated port:
- one always-on host **edge `UdpSocket`** (client-facing: `recv_from`/`send_to`),
- one host **guest-facing `UdpSocket`** toward `vm_ip:agent_udp_port` (§3(b) — **one per port, NOT one per flow**),
- a **flow table `HashMap<SrcAddr, Flow>`** where `Flow` is pure bookkeeping — a `flow_id: u32`, a `RelayGuard`, and an **un-throttled** last-seen `Instant`. It holds **no socket and no task per entry** (this is what bounds host-side fd/ephemeral cost — see P0-L4-5, mechanics H4).

The pump is two loops, not a task-per-flow:
- **Reach loop** (`recv_from` on the edge socket): magic pre-filter → return-routability (§3(c)) → on a proven source, look up/admit the flow → frame `{auth-hdr(secret ⊕ nonce ⊕ flow_id) ‖ datagram}` (§3(a-auth)) → `send` on the single guest-facing socket.
- **Return loop** (`recv` on the single guest-facing socket): verify+strip the agent's auth-header, read `flow_id`, look up the client `SrcAddr`, `send_to(src)` on the edge socket. **`flow_id` is the reply-demux key** `relay_bidirectional` lacks (P0-L4-7).

Because return demux is by `flow_id` in a framed header, the host needs **no per-flow socket** and **no per-flow task** — the two shared loops plus a periodic sweep over the flow table for idle eviction. This is the direct fix for host ephemeral-port / task exhaustion under a flow flood.

**Agent side (BUILD NEW):** a UDP land-forward listener modeled on `db_leg_loopback_proxy` (`container_supervisor.rs:1139`). It receives framed transit datagrams on `agent_udp_port`, **const-time verifies + strips** the host auth-header (§3(a-auth)), and forwards the payload to `127.0.0.1:9987`. Reply demux **does** require per-flow guest-side sockets (the app replies to whatever source the agent presented), so the agent keeps a `flow_id → connected loopback UdpSocket` map — but that map has its **own explicit bound** `≤` the host per-project cap, sized to the microVM's fd/RAM headroom, fail-closed on overflow, and idle-evicted independently. State the FD budget on both sides in the impl. "The agent just needs a firewall rule" is the **wrong** model: a direct eth0 bind would bypass the entire wake/return-routability/quota/idle machinery and expose an unauthenticated UDP service to the hostile L2 segment [P0-L4-1].

**Why not `relay_bidirectional`** (`wsproxy/src/lib.rs:185`, hooked variant `:196+`): its `AsyncRead`/`AsyncWrite` byte model has no datagram boundary and no `SocketAddr`/`flow_id` per packet [P0-L4-7]. We keep its `RelayHooks{cancel,on_activity}` *semantics* — `select!` on the `CancellationToken` — but implement the copy loops over `UdpSocket` with framed transit.

**Bookkeeping reuse:** each flow registers via `DbRelayRegistry::try_register` (`db_relay.rs:110`) on admission and its `RelayGuard::drop` (`db_relay.rs:297-329`) decrements on idle-eviction; the **live-flow gauge mirrors `conn_count`** (`db_relay.rs:220-228`). The `ActivityTracker` stamp (post-wake at `db_ingress.rs:262`) is bumped on admitted datagrams via the throttled `on_activity` — **but the per-flow eviction clock does NOT reuse that throttle** (§3(d)).

#### 3(a-auth) Host↔guest transit authentication — the connectionless leg

The DB agent leg authenticates a **secret in a per-connection TCP/HTTP-Upgrade preamble** validated once (`main.rs:1227-1237`). UDP has no connection, so that check **does not port** — we do not claim it does. On a shared L2 bridge, a co-tenant can address (or spoof toward) the agent's transit listener, so **every** host→guest datagram carries a fixed-size authenticated header, and the listener is additionally L2-source-guarded. Two layers:

1. **Per-datagram authenticated header (defense-in-depth #1).** The host prepends `{ flow_id, monotonic nonce, HMAC(per-VM splice secret, flow_id ‖ nonce ‖ payload) }`. The agent const-time-verifies the HMAC and **rejects replays** via a per-flow high-water nonce window, then strips the header before `send_to 127.0.0.1:9987`. The return direction is symmetric (agent proves it is the real agent). This is per-*datagram* auth that survives connectionlessness; the "secret in the first datagram only" and "silently trust the host source IP" alternatives are both rejected (either leaves subsequent datagrams unauthenticated or is L2-spoofable). **P0-L4-7 is scoped accordingly:** datagram boundaries are preserved *for the payload after header strip* — the transit wire carries exactly one framed record per client datagram (no coalescing), and the client↔edge and agent↔app legs are raw datagrams.
2. **L2 source-guard (defense-in-depth #2).** The agent transit listener is pinned so only the **host TAP source** is admitted, using the same ebtables/anti-spoof source-guard that fences build egress (dockerfile-builder L2 source-guard work) — a co-tenant cannot forge the host's L2/L3 source onto the bridge. Preferred posture: keep the seam on the **host-side bridge-gateway path** the DB gateway already uses (`db_gateway.rs:162` binds `172.16.0.1`), not a fresh guest eth0 surface.

Anti-replay is explicit: the nonce window defeats a co-tenant replaying a captured authenticated datagram.

### 3(b) Port-per-project L4 routing

**Config (additive).** A `#[serde(default)] pub l4: HashMap<String, L4PortConfig>` on `ProjectConfig` (`crates/jkbase-common/src/config.rs:6-27`), mirroring the `routes`/`servers`/`sites` table pattern:

```toml
[l4.teamspeak]
proto       = "udp"      # fail-closed resolver enum, mirror DatabaseEngine::engine() (config.rs:674-685)
guest_port  = 9987       # loopback port the tenant's service listens on
# external_port omitted  ⇒ random-allocated; an admin pin (§3(b) pin-grant) keeps it at 9987
```

`L4PortConfig` copies the `DatabaseConfig` shape (`config.rs:590-619`): a `proto()` resolver that **rejects an unknown value at preflight** (like `engine()`/`tier()`), a `validate()` (`config.rs:712-721`). The tenant declares only `guest_port`; **neither `external_port` nor `agent_udp_port` is a tenant-forgeable fact** [P0-L4-8].

**Host-asserted ports ride the reserved metadata channel.** The host decides `external_port` (public) and `agent_udp_port` (the in-VM transit listen port, an analogue of the DB `backend_port` and **distinct from `guest_port`** — the host dials `vm_ip:agent_udp_port`, the agent loopback-forwards to `127.0.0.1:guest_port`). Both are tenant-unforgeable, so they ride the `_platform.json`/`_db_reach.json` family (`config.rs:152-172`, `:178-214`), all `_`-prefixed so the agent's static server never serves them — never `routes_json`/`database_json` (`config.rs:825-898`).

**Store record — `PortAllocation` mirrors `VmAllocation`** (`crates/jkbase-control/src/store.rs:169-187`):

```rust
pub struct PortAllocation {
    pub project_id: String,
    pub name: String,          // composite key {project_id}:{name} — multi-port per project
    pub proto: String,         // "udp" | "tcp"
    pub external_port: u16,    // host-bound public port (host-asserted, STICKY — see below)
    pub guest_port: u16,       // loopback port the tenant service binds
    pub agent_udp_port: u16,   // host-set in-VM transit listen port (≠ guest_port)
    pub pinned: bool,          // admin-granted fixed port
    #[serde(default)] pub host_id: String,
    #[serde(default)] pub placement_epoch: u64,
}
```

New `const PORT_ALLOCATIONS: TableDefinition = "port_allocations"` in the block at `store.rs:15-23`, keyed by the composite `"{project_id}:{name}"` — L4 needs many-per-project, so mirror the secrets/access-keys composite-key + `delete_all_for_project` scan pattern at `store.rs:1730/1919/2075`. CRUD copies `save/get/list/remove_vm_allocation` (`store.rs:828-868`) verbatim.

**`allocate_port` is idempotent + sticky.** If a `PortAllocation` already exists for `(project_id, name)` it is **reused verbatim** (including `pinned`/`external_port`/`agent_udp_port`); only a genuinely-new `(project, name)` draws a new port; a rename = new alloc + explicit free of the old. **`external_port` is stable for the life of the allocation record** — it survives redeploy, rollback, and VM re-adoption, and is freed only on project-delete or on reconcile of a *removed* `[l4.*]` stanza. This is load-bearing: the flagship tenant's `9987` (and every non-pinned tenant's SRV target) must not move under a redeploy.

**Allocation is a reservation; `bind()` is the arbiter** [mechanics H3 / completeness P1-3]. The store scan alone is **not** "collision-free" — it cannot see host outbound ephemeral sockets or non-jkbase listeners. Two rules:
1. **Range outside the kernel ephemeral range.** The auto-alloc L4 range is chosen strictly **below** the host's actual `ip_local_port_range` floor (default `32768`), e.g. `20000..=30000` — the original `20000..=40000` overlapped the ephemeral range and is rejected. At startup the host reads the live `ip_local_port_range` sysctl and **fails closed** if the configured L4 range overlaps it.
2. **Bind-probe on allocation.** `allocate_port` scans `list_port_allocations` (host-island-scoped by `host_id`, like `next_free_octet`, `main.rs:976-983`), picks a candidate, then **attempts the actual `bind()`**; `EADDRINUSE` ⇒ treat as in-use, retry next candidate. Set `SO_REUSEADDR` and specify bind ordering on restart so a re-bind doesn't race a lingering socket. **Edge-bind failure is a hard, surfaced deploy error — never best-effort/silent-no-ingress.**

**Reuse quarantine** [threat M1]. UDP clients of a torn-down project keep sending to external port P; if P is immediately reallocated, their `TS3INIT1` datagrams would be admitted into a *different* tenant's guest. So: reallocation is gated on **confirmed edge-socket close**, and a freed external port enters a **quarantine cooldown** (a `PORT_QUARANTINE{port → freed_at}` set, cooldown longer than plausible client-retransmit / SRV-TTL) during which `allocate_port` skips it. Non-pinned allocation additionally **randomizes within range** (not lowest-free) to further cut reuse-collision odds.

**Privileged-port policy:** auto range strictly `>1024`, excludes `80`/`443`/reserved; a pin `<1024` needs an explicit admin grant (TS3's `9987` is fine).

**Admin pin-grant surface** [completeness P2-7]. A **platform-admin-only** control-API endpoint / CLI subcommand (`jkbase l4 pin <project> <name> <port>`) writes `pinned=true` + the fixed `external_port` to `PortAllocation`. If the requested port is already bound/allocated by another project the grant is **rejected** (never evicts an incumbent). This is the one manual step the flagship tenant depends on.

**Host firewall inbound-open** [completeness P1-4]. On allocation the deploy path installs an **idempotent, rollback-safe inbound-allow** nftables rule for `external_port/proto` (the host default-denies inbound), symmetric to the teardown free.

**Dealloc on delete + reconcile:** `store.remove_port_allocations(project_id)` in `handle_teardown` beside `remove_vm_allocation` (`main.rs:2188-2189`); free the external resource — edge `UdpSocket` + guest-facing socket + nftables entry — in the `teardown_tap` slot (`main.rs:2207-2210`), idempotent/best-effort. If L4 ports attach to a dedicated DB sibling, mirror in `teardown_db_vm_sibling` (`main.rs:2228-2258`, frees at `:2249`) and the reconcile callers at `main.rs:2133`. A **redeploy reconciles the live L4 set**: stanzas removed from `[l4.*]` have their sockets closed + ports freed; surviving stanzas keep their sticky ports (edge socket re-bound before the old is dropped, so no ingress gap on redeploy).

### 3(c) Unverified-source hardening — return-routability, then throttle

The trigger is source-spoofable, so the first job is to make the source **prove it can receive at its claimed address** before we spend anything. Then, and only then, the same throttle+budget discipline as the DB spine.

1. **Magic pre-filter [P0-L4-3].** First 8 bytes `== b"TS3INIT1"`, else `DROP`. **Noise rejection ONLY — explicitly NOT a security boundary and NOT counted in any adversarial bound**: the 8 bytes are a constant an attacker always includes. Its sole job is to keep obvious garbage off the (already-cheap) challenge path.

2. **Stateless return-routability challenge [P0-L4-10] — the load-bearing gate.** On a magic-passing datagram from a source with **no existing flow**, the edge does **not** wake and does **not** allocate any per-source state. It computes a stateless cookie `C = truncate(HMAC(host_cookie_key, src_ip ‖ src_port ‖ time_window))` and emits **one** small challenge datagram carrying `C`. Only when the edge receives a datagram back from the same source echoing a **valid, unexpired** `C` is the source deemed **return-routable** and allowed to proceed to the wake gate. Because a spoofed source never receives the challenge (it went to the victim), an off-path spoofer cannot complete this — exactly the property the TCP handshake gives the HTTP plane. Held state before proof: **none** (the cookie is recomputed on echo), so a spoof flood cannot fill the flow table pre-wake (closes the pre-wake half of P0-L4-5).
   - **Protocol adapter.** The challenge must be *echoed by the client*, which requires protocol cooperation. TS3's own low-level `Init1` exchange is a cookie/RSA-puzzle handshake built to defeat spoofing: the edge answers the **stateless prefix** of it (generate/echo the step-0→1 randoms) with no wake, and requires the client's **step-2 echo** before booting; the guest completes the RSA-puzzle steps (3→4) *after* wake. So the v1 gate is TS3's native anti-spoof handshake, relocated to the edge and made boot-deferring. **Generic UDP protocols with no echo-able handshake are NOT auto-supported in v1** — each proto needs a return-routability adapter; TS3 is the only v1 proto (matches D1/D5). This adds **one RTT before boot**, well within TS3's connect window.

3. **Wake throttle + UDP-plane budget [P0-L4-2].** After return-routability, before the `WakeCallback` `.await` (in the register-before-wake slot, `db_ingress.rs:212`/`:242`):
   - a `WakeRateLimiter` (sibling of `PerIpLimiter`, `db_ingress.rs:35`, RAII decrement + prune-at-zero like `IpPermit` Drop `:70-80`) keyed on **`base_project_id`** (via `vm_identity::base_project_id`, `main.rs:3716`, so app + `.db` VMs share one budget). **Keyed on base-project, NOT `(project, port)`** — otherwise a tenant with N allocated ports would get N independent caps and multiply its share of any shared budget. The **per-tenant allocated-port count is itself hard-capped** (§6) so port-multiplication can't inflate the wake axis.
   - a **per-return-routable-IP** cap. Post-challenge the source IP is verified, so per-IP limiting is a **real** control here (the HTTP plane's primary source defense), not the "non-load-bearing add" the earlier draft called it.
   - a **UDP-plane-private** `wake_budget: Arc<Semaphore>`, acquired with **non-blocking `try_acquire_owned`** around the `WakeCallback` (mirroring the DB spine — a failed acquire ⇒ `DROP`, never park a task on the semaphore). **This budget is NOT shared with the HTTP or DB planes** — the spoofable UDP plane must not be able to starve the stronger planes' cold boots (the HTTP path has no such semaphore today and we do not introduce cross-plane coupling).

Enum: add **`WakeError::RateLimited(String)`** at `lib.rs:30` (alongside `OverQuota`/`Unavailable`/`Gone` at `:34`/`:36`/`:40`) so the UDP responder drops, the HTTP mapper (`lib.rs:617-641`) renders 429/503, and the DB mapper (`db_ingress.rs:246`) renders its own signal. Promote the `WAKE_BACKOFF` `bail!` (`main.rs:3818`, blanket-mapped to `Unavailable` at `main.rs:3748`) to this variant so failure-throttle vs rate-cap refusals read distinctly in logs/metrics. The existing `WAKE_BACKOFF` (`main.rs:3700`, enforced `:3814`) and the `wake_project` quota gate (`main.rs:3706`, `bandwidth_blocked → OverQuota` at `:3719-3727`) still apply **inside** the callback; `WakingGuard` (`main.rs:3659`, `:3881`) still guarantees single-flight, so the limiter bounds the *rate of new drivers*, not concurrent duplicate boots.

### 3(d) Timer-only idle detection

**REUSE `idle_detection_loop`** (`main.rs:4297`) — it excludes any project whose `conn_count` gauge (`db_relay.rs:220-228`) is `>0`, so a byte-silent-but-live voice flow keeps the project warm for free. Three corrections over the naive reuse:

- **Un-throttled eviction clock.** The reused `on_activity` stamp is throttled to `ACTIVITY_STAMP_INTERVAL = 30s` (`wsproxy/src/lib.rs:30`). The **per-flow eviction timer must NOT reuse that throttled stamp** — it keeps its own **per-datagram** last-seen `Instant`, else an actively-talking flow whose throttled stamp last landed at t=0 would be evicted mid-call. `UDP_RELAY_IDLE_TIMEOUT` has a **floor comfortably above both the keepalive interval and the 30s stamp throttle**.
- **Force-age on last-flow eviction.** The global hibernate check fires when `now - ActivityTracker.last > idle_timeout` **and** `conn_count == 0`, where `idle_timeout` is the global `DEFAULT_RELAY_IDLE_TIMEOUT` (600s, `main.rs:1743`). Flow eviction alone does **not** clear the `ActivityTracker`, so a short `UDP_RELAY_IDLE_TIMEOUT` would still leave the project stuck-warm for ~600s. **On last-flow eviction (`conn_count → 0`) we proactively force-age/clear the project's `ActivityTracker` entry** so it becomes an immediate hibernation candidate. No premature-hibernate risk exists (`conn_count>0` protects live flows); this purely fixes the stuck-warm tail so scale-to-zero actually behaves in tens of seconds, not 600s.
- **Concrete timeout.** `UDP_RELAY_IDLE_TIMEOUT` default **45s** (per-`proto`/per-app tunable), chosen `> TS3 keepalive floor` (TS3 clients emit a keepalive well under 1s; the 45s floor gives ample margin) and `> 30s` stamp throttle. **Failure mode to document for operators:** if a tenant app's keepalive interval exceeds the configured timeout, the flow is evicted mid-session — so the timeout is set deliberately per proto. The un-throttled clock plus the keepalive floor means an active flow always re-stamps well within the window, so there is no mid-session hibernate; absence of that traffic *is* the disconnect signal. The idle-loop poll granularity (up to ~60s) adds jitter on top of the timeout + grace window — the effective hibernate latency is stated as `UDP_RELAY_IDLE_TIMEOUT + grace + poll-jitter`, not a single number.

### 3(e) What TCP L4 reuses vs. rebuilds (follow-on scoping)

The **control** plane is genuinely transport-agnostic and extends unchanged: the config table, `PortAllocation`/`agent_udp_port`/stickiness/quarantine, `allocate_port`, wake throttle + budget, teardown/reconcile, firewall open, admin pin-grant. The **data** plane inverts for TCP and must **not** be assumed to be "just add `proto=tcp`":
- TCP **has** a handshake, so return-routability is provided by the kernel completing SYN/SYN-ACK/ACK — **no cookie adapter and no magic pre-filter are needed** (both are UDP-only).
- `relay_bidirectional` (`wsproxy/src/lib.rs:185`) becomes the **right** pump — it is a TCP byte-stream copier; the framed flow-id transit and per-flow demux are unnecessary.
- Idle detection can use **socket close / half-close** instead of an un-throttled timer.
So the TCP follow-on is a *different, simpler* data path bolted onto the *same* control plane. TS3 file-transfer TCP `30033` + ServerQuery TCP `10011` are the natural first TCP tenants but are **out of v1 scope**.

## 4. Threat model — invariants

All tenants untrusted; **the trigger is source-spoofable and unverified until the source completes a return-routability challenge.** That fact — and the honest admission that this is *weaker* source assurance than the HTTP plane's completed TCP handshake, closed by a compensating control — shapes every defense. Most-critical first.

| ID | Invariant | Why / mechanism |
|---|---|---|
| **P0-L4-10** | **No boot is spent and no >1x reply is emitted until the source proves return-routability.** | A stateless HMAC cookie challenge (§3(c)) — the UDP analog of the TCP handshake — is answered with **one** small packet and **zero** held state; only an echoed, unexpired cookie admits a source. An off-path spoofer never receives the challenge, so it can neither drive a boot nor pull a stream toward a victim. This is the compensating control for the fact that a bare datagram, unlike an HTTP wake, carries no source proof. |
| **P0-L4-4** | **The plane accepts *spoofable, unverified* sources — this is NOT byte-parity with HTTP and is not claimed as such.** | HTTP wakes only after a completed TCP handshake (source verified via ISN echo); a UDP datagram proves nothing. We do not argue down to the HTTP plane; we *manufacture* the missing return-routability (P0-L4-10) and only then apply per-source controls. There is no identity auth of the end client (the platform never authenticates the guest's users) — the defense is return-routability + throttle, honestly bounded. |
| **P0-L4-2** | **Wake is gated by a per-BASE-PROJECT cap + a per-return-routable-IP cap + a UDP-plane-PRIVATE non-blocking concurrent-wake budget, all synchronous BEFORE the wake `.await`.** | Keyed on `base_project` (not `(project,port)`, so extra ports can't multiply budget share) via `vm_identity::base_project_id` (`main.rs:3716`); per-IP is meaningful because the IP is *verified* by P0-L4-10; the budget is `try_acquire_owned` (fail-closed, no parked tasks) and **not shared with HTTP/DB** so this plane can't starve theirs. Refused ⇒ `WakeError::RateLimited` ⇒ `DROP`, no boot spent. |
| **P0-L4-12** | **Keep-warm requires proven, sustained *bidirectional* liveness; an unverified dribble cannot pin a victim's VM warm or run up its bill.** | The DB spine's idle-keeps-warm property is bounded to the authenticated owner; with no client auth that bound is otherwise lost. Restored by: only return-routability-proven flows count toward `conn_count`; `conn_count>0` requires sustained bidirectional traffic (not just inbound); a cap on distinct-source warm-holding flows; and **warm-VM-hours never driven by a verified peer are not billed** (§6). Closes the anonymous-keep-warm / economic-DoS vector. |
| **P0-L4-1** | **The guest L4 service binds guest loopback ONLY; the agent is the sole in-VM mediator, over an authenticated + L2-source-guarded transit leg.** | TS3 on `127.0.0.1:9987` (mirror rhypedb `container_supervisor.rs:322-323`); agent land-forward on `agent_udp_port` verifies the per-datagram host auth-header (§3(a-auth)) and is pinned to the host TAP source. An eth0 service bind would expose an unauthenticated UDP surface to the hostile L2 segment and bypass wake/quota/idle. |
| **P0-L4-11** | **Every host↔guest transit datagram is individually authenticated (secret+nonce HMAC) and replay-resistant; the leg is defense-in-depth with an L2 source-guard.** | UDP has no per-connection preamble to gate on, so the DB "secret in the TCP upgrade" check does **not** port. A fixed-size header carries `HMAC(splice_secret, flow_id ‖ nonce ‖ payload)`; the agent const-time-verifies, checks the monotonic nonce window (anti-replay against an L2 co-tenant), and strips before loopback. |
| **P0-L4-5** | **Flow-table admission is bounded per-project AND globally; agent-side flow map is separately bounded to VM resources.** | Host flow entries are pure bookkeeping (no per-flow socket/task), capped per base-project **and** by a global all-projects ceiling (byte/count) — the real host-memory DoS bound. The agent map is bounded `≤` host cap, sized to the microVM. Both hold **with `TS3INIT1` present on every attack packet** (the magic filter is not counted). Pre-wake there is no per-source state at all (P0-L4-10). Over-cap ⇒ `DROP` (fail-closed). |
| **P0-L4-6** | **Reflection is bounded to at most ONE small (≤ request-size) challenge packet per source per time-window, rate-capped — never a boot, never a stream.** | Before return-routability the only outbound is the stateless cookie challenge — the exact posture of a TCP SYN-cookie's SYN-ACK. Challenge emission is per-source-prefix and globally rate-capped so it can't itself be a flood reflector. After proof, replies flow only to a return-routable source. The `≈1x` on the challenge relies on the TS3 `Init1` step-1 reply being ≈ request-size (a protocol fact); no amplification path exists via wake or stream. |
| **P0-L4-3** | **The `TS3INIT1` 8-byte magic filter is noise rejection ONLY — NOT auth, NOT a security bound, and NOT counted in P0-L4-5/-6.** | Trivially forgeable, so an attacker always includes it. It only keeps garbage off the (already-cheap) challenge path. Any bound that assumed it pre-thins an attack flood would be under-sized — so it is excluded from every adversarial bound. |
| **P0-L4-7** | **Datagram boundaries are preserved end-to-end for the payload; `relay_bidirectional` is NOT reused; reply demux is by `flow_id`.** | Its byte-stream model (`wsproxy/src/lib.rs:185`) coalesces/splits datagrams and loses the per-packet reply key. The transit leg carries exactly one framed `{auth-hdr ‖ payload}` record per client datagram (no coalescing); client↔edge and agent↔app legs are raw datagrams; `flow_id` in the header is the reply-demux key. |
| **P0-L4-8** | **Host-asserted `external_port` + `agent_udp_port` ride the reserved `_`-channel, never the tenant sidecar.** | Tenant declares only `guest_port`; the bound public port and the in-VM transit port are host-decided and tenant-unforgeable, in the `_platform.json`/`_db_reach.json` family (`config.rs:152-214`). A tenant cannot forge or hijack another project's port. |
| **P0-L4-9** | **Fail-closed on every anomalous path.** | Unknown port, failed return-routability, missing/invalid transit header, replayed nonce, over-rate, over-budget, per-project or global flow-table full, agent-map full, guest UDP not-yet-listening, bind-probe `EADDRINUSE` ⇒ **drop/refuse/hard-error**, never a silent passthrough into the unauthenticated engine and never a silent no-ingress deploy. |

## 5. Lifecycle edge cases

- **Cold-boot UDP-readiness gate (`/proc/net/udp`, not a probe).** `wait_for_agent` probes guest TCP `:80` — correct for **snapshot resume** (agent already up). But on a **cold boot of a pure-UDP app**, `:80` answering does **not** mean `127.0.0.1:9987/udp` is bound. There is **no reliable active UDP liveness probe** (a probe datagram is indistinguishable from silence, or draws a filtered ICMP). **Fix:** the agent polls `/proc/net/udp` for the `127.0.0.1:9987` bind (`0100007F:270B`) — a deterministic in-guest readiness signal — before replaying the buffered datagram(s). *(Anchor: `wait_for_agent` is the TCP `:80` readiness probe on the boot path near the `wait_for_route`/`wait_for_db_vm_running` waiters at `main.rs:3826`.)*
- **Bounded replay buffer, proven-source only [R-replay, threat L2].** Buffer the post-return-routability datagram(s) that arrive during the multi-second cold boot; replay **after** the `/proc/net/udp` readiness signal fires — and **only to a return-routability-proven source** (so replay is never an extra reflected packet to a victim). **Cap it hard** (a few packets / small byte ceiling); overflow ⇒ drop — the client's keepalive retransmits anyway. Keepalives arriving mid-boot feed this same bounded buffer.
- **First-connect-after-deploy blip.** With no snapshot yet, wake is a **full cold boot** (> the ~125ms resume) plus the one return-routability RTT, which can exceed TS3's ~5s connect window on the *very first* connection after a deploy. One-time blip: the client retries, the now-warm/snapshotted VM answers. **Document; do not special-case.**
- **Host-restart flow-table loss = reconnect (NOT socket-activation).** The always-on edge socket is re-bound on host-process restart by a **plain in-process bind** — it is **NOT** socket-activated: systemd `.socket` units pre-declare a *static* port, and L4 external ports are dynamically allocated, so the `:80`/`:443` adoption path (PRs #59/#60) **does not apply**. The in-memory flow table + agent-side sockets are lost. This is the explicit **non-goal**: **NOT gapless across host-process restart**. UDP clients resume sending; the next datagram re-runs return-routability + wake into a fresh flow. TS3 auto-reconnects — acceptable (D8).
- **NAT source-port rebinding.** Flows key on `ip:port`; a client whose NAT rebinds its source port mid-session becomes a *new* flow (fresh return-routability + admission). Expected and cheap given the keepalive floor.
- **Datagram size / MTU.** `recv_from` **silently truncates** past the supplied buffer, so relay buffers are sized to the max UDP payload (65507) or the negotiated app max. The transit leg adds the auth-header, so **TAP MTU ≥ client-facing MTU + header size**, else DF-set datagrams draw `EMSGSIZE` (drop the flow's oversize datagram, do not wedge the flow) or fragment. Document the DF/`EMSGSIZE` handling.
- **IPv4/IPv6.** v1 edge `UdpSocket` binding policy (v4-only vs dual-stack), v6 `SrcAddr` flow keys, and any v6→v4-guest translation are stated explicitly per proto; v1 TS3 ships v4, dual-stack flagged as a follow-on.

## 6. Metering / quota / billing

Stated honestly as **what is wired in v1 vs deferred** [completeness P2-9]:

- **Allocated L4 port count — hard-capped and enforced in v1.** A per-project/per-tenant cap on `PortAllocation` records, mirroring `per_project_max`/`warm_vm_max`, enforced at deploy (exceeding it **fails the deploy closed**). This bounds public-port exhaustion, always-on-socket count, **and** the wake axis (P0-L4-2 keys on base-project so ports can't multiply budget).
- **Wake-rate is a metered signal in v1.** The per-base-project cap (§3(c)) emits drop-reason counters (§ Observability); excess wakes are refused (`RateLimited`).
- **Warm-VM-hours — instrumented but BILLING DEFERRED.** A tenant that pins TS3 always-warm bills like the managed-DB warm-VM leg — but that leg is **cap-exempt today (tenant `None` at `db_gateway.rs:271`)** and the app→DB leg-budget billing is an open follow-up. v1 **instruments** warm VM-hours but marks them **unbilled**, deferred to the same named follow-up card. Per P0-L4-12, only warm-hours **driven by a return-routability-proven peer** are ever eligible to bill — an attacker cannot run up a victim's bill.
- **Bytes-relayed** rides the live-flow gauge that mirrors `conn_count`, same wiring as the DB splice — instrumented in v1.

## 7. Testing / on-box e2e

A `tools/dev test` gauntlet analog on a real microVM (this box is KVM/jailer-capable). Deploy a **UDP echo** (or a real TS3 server) as an L4 tenant, drive a **real UDP client**, and prove:

1. **Return-routability then cold-wake** — a first datagram draws a challenge and **no boot**; only the echoed cookie triggers resume → reply. Assert boot count stays 0 until the cookie round-trip completes [P0-L4-10].
2. **Relay round-trip** — multi-packet exchange with datagram boundaries preserved (send N distinct-sized datagrams, assert N distinct replies, no coalescing) [P0-L4-7].
3. **Idle → hibernate in tens of seconds** — stop sending → after `UDP_RELAY_IDLE_TIMEOUT` + grace, `conn_count → 0` **and** the force-aged `ActivityTracker` yields hibernate promptly (assert FC pid gone / snapshot taken, and that it does **not** wait ~600s) [M2].
4. **Spoofed-source cannot wake or reflect** — send magic-passing datagrams with a spoofed source that never echoes the cookie → no boot, no flow entry, at most one ≤1x challenge to the (test-controlled) "victim", rate-capped [B1/P0-L4-6].
5. **Wake-rate/budget rejection** — flood proven sources / rapid re-wake → `RateLimited` drops, boot count bounded; and a UDP flood does **not** stall a concurrent HTTP wake (assert plane isolation) [P0-L4-2].
6. **Transit-header auth** — inject a datagram to `agent_udp_port` with a bad/absent/replayed header → agent drops, nothing reaches loopback `:9987` [P0-L4-11].
7. **Readiness gate** — cold-boot the pure-UDP app → datagrams buffered until `/proc/net/udp` shows `:9987/udp` → replay → reply (no first-datagram-into-unbound-socket loss) [M3].
8. **Port stickiness + reuse quarantine** — redeploy keeps `external_port`; a deleted project's port is **not** immediately reallocated (quarantine), and a stale client's datagrams to it are not injected into a new tenant [M1/P1-1].

## 8. Implementation outline (jkbase-side, ordered)

Decision-independent, transport-agnostic control work first:

1. **Config + store.** `L4PortConfig` table on `ProjectConfig` (`config.rs:6-27`) with a fail-closed `proto()` resolver; `PortAllocation` (+ `agent_udp_port`, stickiness) + `PORT_ALLOCATIONS` + `PORT_QUARANTINE` + composite-key CRUD (`store.rs:169-187`, `:828-868`); **idempotent/sticky** `allocate_port` mirroring `next_free_octet` (`main.rs:976-983`) with the below-ephemeral range + **bind-probe** + quarantine + privileged-port policy + admin pin-grant surface; reserved-channel emit of `external_port`/`agent_udp_port` (`_platform.json` family, `config.rs:152-214`); **firewall inbound-open** on allocation; dealloc + reconcile in `handle_teardown` (`main.rs:2185-2210`) + `teardown_db_vm_sibling` (`:2228-2258`).
2. **Datagram pump + flow-id transit** in a new `L4Ingress` module (sibling of `db_ingress.rs`): one edge socket + one guest-facing socket per port, bookkeeping-only flow table, framed `{auth-hdr ‖ payload}` transit, `flow_id` return demux; reuse `DbRelayRegistry::try_register`/`RelayGuard`/`conn_count` (`db_relay.rs`); new **un-throttled** per-flow clock + `UDP_RELAY_IDLE_TIMEOUT` + force-age-on-last-eviction; per-project **and global** flow caps.
3. **Agent UDP land-forward** (model `db_leg_loopback_proxy` `container_supervisor.rs:1139`): const-time header verify + nonce anti-replay + strip, L2 source-guard pin, bounded per-flow loopback socket map, `/proc/net/udp` readiness poll + bounded proven-source replay.
4. **Return-routability adapter (TS3)** + **wake throttle + per-IP cap + UDP-private budget + `WakeError::RateLimited`** (`lib.rs:30`), synchronous before `WakeCallback`; promote the `WAKE_BACKOFF` `bail!` (`main.rs:3818`) to the new variant; **do not** couple the budget to the HTTP path.
5. **Observability** (§ below) + **on-box e2e** (§7) + console/CLI surface (§ below).

**Observability [completeness P2-10].** Wire drop-reason counters — `magic_fail`, `return_routability_unproven`, `rate_cap`, `budget_full`, `flow_full_project`, `flow_full_global`, `agent_map_full`, `unknown_port`, `header_auth_fail`, `nonce_replay` — plus `wakes_admitted`, per-project `live_flow` gauge, `challenges_emitted`, and an observed reply/request byte-ratio for the amplification claim; sampled structured logs on drops so an operator can *see* a spoof flood or reflection attempt in flight.

**Tenant discovery UX [completeness P2-8].** `jkbase l4 ls` prints `{name, proto, external_port, guest_port, pinned, srv_name}` per allocation; a console L4 tab (analog of the DB tab) surfaces the same. This is the mechanism a non-pinned tenant uses to learn its random `external_port` — a first-class deliverable, not a trailing bullet.

**SRV publication [completeness P3-13].** For non-pinned tenants the platform publishes `_service._proto` SRV records pointing at the sticky random `external_port` (so SRV-aware clients — TS3 included — resolve without a well-known port). SRV records are written on allocation via jkbase's existing DNS-management path (same backend/lifecycle as the apex wildcard); if that path can't host arbitrary SRV records this is a **named dependency/gap** to resolve before the random-alloc default is usable. Note (threat L3): SRV advertises the exact port to the internet, so "random" is not attack-surface reduction — it is a management convenience, not a security boundary.

## 9. Decisions — PROPOSED (awaiting sign-off)

- **(D1) UDP first; TCP L4 different-data-path follow-on.** v1 ships UDP + TS3 voice `9987`. TS3 file-transfer TCP `30033` + ServerQuery TCP `10011` out of v1 scope. TCP reuses the control plane, rebuilds the data path (§3(e)).
- **(D2) Guest binds loopback + agent land-forward.** Rejected: eth0-bind + firewall — bypasses wake/return-routability/quota/idle and exposes an unauthenticated UDP service to the hostile L2 segment [P0-L4-1].
- **(D3) Return-routability challenge, then throttle — NOT identity auth, NOT HTTP byte-parity.** Wake fires only after a stateless cookie challenge proves the source can receive at its claimed address (the UDP analog of the TCP handshake), then the per-project/per-verified-IP throttle + UDP-private budget. Rejected: (a) claiming "parity with the HTTP wake-before-auth path" — HTTP's source is verified by a completed TCP handshake and ours is not, so that framing is a dishonest downgrade; (b) waking on a bare datagram — a reflector/boot-amplifier [B1/P0-L4-10].
- **(D4) Load-bearing rate axes: per-base-project (aggregate) + per-return-routable-IP.** Per-IP is a *real* control **after** the challenge (the IP is then verified), not the earlier draft's "non-load-bearing add." Rejected: per-`(project,port)` keying — lets extra ports multiply budget share [P0-L4-2].
- **(D5) Pinned external port for TS3 (`9987`) via admin grant; sticky random-alloc default + SRV fallback for others.**
- **(D6) New datagram pump; `relay_bidirectional` NOT reused** — byte-stream model destroys UDP boundaries and the reply-demux key [P0-L4-7].
- **(D7) New `UDP_RELAY_IDLE_TIMEOUT` (default 45s) on an un-throttled per-datagram clock; reuse `idle_detection_loop` + force-age `ActivityTracker` on last-flow eviction.** Rejected: the 30-day DB "never" (`db_ingress.rs:89`), the 600s stream default (`wsproxy/src/lib.rs:25`), and reusing the throttled 30s stamp as the eviction clock.
- **(D8) NOT gapless across host-process restart** — flow table lost, clients reconnect; the edge socket is re-bound by a plain in-process bind (not socket-activation, which can't pre-declare a dynamic port).

**v1 limitations.** (i) UDP only — TCP L4 unbuilt. (ii) TS3 voice `9987` only; file-transfer/ServerQuery TCP out of scope (tenant-visible: no in-client file transfer, no remote query admin). (iii) Not gapless across host restart (reconnect). (iv) Only protocols with an echo-able return-routability handshake are supported; TS3 is the sole v1 proto (generic-UDP needs a per-proto adapter). (v) Return-routability adds one RTT + first-connect-after-deploy cold boot can exceed TS3's ~5s window (one-time blip). (vi) Warm-VM-hour billing instrumented but deferred to the leg-budget follow-up card (v1 = unbilled). (vii) Non-pinned tenants need an SRV record for client discovery, which advertises the port publicly. (viii) A magic-passing spoof flood can still fill a *victim's* proven-flow slots only after passing return-routability (real clients answer the cookie, spoofers can't → evict-junk-first is possible; residual accepted).

**TS3 tenant migration [completeness P3-12].** Beyond the `9987` pin: (a) the TS3 **server identity keypair + its SQLite state must live on the RWO data disk** to survive hibernate/redeploy and preserve server identity across VM moves; (b) file-transfer `30033` / ServerQuery `10011` are unreachable in v1 (restated limitation); (c) TS3 is built/deployed via the **Dockerfile buildpack** (no dedicated TS3 buildpack) — migration mechanics tracked on a separate card.

**Build order:** decision-independent control work first — config table, `PortAllocation` (with `agent_udp_port`/stickiness/quarantine), `allocate_port` (bind-probe + firewall + pin-grant), teardown/reconcile — all transport-agnostic. Then the datagram pump + flow-id transit + agent land-forward, then the return-routability adapter + wake throttle + `WakeError::RateLimited`, then readiness/replay + observability + CLI/console. This new untrusted external L4 seam **gets the multi-agent adversarial review before merge (project convention)**; the review must re-derive every bound (P0-L4-5/-6) **with the magic filter assumed bypassed on every packet** and probe: return-routability bypass, transit-header forgery/replay, port-reuse cross-tenant injection, allocator/ephemeral collision, agent-map exhaustion, cross-plane budget starvation, and datagram-boundary/reply mis-demux. Deploy note: the agent-binary change ships an agent-rootfs update; no toolchain rebake unless a base layer changes (per [[prod-toolchain-rebake-on-build-change]]).