# jkbase — managed TURN relay design

> Status: **design, not built.** Nothing in this doc exists in the tree. Proposed decisions are marked
> **(D#)** and collected in §10 for Joe's sign-off. Threat-model invariants are **P0-TURN-#**.
> Motivation: Apex Telemed needs a TURN relay for 1:1 WebRTC video visits (patients behind cellular /
> symmetric NATs can't connect with STUN alone), and the same gap exists for every networked jkbase
> tenant — conferencing SFUs (issue #87's mediasoup tenant), voice, multiplayer, P2P data channels.
> Siblings: `docs/managed-l4-udp-ingress-design.md` (the UDP abuse model this reuses),
> `docs/managed-rhypedb-p3-design.md` (the jkbase-Auth minting oracle the credential model mirrors),
> `docs/smarter-l4-limiting-design.md` (absolute caps over ratio clamps).
> Threat model: **all tenants untrusted, and so is everyone they hand a credential to.** A TURN relay
> is, by construction, a service that sends traffic *from the platform's IP* to an address *the client
> chooses*. Every load-bearing decision below is about bounding that.

---

## 1. Summary

A **platform-native TURN service** (RFC 8656), one per host, shared by every project that enables it.
It is **not** a tenant workload and does **not** run in a microVM: it is a separate, sandboxed host
process (`jkbase-turn`) supervised alongside `jkbase-server`, which owns credentials, quotas and
metering and talks to it over a local socket.

What a tenant gets:

```js
// Tenant backend, per call:
const r = await fetch(`https://turn.jkbase.app/v1/projects/${PROJECT}/credentials`, {
  method: "POST", headers: { authorization: `Bearer ${JKTK_KEY}` }, body: '{"ttl_secs":7200}' });
const { iceServers } = await r.json();      // ready to drop into RTCPeerConnection
// iceServers = [{ urls: ["turn:turn.jkbase.app:3478?transport=udp",
//                        "turn:turn.jkbase.app:3478?transport=tcp",
//                        "turns:turn.jkbase.app:443?transport=tcp"],
//                 username: "1767225600:prj_abc:Xk9…", credential: "…" }]
```

### 1.1 Why not "just run coturn in a tenant VM"

The existing `[l4.*]` UDP ingress cannot carry a correct TURN server, independently of effort:

| TURN needs | `[l4.*]` provides | Consequence |
|---|---|---|
| the client's real 5-tuple (XOR-MAPPED-ADDRESS, allocation keying) | the agent land-forwards each flow from a fresh `127.0.0.1` port (`jkbase-agent/src/l4_forward.rs`) | mapped/relayed addresses are loopback — wrong |
| one relayed transport address **per allocation** (hundreds of ports) | ≤ 5 ports per project (`MAX_L4_PORTS_PER_PROJECT`), host-chosen from 20000–30000 | ~4 concurrent allocations |
| TCP 3478 and TLS on 443 | UDP only; TCP L4 rejected at preflight | no `turn:?transport=tcp`, no `turns:` — the transports that rescue the worst networks |
| relayed address == the address peers can reach | external port ≠ guest port, decided by the host | coturn advertises a port nobody can reach |

Fixing those inside the L4 plane would mean exposing real client addresses and port ranges to an
untrusted guest — strictly worse than doing it once, host-side, with the platform holding the policy.

### 1.2 Why not a single shared coturn on the host

coturn's shared-secret mode has **one** secret (or one per realm, and the realm is server-chosen, not
client-chosen), and its quota/metering hooks are per-username, not per-tenant. jkbase needs
per-project credentials, per-project allocation caps, per-project byte metering into the existing
bandwidth quota, per-project kill, and a peer policy that knows about the host's own addresses. Those
are the whole product; bolting them onto coturn means patching C that parses untrusted input. See
(D2) for the implementation choice.

## 2. Non-goals (v1)

- Multi-region / anycast. One host, one location (the single OVH host) until the HA arc lands. Clients
  far from North America pay the RTT. Stated in the tenant docs, not hidden.
- Surviving a `jkbase-turn` restart. Allocations are in-memory; clients ICE-restart. (Surviving a
  `jkbase-server` restart **is** a goal — §3.)
- STUN-only service as a product (the TURN listener answers Binding requests, as every TURN server
  does; we don't market it).
- TURN-over-DTLS, RFC 6062 TCP allocations (`REQUESTED-TRANSPORT=TCP`), mobility (RFC 8016).
- IPv6 relayed addresses — Phase T3 (§9).

## 3. Topology & process model

```
  browsers / SDKs (credential holders — untrusted)                    peers (any public host)
     │ udp/3478   │ tcp/3478        │ tls/443 (SNI turn.<domain>)               ▲
═════╪════════════╪═════════════════╪═══════════════ public uplink ═════════════╪══════════
     │            │                 ▼                                           │ udp, from
     │            │      ┌──────────────────────┐                               │ relay range
     │            │      │ jkbase-proxy :443     │ TLS terminate (apex wildcard) │ 61000–65535
     │            │      │ SNI == turn.<domain>  │──┐ plaintext TURN-over-TCP     │
     │            │      └──────────────────────┘  │ + PROXY-v2 header (client   │
     ▼            ▼                                 ▼   addr) over unix socket     │
  ┌────────────────────────────────────────────────────────────────────────────┴──┐
  │ jkbase-turn  (separate systemd unit, DynamicUser, no FS, seccomp, own cgroup)   │
  │   STUN/TURN codec · allocations · permissions · channels · relay sockets        │
  │   peer policy (P0-TURN-3) · per-alloc/per-dest/per-project token buckets        │
  │   in-process hairpin for relay→relay (§4(e))                                    │
  └───────────────┬────────────────────────────────────────────────────────────────┘
                  │ unix socket (/run/jkbase/turn.sock): pushed project policy + key
                  │ material, pulled usage deltas, kill/revoke commands
  ┌───────────────▼──────────────┐
  │ jkbase-server                 │  credential mint API (turn.<domain> reserved host),
  │                               │  quotas, metering loop, control store
  └──────────────────────────────┘
```

**(D1) Separate process, not in-process.** Three reasons, in order of weight:
1. **Blast radius.** STUN/TURN parsing of untrusted datagrams must not be able to crash or corrupt the
   everything-process. A panic or exploit in `jkbase-turn` loses calls, not the control plane, proxy,
   object store and every tenant VM's orchestration.
2. **Sandboxing.** It needs no filesystem, no `/dev/kvm`, no jailer, no store access — only UDP/TCP
   sockets and one unix socket. That is a much tighter systemd sandbox than `jkbase-server` can wear.
3. **Upgrade continuity for free.** `jkbase-server` upgrades (frequent) don't touch it, so UDP and
   TCP-3478 allocations survive them. The `turns:` leg rides `jkbase-proxy` and gets the existing
   zero-bounce socket hand-off + graceful drain (`docs/zero-bounce-phase2-design.md`).

`jkbase-turn` holds **no durable state**. On (re)connect `jkbase-server` pushes the full policy
snapshot: per-project enabled flag, caps, and the per-project HMAC key material (§4(d)). If the unix
socket drops, `jkbase-turn` keeps serving existing allocations for a grace period
(`POLICY_STALE_GRACE`, 120 s) and refuses **new** allocations after it — fail closed for new work,
don't drop live calls for an upgrade. (P0-TURN-9)

## 4. Design detail

### 4(a) Listeners & transports

| Listener | Owner | Notes |
|---|---|---|
| `udp/3478` | `jkbase-turn` | primary; STUN Binding answered too |
| `tcp/3478` | `jkbase-turn` | RFC 8656 framing; for UDP-blocked networks |
| `tls/443`, SNI `turn.<domain>` | `jkbase-proxy` → unix socket → `jkbase-turn` | the corporate/hospital-firewall rescue path |
| relay range `udp/61000–65535` | `jkbase-turn` | relayed transport addresses, §4(c) |

`turns:` on 443 is the single most valuable transport for a healthcare tenant (hospital guest Wi-Fi
and corporate egress often allow only 443). It costs one new branch in the proxy's TLS demux: after
the handshake, `SNI == turn.<domain>` ⇒ splice the plaintext stream to `/run/jkbase/turn.sock`
prefixed with a PROXY-v2 header carrying the TCP-verified client address. Precedent: the proxy
already demuxes post-handshake by ALPN for the managed-DB plane (`jkbase-proxy/src/lib.rs`, `DB_ALPN`).
Route on SNI, not ALPN — browsers don't reliably send `stun.turn` (RFC 7443).

`turn` joins `RESERVED_LABELS` (`jkbase-control/src/store.rs`). Preflight must check no existing
project already owns `turn` as a label before the binary that reserves it ships (one-off prod check).
The apex wildcard cert already covers `turn.<domain>` (same as `auth.`/`storage.`) — no new cert.

### 4(b) Return-routability is free here (unlike `[l4.*]`)

The L4 design's central constraint (§1.1 there: a bare datagram's source is unverifiable) does **not**
bind TURN's client side. Every Allocate is authenticated with the long-term credential mechanism: the
first request gets `401` + a server `NONCE`; only a client that *receives* that response can produce a
valid MESSAGE-INTEGRITY on the retry. A blind spoofer holding a valid credential still cannot complete
an Allocate for a victim's address. Nonces are stateless (HMAC over client 5-tuple + timestamp,
keyed per `jkbase-turn` boot), 60 s validity. (P0-TURN-1)

Consequence: the **client** leg needs no wake budget, no amp clamp, no C0 floor. The **peer** leg is
where the reflection problem lives (§4(e), §4(f)).

### 4(c) Relay port range

- **Range: `udp/61000–65535`** (4,536 ports) on this host. Linux's default `ip_local_port_range` is
  `32768–60999`; coturn's habitual `49152–65535` overlaps it and produces intermittent `EADDRINUSE`
  under load. Fail closed at startup if the range overlaps the ephemeral range, exactly like
  `validate_l4_port_range` (`jkbase-server/src/main.rs`). Must also not overlap `L4_PORT_RANGE`
  (20000–30000). Configurable; validated, not trusted.
- **Firewall:** host nftables accept on the range + 3478/udp+tcp; **one** new OVH edge-firewall rule
  (UDP destination 61000–65535), as was done for the L4 range.
- **Conntrack:** mark 3478 and the relay range `notrack` in the raw table and write the filter rules
  for untracked traffic. Thousands of relay flows must not compete with tenant VMs' NAT entries in the
  shared `nf_conntrack` table. (Check that nothing else on the host relies on conntrack state for these
  ports — nothing should; they're new.)
- **Allocation is random, not lowest-free** (RFC 8656 §7.2 recommends it; makes relayed addresses
  unpredictable to an off-path peer-side injector).
- **Reuse quarantine (P0-TURN-5):** a port freed by an allocation is not reassigned for
  `RELAY_PORT_QUARANTINE` (= max permission lifetime 300 s + slack → 330 s). Otherwise in-flight
  datagrams from the old allocation's peers — possibly another tenant's call — land in the next
  allocation. Mirrors the L4 external-port quarantine (`PORT_QUARANTINE`). In-memory is enough here
  (relay ports don't outlive the process; a restart quarantines everything by construction — start
  with the whole range quarantined for 330 s, or accept the residual: decide in review).
- **Sizing:** bandwidth binds long before ports do (§7), so 4.5k is ample on one host. Exhaustion is a
  fairness problem, handled by caps (§4(f)), not by a bigger range.

### 4(d) Credentials

The standard "TURN REST API" shape (time-limited username, HMAC credential), with jkbase minting.

- **Per-project TURN key** `K_p` (32 random bytes), generated lazily on first mint, held in the control
  store, pushed to `jkbase-turn` over the unix socket. **Never leaves the host.** (P0-TURN-2, mirrors
  P0-AUTH-2.)
- **Minting key** `jktk_…`: a per-project bearer the tenant's backend presents to
  `POST https://turn.<domain>/v1/projects/{id}/credentials`. Same lifecycle as `jkbk_` issuer keys
  (create / list / revoke via CLI + API, owner-scoped, hashed at rest, per-key mint rate limit like
  P0-AUTH-7). Mint route is served by `jkbase-server` (the proxy's `turn.` branch: plain HTTPS
  requests go to the mint API; only the TURN-over-TLS byte stream goes to `jkbase-turn`. Distinguish
  by ALPN `h2`/`http/1.1` vs none/`stun.turn` — or put the mint API under `auth.` instead and keep
  `turn.` pure TURN. **(D4)**
- **Username** = `<expiry_unix>:<project_id>:<nonce_b64>`; **credential** =
  `base64(HMAC-SHA1(K_p, username))` (the de-facto scheme every WebRTC stack and coturn-trained
  developer expects). `jkbase-turn` parses `project_id` from the username, looks up `K_p`, checks
  expiry and the project's enabled/blocked state. Project attribution therefore comes from the
  credential, which only the host can mint — a tenant cannot bill traffic to another project.
  (P0-TURN-2)
- **TTL:** default 2 h, max 24 h, min 60 s. Note for tenant docs: TURN re-authenticates Refresh
  requests with the same credential, so the TTL bounds **call length**, not just setup. Long calls
  re-mint and ICE-restart.
- **Rotation / revocation:** `jkbase turn rotate` replaces `K_p` with a 24 h overlap (old key accepted
  for verification only) — instant-revoke variant drops the old key immediately and kills that
  project's allocations. Revoking a `jktk_` key stops minting; already-minted credentials live to
  expiry unless `K_p` is also rotated (documented, same as JWTs under P3).

Why mint-via-API rather than handing tenants `K_p` to HMAC locally: the secret then never lands in a
tenant's env/CI/logs; minting is rate-limited and observable; revocation has one control point; and
jkbase controls the username format (the project id inside it). Cost: one HTTPS round-trip per call
setup from the tenant's backend. **(D3)** — the local-HMAC variant is a small add later if a tenant
needs zero-RTT minting.

### 4(e) Peer policy — the load-bearing check (P0-TURN-3)

`CreatePermission` / `ChannelBind` / Send-indication destinations are validated **at permission
install and again per datagram on the send path** (permissions are by IP, so re-check is cheap and
closes TOCTOU on policy change):

1. **Deny every non-public address** using the existing single source of truth,
   `jkbase_common::egress::ip_is_public` (loopback, RFC1918 — which covers the VM bridge `172.16/12` —
   link-local incl. metadata, CGNAT, multicast, documentation, v4-mapped v6 canonicalized, …). Do
   **not** add a TURN-local copy of this logic.
2. **Deny the host's own public addresses** — they *are* public, so (1) passes them, and relaying to
   them would reach `:80/:443`, `api.`/`storage.` via the edge, other tenants' `[l4.*]` ports, and
   `:53` *from the host's own IP*, laundering the attacker's origin into "the platform". The address
   set is read from the host's interfaces at startup and on netlink change, plus an explicit config
   list (for NAT/edge-firewall-mapped addresses).
3. **Except: relay-range hairpin.** The common case where **both** call participants relay through
   jkbase makes each side's peer the *other's relayed address* — i.e. the host's own IP. So a peer
   address `(host_ip, p)` with `p` in the relay range **and** a live allocation behind it is allowed
   and delivered **in-process** (allocation → allocation), never via a kernel socket. Any other port on
   the host IP stays denied. **(D5)**: restrict hairpin to allocations of the **same project** by
   default (Apex's calls are within one project; cross-project hairpin only widens who can push bytes
   into whose allocation).
4. **Optional tenant allowlist** of peer CIDRs (e.g. "only my SFU's IP") — tightens, never widens.

### 4(f) Caps (absolute, not ratio — per `docs/smarter-l4-limiting-design.md`)

TURN's peer leg is a reflector by design (a credential holder chooses where relayed bytes go). There is
no amplification (bytes out ≈ bytes in, plus ≤ 36 B framing), so the threat is **source-IP laundering
and bandwidth exhaustion**, bounded with token buckets reused from `jkbase-proxy/src/l4_egress.rs`
(`TokenBucket`, `BoundedTtlMap`) — move them to `jkbase-common` rather than copy:

| Cap | Default (provisional — tune on first real load) | Why |
|---|---|---|
| allocations per project (concurrent) | 50 | relay-range exhaustion / fairness; admin-raisable like `warm_vm_max` |
| allocations per username (credential) | 4 | a leaked credential can't take the range |
| allocation lifetime | RFC default 600 s, refreshable; hard max 24 h | bounded by credential TTL anyway |
| permissions per allocation | 16 | 1:1 needs ~2; small SFU fan-in needs more |
| per-allocation rate (each direction) | 2 MiB/s, 256 KiB burst | 1:1 HD video ≈ 0.2–0.5 MiB/s; screen-share spikes |
| per-destination-IP rate (all allocations, all projects) | 4 MiB/s | caps what any one victim receives from the platform |
| per-project aggregate | 32 MiB/s | breadth, not concentration (same reasoning as L4 `per_project_bps`) |
| TURN-plane global | 256 Mbit/s of the 1 Gbit/s uplink | TURN cannot starve HTTP, L4 and DB planes |
| global allocations | relay range size minus a 10% reserve | a few large tenants can't take every port |

Over-cap datagrams are dropped (UDP) — never queued. Over-cap Allocate gets `486 Allocation Quota
Reached`. Projects over their monthly bandwidth cap (`bandwidth_blocked`) get `486` on Allocate and
`Refresh` failures on existing allocations (calls end at their next refresh, ≤ 10 min). (P0-TURN-6)

### 4(g) Metering & quota

- `jkbase-turn` counts relayed payload bytes per project (client→peer and peer→client, hairpin
  counted once per side's allocation) and reports deltas to `jkbase-server` every 10 s over the unix
  socket; `jkbase-server` lands them in a new `UsageBucket.turn_bytes` (`#[serde(default)]`, zero
  migration).
- The monthly bandwidth check (`metering_loop`, `used = rx + tx`) becomes `rx + tx + turn_bytes`.
  TURN bytes don't flow through any tenant TAP, so without this they'd be free.
- Plus per-project gauges: active allocations, allocation-seconds (for a future price if relay is
  billed separately — **(D6)**).
- Lost deltas (socket down) are a metering gap, not an over-count; `jkbase-turn` keeps counting and
  flushes on reconnect.

### 4(h) Logging & retention

Default is **no client or peer IPs in logs**, because the first tenant is a healthcare company and
because the platform doesn't need them:

- Per-allocation events at `info`: project id, allocation id (random), transport, start/end, byte
  totals, end reason. No IPs, no username nonce.
- Drop/refusal counters per project per reason (peer-policy denial, cap, auth failure) as metrics,
  not per-event logs.
- Per-event IP logging only behind an explicit, time-boxed operator debug switch
  (`jkbase turn debug --project … --for 15m`), auto-expiring, logged itself.
- Journald retention is whatever the host's is (check and document it); TURN adds no other store.

The relay only ever sees SRTP/DTLS ciphertext; jkbase cannot read media. Whether IP + timing metadata
for a healthcare tenant needs a BAA is a business question for Joe, not a design one (§10).

### 4(i) Lifecycle

| Event | Behaviour |
|---|---|
| project enables TURN | `K_p` generated on first mint; policy pushed |
| project disables TURN / deleted | policy push removes it; `jkbase-turn` kills its allocations at once; `K_p` purged on delete (with `jktk_` keys) |
| `jkbase-server` restart | allocations unaffected; `turns:` legs drain via zero-bounce; policy re-pushed on reconnect |
| `jkbase-turn` restart / crash | allocations lost; clients ICE-restart; systemd restarts it; relay range quarantined at start (§4(c)) |
| host reboot | as above |
| monthly bandwidth block | §4(f) |

### 4(j) Tenant surface

- CLI: `jkbase turn enable|disable`, `jkbase turn keys create|ls|revoke`, `jkbase turn rotate
  [--now]`, `jkbase turn status` (active allocations, month-to-date relayed bytes).
- Console: a TURN section on the project page (enable, keys, usage).
- Docs: the mint snippet in §1, a note on `iceTransportPolicy: "relay"` for testing, TTL-bounds-call
  length, the single-region caveat.
- The mint response returns a ready `iceServers` array so tenants don't hand-assemble URLs.

## 5. Threat model — invariants

- **P0-TURN-1** Allocate requires a nonce round-trip; no allocation for an address that can't receive.
- **P0-TURN-2** `K_p` never leaves the host; project attribution comes only from host-minted usernames.
- **P0-TURN-3** No relayed byte reaches a non-public address or the host's own addresses, except
  in-process same-project relay→relay hairpin. Single classifier: `ip_is_public`.
- **P0-TURN-4** `jkbase-turn` runs sandboxed with no filesystem and no store access; it can't touch VMs,
  disks, or other services.
- **P0-TURN-5** Relay ports are quarantined after release; random assignment.
- **P0-TURN-6** Every cap in §4(f) is enforced before a byte is sent; over-cap drops, never queues.
- **P0-TURN-7** The `turn.` SNI branch in the proxy hands only the decrypted stream + PROXY-v2 header to
  the unix socket; `jkbase-turn` trusts the PROXY header only on that socket (never on TCP 3478).
- **P0-TURN-8** Parsing is bounded: max message size, max attributes, no allocation of attacker-sized
  buffers; fuzzed (§8).
- **P0-TURN-9** Policy-stale ⇒ refuse new allocations after grace; never fail open.

Adversarial review targets (per CLAUDE.md hardening rule): peer-policy bypasses (v4-mapped v6,
6to4/Teredo/NAT64 prefixes, hairpin to non-relay ports, DNS-free so no rebinding but check XOR
decoding), credential forgery/attribution, cap evasion via many credentials/projects, quarantine
races, PROXY-header injection, parser DoS, metering evasion (hairpin double/zero count).

## 6. What it reuses

| Need | Existing piece |
|---|---|
| public-IP classification | `jkbase_common::egress::ip_is_public` |
| token buckets, bounded TTL maps | `jkbase-proxy/src/l4_egress.rs` → hoist to `jkbase-common` |
| port-range vs ephemeral validation | `validate_l4_port_range` pattern |
| port reuse quarantine | L4 `PORT_QUARANTINE` semantics (in-memory variant) |
| minting oracle, key lifecycle, rate limit | `jkbase-server/src/auth_service.rs` (`jkbk_`) |
| reserved host + post-TLS demux | proxy `auth.`/`storage.` branches + `DB_ALPN` demux |
| usage buckets, monthly bandwidth block | `UsageBucket`, `metering_loop` |
| zero-bounce for the `turns:` leg | socket activation + drain (`socket_activation.rs`) |

## 7. Capacity (single host, 1 Gbit/s)

A relayed 1:1 video call: worst case both participants relay, each allocation carries ~1.5–2.5 Mbit/s
each way ⇒ host traffic ≈ 4–6 Mbit/s per call (hairpin halves the uplink cost when both relay through
jkbase: the bytes enter and leave once per side, not twice). With the 256 Mbit/s TURN-plane budget
that's **~50–60 fully relayed calls**, or ~250–600 concurrent calls at a typical 10–20 % relay rate.
Fine for Apex's first year at any plausible volume; it's the number to watch, and the global budget is
the knob. Ports (4.5k) are not the constraint.

## 8. Testing

- Unit: credential mint/verify/expiry/attribution; peer policy table (every `ip_is_public` class,
  host addresses, hairpin same/cross project, non-relay host ports); caps; quarantine; nonce validity.
- Fuzz: STUN/TURN decoder (`cargo fuzz`), PROXY-v2 parser.
- On-box e2e (`tools/dev test` style, real network namespace): two clients behind a simulated
  symmetric NAT (netns + nftables masquerade with random ports) with `iceTransportPolicy:"relay"`,
  over UDP, TCP-3478 and TLS-443; assert media flows and `turn_bytes` metered. Use a pure-Rust TURN
  client in the test, plus one Playwright run of two real Chromium peers forcing relay.
- Negative e2e: relay to `172.16.0.1`, `169.254.169.254`, host public IP:443, host IP:<l4 port>,
  another project's allocation — all dropped and counted.
- Prod smoke: one forced-relay call between two real networks (one cellular), byte count matches.

## 9. Implementation outline

- **T0 — core relay (UDP).** `jkbase-turn` crate + systemd unit + sandbox; STUN/TURN codec,
  allocations, permissions, channels; relay range + quarantine; peer policy; caps; unix-socket
  protocol (policy push, usage pull, kill). `jkbase-server`: `K_p` + `jktk_` store tables, mint API,
  `turn` reserved label, `turn_bytes` metering + bandwidth sum, CLI. Unit + fuzz + on-box e2e (UDP).
- **T1 — TCP 3478 + TLS 443.** TCP framing; proxy SNI branch + PROXY-v2 over unix socket; e2e over
  both.
- **T2 — surface.** Console section, docs, `iceServers` mint response polish, `jkbase turn status`.
- **T3 — IPv6 relayed addresses** (`REQUESTED-ADDRESS-FAMILY`), using the host's /64: unique
  relayed *addresses* instead of ports.
- Adversarial multi-agent review gates T0 and T1 before merge. Prod rollout: OVH edge-firewall rule,
  nftables + notrack rules, new systemd unit shipped by `tools/deploy-server.sh` (needs an addition —
  it ships host binary + agent rootfs today).

## 10. Decisions for Joe

- **(D1)** Separate sandboxed `jkbase-turn` process, not in `jkbase-server`. *Recommended.*
- **(D2)** Implementation: **own Rust codec + relay** (with `webrtc-rs/turn` as reference / possibly a
  dependency for the codec) vs **patched coturn**. *Recommend Rust*: per-project policy, metering,
  peer policy and hairpin are the product, and they don't fit coturn's model; Rust keeps the
  untrusted parser memory-safe. Cost: more to build and to prove than deploying coturn.
- **(D3)** Credentials minted by jkbase via API (secret never leaves host) vs tenant-held HMAC
  secret. *Recommend mint-via-API*; add local-HMAC later if needed.
- **(D4)** Mint endpoint on `turn.<domain>` (ALPN-split from TURN-over-TLS) or on `auth.<domain>`.
  *Lean `auth.`*: keeps `turn.` a pure TURN host and reuses the existing service.
- **(D5)** Relay→relay hairpin same-project only by default. *Recommended.*
- **(D6)** Billing: relayed bytes count against the existing monthly bandwidth quota (v1), or a
  separate TURN line item later.
- **(D7)** Defaults in §4(f) — provisional; confirm the 256 Mbit/s TURN-plane share of the uplink.
- **Business, not design:** whether jkbase can carry a healthcare tenant's call metadata without a
  BAA (jkbase / OVH). Apex may need a BAA-backed TURN provider until this is settled, independent of
  whether this design ships.
