# Function host-mediated outbound I/O — Design

> **Status (2026-06-20).** Locked product arc: make functions **parity-capable with servers** — same network
> identity, same egress fence, first-class ingress routing — without dissolving the in-guest agent seam that
> makes per-function policy + sandbox + observation free. This doc realizes the locked decisions; it does not
> re-litigate the default-allow public model or the three-zone shape. It does fix the design wherever the
> adversarial review (four red teams) found a real hole, and calls out the invariant each fix protects.
>
> **The single load-bearing structural fact.** A wasm component owns **no kernel sockets**. The only
> implementation of `wasi:http/outgoing-handler.send-request` for the proxy world is the agent's
> `WasiHttpView::send_request` for `HostState` (`crates/jkbase-agent/src/function_runtime.rs:262`), and
> `wasi:sockets` stays denied. So **100% of function outbound funnels through one Rust function the guest
> cannot skip**, issued on the guest's `eth0`/TAP. The agent is the policy + observation point *by
> construction*, and the outbound rides the same netfilter fence a server's does. Everything below hangs off
> that one chokepoint.

## 1. Summary, goals & non-goals

Functions today have **zero egress**: `send_request` returns `ErrorCode::InternalError("outbound network is
disabled for functions")` before any socket opens (`function_runtime.rs:262-271`), `WasiCtx` denies
TCP/UDP/DNS with a deny-all `socket_addr_check` (`:279-283`), there are no preopens, and there is no vsock.
That deny floor is the safest possible default and we keep it as the floor — egress is *enabled-but-policed*
on top of it, never by tearing it down.

This arc replaces the unconditional deny with a **host-mediated, zone-classified, IP-pinned** outbound path
that inherits the guest TAP fence whole-cloth, and makes a function a first-class routing backend so it
behaves like a server end to end.

### Goals (all required)

- **(a) Egress parity with servers.** A function reaches the public internet over the same `eth0`→TAP→`jkbr0`
  path a server uses, inheriting the same netfilter FORWARD fence. HTTP-first (`wasi:http/outgoing-handler`),
  enabled-but-policed.
- **(b) Three-zone model with three per-function policy states.** Own-stuff always-allow, platform-internals
  always-deny (the hard fence), public-internet default-allow-plus-observe / allowlist / sandbox.
- **(c) Ingress parity.** A function is a routing backend peer of a server: any `Host`/path the project owns
  can target a function, not just `/functions/{name}`.
- **(d) Observe-by-default.** Every public outbound *decision* (allow/deny) is recorded by host code into the
  existing log-shipping pipe → an observed-egress manifest (audit / IR / safe allowlist-proposal path).
- **(e) Own-bucket ergonomics.** A typed `jkbase:objectstore/store` WIT binding, auto-scoped to the calling
  project, **no key material in wasm**.

### Non-goals (explicit)

- **Not WebSockets / SSE / streaming / long-lived connections — either direction.** Functions stay
  **request/response + fresh-per-request + sandboxed**. The runtime is a `wasi:http/incoming-handler` (proxy
  world) component that cannot emit `101`; ingress parity does not widen this. (§5, §9 P0-INGRESS-UPGRADE.)
- **Not raw-TCP / `wasi:sockets` in phase 1.** Raw TCP is in scope but **deferred to phase 2 behind a pooling
  model** (§8). `wasi:sockets` stays structurally denied this phase.
- **Not a new isolation technology.** No vsock, no host-side fetch, no second NIC, no host loopback path off
  the TAP. The VM/KVM boundary jkbase already trusts is the boundary; the netfilter fence is the backstop.
- **Not a host MITM of function egress.** Unlike the build mirror (build-only), TLS to third parties is
  end-to-end from inside the tenant VM; the host sees ciphertext leaving the TAP.
- **Not S3-dependent.** The manifest rides `LogStore` (local-FS today, pluggable later) — never a privileged
  object-store path for control-plane/audit state.

## 2. The three-zone model

Every function outbound is classified into exactly **one of three destination zones** *before* any
per-function policy is consulted (P0-EGRESS-ZONE-ORDER). The zone fixes the hard treatment; the policy state
(§3) modulates only the **public** zone.

| Zone | Definition | Treatment | Tenant-configurable? |
|---|---|---|---|
| **1 — OWN STUFF** | Intra-project: the project's own servers (`127.0.0.1:{port}`, never leaves the VM), its own functions (`/functions/{name}`, in-agent), its own object-store bucket (`storage.{platform_domain}`, SigV4-scoped to `project_id`). | **ALWAYS ALLOW.** Survives `egress = false`. Zero config. | No — implicit. |
| **2 — PLATFORM INTERNALS** | `169.254.0.0/16` (cloud metadata + link-local), IPv6 link-local `fe80::/10` / ULA `fc00::/7`, the control plane (`api.`, the host's public IP + gateway IP on control/proxy ports), host loopback services, sibling tenant VMs (`172.16.0.0/24`), **all RFC1918 + CGNAT + non-global**. | **ALWAYS DENY** — the hard fence. Identical posture to the server fence. | **No — never.** |
| **3 — PUBLIC INTERNET** | Any other globally-routable public IP after resolution. | **DEFAULT-ALLOW + OBSERVE.** | Yes — via the three policy states (§3). |

### Deny/allow treatment per zone, and the invariant each protects

**Zone 1 (OWN STUFF) — always allow, confined to the VM.**
- Own servers and own functions never reach `send_request`'s public path: a function calling a sibling
  server is host-routed loopback inside the one VM (`proxy_to_server` → `127.0.0.1:{port}`,
  `crates/jkbase-agent/src/main.rs:711`); a function calling another function dispatches in-agent
  (`extract_function_name`, `main.rs:686-693`). No egress, no fence.
- Own object store is the one Zone-1 destination that *does* leave the VM (the agent has no host-loopback
  reach; guest→host is INPUT-fenced with only `:53` open — `tools/setup-bridge.sh:99-103`). It rides the
  public `storage.{platform_domain}` path through the proxy like a server, and is recognized as OWN so it
  survives the sandbox. **OWN classification runs before the policy switch**, so `egress = false` (or a
  non-matching allowlist) cannot deny it — the deny arm is structurally unreachable for OWN destinations.
  > **P0-EGRESS-ZONE-ORDER.** Zone classification precedes the per-function policy. `egress = false`/allowlist
  > can only deny the **public** zone; it can never deny own-stuff nor permit platform-internals.

  > **P0-EGRESS-OWN-HOST-ASSERTED** *(red-team cross-tenant F2; fence F1/F2)*. OWN membership for the storage
  > host is a **host-asserted fact, never a guest-asserted one.** The platform domain + storage host are
  > delivered into the agent through a channel the **host fully controls and the tenant cannot author** — the
  > kernel cmdline (orchestrator-set boot args, `crates/jkbase-orch/src/vm.rs:103`) or a host-written meta
  > region distinct from the deploy artifact, **never** `jkbase.toml`-derived (see §4.6, §7-F2). OWN-storage
  > additionally requires the **post-DNS resolved IP to be the platform's known storage ingress** (host-pinned
  > IP set), not just a hostname match — a name match alone fails open if a tenant ever controls DNS for a
  > look-alike host.

**Zone 2 (PLATFORM INTERNALS) — always deny, not tenant-configurable, dual-enforced.**
The review's central correction (fence-bypass F1/F2/F3): the design originally claimed Zone-2 deny is
"fail-clean in the agent AND fail-closed in netfilter" *for the whole zone*, but **today the netfilter fence
only drops `169.254.0.0/16`** (`setup-bridge.sh:60`); RFC1918 is deliberately open (`:55-59`), the control API
binds `0.0.0.0:9090`, and the proxy's `ufw allow 80/443` is not interface-scoped — so for everything except
the metadata IP the agent classifier was the *sole* layer. **This arc closes that gap as a hard prerequisite
(§9-PREREQ), so Zone-2 deny is genuinely dual-enforced before any egress ships.**

  > **P0-EGRESS-PLATFORM.** The PLATFORM-INTERNALS deny is not tenant-configurable and is enforced in **both**
  > the agent (fail-clean: a catchable `wasi:http` error, keeps the manifest honest) **and** netfilter
  > (fail-closed: the kernel drops it on the TAP regardless of any agent-policy bug). No `jkbase.toml` value —
  > no allowlist entry, no `egress = true` — can reach metadata, the control plane, host services, siblings, or
  > RFC1918. A buggy agent classifier MUST NOT be sufficient to breach Zone 2.

  > **P0-EGRESS-PLATFORM-BY-IP** *(fence F2)*. The control-plane/host-services deny is enforced **by pinned
  > resolved IP** (the host's public IP + gateway IP, host-injected), **not by hostname** — because
  > `api.{platform_domain}` resolves to a *public* proxy IP, so a hostname-only deny is bypassed by IP-literal +
  > spoofed `Host` header, port suffix, trailing dot, or case. Domain-fronting (`Host: api.{domain}` to the
  > public IP) is defeated because the IP itself is dropped at the fence and rejected by the agent's
  > platform-IP list.

**Zone 3 (PUBLIC INTERNET) — default-allow + observe, modulated by policy state.**
Consciously-accepted: default is detection-not-prevention. The allowlist state makes it preventive; the
sandbox state kills it. See §3.

## 3. Per-function policy states + the `jkbase.toml` schema

Three declared states per function, governing **only the public zone**:

| State | `jkbase.toml` | Public zone | Own stuff | Platform internals |
|---|---|---|---|---|
| **(a) default** (field absent) | — | allow + observe/meter | allow | deny |
| **(b) allowlist** | `egress = ["api.stripe.com", "*.twilio.com"]` | **enforced allowlist** (preventive, connect-time, IP-pinned); host not on list ⇒ deny | allow | deny |
| **(c) sandbox** | `egress = false` | **deny all public** | **still allow** | deny |

### Schema (`jkbase-common`)

A new optional tri-state field on `FunctionConfig` (`crates/jkbase-common/src/config.rs:54-70`), deserialized
via an untagged enum because TOML has no native union:

```rust
// FunctionConfig — add after `schedule`
    /// Per-function PUBLIC-internet egress policy. Three states:
    ///   absent          => default: allow public + observe/meter (zero config)
    ///   ["host", ...]    => ENFORCED allowlist (preventive; connect-time, IP-pinned)
    ///   false            => SANDBOX: kill public egress; OWN STUFF still reachable
    /// OWN STUFF and PLATFORM-INTERNALS are zone-classified BEFORE this field is read (P0).
    #[serde(default)]
    pub egress: Option<EgressPolicy>,

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum EgressPolicy {
    /// `egress = false` => sandbox. `egress = true` is ALSO accepted = "explicit default
    /// WITHIN the project ceiling" (documents intent; never escapes a project allowlist — §3 precedence).
    Toggle(bool),
    /// `egress = ["api.stripe.com", "*.example.com"]` => enforced allowlist.
    Allowlist(Vec<String>),
}
```

A project-wide default lives under `[hosting]` (`HostingConfig`):

```rust
// HostingConfig — add
    /// Project-default egress policy for every function that omits its own `egress`.
    /// This is a CEILING, not merely a default (see precedence). Same tri-state grammar.
    #[serde(default)]
    pub function_egress: Option<EgressPolicy>,
```

### Precedence — the project field is a CEILING, not a default *(red-team integrity HIGH-1)*

The review found a fail-open in the naive "most-specific wins" rule: with `function_egress =
["api.stripe.com"]` at the project level, a function writing `egress = true` would resolve to allow-all-public —
*wider* than the project floor, silently bypassing it. Under the untrusted-marketplace framing the sandbox
exists for, a project importing third-party function code must be able to set a floor that no function can
punch through. So:

**A function may NARROW freely but never WIDEN past the project ceiling.** The effective public-egress
capability is computed host-side at deploy as:

1. If only one of (project, function) is present, use it.
2. If both present, the function policy is **intersected against** the project ceiling for widening:
   - project `Allowlist(P)` × function `Toggle(true)` ⇒ `Allowlist(P)` (true = "default within ceiling", not escape).
   - project `Allowlist(P)` × function `Allowlist(F)` ⇒ `Allowlist(P ∩ F)`.
   - project `Allowlist(P)` × function `Toggle(false)` ⇒ `Sandbox` (narrowing always allowed).
   - project `Sandbox` × anything ⇒ `Sandbox` (a sandbox ceiling cannot be widened by a function).
   - project `Toggle(true)`/absent × function policy ⇒ the function policy verbatim (no ceiling to enforce).
3. Absent everywhere ⇒ default state (allow public + observe).

Precedence is collapsed **once, host-side, into a single concrete `ResolvedEgress`** so the agent never parses
`jkbase.toml`, never re-derives precedence, and never sees the ambiguity.

  > **P0-EGRESS-POLICY-HOST-RESOLVED.** Precedence + the tri-state grammar are resolved host-side at deploy into
  > one concrete `ResolvedEgress` written to the function sidecar. The agent receives one of three concrete
  > states (`Default` / `Sandbox` / `Allowlist(Vec<String>)`), immutable for the VM's life. The policy engine is
  > kept out of the untrusted-input parse path, and a function can never widen past its project ceiling.

### How `egress = false` leaves own-stuff intact (exact mechanism)

The connect-time classifier runs Zone 1 recognition **before** the policy switch and **independent of
`ResolvedEgress`** (§4.4). Because the OWN-allow arm short-circuits before the public-zone deny is evaluated,
the code path that returns the sandbox deny is *unreachable* for own-stuff destinations. A `Sandbox` function
therefore 200s on its own bucket / own server / own function and 502s on `api.stripe.com`. This is asserted by
test, not assumed.

  > **Honest scope of the sandbox guarantee** *(red-team integrity HIGH-2)*. `egress = false` means **"no
  > arbitrary public egress,"** *not* "no exfil." The own-bucket (Zone 1) is a public-TLS channel by design, and
  > a sandboxed function can write data into its own bucket that a colluding party reads back out-of-band via
  > the bucket's presigned/public-read surface. We do **not** claim a sandboxed function "cannot phone home" —
  > it can, through its own Zone-1 bucket. For genuinely-untrusted marketplace code that needs the stronger
  > guarantee, the own-bucket binding under sandbox must be scoped to a non-public-readable, non-presignable
  > sub-prefix (open question §11). The honest documented guarantee is: a sandboxed function cannot open an
  > *arbitrary* outbound channel to an attacker-chosen host.

### Schema edge cases

- `egress = true` ⇒ `Toggle(true)` ⇒ default within the project ceiling (documents intent).
- `egress = []` (empty allowlist) ⇒ **rejected at deploy as a config error** pointing the author at
  `egress = false`, *(red-team integrity MED-5)* — `[]` and `false` are otherwise semantically identical for
  the public zone, and a naive author writing `[]` to mean "deny everything including own-stuff" would be
  surprised that own-stuff still works. We make the ambiguity un-writable rather than silently aliasing it.
- `*.example.com` matches one or more leading labels of `example.com`; `api.stripe.com` matches only that host.
  Matching is on the **request hostname**, exact/case-insensitive/trailing-dot-tolerant, **never** suffix or
  substring (so `api.stripe.com.attacker.com` does not match `api.stripe.com` — verified `egress::host_allowed`).
  An allowlisted host that resolves internal is **still denied** (allowlist widens public; it never overrides
  the fence).

## 4. Egress data path + fence inheritance

### 4.1 The path

```
guest fn (wasi:http outgoing-handler.send-request)
  → agent HostState::send_request          [function_runtime.rs:262]  ← THE ENFORCEMENT POINT
     ├─ zone classify (OWN / PLATFORM / PUBLIC), pre-DNS on hostname
     ├─ DNS:   agent's OWN resolver, pinned to 172.16.0.1:53 (NOT ambient resolv.conf)
     ├─ pin:   classify EACH resolved IP (egress::pick_safe_addr / classify_internal); fail closed
     ├─ policy switch (PUBLIC only): Default→allow+observe · Sandbox→deny · Allowlist→match-or-deny
     ├─ observe: emit EgressEvent BEFORE connect (contact), refine bytes after (§6)
     └─ connect: agent-built hyper client → TcpStream::connect(PINNED addr) on eth0
                 redirect-follow DISABLED; each 3xx re-enters send_request from step 1
  → eth0 → guest TAP → jkbr0 → netfilter FORWARD fence   [setup-bridge.sh]
     ├─ 169.254/16 DROP (metadata)                                     [fail-closed backstop]
     ├─ RFC1918 + gateway + host-public-IP DROP  (NEW prereq §9)       [fail-closed backstop]
     ├─ MASQUERADE 172.16.0.0/24 → uplink · per-TAP bridge_slave isolated · ip6tables DROP
  → public internet (TLS end-to-end; host sees ciphertext)
```

The connect happens **on `eth0` inside the tenant VM**. There is no host-side fetch, no vsock, no second NIC.
Because the agent has no path off the TAP, it *cannot* bypass the fence even if its own policy is buggy: the
netfilter fence is the backstop, the agent's in-process policy is the precise layer on top.

  > **P0-EGRESS-TAP.** Every function outbound is issued by agent code on `eth0` and MUST ride the guest TAP,
  > inheriting the netfilter FORWARD fence + L2 port-isolation. The agent MUST NOT acquire any host-side network
  > path (no vsock — `vsock_cid: None`, `main.rs:1388`/`:1735`; no second NIC; no host loopback) to make an
  > outbound. Enforced structurally: the agent has only `eth0` + loopback.

  > **P0-EGRESS-TLS-E2E.** TLS to third parties is built by the agent inside the tenant VM; the host sees only
  > ciphertext leaving the TAP. The host MUST NOT MITM function egress.

### 4.2 What flips from the structural-deny floor

Surgical, HTTP-first; the deny floor is the starting point, not torn down:

1. **`HostState::send_request` (`function_runtime.rs:262`) becomes the connect-time enforcement point.** The
   deny body is replaced with: zone-classify → resolve (agent-side) → classify each resolved IP → policy
   switch → observe → connect to the pinned address with an **agent-built hyper client** (not upstream
   `default_send_request`, because we must own DNS and the pinned `SocketAddr`).

2. **`wasi:sockets` stays denied (`:279-283`).** `allow_tcp(false)`, `allow_udp(false)` stay; `allow_ip_name_lookup`
   stays **false for the guest** (the guest never resolves — the agent does, so it can pin the result, closing
   guest-resolver TOCTOU); no preopens. HTTP egress is enabled *only* through `send_request`, so the SSRF gate
   has exactly one door.

   > **P0-EGRESS-ONEDOOR.** `wasi:sockets` stays denied; HTTP egress is enabled ONLY via `HostState::send_request`.
   > There MUST be exactly one code path from guest to a socket.

3. **`HostState` gains an immutable per-invocation policy handle** `egress: Arc<FnEgressPolicy>` carrying
   `{ resolved_state, allowlist, platform_ip_set, storage_target, resolver, log_sink }`, snapshotted from
   `LoadedFunction` (which gains an `egress` field beside `env`) at each invoke (`:573`). Fresh-per-request: a
   new `HostState` (hence fresh policy snapshot + fresh hyper client) per call, no cross-request bleed.

### 4.3 `socket_addr_check` is NOT a second layer this phase — the real backstop is netfilter *(red-team integrity MED-1 / fence F6)*

The two sub-designs disagreed: one cited `socket_addr_check` (the wasi `TcpConnect` predicate) as a
belt-and-suspenders second layer; the other (and the chosen data path) builds a bespoke hyper client and
`TcpStream::connect`s the pinned address directly. **The proxy world does not import `wasi:sockets`, and the
agent's own connector never routes through wasmtime-wasi's socket machinery, so `socket_addr_check` is never
consulted in phase 1.** We resolve the contradiction:

- The chosen path is the bespoke pinned hyper connector with the SSRF/zone check **inline in `send_request`**
  as the single, real agent-side gate.
- The **genuine second layer is the netfilter TAP fence** (P0-EGRESS-PLATFORM, now dual-enforced after the
  §9 prereq), not `socket_addr_check`.
- To make the agent-side redundancy real rather than imaginary, `classify_internal` is invoked from **two
  code sites**: once in the policy-classification step, and again in the connector immediately before
  `connect()` — so a bug in the policy site is still caught by the connector site.

  > **P0-EGRESS-DUAL-ENFORCE (phase-1 form).** The fence is enforced by (i) `classify_internal` inline in
  > `send_request`, re-invoked at the connector immediately before `connect()`, AND (ii) the unbypassable
  > netfilter fence on the TAP. `socket_addr_check` is NOT in the phase-1 path and MUST NOT be cited as a layer
  > until phase 2 (raw `wasi:sockets`) actually imports the socket world.

### 4.4 Zones classified before connect, post-DNS, per resolved IP

Classification runs **pre-DNS on the hostname** (OWN recognition, allowlist match) and **again post-DNS on
each resolved IP** (defense in depth). Decision order:

1. **OWN recognition (pre-policy):** host == the host-asserted `storage_target` for this project (and the
   resolved IP ∈ the host-pinned storage ingress set) ⇒ ALLOW, regardless of state.
2. **Post-DNS platform check:** resolve host → `Vec<IpAddr>`; for **each** address,
   `classify_internal(addr)` ⇒ DENY if internal (re-checked per address, fail-closed on any internal address
   in a mixed RRset — though see §4.5 on `pick_safe_addr` semantics).
3. **Policy switch (public only):** `Default` ⇒ allow+observe; `Sandbox` ⇒ deny; `Allowlist` ⇒ match-or-deny.
4. **Connect-pinned:** dial only the resolved+vetted IP, never re-resolve.
5. **Redirect:** each 3xx re-enters step 1 with the new URL.

`classify_internal` returns deny for: `169.254.0.0/16` + `fe80::/10`; `172.16.0.0/24` other than the OWN
gateway path; loopback (`127.0.0.0/8`, `::1`); **all** RFC1918 (`10/8`, `172.16/12`, `192.168/16`), ULA
`fc00::/7`, CGNAT, non-global/unspecified/multicast; and the host-injected platform-IP set (control plane +
host public/gateway IPs). It is the fail-closed **superset** of the netfilter fence — stricter on purpose,
because a function has no legitimate RFC1918 destination other than OWN, matched first.

  > **P0-EGRESS-POST-DNS.** Classification is on **resolved addresses**, re-checked per address; a public name
  > resolving to an internal IP is denied. The IP-literal case (`http://169.254.169.254/`) is the same check
  > (resolution of a literal is the literal). Fail closed on empty resolution / NXDOMAIN.

**IPv6 is refused outright this phase** *(fence F5)*. The product is IPv4-only egress (the guest boots
`ipv6.disable=1`, `vm.rs:103`; the fence drops v6 FORWARD/INPUT). For function egress the connect originates
in-process, so v6 is blocked only by the agent classifier (the fence never sees an agent v6 connect it
declines to make). Rather than depend on `v6_is_public` edge-exhaustiveness (NAT64 `64:ff9b::/96`,
IPv4-compatible `::a.b.c.d`, v4-mapped `::ffff:`), the agent **refuses to connect to any IPv6 address
whatsoever** in phase 1. One rule, removes a whole class of classifier-edge risk.

### 4.5 DNS resolution + IP pin

The agent resolves on `eth0` through the gateway forwarder `172.16.0.1:53` — the only DNS the fence permits
(`setup-bridge.sh:99-103`). It pins to the first egress-safe **public** address via `egress::pick_safe_addr`
and connects to *that literal address*, never re-resolving for the connect. This defeats DNS-rebind/TOCTOU.

  > **P0-EGRESS-RESOLVER-PINNED** *(red-team integrity HIGH-4)*. The agent uses an **explicit** resolver address
  > (`172.16.0.1`), configured programmatically — **not** ambient `/etc/resolv.conf` resolution. The
  > `RUNTIME_RESOLV_CONF` write today targets *server-container overlays* (`container_supervisor.rs:541`), not
  > the agent's own rootfs; the agent's resolver must be provisioned independently and asserted at boot, so a
  > misconfigured rootfs fails **closed** (no resolution → deny) rather than falling back to guest-side
  > resolution. `allow_ip_name_lookup(true)` MUST NOT be flipped to paper over a resolver gap.

  > **P0-EGRESS-PIN.** The connector dials only the exact vetted public IPs from this resolution; no
  > re-resolution between vet and connect. `pick_safe_addr` pins to a vetted-public address and **skips**
  > internal addresses in a mixed RRset (it never dials the internal one — connecting only to the vetted public
  > IP is itself safe). *(Integrity LOW-2: we keep `pick_safe_addr`'s skip-public semantics and drop the earlier
  > "fail-closed on any internal address in the RRset" claim — it was stricter than the shared code and
  > unnecessary, since the internal address is never dialed. Changing it would also change the build proxy's
  > behavior.)*

  > **P0-EGRESS-HOST-AUTHORITY-COHERENT** *(fence F4)*. The hostname used for the allowlist check, the hostname
  > resolved, the IP pinned, and the `Host`/`:authority` sent upstream MUST all be the **same** name. Reject any
  > request where they diverge; re-derive `Host` from the vetted name and never forward a guest-set `Host` that
  > differs from the connect authority. This closes the host-header desync that would otherwise let a function
  > pin allowlisted-host-A's IP but send `Host: not-on-allowlist`.

`egress::{ip_is_public, host_allowed, pick_safe_addr, classify_internal}` are **hoisted from `jkbase-server`
into `jkbase-common`** so the agent links them without pulling in `jkbase-server`, guaranteeing the function
fence and the build fence apply **byte-identical** public-IP logic (v4-mapped-IPv6 canonicalization via
`to_canonical()` included).

  > **P0-EGRESS-SHAREDLOGIC.** Public-IP / allowlist logic is the SAME code as the build egress proxy, hoisted to
  > `jkbase-common`. No divergent reimplementation.

### 4.6 Redirect handling — sound for honest-client-vs-hostile-upstream; not load-bearing vs a hostile guest

`wasi:http` does not auto-follow redirects; the guest re-issues each hop as a new `send-request`, so **every
hop re-enters `send_request` and is re-classified + re-resolved + re-pinned from scratch.** A 200→302→
`169.254.169.254` chain is caught on the second hop by post-DNS `classify_internal` *and* the netfilter DROP.

  > **Honest framing** *(fence F7)*. Against the *hostile-guest* threat model, redirect re-checking adds nothing —
  > a hostile guest writes its own client and simply requests the internal target on hop 0, where the pin +
  > classifier already apply. Redirect re-checking is a genuine defense only for an *honest client hitting a
  > hostile upstream*. So the load-bearing SSRF property is "classify + pin every `send_request`, hop 0
  > included" — not the redirect re-check. We do not market redirect-recheck as a hostile-guest isolation
  > property.

  > **P0-EGRESS-NO-HOST-REDIRECT** *(red-team integrity MED-2)*. The agent's outbound HTTP client MUST be
  > configured with redirect-follow **disabled** (`redirect::Policy::none()`), so a 3xx is returned to the guest
  > verbatim and the guest must re-issue (re-entering the gate). A one-line connector-config change to follow
  > `Location` inside the agent would silently remove the per-hop gate — forbidden and tested.

### 4.7 Streaming / cancellation — in-flight outbound aborted on timeout

The outbound future runs inside the guest handler, which runs inside the spawned task (`:590`). The wall-clock
`timeout` (`:606`) + unconditional `task.abort()` on **every** exit path (`:645` — the load-bearing DoS fix,
review B1/M2/M5) already covers in-flight outbound: aborting the task drops the future tree, dropping the
in-flight `send_request` future. Two requirements make abort *clean*, not merely cooperative:

  > **P0-EGRESS-ABORT.** Request timeout/abort MUST cancel any in-flight outbound and leave **no live outbound
  > socket**. The outbound connection task MUST be owned by the invocation future (not a detached hyper pool
  > task) so `task.abort()` tears down the FD → FIN/RST on the TAP. A half-open connection outliving the abort
  > would pin an FD + a conntrack entry.

  > **P0-EGRESS-BUDGET-CLAMP.** Honor `OutgoingRequestConfig` connect / first-byte / between-bytes timeouts but
  > `min()` each against the remaining wall-clock budget, AND impose aggressive defaults: connect ≤ a few
  > seconds, first-byte ≤ a few seconds, and a **between-bytes idle timeout** (the slowloris-body defense). See
  > §9 DoS for why the 30 s wall clock alone is insufficient once a function can park on I/O.

## 5. Ingress parity — function as a first-class routing backend

The edge needs **zero** changes: the proxy already treats a backend as a whole VM addressed by IP and forwards
`Host`+path verbatim into the guest (`crates/jkbase-proxy/src/lib.rs:537-591`). All work lands **inside the
tenant's own VM** (the agent) plus a no-op wire-schema note. The single load-bearing line blocking it is the
`service == "server"` filter at `jkbase-agent/src/main.rs:526`.

### Data model

`RouteTarget { service: String, name: String }` (`config.rs:48-52`) already round-trips `service = "function"`
end to end via `_routes.json` — **no wire-schema migration**. We promote `service` to a typed backend kind at
the agent's deserialization boundary only. `load_route_config` (`main.rs:507-532`) stops dropping function
routes:

```rust
enum RouteKind { Server, Function }
struct RouteEntry { prefix: String, name: String, kind: RouteKind }

// load_route_config: map service -> kind; unknown => drop (fail closed)
"server"   => RouteKind::Server,
"function" => RouteKind::Function,
_          => return None,   // forward-compat: unknown kind dropped
```

### Dispatch

`handle_request` walks one ordered route table, dispatching by kind (`main.rs:560-574`). `/_jkbase/*` control
endpoints are checked **first** (`:540-558`), before the route walk — verified, so a tenant `[routes."/"]`
catch-all **cannot** shadow `/_jkbase/logs|health` (red-team integrity MED-4, SOUND). The legacy
`/functions/{name}` prefix stays as an always-on implicit function route (keeps existing deployments + the e2e
harness working); explicit `[routes]` entries take precedence by being walked first.

- **Path semantics (DECIDED):** the function receives the **full, unstripped path** — identical to a server
  backend (`proxy_to_server` forwards `path_and_query` verbatim; `invoke_function` already passes the full
  path). The function owns its own sub-routing. A future opt-in `strip_prefix` is out of scope.
- **Missing-function route ⇒ `404`, no fallthrough to static.** This deliberately changes today's fallthrough
  contract (a misspelled function name currently serves the static site) to prevent a declared-but-missing
  function from accidentally exposing the metadata image's `_`-prefixed control files.
- **Host scoping (DECISION):** the common case (`/api/* → fn` on the default host) needs nothing. For
  host-scoped routes we reuse the existing trusted, inbound-stripped `x-jkbase-site` channel — **no new proxy
  header**. *(Red-team cross-tenant F6)*: because `x-jkbase-site` is only set when the host maps to a specific
  site, a no-site custom domain cannot be distinguished from the default host by `(site, prefix)` and a
  `[routes."/"]` function would become a catch-all across **all** the project's hosts (including the public
  apex). We therefore either (a) inject the **resolved host-key** as a trusted header for the agent to match
  on, or (b) restrict function routes to path-scoping only and document the apex-exposure consequence. We do
  **not** ship host-scoping that silently degrades to catch-all on no-site custom domains. This is intra-project
  only — no cross-tenant reach.

### End-to-end `api.proj.example/* → fn`

1. **Host → VM (edge, unchanged):** `api.proj.example` claimed in `DomainMap` as a custom domain → this
   `project_id`; `proxy_request` resolves host-key → VM IP and `forward_request`s. The proxy has no concept of
   function-vs-server.
2. **Path → function (in-VM):** `[routes."/"] service="function" name="api"` (compiled to `_routes.json`)
   dispatches to `invoke_function(state, "api", req)`.

  > **Reserved-host inviolability (verified SOUND).** `api.{platform_domain}` and `storage.{platform_domain}`
  > short-circuit at the proxy on **exact** `Some("api")`/`Some("storage")` *before* any `DomainMap`/tenant-route
  > lookup (`lib.rs:278-301`); `extract_subdomain` returns the **full** hostname for custom domains, so
  > `api.proj.example` (where `proj.example` is the tenant's apex) never collides with the platform `api.` label.
  > A tenant route is matched only *after* the request is already inside the tenant's own VM, so it cannot
  > intercept control-plane or object-store traffic.

### Request/response limits — and why upgrade is structurally impossible

Functions stay request/response, buffered, fresh-per-request. The runtime cannot emit `101` (it's a
`wasi:http/incoming-handler` proxy-world component); `invoke_function` buffers the request body
(`MAX_REQUEST_BODY = 10 MiB`, `main.rs:830,846`) and returns a single buffered `Full<Bytes>` (response capped at
`MAX_RESPONSE_BODY = 10 MiB` → `502 "function response too large"`, `function_runtime.rs:638`). Function dispatch
never touches the wsproxy relay (`proxy_to_server` is the only path wired to it). An upgrade request to a
function route is **rejected up front with `426 Upgrade Required`** (before buffering the body) for a clean
signal; servers remain the only upgradable/streaming backend.

  > **P0-INGRESS-HOST-TRUST.** Backend-kind resolution (server vs function) happens **only inside the tenant's own
  > VM**, from `_routes.json` in that VM's host-built metadata image. The proxy routes by `Host` → `project_id`
  > → VM IP exactly as today and gains **no** awareness of function-vs-server. A malicious `_routes.json` can
  > only mis-route traffic *within its own VM*, never to another tenant — the host/guest trust boundary does not
  > move.

  > **P0-INGRESS-UPGRADE.** Function backends remain strictly request/response. The runtime cannot emit `101`,
  > function dispatch never invokes the wsproxy relay, and upgrade requests to function routes get `426`. This is
  > what keeps a function from being coerced into a long-lived connection that breaks fresh-per-request isolation
  > and the per-VM concurrency bound. Long-lived/streaming traffic MUST be a `server`.

  > **P0-INGRESS-BODYCAPS.** A function reached via an arbitrary route is subject to the identical 10 MiB
  > request/response caps as the `/functions/` path — the caps live in the single `invoke_function` call site.
  > Widening the route surface does not widen the body surface.

## 6. Observe-by-default manifest

Default-allow public egress is **detection, not prevention** — a consciously-accepted trade. The agent is the
unavoidable mediator, so it is the observation point for free. This is a recording subsystem only; enforcement
lives in §4.

### Data model — reuse the log frame, do not invent a wire type

Reuse `LogLine` (`jkbase-common/src/logs.rs:9-24`) as the transport frame: `server` = the function name,
`stream` = the reserved sentinel `"egress"`, `line` = a compact JSON `EgressEvent`, `seq`/`timestamp` assigned
by `LogSink::push` exactly as for app logs.

```rust
// jkbase-common/src/logs.rs — next to LogLine, serialized into LogLine.line
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressEvent {
    pub function: String,
    pub dest_host: String,         // guest-requested authority, pre-DNS: "api.stripe.com"
    pub dest_port: u16,
    pub dest_ip: Option<String>,   // pinned IP if a socket opened; None on pre-connect deny
    pub verdict: Verdict,          // allow | deny-allowlist | deny-sandbox
    pub bytes_out: u64,            // ADVISORY (best-effort, see P0-OBS-BYTES-ADVISORY)
    pub bytes_in: u64,
    pub method: String,
    pub status: Option<u16>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict { Allow, DenyAllowlist, DenySandbox }
```

We record **metadata, never payload** — `host:port`, resolved IP, method, status, byte counts, verdict,
timestamp. **Never** the path, query, headers (no `Authorization`/cookies/keys), or body. The agent originates
TLS (it's in the tenant VM) so it *could* see plaintext; the schema deliberately has no field that can hold a
path/header/body, so this is enforced by type, not discipline.

  > **P0-OBS-METADATA-ONLY.** `EgressEvent` records destination metadata only. There is no field that can hold a
  > path/header/body. The manifest is the project owner's data (same per-project auth scope as their logs), never
  > cross-tenant visible, deleted with the project, never aggregated cross-tenant.

### Data path — reuse the entire log-shipping pipe, with a unified sink

```
guest --send_request--> agent (classify, verdict) --LogSink::push(fn,"egress",json)-->
  bounded VecDeque (monotonic seq, per-boot) --GET /_jkbase/logs?since--> [host PULLS]
  LogShipper::ship ((boot_id,seq) dedup, 2s poll + flush-on-hibernate) --> LogStore::append
  --> host-side filter stream=="egress" --> EgressManifest projection (read-only)
```

  > **P0-OBS-UNIFIED-SINK** *(red-team integrity BLOCKER-1)*. The `LogSink` (and its `seq` + `boot_id`) MUST be a
  > **shared agent-level primitive**, not a `ContainerSupervisor` private. Today `LogSink` is private to
  > `ContainerSupervisor` and `FunctionRuntime` has no handle to it; the design's "just `Arc`-clone the sink"
  > inverts that ownership and is a real refactor, not a one-liner. Promote one `Arc<LogSink>` (with one `seq`
  > source and one process-wide `boot_id`) constructed in `main`, handed to **both** `ContainerSupervisor::new`
  > and `FunctionRuntime`/`HostState`. Two independent `seq` spaces under one `boot_id` would collide the
  > shipper's `(boot_id, seq)` cursor and silently drop egress events — i.e. the manifest would fail **open**
  > (unobserved egress while the operator believes it is observed). This refactor is a prerequisite, not a nicety.

  > **P0-OBS-UNCONDITIONAL.** An event is emitted for **every** Zone-3 outbound decision on all verdicts
  > (`allow`/`deny-allowlist`/`deny-sandbox`), written by host code in the path the guest cannot skip. A function
  > cannot suppress its own egress record. **Emit the contact event (host:port, verdict, ts) BEFORE the connect**,
  > then refine `bytes`/`status` after — so an abort/timeout can lose the byte *refinement* but never the
  > *existence* of the destination (red-team integrity HIGH-3). Zone-1 (own-stuff) is informational; Zone-2
  > denials ride the security log (an attack signal), not the egress manifest.

**Single stream, not a parallel `/_jkbase/egress` endpoint** — the `stream` tag partitions losslessly and a
second pull loop doubles the guest-poll surface + needs a second cursor. **But** *(red-team integrity MED-3,
LOW-1)*:

  > **P0-OBS-STREAM-RESERVED.** The `stream == "egress"` value is **reserved**: only the host egress mediator may
  > write it. Agent code that drains *guest* output already hardcodes `stdout`/`stderr` and MUST NOT let a guest
  > influence the `stream` tag — so a guest cannot inject forged egress rows to bury a real exfil destination or
  > forge a clean audit trail, and cannot tag app-log spam `egress` to inherit the longer egress retention. The
  > manifest projection trusts `stream=="egress"` rows only because the guest path structurally cannot produce
  > them; assert + test this invariant.

### Metering split — bytes-vs-destination

The TAP sampler (`metering::read_tap_bytes`, `metering.rs:25`) measures **total per-project** egress with no
destination/per-function attribution — structurally wrong for a destination manifest. So:

- **Bulk byte totals → metering, unchanged.** A function's outbound naturally shows up as TAP `rx_bytes` in the
  existing `UsageBucket`; the monthly bandwidth cap already governs runaway egress (but see §9 DoS for why the
  60 s/monthly cadence is insufficient as the *only* control). **Do not add per-destination columns to
  `UsageBucket`** — destination data is event-shaped, not gauge-shaped.
- **Per-destination, per-function attribution → the log pipe** (above). Only the mediator sees
  `(function, host:port, verdict)`.

  > **P0-OBS-BYTES-ADVISORY** *(red-team integrity HIGH-3)*. `EgressEvent.bytes_*` are measured at the agent's
  > application/ciphertext boundary and are **best-effort/advisory** (a deliberately-aborted mid-stream transfer
  > under-counts them). They exist for proportionality/anomaly signal, never for invoicing and never for a
  > threshold-based auto-alert a tenant can duck by aborting. **Billing reads the kernel-authoritative TAP
  > counters.** The trustworthy IR primitive is the per-destination **contact** (host:port + verdict, emitted
  > pre-connect), not the byte count.

### Migration path — auto-PROPOSE an allowlist (propose-only, never auto-apply)

Over a window (default 14 days; egress events retained ≥30 days via a `stream`-keyed `LogStore` retention rule,
distinct from high-churn app-log rotation), group `verdict==allow` events by function and take the distinct
`dest_host` set as the **proposed** allowlist, surfaced on the console / `jkbase functions egress propose
<name>` as a copy-paste `egress = [...]` block.

  > **P0-OBS-PROPOSE-ONLY.** Proposals are **NEVER** auto-applied. The observed destination set is
  > attacker-influenced (all tenants untrusted): auto-promoting observed hosts into an *enforced* allowlist would
  > let a compromised function launder a future exfil channel through the observation window. The human (project
  > owner) editing `jkbase.toml` and redeploying through the normal authenticated path is the trust anchor the
  > observation stream is not.

  > **Proposal UX is a convenience, not a security boundary** *(red-team integrity BLOCKER-2)*. The earlier
  > mitigation — "annotate each host with count/last-seen so a one-off `evil.example` is distinguishable" — is
  > defeated: an attacker controls call frequency and inflates `evil.example` to `count=40k, daily`,
  > indistinguishable from `api.stripe.com` by the exact signal we leaned on. So: (1) drop the claim that
  > count/last-seen distinguishes good from evil; (2) surface **provenance** signals the attacker can't fake
  > cheaply — first-seen-relative-to-deploy, whether the host was reached before the most recent redeploy; (3)
  > render proposals as a **NEW-since-last-review diff**, so a poisoned entry is audited as a delta rather than
  > hidden in a flattened set; (4) never include in a proposal any destination whose pinned IP was ever
  > non-public or platform-owned — those are attack signals, not candidates. Propose-only (the owner's own
  > blast radius) is the real boundary.

## 7. Object-store own-bucket binding (`jkbase:objectstore/store`)

A typed capability handle to the project's own bucket — `get/put/list/delete` — with **no key material in
wasm** and **no host/port/URL surface**. Pure ergonomics on a seam the function already has (a function can
*already* reach `storage.{domain}` like a server with a SigV4 key held as a secret); it changes **who holds the
credential and where the request egresses**, not the trust topology. The request still lands in
`objectstore/{id}` — the same per-project FS root, the same `refresh_and_reserve` quota ledger, the same
owner re-bind that the SigV4 path enforces (`crates/jkbase-server/src/objectstore_service.rs:437-501`,
`:486-489`); `{id}` is host-asserted, never guest-named.

### The WIT — transport-free

```wit
package jkbase:objectstore@0.1.0;
interface store {
    variant error { not-found, access-denied, quota-exceeded, too-large, invalid-key, internal }
    record object-meta { key: string, size: u64, etag: string, last-modified: u64 }
    record list-page { objects: list<object-meta>, common-prefixes: list<string>, next-cursor: option<string> }
    get:    func(key: string) -> result<list<u8>, error>;
    put:    func(key: string, body: list<u8>) -> result<_, error>;
    delete: func(key: string) -> result<_, error>;
    list:   func(prefix: string, delimiter: option<string>, cursor: option<string>) -> result<list-page, error>;
}
world function { /* ...wasi:http/proxy imports... */ import store; }
```

Deliberately absent: any `bucket`, `endpoint`, `region`, `host`, `credentials`, `presign`, `multipart`. The
function names *keys*; the agent supplies *everything else*. The type system forecloses "talk to bucket X of
project Y". `list-page` maps 1:1 onto the existing `list_v2` engine method (S3 delimiter/common-prefix
folding). Buffered (`list<u8>`, not `stream`), bodies capped at the function 10 MiB ceilings.

### Data path — the credential is the highest-risk element; fix it before shipping *(red-team cross-tenant F1/F3, F5)*

The naive fulfillment — auto-mint a long-lived `AccessKey` and inject its `secret_key` into the per-VM sidecar
`env` for the agent to read "host-side" — is a **BLOCKER**: "host-side" here means *the agent, which runs
IN-GUEST*, inside the tenant's blast radius. The tenant can read `_functions/{name}.json` off the metadata
block device from any co-deployed process; the `WasiCtxBuilder::env` filter only hides it from one wasm
component's `process.env`. A captured key is a **standing, exfiltratable SigV4 credential** the tenant didn't
choose and can't see to rotate, valid until the owner changes — strictly worse than today's "tenant pastes
their own key." And the agent, holding project A's credential and choosing the destination, is a confused
deputy that could be aimed at a tenant-influenced host (F3).

So this design **rejects the standing-key fulfillment** and adopts:

  > **P0-OBJ-NO-STANDING-KEY.** The binding MUST NOT inject a long-lived project `AccessKey` secret into the VM.
  > Use **short-lived, request/boot-bound credentials**: the platform mints an STS-style token scoped to
  > `project_id` with a TTL of seconds, re-minted per deploy/boot, signed by the agent host-side. Even captured,
  > it expires — matching the fresh-per-request ethos. (The control-plane path to mint/scope these reuses the
  > existing `AccessKey { project_id, tenant_id }` machinery but issues ephemeral tokens, not permanent keys.)
  > The longer-term direction is host-identity-asserted mediation that needs no credential in the VM at all,
  > deferred (§11) because it requires a guest→host control channel that does not exist today.

  > **P0-OBJ-PINNED-DEST.** The agent MUST only ever send the binding-credential-signed request to a
  > **host-pinned, platform-controlled storage endpoint** — the literal platform storage host + platform ingress
  > IP, both from the host-controlled meta region (P0-EGRESS-OWN-HOST-ASSERTED), never from anything reachable
  > through `jkbase.toml`. The agent refuses to sign for any other host. This makes the agent incapable of being
  > aimed at an attacker endpoint even if other config is compromised, and closes the "sign-and-send A's
  > credential to `storage.attacker.example`" oracle.

  > **P0-OBJ-NOKEY.** No credential (token or key) is ever present in the guest's `process.env` /
  > `wasi:cli/environment`. The binding reads it host-side in the agent and filters it out of `WasiCtxBuilder::env`.

  > **P0-OBJ-RESERVED-CHANNEL** *(red-team cross-tenant F5)*. The binding credential is carried in a **separate
  > top-level sidecar field** the tenant-secret merge never touches — `inject_function_secrets` only writes into
  > `env`, so a dedicated field has no namespace overlap. Additionally, reserve the credential name in the
  > function secret-merge the way servers reserve `RESERVED_ENV` (functions have no such filter today): drop any
  > tenant secret colliding with the reserved name, and write the platform credential last so it always wins.
  > This closes the merge-order confused-deputy on the credential channel.

The agent (in the VM) resolves the host-pinned storage host, opens TLS end-to-end over `eth0`/TAP (Zone-1
traffic — always allowed, terminating at the proxy's reserved-host branch, never a sibling/control-plane), and
owns the SigV4 signing with the ephemeral token. Quota + isolation are **inherited for free** because the
request terminates at the unchanged `ObjectStoreService` front: `{id}` from the verified token's `project_id`,
`refresh_and_reserve` fail-closed, the same billing rollup, the same owner re-bind.

  > **P0-OBJ-SCOPE.** The bucket root is `objectstore/{project_id}` where `project_id` is host-verified from the
  > credential, never from guest input. The WIT exposes no project/bucket/host surface; a guest cannot name or
  > reach another project's bucket.

  > **P0-OBJ-QUOTA / P0-OBJ-OPAQUE.** Every `put`/`delete` passes the unchanged `refresh_and_reserve` ledger and
  > folds into the same per-project billing rollup; over-cap bodies fail closed (`error::too-large`) before host
  > buffering. Host error detail (paths, ids, internal strings) is **never** reflected into the WIT `error`
  > variant (matches the "don't reflect errors" hardening, commit `e933657`).

  > **P0-OBJ-ZONE1.** The binding is OWN-STUFF, **survives `egress = false`**, is exempt from the public-egress
  > allowlist (`egress = ["api.stripe.com"]` need not — and must not — list the storage host), and cannot be
  > repurposed to reach Zone 2 because the WIT can only name keys in the project's own bucket. (See §3's honest
  > sandbox-scope note: this same always-allow property is the exfil-via-own-bucket caveat.)

The `store` handle is fresh per `HostState` (no client/connection state bleeds across invocations); the storage
connection is **not** pooled by the function (pooling lives only in a future long-lived tier, §8) — each
invocation touching the bucket pays a TLS handshake, acceptable for coarse-grained object calls.

## 8. Raw-TCP / `wasi:sockets` + pooling — DEFERRED (phase 2)

> **Status: PHASE 2.** Designed here so phase-1 code lands without foreclosing it; **no `wasi:sockets` code
> ships until the §8 gate is met.** Phase 1 (HTTP egress) is the prerequisite and the proving ground for the
> connect-time fence this phase reuses.

### Why a separate phase — the structural mismatch

Functions are **fresh-per-request** — a new `Store`+`HostState`+`ResourceTable` per invocation, the
load-bearing no-bleed property. A raw TCP DB connection is the opposite: long-lived, stateful, expensive to
establish. Connect-per-invocation produces a **handshake storm** and exhausts the DB's `max_connections` — the
canonical serverless-database failure. Pooling MUST live in a **long-lived tier**, never the ephemeral
function. The only long-lived thing in the data path is the **agent** (one per VM, lives for the warm
lifetime).

### The fence is reused, not new

To enable raw TCP: at `HostState::new` (`function_runtime.rs:274-295`) flip `allow_tcp(true)` and replace the
deny-all `socket_addr_check` with the **same** three-zone predicate phase 1 installs, applied to
`SocketAddrUse::TcpConnect`, post-DNS, per resolved IP. `wasi:sockets` is already linked via
`add_to_linker_async`; the capability is entirely `WasiCtx`-gated. **In phase 2 the proxy/socket world imports
`wasi:sockets`, so `socket_addr_check` becomes a genuine second layer** — resolving the MED-1 concern for this
phase only.

  > **P0-RAWTCP-FENCE-PARITY.** Raw-TCP connect uses the same connect-time predicate and three-zone treatment as
  > HTTP egress; PLATFORM INTERNALS are DENY, non-configurable; the socket is a guest-kernel socket on `eth0`
  > riding the netfilter fence + L2 port-isolation (a predicate bug cannot reach a sibling). TLS is end-to-end.
  > `egress = false` denies PUBLIC raw-TCP exactly as PUBLIC HTTP; OWN still connects.

### Agent-as-pooler, and its protocol-blind limit

The agent owns an in-VM pool (`(function, dest_host, dest_port) → VecDeque<IdleConn>`) that outlives any
invocation, living alongside the concurrency semaphore in `main.rs` — **not** in the per-request `HostState`. A
function's connect is mediated by the agent, which lends a borrowed connection and checks it back in (or tears
it down) at invocation end.

The agent is **protocol-blind**: it sees an opaque byte stream and cannot know whether a returned connection
carries residual session state (open txn, `SET search_path`, prepared statement, changed role). Reusing such a
connection would leak session state across invocations.

  > **P0-RAWTCP-NO-SESSION-LEAK.** Pooled connections are reused **only per-`(function, destination)`, never
  > cross-function, never cross-tenant** (structurally impossible — the pool is per-VM, the VM is the boundary). A
  > connection is returned to the idle set **only if explicitly marked clean/reusable by the guest; absent an
  > explicit signal it is force-closed** *(red-team DoS F6: default fail-closed, NOT clean-on-normal-return)* —
  > because a function that returns normally but left a transaction open would otherwise poison the pool, and a
  > reused connection across two different end-users' requests to the same function leaks end-user A's DB session
  > into B's request. Dirty/aborted/errored connections are always force-closed. Document the reuse semantics
  > loudly so app authors know a pooled connection may carry their own prior request's session.

### Better-than-raw-TCP: HTTP query driver / managed-DB HTTP path (rides phase 1)

Raw-TCP `wasi:sockets` is the **BYO-DB escape hatch**, not the recommended path. Two protocol-aware
alternatives dominate it:

1. **DB-side / sidecar pooler (PgBouncer-class):** the function opens raw TCP to a transaction-mode pooler that
   resets session state at transaction boundaries — the realistic near-term answer for BYO DBs once raw TCP
   exists.
2. **HTTP query driver (Postgres-over-HTTP shim):** each query is a stateless HTTP request — collapses onto the
   **phase-1 HTTP egress path**, needs **zero** raw-TCP capability, works the day HTTP egress ships. Cheapest
   correct path; the **preferred** BYO option.

**The serverless-native future** (managed DB, later): a first-party **pooled HTTP query endpoint** — functions
issue queries as HTTP to a platform-internal-but-project-scoped endpoint (analogous to the own-bucket path:
OWN-zone, survives `egress=false`, auto-scoped, no connection lifecycle in the function), riding the same HTTP
egress mediator + observe pipeline. So the DB phasing is: **HTTP query / managed-DB HTTP first (phase 1)**,
raw-TCP `wasi:sockets` second (phase 2 escape hatch), agent pool as the escape hatch's safety net.

### Ceilings + hibernation

Two pool ceilings, both in the agent: **per-`(function, dest)` idle cap** and a **per-VM total open cap** ≤ the
32-permit concurrency semaphore. On a checkout-miss at the total cap: block-with-deadline (bounded by the
invocation's remaining wall budget), then fail typed — never silently exceed. The ceiling is **per-project**
(per-VM pool, no shared pool), so one project cannot exhaust another's connections.

  > **P0-RAWTCP-SNAPSHOT-DEAD.** Hibernation kills the Firecracker process and the pool with it; any socket
  > captured in a snapshot is treated as **dead** on restore (a snapshot-frozen TCP connection is unsound —
  > peer reset, conntrack/NAT gone). The agent restores with an **empty** pool; the first post-wake invocation
  > takes a cold connect. Open sockets MUST NOT count as "activity" that defeats idle hibernation; the idle
  > reaper closes idle sockets before the idle detector hibernates so the VM goes down clean.

### The phase-2 gate (all must hold)

1. Phase-1 connect-time fence + host-mediated chokepoint **live, adversarially reviewed, prod-proven for HTTP**.
2. Observe-by-default landed for egress (per-dest events via the mediator; the manifest pipe).
3. **Real demand for BYO-DB raw TCP** that the HTTP query-driver / managed-DB HTTP path does not satisfy.
4. **Runtime L2 source-guard landed** (§9 — but note this arc already pulls it into the *phase-1* prereq set
   because HTTP egress creates the same attribution exposure).

## 9. Threat model + consolidated invariants

**Load-bearing premise:** ALL tenants are untrusted; the VM is the isolation boundary; cross-tenant reach MUST
be impossible; the host must NEVER trust the guest. The agent's outbound MUST ride the guest TAP and inherit
the netfilter fence; TLS to third parties stays end-to-end (host sees ciphertext).

### What the design gets right (verified, do not re-derive)

The one-door structural floor (`send_request` is the sole outbound impl; `wasi:sockets` denied; no preopens; no
vsock), the TAP-only / no-host-side-path fact, the shared `egress::{ip_is_public,host_allowed,pick_safe_addr}`
logic (RFC1918/CGNAT/ULA/6to4/v4-mapped-v6 via `to_canonical()`, exact-match allowlist), the `169.254/16`
metadata case being genuinely dual-enforced, fresh-per-request + abort-on-timeout cancelling in-flight
outbound, and reserved-host inviolability — all hold against the code.

### PREREQ — close the netfilter gap so Zone-2 deny is genuinely dual-enforced *(fence F1/F2/F3, cross-tenant F4)*

These MUST land **with** the egress code, not after. Until they do, every "AND netfilter (fail-closed)"
invariant is aspirational for PLATFORM targets other than `169.254/16`, and a single agent-classifier bug =
control-plane / object-store / host-service reach with no backstop.

1. **Bind the control-plane API to `127.0.0.1:9090`**, not `0.0.0.0` (`main.rs:676`). The proxy already reaches
   it at `127.0.0.1` (`api_addr`). Closes the direct `172.16.0.1:9090` path.
2. **Add RFC1918 + gateway-IP + host-public-IP FORWARD drops** to `setup-bridge.sh` (the exact commented-out
   lines at `:55-59` plus a `jkbr0 → 172.16.0.1` non-`:53` drop and a guest→host-public-IP drop) — making the
   agent's RFC1918-superset classifier a genuine *second* layer and killing domain-fronting to the control plane.
3. **Interface-scope the `ufw` 80/443 allows** to the public uplink (`provision.sh:72-73` →
   `ufw allow in on $PUB_IFACE to any port 443`), so the gateway IP doesn't expose the proxy to guests.
4. **Add an explicit IPv4 `INPUT -i jkbr0 -j DROP`** after the `:53` ACCEPT, mirroring the existing IPv6 rule —
   removing the v4/v6 asymmetry and the dependence on `ufw` ordering for tenant isolation.
5. **Land the runtime ebtables L2 source-guard** on `jkbr0` (the `JKBUILD-SRCGUARD` equivalent that exists on
   the build bridge, `build_orchestrator.rs:675-788`), pinning each TAP to its allocated `{IP, MAC}`. Without
   it, a function can forge another project's source IP — poisoning the observed-egress manifest attribution and
   the per-project bandwidth meter (cross-tenant DoS via mis-attributed "abuse"). Port-isolation still blocks
   actual cross-tenant *reach*, so this gates **attribution integrity**, not confinement — but functions now
   generate egress (today they generate none), so the latent spoofability becomes load-bearing in **phase 1**.
   Until it lands, observed-egress attribution + per-project bandwidth enforcement MUST NOT be the sole basis
   for punitive action (hibernate/block) against a project.

### Resource / DoS — egress converts functions from CPU-bound/transient to I/O-bound/parkable

The 30 s wall clock, the 60 s/monthly bandwidth meter, the 1000-line shared log buffer, and the count-only
concurrency semaphore were all sized for **CPU-bound, epoch-killable, transient** functions. Egress makes them
**parkable, long-held** — four findings are one mismatch, fixed at the mediator:

  > **P0-DOS-OUTBOUND-TIMEOUTS** *(DoS F1)*. Aggressive per-outbound clamps (connect/first-byte ≤ a few s,
  > **between-bytes idle timeout** for slowloris bodies), all `min()`'d under the wall clock. The permit must not
  > be held across a parked outbound for the full 30 s: use a **separate, smaller semaphore for in-flight
  > outbound slots** so a slowloris flood can't consume all 32 invocation permits. Re-evaluate the 30 s
  > `FUNCTION_WALL_TIMEOUT` now that a function can voluntarily park on I/O (epoch can't interrupt a guest parked
  > in a host outbound call; only the wall clock frees it).

  > **P0-DOS-EGRESS-BYTE-CAP** *(DoS F2)*. Add a **per-invocation outbound byte cap** (request-out + response-in,
  > independent of the 10 MiB wasm response cap) and a **per-project short-window egress rate limiter / token
  > bucket** at the mediator (the only point that sees per-call bytes) — because the monthly cap evaluated once
  > per 60 s tick lets a function push gigabytes between ticks before the lagging "hibernate the VM" response
  > fires. The TAP sampler stays for billing truth; the mediator gets the fast inline ceiling.

  > **P0-DOS-EGRESS-EVENT-BUFFER** *(DoS F3)*. Egress events MUST use a **separate, independently-bounded buffer**,
  > NOT the shared 1000-line app-log `VecDeque` — otherwise a function spraying (even *denied*) events evicts the
  > project's own app logs and, worse, its own audit trail under the exact flood you most want recorded (defeating
  > P0-OBS-UNCONDITIONAL). **Coalesce repeated `(dest_host, port, verdict)` within an invocation into one row with
  > a `count` — including deny events** (a 10k× denied-`evil.example` loop is one row + count, the security signal,
  > not 10k DoS rows). Cap durable egress-event ingestion per project per window so deny-spam can't grow host disk
  > without bound.

  > **P0-DOS-CONNECT-STORM** *(DoS F4)*. Phase 1's fresh-hyper-client-per-call (required for clean abort,
  > P0-EGRESS-ABORT) forecloses keep-alive reuse, so a function looping an HTTPS upstream produces a connect-storm
  > against the upstream **and** repeated TLS-handshake CPU inside the agent (shared with the project's
  > sites/servers). Either land a **bounded agent-held HTTP keep-alive pool** keyed `(function, dest)` in phase 1
  > (force-closed on abort/dirty, never returned — same discipline as the §8 raw-TCP pool), **or** document the
  > connect-storm and add a **per-project outbound connect-rate limiter** + a cap on concurrent in-flight TLS
  > handshakes per VM at the mediator.

  > **P0-DOS-AGGREGATE-MEM** *(DoS F5)*. Add a **byte-denominated** aggregate guest-memory budget per VM across
  > concurrent invocations — the 32-permit count cap allows `32 × 128 MiB ≈ 4 GiB` of guest RAM, and under
  > P0-DOS-OUTBOUND-TIMEOUTS slowloris that commitment becomes simultaneous + long-held, violating host
  > overcommit (which assumes functions don't park) → cross-tenant OOM. Bound peak in **bytes**, not count, and
  > re-examine host overcommit ratios now that a function can hold near-max memory while parked on I/O.

### Consolidated P0 list

| Invariant | Protects |
|---|---|
| **P0-EGRESS-TAP** | outbound rides the guest TAP; no host-side network path (no vsock/2nd-NIC/loopback) |
| **P0-EGRESS-ONEDOOR** | exactly one guest→socket path (`send_request`); `wasi:sockets` denied phase 1 |
| **P0-EGRESS-PLATFORM** | Zone-2 deny non-configurable, dual-enforced (agent fail-clean + netfilter fail-closed) |
| **P0-EGRESS-PLATFORM-BY-IP** | control-plane/host deny by pinned IP, not hostname (defeats domain-fronting) |
| **P0-EGRESS-ZONE-ORDER** | zone classified before policy; `false`/allowlist deny PUBLIC only |
| **P0-EGRESS-OWN-HOST-ASSERTED** | OWN/storage host is host-asserted (cmdline/host-meta), never `jkbase.toml`-derived; OWN-storage IP-pinned |
| **P0-EGRESS-POST-DNS** | classify resolved IPs per-address; public-name→internal-IP denied; fail closed on empty resolution |
| **P0-EGRESS-PIN** | dial only vetted public IPs; no re-resolve; skip-internal-in-RRset |
| **P0-EGRESS-RESOLVER-PINNED** | agent resolves via explicit `172.16.0.1`, never ambient resolv.conf; fail closed |
| **P0-EGRESS-HOST-AUTHORITY-COHERENT** | allowlist-name == resolved-name == pinned-IP-host == upstream-`Host` |
| **P0-EGRESS-NO-HOST-REDIRECT** | agent never follows redirects; every hop re-enters the gate |
| **P0-EGRESS-DUAL-ENFORCE** | `classify_internal` at policy-site AND connector-site + netfilter; not `socket_addr_check` (phase 1) |
| **P0-EGRESS-SHAREDLOGIC** | byte-identical public-IP logic with the build fence (hoisted to `jkbase-common`) |
| **P0-EGRESS-ABORT / -BUDGET-CLAMP** | timeout cancels in-flight outbound, no leaked socket; clamped budgets |
| **P0-EGRESS-TLS-E2E** | host never MITMs function egress; sees ciphertext |
| **P0-EGRESS-POLICY-HOST-RESOLVED** | precedence collapsed host-side; agent never parses `jkbase.toml`; no widening past ceiling |
| **P0-INGRESS-HOST-TRUST** | backend-kind resolved only in-VM; proxy gains no fn-vs-server awareness |
| **P0-INGRESS-UPGRADE / -BODYCAPS** | functions stay request/response; `426` on upgrade; 10 MiB caps on any route |
| **P0-OBS-UNIFIED-SINK** | one shared `LogSink`/`seq`/`boot_id`; manifest cannot fail-open silently |
| **P0-OBS-UNCONDITIONAL** | every verdict recorded by host code, contact emitted pre-connect; unsuppressable |
| **P0-OBS-STREAM-RESERVED** | `stream=="egress"` host-only; no guest-forged/buried manifest rows |
| **P0-OBS-METADATA-ONLY** | manifest is metadata only; never payload; per-project, cross-tenant-invisible |
| **P0-OBS-BYTES-ADVISORY** | per-dest bytes advisory (skewable by abort); billing reads TAP; contact is the IR primitive |
| **P0-OBS-PROPOSE-ONLY** | allowlist proposals never auto-applied; human is the trust anchor; provenance-not-count UX |
| **P0-OBJ-NO-STANDING-KEY** | no standing project credential in the VM; short-lived request/boot-bound tokens |
| **P0-OBJ-PINNED-DEST** | binding credential only ever sent to the host-pinned storage endpoint |
| **P0-OBJ-NOKEY / -RESERVED-CHANNEL** | credential never in `process.env`; carried outside the tenant-secret `env` merge |
| **P0-OBJ-SCOPE / -QUOTA / -OPAQUE / -ZONE1** | `{id}` host-asserted; quota inherited; opaque errors; OWN survives sandbox, cannot reach Zone 2 |
| **P0-DOS-\*** | outbound timeouts, byte cap + rate limit, separate coalesced event buffer, connect-storm bound, aggregate mem |
| **P0-RAWTCP-\*** (phase 2) | fence parity; no session leak (fail-closed reuse); per-VM ceilings; snapshot connections dead |

## 10. Phasing / implementation plan

Sequencing is owned by the Overboard `jkbase` board (the mutable source of truth). The order:

**Phase 0 — netfilter/binding PREREQ (lands with phase 1, gates it).** §9-PREREQ items 1-5: bind control API to
`127.0.0.1`; RFC1918 + gateway + host-public-IP FORWARD drops; interface-scope ufw 80/443; IPv4 `INPUT -i jkbr0
-j DROP`; **runtime ebtables source-guard**. Plus: deliver the platform/storage host + platform-IP set into the
agent via a **host-controlled channel** (kernel cmdline / host-written meta region), and provision the agent's
**own** resolver to `172.16.0.1`. Until these hold, Zone-2 deny is single-layer and attribution is spoofable —
so this phase is a hard prerequisite, not a follow-up.

**Phase 1 — HTTP egress + zones + observe + ingress + own-bucket.**
1. **Hoist `egress::{ip_is_public,host_allowed,pick_safe_addr,classify_internal}` to `jkbase-common`** (shared
   fence logic). Add `EgressPolicy`/`HostingConfig.function_egress` to `config.rs`; resolve precedence host-side
   into `ResolvedEgress`, stamped into the function sidecar by `inject_function_secrets`/sidecar assembly
   (`layer_plan.rs:425,542`), per-VM-image-only.
2. **Refactor `LogSink` to a shared agent-level `Arc<LogSink>`** (one `seq`, one `boot_id`) handed to both
   `ContainerSupervisor` and `FunctionRuntime` (P0-OBS-UNIFIED-SINK) — prerequisite for the manifest.
3. **Rewrite `HostState::send_request`** into the connect-time enforcement point: zone-classify (OWN host-pinned,
   post-DNS per-IP `classify_internal`, IPv6-refuse), policy switch, agent-built pinned hyper client
   (redirect-disabled, classify at connector-site too), emit `EgressEvent` (contact pre-connect, bytes after) to
   the shared sink, aggressive per-outbound timeouts + separate in-flight semaphore + per-invocation byte cap +
   per-project rate limiter. `HostState`/`LoadedFunction` carry the `egress` policy + storage target + token.
4. **Ingress parity:** typed `RouteKind` in `load_route_config` (drop the `service=="server"` filter, fail-closed
   on unknown), unified kind dispatch, keep the legacy `/functions/{name}` implicit route, `426` on upgrade,
   404-no-fallthrough on missing function, path-scoped routes (host-scoping only via resolved-host-key header if
   offered).
5. **Observe manifest:** separate bounded+coalesced egress-event buffer, `stream`-keyed `LogStore` retention,
   read-side manifest projection + propose-only allowlist UX (provenance/diff, never auto-apply).
6. **Own-bucket binding:** the `jkbase:objectstore/store` WIT + host impl (short-lived token, pinned dest, no key
   in wasm, reserved sidecar channel), linked alongside `add_to_linker_async`; `ObjectStoreService` unchanged.

**Phase 2 — `wasi:sockets` + pooling (DEFERRED, behind the §8 gate).** Flip `allow_tcp(true)` + install the
`TcpConnect` predicate (reused from phase 1, now genuinely backed by `socket_addr_check`); agent-held pool keyed
`(function, dest)` with fail-closed reuse, two-level ceilings, snapshot-dead-on-restore. Steer developers to the
HTTP query-driver / managed-DB HTTP path (rides phase 1) first; raw TCP is the BYO escape hatch.

**On-box proving** (`tools/dev test` gauntlet + a red-team fixture set in CI, mirroring the build proxy's):
DNS-rebind, redirect-to-metadata, CDN-shared-IP/domain-front to `api.{domain}`, IP-literal RFC1918, mixed-RRset,
host-header desync, IPv6-literal, sandbox-still-reaches-own-bucket, sandbox-blocks-public, allowlist-exact-not-
suffix, slowloris-upstream-frees-permit, deny-spam-doesn't-evict-app-logs, function-as-route 200 +
`426`-on-upgrade, cross-project bucket 404. Prod e2e before any tenant exposure.

## 11. Open questions / decisions still needed from the maintainer

1. **Sandbox exfil-via-own-bucket (HIGH-2).** `egress = false` cannot close the own-bucket as an exfil channel
   without breaking the feature. Do we (a) document the honest scope ("no *arbitrary* public egress," not "no
   exfil") and ship, or (b) for genuinely-untrusted marketplace code, scope the sandboxed own-bucket binding to a
   **non-public-readable, non-presignable sub-prefix** (quarantining writes from the public/presigned read
   surface while sandboxed)? Recommendation: ship (a) now, design (b) as a follow-up card if a marketplace lands.

2. **Own-bucket credential end-state (BLOCKER F1).** Short-lived STS-style tokens (P0-OBJ-NO-STANDING-KEY) are the
   phase-1 fix, but the cleanest answer — **host-identity-asserted mediation** where the host injects `project_id`
   from the VM's identity and no credential ever enters the VM — requires a guest→host control channel that does
   not exist today (`vsock_cid: None`). Do we invest in that channel (a real cost, a new host/guest seam to
   harden) for the binding, or accept short-lived tokens indefinitely? Recommendation: ship short-lived tokens;
   revisit the host-identity channel if/when a managed-DB HTTP endpoint wants the same primitive.

3. **Phase-1 keep-alive pool vs. connect-storm (DoS F4).** A bounded agent-held HTTP keep-alive pool in phase 1
   would absorb the connect-storm but adds the abort/dirty force-close discipline a phase early. Land it in phase
   1, or ship phase 1 with only a per-project connect-rate limiter and pull the pool forward with phase 2?

4. **Wall-clock budget re-sizing (DoS F1).** Is 30 s still the right `FUNCTION_WALL_TIMEOUT` once a function can
   park on I/O, or do outbound-bearing invocations want a tighter ceiling distinct from pure-CPU ones?

5. **Host-scoped function routes (F6).** Offer them via a new trusted resolved-host-key header, or restrict
   function routes to path-scoping only and document the apex-exposure consequence on no-site custom domains?

6. **Allowlist-proposal provenance signals (BLOCKER-2).** Confirm the propose UX ships as a NEW-since-last-review
   **diff** with provenance (first-seen-relative-to-deploy), not a flattened count-annotated set — and that any
   destination ever resolving non-public/platform-owned is excluded from proposals.
