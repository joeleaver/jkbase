# Managed RhypeDB — native-TCP external ingress design

> Status: design (P1). Companion to `docs/managed-rhypedb-design.md` (which deliberately
> **deferred** raw-TCP ingress in §2.3 — "the edge is HTTP-only"). This reopens that decision:
> the v1 reach-plane is **native L4** — the real `@rhypedb/client` (+ realtime subs) connects to
> a per-project endpoint over TLS, authenticated by a jkbase-issued credential; the edge wakes
> the co-located, loopback-bound DB and relays the raw byte stream to it. Supabase is the UX
> model (connect from outside + a thin CLI).
>
> **Scope: v1 owner-trusted.** The credential is a service-role key, kept server-side, **not**
> browser-facing. The untrusted-browser, rules-gated tier stays the P5 end-state in the parent
> doc. **Threat model: all tenants untrusted; this is a NEW external L4 seam bridging into a
> tenant VM that runs an engine with ZERO data-plane auth.** That last fact shapes every defense.
>
> Produced via a recon → design-synthesis → adversarial-probe workflow. The probe's findings are
> folded in below as **[R#] hard requirements**, not afterthoughts. This seam gets a full
> multi-agent adversarial review before merge (project convention for any new host/guest seam).

## Hard constraints (honored throughout)
- **(a) No rhypedb ENGINE change.** A client-*packaging* TLS request is optional/parallelizable; the wire and engine are untouched.
- **(b) All tenants untrusted; new external L4 seam.**
- **(c) Credential is service-role** (server-side, not browser-facing).
- **(d) Scale-to-zero holds.**

---

## 1. The central fact

RhypeDB's TCP wire is **plaintext, length-prefixed, no handshake/hello, with server-initiated
pushes** (`rhypedb-wire/src/protocol.rs`; `handle_tcp_connection` `rhypedb-server/src/lib.rs:1157`)
and **zero identity fields** — the data plane is unauthenticated by design (single-trusted-caller).
The official `@rhypedb/client` (Rust + TS) is **plaintext-only**: it dials a bare `host:port`, no
TLS, no auth param, and **subscriptions open *separate* connections** to the same `host:port`.

Two consequences drive the whole design:
1. The edge must authenticate **out-of-band** (the wire can't carry a credential without an engine
   change), and it must be a **full-duplex transparent frame relay**, never a request/response
   proxy (the server pushes `Event`/`SubLagged` unsolicited).
2. The unmodified client can't reach a TLS+authed endpoint at all → **something must bridge.** For
   v1 that is a **jkbase-authored local sidecar** (`jkbase db proxy`, the cloud-sql-proxy / Supabase
   model) — zero rhypedb change, and subscriptions are covered transparently because they all dial
   the same local loopback.

## 2. Topology & data flow

```
@rhypedb/client (+ subs, UNMODIFIED)  ──plaintext──▶  jkbase db proxy  (local sidecar, ours)
   dials 127.0.0.1:4201, no TLS/auth                      │ per local conn: open TLS1.3 to
   subs dial their own loopback conn                      │ <project>-db.jkbase.app:4201
                                                          │ + jkbase preamble {akid, secret}
══════ public uplink ═════════════════════════════════════╪══════════════════════════════════
                                                          ▼
  jkbase-proxy  serve_db()   (socket-activated :4201, mirrors serve_https)
    1 TlsAcceptor.accept → ClientHello; Resolver serves the *.jkbase.app wildcard (one-label host)
    2 require SNI present + "<proj>-db.jkbase.app"     ── absent/!-db ⇒ DROP  [R6]
    3 read preamble (bounded + deadline) → lookup DB key by akid → const-time fingerprint cmp
        → AUTHORITATIVE project_id = the KEY's project   [R1]   (SNI only picked the cert)
        → owner re-bind (key.tenant == project.tenant) + require SNI-project == key-project ⇒ else DROP
        → require scope == "db"  [R2]                    ── any failure ⇒ DROP, no backend touched
    4 (project_id from the KEY) wake_cb(project_id).await   — AUTH BEFORE WAKE  [R7]
    5 activity.stamp(project) + per-project conn gauge++ (RAII)
    6 connect <vm_ip>:80, HTTP/1.1 Upgrade /_jkbase/db (+ host→agent splice secret [R3]) → 101
    7 relay_bidirectional(tls_stream, agent_stream)         (wsproxy/src/lib.rs:152)
                                                          │ jkbr0 (port-isolation + JKRUN_SG)
                                                          ▼ <vm_ip>:80
  jkbase-agent :80  /_jkbase/db  ──verify splice secret [R3]──▶ splice ──▶ 127.0.0.1:4201
                                                  rhypedb-server (loopback-only, no auth)
```

The DB stays on **guest loopback**; the only route to it is through the edge auth gate **and** the
agent's mediated splice. SNI selects the cert only; the **authenticated key** is the identity.

## 3. Host naming + cert scheme — RESOLVED

`db.<project>.jkbase.app` is **two labels** deep; `*.jkbase.app` does not cover it (RFC 6125 — one
label), and `*.*.jkbase.app` is forbidden by CABF. The current resolver also silently mis-serves a
two-label host (returns the wildcard for any `*.jkbase.app` suffix → client name-mismatch).

**Decision: `<project>-db.jkbase.app`** — a **one-label** host genuinely covered by the existing
wildcard (zero cert work, resolver already correct), with the `-db` suffix as a clean routing key
distinct from the web host `<project>.jkbase.app`.
- **[R8] Reserve the `-db` project-slug suffix** at project creation, **and migrate existing
  projects** — a project literally named `foo-db` must not shadow project `foo`'s DB host.
- Custom domains (`db.app.com`) layer on for BYO-domain users via the existing HTTP-01 leaf path.
- (Rejected: dedicated port on the web host — confusing; per-host DNS-01 leaf — most moving parts;
  `*.*` — impossible.)

**Port:** one platform-wide socket-activated **`:4201`**; SNI multiplexes all projects → one
listener, one socket unit. Documented fallback if a nonstandard port is egress-filtered in the
field: **ALPN-demux on `:443`** (advertise an `alpn` protocol, branch after handshake). Rejected as
the default because it couples HTTP and raw-relay lifecycles/drain on one accept path — **and**
because the `:443` HTTP branch wakes *before* auth, which would reintroduce unauthenticated
wake-abuse on a shared path (§5, [R7]).

## 4. TLS termination + SNI routing + zero-bounce

TLS terminates at the edge, **reusing `CertManager`/`Resolver` + `TlsAcceptor` verbatim**
(`tls.rs`, the same `server_config()` as `:443`). A **new dedicated `serve_db()` listener** slots in
alongside `serve_https` (not inside it — different drain policy):
- **Socket unit** `tools/units/jkbase-db-ingress.socket` (copy `…-https.socket`): explicit
  `ListenStream=0.0.0.0:4201` (forces `AF_INET`, asserted by `socket_activation.rs`),
  `FileDescriptorName=db-ingress`, **no `PartOf=`**. Raw-TCP can't ride the `:443` socket, so it
  needs its own unit to keep the zero-bounce guarantee.
- **Adoption** in `main.rs` mirroring the `:443` block: `if activated() { take_listener("db-ingress")
  else bail }` (fail-closed — never `bind()` against systemd's open fd); new
  `ProxyConfig.db_listener`. Local dev falls back to `bind(0.0.0.0:4201)`.
- **Graceful drain:** accept loop `select!`s on the shutdown token and stops accepting (leaves the
  fd for the successor), under the same `DRAIN_GRACE` watchdog — but **force-closes** long-lived DB
  connections at the deadline (they won't close naturally). `process::exit(0)` closes only the dup →
  zero-bounce inherited.

## 5. Wake-on-connect + scale-to-zero

`WakeCallback` is protocol-agnostic (`Fn(String) -> Future<Result<String>>`); the raw-TCP path
derives `project_id` (from the **key**, [R1]) and calls the same `wake_cb`.

- **[R7] Authenticate, THEN wake.** Unlike the HTTP path (which wakes before auth because the app is
  the auth-less caller), the DB ingress holds a token: validate preamble → wake → connect. Waking
  before auth is an unauthenticated VM-restore DoS. `WAKE_BACKOFF` + `project_can_wake`/quota gates
  still apply; `WakeError` arms map to closing the connection (no HTTP status to send).
- **Liveness — the sharp correction (P0-DB-6, worse for raw TCP).** A raw relay never passes through
  `proxy_request`, so it never stamps the `ActivityTracker`; and a realtime **subscription can be
  open but byte-silent for minutes**. Last-byte liveness alone is insufficient. Two complementary
  signals:
  1. **Refresh activity on byte flow** — hook the relay's existing per-read `Notify` to stamp the
     activity tracker (throttled ~30s) so a chatty connection keeps the VM warm.
  2. **Per-project active-connection gauge** consulted by `idle_detection_loop`: a project with
     `conn_gauge > 0` is **excluded from hibernation** regardless of last-byte time (covers the
     silent-but-open subscription). Gauge ++ post-wake, -- on relay teardown (RAII, same object as
     the §6 concurrency permit).
- **[R9] Mandatory TCP keepalive on both legs** (not optional): a dead half-open socket must not pin
  the gauge and hold a VM warm forever (standing cost-DoS). Dead peer → reaped → gauge decrements →
  normal hibernation. **Meter/quota DB-attributable warm-time** so an owner can't pin every VM warm
  with one cheap idle connection per project for free compute.

## 6. Backend relay

**Reuse `relay_bidirectional`** (`wsproxy/src/lib.rs:152`) — split both ends, two pump tasks,
half-close propagation, the `Notify` watchdog. Byte-transparent; honors the rhypedb 16 MiB-payload
frame cap end-to-end; must **not** assume request/response (unsolicited server pushes).

**[R3 / decision] Backend reach = agent `/_jkbase/db` Upgrade splice (DB stays loopback-only).**
The edge does an HTTP/1.1 `Upgrade: jkbase-db` to `<vm_ip>:80/_jkbase/db`; on 101 the agent splices
to `127.0.0.1:4201`. This keeps the DB **off the bridge entirely** (strongest isolation — the engine
is never network-reachable), rides the already-allowed `:80` rule, and makes the in-VM agent the
sole mediator. **Strike the direct `<vm_ip>:4201` bind from v1** (the probe's C2): it would put the
unauthenticated engine on the bridge, where cross-tenant defense is *only* L2 port-isolation +
source-guard — one isolation bug = cross-tenant DB compromise. Reserve direct-bind for the dedicated
DB-VM split if ever needed.

**[R3] The agent splice is a real auth boundary, not just a pipe.** The edge token gate and the
bridge isolation gate are **independent** — defeating isolation alone (a setup race, a bug) yields a
direct splice into the unauth DB. So gate `/_jkbase/db` on a **per-boot host→agent shared secret**
(injected like other agent secrets; the edge presents it on the upgrade), so one isolation slip
isn't a full DB compromise. Bind `/_jkbase/*` to the VM's eth0 interface (not guest loopback) so the
tenant app can't drive control endpoints via its own `localhost:80`.

**Isolation the backend-connect respects** (`setup_tap` in `main.rs` — the parent doc's `~2948-2985`
anchors are stale): port-isolation (no sibling-VM reach), `JKRUN_SG` source-guard (anti-spoof),
JKRUNFW L3 backstop (guest→host default-DROP; host-initiated replies via RELATED,ESTABLISHED).
**[R-race] Assert TAP `isolated on` + source-guard are installed BEFORE the FC VM is unpaused**, and
self-test that a fresh TAP rejects sibling traffic before its first packet.

**Concurrency:** a **separate `Semaphore`** from the 1024-permit HTTP-upgrade cap (DB conns are
long-lived) — a **per-project** connection cap (bounds owner over-subscription + rhypedb's per-conn
task fan-out) plus a global ceiling; RAII permit == the §5 gauge entry.

## 7. The auth model — RESOLVED (bearer token in a TLS-internal preamble)

Scored candidates: bearer-token-in-preamble (**chosen**), mTLS client cert, token-in-ALPN/SNI,
in-DB preamble (rejected — needs an engine wire change), TLS-PSK. The bearer token wins for v1: it
rides the grain of existing machinery and needs **no CA, no new `ServerConfig`, no rhypedb change**.
mTLS is the documented upgrade when a dedicated mTLS listener + internal CA + revocation infra land
(naturally paired with the dedicated DB-VM split).

**The credential is a per-project DB access key, FORKED from the SigV4 key lifecycle — not reused
verbatim, and not the StorageBinding.** It's **owner-held** (pasted into the sidecar / saved), so it
must be stable + retrievable — the opposite of the deploy-rotated, VM-injected `StorageBinding`.

- **Mint:** a new control endpoint wrapping the access-key mint with **a distinct DB keyspace**:
  - **[R2] Separate keyspace, not a shared `scope` flag.** Distinct akid prefix **and** a distinct
    table, so an object-store (S3) access key — which tenants paste broadly into SDKs/CI — can
    **never** resolve on the DB path, and a DB key can never sign S3. (A shared global
    `lookup_access_key` + a single `scope` check is one default-value bug away from cross-streaming;
    don't rely on it.) Enforce bidirectionally: DB connect requires a DB-keyspace key; SigV4 rejects
    DB keys.
  - **[R4] Store a `sha256` fingerprint only — never the secret, never argon2.** The secret is
    240-bit (high-entropy) → a fast keyed hash is preimage-safe (the exact git-token rationale in
    `auth.rs`). Reusing `AccessKey` would inherit **cleartext-at-rest** (SigV4 needs the secret to
    recompute HMACs) — a control-db read would yield every DB credential. And **argon2-per-connect**
    on an attacker-reachable, reconnect-heavy endpoint is a CPU-DoS amplifier. So: fork a DB-key
    record persisting `{akid, project_id, tenant_id, token_fingerprint=sha256(secret), label}`;
    return the secret **once** at mint; O(1) lookup + const-time fingerprint compare.
- **[R1] Authorize + route by the KEY's `project_id`, not SNI** (the probe's #1, the confused-deputy
  fix). SNI selects the cert; the authenticated key selects the project/VM. `SNI-project != key-project
  ⇒ DROP` (never "prefer" either). Then the VM you connect to is the key's project **by
  construction** — no deputy to confuse.
- **Owner re-bind:** `key.tenant_id == project.tenant_id` (the orphaned-key fix) — invalidates a key
  after ownership transfer, fails closed if the project is gone.
- **[R5] Revocation/transfer must tear down LIVE relays**, not just block new connects. DB relays
  run for hours/days; "revoke" must mean "the attacker is out **now**." On `delete` (and on owner
  transfer), iterate the per-project relay registry (the §6 gauge) and drop matching live
  connections. Project-delete teardown also purges the DB keyspace.

**The preamble** (inside TLS, edge-consumed, invisible to rhypedb):
`magic "JKDB" | u8 version | u8 akid_len | akid | u16 secret_len | secret`, **bounded length + short
read deadline** (slow-loris guard, [R6]). After validation, everything past the preamble is spliced
raw; **buffer and forward** any client bytes pipelined after the preamble in the same TLS record
([R-relay] below). From rhypedb's view the stream is byte-identical to a normal client.

**[R-relay] Hard ordering invariant + regression test:** validate preamble → **then** open the
backend → **then** relay. No backend socket may be opened on an invalid/short/slow preamble. Never
"optimize" by opening the agent upgrade concurrently with the preamble read (it would flow bytes to
the unauth DB pre-auth).

**[R-sidecar] Sidecar verifies TLS** against public roots + pins the expected `<project>-db.{domain}`
name; **never** an insecure/`rejectUnauthorized:false` flag (it runs on owner/corp machines where
TLS-intercepting middleboxes live, and that would hand the bearer preamble to a MITM). Integration
test: a bad cert is refused.

**[R-replay, v1-acceptable + documented] Channel-bind the preamble.** The static bearer has no
nonce/expiry/TLS binding → a one-time capture replays until manual revoke. Mix an RFC 9266
`tls-exporter` value into the preamble (the sidecar owns its TLS stack → no engine change) so a
captured preamble can't replay on a different TLS session; and/or issue shorter-lived DB tokens with
refresh. At minimum, document the leaked-credential blast radius (revocation = the kill-switch, [R5]).

**[R6] Fail-closed handshake surface:** require `Some(sni)` ending in `-db.{domain}` (the resolver
completes a **SNI-less** handshake by returning the wildcard — so absent/unparseable SNI must be
explicitly dropped before any lookup or wake). Add a **pre-auth** concurrency cap (separate, smaller
semaphore around accept→handshake→preamble) + a hard handshake+preamble deadline + a per-source-IP
connection rate limit — the public `:4201` takes unauthenticated TLS handshakes from the whole
internet, and the post-auth per-project cap does not bound that.

## 8. rhypedb-side requests

- **v1: NONE.** The sidecar bridges an unmodified client. (No engine change, no client change.)
- **Optional, later, a client-PACKAGING request (not engine):** add opt-in TLS to `@rhypedb/client`
  (Rust `tokio-rustls` / TS `node:tls`) with SNI + server-cert verification, threaded through the
  client config **and the subscription dialers** (subs dial their own sockets), plus the ability to
  emit the jkbase preamble post-handshake — so power users connect without the sidecar. Wire +
  engine untouched. Open as a `contributed-by-jkbase` request iff Joe wants the no-sidecar UX.

## 9. Implementation outline (jkbase-side, ordered)

Reused wholesale: `CertManager`/`Resolver` + `TlsAcceptor`, `relay_bidirectional` + watchdog,
`WakeCallback`/`wake_project`, `socket_activation::take_listener`, the access-key lifecycle shape +
owner re-bind, the WS-upgrade relay pattern for the agent backend leg.

1. **DB keyspace credential** (`jkbase-control`): forked DB-key record — sha256 fingerprint at rest
   [R4], distinct prefix + table [R2], mint/list/revoke on the control API, live-relay teardown on
   revoke/transfer [R5].
2. **Host naming**: reserve + migrate the `-db` slug suffix [R8]; register `<project>-db` in the
   `DomainMap` on deploy (no cert change).
3. **`serve_db()` listener** (`jkbase-proxy`): `db_listener` on `ProxyConfig`; accept loop mirroring
   `serve_https` with shutdown-drain; the §2 step sequence with [R1][R6][R7] enforced.
4. **Socket unit + adoption** (`tools/units/` + `main.rs`): new unit (no `PartOf=`, explicit
   `0.0.0.0:`), fail-closed adoption, `DRAIN_GRACE` join with force-close for long-lived conns.
5. **Agent backend channel** (`jkbase-agent`): `/_jkbase/db` Upgrade → splice to `127.0.0.1:4201`,
   gated on the per-boot host→agent splice secret [R3]; `/_jkbase/*` bound to eth0 not loopback.
6. **Liveness** (`jkbase-proxy`/`jkbase-server`): activity-refresh-on-byte-flow + per-project gauge
   in `idle_detection_loop`; mandatory keepalive [R9]; warm-time metering.
7. **Concurrency caps**: separate per-project + global `Semaphore` (post-auth) + the pre-auth cap [R6].
8. **Sidecar** (`jkbase-cli`): `jkbase db proxy --project <id>` (local plaintext listener → per-conn
   TLS tunnel + preamble; credential from the owner's CLI session; verifies TLS [R-sidecar]) + `jkbase
   db key {create,list,revoke}`.
9. **Console**: owner-scoped DB-credential management tab (mirror the object-store keys UI).
10. **Boot-ordering assertion + self-test** [R-race]: TAP isolated+source-guarded before VM unpause.

**Pre-merge adversarial review** covers: the `serve_db` auth+wake ordering, the preamble parser
(bounds/slow-loris), the SNI↔key↔VM identity collapse [R1], the keyspace partition [R2], the
fingerprint store + live revocation [R4][R5], the agent splice backstop [R3], and the liveness gauge
(no hibernate-mid-stream, no warm-pin via dead socket [R9]).

## 10. Open questions for Joe

1. **Sidecar UX (the main product fork).** v1 "connect from outside" means running a local `jkbase
   db proxy` (cloud-sql-proxy / Supabase-proxy model), because the real client is plaintext.
   Acceptable as the primary UX? Or open the optional rhypedb client-TLS *packaging* request (§8) in
   parallel so power users connect with the bare client + a connection string, no sidecar?
2. **Host naming.** `<project>-db.jkbase.app` (one-label, wildcard-covered, zero cert work; reserve
   `-db`) — accept, or insist on the two-label `db.<project>` aesthetic at the cost of per-host
   DNS-01 leaf issuance?
3. **Port `:4201` vs ALPN-on-`:443`.** Dedicated socket-activated `:4201` recommended (clean drain
   for long-lived conns; keeps auth-before-wake off the HTTP path). The genuine risk: a nonstandard
   port can be egress-filtered by corporate firewalls. Accept, with ALPN-on-`:443` as the field
   fallback?
4. **Credential carrier.** Bearer-token-in-preamble for v1 (no CA); mTLS as the documented upgrade
   with the dedicated DB VM. Agree, or invest in the internal CA up front?

(Backend reach = agent splice [R3] and token-not-mTLS are corroborated by the adversarial probe and
taken as defaults unless Joe redirects.)
