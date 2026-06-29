# Zero-bounce continuity Phase 2 — proxy/TLS socket hand-off

Follow-on to **Phase 1** (`docs/vm-readoption-design.md`, shipped + live): Phase 1 keeps tenant
Firecracker VMs RUNNING across a `jkbase-server` upgrade and re-adopts them, but the proxy/TLS
listeners still go down for the restart window → in-flight + new connections get
connection-refused for ~1–2s. Phase 2 closes the **data-plane** gap so the upgrade is invisible to
clients.

Designed via a multi-agent understand → 3-lens design panel → adversarial review (find→verify).
This doc records the chosen approach and the dispositions of every adversarial finding.

## Chosen approach: systemd socket activation (public `:80`/`:443` only) + bounded graceful drain

systemd `bind()`+`listen()`s each `ListenStream=` socket once and owns the fd for the unit's whole
life. On `systemctl restart jkbase` only the **service** unit cycles, so the kernel socket — and its
accept backlog — never closes: SYNs arriving during the swap complete the handshake into the backlog
and **wait** instead of getting `RST`/`ECONNREFUSED`. The old process holds only a *dup* of each fd;
Phase 1's `std::process::exit(0)` (already skips `TcpListener::Drop` and `VmInstance::Drop`) closes
only that dup, never systemd's reference — so the same exit that spares the surviving Firecrackers
also spares the listening socket. Composes with `KillMode=mixed` exactly like the `jkbase-runtime`
cgroup: the socket is owned by PID 1, outside the service cgroup, structurally untouchable by the
service stop.

A **bounded graceful HTTP drain** lets the old process finish in-flight requests before exiting
(`graceful_shutdown()` per connection: finish the current response, send `Connection: close`).

**Rejected alternatives.** `SO_REUSEPORT` overlap and `SCM_RIGHTS` fd-passing both require the old
and new processes to be alive *simultaneously*, which a sequential `systemctl restart` (stop→start)
never provides; `SCM_RIGHTS` also adds a security-sensitive IPC endpoint vending `:443` fds under the
all-tenants-untrusted model. Socket activation needs no overlap because systemd is the long-lived fd
holder.

### Scope decision: activate ONLY the public `:80`/`:443` (NOT the loopback api/storage)

The control API (`127.0.0.1:9090`) and object-store (`127.0.0.1:9091`) are reachable **externally only
through the proxy** (`api.`/`storage.` reserved hosts → loopback forward). Activating `:80`/`:443`
therefore covers the entire *external* data plane. The loopback listeners stay **in-process binds** so
the **P0 loopback invariant** (function-outbound-io: the control API must never be reachable off
`127.0.0.1`) stays a *structural* guarantee in the binary rather than depending on a unit-file line
(adversarial **HIGH-4**). Storage gains `with_graceful_shutdown` for a clean in-flight S3 drain (a
pre-existing cut). Their brief cold-start gap is harmless (loopback-only; the new proxy's first
`api.`/`storage.` forward retries). The egress build proxies (`:3128`/`:3129`, build-network-only,
ephemeral) are deliberately not activated.

## The reconciled upgrade-shutdown sequence (Phase-1-safe)

On SIGTERM with a fresh `.upgrading` flag, `shutdown_signal`:
1. `proxy_shutdown.cancel()` + `storage_shutdown.cancel()` — stop accepting; begin per-connection
   graceful drain. systemd-owned `:80`/`:443` stay open, so new connections queue for the SUCCESSOR.
2. set `upgrade_kind` and **spawn a watchdog**: `sleep(DRAIN_GRACE) → process::exit(0)` — a HARD
   ceiling so the process exits within the grace window no matter what any drain is doing
   (adversarial **BLOCKER-1**: axum's graceful shutdown has no internal timeout, and a hostile tenant
   could otherwise hold an authenticated `api.` request open for up to `TimeoutStopSec`).
3. `return` (NOT `process::exit` inline) so axum's own graceful shutdown drains the control API.

After `axum::serve(...).await` returns, on the upgrade branch: await the proxy/storage join handles
under `timeout(DRAIN_GRACE)` (fast path) then `process::exit(0)` **regardless of Ok/Err** — never let
`main` unwind on the upgrade path (adversarial **HIGH-2**: a `?` would drop `PlatformState` → `vms` →
`VmInstance::Drop` SIGKILLs every `Owned` survivor). The watchdog from step 2 is the backstop if the
join hangs.

`process::exit(0)` skips destructors → surviving FCs live in `jkbase-runtime`, adopted by the
successor's `adopt_or_reap_runtime_vms`. **Why the drain can't drop a VM:** the proxy's `SharedState`
holds only host→IP route strings, the domain map, an activity tracker, and a wake callback — disjoint
from `PlatformState.vms`. Draining = stop accepting + finish in-flight + drop connection state; it
never removes a `VmInstance`. The upgrade branch `return`s before the hibernate loop, holds `platform`
(an `Arc`) alive across the wait, and never `return Ok(())` before `process::exit(0)`.

`DRAIN_GRACE = 5s` (≪ `TimeoutStopSec=120`): event-driven (an idle/short-request box exits ~instantly),
small enough that a long in-flight request can't widen the successor-start delay much, large enough to
finish virtually all non-bulk exchanges. Bulk transfers exceeding it are cut at exit — exactly as today.

## fd inheritance (`socket_activation` module, hand-rolled, zero new deps)

Parse `sd_listen_fds(3)` once on the **single-threaded** `main` prologue, BEFORE the tokio runtime or
any fork+exec child exists (edition-2024 `env::remove_var` is `unsafe` re: thread races; CLOEXEC must
be armed before any child can inherit):
- `LISTEN_PID` must `== getpid()` (else the vars leaked into a child — we fork+exec jailer/FC/buildpacks).
- `LISTEN_FDS` = count N; fds are `3 .. 3+N` (`SD_LISTEN_FDS_START=3`).
- `LISTEN_FDNAMES` = `:`-separated names from each unit's `FileDescriptorName=`.

Then scrub `LISTEN_*` from the env and **arm `FD_CLOEXEC`** on every inherited fd — `vm.rs` spawns
Firecracker via `Command` redirecting only stdio, so a parent fd without CLOEXEC would leak `:443`/`:80`
into the guest's FC fd table. CLOEXEC is armed even on the `LISTEN_PID`-mismatch branch (the fds, if
present, are still ours to not-leak) (adversarial **LOW-9**).

API: `init()` (prologue), `activated() -> bool` (`LISTEN_PID==getpid() && LISTEN_FDS>0`), and
`take_listener(name) -> Option<std::net::TcpListener>` (validates `SO_ACCEPTCONN` + `SOCK_STREAM` +
`AF_INET` for parity, sets nonblocking, yields each fd at most once). Caller contract
(adversarial **HIGH-3**): `if activated() { take_listener(name) — and BAIL if None }` else `bind()`.
Falling back to `bind()` while activated would hit `EADDRINUSE` against systemd's still-open socket.
Duplicate `FileDescriptorName=` (map collision) fails closed.

**IPv4 parity (adversarial LOW-10):** today binds `([0,0,0,0],port)` = `AF_INET`. The units use the
explicit `0.0.0.0:80`/`0.0.0.0:443` form (a bare `ListenStream=443` would open an `AF_INET6` dual-stack
socket → peer IPs become `::ffff:...`, bypassing the IPv4 ufw/JKRUNFW rules). `take_listener` asserts
`AF_INET` and hard-fails otherwise, so a dual-stack misconfig can't silently change exposure.

## TLS continuity

`CertManager::new` reconstructs the ACME account from `acme-account.json` (no ACME call), loads the
wildcard straight from `fullchain.pem`/`privkey.pem` while present and < 60 days old, and loads each
`custom/<host>/` cert — so a restart needs no ACME round-trip; the successor's `TlsAcceptor` is ready
before it accepts. Termination is per-connection (no session cache), so nothing migrates: new
connections handshake on the new process; established TLS streams finish on the old process via the
drain. ACME HTTP-01 survives the swap because `proxy-http` is the same inherited `:80` fd; only the
in-memory `challenges`/backoff map is lost — a mid-flight order is re-driven by `spawn_reconcile`
(adversarial **LOW-11**, documented: avoid upgrades during a known custom-domain issuance).

## systemd / ops

Two named socket units (`FileDescriptorName=` is unit-level, so one unit per name):
`tools/units/jkbase-proxy-http.socket` (`ListenStream=0.0.0.0:80`, `FileDescriptorName=proxy-http`,
`Backlog=4096`) and `jkbase-proxy-https.socket` (`:443`, `proxy-https`, `Backlog=4096`), both
`Service=jkbase.service`, **no `PartOf=`** (`PartOf=` would cycle the socket on a service restart and
re-open the gap — `Requires=` propagates stop only socket→service). The service adds `Requires=` +
`After=` + `Sockets=` for both. `KillMode=mixed`/`TimeoutStopSec=120`/ExecStartPre/ExecStart unchanged
(the `--proxy-port`/`--https-port` flags become the non-activated bind fallback).

`provision.sh`: write the two units; add the service wiring; `enable` the sockets (NOT `--now` — the
old in-process server still holds the ports; `Requires=` pulls them up during the restart's start
job). Add a `net.core.somaxconn` sysctl drop-in (≥ `Backlog=4096`) so the backlog isn't silently
clamped during the no-acceptor cold-start window (adversarial **MED-6**).

`deploy-server.sh`: idempotent refresh of the two units + a `20-sockets.conf` drop-in (mirrors
`10-drain.conf`), `daemon-reload`, then `systemctl enable` (NOT `--now` — `set -e` + `EADDRINUSE` on
the first rollout would abort the deploy mid-flight; adversarial **MED-5**), BEFORE the unchanged
`.upgrading` + `systemctl restart jkbase` flow. Never `restart` an active socket (drops the backlog).

**Two documented one-time bounces:** the first deploy of this code (old binary predates the sockets,
holds the ports in-process, releases only at exit) and any future socket port-edit. Both call-outs
mirror the existing `.upgrading` first-deploy note.

**Local-dev / non-activated:** with no socket unit and no `LISTEN_*`, `activated()` is false, every
`take_listener` returns `None`, and each role self-`bind()`s its `--*-port` exactly as today.
`tools/dev` unchanged.

## Adversarial dispositions

- **BLOCKER-1** (unbounded api drain): FIXED — watchdog hard-ceiling `process::exit(0)` at `DRAIN_GRACE`.
- **HIGH-2** (axum `?` unwind drops `Owned` FCs): FIXED — `process::exit(0)` on the upgrade branch
  regardless of Ok/Err; never unwind.
- **HIGH-3** (fallback-bind collides with systemd socket): FIXED — `activated()` gates bind vs
  hard-fail; duplicate names fail closed.
- **HIGH-4** (loopback P0 moved out of the binary): FIXED by scope — only `:80`/`:443` activated;
  api/storage stay in-process binds.
- **MED-5** (deploy `--now` EADDRINUSE): FIXED — `enable` without `--now`.
- **MED-6** (backlog overflow in cold-start window): FIXED — `Backlog=4096` + somaxconn sysctl.
- **MED-7** (in-flight build orphaned on upgrade): DEFERRED (pre-existing in Phase 1; builds are
  ephemeral/non-data-plane) — tracked as a follow-up (startup reap of orphaned build FCs).
- **MED-8** (slow backend stream rides DRAIN_GRACE): ACCEPTED — bounded by the watchdog; keep
  `DRAIN_GRACE` small; cut at exit is no worse than today.
- **LOW-9** (CLOEXEC fragility): FIXED — arm on all paths; `init()` in the single-threaded prologue.
- **LOW-10** (IPv6 parity doc-only): FIXED — explicit `0.0.0.0:`/`127.0.0.1:` units + `AF_INET` assert.
- **LOW-11** (ACME backoff reset): DEFERRED + documented.
- **LOW-12** (`serve_http_redirect` no `header_read_timeout`): FIXED — add `header_read_timeout(30s)`.

## Validation plan (mirrors Phase 1: capture → restart → assert; PASS = 0 refused)

On the systemd validation box, then prod:
1. **Sensitivity control:** `systemctl stop jkbase-proxy-https.socket`, run the probe → MUST show
   `refused>0` + an `ss` socket gap (proves the probe can see a gap).
2. **C1 zero-refused under fresh-connection load:** `hey -z 40s -c 50 -disable-keepalive https://app/`
   spanning a mid-run `systemctl restart`; independent curl witness classifying exit code 7 (refused =
   FAIL) vs 52/56 (in-flight reset = tolerated). ASSERT `refused == 0`.
3. **Socket continuity:** `ss -ltnpe` listen-socket inode for `:80`/`:443` unchanged across a restart;
   socket unit stays `active`.
4. **C2 in-flight completes:** slow `--limit-rate` download across a restart; sha256 matches (no
   truncation within `DRAIN_GRACE`).
5. **Loopback invariant:** `:9090`/`:9091` only ever `127.0.0.1` (never `0.0.0.0`/`[::]`).
6. **No fd leak:** no listen-socket inode appears in any tenant FC's `/proc/<pid>/fd`.
7. **Phase-1 not regressed:** tenant FC pids unchanged + in `jkbase-runtime` + re-adopted + 200.
8. **TLS reload disk-only:** same wildcard cert serial before/after; ACME challenge path 404 (not
   refused) across the restart.
9. **Deploy doesn't restart the socket:** `:443` inode unchanged across a full `deploy-server.sh`.

## Validation outcome (systemd, dev box, 2026-06-29) — PASS

Validated under real systemd socket activation (a `jkbase-val-http.socket` →
`jkbase-readopt-val.service`, `:18080`, `Backlog=4096`) with a real tenant bun microVM, mirroring
the Phase-1 capture→restart→assert. The `:80`/`serve_http` path was exercised on-box; `:443`/
`serve_https` shares the identical `resolve_listener` + cancellable-accept + `drive_connection`
machinery (differs only by the per-stream TLS handshake; cert reload is unchanged `CertManager`
disk-load), and is exercised for real on the prod deploy.

- **Socket ownership:** `ss -ltnpe` shows `:18080` held by BOTH `systemd (pid 1)` and `jkbase-server`,
  in the **socket unit's** cgroup (`/system.slice/jkbase-val-http.socket`) — outside the service
  cgroup, so `KillMode=mixed` can't touch it. `Send-Q 4096` (the `Backlog=` + somaxconn bump took).
- **Sensitivity control:** both units stopped → the probe saw **392/392 connection-refused**
  (proves the probe detects a real gap, so a clean treatment run is meaningful).
- **Headline (C1) — zero refused across an upgrade restart:** a fresh-connection curl witness across
  a `.upgrading` + `systemctl restart` (service only) → **2525 requests, 2525 OK, 0 refused, 0
  timeout**. Restart returned in ~0.2s (event-driven drain).
- **Socket continuity:** listen-socket inode **unchanged** (`1703440`) before/after — systemd kept
  the socket, not a fresh bind.
- **Phase-1 intact:** tenant FC pid **unchanged** (`107591`), `VM re-adopted (no bounce) ...
  adopted=1 reaped=0`; journal shows the `upgrade restart — draining HTTP (proxy+storage+api),
  leaving tenant VMs running` branch.
- **No fd leak (threat-model gate):** the `:18080` listen-socket inode is **absent** from the tenant
  FC's `/proc/<pid>/fd` (CLOEXEC arming works).
- **Loopback P0 intact:** api `:19090` + storage `:19091` bound `127.0.0.1`-only (never `0.0.0.0`).

**Conclusion: ready for PR/merge/deploy.** The FIRST prod deploy bounces once (the OUTGOING binary
predates the sockets, holds `:80`/`:443` in-process, releases only at exit); every deploy after is
gapless.
