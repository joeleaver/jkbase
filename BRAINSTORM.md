# jkbase — Architecture Brainstorm

## What is it
A Rust-based, self-hostable Firebase alternative. Multi-tenant platform where
each tenant creates "projects" and picks which services they need.

## Core motivations
- Firebase DB is limiting (no joins, bad indexing, nested doc model)
- Firebase auth is a black box, clunky SDK — always end up rolling own auth
- Tied to GCloud, slow, bad pricing
- Want to own the whole stack, self-host (Linode initially), but structured
  for multi-tenancy from the start

## Platform services (a-la-carte per project)

### MVP
- **Platform proxy / DNS / SSL** — Pingora + rustls-acme. The foundation.
- **Static hosting** — deploy a directory, get a URL
- **Functions** — WASM-based, scale-to-zero
- **Servers** — persistent containers (WebSockets, SQLite, etc.)
- **Control plane + CLI** — project/tenant management

### Future
- **Auth** — not a black box, customizable, sane token/session model. Could be
  built as a jkbase service on the platform itself.
- **Database** — relational + JSON columns, vectors as first-class, real-time
  subscriptions, better index model. Users can host their own DBs in server
  containers in the meantime.
- **Storage** — file/blob storage (not yet discussed)

## Architecture — rough layers

```
Client SDKs (Rust-native, JS)
─────────────────────────────────────
Platform level (host)
  - Pingora proxy / DNS / SSL (ACME)
  - Control plane + redb (embedded k/v)
  - Firecracker VM orchestrator
─────────────────────────────────────
Per-project Firecracker microVM
  - minimal guest rootfs
  - only enabled services run
  - static server │ WASM functions │ container runtime
  - scale-to-zero via memory snapshots
```

## Compute model
Two lifecycle modes:
- **Ephemeral (functions)**: request-triggered, scale to zero. WASM runtime
  (Wasmtime/Wasmer) — tiny cold starts, sandboxed, supports both Rust and JS.
- **Persistent (servers)**: stays alive, holds state (WebSocket connections,
  SQLite, caches). OCI containers with persistent volumes.

## Proxy layer

Built on Pingora + rustls-acme. Thin and fast.

**Responsibilities:**
1. TLS termination (ACME-managed certs)
2. Host lookup → resolve project (subdomain `project.jkbase.dev` or custom domain)
3. Fetch project's routing rules
4. Forward to correct backend (static server, WASM function runner, container)

**Routing model — convention by default, configuration when needed:**
- Deploy a function → it gets a route automatically
- Deploy a server → give it a route prefix
- Static hosting is the fallback for unmatched paths
- No hardcoded path conventions — users control their URL structure
- Zero config works out of the box; override via `jkbase.toml` when needed:

```toml
[routes]
"/api/*" = { service = "server", name = "main-api" }
"/ws/*"  = { service = "server", name = "websocket-server" }
# everything else → static hosting
```

**Custom domains:** CNAME to jkbase, proxy looks up which project owns the domain.

**Hot reloading:** proxy subscribes to control plane config changes, picks up
route updates immediately.

## Isolation model — Firecracker microVMs

Each project gets its own Firecracker microVM. Custom orchestration layer
(no Kata, no k8s — we own this).

**Why Firecracker:**
- Built for exactly this (Lambda/Fargate run on it)
- ~125ms boot, ~5MB memory overhead
- Rust-native
- Simple REST API for VM configuration
- Supports memory snapshots for hibernate/restore (~5ms wake)

**Why not Kata:** solves the wrong problem (making VMs look like containers
to Kubernetes). We're not trying to be Kubernetes.

**Orchestration layer responsibilities:**
- VM lifecycle — create, start, stop, destroy per project
- Image management — minimal rootfs images per service combo
- Networking — tap devices, wired to platform proxy
- Storage — persistent volumes for servers, deploy snapshots for hosting
- Health checking and auto-restart
- Scale-to-zero via Firecracker snapshots (freeze idle VMs to disk,
  restore on incoming request, proxy holds the connection while VM wakes)

**Guest images:** purpose-built minimal rootfs containing only what the
project needs (static file server, WASM runtime, container runtime, etc.).

**What runs where:**
- Platform level (host): proxy, DNS/SSL, control plane, VM orchestrator
- Per-project VM: the project's enabled services

## Language targets
- Rust and JS first

## Static hosting

**Deployment:** CLI-first (`jkbase deploy`), git-based deploys later.

**Versioning:** immutable deployment snapshots with instant rollback.
```
/var/jkbase/hosting/{project-id}/
  deployments/
    v1/   ← immutable
    v2/
    v3/
  live → v3  ← atomic symlink swap
```

**Rollback:** `jkbase rollback` repoints the symlink.

**SPA support:** configurable fallback to index.html.

**Headers/redirects/rewrites:** fully configurable via jkbase.toml.
Less restrictive than Firebase — real configurability.

**Security:** microVM boundary handles isolation. No path traversal
concerns across projects — each VM only has its own files.

## Deploy flow (end-to-end)

```
1. CLI reads jkbase.toml, packages artifacts
   (tarball for static, WASM module for functions, OCI image for servers)
2. CLI authenticates with control plane, uploads artifact
3. Control plane stores artifact, creates deployment record
   (project X, version N, type)
4. Control plane acquires per-project deploy lock (serialize concurrent deploys)
5. Control plane tells orchestrator "project X needs updating"
6. Orchestrator: is VM running?
   - YES → push artifact into VM via virtio-fs, tell guest agent to swap
   - NO  → restore from snapshot (or boot fresh), then push
7. Guest agent activates new version
   - Static: atomic symlink swap
   - Functions: hot-reload WASM module
   - Servers: restart container, health check within N seconds
8. On failure: guest agent rolls back to previous version, reports error
9. Orchestrator confirms success/failure to control plane
10. Control plane updates proxy routing if needed
11. CLI reports result
```

**Incremental deploys:** for static hosting, CLI hashes files locally and
diffs against previous deployment — only uploads changed files.

**Artifact delivery to VM:** virtio-fs mount from host. Host controls what's
shared, VM boundary still provides isolation. Pragmatic for now.

**Failure handling:** broken deploys auto-rollback. Never leave a project in
a half-deployed state. User sees the error immediately with a pointer to logs.

## Control plane

Single binary to start (modular internally). The brain of the platform.

**State store:** redb (pure Rust, embedded, ACID, typed key-value tables).
The DB is just a persistence layer — all coordination (notifications,
routing subscriptions) happens in-process via tokio channels. No need
for database-level pub/sub (Postgres LISTEN/NOTIFY etc.), since everything
runs in the same binary. Values serialized with serde (bincode/messagepack).
Secondary index tables where needed for query patterns.

**Three API audiences:**
- **CLI → control plane**: deploy, rollback, create/delete projects, configure
  routes, manage domains, manage secrets, view logs, manage account
- **Proxy → control plane**: routing data via subscription model (see below)
- **Orchestrator ↔ control plane**: VM status, deployment coordination
  (in-process communication while single binary)

### Routing data subscription

Proxy needs routing data on every request — can't query the control plane
synchronously. Model: notification + fetch, not event stream.

```
Boot:
  1. Full snapshot load (all routing data)
  2. Subscribe to change notifications

Steady state:
  notification "project X changed"
  → fetch project X's full current config
  → update in-memory table (arc-swap HashMap)

Disconnection:
  → keep serving from stale cache
  → reconnect with backoff
  → full re-snapshot on reconnect
  → resume notifications
```

No ordering concerns — the proxy always fetches current truth.
Notifications are just nudges, not events to replay.

### Authentication

API keys / personal access tokens for now. CLI stores token locally
after `jkbase login`.

### Secret store

First-class platform feature. Secrets stored encrypted in the control
plane DB, injected into project VMs at boot as env vars.

```
jkbase secret set DB_URL=postgres://...
jkbase secret set STRIPE_KEY=sk_live_...
jkbase secret list
jkbase secret rm DB_URL
```

### Logging

Control plane aggregates logs from all projects. Guest agents stream
structured JSON log lines to the host (via virtio-fs or VM network).
Control plane indexes by project + service + timestamp.

- `jkbase logs` — recent history
- `jkbase logs --follow` — live tail via subscription
- Logs survive VM teardown/hibernation
- Retention policy: configurable per-project (N days or N MB)

### Domain management

- `jkbase domains add example.com`
- Verification via DNS TXT record
- `jkbase domains verify example.com`
- On verification: proxy starts accepting traffic, ACME issues cert

### Project lifecycle cleanup

Deleting a project must:
- Stop and destroy the VM
- Remove snapshots and deployment artifacts
- Release the subdomain
- Remove routing entries
- Revoke/cleanup TLS certs
- Delete secrets
- Archive or delete logs
- Release metering records

### Metering

Track per-project resource usage:
- CPU/memory time
- Bandwidth (ingress/egress)
- Storage (static hosting + persistent volumes)
- Log volume
- Function invocation count
Even self-hosted, this is useful for understanding resource consumption.

## Functions

**Runtime:** Wasmtime. JS functions use QuickJS compiled to WASM (lightweight).

**Developer-facing API — simple request/response:**

Rust:
```rust
#[jkbase::function]
fn handle(req: Request) -> Response {
    Response::json(json!({ "hello": "world" }))
}
```

JS:
```js
export function handle(req) {
    return { status: 200, body: { hello: "world" } };
}
```

**Trigger types:**
- HTTP — request in, response out (primary)
- Scheduled — cron-triggered, first-class (not a hack like pgcron)
- Event — triggered by platform events (future: DB changes, storage
  uploads, etc.)

**Concurrency:** one request per WASM instance, pool of instances per
function. WASM instances are microseconds to create, so pool is very
dynamic. Simple, correct by default, no concurrency bugs. Can evolve
to event-loop style later if needed.

**Capabilities (WASI-based):**
- Network: outbound HTTP allowed (may restrict destinations later)
- Filesystem: scratch /tmp only, wiped between invocations
- Environment: secrets injected as env vars from platform secret store
- No persistent state — use a server or database for that

**Cross-project calls:** just HTTP. Project A calls project B's function
via `project-b.jkbase.dev/my-function`. Proxy routes it. Can optimize
with internal routing later (skip TLS for co-located projects).

## Servers

Persistent compute — user brings their own application in a container.

**Dockerfile-first**, buildpack-style auto-detection later.

**Config:**
```toml
[servers.api]
dockerfile = "./Dockerfile"
port = 8080
health_check = { path = "/health", interval = "10s", timeout = "5s" }
volumes = [{ name = "data", mount = "/app/data" }]

[servers.websocket]
dockerfile = "./ws/Dockerfile"
port = 3000
```

**Health check:** defaults to GET `/` returns 2xx on declared port.
Overridable per server.

**Multiple servers per project:** all run as containers inside the same
Firecracker VM. Can talk to each other over localhost. Project routing
config directs external traffic to the right one.

**Persistent volumes:** declared in config, mounted into containers.
Survive restarts and redeploys.

**Image builds:** happen on the host (not inside the VM). Faster, access
to build caches. Also supports uploading pre-built images for CI
workflows.

## Guest agent

Single Rust binary, PID 1 (or near-PID 1) inside every project VM.
Host-side orchestrator acts as supervisor — if guest agent crashes,
orchestrator detects via vsock disconnect and reboots VM (~125ms).
No need for in-VM supervisor process.

**Three embedded components:**
1. **Static file server** — hyper-based, serves from `live` symlink
2. **WASM function runtime** — embedded Wasmtime, manages instance pool
3. **Container supervisor** — spawns/monitors server containers as child
   processes

**Also handles:**
- Internal request routing (it's a mini router inside the VM)
- vsock communication with host orchestrator
- Log shipping to host
- Health reporting
- Deployment activation (swap versions, rollback on failure)
- Config application from jkbase.toml
- Secret injection into function/server environments

**Internal routing (no TLS — platform proxy already terminated it):**
```
Request arrives at VM network interface
  → guest agent receives it
  → checks project route config
  → static file?  → serve directly (embedded)
    function?     → dispatch to WASM instance pool (embedded)
    server?       → reverse proxy to container's localhost port
```

**Host communication:** virtio-vsock (no TCP needed, works pre-networking,
purpose-built for VM-to-host communication).

**Startup sequence:**
```
1. Start as PID 1
2. Open vsock to host, announce "alive"
3. Read project config from virtio-fs mount
4. Start enabled services:
   - Bind static file server
   - Load WASM modules into instance pool
   - Pull and start server containers
5. Begin health check loops for containers
6. Start log shipping
7. Report "ready" over vsock
8. Orchestrator tells proxy "VM is up"
```

**Graceful hibernate:**
```
Orchestrator → "prepare for hibernate"
Guest agent  → drain in-flight requests, stop containers gracefully
Guest agent  → "ready for snapshot"
Orchestrator → take Firecracker snapshot
```

## Local development

`jkbase dev` runs the **real platform** locally, not an emulator.
Control plane, proxy, project VM — everything on localhost.

- Static site serving, functions hot-reloading, servers running
- Change a function → recompile WASM → guest agent hot-reloads → instant
- Change static files → re-sync → live
- Cross-project communication works (spin up multiple projects locally)
- No "works locally, breaks in production" — same code paths everywhere

**Requirement:** needs `/dev/kvm` (Linux). Mac users would need a
container-based fallback (future problem).

## Web UIs — self-hosted on jkbase

Both UIs are regular jkbase projects (static sites + functions).
Bootstrap with CLI, then the platform hosts its own management interfaces.

**Tenant dashboard** (`console.jkbase.dev`):
- Project list, create/delete
- Per-project: deployments, rollback, logs, domains, secrets, routes
- Service status and health
- Usage/metering overview
- Calls the same control plane API as the CLI

**Platform admin** (`admin.jkbase.dev`):
- All tenants and projects
- Global resource usage and capacity
- VM status across all projects
- System health, alerts
- Tenant management (quotas, billing, suspension)
- Platform config

**Bootstrap sequence:**
```
1. Install jkbase (single binary)
2. jkbase init — platform setup
3. jkbase admin create-tenant — create yourself
4. jkbase project create admin-ui
5. jkbase deploy — admin UI is live
6. Manage everything from admin.jkbase.dev
```

CLI is always the escape hatch — if the UI breaks, CLI still works.
Not MVP-blocking — CLI covers everything initially.

## CLI

Built with `clap`. The primary interface to jkbase.

**Command structure:**
```
jkbase init                          # initialize platform (admin)
jkbase login                         # interactive auth, stores token
jkbase dev                           # run full platform locally

jkbase project create|list|delete|info
jkbase deploy [--project <name>]     # smart deploy (only changed artifacts)
jkbase rollback [--version <n>]
jkbase deployments list

jkbase server list|restart|stop
jkbase function list|invoke

jkbase secret set|list|rm
jkbase domain add|verify|list|rm
jkbase logs [--follow] [--service <name>]
jkbase token create --name --scope   # scoped tokens for CI

jkbase admin create-tenant|list-tenants|suspend-tenant|status
```

**DX principles:**
- Project context inferred from `jkbase.toml` in current directory
  (like git knows its repo)
- Human-friendly output by default, `--json` for scripting
- Progress indicators on deploys
- Confirmation on destructive actions (`--force` to skip)
- Non-zero exit on failure (deploys that fail always exit 1)

**Authentication priority:**
1. `JKBASE_TOKEN` env var (CI/CD, no prompts)
2. `--token` flag (explicit)
3. Stored token from `jkbase login` (developer default)

**CI/CD support:**
- `jkbase token create --name "github-actions" --scope project:my-app`
- Scoped tokens: revocable, auditable, least-privilege
- Control plane API is always non-interactive — CLI is a wrapper,
  CI can curl the API directly if needed

## Build order

Vertical slice approach — get one request flowing end-to-end first,
then widen.

**Phase 0: Skeleton**
- Cargo workspace with crate stubs
- `jkbase.toml` config parsing (serde + toml)
- CLI skeleton with clap (`jkbase deploy`, `jkbase project create`)

**Phase 1: "Hello World serves from a VM"**
Thinnest vertical slice — every layer minimal but real:
- Control plane: hardcoded single project, redb, minimal deploy API
- Orchestrator: boot one Firecracker VM with minimal rootfs
- Guest agent: embedded static file server, vsock health reporting
- Proxy: Pingora routing localhost → the VM
- CLI: `jkbase deploy` tars a directory and pushes it
- **Milestone: run `jkbase deploy`, hit localhost, see your HTML page**

**Phase 2: Multi-project + real routing**
- Control plane: project CRUD, tenant auth, routing table
- Proxy: subdomain-based routing, ACME/SSL
- Orchestrator: multiple VMs, start/stop
- CLI: `jkbase project create`, `jkbase login`
- **Milestone: two projects serving on different subdomains**

**Phase 3: Functions**
- Guest agent: embed Wasmtime, instance pool
- CLI: detect and deploy WASM modules
- Route config: function routes in jkbase.toml
- **Milestone: deploy a Rust function, call it via HTTP, get a response**

**Phase 4: Servers**
- Guest agent: container supervisor, health checks
- Orchestrator: image builds on host, persistent volumes
- Deploy flow: Dockerfile build + push
- Auto-rollback on failed health check
- **Milestone: deploy a Dockerized API server, hit it through the proxy**

**Phase 5: Operational maturity**
- Secrets store
- Logging pipeline
- Domain management + verification
- Metering
- Scale-to-zero (Firecracker snapshots)
- Rollback / deployment history
- Scheduled functions

**Phase 6: Web UIs**
- Build tenant dashboard, deploy on jkbase
- Build admin dashboard, deploy on jkbase
- Platform is self-hosting

Phase 1 is the hardest — standing up every layer simultaneously. But
each layer is tiny. After that, each phase widens one or two layers
while the rest stay stable.

## Crate structure

```
jkbase/
  Cargo.toml                (workspace)
  crates/
    jkbase-server/           # binary — platform daemon, wires libs together
    jkbase-cli/              # binary — user-facing CLI
    jkbase-agent/            # binary — guest agent, ships in VM rootfs
    jkbase-proxy/            # lib — Pingora wrapper, routing, TLS/ACME
    jkbase-control/          # lib — control plane API, redb, project/tenant mgmt
    jkbase-orch/             # lib — Firecracker VM lifecycle, images, networking
    jkbase-common/           # lib — shared types, config parsing, vsock protocol
```

**Dependency graph:**
```
jkbase-server
  ├── jkbase-proxy    → jkbase-common
  ├── jkbase-control  → jkbase-common
  └── jkbase-orch     → jkbase-common

jkbase-cli    → jkbase-common (config types, API types)
jkbase-agent  → jkbase-common (config types, vsock protocol)
```

Binary crates are thin — jkbase-server is a main.rs that initializes
the three libs and connects them with tokio channels. Clean boundaries
mean splitting into separate processes later is just making three
binaries instead of one.

jkbase-common stays lean: just types, serialization, protocol
definitions. No heavy dependencies.

## Open questions
- Database: build own storage engine vs layer on SQLite/Postgres?
- How do projects communicate cross-project? (HTTP via proxy for now)
- Storage service details
- Admin UI / CLI tooling (self-hosted on jkbase, CLI-bootstrapped)
- Client SDK design
- How to handle project config ("choose your services")
- Guest rootfs image strategy — one image per service combo, or modular?
- Firecracker networking details (tap device setup, IP allocation)
- How does deploy push files into a project's VM? (virtio-fs decided)
- Log shipping mechanism details (virtio-fs vs VM network)
- Secret encryption at rest — what key management?
- Project deletion: hard delete vs soft delete with grace period?
