# jkbase

**Your own little cloud, minus the part where you pay someone else's yacht payment.**

jkbase is a self-hostable platform for shipping **static sites**, **server apps** (built from
source), **WASI functions**, and **raw UDP services** — with a **managed database** and
**S3-compatible object storage** built in. Every project gets its own
[Firecracker](https://firecracker-microvm.github.io/) microVM. Not a container. A real VM, with
its own kernel, booted in ~125ms. Your neighbors can't read your secrets because they're in a
different machine entirely. Blast radius: one.

You push source; the platform builds it **server-side** in a sealed, network-fenced microVM (no
Docker on your laptop, no `node_modules` on your conscience), and serves it on HTTPS. Bun, Node,
Rust, Python and Go all build straight from source; bring-your-own-Dockerfile is the escape hatch
for when you have Opinions.

There are two ways to read this README:

- **"I want to deploy something"** → [Quickstart](#quickstart). You'll be live in four commands,
  then [pick your app type](#what-you-can-deploy).
- **"I want to run the whole thing myself"** → [Self-hosting jkbase](#self-hosting-jkbase). Local
  box or remote server, your call.

---

## Quickstart

### Install the CLI

```bash
git clone https://github.com/joeleaver/jkbase && cd jkbase
cargo install --path crates/jkbase-cli   # installs the `jkbase` binary
```

By default the CLI talks to `https://api.jkbase.app`. Running your own platform? Append
`--api https://api.your-domain.com` to any command (or set `JKBASE_TOKEN` and pass `--api`). Every
command that hits the control API takes `--api` — put it *after* the subcommand.

### 1. Get an account

On the hosted platform, sign up in the web console at `https://console.jkbase.app` (email +
password); it hands you an API token for CLI access. Then:

```bash
jkbase login --token YOUR_TOKEN   # or pipe the token on stdin; saved to ~/.jkbase/credentials
```

> `jkbase init you@example.com` is **different**: it bootstraps a brand-new platform and mints its
> **first admin**, so you only run it on a platform **you** just stood up (see
> [Self-hosting](#self-hosting-jkbase)). Against an already-running platform it returns `platform
> already initialized`.

### 2. Create a project

```bash
jkbase project create my-app
```

### 3. Add a `jkbase.toml`

```toml
[project]
name = "my-app"

[hosting]
public = "./dist"   # your built static files (./dist, ./build, ./public, …)
spa = true          # set true if you use client-side routing
```

### 4. Deploy

```bash
jkbase deploy
```

Your site is live at `https://my-app.jkbase.app`. That's the whole trick.

---

## What you can deploy

Everything is declared in one `jkbase.toml` at your repo root and shipped with `jkbase deploy`. A
single project can combine as many of these as you like.

| You want to deploy… | Declare it with | Reached at |
|---|---|---|
| A **static site** (or several) | [`[hosting]` / `[sites.*]`](#static-sites) | `https://<project>.jkbase.app` (+ prefixes / subdomains) |
| A **server app** (Bun/Node/Rust/Python/Go, or a Dockerfile) | [`[servers.*]`](#servers) | routed by [`[routes]`](#routing--custom-domains) |
| A **function** (Rust or JS/TS → `wasi:http`) | [`[functions.*]`](#functions-wasi-components) | `…/functions/<name>` or a `[routes]` entry |
| A **managed database** (RhypeDB) | [`[database]`](#managed-databases-rhypedb) | loopback in-VM; TLS reach-plane from outside |
| A **raw UDP service** (game / voice / custom protocol) | [`[l4.*]`](#raw-udp-services) | `<host-ip>:<allocated-port>` |
| **Object storage** (S3-compatible) | nothing — [it's always on](#object-storage-s3-compatible) | `https://storage.jkbase.app` |

The full annotated `jkbase.toml` is in the [configuration reference](#jkbasetoml-reference).

---

## Static sites

Point `hosting.public` at your build output and call it a day:

```toml
[hosting]
public = "./dist"
spa = true   # client-side routing → fall back to index.html
```

### Multi-site hosting

Several static directories, one project, prefix routing — and each site can claim its own
subdomain or custom domain:

```toml
[sites.docs]
public = "./docs/build"
prefix = "/docs"
# domain = "docs"               # → docs.jkbase.app, or a full "docs.example.com"

[sites.blog]
public = "./blog/out"
prefix = "/blog"
spa = true
```

A committed site **must** set `public` (a site with no `public` and no `build` is rejected at
deploy, so you can never accidentally publish your whole source tree). Longest matching `prefix`
wins.

### Built sites (Rust/WASM via Trunk)

A site can be **built server-side** instead of committed — point `build = "trunk"` at a Rust/WASM
frontend and the platform runs the build for you (no local toolchain):

```toml
[sites.app]
source  = "plotweb-web"   # a trunk frontend crate
context = "."             # monorepo: mount a wider tree so sibling path-deps resolve
build   = "trunk"
spa     = true
```

---

## Servers

A server runs inside your project's microVM with its own port and optional persistent storage. By
default the platform **builds it from source** — push raw code, the language is auto-detected, and
the build happens server-side in a throwaway microVM:

```toml
[servers.api]
source = "./server"           # build subdir (default ".")
# context = "."               # monorepo: mount a WIDER tree so sibling path-deps resolve (default = source)
# language = "bun"            # optional hint; auto-detected (bun|node|rust|python|go)
port = 8080                   # REQUIRED — authoritative for routing (no default; omitting it fails the deploy)
# command = ["/opt/bun/bin/bun", "run", "start"]   # optional: override the launch argv (argv[0] absolute)
health_check = { path = "/health", interval = "10s", timeout = "5s" }
volumes = [{ name = "data", mount = "/app/data" }]

[routes]
"/api/*" = { service = "server", name = "api" }
```

Then send it some traffic with a `[routes]` entry (see [Routing](#routing--custom-domains)). A
server named `api` is reached by whatever paths/hosts you route to it.

> A project that has **only** `[servers.*]` (no `[hosting]`/`[sites.*]`) serves **nothing**
> statically — every path routes to the server. Add `[hosting]` if you also want to serve static
> assets.

**Bring your own Dockerfile** (the escape hatch). The platform builds it *server-side* with
[buildah](https://buildah.io/) — still no Docker on your machine — and runs the resulting image as
a self-contained server. Omit `language` (the image brings its own runtime — setting both is
rejected); `dockerfile` defaults to `<source>/Dockerfile`; `port` stays authoritative for routing:

```toml
[servers.api]
builder = "dockerfile"
dockerfile = "./Dockerfile"
port = 8080
```

Volumes persist across deploys. Build output does not — that's the point.

### Monorepos & workspaces

By default a target is built from **just its `source` subdir** — that subdir is all that's mounted
in the build VM. So a crate or package that depends on an **in-repo sibling** by relative path
fails to build, because the sibling lives outside the mount.

Add an optional **`context`** — the directory mounted as the build root, exactly like a **Docker
build context**. `source` is then the working directory *within* it:

```toml
[servers.api]
source  = "crates/api"   # WHERE the build runs (the app dir)
context = "."            # WHAT is mounted as the build root (the whole workspace)
port    = 8080
```

Now the whole workspace is mounted, so `../common` resolves. This is buildpack-agnostic — it works
the same for Rust workspaces, pnpm/yarn/npm workspaces, Go multi-module repos, Python monorepos,
and `build = "trunk"` sites.

Rules: `context` defaults to `source`, so **omitting it changes nothing**. `source` must live
**inside** `context`, and both must be relative paths inside the project (no `..`/absolute). Keep
`context` no wider than the path-deps require — a wide context mounts more of your repo into the
build (bigger build, weaker reproducibility), so prefer `apps/` over `.` when that's enough.

---

## Functions (WASI components)

Write a function in **Rust or JavaScript/TypeScript**; the platform builds it server-side (no local
toolchain) to a single **`wasi:http` component** and runs it in the project's microVM — on request
or on a cron schedule. One component ABI (`wasi:http/incoming-handler`) across every language,
executed via [wasmtime](https://wasmtime.dev/).

```toml
[functions.hello]
source   = "./functions/hello"   # source dir; built to a wasi:http component server-side
language = "rust"                # rust | javascript (auto-detected from the source if omitted)
# schedule = "*/5 * * * *"       # optional: also (or instead) run it on a 5-field cron
# egress   = ["api.stripe.com"]  # optional: enforce an outbound allowlist (see below)

# Reach it at /functions/hello, or route it explicitly:
[routes]
"/hello/*" = { service = "function", name = "hello" }
```

A Rust function exports a handler via the `wasi` crate's `proxy::export!`; a JS function is a
Service-Worker-style `addEventListener('fetch', …)` handler (ComponentizeJS / StarlingMonkey). See
`templates/function-rust` and `templates/function-js`. (Only **Rust** and **JavaScript/TypeScript**
build today.)

**What functions can do:** handle HTTP, compute, run on a schedule, read their project's
**secrets** (Rust via `std::env`, JS via `process.env`), make **outbound HTTP** with `fetch`, and
read/write their project's **own object store**. Each invocation is sandboxed and bounded (epoch +
30s wall-clock + 128 MiB memory; 10 MiB request/response bodies) and runs fresh — no state persists
between calls. A scheduled invocation arrives as a plain `POST /functions/<name>` with header
`x-jkbase-trigger: schedule`. Function routes are request/response only (a WebSocket/upgrade request
gets `426 Upgrade Required`).

### Outbound network & object store

Both are **host-mediated and default-deny SSRF-guarded** — the guest owns no kernel sockets; every
outbound request goes through one vetted door that pins DNS and IPs and refuses the platform's own
addresses, all private/metadata ranges, and IPv6, and never follows redirects.

**Public egress** is policed **per function** by `egress` in `jkbase.toml`:

| `egress =` | Behaviour |
|---|---|
| *(omitted)* | **Default** — public egress allowed and observed/metered. |
| `["api.stripe.com", "api.twilio.com"]` | **Allowlist** — only these exact hosts. |
| `false` | **Sandbox** — deny all public egress. |

Set a project-wide **ceiling** with `[hosting] function_egress = …` (same three shapes); a function
may narrow it but never widen past it. (`egress = []` / `function_egress = []` are rejected — use
`false` to sandbox.)

**Object store**: a typed capability (`jkbase:objectstore/store`) gives `get` / `put` / `delete` /
`list` over keys in your project's own `functions` bucket. The credential is minted per deploy and
injected host-side — it never appears in `process.env`, and it keeps working even under
`egress = false`. (Need other buckets? Hold your own [S3 access key](#object-storage-s3-compatible)
as a secret and `fetch` the storage host, subject to your egress policy.)

> The legacy WASI **preview1** path (`_start` + stdin/stdout JSON) still runs unchanged beside the
> component runtime, so older functions keep working; `runtime = "wasip1"` is a supported build path
> for Rust (compute + secrets only — no outbound, no object store).

---

## Managed databases (RhypeDB)

Every project can have its own **managed database** — a [RhypeDB](https://rhypedb.com) instance that
boots inside the project's microVM (or a dedicated sibling VM), backed up automatically, reachable
from your laptop over TLS, and — when you want it — enforcing **default-deny, per-user security
rules** against verified end-user identities. No database to provision, patch, or babysit.

### Turn one on

Add a `[database]` table pointing at a RhypeDB schema file in your source tree:

```toml
[database]
schema = "schema.rhype"    # REQUIRED: your RhypeDB SDL schema
# size   = "4GiB"          # data-disk size (default 1 GiB — bump it for a real workload)
# tier   = "colocated"     # "colocated" (default) or "dedicated"
# rules  = "rules.rhype"   # opt into end-user auth + default-deny rules (see below)
# engine = "rhypedb"       # only value
```

- **`colocated`** (default) runs the database as a second supervised process inside your app's VM —
  zero extra moving parts.
- **`dedicated`** runs it in a **sibling VM** for noisy-neighbor isolation (and the required posture
  before you expose it to untrusted clients). From your app's point of view the two are
  byte-identical.

`size` accepts binary (`GiB`/`MiB`) and decimal (`GB`/`G`) units, case-insensitive.

### Talk to it from your app

Inside the VM the database is on loopback, open to your own app (which the platform trusts) — no
credentials needed:

- HTTP query plane: `http://127.0.0.1:4200`
- Native wire (what RhypeDB's client uses, including subscriptions): `127.0.0.1:4201`

Point RhypeDB's client — the `@rhypedb/client` package — at `127.0.0.1:4201` (or hit
`POST http://127.0.0.1:4200/query` directly). The database is **loopback-only and never routable**
from the internet.

### Reach it from your laptop or CI

RhypeDB's native wire is plaintext, so external access rides a TLS edge at `<project>.db.<domain>`
(e.g. `my-app.db.jkbase.app:443`) fronted by a local sidecar. Mint a reach-plane key, then run the
proxy:

```bash
jkbase db key create --label ci        # prints a JKBD… id + a jkbd_… secret (shown ONCE — save it)

export JKBASE_DB_ACCESS_KEY_ID=JKBD0123456789ABCDEF
export JKBASE_DB_SECRET=jkbd_xxxxxxxxxxxx
jkbase db proxy --project my-app       # listens on 127.0.0.1:4200, tunnels to my-app.db.jkbase.app:443
# → point RhypeDB's client at 127.0.0.1:4200 (the sidecar forwards to the DB's native wire — 4201 exists only inside the VM)
```

The tunnel is TLS 1.3, SNI-pinned, verified against public roots; the key authenticates before any
bytes reach the database. `jkbase db key list` / `jkbase db key rm <id>` manage keys. (Prefer the
env vars over `--access-key-id`/`--secret` flags so the secret stays out of your shell history. For
a private/on-prem edge, `--ca-file` *adds* a trust anchor — it's never a skip-verify mode.)

### Backups & restore

Backups run **automatically nightly** and can be taken on demand. The newest 14 are retained (hard
ceiling 30 per project):

```bash
jkbase db backup                 # take one now (blocks until complete)
jkbase db backups                # list: id, created, size, status
jkbase db restore <backup_id>    # DESTRUCTIVE overwrite — prompts for the project name (--force to skip)
```

### End-user auth & rules (the Firestore-style path)

By default the managed database is **"for your own trusted backend"** — your server talks to it over
loopback and does its own authorization. To let *end users'* clients touch the data directly, jkbase
gives you two pieces that snap together:

**1. jkbase-Auth — a per-project JWT issuer.** jkbase mints EdDSA (Ed25519) JWTs for your users but
**stores no end-user accounts** — *your* backend authenticates users however it likes, then mints a
per-user token with an issuer key:

```bash
jkbase auth key create --label backend   # prints a jkbk_… issuer key (shown ONCE)
```

Your backend presents that `jkbk_…` key to the issuer to mint a short-lived per-user token:

```http
POST https://auth.jkbase.app/v1/projects/<project-id>/token   # Bearer jkbk_… → a per-user EdDSA JWT
GET  https://auth.jkbase.app/v1/projects/<project-id>/.well-known/jwks.json   # public JWKS (anonymous)
```

Your `<project-id>` (distinct from the project name) is printed by `jkbase project create` and
`jkbase project list`.

`jkbase auth mint --sub <user> --key jkbk_…` does the same from the CLI for local development.
`jkbase auth rotate [--hard]`, `jkbase auth signing-keys`, and `jkbase auth jwks` manage the signing
key (soft rotation keeps the old key in the JWKS for ~24h; `--hard` revokes it immediately).

**2. Rules — default-deny, relationship-aware authorization.** Add `rules` to `[database]`:

```toml
[database]
schema = "schema.rhype"
rules  = "rules.rhype"     # verified end-user principal + default-deny rules
tier   = "dedicated"       # recommended before untrusted clients
```

With `rules` set, jkbase bakes the project's public JWKS into the database VM at deploy, and RhypeDB
verifies each end user's JWT **offline** and enforces your rules against the verified principal —
Firestore-style. Without `rules`, there's no end-user enforcement (the trusted-backend model above).

> **v1 caveat:** the JWKS is baked at deploy, so after a `jkbase auth rotate` you must **redeploy**
> for the database VM to pick up the new key.

You can also browse tables, run queries, edit the schema, and manage keys/backups from the
[web console](#web-console)'s **Database studio** — no sidecar required.

---

## Raw UDP services

Not everything is HTTP. jkbase can expose a **raw UDP port** straight to your app — game servers,
voice servers (TeamSpeak, Mumble), or any custom binary protocol — with the same **scale-to-zero**
story as everything else: an idle service hibernates to nothing, and the **first incoming datagram
wakes it** (~125ms) before being delivered.

Declare an `[l4.<name>]` table. You choose the protocol and the **loopback** port your service binds
inside the VM; the platform allocates the public port:

```toml
[l4.voice]
proto      = "udp"       # REQUIRED ("tcp" is not served yet — UDP only)
guest_port = 9987        # REQUIRED: your service binds 127.0.0.1:9987 (loopback ONLY)
# idle_timeout = 60      # seconds of silence before scale-to-zero (clamped 15–600)
# amp_k = 0             # anti-reflection clamp: 0=off (default); 1..=3 opts in (reply ≤ k× the client's bytes)
```

Deploy, then discover the **platform-assigned public port** (there's no way to know it beforehand):

```bash
jkbase deploy
jkbase l4 ls
# NAME    PROTO  PUBLIC   GUEST    PINNED
# voice   udp    24817    9987
# → clients connect to  <your-host-ip>:24817  (UDP)
```

Things to know:

- **No subdomain routing.** UDP has no `Host`/SNI — clients connect to the **raw host IP + the
  allocated port**, not `*.jkbase.app`. The public port is **sticky** across redeploys and rollbacks.
- Your service **must bind `127.0.0.1:<guest_port>` only** (never `0.0.0.0`/`eth0`) — the only path
  in is the platform's authenticated forward.
- Up to **5** L4 ports per project.
- The public port is auto-allocated from **20000–30000**. A platform operator can pin a fixed port
  (e.g. `9987` so existing client bookmarks keep working) with `jkbase l4 pin <name> <port>` — an
  admin-only command.
- Self-hosting: your cloud/edge firewall must allow inbound **UDP 20000–30000** (jkbase opens its
  own host firewall, but not your provider's). See [Self-hosting](#remote-production-server).

---

## Object storage (S3-compatible)

Every project gets its own **S3-compatible object store** at `https://storage.<domain>` (e.g.
`storage.jkbase.app`). Auth is AWS **SigV4** with per-project access keys, so the AWS SDKs, `aws s3`,
`rclone`, and friends work out of the box — pointed at your jkbase endpoint with **path-style**
addressing and region **`us-east-1`**. Buckets and objects are isolated to the project that owns the
key; another project's credentials can't see them.

### Issue an access key

```bash
jkbase access-key issue --label ci      # prints endpoint + id; secret is shown ONCE — save it
jkbase access-key list                  # ids + labels (secrets never shown)
jkbase access-key rm JKBA...            # revoke
```

### What's supported

- **Buckets** — create, delete (empty), head, list. Names are 3–63 chars, lowercase `[a-z0-9-]`.
- **Objects** — `PUT` / `GET` / `HEAD` / `DELETE`, with MD5 ETags, content-type, last-modified, and
  cache-control.
- **Multipart uploads** — initiate / upload part / complete / abort / list, for large objects.
- **Presigned URLs** — time-limited GET/PUT links, no SDK on the client.
- **Listing** — `ListObjects` v1 + v2 with prefix, **delimiter** (folder-style common-prefix
  folding), and pagination (continuation tokens / markers); `max_keys` clamps to 1000.
- **CORS** — per-bucket CORS config (S3 `?cors` subresource) so browsers can upload directly.

Per-project quotas apply (defaults: **16 GiB** of storage, **1,000,000** objects, **100** buckets)
and stored bytes count toward the project's storage cap and metering alongside deployments and data
disks. Object-store traffic is served straight off the platform — no extra service to stand up.

### SDKs

A zero-dependency SigV4 client (Web Crypto + `fetch`; Node 18+, Deno, browsers) lives in
[`sdk/js`](sdk/js) as `@jkbase/objectstore` (vendor it from this repo — not yet on npm) — a minimal
subset (create bucket, put/get/delete, list, presigned GET):

```js
import { ObjectClient } from "@jkbase/objectstore";

const s3 = new ObjectClient("https://storage.jkbase.app", accessKeyId, secretAccessKey);
await s3.createBucket("uploads");
await s3.putObject("uploads", "hello.txt", "hi", "text/plain");
const bytes = await s3.getObject("uploads", "hello.txt");   // Uint8Array
const url   = await s3.presignedGet("uploads", "hello.txt", 900); // 15-min link
```

A fuller **Rust** client — buckets, streaming objects, multipart, presigned GET/PUT, paged listing,
typed errors — lives in [`sdk/rust`](sdk/rust) as `jkbase-objectstore-client` (consume it as a
path/git dependency — not yet on crates.io):

```rust
use jkbase_objectstore_client::ObjectClient;

let s3 = ObjectClient::new("https://storage.jkbase.app", access_key, secret);
s3.create_bucket("assets").await?;
s3.put_object("assets", "hello.txt", b"hi".to_vec(), "text/plain").await?;
let body = s3.get_object_bytes("assets", "hello.txt").await?;
```

Both speak the same SigV4 canonicalization the server verifies — no AWS SDK bloat. (Any AWS SDK also
works: set path-style addressing and region `us-east-1`.)

---

## Routing & custom domains

Routes send paths (or hosts) to a **server** or a **function**:

```toml
# Top-level — must come before any [table] header (it's a bare key on the project).
domains = ["example.com", "www.example.com"]

[routes]
"/api/*"   = { service = "server",   name = "api" }
"/hello/*" = { service = "function", name = "hello" }
```

`service` is either `"server"` or `"function"` (the only two honored values — anything else, and the
route silently doesn't exist); `name` matches a `[servers.*]`/`[functions.*]` key. Static sites are
routed by their own `prefix`/`domain`, not through `[routes]`.

Or attach domains imperatively with `jkbase domain add` (handy for `_acme-challenge` /
TXT-verification flows). `--site <name>` binds a domain to one site within a multi-site project.

---

## Managing secrets

```bash
jkbase secret set STRIPE_KEY=sk_live_...
jkbase secret list
jkbase secret rm STRIPE_KEY
```

Secrets are scoped to the project from your `jkbase.toml` (or pass `--project`). They're injected
into your server's environment and **never** touch the on-disk deployment artifact — they live only
in the per-VM metadata image. Reserved vars (`PORT`/`HOME`/`HOSTNAME`/`PATH`) can't be clobbered by a
secret, no matter how creatively you name it.

A change applies on your next `jkbase deploy` — or, without a rebuild, with **`jkbase restart`**,
which re-injects current secrets/env and restarts the server in place:

```bash
jkbase secret set STRIPE_KEY=sk_live_...
jkbase restart                 # apply it now, no rebuild (deploy rebuilds from source)
```

---

## Deploying

Three ways to get code live, all first-class:

**1. From your machine.** The primary path:

```bash
jkbase deploy
```

**2. Push-to-deploy over git.** `connect` only mints a token and adds a local `jkbase` remote (it
touches `.git/config`, nothing tracked); a push to `main` builds and deploys:

```bash
jkbase repo connect          # mint a push token + add the local `jkbase` remote
git push jkbase main         # build + deploy
```

**3. GitHub Actions.** Opt into a workflow explicitly (it writes a *tracked* file, so it's never a
surprise side effect):

```bash
jkbase repo github           # scaffold .github/workflows/jkbase-deploy.yml — then commit it
#   set the token from `repo connect` as the JKBASE_GIT_TOKEN repo secret, and
#   every push to main/master deploys via Actions.

jkbase repo token            # re-mint the token (revokes the old one)
jkbase repo disconnect       # revoke the token + remove the remote
```

---

## Web console

The platform ships a browser console (itself a jkbase-hosted static site) at `https://console.<domain>`.
Sign in with your token to manage projects without the CLI: deployments and rollback, live logs,
secrets, custom domains, month-to-date usage, S3 access keys, a **storage browser** (upload,
download, delete, folder-style listing), and a **Database studio** for the managed database (browse
tables, run queries, view/edit schema, manage reach-plane keys, take/restore backups). The console
talks to the object store and database over session-scoped Bearer APIs — your S3 secret and database
credentials never touch the browser.

---

## `jkbase.toml` reference

Everything lives in `jkbase.toml`. The kitchen sink, with every table:

```toml
# Top-level bare keys MUST precede any [table] header.
domains = ["example.com", "www.example.com"]   # custom-domain aliases for the whole project

[project]
name = "my-app"

# --- Static site (shortcut) ----------------------------------------------
[hosting]
public = "./dist"
spa    = true
# function_egress = ["api.stripe.com"]   # project-default egress CEILING for functions

# --- Multi-site hosting (each can claim a subdomain / custom domain) ------
[sites.docs]
public = "./docs/build"
prefix = "/docs"
# domain = "docs"                # -> docs.jkbase.app (or a full "docs.example.com")

[sites.app]                      # a BUILT site (Rust/WASM via trunk)
source  = "plotweb-web"
context = "."
build   = "trunk"
spa     = true

# --- A source-built server (Bun/Node/Rust/Python/Go) ----------------------
[servers.api]
source       = "crates/api"      # build subdir (default ".")
context      = "."               # monorepo: mount a wider tree; source must be INSIDE context
# language   = "rust"            # optional hint (bun|node|rust|python|go); auto-detected
port         = 8080              # REQUIRED — authoritative for routing (no default)
# command    = ["/opt/bun/bin/bun", "run", "start"]   # optional argv override; argv[0] absolute
health_check = { path = "/health", interval = "10s", timeout = "5s" }
volumes      = [{ name = "data", mount = "/app/data" }]

# --- A Dockerfile server (escape hatch) -----------------------------------
[servers.legacy]
builder    = "dockerfile"
dockerfile = "./Dockerfile"      # defaults to <source>/Dockerfile
port       = 3000                # do NOT set `language` here (mutually exclusive)

# --- A WASI function (HTTP and/or cron) -----------------------------------
[functions.hello]
source   = "./functions/hello"
# language = "rust"              # rust | javascript; auto-detected
# runtime  = "wasi-http"         # default; "wasip1" = legacy Rust path
# schedule = "*/5 * * * *"       # optional cron
# egress   = false               # false=sandbox | (omit)=default+observe | ["api.stripe.com"]=allowlist

# --- Managed database (RhypeDB) -------------------------------------------
[database]
schema = "schema.rhype"          # REQUIRED
# rules  = "rules.rhype"         # opt into verified end-user auth + default-deny rules
# size   = "4GiB"                # data-disk size (default 1 GiB)
# tier   = "colocated"           # or "dedicated" (sibling VM)
# engine = "rhypedb"             # only value

# --- Raw UDP ingress (e.g. a voice server) --------------------------------
[l4.voice]
proto        = "udp"             # REQUIRED ("tcp" not yet supported)
guest_port   = 9987              # REQUIRED — the loopback port your service binds
# idle_timeout = 60              # seconds, clamped [15, 600]
# amp_k        = 0               # 0=off (default); 1..=3 opts into the reflection clamp

# --- Connected-repo push build (optional) ---------------------------------
# [build.repo]
# url    = "https://github.com/you/my-app"
# branch = "main"                # default

# --- Explicit routing to servers/functions --------------------------------
[routes]
"/api/*"  = { service = "server",   name = "api" }
"/hello"  = { service = "function", name = "hello" }
```

> The name `rhypedb` is **reserved** for the managed database — a `[servers.*]`/`[functions.*]`/
> `[sites.*]` or a route target named `rhypedb` is rejected at deploy.

---

## CLI reference

| Command | What it does |
|---|---|
| `jkbase init <email>` | Initialize a platform + create the first admin account |
| `jkbase login --token <tok>` | Authenticate with an existing token (or pipe on stdin) |
| `jkbase project create <name>` | Create a project |
| `jkbase project list` | List your projects |
| `jkbase project info <name>` | Show a project's details |
| `jkbase project delete <name>` | Delete a project (and purge its data + secrets) |
| `jkbase deploy [--json]` | Build + deploy the current project |
| `jkbase restart [--force] [--json]` | Restart the server, re-injecting secrets, **without** a rebuild |
| `jkbase rollback [--version N] [--force]` | Roll back to a previous deployment |
| `jkbase deployments` | Show deployment history |
| `jkbase logs [-f] [--service X] [-n N] [--json]` | Tail server logs (`-f` to follow) |
| `jkbase usage` | Month-to-date metered usage (CPU, bandwidth, storage, build-minutes) |
| `jkbase quota [--set-storage-gib N] [--set-bandwidth-gib N] [--set-build-minutes N]` | Show / restrict per-project quotas |
| `jkbase secret set\|list\|rm` | Manage secrets |
| `jkbase access-key issue\|list\|rm` | Manage S3 object-store access keys |
| `jkbase db key create\|list\|rm` | Manage managed-database reach-plane access keys |
| `jkbase db proxy` | Local sidecar tunneling RhypeDB's client to the managed DB over TLS |
| `jkbase db backup\|backups\|restore <id>` | Take / list / restore managed-database backups |
| `jkbase auth key create\|list\|rm` | Manage jkbase-Auth issuer keys (`jkbk_…`) |
| `jkbase auth rotate\|signing-keys\|jwks\|mint` | Rotate the signing key; inspect keys/JWKS; mint a token (dev) |
| `jkbase domain add\|verify\|list\|rm` | Manage custom domains (`add --site <name>` to bind to one site) |
| `jkbase l4 ls` | List a project's allocated raw-UDP ports (discover the public port) |
| `jkbase repo connect\|github\|token\|disconnect` | Push-to-deploy: mint token/remote, scaffold CI, rotate, revoke |

Every command that hits the control API takes `--api URL` (default `https://api.jkbase.app`), placed
after the subcommand; the token can also come from `$JKBASE_TOKEN`. (`jkbase auth jwks`/`mint` use
`--issuer` instead, default `https://auth.jkbase.app`.) Platform operators have two more:
`jkbase l4 pin <name> <port>` and raising quotas above defaults via `--admin-token`
(`$JKBASE_ADMIN_TOKEN`) — both no-ops on a server started without an admin token.

---

## Self-hosting jkbase

So you want to run the whole circus yourself. Respect. jkbase boots real microVMs, so the host needs
**KVM** — a bare-metal Linux box, or a VM/VPS with **nested virtualization** enabled. Today the host
tooling is **Debian/Ubuntu only** (it's all `apt` + a Wolfi/apko image bake; the *images* are
portable, the bake scripts are not).

### Local (development box)

For hacking on jkbase itself, or kicking the tires. `tools/dev` is one idempotent, pin-aware command
that takes a fresh checkout to a working build+runtime box — no more stitching seven scripts together
by hand and wondering which one you forgot.

**You need:** Debian/Ubuntu, a writable `/dev/kvm`, passwordless `sudo`, and `rustup`. (`tools/dev
preflight` checks all of it and tells you what's missing — no guessing.)

```bash
git clone https://github.com/joeleaver/jkbase && cd jkbase

./tools/dev deps        # apt packages + rust targets + adds you to the `kvm` group
#   ↑ log out and back in once so the kvm group membership takes effect

./tools/dev all         # the heavy lifting, all cached + idempotent:
                        #   Firecracker, the 6.12 guest kernel, the language build
                        #   toolchains (bun/node/rust/python/go/dockerfile + the function
                        #   and trunk toolchains), and the shared base layers. Re-run it
                        #   anytime; it only rebuilds what actually changed.

./tools/dev net         # per boot: the build bridge + firewall + cgroup (root)
./tools/dev doctor      # all green? you're good.
./tools/dev test        # optional: the on-box gauntlet — builds a real app in a
                        #   microVM and curls it for an HTTP 200. Proof, not vibes.
```

`tools/dev <stage>` runs any single stage; `--check` is a dry-run that tells you what each stage
*would* do without touching anything. Stages: `preflight deps assets rust kernel toolchains
baselayers net all doctor test`.

To actually **run the platform** locally and deploy to it:

```bash
sudo bash tools/setup-bridge.sh    # the runtime network bridge (jkbr0), once per boot

./target/release/jkbase-server \
  --data-dir   /var/jkbase \
  --fc-dir     .firecracker \
  --agent-bin  target/x86_64-unknown-linux-musl/release/jkbase-agent \
  --build-net \                     # builds fetch deps through the fenced egress proxy
  --build-proxy-any-port 3129       # opt-in: enables `builder = "dockerfile"` builds
                                    #   (`tools/dev net` already opened 3129 in the firewall)

jkbase init you@example.com --api http://127.0.0.1:9090   # bootstrap your local platform
```

Locally there's no wildcard DNS or TLS, so the proxy listens on `:8080` (default `--proxy-port`) and
you reach a deployed site by sending its `Host:` header to `http://127.0.0.1:8080`. The S3 object
store rides along automatically: the server binds it on `127.0.0.1` (`--storage-port`, default 9091)
and the proxy routes `storage.<domain>` to it — no extra process to run.

### Remote (production server)

One command from your workstation provisions a fresh server end to end — system deps, Firecracker, a
release build of jkbase, the **6.12 guest kernel** (built on the box; the layered runtime needs
erofs/overlay), the systemd unit (with socket activation for zero-bounce restarts), and the isolated
build network:

```bash
./tools/provision.sh you@your-server.example.com    # SSH target needs passwordless sudo
```

Then, on the server side (`provision.sh` prints these as it finishes):

1. **DNS creds (wildcard TLS via DNS-01)** — fill in `/var/jkbase/.env`. The wildcard cert is issued
   over ACME DNS-01, so jkbase needs to write a TXT record to your zone. Pick a provider with
   `ACME_DNS_PROVIDER` (default `cloudflare`):
   ```ini
   ACME_EMAIL=you@example.com

   # ACME_DNS_PROVIDER=cloudflare   (default)
   CLOUDFLARE_API_TOKEN=...
   CLOUDFLARE_ZONE_ID=...

   # …or any RFC2136 (dynamic-update) DNS server — BIND/Knot/PowerDNS/etc:
   # ACME_DNS_PROVIDER=rfc2136
   # RFC2136_NAMESERVER=ns1.your-domain.com:53
   # RFC2136_TSIG_NAME=acme-key
   # RFC2136_TSIG_SECRET=<base64>          # as in a BIND key file
   # RFC2136_TSIG_ALGORITHM=hmac-sha256    # or hmac-sha384 / hmac-sha512
   # RFC2136_ZONE=your-domain.com          # defaults to --domain
   ```
   With RFC2136, the host must be able to reach the nameserver (UDP/53, the update target), and the
   zone you update must be the one Let's Encrypt resolves publicly.
2. **Build toolchains** — provisioning bakes only the busybox `default.ext4`. To serve the languages
   above you additionally need the per-language toolchain images (`bun.ext4`, `node.ext4`,
   `rust.ext4`, `python.ext4`, `go.ext4`, `dockerfile.ext4`, plus `jkbuild-function.ext4` for
   functions and `trunk.ext4` for trunk sites) and the shared base layers (base + node + rust +
   rhypedb runtimes). Bake them with `tools/dev toolchains` / `tools/dev baselayers` and drop the
   results in `/var/jkbase/toolchains` and `/var/jkbase/baselayers`. *(Automating this in
   `provision.sh` is on the list.)*
3. **Start it:** `ssh you@your-server 'sudo systemctl start jkbase'`
4. **Point DNS:** `*.your-domain.com → your server's IP`. The wildcard covers each project's
   subdomain plus the reserved hosts `api.`, `storage.`, `console.`, `auth.`, and per-project
   `<project>.db.`.
5. **Open UDP** (only if you use [raw UDP services](#raw-udp-services)) — allow inbound **UDP
   20000–30000** (plus any admin-pinned port) at your cloud/edge firewall. jkbase opens its own host
   firewall, but can't open your provider's.
6. **Bootstrap:** `jkbase init you@example.com --api https://api.your-domain.com`

Ship a code update later with:

```bash
./tools/deploy-server.sh you@your-server.example.com    # pull, rebuild, drain, restart (host + agent)
```

`deploy-server.sh` ships the host binary and agent rootfs but **not** the build toolchain images.
When you change the build pipeline (the `jkbuild` lifecycle) or a toolchain input, rebake the
toolchains in place with:

```bash
./tools/rebake-toolchains.sh you@your-server.example.com   # [LANG …]; default = toolchains already present
```

---

## How it works

A single `jkbase-server` process is the control plane, the reverse proxy, and the orchestrator:

- **Routing & TLS.** The proxy terminates HTTPS (DNS-01 ACME for the wildcard, HTTP-01 for custom
  domains), maps the request's `Host` to a project, and forwards over a per-VM TAP/bridge. Reserved
  hosts short-circuit that: `api.` (the control API), `storage.` (object store), `auth.` (the
  per-project JWT issuer), and `<project>.db.` (the managed-database TLS reach edge). The console is
  just a normal jkbase project on `console.<domain>`. Raw UDP is routed by port, not `Host`.
- **On-demand boot & hibernation.** Idle projects (default 5 min) hibernate to a snapshot; the next
  request — HTTP *or* the first UDP datagram — wakes them in ~125ms. Over-quota projects stay parked
  until the monthly reset.
- **Per-project microVM.** Each project boots its own kernel under Firecracker + the jailer with a
  content-addressed, layered read-only rootfs (shared Wolfi base + per-language runtime, page-cached
  across tenants) plus a thin app layer. An in-VM `jkbase-agent` mounts the layers, injects secrets,
  supervises servers/functions/the database, and serves the app on port 80.
- **Storage substrate.** Storage is abstracted behind four pluggable roles — control store, lease,
  data disk, and blob store. The single-host defaults are `redb`, file locks, loop devices, and the
  local filesystem; cluster backends (etcd, Ceph RBD, S3-compatible) exist behind feature flags but
  are **not** the production path yet. The platform never assumes S3 for its *own* state — object
  storage is a product it serves, not a dependency it leans on.

### Why microVMs instead of containers?

Because "all tenants are untrusted" is a load-bearing assumption here, not a slogan. A shared kernel
is a shared fate; a hypervisor boundary is not. Every project boots its own kernel under Firecracker
+ the jailer, builds run in sealed VMs with **default-deny egress** (a build can reach pinned package
registries and nothing else — no SSRF into your control plane) and a **fetch-then-seal** model (the
host tears the network down before the offline compile), shared base layers are integrity-checked
with **dm-verity** (a poisoned shared layer can't ride into every tenant), and data disks are fenced
read-write-once so a restored or relocated VM can never scribble on a disk another VM still holds.
It's more moving parts than `docker run`. It's also a lot harder for tenant #2 to ruin tenant #1's
afternoon.

### Status

Single-host is the production configuration today. Static sites, server apps (Bun/Node/Rust/Python/Go
+ Dockerfile), functions (Rust/JS → `wasi:http`, with host-mediated outbound HTTP and own-bucket
object-store access), raw UDP services with scale-to-zero ingress, the **managed database** (RhypeDB
— co-located or dedicated, with a TLS reach-plane, automatic + on-demand backups, a per-project
jkbase-Auth JWT issuer, and default-deny end-user rules), S3-compatible object storage, secrets,
custom domains, metering/quotas, and push-to-deploy are all live and proven on prod. Still to come:
a browser-facing WebSocket gateway for the managed database, a console rules editor, and TCP for raw
L4. The next infrastructure arc is the HA / multi-node cluster layer (the substrate seams are in
place for it).

---

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option — the
standard Rust permissive combo. Use whichever suits you.

Unless you state otherwise, any contribution you intentionally submit for inclusion shall be
dual-licensed as above, with no additional terms.
