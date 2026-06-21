# jkbase

**Your own little cloud, minus the part where you pay someone else's yacht payment.**

jkbase is a self-hostable platform for shipping **static sites** and **server apps**, with **S3-compatible object storage** built in — and every project gets its own [Firecracker](https://firecracker-microvm.github.io/) microVM. Not a container. A real VM, with its own kernel, booted in ~125ms. Your neighbors can't read your secrets because they're in a different machine entirely. Blast radius: one.

You push source; the platform builds it **server-side** in a sealed, network-fenced microVM (no Docker on your laptop, no `node_modules` on your conscience), and serves it on HTTPS. Bun, Node, Rust, Python and Go all build straight from source; bring-your-own-Dockerfile is the escape hatch for when you have Opinions.

There are two ways to read this README:

- **"I want to deploy something"** → [Deploy an app](#deploy-an-app). You'll be live in four commands.
- **"I want to run the whole thing myself"** → [Self-hosting jkbase](#self-hosting-jkbase). Local box or remote server, your call.

---

## Deploy an app

### Install the CLI

```bash
cargo install --path crates/jkbase-cli   # installs the `jkbase` binary
```

By default the CLI talks to `https://api.jkbase.app`. Running your own platform? Append `--api https://api.your-domain.com` to any command (or set `JKBASE_TOKEN` + `--api`). Every command below takes `--api`.

### 1. Get an account

```bash
jkbase init you@example.com
```

Saves an API token to `~/.jkbase/credentials`. Already have a token? `jkbase login --token YOUR_TOKEN`.

> On a platform **you** just stood up, `jkbase init` bootstraps it and mints the **first admin** account — see [Self-hosting](#self-hosting-jkbase).

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

## Project configuration

Everything lives in `jkbase.toml`. The kitchen sink:

```toml
[project]
name = "my-app"

# Static site
[hosting]
public = "./dist"
spa = true

# A server, built from source — no Dockerfile, no toolchain on your machine.
# The language is auto-detected from the source (Bun, Node, Rust, Python, Go).
[servers.api]
source = "./server"
port = 8080
health_check = { path = "/health", interval = "10s", timeout = "5s" }
volumes = [{ name = "data", mount = "/app/data" }]

# Send some URLs to that server
[routes]
"/api/*" = { service = "server", name = "api" }
```

### Static sites

Point `hosting.public` at your build output and call it a day:

```toml
[hosting]
public = "./dist"
spa = true
```

### Multi-site hosting

Several static directories, one project, prefix routing — and each site can claim its own subdomain or custom domain:

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

### Servers

A server runs inside your project's microVM with its own port and optional persistent storage. By default the platform **builds it from source** — push raw code, the language is auto-detected, and the build happens server-side in a throwaway microVM:

```toml
[servers.api]
source = "./server"           # build subdir (default ".")
# language = "bun"            # optional hint; auto-detected (bun|node|rust|python|go)
port = 8080                   # required — authoritative for routing
# command = ["/opt/bun/bin/bun", "run", "start"]   # optional: override the launch argv (argv[0] absolute)
health_check = { path = "/health", interval = "10s", timeout = "5s" }
volumes = [{ name = "data", mount = "/app/data" }]
```

**Bring your own Dockerfile** (the escape hatch). The platform builds it *server-side* with [buildah](https://buildah.io/) — still no Docker on your machine — and runs the resulting image as a self-contained server. Omit `language` (the image brings its own runtime); `dockerfile` defaults to `<source>/Dockerfile`; `port` stays authoritative for routing:

```toml
[servers.api]
builder = "dockerfile"
dockerfile = "./Dockerfile"
port = 8080
```

Volumes persist across deploys. Build output does not — that's the point.

### Functions (WASI components)

Write a function in **Rust or JavaScript/TypeScript**; the platform builds it server-side
(no local toolchain) to a single **`wasi:http` component** and runs it in the project's
microVM — on request or on a cron schedule. One component ABI
(`wasi:http/incoming-handler`) across every language, executed via
[wasmtime](https://wasmtime.dev/).

```toml
[functions.hello]
source   = "./functions/hello"   # source dir; built to a wasi:http component server-side
language = "rust"                # rust | javascript (auto-detected from the source if omitted)
# schedule = "*/5 * * * *"       # optional: also (or instead) run it on a cron
```

A Rust function exports a handler via the `wasi` crate's `proxy::export!`; a JS function is
a Service-Worker-style `addEventListener('fetch', …)` handler (ComponentizeJS /
StarlingMonkey). See `templates/function-rust` and `templates/function-js`.

**What functions can do today:** handle HTTP, compute, run on a schedule, and read their
project's **secrets** — Rust via `std::env`, JS via `process.env`. Each invocation is
sandboxed and bounded (epoch + wall-clock + memory caps) and runs fresh — no state
persists between calls.

**Current limits (being lifted):** no **outbound network** yet — a function can't `fetch`
the internet or reach the object store. Outbound is the next arc: one host-mediated,
default-deny, SSRF-guarded path that delivers own-bucket object-store access *and*
allowlisted egress together. (A function can already *hold* an API token via secrets — it
just can't make the call yet.)

> The legacy WASI **preview1** path (`_start` + stdin/stdout JSON) still runs unchanged
> beside the component runtime, so older functions keep working; `runtime = "wasip1"` is a
> supported build path for Rust.

### Routing & custom domains

```toml
# Top-level — must come before any [table] header (it's a bare key on the project).
domains = ["example.com", "www.example.com"]

[routes]
"/api/*" = { service = "server", name = "api" }
```

Or attach domains imperatively with `jkbase domain add` (handy for `_acme-challenge` / TXT-verification flows). `--site <name>` binds a domain to one site within a multi-site project.

---

## Object storage (S3-compatible)

Every project gets its own **S3-compatible object store** at `https://storage.<domain>` (e.g. `storage.jkbase.app`). Auth is AWS **SigV4** with per-project access keys, so the AWS SDKs, `aws s3`, `rclone`, and friends work out of the box — pointed at your jkbase endpoint. Buckets and objects are isolated to the project that owns the key; another project's credentials can't see them.

### Issue an access key

```bash
jkbase access-key issue --label ci      # secret is shown ONCE — save it
jkbase access-key list                  # ids + labels (secrets never shown)
jkbase access-key rm AKID...            # revoke
```

`issue` prints the endpoint, the access-key id, and the secret. Point any S3 client at the endpoint with **path-style** addressing.

### What's supported

- **Buckets** — create, delete (empty), head, list.
- **Objects** — `PUT` / `GET` / `HEAD` / `DELETE`, with MD5 ETags, content-type and last-modified.
- **Multipart uploads** — initiate / upload part / complete / abort / list, for large objects.
- **Presigned URLs** — time-limited GET/PUT links, no SDK on the client.
- **Listing** — `ListObjects` v1 + v2 with prefix and pagination (continuation tokens / markers).

Per-project quotas apply (defaults: ~16 GiB of storage, 1,000,000 objects, 100 buckets) and stored bytes count toward the project's storage cap and metering alongside deployments and data disks. Object-store traffic is served straight off the platform — no extra service to stand up.

### JavaScript SDK

A zero-dependency SigV4 client (Web Crypto + `fetch`; Node, Deno, browsers) lives in [`sdk/js`](sdk/js):

```js
import { ObjectClient } from "@jkbase/objectstore";

const s3 = new ObjectClient("https://storage.jkbase.app", accessKeyId, secretAccessKey);
await s3.createBucket("uploads");
await s3.putObject("uploads", "hello.txt", "hi", "text/plain");
const body = await s3.getObject("uploads", "hello.txt");
const url  = await s3.presignedGet("uploads", "hello.txt", 900); // 15-min link
```

No AWS SDK bloat — the same SigV4 canonicalization the server verifies.

---

## Web console

The platform ships a browser console (itself a jkbase-hosted static site) at `https://console.<domain>`. Sign in with your token to manage projects without the CLI: deployments and rollback, live logs, secrets, custom domains, month-to-date usage, S3 access keys, and a **storage browser** for poking through buckets and objects (upload, download, delete, folder-style listing). The console talks to the object store over a session-scoped Bearer API — your S3 secret never touches the browser.

---

## Managing secrets

```bash
jkbase secret set DATABASE_URL=postgres://...
jkbase secret list
jkbase secret rm DATABASE_URL
```

Secrets are scoped to the project from your `jkbase.toml` (or pass `--project`). They're injected into your server's environment at deploy time and **never** touch the on-disk deployment artifact — they live only in the per-VM metadata image. Reserved vars (`PORT`/`HOME`/`HOSTNAME`/`PATH`) can't be clobbered by a secret, no matter how creatively you name it.

---

## Push-to-deploy

Deploy straight from your machine — `connect` only mints a token and adds a local
`jkbase` remote (it touches `.git/config`, nothing tracked):

```bash
jkbase repo connect          # mint a push token + add the local `jkbase` remote
git push jkbase main         # build + deploy
```

Prefer CI? Opt into a GitHub Actions workflow explicitly (it writes a *tracked*
file, so it's never a surprise side effect):

```bash
jkbase repo github           # scaffold .github/workflows/jkbase-deploy.yml — then commit it
#   set the token from `repo connect` as the JKBASE_GIT_TOKEN repo secret, and
#   every push deploys via Actions.

jkbase repo token            # re-mint the token (revokes the old one)
jkbase repo disconnect       # revoke the token + remove the remote
```

---

## CLI reference

| Command | What it does |
|---|---|
| `jkbase init <email>` | Initialize a platform + create the first admin account |
| `jkbase login --token <tok>` | Authenticate with an existing token |
| `jkbase project create <name>` | Create a project |
| `jkbase project list` | List your projects |
| `jkbase project info [name]` | Show a project's details |
| `jkbase project delete <name>` | Delete a project (and purge its data + secrets) |
| `jkbase deploy` | Build + deploy the current project |
| `jkbase rollback [--version N] [--force]` | Roll back to a previous deployment |
| `jkbase deployments` | Show deployment history |
| `jkbase logs [-f] [--service X] [-n N] [--json]` | Tail server logs (`-f` to follow) |
| `jkbase usage` | Month-to-date metered usage (CPU, bandwidth, storage) |
| `jkbase quota [--set-storage-gib N] [--set-bandwidth-gib N]` | Show / restrict per-project quotas |
| `jkbase secret set\|list\|rm` | Manage secrets |
| `jkbase access-key issue\|list\|rm` | Manage S3 object-store access keys |
| `jkbase domain add\|verify\|list\|rm` | Manage custom domains (`add --site <name>` to bind to one site) |
| `jkbase repo connect` | Mint a push token + add a local `jkbase` remote (local only) |
| `jkbase repo github` | Scaffold a GitHub Actions deploy workflow (opt-in; writes a tracked file) |
| `jkbase repo token\|disconnect` | Re-mint / revoke the git-push token |

Every command takes `--api URL` (default `https://api.jkbase.app`); the token can also come from `$JKBASE_TOKEN`.

---

## Self-hosting jkbase

So you want to run the whole circus yourself. Respect. jkbase boots real microVMs, so the host needs **KVM** — a bare-metal Linux box, or a VM/VPS with **nested virtualization** enabled. Today the host tooling is **Debian/Ubuntu only** (it's all `apt` + a Wolfi/apko image bake; the *images* are portable, the bake scripts are not).

### Local (development box)

For hacking on jkbase itself, or kicking the tires. `tools/dev` is one idempotent, pin-aware command that takes a fresh checkout to a working build+runtime box — no more stitching seven scripts together by hand and wondering which one you forgot.

**You need:** Debian/Ubuntu, a writable `/dev/kvm`, passwordless `sudo`, and `rustup`. (`tools/dev preflight` checks all of it and tells you what's missing — no guessing.)

```bash
git clone https://github.com/joeleaver/jkbase && cd jkbase

./tools/dev deps        # apt packages + rust targets + adds you to the `kvm` group
#   ↑ log out and back in once so the kvm group membership takes effect

./tools/dev all         # the heavy lifting, all cached + idempotent:
                        #   Firecracker, the 6.12 guest kernel, the bun + dockerfile
                        #   toolchains, the shared base layers. Re-run it anytime;
                        #   it only rebuilds what actually changed.

./tools/dev net         # per boot: the build bridge + firewall + cgroup (root)
./tools/dev doctor      # all green? you're good.
./tools/dev test        # optional: the on-box gauntlet — builds a real app in a
                        #   microVM and curls it for an HTTP 200. Proof, not vibes.
```

`tools/dev <stage>` runs any single stage; `--check` is a dry-run that tells you what each stage *would* do without touching anything. Stages: `preflight deps assets rust kernel toolchains baselayers net all doctor test`.

To actually **run the platform** locally and deploy to it:

```bash
sudo bash tools/setup-bridge.sh    # the runtime network bridge (jkbr0), once per boot

./target/release/jkbase-server \
  --data-dir   /var/lib/jkbase \
  --fc-dir     .firecracker \
  --agent-bin  target/x86_64-unknown-linux-musl/release/jkbase-agent \
  --build-net \                     # builds fetch deps through the fenced egress proxy
  --build-proxy-any-port 3129       # opt-in: enables `builder = "dockerfile"` builds
                                    #   (`tools/dev net` already opened 3129 in the firewall)

jkbase init you@example.com --api http://127.0.0.1:9090   # bootstrap your local platform
```

The S3 object store rides along automatically: the server binds it on `127.0.0.1` (`--storage-port`, default 9091) and the proxy routes `storage.<domain>` to it — no extra process to run.

### Remote (production server)

One command from your workstation provisions a fresh server end to end — system deps, Firecracker, a release build of jkbase, the **6.12 guest kernel** (built on the box; the layered runtime needs erofs/overlay), the systemd unit, and the isolated build network:

```bash
./tools/provision.sh you@your-server.example.com    # SSH target needs passwordless sudo
```

Then, on the server side (`provision.sh` prints these as it finishes):

1. **DNS creds (wildcard TLS via DNS-01)** — fill in `/var/jkbase/.env`. The wildcard cert
   is issued over ACME DNS-01, so jkbase needs to write a TXT record to your zone. Pick a
   provider with `ACME_DNS_PROVIDER` (default `cloudflare`):
   ```
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
2. **Build toolchains** — provisioning bakes the busybox `default.ext4`. For Bun and Dockerfile builds you also need `bun.ext4` + `dockerfile.ext4` + the shared base layers. Bake them with `apko` + `tools/dev toolchains` / `tools/dev baselayers` and drop the results in `/var/jkbase/toolchains` and `/var/jkbase/baselayers`. *(Automating this in `provision.sh` is on the list.)*
3. **Start it:** `ssh you@your-server 'sudo systemctl start jkbase'`
4. **Point DNS:** `*.your-domain.com → your server's IP` (Firecracker-per-project means each app answers on its own subdomain; the wildcard also covers `api.`, `storage.`, and `console.`).
5. **Bootstrap:** `jkbase init you@example.com --api https://api.your-domain.com`

Ship a code update later with:

```bash
./tools/deploy-server.sh you@your-server.example.com    # pull, rebuild, drain, restart
```

---

## How it works

A single `jkbase-server` process is the control plane, the reverse proxy, and the orchestrator:

- **Routing & TLS.** The proxy terminates HTTPS (DNS-01 ACME for the wildcard, HTTP-01 for custom domains), maps the request's `Host` to a project, and forwards over a per-VM TAP/bridge. Two reserved hosts short-circuit that: `api.` (the control API) and `storage.` (the object-store service). The console is just a normal jkbase project deployed on `console.<domain>`.
- **On-demand boot & hibernation.** Idle projects (default 5 min) hibernate to a snapshot; the next request wakes them in ~125ms. Over-quota projects stay parked until the monthly reset.
- **Per-project microVM.** Each project boots its own kernel under Firecracker + the jailer with a content-addressed, layered read-only rootfs (shared Wolfi base + per-language runtime, page-cached across tenants) plus a thin app layer. An in-VM `jkbase-agent` mounts the layers, injects secrets, and serves the app on port 80.
- **Storage substrate.** Storage is abstracted behind four pluggable roles — control store, lease, data disk, and blob store. The single-host defaults are `redb`, file locks, loop devices, and the local filesystem; cluster backends (etcd, Ceph RBD, S3-compatible) exist behind feature flags but are **not** the production path yet. The platform never assumes S3 for its *own* state — object storage is a product it serves, not a dependency it leans on.

### Why microVMs instead of containers?

Because "all tenants are untrusted" is a load-bearing assumption here, not a slogan. A shared kernel is a shared fate; a hypervisor boundary is not. Every project boots its own kernel under Firecracker + the jailer, builds run in sealed VMs with **default-deny egress** (a build can reach pinned package registries and nothing else — no SSRF into your control plane) and a **fetch-then-seal** model (the host tears the network down before the offline compile), shared base layers are integrity-checked with **dm-verity** (a poisoned shared layer can't ride into every tenant), and data disks are fenced read-write-once so a restored or relocated VM can never scribble on a disk another VM still holds. It's more moving parts than `docker run`. It's also a lot harder for tenant #2 to ruin tenant #1's afternoon.

### Status

Single-host is the production configuration today. Static sites, server apps (Bun/Node/Rust/Python/Go + Dockerfile), S3-compatible object storage, secrets, custom domains, metering/quotas, and push-to-deploy are all live. Functions (Rust/JS, built server-side to `wasi:http` components) are a supported deploy target too, with outbound network — object-store access + allowlisted egress — as the next capability. The next infrastructure arc is the HA / multi-node cluster layer (the substrate seams are in place for it).

---

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option — the standard Rust permissive combo. Use whichever suits you.

Unless you state otherwise, any contribution you intentionally submit for inclusion shall be dual-licensed as above, with no additional terms.
