# jkbase

**Your own little cloud, minus the part where you pay someone else's yacht payment.**

jkbase is a self-hostable platform for shipping **static sites**, **WASM functions**, and **server apps** — and every project gets its own [Firecracker](https://firecracker-microvm.github.io/) microVM. Not a container. A real VM, with its own kernel, booted in ~125ms. Your neighbors can't read your secrets because they're in a different machine entirely. Blast radius: one.

You push source; the platform builds it **server-side** in a sealed, network-fenced microVM (no Docker on your laptop, no `node_modules` on your conscience), and serves it on HTTPS. Bun is the lead language; bring-your-own-Dockerfile is a supported escape hatch for when you have Opinions.

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
# The language is auto-detected (Bun leads; Node/Python/Go ride the same lifecycle).
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

Several static directories, one project, prefix routing:

```toml
[sites.docs]
public = "./docs/build"
prefix = "/docs"

[sites.blog]
public = "./blog/out"
prefix = "/blog"
```

### Servers

A server runs inside your project's microVM with its own port and optional persistent storage. By default the platform **builds it from source** — push raw code, the language is auto-detected, and the build happens server-side in a throwaway microVM:

```toml
[servers.api]
source = "./server"
port = 8080
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

### WASM functions

```toml
[functions.hello]
source = "./functions/hello"   # builds to a wasi-http component, server-side
# schedule = "*/5 * * * *"      # optional: run it on a cron instead of (or as well as) on request
```

### Routing & custom domains

```toml
[routes]
"/api/*" = { service = "server", name = "api" }

domains = ["example.com", "www.example.com"]
```

Or attach domains imperatively with `jkbase domain add` (handy for `_acme-challenge` / TXT-verification flows).

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
| `jkbase rollback [--version N]` | Roll back to a previous deployment |
| `jkbase deployments` | Show deployment history |
| `jkbase logs [-f] [--service X]` | Tail server logs (`-f` to follow) |
| `jkbase usage` | Month-to-date metered usage (CPU, bandwidth, storage) |
| `jkbase quota [--set-storage-gib N]` | Show / restrict per-project quotas |
| `jkbase secret set\|list\|rm` | Manage secrets |
| `jkbase domain add\|verify\|list\|rm` | Manage custom domains |
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
  --build-net                       # builds fetch deps through the fenced egress proxy

jkbase init you@example.com --api http://127.0.0.1:9090   # bootstrap your local platform
```

### Remote (production server)

One command from your workstation provisions a fresh server end to end — system deps, Firecracker, a release build of jkbase, the **6.12 guest kernel** (built on the box; the layered runtime needs erofs/overlay), the systemd unit, and the isolated build network:

```bash
./tools/provision.sh you@your-server.example.com    # SSH target needs passwordless sudo
```

Then, on the server side (`provision.sh` prints these as it finishes):

1. **Secrets / DNS creds** — fill in `/var/jkbase/.env`:
   ```
   CLOUDFLARE_API_TOKEN=...
   CLOUDFLARE_ZONE_ID=...
   ACME_EMAIL=you@example.com
   ```
2. **Build toolchains** — provisioning bakes the busybox `default.ext4`. For Bun and Dockerfile builds you also need `bun.ext4` + `dockerfile.ext4` + the shared base layers. Bake them with `apko` + `tools/dev toolchains` / `tools/dev baselayers` and drop the results in `/var/jkbase/toolchains` and `/var/jkbase/baselayers`. *(Automating this in `provision.sh` is on the list.)*
3. **Start it:** `ssh you@your-server 'sudo systemctl start jkbase'`
4. **Point DNS:** `*.your-domain.com → your server's IP` (Firecracker-per-project means each app answers on its own subdomain).
5. **Bootstrap:** `jkbase init you@example.com --api https://api.your-domain.com`

Ship a code update later with:

```bash
./tools/deploy-server.sh you@your-server.example.com    # pull, rebuild, drain, restart
```

### Why microVMs instead of containers?

Because "all tenants are untrusted" is a load-bearing assumption here, not a slogan. A shared kernel is a shared fate; a hypervisor boundary is not. Every project boots its own kernel under Firecracker + the jailer, builds run in sealed VMs with **default-deny egress** (a build can reach pinned package registries and nothing else — no SSRF into your control plane), and data disks are fenced read-write-once so a restored or relocated VM can never scribble on a disk another VM still holds. It's more moving parts than `docker run`. It's also a lot harder for tenant #2 to ruin tenant #1's afternoon.

---

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option — the standard Rust permissive combo. Use whichever suits you.

Unless you state otherwise, any contribution you intentionally submit for inclusion shall be dual-licensed as above, with no additional terms.
