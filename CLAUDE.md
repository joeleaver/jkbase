# CLAUDE.md

Guidance for working in this repo. See `README.md` for the user-facing product story and
`docs/build-subsystem-design.md` for the build subsystem's full design + threat model.

## What jkbase is

A self-hostable, multi-tenant platform that boots a **Firecracker microVM per project** (not a
container — a real VM with its own kernel, jailed). It hosts static sites and server apps (built
server-side from source), serves an S3-compatible object store, and terminates TLS — all from a
single `jkbase-server` process. WASM functions are wired but experimental.

**Threat model is load-bearing: ALL tenants are untrusted.** This is a Firebase-style public
offering, so isolation must hold against hostile actors — there is no trusted tier. The host must
never mount or parse a guest filesystem; builds are network-fenced; data disks are fenced
read-write-once; shared layers are dm-verity integrity-checked. When changing anything on the
host/guest boundary, assume the guest is adversarial.

## Workspace layout (Rust workspace, edition 2021/2024 per crate)

| Crate | Role |
|---|---|
| `jkbase-server` | The everything-process: HTTP control API, reverse proxy + TLS/ACME, Firecracker orchestration glue, metering/quota loops, log shipping, the build orchestrator, the object-store service, egress proxy + package mirror. Start here for runtime behavior. |
| `jkbase-control` | Control-plane logic with no infra deps: project/domain/secret/deployment store, versioning + rollback, git-push trigger auth. |
| `jkbase-orch` | Firecracker + jailer VM lifecycle (boot, drives, snapshot/restore, cgroups, seccomp). |
| `jkbase-substrate` | Vendor-neutral storage abstraction: four roles (control store, lease, data disk, blob store) with pluggable backends + capability negotiation that refuses unsafe multi-node configs. |
| `jkbase-proxy` | HTTPS reverse proxy: `Host` → project routing, TLS/ACME, on-demand wake, idle hibernation gateway. |
| `jkbase-wsproxy` | WebSocket / HTTP-upgrade relay to backend tenant VMs. |
| `jkbase-objectstore` | The S3 engine: bucket/object/multipart ops, ListV2 with delimiter folding. Unauthenticated; isolation + quota live in the server's `objectstore_service.rs` front. |
| `jkbase-agent` | In-VM init (musl static): mounts layers, injects secrets, serves HTTP on :80, dispatches to the server supervisor or the wasmtime function runtime. |
| `jkbase-common` | Shared types: `ProjectConfig` (the `jkbase.toml` schema), routing table, log framing, metered resources. |
| `jkbuild` / `jkbuild-types` | The in-VM build lifecycle + per-language buildpacks (bun, node, rust, python, go, dockerfile) and their shared types. |

`crates/jkbase-cli` is the `jkbase` binary; `sdk/js` is the zero-dep SigV4 JS client for the object
store; `sites/` holds platform-hosted apps (the `console` SPA is dogfooded as a jkbase site).

## Architecture quick map

- **Request path:** HTTPS → `jkbase-proxy` (TLS terminate, `Host` → project) → if hibernated, wake
  (~125ms) → forward over per-VM TAP/bridge → `jkbase-agent` :80 → app. Two reserved hosts
  short-circuit routing: `api.` (control API) and `storage.` (object-store service); `console.` is
  just a normally-deployed jkbase project (the dogfooded `sites/console` SPA).
- **Deploy path:** `jkbase deploy` tars source → `POST /projects/{id}/deploy` → quota check →
  server-side build in an ephemeral jailed microVM (fetch-then-seal) → build per-project metadata
  image (secrets + routes + layer list) → atomic `live` symlink swap → boot VM with layered RO
  rootfs + RWO data disk. Versioned; old deployments pruned (keep ~10); rollback flips the symlink.
- **Build:** one ephemeral build VM per server/function. Fetch phase has a TAP routed through the
  default-deny **egress proxy** (exact-host allowlist + public-IP pin, re-checked on every redirect);
  host then **drops the TAP** and the compile runs offline. Output is content-addressed `erofs`
  layers (shared Wolfi base + per-language runtime + thin app layer); the host reads blobs via
  `debugfs` + sha256, never mounts them. Optional cross-tenant package **mirror** dedups upstream
  tarballs. dm-verity protects shared layers.
- **Storage substrate:** single-host defaults are `redb` (control), flock (lease), loop devices
  (data disk), local FS (blobs). Cluster backends (etcd / Ceph RBD / S3) are feature-gated and
  **not** the production path. The control plane must never depend on S3 for its own state — S3 is
  only ever one blob-store backend, never privileged.

## HA status

Single-host is the only production configuration today. The substrate roles exist so the HA /
multi-node cluster layer can land without rewrites, but etcd/ceph/s3 backends are untested at scale.
HA is the next planned arc (tracked on Overboard, not in-repo).

## Build, test, run

```bash
cargo build --workspace                  # build everything
cargo build -p jkbase-server             # one crate
cargo test --workspace                   # unit/integration tests
cargo clippy --workspace --all-targets   # lint (CI runs this)
cargo fmt --all                          # format

# The agent is a static musl binary the server hands to each VM:
cargo build -p jkbase-agent --release --target x86_64-unknown-linux-musl

# Object-store JS SDK tests:
cd sdk/js && node --test objectstore.test.mjs
```

Toolchain is pinned in `rust-toolchain.toml`. `.github/workflows/ci.yml` is the source of truth for
what must pass.

### Anything that needs a real microVM

This box is KVM/jailer-capable with passwordless sudo — **boot-test orchestration code locally, don't
punt to the prod server.** `tools/dev` is the idempotent, pin-aware bootstrap (`preflight deps assets
rust kernel toolchains baselayers net all doctor test`; `--check` for a dry run). `tools/dev test` is
the on-box gauntlet: builds a real app in a microVM and curls it for HTTP 200. Prod target and deploy
flow are recorded in memory, not here.

## Conventions

- **Match the surrounding code.** These crates have a distinct voice — terse, high-density doc
  comments that explain *why* and call out threat-model invariants (`P0-…` style). Mirror it; don't
  add generic boilerplate.
- **Commit as you go** in small atomic commits; branch first, don't push unless asked. Co-author
  trailer is required on commits (see harness instructions).
- **Plans/tasks live on the Overboard "jkbase" board**, not in-repo TODOs or harness tasks.
- **Hardening work is reviewed adversarially.** Security-relevant changes (isolation, egress,
  quotas, SigV4, fencing) get a multi-agent adversarial review before merge — assume any new
  host/guest seam will be probed for bypasses.
- Keep the storage substrate **pluggable**; don't bake in an S3 (or any single-backend) assumption
  for control-plane state.
