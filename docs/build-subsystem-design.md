# jkbase Build Subsystem — Design

> **Update 2026-06-05 (priority steer).** The **server/OCI path is the priority**; multi-language WASM functions are **deferred off the critical path** (so the wasip1→component-model migration no longer blocks anything near-term). Building/deploying your **own Docker container stays a first-class option but is not required** — zero-config buildpacks are the default. **Cross-tenant dedup/efficiency is a primary driver**, in two forms: build-time (package mirror) and runtime/storage (shared content-addressed base layers + per-app overlay) — which means the **server runtime becomes layered rather than flat**, so `container_supervisor.rs` mounts an overlay instead of chrooting a flat tree (this revises the "supervisor unchanged" claims in §5a/§8). Re-sequenced roadmap and reframed cards live on the Overboard `jkbase` board (tag `build`), which is the source of truth for sequencing; §5a/§8/§9/§11 below have been reconciled to this steer.

## 1. Summary

We are building `jkbuild`: a server-side, multi-language buildpack system that lets tenants `git push` (or `jkbase deploy` raw source) and have the platform — not their laptop — build it. The shape of the answer is **reuse, not reinvent**: builds run in an ephemeral Firecracker microVM orchestrated by the *existing* `jkbase-orch`, emit jkbase's *existing* on-wire artifact contract (`_functions/<name>.wasm`, `_servers/<name>/` rootfs + `ServerManifest`), and hand off to the *unchanged tail of `do_deploy`* — so deployment history, versioning, and rollback are untouched. Servers build via the Cloud Native Buildpacks (Paketo) lifecycle run headless; functions build via a jkbase-curated per-language toolchain matrix targeting the WASI 0.2 component model with `wasi:http`. The hard constraint throughout — and the source of the most expensive net-new work — is that the build phase *intentionally executes hostile, attacker-controlled code*, so the microVM boundary plus host-enforced egress control are load-bearing, not optional.

## 2. Goals & non-goals

**Goals (all four are required):**

- **(a) Kill the Dockerfile + local toolchain.** No hand-written Dockerfile, no `cargo`/`docker` on the user's machine.
- **(b) Server-side `git push`-style deploys.** The build runs on the platform.
- **(c) Multi-language functions** (JS, Python, Go, C/C++, Rust) compiled to WASM — not just Rust.
- **(d) Build caching + reproducibility + metered, billable build minutes.**

**Non-goals (explicit):**

- **Not a new isolation technology.** We do not add gVisor, a build fleet, a build daemon, or containers-as-a-boundary. The Firecracker/KVM boundary jkbase already trusts is the boundary.
- **Not BYO buildpacks.** Tenants cannot supply their own buildpacks; that reintroduces the arbitrary-`RUN` problem goal (a) exists to kill. (A gated Dockerfile *escape hatch* is retained — see §5a — but still runs only inside the VM under network-off compile.)
- **Not arbitrary system packages.** Native build-time system libraries are supported only insofar as they are pre-baked into the curated toolchain image. There is no `apt install` at build time.
- **Not S3-dependent.** No object-storage assumption for cache/artifacts/mirror; everything is content-addressed through the existing `data_dir` seams and remains pluggable.
- **Not wasip3/async-0.3.** We target stable WASI 0.2; experimental worlds are out of scope.

## 3. Current state

The current build path is **100% client-side, in the CLI** (`jkbase-cli/commands/deploy.rs`). The platform never builds — it receives pre-built artifacts.

- **Functions:** `build_function()` shells out to `cargo build --target wasm32-wasip1 --release` for a Rust crate, or ships a prebuilt `.wasm`. No other language is supported.
- **Servers:** `build_server()` shells out to `docker build` against a **user-authored Dockerfile**, then `docker create` + exports the rootfs tarball + a `ServerManifest { port, cmd, env, working_dir, health_check, volumes }`.
- **Wire contract:** wasm blobs + server rootfs tarballs + manifests + route/site/domain/schedule JSON are gz-tarballed and POSTed to `POST /projects/{id}/deploy` (512 MiB body limit, `deploy_locks` serialization, `QuotaExceeded`→402).
- **Deploy tail (`do_deploy`, reused verbatim):** storage-quota gate → stage into `deployments/v{N}` → atomic `live` symlink swap → `save_deployment` → `prune_deployments` (keeps newest 10) → `deploy_callback`.
- **Rollback (`do_rollback`):** re-points `live` at a stored `v{N}` directory of *already-built artifacts* and rebuilds the content image. It does **not** rebuild from source — important for §6 and §8.
- **Function runtime (`jkbase-agent/function_runtime.rs`):** wasip1 **command modules** — `_start` + stdin/stdout JSON. `load_all_from_dir` loads them.
- **Server runtime (`container_supervisor.rs`):** chroots into the flat rootfs tree and runs the `ServerManifest` cmd. Unchanged by this work.
- **Isolation primitives that do NOT yet exist in `jkbase-orch`:** `VmInstance::start` wires only drives/TAP/vsock. `rootfs.rs` builds images via `sudo` loopback-mount `mkfs`/`mount` scripts — there is **no** jailer, no cgroup-v2 limits, no seccomp, no non-root runner, no copy-on-write/overlay path, no wall-clock timeout. Runtime gets away with this because it runs pre-built artifacts; a build VM runs attacker code, so these must be built. **This is net-new `orch` work the design counts explicitly (Phase B0), not hidden inside "reuse".**

## 4. Architecture

End-to-end: a trigger normalizes to an **immutable source snapshot + build request**, which boots **one throwaway hardened build microVM**, which emits jkbase's existing artifacts to a host-readable **output drive**, which the control plane feeds into the **unchanged `do_deploy` tail**.

### Where builds run — the decision

**One ephemeral Firecracker microVM per build, orchestrated by `jkbase-orch`, destroyed on completion or timeout. Never the host, never a container, never a shared/multi-tenant builder, never two tenants in one sandbox.**

Justification: the build phase executes attacker-controlled code by design (`build.rs`, `setup.py`, npm hooks, CNB `bin/build`, buildpack logic). The *only* boundary jkbase already trusts against hostile code is the Firecracker/KVM hardware boundary used for runtime. Reusing it means **no new isolation technology and no new trust assumption** — a build escapes only via a hypervisor 0-day, the platform-wide risk we already accept. Containers are a resource-control mechanism, not a security boundary, and are rejected for the *outer* boundary.

**Critical correction from red-team (feasibility P0-1, P2-5):** "reuse `orch`" is only true for the hypervisor boundary. The in-guest hardening (jailer, cgroup-v2 `pids`/`memory.max`/CPU weight/disk quota, seccomp, non-root runner, wall-clock timeout) and the **CoW/overlay rootfs** are *absent today* and are an explicit, separately-estimated deliverable (**Phase B0**). The toolchain image (1–2 GB for Rust/LLVM) is a **read-only backing drive + per-build writable overlay drive** (Firecracker supports multiple drives), never re-`mkfs`'d per build.

**Artifact transport (feasibility P2-7):** bulk artifacts are written by the guest to a **shared writable output drive** that the host reads *after* VM teardown — *not* streamed over vsock. vsock carries logs only. Critically (threat-model P0-3), the host must **never mount/parse a guest-written filesystem with the host kernel**. The output drive is returned as a content-addressed stream the host validates, or unpacked only inside a throwaway VM — the same rule the design already applies to server-rootfs flattening now applies to the cache and artifact return path too.

```
TRIGGER (one funnel: POST /projects/{id}/build)
  ├─ (P1) jkbase deploy → tar source (no .git/node_modules/target) → POST
  ├─ (P4) git push jkbase main → smart-HTTP git-receive-pack → archive tip → funnel
  └─ (P4) connected repo webhook → shallow-clone INSIDE build VM → funnel
        │  reuses: deploy_locks · 512 MiB body limit · QuotaExceeded→402
        ▼
PRE-BUILD GATE (control): debit estimated minimum build-minutes; 402 if over cap
        ▼
┌──────────────────────── jkbase-orch::build_vm ────────────────────────────┐
│  Ephemeral Firecracker microVM  (jailer · seccomp · non-root runner)       │
│  ┌─ RO backing drive: curated toolchain image (content-addressed)          │
│  ├─ writable OVERLAY drive (scratch, CoW)                                   │
│  ├─ per-PROJECT writable cache drive (create_data_disk; quota-counted)     │
│  ├─ writable OUTPUT drive (host reads post-teardown)                        │
│  ├─ RO source mount (immutable snapshot)                                    │
│  ├─ cgroup-v2: pids · memory.max · cpu.weight · disk quota                  │
│  ├─ hard wall-clock timeout → kill VM, bill minutes consumed                │
│  └─ vsock: LOG stream only                                                  │
│                                                                            │
│   FETCH phase  ──TAP──▶ host egress proxy (default-deny allowlist + mirror) │
│                          resolve→pin-IP→denylist RFC1918/loopback/metadata  │
│   ── HOST tears down TAP / drops route ──                                   │
│   SEAL: COMPILE phase runs network-OFF (host-enforced, no guest re-enable)  │
│                                                                            │
│   SERVER path → CNB (Paketo) lifecycle headless → OCI-layout → flatten →    │
│                 ServerManifest translate                                    │
│   FUNCTION path → per-language toolchain → one wasi:http component (.wasm)   │
└────────────────────────────────────────────────────────────────────────────┘
        │  emits jkbase's EXISTING artifacts to OUTPUT drive
        ▼
BUILD JOB resource (GET /projects/{id}/builds/{build_id}): queued|building|live|failed
  + captured log tail + per-phase timings + cache_hit  (persisted, NOT log_shipper)
        │  on SUCCESS only
        ▼
┌──────────── UNCHANGED do_deploy TAIL ────────────┐
│ storage-quota gate → stage deployments/v{N}      │
│ → atomic `live` symlink swap → save_deployment   │
│ → prune_deployments → deploy_callback            │
└──────────────────────────────────────────────────┘
        │
        ▼   (old `live` stays serving until swap; rollback re-points `live`,
RUNTIME VM (unchanged)   never rebuilds from source — §6/§8)
```

**Builds never block serving (completeness P0-1).** Builds are asynchronous background jobs decoupled from the `live` symlink. The old version keeps serving; the atomic swap happens only on build success. This preserves the scale-to-zero UX contract: a scaled-to-zero function still resumes from its memory snapshot in ms — it is never put behind a cold toolchain boot. Build state (`queued/building/live/failed`) is a first-class field distinct from runtime state.

## 5. The buildpack model

Two genuinely different problems get two builders, sharing only the VM + egress + metering.

### 5a. Server / OCI path (kill the Dockerfile)

**Cloud Native Buildpacks (Paketo) lifecycle, run headless inside the build VM** — no `pack`, no Docker daemon, no buildah for the common path:

1. `detector` picks Node/Python/Go/Java/.NET/Ruby from source.
2. `builder` compiles.
3. `exporter` writes **OCI-layout on disk** (`-layout`, no registry push).
4. **Keep the layers — do *not* flatten.** Emit the image as **content-addressed read-only layer images** (erofs/squashfs, in the spirit of composefs): shared **base/run-image layers** (platform-built, dedup'd across every tenant on that runtime) + a thin **per-app layer**. Flattening to a single tree would defeat the runtime dedup in §8.
5. **Translate** the OCI config → `ServerManifest`: `Entrypoint`+`Cmd`→`cmd`, `Env`→`env`, `WorkingDir`→`working_dir`, exposed port→`port`, healthcheck→`health_check`.

No run-image extension (avoids the kaniko `extend` phase). **CNB's own "untrusted builder" mode is explicitly NOT our boundary — the VM is.** **`container_supervisor.rs` changes** (revises the earlier "unchanged" claim): instead of chrooting a flat tree it **mounts an overlay — RO base + app layers as lowerdirs, a writable scratch upperdir — inside the *runtime* VM and `pivot_root`s**. The overlay is composed **guest-side** so the host never mounts the untrusted app layer; see §8 (dedup) and §9 (P0-3).

**Escape hatch (gated):** when detection fails, heuristic Dockerfile synthesis + rootless buildah inside the *same* VM, and a `builder = "dockerfile"` option for a user-supplied Dockerfile. Red-team feasibility/threat-model: this is *safe* under the VM but means goal (a) is "no *required* Dockerfile," not "Dockerfiles impossible." The escape hatch runs under the **same network-off-compile** rule, and its final unpack **never** touches the host kernel (threat-model P0-3, P2-9). It is Phase-B+, not a day-one co-equal option.

### 5b. Function / WASM path (multi-language)

**A jkbase-curated per-language toolchain matrix — NOT CNB.** CNB targets OCI images, not a single `.wasm`; bending it to wasm is a hack pile. A small in-VM **function-builder** dispatches on declared/detected language to a pinned, digest-sealed toolchain, each emitting **one `wasi:http` component**:

| Language | Toolchain |
|---|---|
| Rust | `cargo-component` (`wasm32-wasip2`) |
| JS/TS | ComponentizeJS / StarlingMonkey (server-side esbuild/swc bundle first; Javy as optional tiny/fast sync-only mode) |
| Python | `componentize-py` |
| Go | TinyGo (`wit-bindgen`) |
| C/C++ | wasi-sdk |

For pure JS/TS we borrow the Deno/Val Town pattern: a light server-side bundle → ComponentizeJS, far cheaper than an OCI build.

## 6. Function runtime contract

**Decision: migrate `function_runtime.rs` from wasip1 command-modules (`_start` + stdin/stdout JSON) to the WASI 0.2 component model with the `wasi:http/proxy` world (`wasi:http/incoming-handler@0.2.0`).**

**Justification.** The *entire* multi-language frontier (ComponentizeJS/StarlingMonkey, componentize-py, cargo-component, TinyGo wit-bindgen) targets WASI 0.2. Staying on wasip1 strands JS on Javy's no-async/no-`fetch` contract, leaves Python with no clean story, and forces a bespoke calling convention per language — exactly the hack pile goal (c) must avoid. One WIT world becomes the universal function ABI: every language exports the same handler; host integration is written **once** via `wasmtime-wasi-http`'s `WasiHttpView`/`WasiHttpCtx`; native outbound `fetch` + a real async event loop come for free. Keep `consume_fuel` + per-invocation fuel for metering. Avoid wasip3/async-0.3 (experimental, unstable through late 2025).

**This is the single biggest risk in the whole effort** — it rewrites the hottest, most-tested request path, and the componentizer tooling is younger than `cargo build --target wasm32-wasip1`. De-risking is sequencing and additivity (see §11): the new path is **purely additive** because Wasmtime still executes legacy wasip1 core modules. `load_all_from_dir` detects component-vs-core-module and dispatches to the new `wasi:http` path or the legacy `_start` path. Both run in production indefinitely.

**Migration for already-deployed functions (completeness P0-2, P1-6).** Two distinct facts must hold:

1. **Rollback safety:** built artifacts are copied into `deployments/v{N}` and are **fully decoupled from the evictable build cache**. Rollback re-points `live` at stored artifacts and **never triggers a rebuild**. Every existing deployed Rust function (a wasip1 blob) keeps working, and rollback can target pre-migration versions.
2. **Tenant *source* migration is real and must not be hand-waved.** Dual-*run* keeps old *binaries* working, but a tenant who edits and redeploys their Rust source must now build to a component against `wasi:http` — a breaking source-level API change. **We commit to building the legacy path, not just running pre-built blobs:** `runtime = "wasip1"` is a *supported build path* for Rust indefinitely (so old-style `_start`+JSON source still builds), **and** we ship a thin `wasi:http` Rust shim so first-party + tenant functions can migrate near-mechanically. Languages are gated in one at a time; each is revertible.

## 7. Language support matrix & rollout order

1. **Component + `wasi:http` runtime** in `jkbase-agent` (prerequisite for all functions below).
2. **Rust → component** (`cargo-component`, `wasm32-wasip2`) — migrate the baseline, prove the ABI on **first-party canary functions we control** before any tenant exposure.
3. **JS/TS → ComponentizeJS/StarlingMonkey** — biggest user unlock, real async DX. (Javy optional sync-only fast mode.)
4. **Python → componentize-py** — second-biggest audience; deps frozen at build = good hermeticity.
5. **TinyGo** — ship with loud docs on `GOMAXPROCS=1` cooperative scheduler + limited reflection.
6. **C/C++ → wasi-sdk** — near-free once toolchains are in the image.

**Servers** ride CNB/Paketo (Node/Python/Go/Java/.NET/Ruby) from day one of the server path. **Skipped:** AssemblyScript (WASI removed). **Deferred:** MoonBit/Grain (immature).

## 8. Caching, reproducibility & build-minute metering

**Cross-tenant rule (absolute): no tenant ever *writes* a cache entry another tenant *reads*.**

**Two tiers:**

- **Writable cache — per-project only.** A per-project cache disk (`{data_dir}/buildcache/{project_id}/`, via `create_data_disk`) holds Cargo/npm/pip dirs, the CNB layer cache, and the Go build cache; mounted only into that project's build VM; counts against the project storage quota.
- **Read-only shared base — immutable, content-addressed.** Toolchain rootfs images, Paketo base/run-images, and the buildpack roster are platform-built, addressed by digest, mounted read-only. A tampered layer has a different hash and simply isn't the cached one — poisoning is structurally impossible.

**The package mirror is the dedup point** — upstream packages cached once, verified against lockfile hashes — giving sharing's storage win with zero writable shared surface.

**Runtime/storage dedup — the second, distinct win.** The mirror dedups *build inputs*; separately, the *runtime rootfs* dedups *base layers*. The CNB build emits **content-addressed read-only layer images** (erofs/squashfs, à la composefs); each shared base/run-image layer is stored **once** and attached **read-only to every runtime microVM** that needs it, so the host page cache for that backing file is shared across all of them — a storage win **and** a cold-start win under scale-to-zero (N Node apps share one Node-runtime layer). The per-app layer stacks on top. **Composition is guest-side:** the host attaches the trusted base layers + the untrusted app layer as block devices and the *guest* kernel does the `overlay` mount + `pivot_root` — the host never mounts the untrusted app fs (§9, P0-3). This also retires today's `rootfs.rs` `sudo` loopback-`mkfs` of a full image per deploy. Base images are pinned by content hash and integrity-checked (fs-verity / dm-verity), since a swapped base would poison every tenant on that runtime.

**Cache-key safety (threat-model P0-2 — corrected).** The naive key `hash(toolchain, lockfile, buildpack, source-tree)` is attacker-controllable: a tenant could pre-seed a key with a poisoned compiled artifact (a backdoored `.rlib`, a tampered npm entry, a poisoned CNB layer) that a later legitimate build of the *same* project consumes, smuggling a non-reproducible binary past the buildpack. **Fix:** the writable cache stores **only content-addressed, independently-verifiable artifacts** — package tarballs verified against lockfile digests via the mirror — **never opaque compiled output**, unless that output is itself keyed by and re-validated against a digest the platform computed. Any compiled-output cache entry is invalidated if the toolchain or any input digest fails re-verification.

**Reproducibility (scoped honestly — completeness P2-7).** We claim bitwise reproducibility **only for the sealed-compile phase given a fixed lockfile + toolchain digest**, *not* end-to-end through a mutable cache. Mechanism: pin everything by digest; **fetch-then-seal** (resolve deps through the mirror, then compile with network OFF) with vendored/`--offline` builds; apko/melange for jkbase-owned base/runtime layers (bitwise-reproducible, SBOM-emitting). Native build-time libs are pre-baked into the toolchain image (network-off compile cannot fetch them).

**Build-minute metering reuses `metering.rs` — with a correction for short bursts (threat-model P1-4, feasibility P2-6).** The build VM has a pid + TAP, so `read_cpu_jiffies`/`read_tap_bytes`/`SamplerState` apply. But the 60 s `metering_loop` tick would let a build killed at 59 s escape metering entirely (free crypto-mining via sub-tick resubmits). **Fix:** meter build VMs **on exit** — read final cgroup `cpu.stat`/accumulated jiffies at teardown (we own the lifecycle) — and bill the floor of wall-clock too, not only on the periodic tick. The **pre-build 402 gate debits an estimated minimum *before* launch**, so a tenant already at quota can't trigger launch-storms.

**Provenance & observability.** `DeploymentMeta` records `{builder_digest, cache_key, source_commit, cache_hit, build_duration_breakdown}` (per-phase timings — feasibility/completeness P2-9). Add `build_seconds` to `UsageBucket` + `add_usage` (or sibling `add_build_usage`); surface in `UsageResponse`/`QuotaResponse`; add `build_seconds_per_month` to `QuotaLimits`. Expose the cap and per-phase cost up front in the console — explicitly avoiding Vercel's surprise-bill reputation.

## 9. Security model (hostile tenants, no trusted tier)

- **Isolation.** One ephemeral Firecracker VM per build (KVM/hardware boundary), CoW overlay destroyed on exit, **non-root + seccomp + jailer** inside, cgroup-v2 `pids`/`memory.max`/CPU + disk quota (fork-bomb/OOM/disk-fill defense), hard wall-clock timeout → kill VM. Never two tenants in one sandbox. **These primitives are net-new in `orch` (Phase B0) — see §3.**
- **Host never parses guest filesystems (threat-model P0-3).** Cache + artifact return is a host-validated content-addressed stream or unpacked only in a throwaway VM. The host kernel never mounts a guest-written ext4/overlay.
- **Runtime overlay is composed guest-side (P0-3, runtime extension).** The layered runtime rootfs (§8) stacks trusted shared base layers (RO) under an untrusted per-app layer. The host attaches *all* layers as block devices, but the **guest** kernel performs the `overlay` mount + `pivot_root` — so the host never mounts the hostile app filesystem. A malicious app image can only attack the guest's own kernel (already the tenant's blast radius). Trusted base images are pinned by content hash + fs-verity/dm-verity (a poisoned base would hit every tenant on that runtime).
- **Egress proxy is the hard part (threat-model P0-1 — the proxy is itself the SSRF/exfil engine).** Because the mirror terminates TLS to inspect/cache, it holds a CA the build VM trusts and fetches on the build's behalf — and CDN-fronted registries (npm→Fastly/Cloudflare, PyPI→Fastly) share IPs/domains with attacker-controllable content, with tarball-URL fields and redirects pointing at attacker-influenced hosts. The proxy therefore **must**: (a) resolve the allowlisted hostname *itself* and pin egress to the resolved **public** IP, re-checking the RFC1918/loopback/cloud-metadata denylist **after resolution and after every redirect** (defeats DNS-rebind/TOCTOU); (b) **refuse to follow redirects off the allowlist**; (c) **only ever serve from the mirror's already-verified content, never proxy-pass live**. "Allowlisted hostname" and "safe destination IP" are **independent checks, both required.** Allowlist = crates.io, registry.npmjs.org, PyPI, plus github.com/gitlab.com for git deps (completeness P1-5).
- **Seal is host-enforced (threat-model P1-6).** "Network OFF for compile" is the **host removing the TAP device / dropping the route** before signaling the compile phase. The guest has no API to bring it back; an in-VM `unshare` is not the boundary.
- **Scripts are noise-reduction, not a boundary (threat-model P1-5).** `ignore-scripts=true` + `.npmrc` kills the most-abused npm `postinstall` vector but does nothing for `pip`/`setup.py`, `build.rs`, `cgo`/`//go:generate`, or CNB `bin/build`. We document plainly: **build-time code *will* run hostile and nothing inside the VM is trusted.** The boundary is the VM + host-enforced network-off compile, full stop.
- **Buildpack supply chain.** Curated, pinned-by-digest, cosign/Sigstore-verified roster only. **No BYO buildpacks.** Emit SBOM + SLSA provenance — which prove *origin, not safety*, and complement, never replace, the VM boundary.
- **Transitive-dependency worms (threat-model P2-7).** cosign verifies the buildpack's origin, not the packages it pulls. A fresh Shai-Hulud-class malicious version runs at build before any quarantine exists. **Stated mitigation is the network-off-compile invariant, not quarantine:** even if the worm executes at build, with egress torn down it cannot self-propagate or exfiltrate. Lockfile-digest pinning through the mirror bounds *which* versions run.
- **Secrets (threat-model P1-8, P2-8).** Injected at the **proxy boundary** as per-build, per-tenant, short-lived tokens — real creds never enter the build VM or land in image layers. **Product limit stated explicitly:** private-dependency support is limited to protocols the MITM proxy can intercept (private npm scope, private crate registry, https git). `git+ssh` / protocols the proxy can't intercept are **unsupported**, not silently leaked.
- **git-push seam (completeness P2-8).** Tokens are **per-project**; a push to project X with a Y-scoped token 403s. `git-receive-pack` enforces a **hard pack-size + object-count limit during receive** (streamed, so the 512 MiB body limit doesn't apply cleanly) → pack-bomb/refs-explosion DoS defense. Webhooks use **HMAC + timestamp anti-replay** with rotatable secrets.

**Residual risks (stated honestly):**
1. A Firecracker/KVM 0-day escapes everything — mitigated only by patch cadence + per-build blast-radius.
2. An allowlisted upstream ships a malicious version running at build — *spread/exfil* defanged by network-off compile; *execution* not eliminated.
3. The egress proxy/mirror is a new high-value target and a correctness dependency (outage → build failures).
4. Pathological-but-legal builds burn legit minutes — billed, not blocked.

## 10. Changes per crate

- **jkbase-cli (`deploy.rs`):** delete `build_function`/`build_server` local shellouts; `deploy` tars *source* (excludes `.git`/`node_modules`/`target`) and POSTs `/build`; **poll/stream the build-job resource** (not the runtime log channel); add connected-repo config + a `git push` helper.
- **jkbase-control (`api.rs`/`store.rs`):** add `POST /projects/{id}/build` funnel → orchestrate build VM → call `do_deploy` tail (reuse `deploy_locks` / 512 MiB / 402); add **`GET /projects/{id}/builds/{build_id}`** build-job resource (terminal status + captured log tail, persisted independent of `log_shipper`; detect/build stderr user-visible, proxy/secret-injection redacted); phase-4 git smart-HTTP (`/git/{id}/...`, per-project token auth, pack limits) + webhook (`/projects/{id}/hooks/push`, HMAC+anti-replay); `build_seconds` on `UsageBucket`/`QuotaLimits` + **pre-build estimated-minimum 402 gate**; `{builder_digest, cache_key, source_commit, cache_hit, build_duration_breakdown}` on `DeploymentMeta`; per-target build scheduling + atomic-vs-partial deploy policy (see §12).
- **jkbase-orch (`rootfs.rs`/`vm.rs`/`firecracker.rs`, new `build_vm.rs`):** **Phase B0 hardening** — jailer + cgroup-v2 (`pids`/`memory.max`/CPU/disk quota) + seccomp + non-root runner + wall-clock timeout; **RO backing toolchain drive + writable overlay** (no per-build `mkfs` of a multi-GB image); per-project cache drive + writable **output drive** (host reads post-teardown, never host-mounts guest fs); RO source mount; TAP→egress proxy with host-side teardown for seal; vsock for **logs only**; destroy-on-exit.
- **jkbase-agent (`function_runtime.rs`, new build-runner):** component + `wasmtime-wasi-http` linker **alongside** the legacy wasip1 `_start` path (dispatch in `load_all_from_dir`); new in-VM build-runner — CNB lifecycle for servers (OCI-layout → **content-addressed layer images**, no flatten, + `ServerManifest` translate, in-VM), per-language wasm dispatch for functions. `container_supervisor.rs` **gains a guest-side overlay mount + `pivot_root`** over shared RO base layers (§5a/§8).
- **jkbase-server (`metering.rs`/`main.rs`):** meter the build VM **on exit** (final cgroup `cpu.stat`/jiffies + wall-clock floor) into `build_seconds`; run the egress proxy + package mirror as host services; enforce the wall-clock timeout.
- **jkbase-common (`config.rs`):** activate the unused `FunctionConfig.runtime`; replace `ServerConfig.dockerfile: String` with optional `builder`/`language` (auto-detect when omitted); add a `[build]` block.

**New `jkbase.toml` surface:**

```toml
[functions.api]
source   = "./functions/api"   # source dir, not a .wasm
language = "javascript"         # rust|javascript|python|tinygo|cpp (auto-detect if omitted)
runtime  = "wasi-http"          # default; "wasip1" = legacy (still a supported BUILD path for Rust)

[servers.web]
source   = "./server"           # replaces `dockerfile = "..."`
builder  = "auto"               # auto (CNB detect) | paketo/node | dockerfile (gated escape hatch)
[servers.web.health_check]
path = "/healthz"

[build]
minutes_cap   = 200             # per-project build-minute quota (402 over-cap)
allow_network = false           # fetch-then-seal default (compile is host-enforced network-off)
[build.repo]                    # phase 4 connected-repo
url    = "github.com/acme/app"
branch = "main"
```

## 11. Phased roadmap

**Sequencing is owned by the Overboard `jkbase` board** (cards tagged `build`) — the mutable source of truth; it supersedes any order written here, and each card carries its own per-phase demo. Under the 2026-06-05 steer the order is **server-first**:

1. **Foundations** — harden `orch` for hostile build VMs (jailer, cgroup-v2, seccomp, non-root runner, wall-clock timeout) + multi-drive build rootfs (RO backing + CoW overlay + output drive).
2. **Build-pipeline core** — `POST /build` funnel + build-job resource, default-deny egress proxy, host-enforced fetch-then-seal, build-minute metering + pre-build 402 gate.
3. **Server vertical (lead)** — CNB buildpacks default (Dockerfile/BYO kept as fallback) → **layered, content-addressed** artifact; **layered runtime rootfs** (guest-side overlay over shared base layers — the runtime-dedup enabler).
4. **Package mirror** — cross-tenant dependency dedup.
5. **`git push` + webhook triggers.**
6. **Deferred (functions, off the critical path)** — `wasi:http` component runner → Rust function built server-side → multi-language toolchains.

The riskiest item — the wasip1→component-model migration — now sits in (6), blocking nothing near-term.

**Roadmap fit:** this *is* Phase-5 ops maturity — it reuses metering/quota/log-shipping/rollback wholesale and adds build minutes as a first-class metered resource. **Pluggable storage stays honored:** the per-project cache disk, build artifacts, and the package mirror are content-addressed blobs addressed through existing `data_dir` seams — a future pluggable backend hosts them without changing the build contract. No S3 assumption.

## 12. Open questions & risks

- **Monorepo / multi-target builds (completeness P1-4) — must decide before B2.** N functions in M languages + servers per repo: one shared-toolchain build VM per project build (reusing the warm toolchain across targets) is the intended answer, but CNB `detector` assumes one app per source root. **Decide:** per-target sub-detection within one VM, and **atomic-vs-partial deploy policy** (today `do_deploy` is all-or-nothing). Validate cheaply with a 2-function + 1-server fixture repo in B1/B2.
- **Cold-build budget vs DX.** Even decoupled from serving, a cold `cargo-component` build is minutes. **Validate cheaply:** measure cold vs warm-cache build time for the Rust slice in B1; if cold is unacceptable, pre-warm a per-language toolchain overlay snapshot (reuse the scale-to-zero snapshot machinery).
- **Compiled-output cache safety vs hit rate (§8).** Restricting the writable cache to verifiable package tarballs (not compiled output) is safe but may tank hit rate for big Rust/LLVM builds. **Validate:** measure hit rate with package-only caching in B1 before deciding whether a platform-keyed compiled-output cache is worth its verification cost.
- **Egress proxy correctness is a single point of failure.** A bug that follows one off-allowlist redirect is a full SSRF into the control plane. **Validate cheaply:** a red-team fixture set (DNS-rebind, redirect-to-metadata, CDN-shared-IP) run in CI against the proxy before B1 ships to any tenant.
- **componentizer maturity.** ComponentizeJS/componentize-py/TinyGo are younger than `cargo build`. **Validate:** gate each language behind a canary + revert switch; do not GA a language until its toolchain digest is pinned and a non-trivial example passes.
- **Native-lib pre-baking scope.** "Pre-bake into the toolchain image" is unbounded (every crate's `build.rs` wants different system libs). **Decide:** a documented, finite supported set (openssl, pkg-config, zlib, …); everything else is explicitly unsupported and surfaced as a clear build error, not a mysterious link failure.

## 13. Proposed Overboard cards

- **Harden orch for hostile build VMs** — add jailer, cgroup-v2 (pids/memory/CPU/disk), seccomp, non-root runner, and wall-clock timeout to `jkbase-orch`.
- **CoW build rootfs + multi-drive layout** — RO toolchain backing drive + writable overlay + cache + output drives, no per-build `mkfs`.
- **Default-deny egress proxy with IP-pinning + redirect/DNS-rebind defense** — allowlist hostname *and* re-checked public-IP, no off-allowlist redirects, serve-from-mirror-only.
- **Host-enforced fetch-then-seal** — host tears down TAP/route before the compile phase; verify no guest re-enable path.
- **`POST /build` funnel + build-job resource** — source-snapshot intake reusing deploy_locks/402, plus `GET /builds/{id}` status + persisted log tail.
- **Rust-function proof slice (B1)** — source-only `jkbase deploy` → component → `wasi:http`, built in-VM, metered, deployed via the unchanged `do_deploy` tail.
- **`wasi:http` component runner (additive)** — `wasmtime-wasi-http` path in `function_runtime.rs` dispatched alongside the legacy wasip1 `_start` path in `load_all_from_dir`.
- **Build-minute metering + pre-build 402 gate** — meter build VMs on exit (cgroup cpu.stat + wall-clock floor), add `build_seconds` to usage/quota, debit estimated minimum before launch.
- **CNB/Paketo server builds (kill the Dockerfile)** — headless lifecycle → OCI-layout → **content-addressed layer images** (no flatten) → `ServerManifest` translate; runtime mounts a guest-side overlay over shared base layers.
- **Package mirror with lockfile-digest verification** — content-addressed upstream cache, the cross-tenant dedup point; cache stores verified tarballs, never opaque compiled output.
- **Multi-language function toolchains** — JS (ComponentizeJS), Python (componentize-py), TinyGo, C/C++ (wasi-sdk), each gated + revertible behind a pinned digest.
- **git push + webhook triggers** — smart-HTTP `git-receive-pack` (per-project token, pack-size/object limits) + connected-repo webhook (HMAC + anti-replay).
