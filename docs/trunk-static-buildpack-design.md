# Design note: Trunk buildpack + static build targets

Status: **DRAFT — needs sign-off on the two public-API proposals below.**
Branch: `feat/trunk-buildpack`.
Author: prepared for Joe's review.

## Goal

Build Rust/WASM frontends (Trunk) **server-side**, the same way the platform
already builds bun/node/rust/python/go servers and wasm functions — so a deploy
ships raw source instead of a pre-built `dist/`. The produced static bundle is
served through the existing `[hosting]`/`[sites]` static-serving path.

```toml
# jkbase.toml — the frontend is BUILT by the platform, not committed pre-built.
[sites.app]
source = "./web"     # a Rust/WASM crate with a Trunk.toml
build  = "trunk"     # platform runs `trunk build --release` server-side
```

## What landed (self-contained, low-risk)

These are drop-ins that don't change any public type or wire contract:

1. **`crates/jkbuild/src/buildpacks/trunk.rs`** — a `Buildpack` modeled on the
   node/rust tree-shippers.
   - `detect`: confidence **95** when both `Trunk.toml` **and** `Cargo.toml` are
     present (zero-config opt-in); `Fail` on a foreign `language` hint;
     `language = "trunk"` is authoritative (100). It deliberately does **not**
     claim a bare `Cargo.toml` — that's a server crate.
   - `fetch` (network up): `cargo fetch` (`--locked` with a `Cargo.lock`) over the
     sparse registry/git hosts, then warms trunk's version-matched
     `wasm-bindgen`/`wasm-opt` into the persistent cache drive (`trunk tools
     install`; github is allow-listed). `CARGO_HOME` + the trunk/XDG cache live on
     the cache drive.
   - `compile` (offline): `trunk build --release --offline`, then the produced
     `dist/` becomes a single **launch** layer with **no processes** (a static
     artifact, not a server).
   - Registered ahead of `rust` in the roster; `rust` stands down when a
     `Trunk.toml` is present (mirrors node → bun).

2. **Toolchain image** — `images/apko/build-trunk.apko.yaml` +
   `INJECT_TRUNK` in `tools/build-image.sh` + a `trunk` asset in
   `tools/install-image-tools.sh`. Bakes a pinned Rust toolchain with the
   `wasm32-unknown-unknown` std (injected, same reasoning as the function
   toolchain's `INJECT_RUST_WASIP2`), `binaryen` (`wasm-opt`), and the `trunk`
   CLI. `select_toolchain` already keys a non-function target on language, so a
   trunk static target picks `trunk.ext4` first.

## What's a PROPOSAL (cross-crate, needs your call)

The trunk buildpack alone produces a launch tree, but nothing in the build
pipeline knew how to turn that into **served static content** — there was no
static build-artifact target. Today static content is only ever *copied from
committed source* by `assemble_sites`; servers export an erofs layer + manifest
and functions export a `.wasm`. Two decisions were required:

### Proposal 1 — `TargetKind::Static`

`crates/jkbase-control/src/store.rs` gains a third `TargetKind` variant
(`Function`, `Server`, **`Static`**). This is the cleanest way to fan a built
site out as its own build VM and route its output, reusing the entire existing
per-target orchestration (seeding, status, metering, toolchain selection).

It is a small, additive enum change, but `TargetKind` is `Serialize`/`Deserialize`
and persisted in the build record (redb), so it's effectively public surface —
hence flagging it. No migration is needed (it's an added variant, never written
by old records).

### Proposal 2 — the config shape: `build` on `[sites.*]`

I extended `[sites.<name>]` rather than inventing a `[frontends.*]` block:

```toml
[sites.app]
source = "./web"
build  = "trunk"
```

Rationale (the least-surprising shape):
- A built site **is a site** — it serves at a prefix/domain exactly like a
  committed site, and shares the same routing/SPA/`_sites.json` plumbing. A
  separate `[frontends.*]` block would duplicate all of that and force a user to
  learn a second concept that maps 1:1 onto sites.
- `public` becomes optional and is ignored for a built site (the build output
  fills the slot); `source` is the build input; `build` selects the strategy
  (only `"trunk"` today, but it's an extensible enum — `SiteBuild`).
- A committed site (no `build`) is **completely unchanged**.

If you'd rather have `[frontends.*]`, the orchestrator wiring is isolated to
`enumerate_targets` + `collect_static_site` + the `SiteConfig` fields and is
cheap to reshape.

### How the static output flows (the part I kept deliberately minimal)

The server's layered export packs each launch layer into a content-addressed
**erofs** blob, and `collect_layered_server` only knows how to write a *server
manifest* + reference that erofs layer for the overlay runtime. Serving a static
`dist/` needs a **plain directory** in the staged site location, which would
otherwise require erofs extraction host-side (a new tool in the server path).

To avoid that, a static target uses a **flat-tarball export** instead of erofs:

- `jkbuild-types`: new `/static.tar.gz` out-file contract.
- `jkbuild` lifecycle: a `jkbase.kind=static` path runs the *same*
  detect/fetch/seal/compile pipeline (`run_buildpack_pipeline`, shared with the
  server path) but exports the launch tree via the existing `pack_flat_tarball`
  to `/out/static.tar.gz` — no erofs, no manifest.
- `jkbase-orch`: `BuildVmConfig.build_static` → `jkbase.kind=static` (mutually
  exclusive with `build_function`).
- `jkbase-server`: `collect_static_site` dumps `/static.tar.gz`, untars it (tar-rs
  refuses `..`/absolute escapes), and copies the tree into the staged site
  location — the **same** destination and the **same `_`-prefix guard** (review
  B-1) as committed content. So a built tree gets no extra trust, and the serving
  path downstream is byte-identical to today's committed-site path.

This reuses existing machinery (`pack_flat_tarball`, `unpack_tar_gz`,
`copy_filtered[_guarded]`) and adds **no new host tooling**. The trade-off vs. the
erofs/layered path: a static site is *not* content-addressed/dedup'd as a runtime
layer — but it isn't a runtime layer (nothing runs), so that machinery doesn't
apply. If you'd prefer static sites to also be erofs layers (e.g. for blob
dedup), that's the alternative; it costs an erofs-extract step on the host.

## Verification

- `cargo build` (whole workspace) and `cargo test` for **jkbuild**,
  **jkbase-common**, **jkbase-control**, **jkbuild-types**, **jkbase-server**,
  **jkbase-orch** (incl. examples) all pass. New unit tests cover: trunk
  `detect`, `Trunk.toml` dist resolution, the dist-tree move, the rust→trunk
  defer, the `[sites.*] build` config resolution, static-target enumeration,
  `toolchain_candidates` for a static/trunk target, and the `/static.tar.gz`
  contract.
- **Not verifiable here:** the end-to-end runtime — booting a real build VM needs
  KVM/Firecracker + the baked `trunk.ext4` + base/runtime layers. Those tests are
  the existing `#[ignore]` `onbox::*` set; a `trunk_static_pipeline_to_http_200`
  belongs alongside them once the image is baked on the KVM box.

## Suggested review order

1. The two proposals above (`TargetKind::Static`, the `[sites.*] build` shape).
2. The static export contract (`/static.tar.gz` + the lifecycle/orch flags).
3. `collect_static_site` security (reuses the committed-content guard).
4. The toolchain image + `INJECT_TRUNK`.
