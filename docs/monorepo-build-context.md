# Design note: monorepo build context

Status: **DRAFT — needs sign-off on the `context` knob shape (one public-API decision below).**
Branch: `feat/monorepo-build-context`.
Author: prepared for Joe's review.

## Problem

A build target — a `[servers.*]`, or a `[sites.*]` with `build = "trunk"` — is built
in a VM whose read-only source image is built from **only that target's `source`
subdir**. So a buildable crate that depends on an **in-repo sibling** by relative
path fails: the sibling isn't in the mounted subdir.

```toml
# jkbase.toml at a Rust workspace root
[sites.app]
source = "plotweb-web"   # a trunk frontend crate
build  = "trunk"
```

```toml
# plotweb-web/Cargo.toml
[dependencies]
plotweb-common = { path = "../crates/plotweb-common" }   # ← sibling, NOT under plotweb-web/
```

Today only `plotweb-web/` is imaged and mounted at `/src`, so `../crates/plotweb-common`
points outside the mount and the build dies at `cargo`/`trunk` resolve time. This is
not one app's problem — it blocks essentially **every** monorepo: Rust workspaces,
pnpm/yarn/npm workspaces, Go multi-module repos, Python monorepos, etc.

## The knob: `context`

Add an optional `context` field to `[servers.*]` and `[sites.*]`:

```toml
[sites.app]
source  = "plotweb-web"   # WHERE the build runs (the app dir)
context = "."             # WHAT is mounted as the build root (the whole workspace)
build   = "trunk"
```

Semantics, mirroring a **Docker build context**:

- `context` = a directory (relative to the project root) mounted as the build root
  (`/src` in the build VM).
- It **defaults to the target's `source`** (`.`/current default for a bare server).
  So **an unset `context` is byte-identical to today** — we image and mount just the
  source subdir, and build at its root.
- When set wider than `source`, the whole `context` is imaged and mounted, and
  detect/build/launch run in `source` **interpreted relative to `context`**. With the
  wider tree mounted, `../sibling` path-deps resolve.

`source` must live **inside** `context` (validated at deploy; `..`/absolute escapes
rejected on both).

## Why this generalizes across ALL buildpacks

The change is at the **mount + working-directory** layer, *below* every buildpack — it
is buildpack-agnostic:

- The orchestrator images `context` (not the source subdir) into the RO `/src` drive.
- The in-VM lifecycle copies the **whole** `/src` context into the writable workspace
  (so siblings are present and mutable), then runs the buildpack `detect` and sets the
  buildpack's `app_dir` to `<workspace>/<build_subdir>`, where `build_subdir` is
  `source` relative to `context`.

Every buildpack already receives its working tree via `app_dir`/`/src`; none reaches
outside it. So `cargo` (rust), `trunk`, `bun`/`npm`/`pnpm` (node/bun), `go`, `pip`/`uv`
(python), and even `builder = "dockerfile"` all see a wider, sibling-complete tree with
**zero buildpack changes**. The `dockerfile` path is preserved: its path is relative to
the build subdir (= `app_dir`), unchanged.

## Plumbing (what landed)

1. **`crates/jkbase-common/src/config.rs`** — `context: Option<String>` on
   `ServerConfig` and `SiteConfig`; resolvers `context_dir()` (the dir to mount,
   default = `source`) and `build_subdir()` (the source relative to context, `"."` when
   unset). A pure `rel_within(context, source)` helper.
2. **`crates/jkbase-server/src/build_orchestrator.rs`** — `TargetSpec` carries
   `context_subdir` (→ ext4 + mount) and `build_subdir` (the in-context source path).
   The build path images `context_subdir`, runs `detect_language` on
   `context/<build_subdir>`, and threads `build_subdir` into `BuildVmConfig`.
   `enumerate_targets` populates both from config (default: context = source →
   build_subdir = `"."`, identical to today). `validate_manifest` checks `context`
   safety and `source ⊆ context`.
3. **`crates/jkbase-orch/src/build_vm.rs`** — `BuildVmConfig.build_subdir`, emitted as a
   `jkbase.build_subdir=<subdir>` kernel-cmdline token (guarded by the existing
   `is_safe_cmdline_path`; `"."` emits nothing → no behavior change for non-monorepos).
4. **`crates/jkbuild/src/lifecycle.rs`** — parse `jkbase.build_subdir` (re-validated:
   no `..`/absolute/flag — defence in depth, falls back to `"."`); copy the whole
   context to the workspace; scope `detect`/`app_dir` to `<workspace>/<build_subdir>`.
   A `join_subdir(".")` identity keeps the default path byte-for-byte unchanged.

No migration. `context` is purely additive and opt-in; existing manifests build
exactly as before.

## API decision for Joe (the one knob shape to sign off)

Three shapes were considered:

1. **`context` (chosen)** — a Docker-build-context-like directory; `source` becomes
   the app dir *within* it. **Pro:** familiar mental model (everyone knows
   `docker build <context>`); orthogonal to `source`; default = `source` makes it a
   pure no-op when unset; reads naturally for both servers and sites. **Con:** two
   path fields whose relationship (`source ⊆ context`) must be validated and explained.

2. **`workspace = true` (boolean)** — "mount the repo root, build in `source`."
   **Pro:** one bit, dead simple for the common Rust/JS-workspace case. **Con:**
   inflexible — can't mount an *intermediate* dir (e.g. `apps/` for an
   `apps/web` + `apps/lib` split) without dragging the entire repo; "the repo root"
   is ambiguous (upload root vs. nearest workspace manifest); doesn't compose if
   different targets want different context widths.

3. **Redefine `source` = root + add `build_subdir`** — `source` becomes the mount,
   `build_subdir` the app dir. **Pro:** also two fields. **Con:** *changes the meaning
   of an existing field* — every current manifest's `source` would silently become "the
   mount root," a behavior change and a migration hazard; this is exactly what we must
   avoid (the #1 review concern is a byte-identical default).

`context` (option 1) keeps `source` meaning what it means today, adds an opt-in widening,
and defaults to a no-op. **This is the field we'd like signed off.**

## Tradeoffs to weigh

- **Build-context SIZE / scan time.** A wide `context` images and copies the whole
  subtree per target. For a big monorepo this inflates the RO image build, the
  workspace copy, and `detect` scan time — and it happens **once per target**, so a
  manifest with N targets all rooted at `.` images the repo N times. Mitigations to
  consider later: a `.jkbaseignore`/context-prune step (Docker-style `.dockerignore`),
  or de-duping identical contexts across targets in one build. Not in this PR.
- **What a target's build now SEES (security/blast-radius).** With `context = "."` the
  build VM sees the *entire* uploaded tree, not just one app's source — including other
  apps' source and any secrets a tenant left in the repo. The VM is already the
  jailed, fetch-then-seal security boundary (a build can't exfiltrate post-seal), so
  this widens what a *buggy/hostile build script* can read of the **tenant's own**
  upload, not host data. Still, it's a real "least privilege" regression vs. the
  narrow mount — worth a docs callout so authors set `context` no wider than needed.
- **Determinism.** A wider context means more inputs feed the build, so unrelated edits
  elsewhere in the context can change a target's build/cache outcome. Keeping `context`
  as narrow as the path-deps require (e.g. `apps/`, not `.`) preserves the tightest
  reproducibility. The default (unset → `source`) stays maximally deterministic.

## Status / what couldn't be verified

- `cargo build --workspace`, `cargo build --workspace --examples`, and
  `cargo test --workspace` are clean; all existing tests pass and the `onbox::*` KVM
  tests stay `#[ignore]`d.
- New unit tests guard: (a) unset `context` → staging + `app_dir` identical to today
  (the regression guard); (b) `context = "."` + `source = "web"` → image from root,
  `build_subdir = "web"`, detect runs in `web/`; (c) validation rejects
  source-outside-context and `..`/absolute escapes.
- A **real build VM cannot run here** (needs KVM/Firecracker + baked toolchain images +
  root). The end-to-end proof — a monorepo target whose build resolves a sibling
  path-dep — is added as an **ignored `onbox::*` stub**
  (`monorepo_context_resolves_sibling_path_dep`) to be wired on the KVM box.
