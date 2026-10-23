# Storage scale-out: getting tenant bytes off the single host

## Problem

Every byte jkbase stores lives on the one prod host's local disks (2× 4 TB HDD, md RAID1; 163 GB
used on 2026-10-23). Capacity is not the constraint. These are:

- **Durability is one box.** RAID1 survives a disk, not the host. Losing the host loses every
  tenant's objects, data disks and backups at once.
- **No path to a second host.** The tenant object store's *index is the directory tree*: an object
  is `{bucket}/{stem}` + `{stem}.meta`, listing is `read_dir`, counting is a walk, bucket existence is
  `try_exists`. Nothing about that can move off a POSIX filesystem, so neither the bytes nor the
  gateway can move off this host.
- **Spinning disks under databases.** Data disks (RhypeDB, tenant state) sit on 7200 rpm HDDs.

"Add a bigger disk" fixes none of these. This doc is the plan for the three that matter.

## Principle: one answer per storage role, not one storage system

The four substrate roles already say this ([decision record], `jkbase-substrate`):

| What | Access pattern | Where it goes |
|---|---|---|
| **Tenant objects** (`storage.` product) | streamed, ranged, immutable-per-version, unbounded | index stays ours; **bytes go to a pluggable segment store** (local → remote S3-compatible → own cluster) |
| **Data disks** (R3) | random block I/O, latency-bound, single writer | **stay local** (NVMe on the next host); durability by **shipping backups/logs to the blob tier** |
| **Platform blobs** (R4: layers, snapshots, build artifacts) | big, immutable, content-addressed | substrate `BlobStore` — wire the existing `s3` backend in the HA arc |
| **Control state** (R1/R2) | small, transactional | redb today → replicated KV in the HA arc. **Never** on S3, never on the tenant product. |

Remote object storage is the right home for immutable bytes and the wrong home for a block device;
a networked block layer (Ceph RBD) is the right home for data disks only once there are ≥3 nodes on a
fast network — on budget bare metal with HDDs + 1 Gbit it is all cost and no benefit. So Ceph stays
an HA-arc option, not this arc.

## The key move: split the object store's index from its bytes

```
            ┌──────────────── ObjectStore (per project) ────────────────┐
  S3 / console ─▶ auth · quota · CORS · SigV4 (unchanged, objectstore_service.rs)
            │                                                            │
            │   ObjectIndex (redb, {root}/.index.redb)                   │
            │     buckets   name            → BucketRow{created, cors}   │
            │     objects   bucket\0key     → ObjectMeta                 │
            │     manifests bucket\0key     → [SegRef{id, size}]         │
            │     uploads   bucket\0upload  → UploadInfo                 │
            │     parts     upload\0part#   → PartRow{segment, md5, size}│
            │     pending   segment         → created (write in flight)  │
            │     garbage   segment         → retired (to delete)        │
            │                                                            │
            │   SegmentStore (trait)  — immutable byte blobs by id       │
            │     LocalSegments  {root}/.segments/ab/abcd…   ← step 1    │
            │     remote S3-compatible / Garage              ← step 2+   │
            └────────────────────────────────────────────────────────────┘
```

**An object is a manifest of segments.** A single PUT is one segment; a completed multipart upload
is its parts' segments *in order* — `complete_multipart` no longer copies every byte into a new file
(today it concatenates, doubling write I/O and transiently doubling disk use). A ranged GET walks the
manifest and opens only the segments it needs.

**The index is transactional and authoritative.** Every visible state change is one redb write
transaction; bytes are written *before* the transaction that makes them visible and deleted only
*after* the transaction that makes them unreachable. So a crash can leak a segment but never expose a
torn object or a dangling reference.

### Segment lifecycle (crash safety without ever listing the byte store)

1. `pending[id] = now` is committed **before** a byte is written.
2. The bytes are streamed to the segment store (tmp → fsync → `link` into place, never replacing
   an existing id → directory fsync).
3. One transaction references the segment (object or part row), removes `pending[id]` (refusing
   if it is already gone), and moves any segments it displaced (overwrite, part re-upload, unused
   parts at complete, delete, abort) to `garbage`.
4. Right after that commit the store deletes the displaced segments' bytes — unless a GET in this
   process has them pinned — and forgets them.
5. The sweeper (every 10 min, bounded batches per project) retries whatever garbage is left, and
   first moves `pending` rows older than `PENDING_ORPHAN_AGE` (> the 6 h upload ceiling) to
   garbage in the same transaction that claims them, so a writer the clock made look dead fails
   its commit instead of referencing bytes being deleted. A request cancelled mid-body releases
   its pending row on drop.

Because every segment id is recorded *before* its bytes exist, the sweeper never needs to list the
byte store — essential once that store is a remote bucket with millions of keys and per-LIST cost.

**Why delete immediately, and why pins:** the byte quota lets an overwrite through on its net
growth, so retaining replaced versions for any grace period lets same-size overwrite churn fill the
shared disk unaccounted (an adversarial review proved ~450 GB/h at line rate with a 1 h grace). So
displaced bytes go at once. A GET in flight pins its manifest's segments for as long as its body
streams: it pins, then re-reads the manifest, so a segment is either pinned before it can be
retired or the reader sees the newer manifest. Pins are in-process; with a remote byte store and
more than one gateway host, step 2 has to carry them across hosts (or fall back to a short grace).

### Why redb, per project

- Already in the tree, O(1) `len()` (count quotas stop walking directories), ordered range scans
  (ListV2 + delimiter folding become an index seek: after emitting folder `p/` the scan jumps to
  `p/` ++ `0xFF`, which sorts after every UTF-8 key under it — a million-key folder costs one step).
- Per project = per-tenant blast radius, and the file moves with the project.
- Values are JSON (`serde`), same forward/backward-compat choice as the `SNAPSHOTS` table.
  Manifests live apart from metadata, so HEAD, LIST and quota checks never parse a 10 000-entry
  manifest. Page cache is capped at 8 MiB per index (redb's 1 GiB default is per database, and
  the server keeps thousands open).
- Index writes queue per project in async land (one at a time — redb has one writer anyway), so a
  write flood from one tenant parks requests, not blocking-pool threads that other tenants need.
- **HA later:** the index must follow the project between hosts. Candidates, decided in the HA arc,
  not now: (a) lease-fenced owner + index snapshot/log shipped to the blob tier; (b) an LSM that
  lives *in* the blob tier with writer-epoch fencing (SlateDB-style), so durability of the index =
  durability of the bytes. The `ObjectIndex` seam keeps that swap local to one module.

### Why a new `SegmentStore` and not the substrate `BlobStore`

The substrate `BlobStore` is the *cluster's own* R4: file-path based (`put_file`/`get_to_file`),
whole-blob, built for multi-GiB snapshots. The tenant data plane needs streamed writes from a
request body, **ranged streamed reads**, and (step 2) per-project encryption — and the decision record
wants the tenant product and platform state kept apart anyway. Backends can share code (both will
likely sit on the `object_store` crate for remote), but not the trait.

### Threat-model invariants (all tenants hostile)

- **P0 — no cross-tenant content addressing.** Segment ids are random per write, never content
  hashes. A shared CAS would let a tenant learn whether *another* tenant stored given bytes (an
  existence oracle via timing, dedup-billing or a `put_if_absent` result). No dedup across projects.
- **P0 — no tenant-controlled path.** The bucket/key never reaches a filesystem path or a remote key:
  the byte store only ever sees ids the engine minted. (Removes the whole stem-encoding/`NAME_MAX`
  class that PR #107 had to patch.)
- **P0 — remote bytes are ciphertext (step 2).** Before any byte leaves the host it is encrypted
  under a per-project data key (AEAD, per-segment nonce, segment id bound as associated data so a
  provider can't swap segments between objects). Keys live in the control store, never next to the
  bytes. A provider breach or subpoena yields ciphertext.
- **P1 — index identity.** The index file is opened once per process (a redb lock; one open slot
  per root, so opening or migrating one project never waits on another). The per-project cache
  checks the file's `(dev, inode)` on every hit, and the segment store checks its directory's
  before every write, so a project that is deleted and recreated under the same id can never
  write into the previous incarnation's index, nor leak bytes into the new one's.
- **P1 — no host detail in errors.** Internal failures answer S3's generic `InternalError`; the
  detail (index errors, paths) goes to the log.

## Phases

### Step 1 — index/bytes split, local only (no behavior change) ← this branch

- `ObjectIndex` + `SegmentStore` trait + `LocalSegments`, all inside `jkbase-objectstore`.
- Public `ObjectStore` API unchanged except `get_object`, which returns a manifest handle that streams
  any `[start, start+len)` (ranged GET no longer assumes one seekable file).
- **Migration** from the legacy layout, on server boot and on any open that finds layout-1
  content: each bucket directory is first renamed to `.migrating-<bucket>` (invisible to an older
  binary), then its objects are hard-linked into `.segments/` (pending rows first) and committed in
  batches of 512 per transaction, then unlinked. Legacy content always wins over the index — it is
  never older — so a re-run after a crash, or after a rollback that wrote new layout-1 directories,
  converges on the newest data and never resurrects a delete. In-flight multipart uploads and CORS
  sidecars migrate too; unreadable objects are moved to `.unmigrated/`, never deleted.
  **Rolling back is unsupported but not silently lossy:** an older binary sees an empty store, and
  whatever it writes is picked up on the next start of this one.
- Deliberate S3-fidelity change: CompleteMultipartUpload with parts out of ascending order (or
  repeated) is refused with `InvalidPartOrder`, as S3 does; the old engine silently reordered or
  duplicated bytes. The Rust SDK now de-duplicates re-uploaded part numbers. S3's 5 MiB minimum
  part size is **not** enforced: clients written against this server (our SDK example included) use
  small parts, and the manifest split keeps tiny-part objects cheap for everyone but their reader.
- Quota counts read `len()`; byte billing (`dir_bytes` over the project root) is unchanged because
  segments + index still live under `{data_dir}/objectstore/{id}`.
- Done = full existing test suite green (S3 + console + quota + CORS + range), new tests for
  migration, crash-orphan sweep, overwrite-while-reading, multipart-without-copy; on-box e2e via the
  JS SDK; prod deploy migrates every project.

### Step 2 — remote segment backend + per-project encryption

- `RemoteSegments` over any S3-compatible endpoint (`object_store` crate), selected per server by
  config; the endpoint must not resolve to jkbase's own `storage.` host (reuse
  `assert_not_self_referential`).
- Per-project data keys + AEAD framing (fixed-size encrypted chunks so ranged reads stay cheap).
- New writes go remote; a background mover copies old local segments and flips manifests
  transactionally (old local segment → `garbage`). Local disk becomes a cache, then nothing.
- Choose the provider on egress price first (every GET flows through us), then storage price,
  then region. Verify prices at decision time.
- Billing switches from `dir_bytes` to index-summed bytes (local disk no longer reflects usage).

### Step 3 — data-disk durability via the blob tier

Generalize the managed-RhypeDB backups to every data disk: periodic consistent snapshots (and, where
the workload allows, a log stream) shipped to the substrate blob tier, encrypted per project. Gives
cross-host restore = cold boot from the latest disk image, the RTO the HA arc assumes.

### Step 4 — own the byte tier (when volume justifies it)

Three or more cheap storage boxes running an S3-compatible store (Garage is the current best fit:
Rust, built for geo-distributed commodity nodes, light ops) behind the *same* `RemoteSegments`
backend — a config change, not a rewrite. Ceph RBD for data disks is evaluated here too, with
NVMe + ≥10 Gbit as the entry ticket.

## Explicitly not changing

- Auth, SigV4, quotas, CORS, isolation, metering: all stay in `objectstore_service.rs` above the
  `ObjectStore` API.
- The control plane never depends on the tenant store or on S3.
- Single-host remains the production topology until the HA arc lands.

[decision record]: Overboard card `cmr2br5ih00dak4f3gb0bz2j4`
