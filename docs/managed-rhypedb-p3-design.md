# Managed RhypeDB P3 — jkbase Auth (per-project EdDSA-JWT issuer)

Grounded implementation plan for **P3** of the managed-RhypeDB arc. Parent design +
phase map: `docs/managed-rhypedb-design.md` §3 (identity), §5 #5–6 (rhypedb hooks), §6 #11
(issuer), §7 (roadmap), OPEN DECISION 4 (scope). Prior phase: `docs/managed-rhypedb-p2-design.md`.
This doc is grounded in a fresh (post-P2) four-way code recon; file:line refs are current as of
`main` after PR #66 (`2678cd3`).

P3 is **the identity prerequisite** for the Firestore-style end-state (P4 in-engine authz, P5
direct-from-untrusted-client). It is a **reusable platform primitive** — the first consumer is the
managed DB, but functions/servers can use it the day it ships.

---

## 0. Scope decision (OPEN DECISION 4) — MINTER CORE, login-UX deferred

Everyone builds the same **per-project Ed25519 + JWKS crypto core** — the expensive, hard-to-change
part. The fork is how far this first increment goes on top of it:

- **✅ THIS INCREMENT — the minter core (aka "signing oracle").** jkbase holds a per-project Ed25519
  keypair, publishes per-project JWKS, and **mints a short-lived JWT when the tenant's own
  already-authenticated backend asks**. jkbase never stores end-user accounts or passwords. A strict
  subset; ships fast; immediately useful (a tenant's functions/servers can mint + verify their own
  per-user tokens today); unblocks P4/P5 for any tenant who brings their own auth. This is the parent
  doc's Decision-4 recommendation verbatim ("the per-project EdDSA+JWKS core… with signup-UX/OIDC
  layered later").
- **⛔ DEFERRED — jkbase-owned end-user login.** Signup/login/password-reset + a per-project user
  directory (`AUTH_USERS`) + console Auth tab = the zero-backend Firebase-Auth competitor. Bigger
  surface (email verification, reset, OIDC/social). **Not** required to reach the Firestore end-state
  if tenants bring their own auth. It sits cleanly on the *same* core, so building it later is **not
  rework**. Joe was asked (2026-07-07) but AFK → proceeding on the recommended safer subset per the
  P2 precedent; **reversible/additive** if he wants the full platform.

Net: P3 = a host-side, per-project JWT signing service + JWKS + rotation + issuer keys + CLI. Zero
rhypedb changes (the recon confirms nothing in the engine consumes a JWT yet — see §6).

---

## 1. Architecture

```
  tenant's OWN backend (authenticates its end-users however it likes)
        │  POST auth.jkbase.app/v1/projects/{id}/token   (Bearer jkbk_… issuer key)
        │  { sub, claims?, aud?, ttl? }
        ▼
  proxy_request:  Host = auth.{domain}  ── reserved branch (mirror api./storage.) ──► forward_to_api
        ▼
  AuthService  (in-process loopback axum, 127.0.0.1:{auth_port}, mirror objectstore_service.rs)
    · authenticate issuer key (jkbk_ secret → fingerprint lookup → project + owner-rebind)
    · load/lazily-mint the project's Ed25519 signing key (control store, host-side)
    · sign compact JWT { iss, sub, aud, exp, iat, jti, ...claims }  with the CURRENT kid
        ▼  returns the JWT (shown to the backend, handed to the end-user client)

  ANY verifier (tenant middleware · a jkbase function · later the P5 DB-gateway):
        GET auth.jkbase.app/v1/projects/{id}/.well-known/jwks.json   (anonymous, cacheable)
        → { keys:[ current + rotating-out public Ed25519 keys ] }
        → verify offline: EdDSA sig (alg PINNED) · iss · aud · exp · skew  → {sub, claims}
```

**Why a loopback HTTP service, not the ALPN edge.** The traffic is ordinary browser/backend HTTPS
(`GET …/jwks.json` anonymous+cacheable, `POST …/token` credentialed, CORS preflights). That is
exactly the shape `objectstore_service.rs` already handles (anonymous + Bearer + signed in one axum
router behind a loopback bind the edge forwards to). `db_ingress.rs` exists to splice a *raw
non-HTTP wire protocol* to a woken VM — wrong shape here; a JWT service has no wire protocol and no
per-request VM wake.

**Why the private key stays host-side (new invariant P0-AUTH-2).** EdDSA is asymmetric, so only the
*public* key is needed to verify. The private signing key lives at rest in the control store (redb,
host-only) and **never enters a tenant VM** — even better than the reserved-metadata channel
(`_db_reach.json`) that ferries the DB's *symmetric* splice/admin secrets. Verifiers get the public
key via JWKS. (At P4 the DB VM only needs the public key; it fetches JWKS or gets it baked via the
existing reserved channel.)

**Key identity & rotation (P0-AUTH-4).** `kid = "{project_id}.{serial}"`. The store holds a
`current` keypair and an `Option<previous>` public key. Rotation mints a new `current`, demotes the
old to `previous`, and **keeps the old public key in JWKS for a window ≥ the max token TTL** so
in-flight tokens still verify — the existing per-deploy *hard-overwrite* rotation
(`mint_db_admin_token`, `store.rs`) would strand valid tokens, so this needs the dual-key window.
A *compromised* key is force-rotated AND dropped from JWKS immediately to hard-revoke.

---

## 2. Security invariants (P0-AUTH-*) — adversarial-review targets

| ID | Invariant | Why / mechanism |
|---|---|---|
| **P0-AUTH-1** | **Per-project signing keys.** | A global key lets project A mint project B's tokens. Keypair keyed by `project_id`; JWKS is per-project; `iss`/`kid` name the project. |
| **P0-AUTH-2** | **Private key never leaves the host.** | Asymmetric ⇒ only the public key is exported (JWKS). Private key at rest in the control store, host-only, never in a VM/env/tenant file. |
| **P0-AUTH-3** | **Owner-rebind on the issuer-key path.** | A `jkbk_` minted under owner A must not mint after a same-slug recreate by owner B. Mirror the S3/git/console guard (`objectstore_service.rs:519-533`): key→project→`get_project`→`tenant_id` match, else deny. |
| **P0-AUTH-4** | **kid rotation with an overlapping public window ≥ max TTL.** | Rotation never strands valid tokens; compromise → force-rotate + drop kid from JWKS = hard revoke. |
| **P0-AUTH-5** | **Verify PINS alg=EdDSA + kty=OKP/Ed25519.** | Classic JWT break: never trust the token header's `alg`; reject `alg:none` and alg-substitution. Our reference verifier (and the P5 gateway) hardcode EdDSA and look the kid up in JWKS. |
| **P0-AUTH-6** | **`auth` is a RESERVED_LABEL; project is resolved from the authenticated key, not client input.** | Add `"auth"` to `RESERVED_LABELS` (`store.rs:85`) so no tenant claims `auth.{domain}`. The mint path takes the project from the issuer-key record (authoritative); a path/body project id is only cross-checked against it. |
| **P0-AUTH-7** | **Short-lived tokens + minted-rate cap.** | Default TTL ≤ 1h, hard max (e.g. 24h); per-issuer-key token-mint rate limit (mirror `db_ingress` `PerIpLimiter`) bounds a leaked-key blast radius. |
| **P0-AUTH-8** | **Fail-closed everywhere.** | No/invalid issuer key → deny; JWKS for an unknown/deleted project → 404; unknown kid at verify → fail; a project with no keypair yet → JWKS `{keys:[]}` (verifies nothing), mint lazily provisions one. |

Egress/isolation note: the issuer runs host-side (loopback), so there is **no new host/guest seam**
in the minter core — the only public surface is the `auth.` HTTPS routes the proxy already fronts.

---

## 3. Wire formats

**JWT (RFC 7519 compact, EdDSA):**
```
header  = { "alg":"EdDSA", "typ":"JWT", "kid":"{project_id}.{serial}" }
claims  = { "iss":"https://auth.{domain}/v1/projects/{project_id}",
            "sub":"<end-user uid, tenant-chosen>",
            "aud":"<project_id>  (or a tenant-supplied audience, allowlisted later)",
            "iat":<unix>, "exp":<unix, iat+ttl>, "jti":"<random>",
            ...tenant custom claims (namespaced under a `claims` object to prevent
               collisions with reserved registered claims) }
signature = EdDSA(base64url(header) + "." + base64url(claims))
```
Custom claims go under a nested object (e.g. the token carries `{..., "claims": {...tenant...}}`) so
a tenant can never overwrite `iss`/`aud`/`exp`/`sub`. P4's rules read `request.auth.uid` (=`sub`)
and `request.auth.claims.*`.

**JWKS (RFC 7517, published per project):**
```
GET /v1/projects/{id}/.well-known/jwks.json  →
{ "keys":[ { "kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA",
             "kid":"{project_id}.{serial}","x":"<base64url(32-byte pubkey)>" }, … ] }
```
Both are trivially expressible with in-tree deps (`serde_json` + `base64 URL_SAFE_NO_PAD`); the ONLY
net-new crypto dependency is an Ed25519 signing crate (`ed25519-dalek`).

---

## 4. Endpoints & CLI

**AuthService (`auth.` loopback, browser/backend-facing):**
- `GET  /v1/projects/{id}/.well-known/jwks.json` — anonymous, cacheable, CORS-open (verifiers are everywhere).
- `POST /v1/projects/{id}/token` — auth = issuer key (`Authorization: Bearer jkbk_…`); body `{sub, claims?, aud?, ttl?}`; returns `{token, exp}`. Rate-limited (P0-AUTH-7).
- (optional dev helper) `POST /v1/projects/{id}/verify` — server-side verify for debugging; NOT the hot path (verify is offline via JWKS).

**Control API (`api.` owner-Bearer — mirror `/projects/{id}/db-keys`):**
- `POST /projects/{id}/auth/keys`  — mint an issuer key (`jkbk_…`), shown once; fingerprint at rest.
- `GET  /projects/{id}/auth/keys`  — list issuer keys (no secrets).
- `DELETE /projects/{id}/auth/keys/{key_id}` — revoke one.
- `POST /projects/{id}/auth/rotate` — force a signing-key rotation (dual-window).
- `GET  /projects/{id}/auth/signing-keys` — list kids + status (current/previous, created_at).

**CLI `jkbase auth …` (mirror `DbKeyCommand`, `commands/mod.rs:226-257`):**
`auth key {create,list,rm}` · `auth rotate` · `auth jwks {id}` (fetch/inspect) · `auth mint --sub … --claim k=v` (dev convenience, uses an issuer key).

**Config:** the minter core needs **no new `jkbase.toml` stanza** — provisioning is triggered by
`jkbase auth key create` (lazy keypair mint), exactly like the DB reach plane needs no config beyond
`jkbase db key create`. A future optional `[auth]` stanza (default TTL, audience allowlist) is a
later refinement, not a P3-core requirement.

---

## 5. The seams (grounded file:line) — what to add where

1. **Crypto core (new module, `jkbase-control` or a tiny new `jkbase-jose` crate).** `ed25519-dalek`
   keygen/sign/`VerifyingKey`; a hand-rolled JOSE module on `serde_json`+`base64` for JWT
   sign/verify + JWKS emit. Unit-tested standalone (sign→verify round-trip, alg-pin, exp/skew,
   kid mismatch, tamper). **100% decision-independent — build first.**
2. **`auth.rs` token family (`crates/jkbase-control/src/auth.rs`).** Add `generate_issuer_key()` →
   `jkbk_` prefix (256-bit, fingerprint-at-rest — mirror `generate_db_secret` at `:100`) and a
   `generate_kid_serial()`. Voice: match the dense prefix-rationale doc-comments (`:79-134`).
3. **Control store (`crates/jkbase-control/src/store.rs`).** Two new tables (register in BOTH the
   `const` list at `:8-81` AND the init txn at `:658-680`):
   `AUTH_SIGNING_KEYS` (`project_id` → `{current, previous, next_serial}`; private key recoverable at
   rest like the S3 secret `auth.rs:69-72`) and `AUTH_ISSUER_KEYS` + `AUTH_ISSUER_KEYS_BY_PROJECT`
   (`{project_id}:{key_id}` index — mechanical clone of `DB_ACCESS_KEYS`(+`_BY_PROJECT`) methods
   `store.rs:1872-1976`, incl. per-project cap + scoped delete + teardown purge). Add `"auth"` to
   `RESERVED_LABELS` (`:85`).
4. **AuthService (`crates/jkbase-server/src/auth_service.rs`, new).** Mirror
   `objectstore_service.rs`: struct + `into_router()` (anonymous JWKS route + Bearer `/token` route +
   CORS), issuer-key auth + owner-rebind (`objectstore_service.rs:519-533`), lazy keypair provision,
   sign. Per-issuer-key rate limiter (mirror `db_ingress` `PerIpLimiter`).
5. **Proxy reserved host (`crates/jkbase-proxy/src/lib.rs`).** A third reserved branch after
   `storage.` (~`:540`) + `auth_addr: Arc<Option<String>>` in `SharedState`(`:151-165`) and
   `ProxyConfig`(`:107-149`), reusing `forward_to_api` (`:725-774`). ~15 lines.
6. **Wire-up (`crates/jkbase-server/src/main.rs`).** Bind `AuthService` on `127.0.0.1:{auth_port}`
   (mirror the objectstore bind `main.rs:1100-1144`); set `auth_addr` into `ProxyConfig`
   (mirror `:1704-1705`). TLS: **nothing new** — `auth.{domain}` is a single label already covered
   by the apex `*.{domain}` wildcard (`tls.rs` ensure_wildcard). No DNS/cert work.
7. **Control API owner routes (`crates/jkbase-control/src/api.rs`).** The `/projects/{id}/auth/*`
   handlers (mirror the `/db-keys` routes at `api.rs`), behind `require_auth`.
8. **CLI (`crates/jkbase-cli`).** `Auth(AuthCommand)` arm on `Command` (`commands/mod.rs:9-120`) +
   nested `AuthCommand`/`AuthKeyCommand` (mirror `DbCommand`/`DbKeyCommand` `:189-257`) + handlers
   (mirror `run_db_key` `:1175-1209`).

---

## 6. Why P3 is cleanly separable from P4 (and validated jkbase-side only)

Recon of the sibling `rhypedb` repo (`/home/joe/dev/rhypedb`, `master`): the data plane is **fully
unauthenticated** — HTTP `/query` (`crates/rhypedb-server/src/lib.rs:250`), the binary TCP handler
(`lib.rs:1246→1257`, and the wire `Frame` has no identity field / no `REQ_AUTH` frame,
`rhypedb-wire/src/protocol.rs:106-146`), and the TCP-only subscribe path (`lib.rs:1608`, no
WebSocket) all execute with **no principal**. `ExecContext` has no identity field
(`rhypedb-query/src/executor.rs:60-77`). No `--rules` flag, no rules parsing anywhere. The only token
rhypedb reads is the static admin bearer (exact-string compare, `admin.rs:88`) — host-plane, not
end-user. **So nothing in the engine consumes a jkbase JWT today.** P3 therefore ships and is
validated entirely jkbase-side (mint → verify against JWKS → tests), with **zero rhypedb changes**,
and no claim shape is constrained by current engine code (that becomes a P4 choice).

**P4 (later, in rhypedb):** add an Ed25519/JWT verify dep, a `Principal` + `principal:
Option<Principal>` on `ExecContext` (`executor.rs:60`), extraction at all three entrypoints (HTTP
header; a new auth frame for the binary/subscribe protocol which currently can't carry a token), and
a default-deny rules evaluator. **P5:** WS `/subscribe`, the `db.` reserved-host gateway (terminates
the end-user JWT, injects an HMAC internal principal header — P0-DB-5), sub-liveness reaper.

---

## 7. Build plan / Overboard cards

Small atomic commits; branch `feat/managed-db-p3-jkbase-auth` (off `main`). CI runs
`clippy --workspace --all-targets -D warnings`, which compiles the bin WITHOUT `cfg(test)` — every
new item must be used in non-test code in the same commit (the P2 cohesion landmine).

- **P3a — crypto core.** The JOSE/EdDSA module: per-project keypair, JWKS emit, JWT sign/verify with
  alg-pin, exp/skew, kid lookup, tamper rejection. Unit tests. (Decision-independent; highest value.)
- **P3b — store + issuer-key family.** `AUTH_SIGNING_KEYS` + `AUTH_ISSUER_KEYS`(+`_BY_PROJECT`)
  tables & methods; `generate_issuer_key`; `"auth"` in `RESERVED_LABELS`; owner-rebind; kid rotation
  (dual window). Unit tests (round-trip, rotation window, owner-rebind, teardown purge).
- **P3c — AuthService + reserved host.** New loopback service (JWKS + `/token` + CORS + rate limit),
  the `auth.` proxy branch, `main.rs` bind + `auth_addr`.
- **P3d — control API owner routes + CLI.** `/projects/{id}/auth/*` + `jkbase auth …`.
- **P3e — on-box / e2e + adversarial review.** e2e: mint a token via the sidecar/CLI, fetch JWKS,
  verify offline (all jkbase-side; no FC VM strictly needed for the minter core, though a
  jkbase-hosted function verifying a token is a good real-path proof). Multi-agent adversarial review
  of the new seam (per CLAUDE.md) — alg-substitution, cross-project mint, owner-rebind, rotation
  window, rate-limit, `auth.` host confusion. Fix all BLOCKER/HIGH before merge.

Then: merge as one unit → deploy (host binary via `deploy-server.sh`; **no** additive erofs layer —
the issuer is pure host-side; no agent change) → prod smoke (mint + JWKS + offline verify against
real `auth.jkbase.app`).

**Deferred (own cards, NOT this increment):** jkbase-owned end-user login UX + `AUTH_USERS`
directory + console Auth tab (Model A); optional `[auth]` config stanza (TTL/audience policy);
source-IP mint auth for jkbase-hosted apps (mirror the P2 app→DB leg, so an in-VM app mints without
holding a `jkbk_`); OIDC/social import. P4 (rhypedb principal hook) and P5 (WS + `db.` gateway) are
their own arcs.

---

## 8. Verified file references (checkable, current post-P2)
- jkbase-control: token family `crates/jkbase-control/src/auth.rs:25-134` (prefixes), fingerprint
  `:136-168`, argon2 `:170-193`; store tables `store.rs:8-81` + init txn `:658-680`,
  `RESERVED_LABELS` `:85`, DB-key methods (clone target) `:1872-1976`, `authenticate` O(n) scan (to
  AVOID) `:2374`; owner routes `api.rs:382-391`, `require_auth` `:684-725`.
- jkbase-server: objectstore service template `objectstore_service.rs:81-133,164-213,461-533`,
  owner-rebind `:519-533`; loopback bind `main.rs:1100-1144`, api/storage addr `:1704-1705`.
- jkbase-proxy: reserved-host branches `lib.rs:514-540`, `forward_to_api` `:725-774`, SharedState
  `:151-165`, ProxyConfig `:107-149`; TLS apex wildcard `tls.rs:182-213` (covers `auth.{domain}`).
- jkbase-common: reserved-metadata channel pattern `config.rs:174-205` (`DbReachFacts`).
- jkbase-cli: credentials `credentials.rs`, dispatch `commands/mod.rs:9-120`, `DbKeyCommand`
  `:226-257`, `run_db_key` `:1175-1209`.
- rhypedb (sibling repo, P4/P5 targets): `/query` `crates/rhypedb-server/src/lib.rs:250`, TCP
  `:1246-1257`, subscribe `:1608`, admin auth `admin.rs:75-96`; `ExecContext` `executor.rs:60-77`;
  wire frame `rhypedb-wire/src/protocol.rs:106-146`.
