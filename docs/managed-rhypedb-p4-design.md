# Managed RhypeDB P4 — Data-plane authorization (verified principal + default-deny rules)

Grounded implementation plan for **P4** of the managed-RhypeDB arc — the **Firestore core**: an
authenticated **end-user principal** threaded through the query engine plus a **default-deny,
relationship-aware security-rules evaluator**. Parent design + phase map:
`docs/managed-rhypedb-design.md` §3 (identity & rules), §5 #5–6 (rhypedb hooks), §7 (roadmap).
Prior phases: P2 `docs/managed-rhypedb-p2-design.md`, P3 `docs/managed-rhypedb-p3-design.md`.

**This is the one phase whose code lives in the sibling repo `/home/joe/dev/rhypedb` (branch
`feat/data-plane-authz-p4`), not jkbase.** This doc lives in jkbase for arc continuity; the rhypedb
PR references it. File:line refs below are grounded in a fresh post-P3 recon of rhypedb `master`
(the recon confirmed the data plane is **fully unauthenticated** — zero principal/JWT/rules/Ed25519
scaffolding anywhere; P4 builds on bare ground).

P4 is the load-bearing prerequisite for **P5** (WS `/subscribe` + the `db.` reserved-host gateway +
direct-from-untrusted-client). P3 (jkbase-Auth, shipped, PR #67) is the issuer; **P4 is the
consumer** — the engine that verifies P3's tokens and enforces rules on them.

---

## 0. Scope + decisions taken (Joe AFK 2026-07-08 → recommended defaults, reversible)

Two forks were genuinely Joe's call. **Both CONFIRMED by Joe on 2026-07-08** (he was first asked
while AFK; I proceeded on the recommended option for each and he then confirmed both). They remain
structured to be reversible (the DSL is a self-contained parser; the trust seam is behind a
`PrincipalSource` seam) but this is now the committed direction, not a provisional default.

- **DECISION 1 — Rules DSL surface → Firestore-familiar syntax + native edge traversal.**
  A `match Type { allow read/create/update/delete/subscribe: if <expr> }` grammar that a Firebase
  dev reads at a glance, but whose expression language can **traverse RhypeDB relationships**
  (`request.auth.uid in resource.owners`) as a cheap pointer-follow rather than Firestore's
  `get()`-based cross-doc reads. This is the synthesis of the parent doc's OPEN DECISION 5
  recommendation ("native, relationship-aware") with Firebase familiarity. Reversible: the DSL is a
  self-contained parser+AST in one module; swapping the surface syntax is a `P4b`-local change.
- **DECISION 2 — Trust seam → the engine verifies the end-user JWT itself** (offline, alg-pinned),
  against the project's Ed25519 **public** key. **This DEVIATES from the parent doc's P0-DB-5**,
  which had the P5 gateway be the only verifier and inject an HMAC-signed internal principal header.
  Rationale: (a) P3 already ships a per-project JWKS/public-key model — the DB VM can hold the public
  key with **zero network on the hot path** (the parent doc's own §3.2 requirement); (b) P4 becomes
  **independently testable without the P5 gateway existing**; (c) no shared HMAC secret to mint/
  rotate/leak; (d) the token is verified where it is used (one verifier, not two). The P5 gateway
  degrades to a thin **router + waker + quota** front (it still resolves host→project, wakes the VM,
  and enforces quota — like `objectstore_service.rs` — but forwards the client JWT unchanged).
  **Reversibility (load-bearing):** principal extraction is a small **`PrincipalSource` seam**
  (§4.1) — a JWT-verify source today; an HMAC-header source can be added later **without touching
  the rules engine or the executor gates**, so P0-DB-5 can be reinstated as an *additional* trust
  path if Joe wants belt-and-suspenders at P5.

Net P4 = a new `rhypedb-authz` crate (JWT verify + `Principal` + the rules language) + a `principal`
on `ExecContext` + authz gates in the executor + principal extraction at all three entrypoints + a
per-event subscribe filter + config wiring. **Fail-open compatibility is a hard requirement:** a
deployment with **no rules configured** (every v1/P0–P2 co-located + dedicated tenant today) stays
**exactly as open as it is now** — rules-off ⇒ engine unchanged. Rules are opt-in; turning them on
is what closes the doors.

---

## 1. Architecture

```
  end-user browser/mobile (P5)          tenant's own backend (v1/P0–P2, trusted)
        │  Authorization: Bearer <jkbase JWT>          │  (no principal → rules-off path)
        ▼                                               │
  [P5] db.{project}.jkbase.app gateway:                 │
       host→project · wake VM · quota                   │
       forwards the JWT UNCHANGED  ────────────┐        │
                                               ▼        ▼
                              rhypedb-server entrypoints (all 3):
                                HTTP POST /query        (Authorization header)
                                TCP  REQ_AUTH frame     (new frame 0x08, then REQ_QUERY/EXECUTE)
                                TCP  REQ_SUBSCRIBE       (principal captured at auth, per-event filter)
                                               │
                    rhypedb-authz::verify(jwt, jwks, opts)   ← offline, EdDSA pinned, per-project
                                               │  → Principal { uid, claims, authenticated }
                                               ▼
                    ExecContext { db, …, governor, principal, rules }
                                               │
                    ┌──────────────────────────┼───────────────────────────┐
                    ▼ pre-exec op/type gate     ▼ per-object READ gate       ▼ per-mutation WRITE gate
              (cheap, AST-static)        (after materialize; field/edge)  (fetch-then-check pre-mutation)
                                               │
                             rhypedb-authz::rules::evaluate(op, type, principal, resource) → allow|deny
                                               │  default-deny: no matching rule ⇒ deny
                                               ▼
                          engine ops (db.get/filter/create/update/delete/link/…)
```

**Why the engine verifies (DECISION 2).** EdDSA is asymmetric: the engine needs only the **public**
key to verify, so the private key never leaves the host (P3's P0-AUTH-2 is undisturbed). The engine
loads the project's JWKS (public keys, incl. the rotation-window set) from config at boot/reload —
**no network on the query path**. Verification is a faithful **verify-only** port of jkbase's shipped
`jkbase-control/src/jose.rs` (same header `{alg:EdDSA,typ:JWT,kid}`, same claims
`{iss,sub,aud,iat,exp,jti,claims}`, same OKP/Ed25519 JWKS) — so tokens minted by `auth.jkbase.app`
verify in the engine byte-for-byte. The engine's copy is clock-*ful* (it has a wall clock) but keeps
the clock-free `verify(now)` core for testability.

**Why rules run inside the engine, not at the gateway.** Firestore-style rules reference **document
fields** (`resource.published`, `resource.author`) and **relationships** (`resource.owners`), which
don't exist until the object is fetched. A pure proxy can't authorize without parsing the engine's
data. So the gateway (P5) only *authenticates* (and at P4, not even that — the engine does); the
engine *authorizes* against materialized objects it already has in hand.

**Principal shape.** `Principal { uid: Option<String>, claims: serde_json::Value, authenticated:
bool }`, derived from a verified token: `uid = sub`, `claims = the nested custom-claims object`,
`authenticated = true`. An absent/invalid token → the **anonymous principal** (`authenticated:
false`, `uid: None`), which is a first-class value the rules evaluate against (so `allow read: if
request.auth != null` denies anon cleanly). The rules-language names map: `request.auth` ↔
`authenticated`, `request.auth.uid` ↔ `uid`, `request.auth.claims.*` ↔ `claims.*`, `resource.<f>` ↔
the object's field, `request.<f>` ↔ an incoming write's field.

---

## 2. Security invariants (P0-DB-AUTHZ-*) — adversarial-review targets

| ID | Invariant | Why / mechanism |
|---|---|---|
| **P0-DBA-1** | **Default-deny once rules are on.** | With a rules program loaded, an op with no matching `allow` that evaluates true is **denied**. The open routes become closed. (Rules-OFF ⇒ fully open, unchanged — the opt-in gate.) |
| **P0-DBA-2** | **Verify PINS `alg=EdDSA` + `kty=OKP/Ed25519`; key chosen from trusted JWKS by `kid`.** | Never trust the token header's `alg`; reject `alg:none` + HS256-substitution. Direct port of P3's P0-AUTH-5. `verify_strict` rejects small-order/malleable sigs. |
| **P0-DBA-3** | **Per-project keys; cross-project tokens fail closed.** | The engine's JWKS is the one project's key set. A token minted for project B presents an unknown `kid` (or, if kid collides, a bad signature) → deny. Optional `aud=project_id` pin is defense-in-depth. |
| **P0-DBA-4** | **Every entrypoint gates; no unauthenticated bypass when rules are on.** | HTTP `/query`, the binary TCP query/execute path, **and** subscribe all resolve a `Principal` and run the same gate. The TCP path is anonymous-for-life today (no handshake) — a `REQ_AUTH` frame sets the connection principal; queries before auth get the **anonymous** principal (⇒ default-deny under rules), never an implicit allow. |
| **P0-DBA-5** | **Subscribe is not a read-rule bypass.** | A subscription is a standing read. The security-critical hook is a **per-event** principal filter beside `filter.matches` (`rhypedb-subscribe`): an event is delivered only if the subscriber's principal passes the **read** rule for that specific object/type. Subscribe-time also gates the `subscribe` op. Without the per-event filter, a sub streams rows the principal can't read. |
| **P0-DBA-6** | **Write rules see the PRE-mutation object.** | `update`/`delete`/`unlink` rules like `request.auth.uid == resource.author` must evaluate against the object **as it exists before** the write (else an attacker rewrites `author` to themselves in the same update). The gate fetches-then-checks before the mutating engine call. `create` rules see only `request.*` (no prior resource). |
| **P0-DBA-7** | **Rules are default-deny on evaluation error + resource-bounded.** | A rule that errors (missing field, type mismatch, traversal over-budget) **denies**, never allows. Rule-driven edge traversals are bounded by the same [`Governor`] budgets as queries (a rule can't become an unmetered fan-out DoS). |
| **P0-DBA-8** | **Fail-closed everywhere; rules load is fail-closed.** | Malformed rules file → the server **refuses to start** (not "start open"). Unknown op/type in a rule → compile error. No/invalid JWKS with rules on → refuse to start. A verify failure → anonymous principal (⇒ default-deny), not an allow. |

No new host/guest seam: P4 is entirely inside the guest engine. The jkbase host changes at P4 are
config-plumbing only (bake the JWKS + rules file into the DB VM via the existing reserved metadata
channel — the `StorageBinding`/`_database.json` pattern) and land alongside; the untrusted-client
edge is **P5**.

---

## 3. The rules language (DECISION 1) — Firestore-familiar, relationship-aware

A project ships an optional `rules.rhype` (already plumbed through jkbase deploy as
`[database].rules`, baked into the DB VM's metadata image; unused until now). Grammar:

```
rules  := stmt*
stmt   := "match" TypeName "{" allow* "}"
allow  := "allow" ops ":" "if" expr ";"
ops    := op ("," op)*
op     := "read" | "create" | "update" | "delete" | "subscribe"        // "write" = create,update,delete
expr   := or
or     := and ("||" and)*
and    := cmp ("&&" cmp)*
cmp    := unary (("==" | "!=" | "<" | "<=" | ">" | ">=" | "in") unary)?
unary  := "!" unary | primary
primary:= literal | path | "(" expr ")"
path   := ident ("." ident)*        // request.auth.uid, resource.author, resource.org.name, request.title
literal:= string | number | bool | "null"
```

**Bound names in scope during evaluation:**
- `request.auth` — the principal. `request.auth == null` ⇔ anonymous. `request.auth.uid` = `sub`.
  `request.auth.claims.<k>` = the token's nested custom claim `<k>`.
- `resource.<field>` — a field of the **pre-mutation** stored object (read/update/delete/subscribe).
  `resource.<rel>` where `<rel>` is a **relationship** field resolves to the set of linked target
  ids (or the single id for a 1:1) — this is what makes `uid in resource.owners` a native edge
  traversal (`db.get_links_many`), not a join. One-hop dotted traversal into a linked object's
  scalar (`resource.org.name`) is allowed and bounded by the governor; deeper chains are a
  compile-time error in v1 (kept cheap + analyzable).
- `request.<field>` — the **incoming** field value on a `create`/`update` (so a rule can constrain
  what a write may set, e.g. `request.ownerId == request.auth.uid`).

**Operators.** `==`/`!=` compare scalars (reuse the engine's `compare_values`); `<,<=,>,>=` on
ordered scalars; `in` tests membership of a scalar in a relationship-set or a `Json` array;
`&&`/`||`/`!` boolean; parens. `null` is a first-class literal (anon check + absent-field check).
Everything is **total** — a missing field or a type mismatch yields "deny" for that clause
(P0-DBA-7), never a panic.

**Semantics.** For an op on a type, evaluate each `allow <op>` clause for that type; **any** clause
true ⇒ allow; no clause matches or all false ⇒ **deny** (default-deny, P0-DBA-1). `write` in a rule
expands to `create,update,delete`. A type with a `match` block but no clause for an op denies that
op. A type with **no** `match` block denies **all** ops (default-deny) — *when rules are on*.

**Backward-compat gate (the whole ballgame for not breaking prod).** `ExecContext.rules:
Option<Arc<RulesProgram>>`. `None` ⇒ the executor takes the **exact current code path**, no gate, no
principal check — every existing co-located/dedicated deployment is byte-unchanged. `Some(program)`
⇒ enforce. Rules are configured only by a project that opts in (`[database].rules = "rules.rhype"`),
which no shipping tenant does yet.

---

## 4. Principal threading + the executor gates

### 4.1 The `PrincipalSource` seam (keeps DECISION 2 reversible)
A tiny trait resolves a request's identity into a `Principal`, isolating "how identity arrives" from
"how it's enforced":
```
trait PrincipalSource { fn principal(&self, bearer: Option<&str>) -> Principal; }
struct JwtSource { jwks: Jwks, opts: VerifyOptions }   // P4: verify EdDSA JWT → Principal, else anon
// future: struct HmacHeaderSource { secret: … }        // P0-DB-5 belt-and-suspenders, no engine change
```
The server builds one `JwtSource` from config at boot; entrypoints call `.principal(bearer)` and put
the result on `ExecContext`. Swapping/adding a source never touches the rules engine or the gates.

### 4.2 `ExecContext` (rhypedb-query `executor.rs:60`)
Add two fields:
```
pub principal: Principal,             // anonymous when unauthenticated / rules-off
pub rules: Option<Arc<RulesProgram>>, // None ⇒ enforcement bypassed (compat)
```
The struct already flows by `&ExecContext` into every executor fn, so this threads for free. The
sole constructor `ExecContext::new` (`executor.rs:84`) defaults `principal = Principal::anonymous()`,
`rules = None` (embedded/library callers + all existing tests unchanged). Two production literals get
the real values: HTTP `handle_query` (`lib.rs:279`) and TCP `execute_parsed` (`lib.rs:1755`).

### 4.3 The three gate points (all inside rhypedb-query, principal already in scope)
1. **Pre-execution op/type gate** in `execute()` (`executor.rs:96`), before the pipeline runs.
   Statically classify the `Query` (source + steps) into (op, type) pairs — all knowable from the
   AST with no I/O — and deny early for whole-verb violations (e.g. anon may not `delete` type X).
   Cheap, fail-closed, catches the coarse cases before any row is touched.
2. **Per-object READ gate** after each materialization (`execute_source`/`execute_step`/
   `materialize_ids`, `executor.rs:167,172,230,250,475,889`): filter the produced `Object`s through
   the read rule; a denied object is **dropped from the result** (Firestore semantics: you get the
   rows you may read, not an error) unless the op is a point `get` of a denied id (→ empty/deny).
   Reuse `obj.ensure_fields_deserialized()` + `obj.fields.get()` + `compare_values`; relationship
   predicates drive `db.get_links_many`.
3. **Per-mutation WRITE gate** immediately before `db.update`/`delete`/`link`/`unlink`
   (`executor.rs:521,534,566,579`) and `db.create`/`create_batch` (`executor.rs:214,226`). For
   update/delete/unlink: **fetch the pre-mutation object and check** (P0-DBA-6). For create: check
   `request.*` only. A denied write → `QueryError` (a write is a discrete intent; unlike read it
   fails loudly).

### 4.4 Subscribe (rhypedb-server + rhypedb-subscribe)
- **Subscribe-time:** in the `REQ_SUBSCRIBE` arm (`lib.rs:1649`) gate the `subscribe` op for the
  filter's type against the connection principal; deny → reject the subscription.
- **Per-event (P0-DBA-5, the critical one):** attach the principal (+ an `Arc<RulesProgram>`) to the
  `Subscription`/sink (mirror how `exclude_origin` rides as an in-process-only field). Beside
  `filter.matches` (`rhypedb-subscribe/src/lib.rs:228`) — or in `ConnEventSink::deliver`
  (`lib.rs:1145`) — evaluate the **read** rule for the event's object before delivering. The
  `ChangeEvent` already carries `type_name`, `object_id`, and `fields` (the changed field map), so
  field-only rules evaluate directly; a rule needing an unchanged field or an edge does a bounded
  `db.get`/`get_links` at delivery. Deny → drop the event silently (no leak that it existed).

### 4.5 New wire frame (rhypedb-wire `protocol.rs`)
Add `REQ_AUTH = 0x08` (next free kind; requests are single bytes, not a versioned enum). Payload =
`[tok_len:u32][utf8 bearer token]`. **Back-compat is free:** an old server hits the existing
unknown-kind→`RESP_ERROR` catch-all (`lib.rs:1722`), so a new client detects "auth unsupported"; an
old client never sends it and stays anonymous (⇒ default-deny only if that deployment has rules on,
which an old-client deployment won't). Handle it in the TCP `match frame.kind` (`lib.rs:1409`): parse
+ verify → set the per-connection `principal` (new field near `lib.rs:1281-1303`). A `REQ_AUTH`
failure returns an error frame **without** closing the connection (client may retry), but leaves the
principal anonymous.

### 4.6 Config wiring (rhypedb-server `config.rs` + `AppState`)
Mirror `RHYPEDB_ADMIN_TOKEN` (`config.rs:88` → `AppState.admin_token` `lib.rs:868`), CLI>env>file>
default via `resolve()`:
- `RHYPEDB_RULES` / `--rules <path>` — the compiled `RulesProgram` (parse at boot; **fail-closed** if
  malformed). Absent ⇒ `rules = None` (compat).
- `RHYPEDB_AUTH_JWKS` / `--auth-jwks <path|inline>` — the per-project JWKS (public keys, incl. the
  rotation window). Required if rules are on (else refuse to start, P0-DBA-8).
- `RHYPEDB_AUTH_ISS` / `RHYPEDB_AUTH_AUD` (optional) — pin issuer/audience (defense-in-depth).
`AppState` holds `Arc<RulesProgram>` + the `JwtSource`; both are hot-reloadable on the existing
`reload_lock` path (schema reload already exists — rules/JWKS reload rides it).

---

## 5. Seams (grounded file:line, from the post-P3 recon) — what to touch, in dep order

1. **New crate `rhypedb-authz`** (nothing exists): `Principal`; a **verify-only** JOSE/Ed25519 port
   of jkbase `jose.rs` (`Jwk`/`Jwks`/`Claims`/`verify`, alg-pinned, clock-free core); the rules
   `Lexer`/`Parser`/`RulesProgram` AST + `evaluate(op, type, &Principal, resource_accessor)`. First
   crypto dep in the tree: `ed25519-dalek = "2"` (+ `base64`, `serde`, `serde_json`, `thiserror`, all
   already workspace deps). Depends on `rhypedb-schema` (type/field/relation defs) +
   `rhypedb-wire`/`rhypedb-engine` (`Value`, `Object`) for the resource accessor. **Unit-tested
   standalone** (P4a+P4b); decision-independent for the verify half.
2. **`ExecContext`** — `rhypedb-query/src/executor.rs:60` (+ `new` at `:84`): add `principal`,
   `rules`. §4.2.
3. **Executor gates** — `rhypedb-query/src/executor.rs`: pre-exec `execute()` `:96`; per-object read
   after `:167,172,230,250,475,889`; per-mutation write before `:214,226,521,534,566,579`. §4.3.
   Reuse `evaluate_predicate`/`compare_values` (`:942,964`), `resolve_relation_field` (`:910`),
   `db.get_links_many` (`:430`). Bound rule traversals with the in-scope `ctx.governor`.
4. **HTTP entrypoint** — `rhypedb-server/src/lib.rs:279` (`handle_query`): read `Authorization`
   header → `JwtSource.principal` → into the `ExecContext` literal. `QueryRequest` (`:201`) needs no
   body field (header carries the token).
5. **TCP entrypoint** — `rhypedb-server/src/lib.rs:1755` (`execute_parsed`) + the connection loop
   (`:1305`, `match frame.kind` `:1409`): per-connection `principal` state (`:1281-1303`), handle
   `REQ_AUTH`. §4.5.
6. **Wire** — `rhypedb-wire/src/protocol.rs:106` (kinds) + codec: `REQ_AUTH=0x08` + payload
   encode/decode; strict/fail-closed like `decode_subscribe_filter` (`:850,891`).
7. **Subscribe authz** — `rhypedb-server/src/lib.rs:1649` (subscribe-time gate) + per-event filter at
   `rhypedb-subscribe/src/lib.rs:228` (or `ConnEventSink::deliver` `lib.rs:1145`); principal-aware
   field on `Subscription`/`SubscriptionFilter` (`subscribe/src/lib.rs:37,154`). §4.4.
8. **Config / AppState** — `rhypedb-server/src/config.rs:88-99` (+ `FileConfig`/`resolve`) +
   `AppState` (`lib.rs:864-882`). §4.6. Constant-time compares where relevant (the admin path uses a
   plain `!=` at `admin.rs:88` — don't copy that for any secret compare).

---

## 6. Why P4 is testable without P5 (and mostly without jkbase)

Because the engine verifies the JWT itself (DECISION 2), the whole of P4 is exercisable with a
self-minted keypair: unit + integration tests sign a token with a test Ed25519 key, hand the engine
the matching JWKS + a `rules.rhype`, and assert allow/deny across `/query` (HTTP), the TCP path, and
subscribe — **no P5 gateway, no live `auth.jkbase.app`**. The jkbase-interop proof (P4e) mints a real
token via the shipped P3 issuer and verifies the engine accepts it byte-for-byte (the format is a
faithful port of `jose.rs`). The on-box FC e2e (a `[database]` project with a `rules.rhype` + an app
that presents a token) is the end-to-end proof but is not required to land the engine work.

---

## 7. Phased sub-plan + Overboard

Board `cmr2br5kr00hrk4f3mbnue3ht` (rhypedb), tag `contributed-by-jkbase`. EPIC card
`cmr2br5kt00hwk4f3e1dqaeiz` ("Data-plane authorization — verified principal + default-deny
security-rules engine"). WS `/subscribe` (`cmr2br5kw00i0k4f3lpfoo4zq`) + the `db.` gateway are **P5**,
separate. (Board hygiene: the governor `cmr2br5ks00htk4f3vn7tauyv` and metering
`cmr2br5l300iik4f3wm4rn1uc` cards are shipped-but-unmoved — flip to DONE.)

- **P4a — principal + JWT-verify core.** `rhypedb-authz` crate; `Principal`; verify-only EdDSA JOSE
  (port of `jose.rs`); JWKS load. Unit tests (roundtrip vs a real jkbase-minted token fixture,
  alg-pin, tamper, exp/skew, cross-project kid). *Decision-independent.*
- **P4b — rules language.** Lexer/parser/AST + `evaluate` with the resource accessor + native edge
  traversal + default-deny + total (deny-on-error) semantics. Unit tests (each op, edge membership,
  `request.*` write constraints, malformed-rules-fail-closed).
- **P4c — thread principal + gates.** `ExecContext` fields; the three gate points; the compat
  (`rules=None`) fast path. Executor integration tests (allow/deny read filtering, pre-mutation write
  gate, default-deny).
- **P4d — entrypoints + wire + subscribe + config.** HTTP header; `REQ_AUTH` frame; subscribe
  per-event filter; `config.rs`/`AppState` wiring; hot-reload. Server integration tests across all 3
  entrypoints.
- **P4e — jkbase-interop + on-box e2e + adversarial review.** Real P3 token accepted; FC `[database]`
  project with rules enforcing allow/deny end-to-end. Multi-agent adversarial review (alg-
  substitution, cross-project principal, subscribe read-bypass, write-gate on pre-mutation object,
  fail-open regressions, rule-traversal DoS). Fix all BLOCKER/HIGH before merge.

Then: merge the rhypedb branch as one reviewed unit → publish/point jkbase at the new engine build
(the DB VM's `rhypedb-server` binary is a baked erofs runtime layer → a **toolchain rebake**, per
[[prod-toolchain-rebake-on-build-change]], not just a host-binary swap). jkbase-side P4 wiring (bake
the JWKS + `rules.rhype` into the DB VM's metadata image via the reserved channel; surface
`[database].rules` end-to-end) is small and lands with the rebake. **P5** (WS + `db.` gateway +
console rules/Auth tab) is the next arc.

---

## 8. Verified file references (post-P3 recon, rhypedb `master`)
- Entrypoints: HTTP `handle_query` `rhypedb-server/src/lib.rs:250` (route `:895`), `ExecContext`
  literal `:276-287`; TCP `handle_tcp_connection` `:1246` → `handle_connection_stream` `:1257`, loop
  `:1305`, `match frame.kind` `:1409`, `REQ_QUERY` `:1424`/`REQ_EXECUTE` `:1529`, `execute_parsed`
  `:1748` + `ExecContext` literal `:1755-1761`; subscribe `REQ_SUBSCRIBE` `:1602`, `subscribe_sink`
  `:1649`, `ConnEventSink::deliver` `:1145`.
- `ExecContext` `rhypedb-query/src/executor.rs:60-77`, `new` `:84`; gate points `:96,167,172,214,226,
  230,250,475,521,534,566,579,889`; `evaluate_predicate` `:942`, `compare_values` `:964`,
  `resolve_relation_field` `:910`, `db.get_links_many` `:430`.
- AST `rhypedb-query/src/ast.rs` (`Query` `:5`, `Source` `:13-37`, `Step` `:44-97`); parser
  `parser.rs:28`; error `error.rs:6` (add an authz variant or reuse `Type`).
- Schema `rhypedb-schema/src/types.rs`: `Schema` `:5`, `TypeDef` `:35`, `FieldDef` `:60`, `FieldType`
  `:110`, `RelationType` `:132`, `EdgeFieldDef` `:139`, directives `:151` (`Inverse` `:177`,
  `OnDelete` `:170`).
- Object/Value `rhypedb-wire/src/object.rs`: `Object` `:126`, `FieldMap` `:114`,
  `ensure_fields_deserialized` `:150`, `Value` `:10`, `value_to_query_json` `:95`.
- Wire `rhypedb-wire/src/protocol.rs`: `Frame` `:142`, kinds `:106-135`, `MAX_FRAME_PAYLOAD` `:103`,
  `decode_query_payload` `:690`, `decode_subscribe_filter` `:840`, unknown-kind→Error catch-all
  server-side `lib.rs:1722`.
- Subscribe `rhypedb-subscribe/src/lib.rs`: `SubscriptionHub` `:165`, `subscribe_sink` `:202`,
  `publish` `:222`, `filter.matches` `:228`, `SubscriptionFilter` `:37` (`exclude_origin` in-proc-only
  precedent `:44-55`), `ChangeEvent` `:9` (`origin` `:24`).
- Admin/config `rhypedb-server/src/admin.rs:75-96` (`admin_token` `!=` `:88` — don't copy for
  secrets); `config.rs:88-99` env vars, `resolve()` `:246+`; `AppState` `lib.rs:864-882`
  (`admin_token` `:868`).
- jkbase issuer (P4 must accept its tokens): `jkbase-control/src/jose.rs` (whole file — the port
  source), `Claims` `:107-118`, `verify` `:256-309`, `Jwk`/`Jwks` `:120-164`.
