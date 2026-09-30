# Wildcard custom domains (`*.sub.example.com`)

**Status:** implemented; revised after adversarial review. User-facing docs: README → "Wildcard domains".

## Why

A tenant that mints a new origin per upload (DevelUp serves each game build from
`<buildId>.play.develup.win`, all handled by one server app keyed on `Host`) could not be hosted:
jkbase routed only exact registered hosts plus flat `<label>.<platform>` subdomains, and even a
per-upload `domain add` would need a TXT proof and an HTTP-01 cert per name.

## Design as built

- **Registry.** A new `DomainKind::Wildcard`, keyed by the literal `*.<base>` in its **own redb table**
  (`wildcard_domains`), which a pre-wildcard binary never opens (see Rollback). Exact keys never
  contain `*`, so the two tables' key spaces are disjoint and uniqueness needs no cross-table check.
  `DomainRecord` gains `acme_delegation: Option<String>` (`#[serde(default)]`, skipped when `None`), so
  pre-change rows load unchanged and exact rows re-serialize byte-identically. `DomainKind` and
  `DomainStatus` gain `#[serde(other)] Unknown`, so a kind or status added by a *future* binary
  decodes (never routed, never activated) instead of failing the listing after a rollback.
- **Names** (`jkbase-control/src/domain_name.rs`). `*.` must be the entire leftmost label; the base
  must be an LDH name with ≥2 labels and an alphabetic TLD, not on/under the platform domain, not an
  ancestor of it, not a two-label `<generic-SLD>.<ccTLD>` (`co.uk`, `com.au`, …) and not a listed
  shared-hosting suffix (`github.io`, …). Exact custom names and platform labels are LDH-validated too
  (platform labels use the project-id alphabet `[a-z0-9-]{1,63}`), which keeps `*` out of the exact
  key space and `_` (the delegation zone's label) out of the tenant namespace. There is **no Public
  Suffix List** in the workspace; the suffix check is deliberately conservative and not exhaustive —
  the DNS-TXT proof is the boundary.
- **Ownership.** Same mechanism as custom domains: TXT `_jkbase-challenge.<base>` = the record's
  token. On a TLS server `verify` *also* requires `_acme-challenge.<base>` to already CNAME to the
  record's delegation target. A wildcard's token and delegation label are the tenant's **claim
  proof**: HMAC-SHA256 under a platform secret (`platform_secrets` table, minted once, never leaves
  the store) over (tenant, host, generation). They're deterministic, so re-claiming an unverified
  name (or a squatter re-taking its pending row) never changes the records a tenant published, and
  unguessable across tenants. The **generation** (`claim_generations` table, per tenant and host) is
  bumped in the same txn whenever a *verified* wildcard is released: removal, project delete, or the
  boot purge of an orphan. Records a former owner left in DNS then prove nothing for them, so they
  can't re-snipe the name from its next claimant (review N1). Pending releases don't bump it. Rows
  written before this keep their stored values; no migration. Users are told to delete the TXT and
  `_acme-challenge` CNAME after removing a domain.
- **Claims** (`Store::claim_wildcard`, one write txn). Per tenant: at most 5 pending wildcards and
  `MAX_WILDCARD_DOMAINS_PER_TENANT` (default 20) in total. **Proof wins:** adding a name another tenant
  holds as a *pending* claim answers 202 with the caller's own records (nothing is stored), and
  `verify` succeeds over that foreign pending row as soon as the caller's proof is in DNS
  (`Store::activate_claim` swaps the row in its txn, if it's still the pending row that was read,
  and within the caller's cap). A pending claim older than 15 minutes can also be replaced outright,
  so the owner can see it in their list. A squatter re-taking the row gains nothing: the owner's
  records never rotate. Active rows are never replaceable. (Exact hosts keep today's first-come
  behaviour; see Open.)
- **Activation** (`Store::activate_domain_exclusive`, one write txn over both tables). Verify reads
  the claim, awaits DNS, then flips it Active only if the row is **still that same pending claim**
  (tenant, project, token): a removal, project delete or takeover during the DNS wait yields `Stale`
  (409) and writes nothing. In the same txn it refuses if a *different* tenant holds `B` or `*.B`
  Active — both prove ownership through `_jkbase-challenge.B`, so they can't be split across tenants.
  Pending rows never block. An exact `x.B` under someone's `*.B` is allowed (see precedence).
- **Routing** (`jkbase-proxy::resolve_domain`). The `Host` is port-stripped, lowercased and root-dot
  trimmed. (1) exact domain-map lookup — platform labels and exact hosts always win; (2) only for
  off-platform hosts, strip exactly one label and look up `*.<rest>`. Two hash lookups, no scan. A host
  containing `*` resolves to nothing. The matched key keys the fast-path route table, so wake /
  hibernate need no change. Exact-after-wildcard needs no invalidation: nothing is cached per host.
- **TLS.** `CertManager::ensure_cert` dispatches `*.` keys to `ensure_wildcard_cert`: a DNS-01 order for
  the single identifier `*.<base>`, publishing the TXT at `<label>.<ACME_DELEGATION_ZONE>` through the
  platform's existing `DnsProvider` (Cloudflare / RFC2136; the zone defaults to
  `_acme-delegation.<domain>`, inside the zone those already write). The CA follows the tenant's CNAME.
  Certs cache under `certs/wildcard/<base>/`. SNI: exact per-host cert → platform wildcards → the one
  tenant wildcard covering the SNI.
- **ACME budget.** Every tenant cert order (custom HTTP-01 and wildcard DNS-01, issuance, renewal,
  retry, and orders triggered by verify) passes, in cost order (`CertManager::gate_tenant_order`):
  1. the host's own backoff slot. It backs off exponentially from 5 min, doubling to a 24 h cap. A
     wildcard gives up after 8 consecutive failures (~10.5 h); a custom domain keeps retrying at the
     cap. This state persists in `certs/issue-health.json`, so a restart re-arms nothing;
  2. free DNS pre-checks through the same DoH resolver `verify` uses: for a wildcard, that
     `_acme-challenge.<base>` still CNAMEs to its delegated name; for both kinds, an RFC 8659 CAA
     check (tree-climbing, `issuewild` for wildcards) that Let's Encrypt may issue. A CAA
     `issue ";"` is refused here instead of failing at the CA;
  3. a **global token bucket** for tenant orders: `TENANT_ACME_ORDERS_PER_3H`, default 60, refilled
     evenly. Platform certs (apex, `*.db`) never draw from it, so the rest of the account's limit
     (Let's Encrypt: 300 / 3 h) stays reserved for them. It's in memory; restarts aren't tenant-
     triggerable;
  4. the owner's **persisted per-tenant budget**: `TENANT_ACME_ORDERS_PER_DAY`, default 20 per
     sliding 24 h, stored per tenant in `tenant_acme_orders`. Removing and re-adding domains, or a
     restart, refunds nothing. Over budget, the host is parked until the next slot frees, and the
     API reports `tls: failed` with `tls_error` naming that time.
  Re-verify re-arms a stopped cert (resets its backoff and give-up) only when the tenant's budget
  has room; otherwise it answers 429 with the retry time. The reconcile loop runs at most 4 due
  wildcard orders per tick, concurrently, alongside the serial custom-domain pass.
- **Status.** The stored record goes Active at verification (that gates routing + issuance, exactly as
  for custom domains). The API reports a wildcard as `pending` while `tls` is `provisioning` or
  `failed`, and `active` once a cert serves — so it reads Pending until verification *and* issuance
  succeed. In TLS mode it isn't reachable before then anyway (no cert; port 80 only redirects).
- **Capability gate.** `AppState.wildcard_support`: `Dns01{zone}` with TLS, `PlainHttp` without (local
  dev: routes on the HTTP port, TXT alone activates, no CNAME asked), `Unsupported` (the fail-closed
  default) → `add`/`verify` answer 501.
- **Removal.** `deactivate_host` (domain rm and project delete) also calls `cert_remove` →
  `CertManager::forget_cert`: drops the resolver entry, backoff state and cache dir. The reconcile loop
  iterates the domain map, so renewal stops. An order (DNS-01 *or* HTTP-01) that finishes after removal
  re-checks the map and deletes what it wrote.
- **`project.domains` cache.** Holds only *verified exact* hosts. Wildcards and pending hosts are kept
  out (see Rollback for why).

## Rollback

A pre-wildcard binary never opens `wildcard_domains`, so on rollback **only wildcard hosts stop
routing**; every exact host and platform subdomain keeps working, and project deletes clean up their
exact rows as before. Nothing needs deleting first.

What the old binary *can* do is grandfather: at boot it recreates every `project.domains` entry that
has no DOMAINS row as an **Active custom domain with no token**. That's why the cache never holds
wildcard (or pending) hosts. And on roll-forward, before building the domain map, the new binary runs
`Store::purge_invalid_domain_rows`, which:
- deletes any DOMAINS row whose key contains `*` (the only writer is that grandfathering);
- deletes any wildcard row whose project is gone or now belongs to another tenant (a project the
  old binary deleted, possibly re-created under the same id). A wildcard row it can't *decode* is
  kept and warned about, never deleted: it may be a newer binary's data;
- strips `*` hosts from every `project.domains` cache.

Surviving wildcard rows resume routing and renewal as they were.

Rollback **procedure:** deploy the old binary as usual; tell wildcard owners that their hosts are down
until roll-forward. Don't hand-edit DOMAINS.

## Threat notes (tenants are hostile)

| Attack | Why it fails |
|---|---|
| Wildcard over the platform (`*.jkbase.app`, `*.db.jkbase.app`, `*.api.jkbase.app`, the delegation zone) to capture reserved/tenant hosts | Refused by name validation; the proxy also never wildcard-routes a platform host and the SNI resolver classifies platform names before any tenant wildcard (both unit-tested with a planted rogue key). |
| Wildcard *above* the platform (`*.example.com` when the platform is `jkbase.example.com`) | Refused: it would match the platform apex. |
| `*.co.uk`, `*.github.io`, `*.com` | Refused (conservative suffix check); independently unprovable, since the registry controls `_jkbase-challenge.<suffix>`. |
| Claim the `_acme-delegation` label as a platform subdomain | Platform labels are `[a-z0-9-]` only. |
| Capture another tenant's exact host with a covering wildcard | Exact lookup always runs first, per request; a later exact registration takes over immediately. |
| Capture `a.b.sub.example.com` with `*.sub.example.com` | One label is stripped, so it looks up `*.b.sub.example.com`. |
| Make the platform publish a DNS-01 answer at a name the tenant chooses | The TXT name is `<label>.<zone>`; the label is 128-bit CSPRNG hex minted by control, validated again in the proxy, and never tenant-supplied. |
| Answer ACME for another tenant's wildcard | Each domain has its own label; pointing your own `_acme-challenge` at a victim's label gains nothing, because the TXT value is the key authorization of the *victim's* order on the platform account. |
| Split one DNS node between tenants (`B` exact vs `*.B`) | Refused against Active records of another tenant, atomically at verify. |
| Former owner re-snipes a name with records it left in DNS | Releasing a verified claim rotates that owner's proof generation; the stale records no longer match. |
| Squat a victim's wildcard with an unverifiable claim | Proof wins over any pending row; the owner's records are deterministic, so re-taking the row can't invalidate them; ≤5 pending per tenant. |
| Undo a removal / clobber a new claim by verifying across it | Activation re-reads the row in its txn and refuses a stale claim. |
| Rollback residue: proof-less `*` rows, orphaned wildcards | The cache never holds them; boot purge removes what an old binary left. |
| Burn the shared ACME account's limits (e.g. add → verify → remove over fresh names, with a CAA record that fails every order) | CNAME and CAA pre-checked for free; persisted per-tenant budget (20/day) that removal and restart don't refund; global tenant bucket (60/3 h) reserving the rest of the account for platform certs; persisted backoff/give-up; ≤4 wildcard orders/tick. Re-verify re-arms only within budget. |
| Path traversal through the cert cache | Names are LDH-validated in control; `cert_cache_dir` re-checks before any write/`remove_dir_all`. |

Tenant-side caveat (README): a wildcard **CNAME** for `*.<base>` also answers TXT lookups for every
unset name under `<base>`, including `_jkbase-challenge.<x>.<base>`. Point it only at a name nobody
else can publish TXT under, or use A/AAAA.

## Open / follow-ups

- **Separate ACME account for tenant certs** (recommended): tenant orders still share the platform
  account. The budgets above bound them, and platform certs keep a reserved share, but Let's
  Encrypt's per-account *failed-validation* and *pending-authorization* limits are shared too. Many
  Sybil tenants can also still drain the global tenant bucket, which delays other tenants' certs
  but never the platform's.
- The console shows a 202 "held by another account" add as a banner with the records; verifying it
  is CLI/API only, because the name isn't in the caller's list until they win it. A proof-wins
  takeover starts with no `site` binding.
- Exact custom domains keep first-come Pending claims (no takeover, no caps). The same approach
  would work there but changes long-standing behaviour, so it's left for a separate change.
- The ACME flow has no test double (`instant_acme::Account` talks to a real CA), so DNS-01 issuance is
  covered in pieces: order/challenge-name construction, label validation, the pre-order CNAME check,
  the backoff/give-up state machine, and that the RFC2136 backend accepts the delegated name. Not
  exercised against Pebble or LE staging.
- A replaced pending claimant has to `add` again and publish a new TXT token.
