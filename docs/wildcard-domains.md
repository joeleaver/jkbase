# Wildcard custom domains (`*.sub.example.com`)

**Status:** implemented. User-facing docs: README → "Wildcard domains".

## Why

A tenant that mints a new origin per upload (DevelUp serves each game build from
`<buildId>.play.develup.win`, all handled by one server app keyed on `Host`) could not be hosted:
jkbase routed only exact registered hosts plus flat `<label>.<platform>` subdomains, and even a
per-upload `domain add` would need a TXT proof and an HTTP-01 cert per name.

## Design as built

- **Registry.** A new `DomainKind::Wildcard`; the record's key is the literal `*.<base>`, in the same
  DOMAINS table and the same global-uniqueness claim as every other host. `DomainRecord` gains
  `acme_delegation: Option<String>` (`#[serde(default)]`, skipped when `None`): pre-wildcard rows load
  unchanged and exact rows re-serialize byte-identically.
- **Names** (`jkbase-control/src/domain_name.rs`). `*.` must be the entire leftmost label; the base
  must be an LDH name with ≥2 labels and an alphabetic TLD, not on/under the platform domain, not an
  ancestor of it, not a two-label `<generic-SLD>.<ccTLD>` (`co.uk`, `com.au`, …) and not a listed
  shared-hosting suffix (`github.io`, …). Exact custom names are now LDH-validated too, which is what
  keeps `*` out of the exact key space. There is **no Public Suffix List** in the workspace; the
  suffix check is deliberately conservative and not exhaustive — the DNS-TXT proof is the boundary.
- **Ownership.** Same mechanism as custom domains: TXT `_jkbase-challenge.<base>` = the record's
  token. On a TLS server `verify` *also* requires `_acme-challenge.<base>` to already CNAME to the
  record's delegation target, so activation never leads to ACME orders that must fail.
- **Cross-kind conflicts.** `*.B` and exact `B` both prove ownership through `_jkbase-challenge.B`, so
  they may not be split across tenants: a claim (and, re-checked atomically in one write txn,
  `activate_domain_exclusive`, a verify) is refused if a *different* tenant holds an **Active** record
  under the other key. Pending records never block — a squatted Pending claim proves nothing. An exact
  `x.B` under someone's `*.B` is allowed (see precedence). The wildcard key itself is first-come unique,
  exactly like exact hosts (same Pending-squat behaviour as today).
- **Routing** (`jkbase-proxy::resolve_domain`). The `Host` is port-stripped, lowercased and root-dot
  trimmed. (1) exact domain-map lookup — platform labels and exact hosts always win; (2) only for
  off-platform hosts, strip exactly one label and look up `*.<rest>`. Two hash lookups, no scan. A host
  containing `*` resolves to nothing. The matched key (not the host) keys the fast-path route table, so
  wake/hibernate need no change. Exact-after-wildcard needs no invalidation: nothing is cached per host.
- **TLS.** `CertManager::ensure_cert` dispatches `*.` keys to `ensure_wildcard_cert`: a DNS-01 order for
  the single identifier `*.<base>`, publishing the TXT at `<label>.<ACME_DELEGATION_ZONE>` through the
  platform's existing `DnsProvider` (Cloudflare / RFC2136 — the zone defaults to
  `_acme-delegation.<domain>`, inside the zone those already write). The CA follows the tenant's CNAME.
  Certs cache under `certs/wildcard/<base>/` and reuse the existing freshness/backoff/reconcile loop.
  SNI: exact per-host cert → platform wildcards → the one tenant wildcard covering the SNI.
- **Status.** The stored record goes Active at verification (that gates routing + issuance, exactly as
  for custom domains). The API reports a wildcard as `pending` / `tls: provisioning` until its cert is
  loaded, then `active` — so "Pending until verification and issuance succeed" holds for the tenant,
  and in TLS mode it isn't reachable before then anyway (no cert; port 80 only redirects).
- **Capability gate.** `AppState.wildcard_support`: `Dns01{zone}` with TLS, `PlainHttp` without (local
  dev: routes on the HTTP port, TXT alone activates, no CNAME asked), `Unsupported` (the fail-closed
  default) → `add`/`verify` answer 501. Today every TLS config carries a DNS-01 backend, so
  `Unsupported` is only reachable by an embedder that doesn't set it.
- **Removal.** `deactivate_host` (domain rm and project delete) also calls `cert_remove` →
  `CertManager::forget_cert`: drops the resolver entry, the backoff slot and `certs/wildcard/<base>/`.
  The reconcile loop iterates the domain map, so renewal stops. An issuance that finishes after removal
  re-checks the map and discards its cert.

## Threat notes (tenants are hostile)

| Attack | Why it fails |
|---|---|
| Wildcard over the platform (`*.jkbase.app`, `*.db.jkbase.app`, `*.api.jkbase.app`, the delegation zone) to capture reserved/tenant hosts | Refused by name validation; the proxy also never wildcard-routes a platform host and the SNI resolver classifies platform names before any tenant wildcard (both unit-tested with a planted rogue key). |
| Wildcard *above* the platform (`*.example.com` when the platform is `jkbase.example.com`) | Refused: it would match the platform apex. |
| `*.co.uk`, `*.github.io`, `*.com` | Refused (conservative suffix check); independently unprovable — the registry controls `_jkbase-challenge.<suffix>`. |
| Capture another tenant's exact host with a covering wildcard | Exact lookup always runs first, per request; a later exact registration takes over immediately. |
| Capture `a.b.sub.example.com` with `*.sub.example.com` | One label is stripped, so it looks up `*.b.sub.example.com`. |
| Make the platform publish a DNS-01 answer at a name the tenant chooses | The TXT name is `<label>.<zone>`; the label is 128-bit CSPRNG hex minted by control, validated again in the proxy, and never tenant-supplied. |
| Answer ACME for another tenant's wildcard | Each domain has its own label; a tenant pointing its own `_acme-challenge` at a victim's label gains nothing — the TXT value is the key authorization of the *victim's* order on the platform account. |
| Split one DNS node between tenants (`B` exact vs `*.B`) | Refused against Active records of another tenant, atomically at verify. |
| Resurrect a removed wildcard without proof (stale `project.domains` cache → boot-time grandfathering) | `grandfather_domain` skips any host containing `*`. |
| Path traversal through the cert cache | Names are LDH-validated in control; `cert_cache_dir` re-checks before any write/`remove_dir_all`. |
| Burn the platform ACME account's rate limits with never-completing wildcards | `verify` requires the CNAME before activation; failures back off per host (`ISSUE_BACKOFF`). A tenant can still verify, then delete the CNAME: that costs one failed order per 5 min per wildcard — the same exposure custom domains (HTTP-01) already have. |

Tenant-side caveat (README): a wildcard **CNAME** for `*.<base>` also answers TXT lookups for every
unset name under `<base>`, including `_jkbase-challenge.<x>.<base>`; point it only at a name whose TXT
you control, or use A/AAAA.

## Known limits / open

- Rollback: a binary from before this change cannot parse `"kind":"wildcard"`. The old
  `list_all_domains` fails the whole listing on one bad row, so rolling back with any wildcard stored
  would boot with an **empty domain map** (every tenant 404s). This change makes the new binary skip
  undecodable rows, but that can't be retrofitted into old binaries — delete wildcard rows first.
- The ACME flow has no test double (`instant_acme::Account` talks to a real CA), so DNS-01 issuance is
  covered in pieces: order/challenge-name construction, delegation-label validation, and that the
  RFC2136 backend accepts the delegated name. Not exercised against Pebble/LE staging.
- No per-tenant cap on wildcard count (none exists for custom domains either).
