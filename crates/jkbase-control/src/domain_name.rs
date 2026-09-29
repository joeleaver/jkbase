//! Tenant-supplied domain names → routing host keys.
//!
//! Every name that reaches the DOMAINS registry passes through [`derive_host_key`]. It
//! is the gate that keeps the three key spaces in the one domain map disjoint — bare
//! platform labels (`docs`), exact external hosts (`docs.example.com`) and wildcards
//! (`*.sub.example.com`) — and keeps tenants off the platform's own names. Tenants are
//! hostile: anything a name could be abused as (a path component in the cert cache, a
//! wildcard over `api.`/`storage.`/the `*.db.` zone, a wildcard over a registry suffix)
//! is refused here, before any DNS proof is even attempted.

use crate::store::DomainKind;
use jkbase_common::routing::WILDCARD_PREFIX;

/// Second-level labels that ccTLD registries hand out as public suffixes
/// (`co.uk`, `com.au`, `ac.jp`, `gov.in`, …). A two-label base whose TLD is a
/// two-letter ccTLD and whose first label is one of these is refused as a wildcard
/// base. Deliberately conservative, NOT the Public Suffix List (the workspace has none):
/// the DNS-TXT proof on the base is the real ownership boundary — a registrant can't
/// publish `_jkbase-challenge.co.uk` — so this only fails obviously-wrong input early.
const CCTLD_GENERIC_SLDS: &[&str] = &[
    "ac", "co", "com", "edu", "gov", "govt", "gv", "ltd", "me", "mil", "ne", "net", "nhs", "nic",
    "nom", "or", "org", "plc", "police", "sch",
];

/// Well-known shared-hosting suffixes where anyone can obtain a child name. Not
/// exhaustive (see [`CCTLD_GENERIC_SLDS`] — the TXT proof is the boundary); refused as
/// wildcard bases so a squatted Pending claim can't even sit on them.
const SHARED_HOSTING_SUFFIXES: &[&str] = &[
    "appspot.com",
    "azurewebsites.net",
    "blogspot.com",
    "cloudfront.net",
    "firebaseapp.com",
    "fly.dev",
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "netlify.app",
    "onrender.com",
    "pages.dev",
    "vercel.app",
    "web.app",
    "workers.dev",
];

/// Normalize a user-supplied domain to its routing host-key and classify it.
/// Accepts a bare label (`docs`), a platform host (`docs.jkbase.app`), a full custom
/// domain (`docs.example.com`) or a single-label wildcard (`*.sub.example.com`).
/// Nested platform subdomains and the apex are rejected (flat scheme only).
pub fn derive_host_key(input: &str, platform_domain: &str) -> Result<(String, DomainKind), String> {
    let d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return Err("domain cannot be empty".to_string());
    }
    if let Some(base) = d.strip_prefix(WILDCARD_PREFIX) {
        validate_wildcard_base(base, platform_domain)?;
        return Ok((d, DomainKind::Wildcard));
    }
    if d.contains('*') {
        return Err(
            "'*' is only allowed as the entire leftmost label (e.g. *.sub.example.com)".to_string(),
        );
    }
    let suffix = format!(".{platform_domain}");
    if d == platform_domain {
        return Err("cannot attach the platform apex domain".to_string());
    }
    if let Some(label) = d.strip_suffix(&suffix) {
        if label.is_empty() || label.contains('.') {
            return Err("only flat subdomains (<label>.{platform}) are supported"
                .replace("{platform}", platform_domain));
        }
        return Ok((label.to_string(), DomainKind::Subdomain));
    }
    if d.contains('.') {
        validate_hostname(&d)?;
        Ok((d, DomainKind::Custom))
    } else {
        // bare label → platform subdomain
        Ok((d, DomainKind::Subdomain))
    }
}

/// A wildcard base (`sub.example.com` of `*.sub.example.com`) must be a real external
/// name the tenant can prove, and must not cover anything the platform serves.
fn validate_wildcard_base(base: &str, platform_domain: &str) -> Result<(), String> {
    if base.is_empty() {
        return Err("wildcard needs a base domain (e.g. *.sub.example.com)".to_string());
    }
    if base.contains('*') {
        return Err("only a single leading '*.' label is allowed in a wildcard".to_string());
    }
    // `*.{platform}` and anything under it would shadow `api.`/`storage.`/`console.`,
    // every project subdomain, the `*.db.` reach zone and the ACME delegation zone.
    if base == platform_domain || base.ends_with(&format!(".{platform_domain}")) {
        return Err(format!(
            "wildcards on or under the platform domain ({platform_domain}) are reserved"
        ));
    }
    // A base ABOVE the platform (`*.example.com` over `jkbase.example.com`) would match
    // the platform apex itself.
    if platform_domain.ends_with(&format!(".{base}")) {
        return Err(format!(
            "a wildcard over '{base}' would cover the platform domain ({platform_domain})"
        ));
    }
    validate_hostname(base)?;
    let labels: Vec<&str> = base.split('.').collect();
    if labels.len() < 2 {
        return Err("a wildcard base needs at least two labels (e.g. *.sub.example.com)".into());
    }
    let tld = labels[labels.len() - 1];
    if labels.len() == 2 && tld.len() == 2 && CCTLD_GENERIC_SLDS.contains(&labels[0]) {
        return Err(format!("'{base}' is a public registry suffix"));
    }
    if SHARED_HOSTING_SUFFIXES.contains(&base) {
        return Err(format!("'{base}' is a shared-hosting suffix"));
    }
    // RFC 6125 names are ≤253 octets; leave room for the one label the wildcard spans.
    if base.len() > 253 - 2 {
        return Err("wildcard base is too long".to_string());
    }
    Ok(())
}

/// LDH hostname check for external names: 2+ labels, each 1–63 of `[a-z0-9-]` without
/// a leading/trailing hyphen, ≤253 total, and an alphabetic (or IDNA `xn--`) TLD — so no
/// IP literals, no `*`/`_`/`/`, and nothing that could escape a cert-cache directory.
fn validate_hostname(name: &str) -> Result<(), String> {
    if name.len() > 253 {
        return Err("domain is too long".to_string());
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("'{name}' is not a fully-qualified domain"));
    }
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(format!("'{name}' is not a valid hostname"));
        }
    }
    let tld = labels[labels.len() - 1];
    if !(tld.starts_with("xn--") || tld.bytes().all(|b| b.is_ascii_lowercase())) {
        return Err(format!("'{name}' does not end in a valid top-level domain"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "jkbase.app";

    fn key(input: &str) -> Result<(String, DomainKind), String> {
        derive_host_key(input, P)
    }

    #[test]
    fn exact_forms_keep_their_classification() {
        assert_eq!(key("docs").unwrap(), ("docs".into(), DomainKind::Subdomain));
        assert_eq!(
            key("docs.jkbase.app").unwrap(),
            ("docs".into(), DomainKind::Subdomain)
        );
        assert_eq!(
            key(" Docs.Example.com. ").unwrap(),
            ("docs.example.com".into(), DomainKind::Custom)
        );
        assert!(key("jkbase.app").is_err());
        assert!(key("a.b.jkbase.app").is_err());
    }

    #[test]
    fn exact_names_can_never_collide_with_the_wildcard_key_space() {
        for bad in [
            "a*.example.com",
            "x.*.example.com",
            "foo.*",
            "docs_1.example.com",
            "../../etc.example.com",
            "a/b.example.com",
            "1.2.3.4",
            "-bad.example.com",
        ] {
            assert!(key(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn wildcard_accepted_forms() {
        assert_eq!(
            key("*.play.develup.win").unwrap(),
            ("*.play.develup.win".into(), DomainKind::Wildcard)
        );
        assert_eq!(
            key("*.Sub.Example.COM.").unwrap(),
            ("*.sub.example.com".into(), DomainKind::Wildcard)
        );
        // Two-label base is the minimum.
        assert!(key("*.example.com").is_ok());
        // A ccTLD base that is NOT a generic SLD is a normal registered domain.
        assert!(key("*.play.example.co.uk").is_ok());
        assert!(key("*.example.de").is_ok());
        assert!(key("*.xn--bcher-kva.example").is_ok());
    }

    #[test]
    fn wildcard_rejects_platform_and_reserved_zones() {
        for bad in [
            "*.jkbase.app",
            "*.api.jkbase.app",
            "*.storage.jkbase.app",
            "*.console.jkbase.app",
            "*.db.jkbase.app",
            "*.x.db.jkbase.app",
            "*._acme-delegation.jkbase.app",
        ] {
            assert!(key(bad).is_err(), "{bad} must be rejected");
        }
        // A wildcard ABOVE the platform domain would cover its apex.
        let err = derive_host_key("*.example.com", "jkbase.example.com").unwrap_err();
        assert!(err.contains("cover the platform"), "{err}");
    }

    #[test]
    fn wildcard_rejects_public_suffix_and_tld_ish_bases() {
        for bad in [
            "*.com",
            "*.uk",
            "*.co.uk",
            "*.com.au",
            "*.ac.jp",
            "*.github.io",
            "*.herokuapp.com",
            "*.",
            "*",
            "*.1.2.3",
        ] {
            assert!(key(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn wildcard_rejects_multi_label_and_embedded_stars() {
        for bad in [
            "*.*.example.com",
            "**.example.com",
            "*a.example.com",
            "a.*.example.com",
            "*.sub.*.example.com",
            "*.sub_x.example.com",
        ] {
            assert!(key(bad).is_err(), "{bad} must be rejected");
        }
    }
}
