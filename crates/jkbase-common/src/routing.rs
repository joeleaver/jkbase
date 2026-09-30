//! Shared routing types used by both the proxy (reader) and the control plane
//! (writer) so the in-memory domain map they share is the same concrete type.

use serde::{Deserialize, Serialize};

/// Resolution target for a claimed host: which project owns it (so the proxy can
/// wake the right VM even while hibernated) and which site within that project
/// the host serves (`None` = the default site).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainTarget {
    pub project_id: String,
    pub site: Option<String>,
    /// Wildcard domains only: the random per-domain label the tenant's
    /// `_acme-challenge.<base>` CNAMEs to (under the platform's ACME delegation zone).
    /// The cert manager publishes the DNS-01 TXT there and NOWHERE else — the name is
    /// minted server-side, never tenant-chosen. `None` for every exact host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_delegation: Option<String>,
}

/// Domain-map key prefix of a wildcard registration (`*.sub.example.com`). An exact
/// host can never carry it: control rejects `*` in exact names, so the two key spaces
/// in the one map are disjoint.
pub const WILDCARD_PREFIX: &str = "*.";

/// Canonical form of a client-supplied host (`Host` header minus port, or SNI): ASCII
/// lowercase with one trailing root dot removed. Every key in the domain map is stored
/// in this form, so `Abc.Play.Example.com.` and `abc.play.example.com` resolve alike.
pub fn normalize_host(host: &str) -> String {
    let h = host.strip_suffix('.').unwrap_or(host);
    h.to_ascii_lowercase()
}

/// The ONE wildcard key that may cover `host`: strip exactly one leading label and
/// prefix `*.` (RFC 6125 §6.4.3 — a wildcard spans a single label, so
/// `a.b.sub.example.com` looks up `*.b.sub.example.com`, never `*.sub.example.com`).
/// `None` when there is no label to strip, the label is empty or itself `*`, or the
/// remainder has fewer than two labels (wildcard bases are never TLD-ish). A single
/// hash lookup per request — no suffix scan.
pub fn wildcard_key(host: &str) -> Option<String> {
    let (label, rest) = host.split_once('.')?;
    if label.is_empty() || label == "*" || rest.is_empty() || rest.starts_with('.') {
        return None;
    }
    if !rest.contains('.') {
        return None;
    }
    Some(format!("{WILDCARD_PREFIX}{rest}"))
}

/// Whether a domain-map key is a wildcard registration.
pub fn is_wildcard_key(key: &str) -> bool {
    key.starts_with(WILDCARD_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercases_and_drops_one_root_dot() {
        assert_eq!(
            normalize_host("Abc.Play.Example.COM."),
            "abc.play.example.com"
        );
        assert_eq!(
            normalize_host("abc.play.example.com"),
            "abc.play.example.com"
        );
        assert_eq!(normalize_host(""), "");
    }

    #[test]
    fn wildcard_key_strips_exactly_one_label() {
        assert_eq!(
            wildcard_key("abc.sub.example.com").as_deref(),
            Some("*.sub.example.com")
        );
        // Single-level only: the deeper host maps to a DIFFERENT (deeper) key.
        assert_eq!(
            wildcard_key("a.b.sub.example.com").as_deref(),
            Some("*.b.sub.example.com")
        );
        // Nothing to strip / TLD-ish remainder / degenerate labels.
        assert_eq!(wildcard_key("localhost"), None);
        assert_eq!(wildcard_key("example.com"), None);
        assert_eq!(wildcard_key(".sub.example.com"), None);
        assert_eq!(wildcard_key("a..example.com"), None);
        assert_eq!(wildcard_key("*.sub.example.com"), None);
        assert_eq!(wildcard_key("abc."), None);
    }
}
