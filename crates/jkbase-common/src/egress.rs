//! Shared egress SSRF / allowlist logic — the SINGLE source of truth for "is this
//! destination safe to egress to", used by BOTH the build egress proxy (jkbase-server)
//! and the function-runtime egress gate (jkbase-agent), so the two fences apply
//! byte-identical public-IP classification (P0-EGRESS-SHAREDLOGIC). Pure std; no deps.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// True if `ip` is a globally-routable public address safe to egress to. Default
/// **deny**: only addresses that are clearly public unicast pass. v4-mapped IPv6
/// is canonicalized first so `::ffff:169.254.169.254` is caught as the metadata
/// IP. This is the load-bearing SSRF check — keep it conservative.
pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4_is_public(v4),
        IpAddr::V6(v6) => v6_is_public(v6),
    }
}

fn v4_is_public(ip: Ipv4Addr) -> bool {
    // std-stable categories: loopback (127/8), private (10/8, 172.16/12,
    // 192.168/16), link-local (169.254/16 — incl. 169.254.169.254 metadata),
    // broadcast (255.255.255.255), unspecified (0.0.0.0), multicast (224/4),
    // documentation (192.0.2/24, 198.51.100/24, 203.0.113/24).
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_documentation()
    {
        return false;
    }
    let o = ip.octets();
    // Ranges not covered by the stable std helpers:
    if o[0] == 0 {
        return false; // 0.0.0.0/8 "this network"
    }
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        return false; // 100.64.0.0/10 CGNAT
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false; // 192.0.0.0/24 IETF protocol assignments
    }
    if o[0] == 192 && o[1] == 88 && o[2] == 99 {
        return false; // 192.88.99.0/24 6to4 relay anycast
    }
    if o[0] == 198 && (o[1] & 0xfe) == 18 {
        return false; // 198.18.0.0/15 benchmarking
    }
    if o[0] >= 240 {
        return false; // 240.0.0.0/4 reserved
    }
    true
}

fn v6_is_public(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let seg = ip.segments();
    // Allow ONLY global unicast 2000::/3, which excludes ULA (fc00::/7) and
    // link-local (fe80::/10) by construction; then carve out documentation and
    // 6to4 (which embeds a v4 that could be private/metadata).
    if (seg[0] & 0xe000) != 0x2000 {
        return false;
    }
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false; // 2001:db8::/32 documentation
    }
    if seg[0] == 0x2002 {
        return false; // 2002::/16 6to4
    }
    true
}

/// Exact, case-insensitive allowlist match (trailing dot tolerated). Never does
/// suffix/subdomain matching — `crates.io.evil.com` must not pass for `crates.io`.
pub fn host_allowed(host: &str, allowlist: &[String]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    allowlist.iter().any(|a| a.eq_ignore_ascii_case(&h))
}

/// First public, egress-safe address from a resolved set (the pinned target).
/// `None` if every resolved address is non-public (a rebind/SSRF attempt).
pub fn pick_safe_addr<I: IntoIterator<Item = SocketAddr>>(addrs: I) -> Option<SocketAddr> {
    addrs.into_iter().find(|a| ip_is_public(a.ip()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_vs_private_classification() {
        assert!(ip_is_public(ip("140.82.112.3")));
        assert!(ip_is_public(ip("8.8.8.8")));
        assert!(!ip_is_public(ip("10.0.0.1")));
        assert!(!ip_is_public(ip("172.16.0.1")));
        assert!(!ip_is_public(ip("192.168.1.1")));
        assert!(!ip_is_public(ip("169.254.169.254"))); // cloud metadata
        assert!(!ip_is_public(ip("127.0.0.1")));
        assert!(!ip_is_public(ip("100.64.0.1"))); // CGNAT
        assert!(!ip_is_public(ip("::ffff:169.254.169.254"))); // v4-mapped metadata
        assert!(!ip_is_public(ip("fd00::1"))); // ULA
        assert!(!ip_is_public(ip("fe80::1"))); // link-local
        assert!(ip_is_public(ip("2606:4700::1111"))); // public v6
    }

    #[test]
    fn host_allowed_is_exact_not_suffix() {
        let al = vec!["crates.io".to_string(), "registry.npmjs.org".to_string()];
        assert!(host_allowed("crates.io", &al));
        assert!(host_allowed("CRATES.IO.", &al)); // case + trailing dot tolerated
        assert!(!host_allowed("crates.io.evil.com", &al)); // suffix attack
        assert!(!host_allowed("sub.crates.io", &al)); // not exact
        assert!(!host_allowed("169.254.169.254", &al));
    }

    #[test]
    fn pick_safe_addr_skips_unsafe() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:443".parse().unwrap(),
            "169.254.169.254:443".parse().unwrap(),
            "140.82.112.3:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ];
        assert_eq!(
            pick_safe_addr(addrs).map(|a| a.ip()),
            Some(ip("140.82.112.3"))
        );
        let unsafe_only: Vec<SocketAddr> = vec![
            "10.0.0.1:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        assert!(pick_safe_addr(unsafe_only).is_none());
    }
}
