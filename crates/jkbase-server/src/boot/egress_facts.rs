//! Host-asserted platform egress facts handed to every guest agent.

use crate::cli::Args;
use jkbase_common::config::PlatformEgress;
use tracing::{info, warn};

/// Host-asserted platform egress facts, computed once. The OWN object-store host is
/// `storage.{domain}`; the Zone-2 deny-set is the host's own public uplink IP(s).
///
/// ALWAYS union the operator's --platform-ips with auto-discovery (never replace) — review
/// M-1. tools/setup-bridge.sh independently opens guest→PUB_IP:80,443 for EVERY global IP on
/// the uplink (its own discovery), so if an operator passed a NARROWER explicit list the
/// agent's deny-set could miss a secondary/failover IP the firewall still exposes → a
/// function could reach the control-plane proxy on that IP. Unioning guarantees the agent
/// deny-set ⊇ the discovered uplink set the firewall allows, closing the desync; --platform-ips
/// only ADDS (e.g. an IP behind NAT that discovery can't see), never subtracts.
pub(crate) fn platform_egress(args: &Args) -> PlatformEgress {
    let mut platform_ips = discover_uplink_ips();
    for ip in &args.platform_ips {
        if !platform_ips.contains(ip) {
            platform_ips.push(ip.clone());
        }
    }
    if platform_ips.is_empty() {
        // The netfilter fence ALLOWS guest→public-IP:80,443 (servers reach the object-store /
        // own-sites through the proxy there), so the agent's platform-IP list is the ONLY
        // layer denying a function the control plane on those ports. Empty = that agent-side
        // Zone-2 deny is disabled — loudly flag it (the control API is still loopback-bound +
        // auth-gated, but this is a real gap to close before tenant exposure).
        warn!(
            "no platform uplink IPs (auto-discovery empty and --platform-ips unset); function egress Zone-2 deny by IP is DISABLED — set --platform-ips"
        );
    } else {
        info!(ips = ?platform_ips, "platform egress deny-set (Zone-2 platform IPs)");
    }
    PlatformEgress {
        storage_host: Some(format!("storage.{}", args.domain)),
        platform_ips,
    }
}

/// Discover the host's public uplink IPv4(s): the global-scope addresses on the
/// default-route interface. Mirrors `tools/setup-bridge.sh` (`ip route show default` →
/// `ip -4 -o addr show $IFACE scope global`). Fail-soft: returns empty on any error (the
/// caller warns), never a partial/garbage IP. Used to build the agent's Zone-2 deny-set.
fn discover_uplink_ips() -> Vec<String> {
    let iface = match std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            // "default via <gw> dev <iface> ..." — take the token after `dev`.
            text.lines().next().and_then(|l| {
                let mut it = l.split_whitespace();
                while let Some(tok) = it.next() {
                    if tok == "dev" {
                        return it.next().map(str::to_string);
                    }
                }
                None
            })
        }
        _ => None,
    };
    let Some(iface) = iface else {
        return Vec::new();
    };
    match std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", &iface, "scope", "global"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                // "<n>: <iface>    inet <ip>/<prefix> ..." — take the addr after `inet`,
                // strip the prefix, and only keep a parseable IPv4.
                let mut it = l.split_whitespace();
                while let Some(tok) = it.next() {
                    if tok == "inet" {
                        let addr = it.next()?.split('/').next()?;
                        if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                            return Some(addr.to_string());
                        }
                    }
                }
                None
            })
            .collect(),
        _ => Vec::new(),
    }
}
