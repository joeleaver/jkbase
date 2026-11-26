//! L4 (raw UDP) port bookkeeping on the host side: the external-port range and its quarantine,
//! allocation of edge ports and agent-side UDP ports, and reading a deployment's declared `[l4.*]`
//! ports from its `_l4_ports.json` sidecar.

use anyhow::{Context, Result};
use jkbase_common::config::L4Proto;
use jkbase_control::store::PortAllocation;
use std::collections::HashSet;
use std::path::Path;

/// Auto-allocated L4 external-port range. Chosen strictly BELOW the kernel ephemeral range
/// (`ip_local_port_range`, default floor 32768) so `allocate_port` never draws a port the
/// kernel also hands to host outbound sockets — a collision the control-store scan can't
/// see [mechanics H3]. An admin PIN may sit outside this range (e.g. TeamSpeak's 9987).
pub(crate) const L4_PORT_RANGE: std::ops::RangeInclusive<u16> = 20000..=30000;

/// Reuse-cooldown (seconds) for a freed L4 external port [threat M1]: longer than plausible
/// client retransmit / SRV TTL, so a torn-down tenant's stale clients can't have their
/// datagrams admitted into a different tenant that reused the port.
pub(crate) const L4_PORT_QUARANTINE_SECS: u64 = 3600;

/// The kernel's `ip_local_port_range` low bound. The auto L4 range MUST sit strictly below
/// it. Fails closed (a missing/garbled sysctl aborts the L4 allocation rather than risking
/// an overlap that silently steals a kernel ephemeral port).
pub(crate) fn ip_local_port_range_floor() -> Result<u16> {
    let s = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .context("read /proc/sys/net/ipv4/ip_local_port_range")?;
    s.split_whitespace()
        .next()
        .and_then(|t| t.parse::<u16>().ok())
        .context("parse ip_local_port_range low bound")
}

/// Fail closed if the auto L4 port range overlaps the kernel ephemeral range. Checked
/// lazily at first allocation (not unconditionally at startup) so a host that never uses
/// L4 is unaffected by an aggressive local `ip_local_port_range`.
pub(crate) fn validate_l4_port_range() -> Result<()> {
    let floor = ip_local_port_range_floor()?;
    if *L4_PORT_RANGE.end() >= floor {
        anyhow::bail!(
            "L4 auto port range {}..={} overlaps the kernel ephemeral range (ip_local_port_range floor {floor}); \
             lower L4_PORT_RANGE below {floor}",
            L4_PORT_RANGE.start(),
            L4_PORT_RANGE.end(),
        );
    }
    Ok(())
}

/// Candidate external ports for a NEW non-pinned L4 allocation, in try-order. Excludes
/// ports already allocated in THIS host-island, ports still within the reuse-cooldown, and
/// (belt-and-suspenders) the reserved 80/443. Randomized start within the range
/// (`start_offset`) rather than lowest-free, to further cut reuse-collision odds [threat
/// M1]. The caller bind-probes each in order — this is candidate selection only, pure and
/// unit-testable. `now` compares against the quarantine freed-at.
pub(crate) fn l4_port_candidates(
    existing: &[PortAllocation],
    quarantine: &[(u16, u64)],
    host_id: &str,
    now: u64,
    start_offset: u16,
) -> Vec<u16> {
    let used: HashSet<u16> = existing
        .iter()
        .filter(|p| p.host_id.is_empty() || p.host_id == host_id)
        .map(|p| p.external_port)
        .collect();
    let cooling: HashSet<u16> = quarantine
        .iter()
        .filter(|(_, freed)| now.saturating_sub(*freed) < L4_PORT_QUARANTINE_SECS)
        .map(|(port, _)| *port)
        .collect();
    let span = (*L4_PORT_RANGE.end() - *L4_PORT_RANGE.start()) as u32 + 1;
    let base = *L4_PORT_RANGE.start();
    (0..span)
        .map(|i| base + ((start_offset as u32 + i) % span) as u16)
        .filter(|p| !used.contains(p) && !cooling.contains(p) && *p != 80 && *p != 443)
        .collect()
}

/// Bind-probe an L4 external port on the host wildcard: a successful bind (then immediate
/// close) means the port is free of BOTH jkbase allocations and any other host listener /
/// ephemeral socket the control-store scan can't see [mechanics H3]. The real edge socket
/// (L4Ingress) is the true arbiter and fails the deploy loud if it later can't bind; this
/// probe only avoids reserving an obviously-taken port.
pub(crate) fn l4_bind_probe(proto: L4Proto, port: u16) -> bool {
    let addr = (std::net::Ipv4Addr::UNSPECIFIED, port);
    match proto {
        L4Proto::Udp => std::net::UdpSocket::bind(addr).is_ok(),
        L4Proto::Tcp => std::net::TcpListener::bind(addr).is_ok(),
    }
}

/// The next free in-VM transit port for a project's L4 land-forward: distinct from
/// `guest_port` and from the project's other allocations' transit ports. Per-VM namespace
/// (the agent listens on `eth0:agent_udp_port` inside the project's own VM), so only
/// per-project uniqueness matters — not host-island scope.
pub(crate) fn next_agent_udp_port(
    all: &[PortAllocation],
    project_id: &str,
    guest_port: u16,
) -> Result<u16> {
    // Inside the VM the agent land-forward binds `0.0.0.0:agent_udp_port` while EACH stanza's
    // tenant app binds `127.0.0.1:guest_port`. A `0.0.0.0:P` UDP bind conflicts with a
    // `127.0.0.1:P` bind, so the transit port must avoid not just sibling agent ports but EVERY
    // sibling stanza's guest_port too (and this stanza's own) — else a two-port project could
    // seat its agent listener on a port another of its apps already holds, and one of the two
    // binds fails at boot (a silent no-service). Exclude the union across the project.
    let mut used: HashSet<u16> = all
        .iter()
        .filter(|p| p.project_id == project_id)
        .flat_map(|p| [p.agent_udp_port, p.guest_port])
        .collect();
    used.insert(guest_port);
    (40000u16..=40999)
        .find(|p| !used.contains(p))
        .context("no free in-VM transit port for project")
}

/// Read the host-baked `_l4_ports.json` (the tenant's `[l4.*]` declarations) for a
/// project's live deployment, resolved to `(name, proto, guest_port)`. A missing/garbled
/// file ⇒ empty. Entries with an unresolvable proto or a zero/oversize `guest_port` are
/// dropped, and TCP is skipped defensively (preflight already rejected it, but the v1
/// runtime data path is UDP-only). Mirrors [`project_is_dedicated`] — the same
/// tenant-unforgeable sidecar.
/// One tenant-declared `[l4.*]` port, read back from the baked `_l4_ports.json` sidecar. Carries
/// the tenant facts (`name`/`proto`/`guest_port`) plus the RESOLVED per-port tunables
/// (`idle_timeout_secs`/`amp_k`, already clamped at bake) the runtime relay needs — the design's
/// completeness-M1 carriage (§3(b)/§3(d)). A pre-tunable sidecar (older bake) falls back to the
/// `L4PortConfig` defaults so an old image never mis-sizes the relay.
pub(crate) struct L4PortDecl {
    pub(crate) name: String,
    pub(crate) proto: L4Proto,
    pub(crate) guest_port: u16,
    pub(crate) idle_timeout_secs: u64,
    pub(crate) amp_k: u8,
}

pub(crate) fn read_l4_port_decls(data_dir: &Path, project_id: &str) -> Vec<L4PortDecl> {
    let path = data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .join("_l4_ports.json");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&content) else {
        return Vec::new();
    };
    arr.into_iter()
        .filter_map(|v| {
            let name = v.get("name")?.as_str()?.to_string();
            let proto = match v.get("proto")?.as_str()? {
                "udp" => L4Proto::Udp,
                _ => return None, // TCP data path unbuilt in v1; anything else is invalid.
            };
            let guest_port = v.get("guest_port")?.as_u64()?;
            if guest_port == 0 || guest_port > u16::MAX as u64 {
                return None;
            }
            // Older sidecars predate the tunables → resolved defaults (60s idle; amp clamp OFF).
            // Re-clamp defensively even though the bake already clamped — but MATCH
            // `L4PortConfig::amp_k()`: absent/0 ⇒ 0 (clamp disabled, the W-econ default), NOT 1.
            // A stale `.unwrap_or(1)/.clamp(1,3)` here would re-floor a baked `amp_k:0` back to 1
            // and silently re-arm the retired ratio clamp + auto-hibernate kill-switch.
            let idle_timeout_secs = v
                .get("idle_timeout")
                .and_then(|x| x.as_u64())
                .unwrap_or(60)
                .clamp(15, 600);
            let amp_k = v.get("amp_k").and_then(|x| x.as_u64()).unwrap_or(0).min(3) as u8;
            Some(L4PortDecl {
                name,
                proto,
                guest_port: guest_port as u16,
                idle_timeout_secs,
                amp_k,
            })
        })
        .collect()
}

#[cfg(test)]
mod l4_port_decl_tests {
    use super::read_l4_port_decls;
    use std::path::PathBuf;

    /// Write a `_l4_ports.json` sidecar under a scratch data-dir and return `(data_dir, project)`.
    fn stage_sidecar(tag: &str, json: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jkb-l4decl-{tag}"));
        let live = dir.join("hosting").join("proj").join("live");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("_l4_ports.json"), json).unwrap();
        dir
    }

    // The load-bearing regression (BLOCKER, W-econ review): the readback must resolve amp_k the
    // SAME way `L4PortConfig::amp_k()` bakes it — absent/0 ⇒ 0 (clamp OFF, the default), 1..=3 pass,
    // >3 clamps to 3. A stale `.unwrap_or(1)/.clamp(1,3)` here re-floored 0→1 and silently re-armed
    // the retired ratio clamp on every default port.
    #[test]
    fn amp_k_readback_matches_bake_semantics() {
        let dir = stage_sidecar(
            "ampk",
            r#"[
              {"name":"off",   "proto":"udp","guest_port":9987,"idle_timeout":60,"amp_k":0},
              {"name":"absent","proto":"udp","guest_port":9988,"idle_timeout":60},
              {"name":"opt2",  "proto":"udp","guest_port":9989,"idle_timeout":120,"amp_k":2},
              {"name":"hi",    "proto":"udp","guest_port":9990,"idle_timeout":60,"amp_k":250}
            ]"#,
        );
        let decls = read_l4_port_decls(&dir, "proj");
        let k = |name: &str| decls.iter().find(|d| d.name == name).unwrap().amp_k;
        assert_eq!(k("off"), 0, "explicit 0 stays OFF (must not re-floor to 1)");
        assert_eq!(k("absent"), 0, "omitted ⇒ clamp OFF (the W-econ default)");
        assert_eq!(k("opt2"), 2, "explicit in-range opt-in passes through");
        assert_eq!(k("hi"), 3, "out-of-range high clamps to the ceiling");
        // idle stays clamped to [15,600] independently.
        let idle = |name: &str| {
            decls
                .iter()
                .find(|d| d.name == name)
                .unwrap()
                .idle_timeout_secs
        };
        assert_eq!(idle("opt2"), 120);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_sidecar_yields_no_decls() {
        // A project with no sidecar (and thus resolve_spec's `.unwrap_or((60, 0))` fallback) is the
        // clamp-OFF default, never a re-armed clamp.
        let dir = std::env::temp_dir().join("jkb-l4decl-none-xyz");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(read_l4_port_decls(&dir, "proj").is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::store::PortAllocation;

    #[test]
    fn l4_port_candidates_scope_quarantine_and_randomize() {
        let p = |ext: u16, host: &str| PortAllocation {
            project_id: "x".into(),
            name: format!("n{ext}"),
            proto: "udp".into(),
            external_port: ext,
            guest_port: 9987,
            agent_udp_port: 40000,
            pinned: false,
            host_id: host.into(),
            placement_epoch: 0,
        };
        let base = *L4_PORT_RANGE.start();

        // Host-island scoping: a peer's use of a port does NOT remove it from our candidates.
        let existing = vec![p(base, "me"), p(base + 1, "peer")];
        let cands = l4_port_candidates(&existing, &[], "me", 0, 0);
        assert!(!cands.contains(&base), "our own allocated port is excluded");
        assert!(
            cands.contains(&(base + 1)),
            "a peer-island port stays available to us"
        );

        // Quarantine: a still-cooling freed port is skipped; an expired one is offered.
        let now = 10_000_000;
        let q = vec![
            (base + 2, now - 10),                            // cooling (< 3600s) → skip
            (base + 3, now - (L4_PORT_QUARANTINE_SECS + 1)), // expired → offer
        ];
        let cands = l4_port_candidates(&[], &q, "me", now, 0);
        assert!(!cands.contains(&(base + 2)), "cooling port skipped");
        assert!(cands.contains(&(base + 3)), "expired-cooldown port offered");

        // Randomized start: a non-zero offset rotates the try-order (not lowest-first).
        let cands = l4_port_candidates(&[], &[], "me", 0, 5);
        assert_eq!(cands.first(), Some(&(base + 5)));

        // Never offers the reserved ports (they're outside the range anyway, but explicit).
        assert!(!l4_port_candidates(&[], &[], "me", 0, 0).contains(&443));
    }
}
