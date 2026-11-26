//! Runtime VM networking on the host: per-VM TAP devices on the runtime bridge, the slot →
//! {IP, MAC} identity map, and the ebtables L2 source guard that pins each TAP to that identity so a
//! guest cannot spoof another tenant's address.

use anyhow::{Context, Result};
use tracing::info;

pub(crate) async fn setup_tap(tap_name: &str) -> Result<()> {
    let exists = tokio::process::Command::new("ip")
        .args(["link", "show", tap_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?
        .success();

    if !exists {
        run_cmd("ip", &["tuntap", "add", "dev", tap_name, "mode", "tap"]).await?;
        info!(tap_name, "tap device created");
    }

    // (Re)assert master + isolation + IPv6-off UNCONDITIONALLY — not only on fresh
    // creation. A TAP that survives a restart/wake, or one created by an older binary
    // (pre-isolation), must be brought to the current security posture rather than left
    // at whatever it had; all of these are idempotent. Without this, every project
    // already running when this fix first deploys would stay un-isolated.
    run_cmd("ip", &["link", "set", tap_name, "master", "jkbr0"]).await?;
    // Bridge port isolation: isolated ports cannot forward to each other at L2, so one
    // tenant's runtime VM can't reach another's at 172.16.0.x on the shared bridge (the
    // gateway/uplink — a non-isolated port — stays reachable, so egress is unaffected).
    // Fail-closed: if the kernel can't apply it, the deploy fails rather than running a
    // VM with cross-tenant L2 reachability. Port isolation blocks cross-tenant *reach*;
    // the ebtables L2 source-guard installed below closes *spoofing* (the other half).
    run_cmd(
        "ip",
        &[
            "link",
            "set",
            "dev",
            tap_name,
            "type",
            "bridge_slave",
            "isolated",
            "on",
        ],
    )
    .await?;
    // Disable IPv6 on the TAP so a guest can't pivot to metadata/host over v6 around the
    // IPv4-only bridge SSRF DROP (defense in depth — runtime guests also boot
    // ipv6.disable=1). Best-effort: the load-bearing guard is the guest-side disable.
    let _ = run_cmd(
        "sysctl",
        &["-w", &format!("net.ipv6.conf.{tap_name}.disable_ipv6=1")],
    )
    .await;
    run_cmd("ip", &["link", "set", tap_name, "up"]).await?;

    // L2 source-guard (anti IP/MAC spoof): pin this TAP to its deterministic {MAC, IPv4
    // src, ARP src}. Port isolation (above) blocks cross-tenant *reach*; this closes
    // *spoofing* — without it a hostile guest can emit frames bearing another project's
    // source IP, poisoning per-project egress attribution + the bandwidth meter (and any
    // future `-s`-scoped rule). Mirrors the build bridge's JKBUILD_SG. Fail-closed, to
    // match the port-isolation posture above. {ip,mac} derive from the TAP name via the
    // same deterministic octet map as allocate_ip, so setup_tap needs no new args.
    if let Some((ip, mac)) = tap_identity(tap_name) {
        install_tap_source_guard(tap_name, &ip, &mac)
            .await
            .context("install runtime L2 source-guard (is ebtables installed?)")?;
    } else {
        anyhow::bail!(
            "tap {tap_name:?} is outside the tapN scheme — refusing to boot without its L2 source-guard"
        );
    }

    Ok(())
}

pub(crate) async fn teardown_tap(tap_name: &str) -> Result<()> {
    let exists = tokio::process::Command::new("ip")
        .args(["link", "show", tap_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?
        .success();

    if exists {
        run_cmd("ip", &["link", "delete", tap_name]).await?;
        info!(tap_name, "tap device removed");
    }

    Ok(())
}

pub(crate) async fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new(cmd)
        .args(args)
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("{} {:?} failed with {}", cmd, args, status);
    }
    Ok(())
}

/// The ebtables (L2/bridge filter) chain holding the runtime per-TAP source-guard rules.
pub(crate) const RUNTIME_SOURCE_GUARD_CHAIN: &str = "JKRUN_SG";

/// The deterministic identity of a runtime VM slot, keyed by its last IP octet (2..=254).
/// `PlatformState::allocate_ip` and `tap_identity` BOTH go through this single formula, so
/// the L2 source-guard can never pin a different {ip,mac} than the VM was actually given.
pub(crate) fn slot_identity(octet: u8) -> (String, String, String) {
    (
        format!("tap{}", octet - 2),
        format!("172.16.0.{octet}"),
        format!("AA:FC:00:00:00:{octet:02X}"),
    )
}

/// Derive a runtime TAP's deterministic `(ipv4, mac)` from its name (the inverse of the
/// `slot_identity` map). Because that map is a bijection, a TAP's source-guard rules are
/// stable across project churn — so they need no teardown (a deleted TAP's rules match
/// nothing; a reused octet gets the identical {ip,mac}).
pub(crate) fn tap_identity(tap: &str) -> Option<(String, String)> {
    let n: u16 = tap.strip_prefix("tap")?.parse().ok()?;
    let octet = n.checked_add(2)?;
    if octet > 254 {
        return None;
    }
    let (_, ip, mac) = slot_identity(octet as u8);
    Some((ip, mac))
}

/// Serializes all runtime ebtables edits. The nf_tables ebtables backend does a whole-
/// ruleset read-modify-write per call, so concurrent project wakes (proxy-driven, routine)
/// clobber each other (verified: 20 concurrent `-A` → only 2 land; `--concurrent` does not
/// help). Held across the chain-ensure + per-TAP rule installs.
pub(crate) static RUNTIME_EBTABLES_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

pub(crate) fn runtime_ebtables_lock() -> &'static tokio::sync::Mutex<()> {
    RUNTIME_EBTABLES_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Ensure the runtime source-guard chain exists and is hooked into the L2 INPUT (frames
/// to the gateway/host) + FORWARD (VM↔VM, already port-isolated — defense in depth) paths.
/// Do NOT flush: unlike the build guard (a static pool repopulated at startup), runtime
/// TAPs are pinned lazily in `setup_tap`, so flushing here would drop active TAPs' rules
/// until their next wake. Idempotent: `-N` ignores "exists", the hook is `-C`-guarded.
/// Rules match `-i tap*`, so build-bridge (`jkbld*`) frames fall straight through.
pub(crate) async fn ensure_runtime_source_guard_chain() -> Result<()> {
    let _ = run_ebtables(&["-t", "filter", "-N", RUNTIME_SOURCE_GUARD_CHAIN]).await;
    for hook in ["INPUT", "FORWARD"] {
        if !ebtables_ok(&[
            "-t",
            "filter",
            "--check",
            hook,
            "-j",
            RUNTIME_SOURCE_GUARD_CHAIN,
        ])
        .await
        {
            run_ebtables(&["-t", "filter", "-I", hook, "-j", RUNTIME_SOURCE_GUARD_CHAIN])
                .await
                .with_context(|| format!("hook runtime source-guard into ebtables {hook}"))?;
        }
    }
    Ok(())
}

/// Install the per-TAP L2 source-guard: DROP any frame on `tap` not bearing this slot's
/// source MAC / IPv4 source / ARP source, plus DROP 802.1Q VLAN-tagged frames outright (a
/// tagged frame's outer ethertype is 0x8100, so `-p IPv4`/`-p ARP` would skip the source
/// pins). Idempotent (`-C` before `-A`), so re-asserting a surviving TAP on wake is a
/// no-op. Mirrors `build_orchestrator::ensure_source_guard` rule-for-rule.
pub(crate) async fn install_tap_source_guard(tap: &str, ip: &str, mac: &str) -> Result<()> {
    let _guard = runtime_ebtables_lock().lock().await;
    ensure_runtime_source_guard_chain().await?;
    let rules: [Vec<&str>; 4] = [
        vec!["-i", tap, "-p", "802_1Q", "-j", "DROP"],
        vec!["-i", tap, "!", "-s", mac, "-j", "DROP"],
        vec!["-i", tap, "-p", "IPv4", "!", "--ip-src", ip, "-j", "DROP"],
        vec![
            "-i",
            tap,
            "-p",
            "ARP",
            "!",
            "--arp-ip-src",
            ip,
            "-j",
            "DROP",
        ],
    ];
    for r in &rules {
        let mut check = vec!["-t", "filter", "--check", RUNTIME_SOURCE_GUARD_CHAIN];
        check.extend_from_slice(r);
        if !ebtables_ok(&check).await {
            let mut add = vec!["-t", "filter", "-A", RUNTIME_SOURCE_GUARD_CHAIN];
            add.extend_from_slice(r);
            run_ebtables(&add).await?;
        }
    }
    Ok(())
}

/// Run an ebtables command, erroring on failure (fail-closed). Distinct from the build
/// orchestrator's own copy so the runtime guard does not couple to that module.
pub(crate) async fn run_ebtables(args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new("ebtables")
        .args(args)
        .status()
        .await
        .context("spawn ebtables")?;
    if !status.success() {
        anyhow::bail!("ebtables {args:?} failed: {status}");
    }
    Ok(())
}

/// True iff the ebtables command succeeds — for `-C` existence checks; never errors.
pub(crate) async fn ebtables_ok(args: &[&str]) -> bool {
    tokio::process::Command::new("ebtables")
        .args(args)
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod source_guard_tests {
    use super::{slot_identity, tap_identity};

    #[test]
    fn tap_identity_inverts_slot_identity_over_all_octets() {
        // The two octet maps live ~1900 lines apart; this binds them so the source-guard
        // can never pin a different {ip,mac} than allocate_ip handed the VM.
        for octet in 2u8..=254 {
            let (tap, ip, mac) = slot_identity(octet);
            assert_eq!(
                tap_identity(&tap),
                Some((ip, mac)),
                "tap_identity must invert slot_identity for octet {octet}"
            );
        }
    }

    #[test]
    fn tap_identity_rejects_out_of_range_and_malformed() {
        assert_eq!(tap_identity("tap253"), None); // octet 255 > 254
        assert_eq!(tap_identity("eth0"), None);
        assert_eq!(tap_identity("tapX"), None);
        assert_eq!(tap_identity("tap"), None);
    }
}
