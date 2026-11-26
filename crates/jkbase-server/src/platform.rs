//! Process-wide runtime state: [`PlatformState`] (every live VM, its lifecycle, incarnation and
//! disk-lease token, plus the host facts each VM is booted from) and the small pure helpers that
//! read or allocate from it.

use crate::{slot_identity};
use crate::l4_ports::{L4_PORT_RANGE, l4_bind_probe, l4_port_candidates, next_agent_udp_port, validate_l4_port_range};
use anyhow::{Context, Result};
use jkbase_common::config::{L4Proto, PlatformEgress};
use jkbase_control::store::{PortAllocation, Store, VmAllocation};
use jkbase_orch::vm::VmInstance;
use jkbase_substrate::{DataDiskProvider, FenceToken, Lease};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmLifecycle {
    Running,
    Hibernated,
    Waking,
    Hibernating,
}

/// True while a wake or hibernate is mid-flight for a VM id. Both drop the platform lock across
/// their slow VM op while still holding the id's data-disk lease (+ for hibernate, a paused-but-
/// alive FC mapping the disk), so anything that would supersede/re-fence that id must wait it out.
pub(crate) fn lifecycle_in_flight(state: Option<&VmLifecycle>) -> bool {
    matches!(
        state,
        Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
    )
}

/// Per-VM-id incarnation markers. A fresh marker is minted at every commit-to-Running (deploy,
/// wake, DB-VM boot, re-adoption) and dropped whenever the VM is retired — superseded, torn down,
/// self-fenced, force-stopped or hibernated. `hibernate_project` drops the lock across its
/// pause+snapshot: it captures the marker up front and, on relocking, acts only if it is STILL
/// current. Otherwise the VM it paused was retired under it and the id's `disk_tokens` / `vms` /
/// `vm_states` / snapshot meta now belong to a newer incarnation (or to nobody) — releasing that
/// token would detach a LIVE FC's loop device (RWO broken), and stamping `Hibernated` + a snapshot
/// over a `Running` VM would later restore stale guest RAM against a newer disk.
#[derive(Default)]
pub(crate) struct Incarnations {
    current: HashMap<String, u64>,
    /// Monotonic across ALL ids for the process lifetime, so a marker is never reused (no ABA:
    /// a retired-then-recommitted id can't collide with a stale captured value).
    next: u64,
}

impl Incarnations {
    /// Commit-to-Running: mint this id's new marker (replacing any prior one).
    pub(crate) fn commit(&mut self, id: &str) -> u64 {
        self.next += 1;
        self.current.insert(id.to_string(), self.next);
        self.next
    }
    /// The live VM at `id` is gone (or going): no capture taken before this stays current.
    pub(crate) fn retire(&mut self, id: &str) {
        self.current.remove(id);
    }
    /// The marker of the VM a lock-dropping op is about to act on. A `Running` VM always has one;
    /// mint defensively if not, so the op still detects a later supersede.
    pub(crate) fn capture(&mut self, id: &str) -> u64 {
        match self.current.get(id) {
            Some(n) => *n,
            None => self.commit(id),
        }
    }
    pub(crate) fn is_current(&self, id: &str, marker: u64) -> bool {
        self.current.get(id) == Some(&marker)
    }
    /// No VM is committed at `id` (retired, and nothing has recommitted yet).
    fn is_vacant(&self, id: &str) -> bool {
        !self.current.contains_key(id)
    }
}

/// A superseded hibernate's ONLY write: if its VM was retired and nothing has recommitted (the
/// superseder failed or is still booting), the `Hibernating` it set is still its own — a newer
/// incarnation's hibernate needs a commit first — so settle it to `Hibernated` (no snapshot meta ⇒
/// the next wake cold-boots), as `force_stop_and_cleanup` would. Left alone it would wedge the id:
/// wakes time out waiting on it and deploys wait it out then fail. Anything else is not ours.
pub(crate) fn settle_superseded_hibernate(plat: &mut PlatformState, id: &str) {
    if plat.vm_incarnations.is_vacant(id)
        && plat.vm_states.get(id) == Some(&VmLifecycle::Hibernating)
    {
        plat.vm_states
            .insert(id.to_string(), VmLifecycle::Hibernated);
    }
}

pub(crate) struct PlatformState {
    pub(crate) vms: HashMap<String, VmInstance>,
    pub(crate) vm_states: HashMap<String, VmLifecycle>,
    /// See [`Incarnations`]: lets a lock-dropping hibernate tell "my VM" from a newer one.
    pub(crate) vm_incarnations: Incarnations,
    /// The base-rootfs hash each RUNNING VM is ACTUALLY mapped against (cold boot ⇒ the current
    /// hash; a restored VM ⇒ the hash it restored from, which after a redeploy is the OLD blob,
    /// not `base_rootfs_hash`). Stamped into the snapshot at hibernate so the next restore + the
    /// GC reference set point at the bytes the guest RAM truly depends on. Keyed by project_id;
    /// set on commit-to-Running, removed on hibernate/teardown.
    pub(crate) vm_rootfs_hashes: HashMap<String, String>,
    /// Last failed-wake instant per project — the wake path fast-fails (Retry-After) within
    /// [`WAKE_BACKOFF`] of it so a doomed project can't be spun into unbounded boot attempts by
    /// continuous traffic. Cleared on a successful wake.
    pub(crate) wake_failures: HashMap<String, std::time::Instant>,
    /// `boot_db_vm` calls in flight per DB VM id (a count: a deploy's and a wake-path cold boot's
    /// can overlap). Such a boot holds the DB VM's allocation from before its fence until it
    /// commits, so `drop_dedicated_db` refuses while this is non-zero. Each boot owns its own
    /// increment ([`DbBootGuard`]), unlike the shared `vm_states` entry.
    pub(crate) db_boots: HashMap<String, u32>,
    pub(crate) store: Store,
    pub(crate) firecracker_bin: PathBuf,
    pub(crate) kernel_path: PathBuf,
    /// The content-addressed base rootfs every VM boots from: `base-rootfs/<hash>.ext4`,
    /// an IMMUTABLE blob. A redeploy that ships a new agent mints a new hash/blob next to
    /// the old one, so a snapshot taken before the redeploy still restores byte-correct
    /// against the bytes its guest RAM expects (vs. the old in-place rewrite that poisoned
    /// every pre-existing snapshot). See `base_rootfs_hash` and the startup CAS placement.
    pub(crate) base_rootfs_path: PathBuf,
    /// sha256 of `base_rootfs_path` — stamped into each snapshot at hibernate time and the
    /// "keep" root of the startup CAS GC.
    pub(crate) base_rootfs_hash: String,
    pub(crate) data_dir: PathBuf,
    /// Read-write-once data-disk provider (R3) + exclusive lease (R2) — every data
    /// disk is fenced through these so a restored/relocated VM can never write a disk
    /// a prior VM still holds. Single-node today (LocalLoop + FlockLease); the same
    /// seam swaps to CephRbd + EtcdLease for HA.
    pub(crate) data_disk: Arc<dyn DataDiskProvider>,
    pub(crate) lease: Arc<dyn Lease>,
    /// The live fence token per project that currently holds its data disk RWO.
    pub(crate) disk_tokens: HashMap<String, FenceToken>,
    /// This host's stable identity, stamped into lease tokens.
    pub(crate) host_id: String,
    /// HA P2: set while THIS host holds the `cluster-leader` lease. Advisory at P2 —
    /// nothing gates on it yet (placement is P3) — and the data-disk write-boundary
    /// self-fence, not this flag, is the split-brain safety guarantee.
    pub(crate) is_leader: Arc<AtomicBool>,
    /// Host-asserted platform egress facts (OWN object-store host + the platform's own
    /// public IP deny-set), stamped into every per-VM metadata image as `_platform.json`
    /// so the in-VM agent can recognize OWN-storage (Zone 1) and deny the control-plane /
    /// proxy IP(s) (Zone 2). Computed once at startup; the same for every VM on this host.
    pub(crate) platform_egress: PlatformEgress,
}

/// Parent cgroup-v2 dir for runtime Firecrackers. Every runtime FC is migrated into a
/// `<this>/<project_id>` leaf right after spawn so it lives OUTSIDE `jkbase.service`'s
/// cgroup and survives `systemctl restart` (`KillMode=mixed` reaps only the service's own
/// cgroup) for the next process to re-adopt. Provisioned by `tools/setup-runtime-cgroup.sh`
/// (an `ExecStartPre`), mirroring `jkbase-build`. See `docs/vm-readoption-design.md` §1.
pub(crate) const RUNTIME_CGROUP_PARENT: &str = "/sys/fs/cgroup/jkbase-runtime";

impl PlatformState {
    /// HA P2: whether this host currently holds cluster leadership. Advisory until P3
    /// (placement) gates on it.
    #[allow(dead_code)] // consumed by the P3 placement gate
    fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    pub(crate) fn allocate_ip(&self) -> Result<(String, String, String)> {
        let existing = self.store.list_vm_allocations()?;
        match next_free_octet(&existing, &self.host_id) {
            Some(octet) => {
                let (tap, ip, mac) = slot_identity(octet);
                Ok((ip, tap, mac))
            }
            None => anyhow::bail!("no available IP addresses in this host's 172.16.0.0/24 island"),
        }
    }

    /// Allocate (or reuse) the public `external_port` + in-VM `agent_udp_port` for a
    /// project's `[l4.<name>]` port. See docs/managed-l4-udp-ingress-design.md §3(b).
    ///
    /// - **Idempotent + sticky:** an existing allocation for `(project, name)` is returned
    ///   verbatim — `external_port`/`agent_udp_port`/`pinned` never move under a redeploy,
    ///   rollback, or VM re-adoption (load-bearing for a pinned flagship port + SRV targets).
    /// - **Reservation, then bind is the arbiter:** the control-store scan can't see host
    ///   outbound-ephemeral or non-jkbase sockets, so a candidate is host-island-scanned +
    ///   quarantine-skipped + randomized, then **bind-probed**; `EADDRINUSE` → next candidate.
    /// - **`pinned_port`:** `Some(p)` forces an admin-granted fixed port (never evicts an
    ///   incumbent); `None` draws from the auto range (strictly below the kernel ephemeral
    ///   floor).
    /// - Enforces [`Store::MAX_L4_PORTS_PER_PROJECT`].
    pub(crate) fn allocate_port(
        &self,
        project_id: &str,
        name: &str,
        proto: L4Proto,
        guest_port: u16,
        pinned_port: Option<u16>,
    ) -> Result<PortAllocation> {
        // Sticky reuse — the whole point: the HOST-asserted `external_port` (+ `pinned`)
        // must survive redeploy. But refresh the TENANT-asserted `proto`/`guest_port` from
        // this deploy (the tenant may have edited `[l4.*]`), and fill a placeholder
        // `agent_udp_port` for a row created by a PRE-deploy admin pin (transit port == 0).
        if let Some(mut existing) = self.store.get_port_allocation(project_id, name)? {
            let mut changed = false;
            if existing.proto != proto.as_str() {
                existing.proto = proto.as_str().to_string();
                changed = true;
            }
            if existing.guest_port != guest_port {
                existing.guest_port = guest_port;
                changed = true;
            }
            if existing.agent_udp_port == 0 {
                let all = self.store.list_port_allocations()?;
                existing.agent_udp_port = next_agent_udp_port(&all, project_id, guest_port)?;
                changed = true;
            }
            if changed {
                self.store.save_port_allocation(&existing)?;
            }
            return Ok(existing);
        }
        // Lazy so non-L4 hosts are unaffected: the auto range must sit below the kernel
        // ephemeral floor, else we'd draw a port the kernel also hands to outbound sockets.
        validate_l4_port_range()?;

        let all = self.store.list_port_allocations()?;
        let mine = all.iter().filter(|p| p.project_id == project_id).count();
        if mine >= Store::MAX_L4_PORTS_PER_PROJECT {
            anyhow::bail!(
                "L4 port limit reached ({} per project)",
                Store::MAX_L4_PORTS_PER_PROJECT
            );
        }
        let quarantine = self.store.list_port_quarantine()?;
        let now = unix_now();

        let candidates: Vec<u16> = match pinned_port {
            Some(p) => {
                if p == 80 || p == 443 {
                    anyhow::bail!("cannot pin reserved port {p}");
                }
                // Never evict an incumbent: a pin onto a port already held in this island
                // is rejected. Quarantine does NOT block a deliberate admin pin.
                let taken = all.iter().any(|a| {
                    (a.host_id.is_empty() || a.host_id == self.host_id) && a.external_port == p
                });
                if taken {
                    anyhow::bail!("port {p} is already allocated on this host");
                }
                vec![p]
            }
            None => {
                let span = (*L4_PORT_RANGE.end() - *L4_PORT_RANGE.start()) as u64 + 1;
                let offset = (now % span) as u16;
                l4_port_candidates(&all, &quarantine, &self.host_id, now, offset)
            }
        };

        // Bind-probe: the first candidate that actually binds wins.
        let external_port = candidates
            .into_iter()
            .find(|p| l4_bind_probe(proto, *p))
            .context("no bindable L4 external port available (range exhausted or contended)")?;

        let agent_udp_port = next_agent_udp_port(&all, project_id, guest_port)?;

        let alloc = PortAllocation {
            project_id: project_id.to_string(),
            name: name.to_string(),
            proto: proto.as_str().to_string(),
            external_port,
            guest_port,
            agent_udp_port,
            pinned: pinned_port.is_some(),
            host_id: self.host_id.clone(),
            placement_epoch: 0,
        };
        self.store.save_port_allocation(&alloc)?;
        // A deliberately-pinned port may have been cooling; claiming it clears the entry so
        // the cooldown bookkeeping doesn't linger. (Auto-alloc already skips cooling ports.)
        let _ = self.store.unquarantine_port(external_port);
        Ok(alloc)
    }
}

/// HA P4 — the next free last-octet in THIS host's `172.16.0.0/24` island, considering
/// only allocations owned by `host_id` (empty host_id = single-node / pre-placement =
/// ours). Each host runs the same /24 on its own L2 bridge, so a peer's IPs are on a
/// separate segment — they neither collide with ours nor count against our range. This
/// also removes the cross-host uniqueness race on the shared control store (each host
/// allocates independently). `None` when the island is full.
pub(crate) fn next_free_octet(allocations: &[VmAllocation], host_id: &str) -> Option<u8> {
    let used: HashSet<u8> = allocations
        .iter()
        .filter(|a| a.host_id.is_empty() || a.host_id == host_id)
        .filter_map(|a| a.ip.split('.').next_back()?.parse::<u8>().ok())
        .collect();
    (2..=254u8).find(|o| !used.contains(o))
}

/// Current unix time in whole seconds (0 on a pre-epoch clock — never panics).
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::store::VmAllocation;

    /// Exactly the two lock-dropping transitions gate a supersede; settled states don't.
    #[test]
    fn lifecycle_in_flight_is_waking_or_hibernating_only() {
        assert!(lifecycle_in_flight(Some(&VmLifecycle::Waking)));
        assert!(lifecycle_in_flight(Some(&VmLifecycle::Hibernating)));
        assert!(!lifecycle_in_flight(Some(&VmLifecycle::Running)));
        assert!(!lifecycle_in_flight(Some(&VmLifecycle::Hibernated)));
        assert!(!lifecycle_in_flight(None));
    }

    /// The hibernate-vs-supersede race: a hibernate captures its VM's marker, drops the lock, and
    /// meanwhile a redeploy retires that VM and commits a new one. On relock the capture must read
    /// stale — both in the supersede-only window (nothing recommitted yet) and after the new commit
    /// — while an undisturbed hibernate still reads current. Markers never repeat across ids or
    /// retire/recommit cycles (no ABA).
    #[test]
    fn hibernate_capture_goes_stale_on_supersede_and_never_aliases() {
        let mut inc = Incarnations::default();
        let old = inc.commit("p.db");
        let captured = inc.capture("p.db");
        assert_eq!(captured, old, "capture of a committed VM is its marker");
        assert!(inc.is_current("p.db", captured));

        // boot_db_vm's supersede retires the paused VM's incarnation…
        assert!(!inc.is_vacant("p.db"));
        inc.retire("p.db");
        assert!(
            !inc.is_current("p.db", captured),
            "superseded, not yet recommitted"
        );
        assert!(
            inc.is_vacant("p.db"),
            "the stale hibernate may settle its own Hibernating"
        );
        // …then commits the new boot.
        let new = inc.commit("p.db");
        assert!(
            !inc.is_vacant("p.db"),
            "a newer incarnation's state is off-limits"
        );
        assert_ne!(new, captured);
        assert!(
            !inc.is_current("p.db", captured),
            "a newer incarnation owns the id"
        );
        assert!(inc.is_current("p.db", new));

        // A marker is unique across ids too: another VM's marker never reads current here.
        let other = inc.commit("q");
        assert!(!inc.is_current("p.db", other));
        assert!(inc.is_current("q", other));

        // A Running VM with no marker (defensive) is minted one, which then guards like any other.
        let minted = inc.capture("r");
        assert!(inc.is_current("r", minted));
        inc.commit("r");
        assert!(!inc.is_current("r", minted));
    }

    #[test]
    fn next_free_octet_is_scoped_per_host_island() {
        // HA P4: each host's /24 is its own L2 island, so only OUR allocations (and legacy
        // empty-host_id ones) constrain the next octet; a peer reusing the same octets on
        // its own segment must not block us or exhaust our range.
        let a = |pid: &str, ip: &str, host: &str| VmAllocation {
            project_id: pid.into(),
            ip: ip.into(),
            tap_device: "t".into(),
            mac: "AA".into(),
            host_id: host.into(),
            placement_epoch: 1,
        };
        let allocs = vec![
            a("p1", "172.16.0.2", "me"),
            a("p2", "172.16.0.3", "me"),
            a("peer1", "172.16.0.2", "peer"), // peer reuses .2 on ITS island — ignored for us
            a("peer2", "172.16.0.4", "peer"), // peer's .4 — ignored for us
            a("legacy", "172.16.0.5", ""),    // empty host_id = ours
        ];
        // me: own {2,3} + legacy {5}; peer's {2,4} ignored → next free = 4.
        assert_eq!(next_free_octet(&allocs, "me"), Some(4));
        // peer: own {2,4} + legacy {5} → next free = 3.
        assert_eq!(next_free_octet(&allocs, "peer"), Some(3));
        // Empty pool starts at .2.
        assert_eq!(next_free_octet(&[], "me"), Some(2));
    }
}
