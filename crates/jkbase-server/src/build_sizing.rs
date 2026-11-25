//! Build-VM memory: per-project sizing + the host-wide budget every build VM draws from.
//!
//! A build VM's guest RAM is the host default (`BuildDeps::mem_size_mib`) unless the platform
//! operator granted the project more (`QuotaLimits::build_mem_mib`, admin-only — a tenant can
//! never size its own VM). Raising one project's VM is only safe because every build VM, of
//! every tenant, first reserves its RAM from ONE [`BuildMemBudget`]: the per-job
//! `max_concurrent` semaphore bounds VMs per build, not per host, so without the budget N
//! concurrent tenants × 4 targets × an enlarged VM could commit more guest RAM than the host
//! has and host-OOM everyone (threat model: all tenants untrusted, the host is shared).
//!
//! A guest that exhausts its RAM is OOM-killed INSIDE the guest (the cgroup cap sits above guest
//! RAM, so the host never sees it): the compiler dies of SIGKILL and the build script exits 1.
//! jkbuild records the guest's `oom_kill` counter in `/out/oom_kills`; [`oom_failure`] turns that
//! into an error that names the cause and the size, instead of an opaque "status Some(1)".

use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MIB: u64 = 1024 * 1024;

/// The machine size one build VM boots with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildVmSize {
    pub mem_size_mib: u32,
    /// The VM's cgroup `memory.max`: guest RAM plus the host's VMM headroom.
    pub cgroup_mem_max_bytes: u64,
}

/// Size a project's build VM. With no override it is exactly the host default (byte-identical to
/// the pre-override behaviour). An override keeps the host's configured headroom between guest
/// RAM and the cgroup cap (Firecracker + jailer overhead), so the cap always sits ABOVE guest RAM
/// — an OOM stays inside the guest, where jkbuild can report it, rather than SIGKILLing the VMM.
pub fn size_for(
    default_mem_mib: u32,
    default_cgroup_mem_max_bytes: u64,
    override_mib: Option<u32>,
) -> BuildVmSize {
    match override_mib {
        None => BuildVmSize {
            mem_size_mib: default_mem_mib,
            cgroup_mem_max_bytes: default_cgroup_mem_max_bytes,
        },
        Some(mib) => {
            let headroom =
                default_cgroup_mem_max_bytes.saturating_sub(u64::from(default_mem_mib) * MIB);
            BuildVmSize {
                mem_size_mib: mib,
                cgroup_mem_max_bytes: (u64::from(mib) * MIB).saturating_add(headroom),
            }
        }
    }
}

/// Host-wide guest-RAM budget (MiB) shared by every build VM of every tenant. A VM holds its
/// reservation for its whole run; builds that don't fit wait (FIFO — tokio's semaphore is fair,
/// so a big VM isn't starved by a stream of small ones).
#[derive(Debug)]
pub struct BuildMemBudget {
    sem: Arc<Semaphore>,
    total_mib: u32,
}

impl BuildMemBudget {
    pub fn new(total_mib: u32) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(total_mib as usize)),
            total_mib,
        }
    }

    /// Reserve `mib` for one build VM, waiting until it fits. A VM larger than the whole budget
    /// could never fit — refused with an operator-facing reason instead of waiting forever.
    pub async fn reserve(&self, mib: u32) -> Result<OwnedSemaphorePermit> {
        if mib > self.total_mib {
            bail!(
                "build VM needs {mib} MiB but the host's build-memory budget is {} MiB; \
                 lower the project's build memory or raise --build-mem-budget-mib",
                self.total_mib
            );
        }
        Ok(self.sem.clone().acquire_many_owned(mib).await?)
    }
}

/// Parse jkbuild's `/out/oom_kills` (the guest kernel's `oom_kill` count). Guest-written, so
/// untrusted: it can only change this tenant's OWN error text, and anything that isn't a plain
/// count is ignored.
pub fn parse_oom_kills(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.trim().parse().ok()
}

/// The error for a target whose build failed after the guest OOM-killed something.
pub fn oom_failure(mem_size_mib: u32, kills: u64, log: &str) -> String {
    let plural = if kills == 1 { "" } else { "es" };
    format!(
        "build ran out of memory: the {mem_size_mib} MiB build VM OOM-killed {kills} process{plural} \
         (the compiler/linker below died of SIGKILL). Reduce peak build memory (e.g. thin LTO, \
         fewer codegen jobs, fewer parallel wasm crates) or ask the platform operator to raise \
         this project's build memory.\n{log}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_override_is_the_host_default_exactly() {
        assert_eq!(
            size_for(4096, 4608 * MIB, None),
            BuildVmSize {
                mem_size_mib: 4096,
                cgroup_mem_max_bytes: 4608 * MIB
            }
        );
    }

    #[test]
    fn override_keeps_the_hosts_headroom_above_guest_ram() {
        let s = size_for(4096, 4608 * MIB, Some(8192));
        assert_eq!(s.mem_size_mib, 8192);
        assert_eq!(s.cgroup_mem_max_bytes, (8192 + 512) * MIB);
        // A smaller grant keeps the same headroom too.
        assert_eq!(
            size_for(4096, 4608 * MIB, Some(2048)).cgroup_mem_max_bytes,
            2560 * MIB
        );
        // A host configured with no headroom (cap below RAM) can't underflow.
        assert_eq!(
            size_for(4096, 1, Some(1024)).cgroup_mem_max_bytes,
            1024 * MIB
        );
    }

    #[tokio::test]
    async fn budget_admits_what_fits_and_refuses_what_never_can() {
        let b = BuildMemBudget::new(8192);
        let a = b.reserve(4096).await.unwrap();
        let c = b.reserve(4096).await.unwrap();
        // Full: a third reservation waits until one is released.
        let waiting = tokio::time::timeout(std::time::Duration::from_millis(50), b.reserve(1024));
        assert!(waiting.await.is_err(), "budget exhausted, must wait");
        drop(a);
        let d = tokio::time::timeout(std::time::Duration::from_secs(1), b.reserve(4096))
            .await
            .expect("released RAM is reusable")
            .unwrap();
        drop((c, d));
        let err = b.reserve(8193).await.unwrap_err().to_string();
        assert!(
            err.contains("8193 MiB") && err.contains("8192 MiB"),
            "{err}"
        );
    }

    #[test]
    fn oom_count_parse_is_strict() {
        assert_eq!(parse_oom_kills(b"3\n"), Some(3));
        assert_eq!(parse_oom_kills(b"0"), Some(0));
        assert_eq!(parse_oom_kills(b"-1"), None);
        assert_eq!(parse_oom_kills(b"lots"), None);
        assert_eq!(parse_oom_kills(&[0xff, 0xfe]), None);
    }

    #[test]
    fn oom_message_names_the_size_and_keeps_the_log() {
        let m = oom_failure(4096, 1, "rustc ... (signal: 9, SIGKILL: kill)");
        assert!(
            m.starts_with("build ran out of memory: the 4096 MiB build VM OOM-killed 1 process ")
        );
        assert!(m.ends_with("(signal: 9, SIGKILL: kill)"));
        assert!(oom_failure(4096, 2, "").contains("2 processes"));
    }
}
