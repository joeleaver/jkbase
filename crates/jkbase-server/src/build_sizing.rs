//! Build-VM memory: per-project sizing + the host-wide budget every build VM draws from.
//!
//! A build VM's guest RAM is the host default (`BuildDeps::mem_size_mib`) unless the platform
//! operator granted the project more (`QuotaLimits::build_mem_mib`, admin-only — a tenant can
//! never size its own VM). Raising one project's VM is only safe because every build VM, of
//! every tenant, first reserves its memory from ONE `build_mem_budget::BuildMemBudget`: the per-job
//! `max_concurrent` semaphore bounds VMs per build, not per host, so without the budget N
//! concurrent tenants × 4 targets × an enlarged VM could commit more RAM than the host has and
//! host-OOM everyone (threat model: all tenants untrusted, the host is shared).
//!
//! That budget is itself a cross-tenant resource; its fair admission policy lives with it. A VM
//! reserves its cgroup cap (guest RAM + VMM headroom), the most it can actually commit.
//! The orchestrator takes a reservation only once the VM is about to boot (after the
//! per-language cache lock) and drops it as soon as the VM exits, so it is never held idle.
//!
//! A guest that exhausts its RAM is OOM-killed INSIDE the guest (the cgroup cap sits above guest
//! RAM, so the host never sees it): the compiler dies of SIGKILL and the build script exits 1.
//! jkbuild records the guest's `oom_kill` counter in `/out/oom_kills`; [`oom_failure`] turns that
//! into an error that names the cause and the size, instead of an opaque "status Some(1)".

const MIB: u64 = 1024 * 1024;

/// The machine size one build VM boots with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildVmSize {
    pub mem_size_mib: u32,
    /// The VM's cgroup `memory.max`: guest RAM plus the host's VMM headroom.
    pub cgroup_mem_max_bytes: u64,
}

impl BuildVmSize {
    /// What the VM reserves from the budget: its cgroup cap in MiB (rounded up) — the most host
    /// memory it can commit, not just its guest RAM.
    pub fn reserve_mib(&self) -> u32 {
        u32::try_from(self.cgroup_mem_max_bytes.div_ceil(MIB)).unwrap_or(u32::MAX)
    }
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

    #[test]
    fn a_vm_reserves_its_cgroup_cap_not_just_guest_ram() {
        assert_eq!(size_for(4096, 4608 * MIB, None).reserve_mib(), 4608);
        assert_eq!(size_for(4096, 4608 * MIB, Some(8192)).reserve_mib(), 8704);
        let odd = BuildVmSize {
            mem_size_mib: 1,
            cgroup_mem_max_bytes: MIB + 1,
        };
        assert_eq!(odd.reserve_mib(), 2, "rounded up, never under-reserved");
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

    /// On-box proof of the whole path: a node build whose `npm run build` holds ~1.2 GiB of
    /// RSS is OOM-killed in the default 1024 MiB VM and reported AS an OOM with the size
    /// (jkbuild's `/out/oom_kills` → host message); the SAME source then builds once the
    /// project's admin-granted `build_mem_mib` (read from the store per target) is 2048.
    ///
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… <test-bin> --ignored --nocapture \
    ///       build_mem_override_sizes_the_vm_and_oom_is_named
    #[tokio::test]
    #[ignore = "needs KVM + root + a node.ext4 baked with this jkbuild + the build bridge"]
    async fn build_mem_override_sizes_the_vm_and_oom_is_named() {
        use crate::build_orchestrator::onbox::{
            BuildTuning, networked_lang_build_opts, write, write_lang_manifest,
        };
        use jkbase_control::store::{DEFAULT_QUOTA, QuotaLimits, Store};

        let Ok(data) = std::env::var("JKB_DATA").map(std::path::PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return;
        };
        let src = data.join("oom-fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        write_lang_manifest(&src, "oomfix", "node");
        write(
            src.join("server/package.json"),
            "{\n  \"name\": \"oomfix\",\n  \"private\": true,\n  \"scripts\": { \"build\": \"node build.js\", \"start\": \"node server.js\" }\n}\n",
        );
        // Off-heap Buffers, touched so the pages are really resident (not V8's heap cap).
        write(
            src.join("server/build.js"),
            "const held = [];\nfor (let i = 0; i < 19; i++) held.push(Buffer.alloc(64 << 20, 1));\nconsole.log('held ' + held.length * 64 + ' MiB');\n",
        );
        write(
            src.join("server/server.js"),
            "require('http').createServer((_q, r) => r.end('ok\\n')).listen(Number(process.env.PORT) || 3000);\n",
        );
        // `rebuild = true` on both builds: an earlier run's successful build of this exact
        // source would otherwise be reused per target, with no VM to size.
        let redb = "onbox-oom.redb";
        let _ = std::fs::remove_file(data.join(redb));
        let tuning = || BuildTuning {
            vcpu: 2,
            guest_mem_mib: 1024,
            cgroup_mem_mib: 1536,
            cgroup_cpu_max: "200000 100000",
            scratch_mib: 512,
            output_mib: 64,
            timeout_secs: 300,
            fetch_deadline_secs: 180,
        };

        let Some(first) =
            networked_lang_build_opts("oomfix", redb, "node.ext4", &src, tuning(), 1, true).await
        else {
            return;
        };
        let err = match first {
            Ok(_) => panic!("a 1.2 GiB build must not fit the 1024 MiB default VM"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("build ran out of memory: the 1024 MiB build VM OOM-killed"),
            "an OOM must be named as one, with the VM size: {err}"
        );

        // The operator grants 2048 MiB; the next build reads it from the store per target.
        {
            let store = Store::open(&data.join(redb)).unwrap();
            store
                .set_quota(
                    "oomfix",
                    &QuotaLimits {
                        build_mem_mib: Some(2048),
                        ..DEFAULT_QUOTA
                    },
                )
                .unwrap();
        }
        let fx = networked_lang_build_opts("oomfix", redb, "node.ext4", &src, tuning(), 2, true)
            .await
            .expect("env checked above")
            .expect("the same build fits once the project's build VM is 2048 MiB");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: 1024 MiB → OOM named with size; 2048 MiB override → build succeeded");
    }
}
