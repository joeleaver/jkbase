//! Guest wall-clock discipline via chrony + the KVM PTP device.
//!
//! A Firecracker microVM drifts two ways, both observed: (1) the guest runs on the
//! free-running `tsc` clocksource (kvm-clock is available but auto-deselected; we
//! deliberately do NOT pin `clocksource=kvm-clock`, which opts into a documented
//! Firecracker restore regression where the *monotonic* clock jumps on resume), so
//! an undisciplined, calibration-derived TSC accumulates offset; (2) a snapshot
//! freezes the guest clock, so a restored VM resumes behind by the paused duration.
//!
//! The canonical Firecracker fix is chrony disciplined by the KVM-backed PTP device
//! (`/dev/ptp0`, "KVM virtual PTP"). chrony reads the host's UTC from the PHC with
//! cheap paravirt calls — no network — and corrects both the TSC *frequency* error
//! and the offset (measured ~12 ppm on the dev box, held to sub-microsecond). The
//! agent is the VM's PID 1, so it owns starting and supervising chronyd; we run it
//! as root (`-u root`, no privilege drop) since the VM is single-tenant and chronyd
//! runs in the agent's init context, never exposed to tenant code.
//!
//! For the hibernate/resume jump, chrony's `makestep` would step on its next poll,
//! but the host calls [`resync_now`] (POST `/_jkbase/resync-clock`) right after it
//! resumes a restored snapshot so the correction is *instant* — the first request
//! after wake already sees correct time.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::process::Command;

const CHRONYD: &str = "/usr/sbin/chronyd";
/// The KVM-backed PTP device (`ptp_kvm` registers it). chrony reads it as a refclock
/// for steady-state discipline; [`resync_now`] reads it directly for the instant
/// resume step.
const PTP_DEVICE: &str = "/dev/ptp0";
/// chrony's writable runtime dir (driftfile + command socket). `/run` is a tmpfs
/// the agent mounts, so this is recreated each boot.
const CHRONY_RUNDIR: &str = "/run/chrony";

/// Prepare chrony's runtime dir and start a supervised chronyd that disciplines
/// `CLOCK_REALTIME` from the baked `/etc/chrony.conf` (`refclock PHC /dev/ptp0`).
/// Call once at startup, only as PID 1 (chronyd needs CAP_SYS_TIME, and there is
/// nothing to discipline in a non-VM context).
pub fn start_chrony() {
    // chrony refuses a command-socket dir more permissive than 0750 (it would
    // otherwise disable the socket, and `chronyc makestep` could not reach it).
    if let Err(e) = std::fs::create_dir_all(CHRONY_RUNDIR) {
        tracing::error!(error = %e, dir = CHRONY_RUNDIR, "failed to create chrony run dir; clock will drift");
        return;
    }
    if let Err(e) =
        std::fs::set_permissions(CHRONY_RUNDIR, std::fs::Permissions::from_mode(0o750))
    {
        tracing::warn!(error = %e, "failed to chmod chrony run dir 0750; command socket may be disabled");
    }

    // Supervise: chronyd should never exit, but if it does, restart it so the clock
    // doesn't silently start drifting for the rest of the VM's life.
    tokio::spawn(async {
        loop {
            tracing::info!("starting chronyd (refclock PHC /dev/ptp0)");
            // `-d` keeps chronyd in the foreground (so we can supervise it);
            // `-u root` skips the privilege drop. Logs inherit stdio -> console.
            let result = Command::new(CHRONYD)
                .args(["-u", "root", "-f", "/etc/chrony.conf", "-d"])
                .kill_on_drop(true)
                .status()
                .await;
            match result {
                Ok(status) => tracing::error!(?status, "chronyd exited; restarting in 2s"),
                Err(e) => tracing::error!(error = %e, "failed to spawn chronyd; retrying in 2s"),
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// Result of an on-demand resync, reported back to the host.
pub struct ResyncResult {
    pub ok: bool,
    pub detail: String,
}

/// Step `CLOCK_REALTIME` directly to the host's UTC, read from the KVM PTP device,
/// for an INSTANT resume correction. The host calls this right after resuming a
/// restored snapshot: the guest clock is frozen at snapshot time, and chrony (poll 1)
/// would auto-correct within a couple of seconds, but reading the PHC and stepping
/// here makes the very first post-wake request see correct time.
///
/// This is a single one-shot step; chrony remains the continuous disciplinarian and
/// accommodates it — whichever lands first wins and the other is a no-op (if this
/// step lands first, chrony's next sample just sees a correct clock; if chrony's own
/// makestep lands first, this re-reads the PHC and steps ~0). Needs `CAP_SYS_TIME`
/// (the agent is the VM's uid-0 PID 1).
pub fn resync_now() -> ResyncResult {
    let reference = match read_ptp_utc() {
        Ok(ts) => ts,
        Err(e) => {
            return ResyncResult {
                ok: false,
                detail: format!("PHC read failed: {e}"),
            };
        }
    };
    let before = now_realtime().tv_sec;
    if let Err(e) = step_realtime(&reference) {
        // EPERM here means the process lacks CAP_SYS_TIME (not PID 1 / not root).
        return ResyncResult {
            ok: false,
            detail: format!("clock_settime failed: {e}"),
        };
    }
    // `tv_sec` is the libc time_t; keep the subtraction in that type (no cast, and
    // don't name the deprecated alias) so it stays clean under -D warnings.
    let stepped = reference.tv_sec - before;
    ResyncResult {
        ok: true,
        detail: format!("stepped CLOCK_REALTIME to PHC ({stepped:+} s)"),
    }
}

/// `man clock_getres(2)`, "Dynamic clocks":
/// `FD_TO_CLOCKID(fd) = ((~(clockid_t)(fd) << 3) | CLOCKFD)`, `CLOCKFD = 3`.
fn fd_to_clockid(fd: i32) -> libc::clockid_t {
    ((!(fd as libc::clockid_t)) << 3) | 3
}

/// Read the host's wall clock (UTC / `CLOCK_REALTIME`) from the KVM PTP device.
/// Verified against the v6.12 kernel: `ptp_kvm`'s `KVM_HC_CLOCK_PAIRING(WALLCLOCK)`
/// returns the host's `CLOCK_REALTIME` — UTC, NOT TAI, so no leap-second offset.
fn read_ptp_utc() -> io::Result<libc::timespec> {
    // The dynamic clock id is only valid while the fd is open — keep `f` alive until
    // AFTER clock_gettime (dropping it first would yield EINVAL).
    let f = OpenOptions::new().read(true).write(true).open(PTP_DEVICE)?;
    let clkid = fd_to_clockid(f.as_raw_fd());
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clkid, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    drop(f);
    Ok(ts)
}

fn now_realtime() -> libc::timespec {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts
}

fn step_realtime(ts: &libc::timespec) -> io::Result<()> {
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
