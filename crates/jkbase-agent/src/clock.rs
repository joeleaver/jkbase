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

use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

const CHRONYD: &str = "/usr/sbin/chronyd";
const CHRONYC: &str = "/usr/bin/chronyc";
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

/// Force chrony to step the clock to its PTP reference immediately (`chronyc
/// makestep`). The host calls this right after resuming a restored snapshot so the
/// resume jump is corrected at once rather than on chrony's next poll.
pub async fn resync_now() -> ResyncResult {
    match Command::new(CHRONYC)
        .args(["-n", "makestep"])
        .stdin(Stdio::null())
        .output()
        .await
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            // chronyc prints "200 OK" when the daemon accepts the command.
            let ok = out.status.success() && stdout.contains("200 OK");
            let detail = format!("{}{}", stdout.trim(), stderr.trim());
            ResyncResult { ok, detail }
        }
        Err(e) => ResyncResult {
            ok: false,
            detail: format!("failed to run chronyc: {e}"),
        },
    }
}
