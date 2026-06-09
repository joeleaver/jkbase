//! Guest wall-clock discipline.
//!
//! A Firecracker microVM has two sources of wall-clock error, both of which this
//! module corrects with no network and no NTP daemon:
//!
//!  1. **Running in a VM.** The guest auto-selects the free-running `tsc`
//!     clocksource (kvm-clock is available but deselected; we deliberately do NOT
//!     pin `clocksource=kvm-clock` — that opts into a documented Firecracker
//!     restore regression where the *monotonic* clock jumps on resume). An
//!     undisciplined, calibration-derived TSC drifts (ppm-level) with nothing to
//!     correct the accumulated offset.
//!  2. **Hibernate / resume.** A snapshot freezes the guest clock; on restore the
//!     VM resumes with its wall-clock continuing from the snapshot instant, so it
//!     is behind by the entire paused duration (seconds … hours).
//!
//! The fix is the canonical Firecracker answer — discipline `CLOCK_REALTIME`
//! against the host via the KVM-backed PTP device — but implemented in-agent
//! (a ~chrony-lite) rather than by shipping chrony, to keep the runtime image
//! minimal and to give the host precise control over the resume re-sync.
//!
//! `ptp_kvm` registers `/dev/ptp0` ("KVM virtual PTP"). Reading it via
//! `clock_gettime` on its dynamic POSIX clock id issues `KVM_HC_CLOCK_PAIRING`
//! (WALLCLOCK), which the host services from `tk->xtime_sec` — i.e. the host's
//! `CLOCK_REALTIME` in **UTC** (verified against the v6.12 kernel source; it is
//! NOT TAI, so no leap-second offset is applied).
//!
//! Stepping/slewing `CLOCK_REALTIME` requires `CAP_SYS_TIME`, which the agent has
//! as the VM's uid-0 PID 1.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

/// The KVM-backed PTP hardware clock that `ptp_kvm` registers.
const PTP_DEVICE: &str = "/dev/ptp0";

/// Above this magnitude we hard-step `CLOCK_REALTIME`; at or below it we slew.
///
/// Mirrors chrony's `makestep`: a hibernate/resume jump (minutes–hours) MUST be
/// stepped — slewing it at the kernel's ~1/12 max rate would take many times the
/// offset in wall time. Steady-state ppm drift (and small *backward* corrections,
/// which a hard step would make most damaging) is slewed instead, so the wall
/// clock stays continuous. 500 ms sits well above realistic inter-pass drift (so
/// we never step on noise) yet bounds the worst-case slew to ~6 s.
const STEP_THRESHOLD_NS: i128 = 500_000_000;

/// How often the background loop disciplines the clock against the PTP reference.
/// The free-running tsc drifts only ppm-level, so the per-pass correction is tiny;
/// the explicit host-triggered re-sync (after resume) is what makes a wake instant.
const DISCIPLINE_INTERVAL: Duration = Duration::from_secs(30);

/// Outcome of one discipline pass, for logging / the control endpoint's response.
pub struct ResyncResult {
    /// `"ptp"` when read from `/dev/ptp0`, `"host"` when the PTP device was
    /// unavailable and we fell back to a host-provided timestamp.
    pub source: &'static str,
    /// Signed `reference − guest` offset in nanoseconds (how far behind/ahead the
    /// guest clock was before correction).
    pub offset_ns: i128,
    /// True if we hard-stepped (large offset), false if we slewed.
    pub stepped: bool,
}

/// `man clock_getres(2)`, "Dynamic clocks":
/// `#define FD_TO_CLOCKID(fd) ((~(clockid_t)(fd) << 3) | CLOCKFD)`, `CLOCKFD = 3`.
fn fd_to_clockid(fd: i32) -> libc::clockid_t {
    ((!(fd as libc::clockid_t)) << 3) | 3
}

fn now_realtime() -> io::Result<libc::timespec> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ts)
}

/// Read the host's wall clock (UTC / `CLOCK_REALTIME`) from the KVM PTP device.
fn read_ptp_utc() -> io::Result<libc::timespec> {
    // The dynamic clock id is only valid while the fd is open — keep `f` alive
    // until AFTER `clock_gettime` (dropping it first would yield EINVAL).
    let f = OpenOptions::new().read(true).write(true).open(PTP_DEVICE)?;
    let clkid = fd_to_clockid(f.as_raw_fd());
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(clkid, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    drop(f);
    Ok(ts)
}

fn ts_to_ns(ts: &libc::timespec) -> i128 {
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

/// Build a `timespec` from a positive UNIX-epoch nanosecond count (the host's
/// clock, supplied as the fallback reference). The remainder is non-negative.
fn ns_to_ts(unix_ns: i128) -> libc::timespec {
    // `as _` infers each field's width from the (target-specific) struct so the
    // syscall struct always matches the linked libc ABI (musl's time_t width).
    libc::timespec {
        tv_sec: (unix_ns / 1_000_000_000) as _,
        tv_nsec: (unix_ns % 1_000_000_000) as _,
    }
}

/// Hard-set `CLOCK_REALTIME` to an absolute UTC reference. Needs `CAP_SYS_TIME`.
fn step_realtime(ts: &libc::timespec) -> io::Result<()> {
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, ts) } != 0 {
        // EPERM => missing CAP_SYS_TIME (not PID 1 / not root).
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One-shot relative offset injection (slew, not step) via
/// `clock_adjtime(ADJ_SETOFFSET | ADJ_NANO)`. `tv_usec` carries NANOSECONDS here
/// (because `ADJ_NANO`) and must be non-negative, so a negative offset is
/// normalized into `(tv_sec, tv_usec)` with a non-negative sub-second part.
fn slew_offset(offset_ns: i128) -> io::Result<()> {
    let mut sec = (offset_ns / 1_000_000_000) as i64;
    let mut nsec = (offset_ns % 1_000_000_000) as i64;
    if nsec < 0 {
        sec -= 1;
        nsec += 1_000_000_000;
    }

    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = (libc::ADJ_SETOFFSET | libc::ADJ_NANO) as _;
    tx.time = libc::timeval {
        tv_sec: sec as _,
        tv_usec: nsec as _,
    };
    // clock_adjtime returns the clock state (>= 0) on success; only -1 is an error.
    if unsafe { libc::clock_adjtime(libc::CLOCK_REALTIME, &mut tx) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Discipline the guest `CLOCK_REALTIME` toward a reference time once.
///
/// Prefers the KVM PTP device (host UTC, no network). If `/dev/ptp0` is
/// unavailable it falls back to `fallback_unix_ns` (the host's clock, pushed over
/// the control channel) so a resume re-sync still works even on a kernel without
/// the PTP device. Steps large offsets, slews small ones.
pub fn resync(fallback_unix_ns: Option<i128>) -> io::Result<ResyncResult> {
    // Read the guest clock first, then the reference as close as possible to the
    // step, so the offset reflects the instant we correct.
    let now = now_realtime()?;
    let (reference, source) = match read_ptp_utc() {
        Ok(ts) => (ts, "ptp"),
        Err(e) => match fallback_unix_ns {
            Some(ns) => (ns_to_ts(ns), "host"),
            None => return Err(e),
        },
    };

    let offset_ns = ts_to_ns(&reference) - ts_to_ns(&now);
    let stepped = offset_ns.unsigned_abs() > STEP_THRESHOLD_NS as u128;
    if stepped {
        step_realtime(&reference)?;
    } else {
        slew_offset(offset_ns)?;
    }
    Ok(ResyncResult {
        source,
        offset_ns,
        stepped,
    })
}

/// Spawn the background discipline loop. Best-effort: a failed pass (e.g. PTP
/// device missing) is logged and retried on the next tick, never fatal.
pub fn spawn_discipline_loop() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(DISCIPLINE_INTERVAL).await;
            match resync(None) {
                Ok(r) => {
                    // Only worth a line when the correction was non-trivial.
                    if r.stepped || r.offset_ns.unsigned_abs() > 1_000_000 {
                        tracing::debug!(
                            source = r.source,
                            offset_ms = (r.offset_ns / 1_000_000) as i64,
                            stepped = r.stepped,
                            "clock disciplined"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "clock discipline pass failed");
                }
            }
        }
    });
}
