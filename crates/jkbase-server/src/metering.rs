//! Host-side metering reads. All signals are measured from the host (`/proc`,
//! `/sys`, on-disk file sizes) — nothing is read from inside a (untrusted) VM.

use std::collections::HashMap;

/// Cumulative CPU jiffies (utime + stime) for `pid`, or `None` if unreadable.
/// Values are USER_HZ jiffies — 100/s on x86_64 Linux (the prod target); the
/// jiffies->seconds divide-by-100 is applied display-side. If the host arch ever
/// changes, switch to `libc::sysconf(_SC_CLK_TCK)`.
pub fn read_cpu_jiffies(pid: u32) -> Option<u64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The "(comm)" field can contain spaces and parens; everything after the
    // last ')' is space-separated. After it, field `state` is index 0, so
    // utime (overall field 14) is index 11 and stime (field 15) is index 12.
    let after = raw.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime.saturating_add(stime))
}

/// `(rx_bytes, tx_bytes)` for a TAP device from the host's perspective
/// (rx = bytes received from the guest = guest egress; tx = sent to the guest =
/// guest ingress). `None` if the device is gone (skip the tick, don't reset).
pub fn read_tap_bytes(tap: &str) -> Option<(u64, u64)> {
    let base = format!("/sys/class/net/{tap}/statistics");
    let rx: u64 = std::fs::read_to_string(format!("{base}/rx_bytes"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let tx: u64 = std::fs::read_to_string(format!("{base}/tx_bytes"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some((rx, tx))
}

/// In-memory cross-tick state for delta computation. NOT persisted: the durable
/// truth is the committed `UsageBucket`; a server restart loses at most one
/// interval (the first post-restart reading re-seeds the baseline, delta=0).
#[derive(Default)]
pub struct SamplerState {
    /// project_id -> (firecracker pid, last cpu jiffies)
    pub last_cpu: HashMap<String, (u32, u64)>,
    /// project_id -> (tap device, last rx, last tx)
    pub last_tap: HashMap<String, (String, u64, u64)>,
}

impl SamplerState {
    /// CPU jiffies consumed since the last sample. Returns 0 (and re-seeds) on
    /// first sight or a pid change (wake/redeploy/restart) so lifetime CPU is
    /// never misattributed to one interval.
    pub fn cpu_delta(&mut self, project_id: &str, pid: u32, current: u64) -> u64 {
        let delta = match self.last_cpu.get(project_id) {
            Some((last_pid, last)) if *last_pid == pid => current.saturating_sub(*last),
            _ => 0,
        };
        self.last_cpu.insert(project_id.to_string(), (pid, current));
        delta
    }

    /// `(rx_delta, tx_delta)` since the last sample. Returns 0 (re-seeds) on
    /// first sight or a TAP change; treats a counter decrease (TAP recreated on
    /// wake resets to 0) as the current value being the delta.
    pub fn tap_delta(&mut self, project_id: &str, tap: &str, rx: u64, tx: u64) -> (u64, u64) {
        let (drx, dtx) = match self.last_tap.get(project_id) {
            Some((last_tap, last_rx, last_tx)) if last_tap == tap => (
                if rx >= *last_rx { rx - *last_rx } else { rx },
                if tx >= *last_tx { tx - *last_tx } else { tx },
            ),
            _ => (0, 0),
        };
        self.last_tap
            .insert(project_id.to_string(), (tap.to_string(), rx, tx));
        (drx, dtx)
    }
}
