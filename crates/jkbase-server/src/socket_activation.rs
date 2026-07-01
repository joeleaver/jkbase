//! Adopt listening sockets handed to us by **systemd socket activation**, so the public
//! proxy/TLS listeners (`:80`/`:443`) survive a `systemctl restart` upgrade with NO
//! connection-refused window. Data-plane half of zero-bounce continuity (Phase 2); the
//! control-plane half — keeping tenant Firecrackers alive across the swap — already lands via
//! the `jkbase-runtime` cgroup + `handoff.json` + `process::exit(0)` (Phase 1). See
//! `docs/zero-bounce-phase2-design.md`.
//!
//! systemd opens each `ListenStream=` socket ONCE and passes the *same* fd into every restart of
//! the service; the kernel keeps the `listen()` backlog across the old→new swap, so in-flight
//! SYNs queue instead of getting RST. The old process's `std::process::exit(0)` (skips `Drop`)
//! closes only its DUP — systemd's original fd stays open and listening for the successor.
//!
//! Protocol (`sd_listen_fds(3)`), parsed ONCE on the main thread before the runtime exists:
//!   `LISTEN_PID`     — pid systemd handed the fds to; MUST == `getpid()`, else the vars leaked
//!                      into a child (we fork+exec jailer/FC/buildpacks) → treat as "not ours".
//!   `LISTEN_FDS`     — count N; fds are the range `3 .. 3+N` (`SD_LISTEN_FDS_START = 3`).
//!   `LISTEN_FDNAMES` — `:`-separated, one name per fd in fd order, from each `[Socket]` unit's
//!                      `FileDescriptorName=`.
//!
//! **Threat model.** The fds come from systemd (trusted), not a guest. The hardening that matters
//! is the OTHER direction: we re-arm `FD_CLOEXEC` (systemd clears it) so `:443`/`:80` can never
//! leak into a tenant jailer/FC fd table (`vm.rs` spawns FC via `Command` redirecting only stdio),
//! and we scrub `LISTEN_*` so no fork+exec child mis-adopts. Callers gate on [`activated`]: when
//! activated, an unresolved fd name is a FATAL misconfig (never fall back to `bind()`, which would
//! hit `EADDRINUSE` against systemd's still-open socket).

use std::collections::HashMap;
use std::net::TcpListener;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::OnceLock;

const SD_LISTEN_FDS_START: RawFd = 3;

struct Activation {
    /// True iff `LISTEN_PID == getpid()` and `LISTEN_FDS > 0` — i.e. systemd activated US.
    /// When true, a caller whose fd name is absent must FAIL CLOSED, not `bind()`.
    activated: bool,
    /// Inherited fds keyed by `FileDescriptorName=`. An fd is taken exactly once (removed), so it
    /// can never be wrapped — hence closed-on-drop — twice. `Mutex` for the take-once mutation.
    fds: std::sync::Mutex<HashMap<String, RawFd>>,
}

static STATE: OnceLock<Activation> = OnceLock::new();

/// Parse + validate `$LISTEN_*`, arm `FD_CLOEXEC` on every inherited fd, and scrub the vars from
/// the environment. MUST be called on the main thread BEFORE the tokio runtime (or any thread /
/// fork+exec) exists: edition-2024 `remove_var` is `unsafe` precisely because it races concurrent
/// env readers, and CLOEXEC must be armed before any child can inherit the fd.
pub fn init() {
    STATE.get_or_init(parse_env);
}

/// True iff systemd socket-activated this process. Callers use it to decide: when `true`, a
/// missing fd name is fatal (the port is held by systemd); when `false`, self-`bind()`.
pub fn activated() -> bool {
    STATE.get().map(|s| s.activated).unwrap_or(false)
}

fn parse_env() -> Activation {
    let pid = std::env::var("LISTEN_PID").ok();
    let count = std::env::var("LISTEN_FDS").ok();
    let names = std::env::var("LISTEN_FDNAMES").ok();
    // Scrub immediately so even an early return leaves nothing for a fork+exec child to inherit.
    // SAFETY: single-threaded startup — init() runs before the runtime/threads/children exist.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    // Arm CLOEXEC on the whole inherited range UNCONDITIONALLY — even if LISTEN_PID mismatches,
    // any fds present at 3.. are ours to NOT leak into a tenant fork+exec (LOW-9).
    if let Some(n) = count.as_deref().and_then(|c| c.parse::<RawFd>().ok()) {
        for i in 0..n {
            arm_cloexec(SD_LISTEN_FDS_START + i);
        }
    }
    // Pure name→fd resolution (PID gate + duplicate fail-closed) — unit-tested below.
    let Some(named) = resolve_fd_names(
        pid.as_deref(),
        count.as_deref(),
        names.as_deref(),
        std::process::id(),
    ) else {
        // Not socket-activated (or LISTEN_* leaked into us) → callers bind().
        return Activation {
            activated: false,
            fds: std::sync::Mutex::new(HashMap::new()),
        };
    };
    // Validate each resolved fd is a real listening SOCK_STREAM before trusting it (syscall —
    // kept out of the pure resolver). AF_INET is asserted later, in take_listener.
    let mut map = HashMap::new();
    for (name, fd) in named {
        if is_listening_stream(fd) {
            map.insert(name, fd);
        } else {
            tracing::error!(fd, %name, "socket-activation: fd is not a listening SOCK_STREAM; ignoring");
        }
    }
    Activation {
        activated: true,
        fds: std::sync::Mutex::new(map),
    }
}

/// Pure `sd_listen_fds` name→fd resolution: the PID gate + `LISTEN_FDNAMES` mapping + duplicate
/// fail-closed, with NO syscalls/env/global state so it is unit-testable. `None` ⇒ not
/// socket-activated (caller binds); `Some(map)` ⇒ activated (caller fails closed on a missing
/// name). A `FileDescriptorName=` repeated across units drops ALL its entries (fail closed); a
/// name absent from `LISTEN_FDNAMES` (fewer names than fds) is skipped.
fn resolve_fd_names(
    pid: Option<&str>,
    count: Option<&str>,
    names: Option<&str>,
    my_pid: u32,
) -> Option<HashMap<String, RawFd>> {
    let count: RawFd = count.and_then(|c| c.parse().ok()).filter(|&n| n > 0)?;
    match pid.and_then(|p| p.parse::<u32>().ok()) {
        Some(p) if p == my_pid => {}
        _ => return None, // not the pid systemd targeted (or unset) → leaked into us
    }
    let mut names: Vec<String> = names
        .map(|s| s.split(':').map(str::to_owned).collect())
        .unwrap_or_default();
    names.resize(count as usize, String::new());
    let mut map = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for i in 0..count {
        let fd = SD_LISTEN_FDS_START + i;
        let name = std::mem::take(&mut names[i as usize]);
        if name.is_empty() {
            continue; // fd with no FileDescriptorName= — unaddressable, skip
        }
        if !seen.insert(name.clone()) {
            // Duplicate FileDescriptorName= across units → fail closed: ban the name entirely so
            // the affected role hits the activated-but-missing fatal path rather than a wrong fd.
            map.remove(&name);
            continue;
        }
        map.insert(name, fd);
    }
    Some(map)
}

/// Re-arm close-on-exec (systemd clears it; we restart via systemd, not self-exec, so the
/// successor gets a FRESH fd from systemd — the old one must not survive any fork+exec).
fn arm_cloexec(fd: RawFd) {
    // SAFETY: F_GETFD/F_SETFD only read/modify the fd's flags; harmless on a non-fd (returns <0).
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// Belt-and-suspenders: the fd must be a real listening TCP socket before we trust it.
fn is_listening_stream(fd: RawFd) -> bool {
    // SAFETY: getsockopt only reads socket options into our stack ints.
    unsafe {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let acc = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut val as *mut _ as *mut _,
            &mut len,
        );
        if acc != 0 || val != 1 {
            return false;
        }
        let mut ty: libc::c_int = 0;
        let mut tlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let t = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut ty as *mut _ as *mut _,
            &mut tlen,
        );
        t == 0 && ty == libc::SOCK_STREAM
    }
}

/// Take the inherited listener named `name` (nonblocking, [`std::net::TcpListener`]) if present.
/// `None` ⇒ not activated, or the name was not passed / already taken / not a valid listening
/// `AF_INET` stream. Caller contract: when [`activated`] is `true`, a `None` for an expected name
/// is a FATAL misconfig — bail, do NOT `bind()` (the port is held by systemd → `EADDRINUSE`).
///
/// `AF_INET` is asserted to preserve exact parity with the historical `bind(([0,0,0,0],port))`: a
/// bare `ListenStream=443` would open an `AF_INET6` dual-stack socket (peer IPs → `::ffff:...`,
/// bypassing the IPv4 firewall) — reject it so a unit typo can't silently change exposure (LOW-10).
pub fn take_listener(name: &str) -> Option<TcpListener> {
    let fd = STATE.get()?.fds.lock().unwrap().remove(name)?;
    // SAFETY: removed under the lock, so no other path can wrap this fd; from_raw_fd takes sole
    // ownership and closes it on drop (which happens on every error return below).
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    match listener.local_addr() {
        Ok(a) if a.is_ipv4() => {}
        Ok(a) => {
            tracing::error!(name, addr = %a, "socket-activation: inherited fd is not AF_INET; refusing");
            return None;
        }
        Err(e) => {
            tracing::error!(name, error = %e, "socket-activation: local_addr failed; refusing");
            return None;
        }
    }
    if let Err(e) = listener.set_nonblocking(true) {
        tracing::error!(name, error = %e, "socket-activation: set_nonblocking failed");
        return None; // listener drops here → fd closed
    }
    Some(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 4242;

    #[test]
    fn two_named_fds_map_by_name_in_order() {
        // The prod shape: jkbase-proxy-http.socket + jkbase-proxy-https.socket → two named fds.
        // Each role looks up BY NAME, so :443 resolves to its OWN fd regardless of pass order.
        let m = resolve_fd_names(Some("4242"), Some("2"), Some("proxy-http:proxy-https"), ME).unwrap();
        assert_eq!(m.get("proxy-http"), Some(&3));
        assert_eq!(m.get("proxy-https"), Some(&4));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn pid_mismatch_is_not_activated() {
        // LISTEN_* leaked into a fork+exec child (jailer/FC) — must read as "not ours" → bind().
        assert!(resolve_fd_names(Some("9999"), Some("2"), Some("proxy-http:proxy-https"), ME).is_none());
        assert!(resolve_fd_names(None, Some("2"), Some("proxy-http"), ME).is_none());
    }

    #[test]
    fn zero_or_missing_count_is_not_activated() {
        assert!(resolve_fd_names(Some("4242"), Some("0"), None, ME).is_none());
        assert!(resolve_fd_names(Some("4242"), None, None, ME).is_none());
    }

    #[test]
    fn duplicate_fdname_fails_closed_for_that_name_only() {
        // Two units sharing a name → that name is banned (caller bails), the distinct one survives.
        let m = resolve_fd_names(Some("4242"), Some("3"), Some("dup:dup:api"), ME).unwrap();
        assert_eq!(m.get("dup"), None, "duplicated name must be dropped (fail closed)");
        assert_eq!(m.get("api"), Some(&5));
    }

    #[test]
    fn fewer_names_than_fds_skips_unnamed() {
        // An fd absent from LISTEN_FDNAMES is unaddressable, not mis-assigned.
        let m = resolve_fd_names(Some("4242"), Some("2"), Some("proxy-http"), ME).unwrap();
        assert_eq!(m.get("proxy-http"), Some(&3));
        assert_eq!(m.len(), 1);
    }
}
