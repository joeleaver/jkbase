mod clock;
mod db_engine;
mod db_reach;
use db_engine::{DbHttpOp, handle_db_query, handle_db_rewrite_covers};
use db_reach::{
    DB_LEG_MAX_CONNS, RHYPEDB_HTTP_PORT, RHYPEDB_TCP_PORT, db_leg_loopback_proxy,
    handle_db_backup, handle_db_restore, handle_db_splice,
};
mod container_supervisor;
mod dmverity;
mod function_egress;
mod function_runtime;
mod l4_forward;
mod log_sink;
mod objectstore_host;
mod static_server;

use anyhow::{Context, Result};
use container_supervisor::ContainerSupervisor;
use function_runtime::{FunctionRequest, FunctionRuntime};
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jkbase_common::layers::RuntimeLayers;
use log_sink::LogSink;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

fn mount_filesystems() {
    use std::ffi::CString;
    use std::ptr;

    let mounts = [
        ("/proc", "proc", "proc"),
        ("/sys", "sysfs", "sysfs"),
        ("/dev", "devtmpfs", "devtmpfs"),
        ("/tmp", "tmpfs", "tmpfs"),
        // chrony's writable runtime dir (driftfile + command socket) lives here.
        ("/run", "tmpfs", "tmpfs"),
    ];

    for (target, fstype, source) in &mounts {
        let _ = std::fs::create_dir_all(target);
        let src = CString::new(*source).unwrap();
        let tgt = CString::new(*target).unwrap();
        let fst = CString::new(*fstype).unwrap();
        unsafe {
            libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, ptr::null());
        }
    }
}

fn seed_entropy() {
    use std::io::Write;
    let mut seed = [0u8; 512];
    for chunk in seed.chunks_mut(8) {
        let tsc: u64;
        unsafe {
            std::arch::x86_64::_mm_lfence();
            tsc = std::arch::x86_64::_rdtsc();
        }
        let bytes = tsc.to_ne_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }

    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/urandom") {
        let _ = f.write_all(&seed);
    }

    if let Ok(f) = std::fs::OpenOptions::new().write(true).open("/dev/random") {
        use std::os::unix::io::AsRawFd;
        #[repr(C)]
        struct RandPoolInfo {
            entropy_count: i32,
            buf_size: i32,
            buf: [u8; 512],
        }
        let mut info = RandPoolInfo {
            entropy_count: 512 * 8,
            buf_size: 512,
            buf: seed,
        };
        unsafe {
            libc::ioctl(f.as_raw_fd(), 0x40085203, &mut info as *mut _);
        }
    }
}

fn mount_content_drive(target: &str) {
    use std::ffi::CString;
    use std::ptr;

    let device = "/dev/vdb";
    if !std::path::Path::new(device).exists() {
        return;
    }

    let _ = std::fs::create_dir_all(target);
    let src = CString::new(device).unwrap();
    let tgt = CString::new(target).unwrap();
    let fst = CString::new("ext4").unwrap();

    let flags = libc::MS_RDONLY;
    let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), flags, ptr::null()) };
    if ret != 0 {
        eprintln!(
            "failed to mount {device} at {target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn mount_data_disk(device: Option<&str>) {
    use std::ffi::CString;
    use std::ptr;

    // The host writes the data-disk device into _layers.json. Fall back to the
    // legacy fixed slot for pre-layered content images, where the data disk was
    // attached right after the content drive (/dev/vdc). With no layers attached,
    // the layered layout also lands the data disk at /dev/vdc, so this is safe.
    let device = device.unwrap_or("/dev/vdc");
    let target = "/mnt/data";

    if !std::path::Path::new(device).exists() {
        return;
    }

    let _ = std::fs::create_dir_all(target);
    let src = CString::new(device).unwrap();
    let tgt = CString::new(target).unwrap();
    let fst = CString::new("ext4").unwrap();

    let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, ptr::null()) };
    if ret == 0 {
        // Off the boot path: a big grow zeroes new inode tables (~1.5% of the added size) and
        // must not stall agent readiness. ext4 online resize is safe under concurrent writers.
        let dev = device.to_string();
        std::thread::spawn(move || {
            if let Err(e) = grow_data_fs(&dev, target) {
                eprintln!("data disk: online grow failed (keeping the current size): {e}");
            }
        });
        let _ = std::fs::create_dir_all("/mnt/data/volumes");
    } else {
        eprintln!(
            "failed to mount {device} at {target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Grow the mounted data-disk ext4 online to fill its device. The host only ever extends the
/// backing device when `[database].size` is raised — growing the filesystem is the guest's job,
/// because the host must never parse a guest filesystem. A no-op when the fs already fills the
/// device (the kernel returns early).
fn grow_data_fs(device: &str, mountpoint: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    const BLKGETSIZE64: u32 = 0x8008_1272; // _IOR(0x12, 114, u64)
    const EXT4_IOC_RESIZE_FS: u32 = 0x4008_6610; // _IOW('f', 16, u64)

    let dev = std::fs::File::open(device)?;
    let mut dev_bytes: u64 = 0;
    if unsafe { libc::ioctl(dev.as_raw_fd(), BLKGETSIZE64 as _, &mut dev_bytes) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fs = std::fs::File::open(mountpoint)?;
    let statfs = |f: &std::fs::File| -> std::io::Result<libc::statvfs> {
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(f.as_raw_fd(), &mut st) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(st)
    };
    let before = statfs(&fs)?;
    let block = before.f_frsize;
    if block == 0 {
        return Ok(());
    }
    let mut new_blocks: u64 = dev_bytes / block;
    if unsafe { libc::ioctl(fs.as_raw_fd(), EXT4_IOC_RESIZE_FS as _, &mut new_blocks) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let after = statfs(&fs)?;
    if after.f_blocks > before.f_blocks {
        eprintln!(
            "data disk: grew fs from {} to {} MiB",
            (before.f_blocks * block) >> 20,
            (after.f_blocks * block) >> 20
        );
    }
    Ok(())
}

/// Read the host-written `_layers.json` from the metadata image, if present.
/// Absent ⇒ a legacy flat content image (chroot servers; no erofs layers).
fn load_runtime_layers(serve_dir: &Path) -> Option<RuntimeLayers> {
    let path = serve_dir.join(RuntimeLayers::FILE);
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<RuntimeLayers>(&content) {
        Ok(rl) => Some(rl),
        Err(e) => {
            eprintln!("failed to parse {}: {e}", path.display());
            None
        }
    }
}

/// Read the host-written `_platform.json` (the host-asserted egress facts) from the
/// metadata image. Absent/malformed ⇒ fail-closed defaults (no OWN-storage host, empty
/// deny-set): stricter, never wider — the agent then leans on the netfilter fence for
/// Zone 2 and treats no host as OWN-storage.
fn load_platform_egress(serve_dir: &Path) -> jkbase_common::config::PlatformEgress {
    let path = serve_dir.join(jkbase_common::config::PlatformEgress::FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            eprintln!(
                "failed to parse {}: {e}; using fail-closed egress defaults",
                path.display()
            );
            Default::default()
        }),
        Err(_) => Default::default(),
    }
}

/// Read the host-written `_db_reach.json` reach-plane facts ([R3]/[RB1]) from the metadata
/// image. Absent/malformed ⇒ default (all-empty), so the splice/backup endpoints stay
/// unreachable and the admin token stays unset — fail-closed, never open.
fn load_db_reach_facts(serve_dir: &Path) -> jkbase_common::config::DbReachFacts {
    let path = serve_dir.join(jkbase_common::config::DbReachFacts::FILE);
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Read the host-written `_l4.json` L4 (UDP) reach facts from the metadata image. Absent/malformed
/// ⇒ default (no ports, empty transit secret), so the agent starts no land-forward — fail-closed,
/// never a silent unauthenticated UDP surface on the hostile L2 segment (P0-L4-8/-9). Sibling of
/// [`load_db_reach_facts`]; the same host-authored `_`-channel family.
fn load_l4_facts(serve_dir: &Path) -> jkbase_common::config::L4Facts {
    let path = serve_dir.join(jkbase_common::config::L4Facts::FILE);
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Guest loopback MTU (bytes) the agent sets when a project serves L4 UDP ports. The default `lo`
/// MTU is 65536, which LIES to a loopback-bound server about the real path: it then emits UDP
/// datagrams far larger than the ~1500-MTU host↔guest transit leg (and the ~1500 client path) can
/// carry, so an oversized reply — e.g. a TS3 channel-list sync for a POPULATED server — EMSGSIZE-
/// drops on the agent's transit send and never reaches the client (a deterministic large-datagram
/// failure; small syncs fit and work). Lowering `lo` to ~1400 makes the app size its datagrams to
/// fit BOTH the 32-byte transit header AND the 1500 client leg — exactly as it would on a normal
/// 1500-MTU public interface (which is why TS3 works on dedicated hosting). Value leaves margin:
/// a ≤1372-byte UDP payload + 32 transit + 28 IP/UDP = ≤1432 < 1500 on the transit leg, and
/// ≤1400 < 1500 on the client leg. Scoped to L4 projects so DB/function-only loopback throughput
/// is untouched. (A companion transit-MTU bump to also carry a FULL-1500 client→guest datagram in
/// the FORWARD direction is a follow-up — TS3 clients send small datagrams, so it isn't blocking.)
const L4_GUEST_LOOPBACK_MTU: i32 = 1400;

/// Set the guest loopback interface MTU via `SIOCSIFMTU` (no iproute2 dependency — the runtime
/// rootfs is a minimal apko userland; the agent already drives raw `ioctl`s). Best-effort: on any
/// failure the app still runs (only large loopback datagrams would be affected), so we log, not
/// bail.
fn set_loopback_mtu(mtu: i32) -> std::io::Result<()> {
    // `libc::ioctl`'s request arg is `c_int` on musl (the shipped target) and `c_ulong` on glibc
    // (the dev-host debug build); match each so both compile.
    #[cfg(target_env = "musl")]
    const SIOCSIFMTU: libc::c_int = 0x8922;
    #[cfg(not(target_env = "musl"))]
    const SIOCSIFMTU: libc::c_ulong = 0x8922;
    // struct ifreq: `char ifr_name[16]` then a union whose first member is `int ifr_mtu`
    // (40 bytes total on x86_64). Set name = "lo", mtu at offset 16.
    let mut req = [0u8; 40];
    req[..2].copy_from_slice(b"lo");
    req[16..20].copy_from_slice(&mtu.to_ne_bytes());
    // SAFETY: AF_INET dgram socket + a correctly-sized, correctly-laid-out ifreq; fd is closed
    // before returning on every path.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let rc = libc::ioctl(fd, SIOCSIFMTU, req.as_mut_ptr());
        let err = std::io::Error::last_os_error();
        libc::close(fd);
        if rc < 0 {
            return Err(err);
        }
    }
    Ok(())
}

/// Add `addr/32` to `lo`, host scope, via one rtnetlink `RTM_NEWADDR` — the L4 flow source
/// (`l4_forward::L4_FLOW_SOURCE_ADDR`). Netlink, not `SIOCSIFADDR` on a `lo:` alias: the ioctl
/// creates the address with its CLASSFUL mask (a /8 for `10.x`) and needs a second
/// `SIOCSIFNETMASK` to narrow it, so for a moment — or for good, if the second call fails — all of
/// `10.0.0.0/8` would route into `lo`. `RTM_NEWADDR` installs the /32 atomically. `NLM_F_REPLACE`
/// makes it idempotent across an agent restart. Same no-iproute2 constraint as
/// [`set_loopback_mtu`]. Best-effort: the caller falls back to a `127.0.0.1` flow source.
fn add_loopback_flow_source(addr: Ipv4Addr) -> std::io::Result<()> {
    // SAFETY: `if_nametoindex` reads a NUL-terminated name; the netlink socket is closed on every
    // path; every buffer handed to the kernel is a correctly-sized local array.
    unsafe {
        let ifindex = libc::if_nametoindex(c"lo".as_ptr());
        if ifindex == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = (|| {
            let req = rtm_newaddr_request(ifindex, addr, 1);
            let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            let sent = libc::sendto(
                fd,
                req.as_ptr().cast(),
                req.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );
            if sent < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // NLM_F_ACK ⇒ the kernel answers with NLMSG_ERROR carrying 0 (ok) or -errno.
            let mut ack = [0u8; 256];
            let n = libc::recv(fd, ack.as_mut_ptr().cast(), ack.len(), 0);
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            parse_netlink_ack(&ack[..n as usize])
        })();
        libc::close(fd);
        result
    }
}

/// The 40-byte `RTM_NEWADDR` request for [`add_loopback_flow_source`]: `nlmsghdr` (16) +
/// `ifaddrmsg` (8) + `IFA_LOCAL` and `IFA_ADDRESS` rtattrs (8 each). Header fields are host byte
/// order; the address is network order. Pure, so the layout is unit-tested without privileges.
fn rtm_newaddr_request(ifindex: u32, addr: Ipv4Addr, seq: u32) -> [u8; 40] {
    const RTM_NEWADDR: u16 = 20;
    const NLM_F_REQUEST: u16 = 0x001;
    const NLM_F_ACK: u16 = 0x004;
    const NLM_F_REPLACE: u16 = 0x100;
    const NLM_F_CREATE: u16 = 0x400;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const IFA_F_PERMANENT: u8 = 0x80;
    const RT_SCOPE_HOST: u8 = 254;
    let mut m = [0u8; 40];
    // nlmsghdr { len, type, flags, seq, pid = 0 (the kernel) }
    m[0..4].copy_from_slice(&40u32.to_ne_bytes());
    m[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
    let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE;
    m[6..8].copy_from_slice(&flags.to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    // ifaddrmsg { family, prefixlen, flags, scope, index }
    m[16] = libc::AF_INET as u8;
    m[17] = 32;
    m[18] = IFA_F_PERMANENT;
    m[19] = RT_SCOPE_HOST;
    m[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    // rtattr { len = 8, type } + the 4-byte address, twice.
    for (off, ty) in [(24, IFA_LOCAL), (32, IFA_ADDRESS)] {
        m[off..off + 2].copy_from_slice(&8u16.to_ne_bytes());
        m[off + 2..off + 4].copy_from_slice(&ty.to_ne_bytes());
        m[off + 4..off + 8].copy_from_slice(&addr.octets());
    }
    m
}

/// Read the kernel's `NLMSG_ERROR` ack: `nlmsghdr` (16) then an `i32` that is 0 on success or a
/// negative errno. Anything else (short read, unexpected type) is an error — fail toward the
/// `127.0.0.1` fallback, never toward assuming the alias exists.
fn parse_netlink_ack(buf: &[u8]) -> std::io::Result<()> {
    const NLMSG_ERROR: u16 = 2;
    if buf.len() < 20 || u16::from_ne_bytes([buf[4], buf[5]]) != NLMSG_ERROR {
        return Err(std::io::Error::other("unexpected rtnetlink reply"));
    }
    match i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]) {
        0 => Ok(()),
        e => Err(std::io::Error::from_raw_os_error(-e)),
    }
}

/// dm-verity mapper name for a layer block device (e.g. `/dev/vdc` → `jkverity-vdc`):
/// stable, unique per device, and within `dmverity::activate`'s accepted name charset.
fn verity_name(device: &str) -> String {
    let base = Path::new(device)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("dev");
    format!("jkverity-{base}")
}

/// Mount an erofs filesystem read-only from `source` (a raw block device or an
/// activated `/dev/mapper` verity node) at `target`.
fn mount_erofs_ro(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;
    let src = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("nul byte in source path"))?;
    let tgt = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("nul byte in target path"))?;
    let fst = CString::new("erofs").unwrap();
    let ret = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fst.as_ptr(),
            libc::MS_RDONLY,
            ptr::null(),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Mount each distinct erofs layer block device read-only under /tmp/layers, and
/// return (`server name` → its ordered lowerdir mountpoints, the managed DB's ordered
/// lowerdir mountpoints if declared). App first, base last. A server (or the DB) whose
/// layers don't all mount is omitted (it won't be started layered).
fn mount_layers(rl: &RuntimeLayers) -> (HashMap<String, Vec<PathBuf>>, Option<Vec<PathBuf>>) {
    let base = Path::new("/tmp/layers");
    let _ = std::fs::create_dir_all(base);

    let mountpoint_for = |device: &str| -> PathBuf {
        let name = Path::new(device)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dev");
        base.join(name)
    };

    // One clear diagnostic if integrity-enforced layers are declared but this guest
    // can't activate dm-verity (no device-mapper / no veritysetup) — those layers then
    // fail closed per-device below; this just names the root cause once up front.
    if !rl.verity.is_empty() && !dmverity::available() {
        eprintln!(
            "dm-verity required by {} shared layer(s) but device-mapper/veritysetup is \
             unavailable in this guest; verified layers will fail closed (their servers \
             will not start layered)",
            rl.verity.len()
        );
    }

    // Mount each distinct device exactly once. A device listed in `rl.verity` is an
    // integrity-enforced shared layer (the base / per-language runtime, whose poisoning
    // would hit every tenant): activate a dm-verity mapping pinned to its host-computed
    // root hash and mount erofs from the verified `/dev/mapper` node — a tampered block
    // then returns EIO. This is FAIL-CLOSED: if verity activation or the verified mount
    // fails we skip the layer (its server simply won't start layered), never falling
    // through to an unverified direct mount. A device ABSENT from `rl.verity` (the
    // per-tenant app layer — self-affecting + host-sha256-verified at attach — and any
    // pre-verity image) is mounted erofs directly.
    let mut mounted: HashMap<String, PathBuf> = HashMap::new();
    // Every distinct device referenced by any tenant server OR the managed DB overlay.
    let mut layer_lists: Vec<&Vec<String>> = rl.servers.values().map(|s| &s.layers).collect();
    if let Some(db) = &rl.database {
        layer_lists.push(&db.layers);
    }
    for layers in layer_lists {
        for device in layers {
            if mounted.contains_key(device) {
                continue;
            }
            if !Path::new(device).exists() {
                eprintln!("layer device {device} not present; skipping");
                continue;
            }
            let mp = mountpoint_for(device);
            let _ = std::fs::create_dir_all(&mp);

            if let Some(params) = rl.verity.get(device) {
                let name = verity_name(device);
                let dev = match dmverity::activate(&name, Path::new(device), params) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("dm-verity activation failed for {device}: {e}; layer skipped");
                        continue;
                    }
                };
                match mount_erofs_ro(dev.path(), &mp) {
                    Ok(()) => {
                        // The erofs mount now pins the mapping; disarm teardown-on-drop
                        // so dropping the handle here can't tear down the live mount.
                        dev.leak();
                        mounted.insert(device.clone(), mp);
                    }
                    Err(e) => {
                        // Mount failed: `dev` is still armed, so dropping it here tears
                        // the verity mapping down — no leaked dm device.
                        eprintln!(
                            "failed to mount verified erofs {device} at {}: {e}",
                            mp.display()
                        );
                    }
                }
            } else if let Err(e) = mount_erofs_ro(Path::new(device), &mp) {
                eprintln!("failed to mount erofs {device} at {}: {e}", mp.display());
            } else {
                mounted.insert(device.clone(), mp);
            }
        }
    }

    // Resolve each server's ordered devices to mountpoints.
    let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for (name, server) in &rl.servers {
        let mut dirs = Vec::with_capacity(server.layers.len());
        let mut ok = true;
        for device in &server.layers {
            match mounted.get(device) {
                Some(mp) => dirs.push(mp.clone()),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !dirs.is_empty() {
            map.insert(name.clone(), dirs);
        } else {
            eprintln!("server '{name}' has unmounted layers; will not start layered");
        }
    }

    // Resolve the managed DB overlay (lowerdir=rhypedb:base) to mountpoints, if declared.
    let database = rl.database.as_ref().and_then(|db| {
        let mut dirs = Vec::with_capacity(db.layers.len());
        for device in &db.layers {
            match mounted.get(device) {
                Some(mp) => dirs.push(mp.clone()),
                None => {
                    eprintln!("managed DB has an unmounted layer ({device}); will not start");
                    return None;
                }
            }
        }
        (!dirs.is_empty()).then_some(dirs)
    });

    (map, database)
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

struct AgentState {
    serve_dir: PathBuf,
    functions_dir: PathBuf,
    functions: FunctionRuntime,
    containers: Arc<ContainerSupervisor>,
    /// The one process-wide log sink (server output + function egress events),
    /// shared by every producer so the host shipper sees a single `(boot_id, seq)`
    /// cursor space. Read directly by the `/_jkbase/logs` endpoint.
    log_sink: Arc<LogSink>,
    route_config: Vec<RouteEntry>,
    sites: Vec<SiteEntry>,
    /// Host→agent managed-DB reach-plane splice secret ([R3]), read from the host-authored
    /// `_db_reach.json`. `Some` only for a project with a managed DB; the `/_jkbase/db`
    /// handler verifies it before splicing (a `None`/mismatch fails closed).
    db_splice_secret: Option<String>,
    /// The per-deploy rhypedb admin bearer ([RB1]), read from the same host-only
    /// `_db_reach.json`. Used ONLY to authorize the agent's own hard-coded loopback admin calls
    /// (`/admin/backup/stream` for a backup pull, `/admin/rewrite-covers` for the owner's
    /// rewrite pass) and the restore respawn — never served, never handed to a tenant process.
    db_admin_token: Option<String>,
}

/// A backend kind a tenant route can target. Resolved at the agent's deserialization
/// boundary ONLY (from `_routes.json` in this VM's host-built metadata image) — the proxy
/// stays unaware of function-vs-server (P0-INGRESS-HOST-TRUST). An unknown kind is dropped
/// (fail-closed) at load.
#[derive(Clone, Copy, PartialEq, Debug)]
enum RouteKind {
    Server,
    Function,
}

struct RouteEntry {
    prefix: String,
    /// Target backend name (server or function) within this project.
    name: String,
    kind: RouteKind,
}

struct SiteEntry {
    name: String,
    root: PathBuf,
    prefix: String,
    spa: bool,
    /// The host this site is bound to, as declared (`[sites.x] domain`), if any.
    domain: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // `jkbase-agent --precompile <in.wasm> <out.cwasm>`: AOT-compile a function with the
    // runtime's exact engine config so the agent deserializes it at boot instead of
    // recompiling the big JS engine. Invoked by the host deploy pipeline (it ships this
    // same binary), so the precompiler and loader configs can never drift.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--precompile") {
        let (Some(input), Some(output)) = (args.get(2), args.get(3)) else {
            eprintln!("usage: jkbase-agent --precompile <in.wasm> <out.cwasm>");
            std::process::exit(2);
        };
        function_runtime::precompile(Path::new(input), Path::new(output))?;
        return Ok(());
    }

    if is_pid1() {
        mount_filesystems();
        seed_entropy();
    }

    tracing_subscriber::fmt::init();

    // Discipline the guest wall clock against the host's KVM PTP device via chrony
    // (refclock PHC /dev/ptp0): it corrects the free-running-tsc frequency error and
    // any offset with no network. As PID 1 we own supervising chronyd. The
    // hibernate/resume jump is corrected instantly on demand via POST
    // /_jkbase/resync-clock (chronyc makestep), fired by the host after it resumes a
    // restored snapshot. See clock.rs.
    if is_pid1() {
        clock::start_chrony();
    }

    let serve_dir =
        PathBuf::from(std::env::var("JKBASE_SERVE_DIR").unwrap_or_else(|_| "/srv/www".to_string()));
    let functions_dir = PathBuf::from(
        std::env::var("JKBASE_FUNCTIONS_DIR")
            .unwrap_or_else(|_| serve_dir.join("_functions").to_string_lossy().to_string()),
    );
    let servers_dir = serve_dir.join("_servers");

    let mut layer_map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut db_lowerdirs: Option<Vec<PathBuf>> = None;
    if is_pid1() {
        mount_content_drive(serve_dir.to_str().unwrap_or("/srv/www"));
        // The metadata image carries _layers.json describing this boot's device
        // assignment: the data-disk device and each server's erofs overlay stack.
        match load_runtime_layers(&serve_dir) {
            Some(rl) => {
                // Layered image: mount the data disk only if the host mapped one
                // (the fixed /dev/vdc slot is now a layer, not a data disk), then
                // compose the erofs layer stack.
                if let Some(dev) = rl.data_device.as_deref() {
                    mount_data_disk(Some(dev));
                }
                // Fail-closed on a newer-than-known contract: an image whose schema
                // exceeds what this agent understands may carry integrity semantics
                // (e.g. a verity map) we cannot honour, so refuse the layered mounts
                // rather than silently mount them unverified. The data disk above is
                // schema-independent and still mounts.
                if rl.schema > RuntimeLayers::SCHEMA {
                    eprintln!(
                        "_layers.json schema {} is newer than this agent supports ({}); \
                         refusing layered mounts (fail-closed)",
                        rl.schema,
                        RuntimeLayers::SCHEMA
                    );
                } else {
                    let (lm, db) = mount_layers(&rl);
                    layer_map = lm;
                    db_lowerdirs = db;
                }
            }
            None => {
                // Legacy flat content image: data disk at the fixed /dev/vdc slot.
                mount_data_disk(None);
            }
        }
    }

    // The single shared log sink: one `seq` source + one `boot_id` for the whole
    // agent process, constructed here and handed to every log producer. Both the
    // server supervisor and (in the egress-observe path) the function runtime push
    // into it, so the host shipper dedups on one cursor space (P0-OBS-UNIFIED-SINK).
    let log_sink = Arc::new(LogSink::new());

    // Host-asserted platform egress facts (`_platform.json`): the OWN object-store host +
    // the platform's own public-IP deny-set. Read once at boot; the agent's egress gate
    // classifies against these. Absent/malformed ⇒ fail-closed defaults (no OWN host, empty
    // deny-set → rely on the netfilter fence for Zone 2; stricter, never wider).
    let platform_egress = load_platform_egress(&serve_dir);
    let egress_ctx = function_egress::EgressContext::new(&platform_egress, log_sink.clone())
        .context("build function egress context")?;

    let mut functions = FunctionRuntime::new(egress_ctx);
    if let Err(e) = functions.load_all_from_dir(&functions_dir) {
        error!(error = %e, "failed to load functions");
    }

    let func_names = functions.list_functions();
    if !func_names.is_empty() {
        info!(functions = ?func_names, "loaded WASM functions");
    }

    // Load the host-authored L4 facts (used again below to start the land-forward). If this project
    // serves any L4 UDP port, shrink the guest loopback MTU BEFORE the tenant server starts, so a
    // loopback-bound app (e.g. TS3) sizes its datagrams to the real transit + client path instead
    // of loopback's 64 KiB lie (see `L4_GUEST_LOOPBACK_MTU`). Best-effort — a failure only affects
    // oversized datagrams and never blocks startup.
    let l4 = load_l4_facts(&serve_dir);
    if !l4.ports.is_empty() {
        match set_loopback_mtu(L4_GUEST_LOOPBACK_MTU) {
            Ok(()) => info!(
                mtu = L4_GUEST_LOOPBACK_MTU,
                "l4: lowered guest loopback MTU so the app sizes datagrams to the real path"
            ),
            Err(e) => warn!(
                error = %e,
                "l4: failed to lower guest loopback MTU (large UDP replies may EMSGSIZE-drop)"
            ),
        }
    }
    // The address flows are presented to the app FROM (see `l4_forward::L4_FLOW_SOURCE_ADDR`).
    // Added before the land-forward starts so no flow ever binds before it exists, and only when
    // a land-forward WILL start (ports + a transit secret). On failure, fall back to `127.0.0.1` —
    // correct for every non-WebRTC app, and no worse than before.
    let l4_flow_source = if l4.ports.is_empty() || l4.transit_secret.is_empty() {
        Ipv4Addr::LOCALHOST
    } else {
        match add_loopback_flow_source(l4_forward::L4_FLOW_SOURCE_ADDR) {
            Ok(()) => {
                info!(
                    addr = %l4_forward::L4_FLOW_SOURCE_ADDR,
                    "l4: flows reach the app from a non-loopback source"
                );
                l4_forward::L4_FLOW_SOURCE_ADDR
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "l4: failed to add the flow source address; flows will come from 127.0.0.1 \
                     (WebRTC clients that drop loopback mapped addresses, e.g. Firefox, will fail ICE)"
                );
                Ipv4Addr::LOCALHOST
            }
        }
    };

    let containers = Arc::new(ContainerSupervisor::new(
        servers_dir,
        layer_map,
        log_sink.clone(),
    ));
    if let Err(e) = containers.start_all().await {
        error!(error = %e, "failed to start server containers");
    }

    // Managed database (RhypeDB): a dedicated, loopback-only supervised server composed
    // from the rhypedb runtime layer (overlay rhypedb:base) — NOT a tenant `_servers`
    // entry and never routed, reachable only at 127.0.0.1:4200 by the project's own app.
    // Schema (+ optional rules) are host-baked into `_database/` in the metadata image;
    // the agent seeds them into the DB's meta volume before the server starts.
    // Host-only reach-plane facts (splice secret + rhypedb admin token), loaded once from the
    // metadata image before the DB starts so the token can be injected into the DB's env.
    let db_reach = load_db_reach_facts(&serve_dir);
    let db_splice_secret =
        (!db_reach.splice_secret.is_empty()).then(|| db_reach.splice_secret.clone());
    let db_admin_token = (!db_reach.admin_token.is_empty()).then(|| db_reach.admin_token.clone());

    // P2 §7.6 — the app→DB in-guest leg. A dedicated project's app VM has NO co-located rhypedb
    // (`db_lowerdirs.is_none()`); its DB runs in a sibling DB VM. Start the in-guest loopback proxy
    // so tenant code reaches its DB on the SAME `127.0.0.1:4200/4201` as co-located — byte-for-byte
    // unchanged. Each accepted loopback connection is spliced to the host DB gateway on the bridge
    // gateway IP (`172.16.0.1`), which source-IP-authenticates and forwards to the DB VM's agent.
    // The `dedicated` flag is set ONLY on a dedicated APP image; a co-located app (which co-hosts
    // rhypedb on those ports) never sets it, so the two can't collide. Capture BEFORE the DB-start
    // block below moves `db_lowerdirs`.
    //
    // Corrupt-image guard ([R4]): a dedicated app image must NEVER also carry the rhypedb overlay —
    // that could only be a mis-built image, and silently co-locating a SECOND rhypedb (two DB
    // identities) is worse than failing closed. If we ever see `dedicated && db_lowerdirs.is_some()`,
    // shout and DROP the overlay so the co-located DB is not started and the leg (to the real
    // sibling DB VM) is used instead.
    if db_reach.dedicated && db_lowerdirs.is_some() {
        error!(
            "CORRUPT IMAGE: `_db_reach.json` marks this a dedicated app VM, but the metadata image \
             ALSO carries the rhypedb overlay — refusing to co-locate a second DB; using the app→DB \
             leg to the sibling DB VM instead"
        );
        db_lowerdirs = None;
    }
    let start_db_leg = db_reach.dedicated && db_lowerdirs.is_none();

    if let Some(lowerdirs) = db_lowerdirs {
        let schema_path = serve_dir.join("_database/schema.rhype");
        match std::fs::read(&schema_path) {
            Ok(schema) => {
                let rules = std::fs::read(serve_dir.join("_database/rules.rhype")).ok();
                // P4: the per-project PUBLIC JWKS rides the reserved channel (`_db_reach.json`),
                // host-authored like the admin token — never a tenant source file. Baked only when
                // the project opts into `[database].rules`; absent ⇒ rules-off.
                let jwks = db_reach.jwks.as_deref().map(str::as_bytes);
                if let Err(e) = containers
                    .start_database(
                        db_admin_token.as_deref(),
                        &schema,
                        rules.as_deref(),
                        jwks,
                        lowerdirs,
                    )
                    .await
                {
                    error!(error = %e, "failed to start managed database");
                }
            }
            Err(e) => error!(
                error = %e,
                path = %schema_path.display(),
                "managed DB declared but schema missing from metadata image"
            ),
        }
    }

    // P2 §7.6 — start the app→DB loopback proxy on a dedicated app VM (see `start_db_leg` above).
    if start_db_leg {
        info!(
            "dedicated tier: starting in-guest app→DB loopback proxy \
             (127.0.0.1:{RHYPEDB_HTTP_PORT}/{RHYPEDB_TCP_PORT} → host DB gateway {})",
            jkbase_common::config::DB_GATEWAY_IP
        );
        // HTTP plane (`POST /query`, …) and the native TCP wire (`@rhypedb/client`, subscriptions)
        // each get their own loopback listener → its matching host-gateway port; both share one
        // in-VM concurrency ceiling.
        let leg_permits = std::sync::Arc::new(tokio::sync::Semaphore::new(DB_LEG_MAX_CONNS));
        tokio::spawn(db_leg_loopback_proxy(
            RHYPEDB_HTTP_PORT,
            jkbase_common::config::DB_GATEWAY_HTTP_PORT,
            leg_permits.clone(),
        ));
        tokio::spawn(db_leg_loopback_proxy(
            RHYPEDB_TCP_PORT,
            jkbase_common::config::DB_GATEWAY_WIRE_PORT,
            leg_permits,
        ));
    }

    let route_config = load_route_config(&serve_dir);
    let sites = load_sites_config(&serve_dir);

    if !sites.is_empty() {
        for site in &sites {
            info!(
                site = %site.name,
                prefix = %site.prefix,
                root = %site.root.display(),
                spa = site.spa,
                "loaded site"
            );
        }
    }

    if containers.is_supervising().await {
        let containers_for_health = containers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                containers_for_health.run_health_checks().await;
            }
        });
    }

    // L4 (UDP) scale-to-zero ingress land-forward. The host relay dials `vm_ip:agent_udp_port` with
    // per-datagram-authenticated transit frames (`l4_transit`); each task const-time verifies +
    // strips the header and forwards the payload, from `l4_flow_source` (above), to
    // `127.0.0.1:guest_port` (the port the tenant's service binds in its OWN code — the agent never
    // binds eth0, P0-L4-1). Facts are host-authored and tenant-unforgeable (`_l4.json`). Empty
    // transit secret (old images / no `[l4.*]`) ⇒ start nothing (fail-closed — an empty key would
    // let a co-tenant forge the MAC). One task per port, each self-contained (not a field on
    // AgentState) so a fault on one port can't wedge another. `l4` was loaded above (for the
    // loopback-MTU decision); reuse it to start the land-forward.
    if !l4.transit_secret.is_empty() {
        for fact in &l4.ports {
            tokio::spawn(l4_forward::run_l4_land_forward(
                fact.clone(),
                l4.transit_secret.clone(),
                l4_flow_source,
            ));
        }
    }

    let port: u16 = std::env::var("JKBASE_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()?;

    let state = Arc::new(AgentState {
        serve_dir,
        functions_dir,
        functions,
        containers,
        log_sink,
        route_config,
        sites,
        db_splice_secret,
        db_admin_token,
    });

    info!("jkbase-agent starting (pid {})", std::process::id());
    info!(port, "listening");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _peer) = listener.accept().await?;
        // Which interface accepted this connection: the host reaches the agent over the
        // VM's eth0 (dest = guest_ip), the in-VM tenant app over loopback. Used to fence
        // `/_jkbase/*` control endpoints off guest loopback ([R3]). Unknown ⇒ not-loopback
        // (allow) so a local_addr glitch can't break host health checks — the /_jkbase/db
        // splice secret is the real gate regardless.
        let on_loopback = stream
            .local_addr()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle_request(state.clone(), req, on_loopback));
            // with_upgrades(): required to proxy WebSockets through to the container.
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                error!(error = %e, "connection error");
            }
        });
    }
}

fn load_sites_config(serve_dir: &Path) -> Vec<SiteEntry> {
    let sites_path = serve_dir.join("_sites.json");
    if !sites_path.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(&sites_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let sites: Vec<jkbase_common::config::ResolvedSite> = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    // Order doesn't matter: `select_site` picks the longest matching prefix itself.
    sites
        .into_iter()
        .map(|s| {
            let root = serve_dir.join(format!("_site_{}", s.name));
            SiteEntry {
                name: s.name,
                root,
                prefix: s.prefix,
                spa: s.spa,
                domain: s.domain,
            }
        })
        .filter(|s| s.root.exists())
        .collect()
}

fn load_route_config(serve_dir: &Path) -> Vec<RouteEntry> {
    let routes_path = serve_dir.join("_routes.json");
    if !routes_path.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(&routes_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let routes: std::collections::HashMap<String, jkbase_common::config::RouteTarget> =
        match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

    let mut routes: Vec<RouteEntry> = routes
        .iter()
        .filter_map(|(prefix, target)| {
            // Typed backend kind; an unknown service is dropped (forward-compat + fail-closed)
            // rather than silently treated as a server.
            let kind = match target.service.as_str() {
                "server" => RouteKind::Server,
                "function" => RouteKind::Function,
                _ => return None,
            };
            Some(RouteEntry {
                prefix: prefix.clone(),
                name: target.name.clone(),
                kind,
            })
        })
        .collect();
    // The request loop takes the first match, so the most specific prefix must come first:
    // `/api/projects/*` wins over `/api/*` (the nginx `location` rule). `_routes.json` is
    // an unordered map, so without this, overlapping prefixes matched in whatever order
    // the map happened to iterate — differently across restarts. Ties break by name for a
    // stable order.
    routes.sort_by(|a, b| {
        let len = |r: &RouteEntry| r.prefix.trim_end_matches('*').len();
        len(b).cmp(&len(a)).then_with(|| a.prefix.cmp(&b.prefix))
    });
    routes
}

/// Where `prefix` mounts `path`, at a path-segment boundary: `Some(rest)` (the path below
/// the mount, `""` for the mount point itself) or `None`. `/play` mounts `/play` and
/// `/play/x` but not `/playground`; `/` (or `""`) mounts everything.
fn mount<'p>(prefix: &str, path: &'p str) -> Option<&'p str> {
    let p = prefix.trim_end_matches('/');
    let rest = path.strip_prefix(p)?;
    (p.is_empty() || rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

fn same_domain(a: &str, b: &str) -> bool {
    let norm = |d: &str| d.trim().trim_end_matches('.').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// The static site that serves `path`, and the path within that site — the longest
/// matching prefix wins.
///
/// `host_site` is the site the proxy says this request's host is bound to (the trusted
/// `X-Jkbase-Site`). On a bound host the candidates are the sites bound to that same
/// domain plus the sites bound to none; the bound site with the shortest prefix is the
/// host's ROOT, serving its whole tree at `/` (whatever its own prefix), and every other
/// candidate is mounted at its prefix. So `studio` (`domain = "playweft"`) serves
/// `playweft.jkbase.app/` while `play` (`prefix = "/play"`, bound to the same domain or to
/// none) serves `/play/*` with its own SPA fallback. A site bound to a DIFFERENT domain is
/// never served on this host. The control plane records one site per host (the first to
/// claim it), so the domain — not that site's name — decides the candidates.
///
/// A host bound through the API to a site that declares no domain works the same way, with
/// that site as the root. Without a bound site, every site is a candidate at its prefix.
fn select_site<'s, 'p>(
    sites: &'s [SiteEntry],
    host_site: Option<&str>,
    path: &'p str,
) -> Option<(&'s SiteEntry, &'p str)> {
    let longest = |candidates: &mut dyn Iterator<Item = &'s SiteEntry>| {
        candidates
            .filter_map(|s| mount(&s.prefix, path).map(|rest| (s, rest)))
            .max_by_key(|(s, _)| s.prefix.trim_end_matches('/').len())
    };
    let Some(bound) = host_site.and_then(|name| sites.iter().find(|s| s.name == name)) else {
        return longest(&mut sites.iter());
    };
    // Sites bound to this host's domain. A host bound through the API to a site that
    // declares no domain has just that one.
    let bound_here = |s: &SiteEntry| match (bound.domain.as_deref(), s.domain.as_deref()) {
        (Some(d), Some(e)) => same_domain(d, e),
        (None, _) => s.name == bound.name,
        (Some(_), None) => false,
    };
    let root = sites
        .iter()
        .filter(|s| bound_here(s))
        .min_by_key(|s| (s.prefix.trim_end_matches('/').len(), s.name != bound.name))
        .unwrap_or(bound);
    let mounted = longest(&mut sites.iter().filter(|s| {
        (s.domain.is_none() || bound_here(s))
            && s.name != root.name
            && !s.prefix.trim_end_matches('/').is_empty()
    }));
    Some(mounted.unwrap_or((root, path)))
}

/// Unified agent response body. Most branches build a buffered [`Full`] (health, control
/// endpoints, errors, static files); the tenant server-app proxy STREAMS the app's response
/// through instead of buffering it (so an SSE/chunked feed flushes frame-by-frame, and a large
/// download isn't loaded wholly into guest RAM). A boxed body lets both coexist in one handler.
type AgentBody = BoxBody<Bytes, std::io::Error>;

/// Box a buffered [`Full`] response into [`AgentBody`] (the `Full` error is `Infallible`, mapped
/// to the `io::Error` the boxed type declares — the closure is never called).
fn box_full(resp: Response<Full<Bytes>>) -> Response<AgentBody> {
    resp.map(|b| b.map_err(|e: std::convert::Infallible| match e {}).boxed())
}

/// Box a buffered byte body into [`AgentBody`].
fn full_body(b: impl Into<Bytes>) -> AgentBody {
    Full::new(b.into())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed()
}

async fn handle_request(
    state: Arc<AgentState>,
    req: Request<hyper::body::Incoming>,
    on_loopback: bool,
) -> Result<Response<AgentBody>, hyper::Error> {
    let path = req.uri().path().to_string();

    // [R3] Control endpoints are for the HOST (reached over the VM's eth0), never the
    // in-VM tenant app. Drop any `/_jkbase/*` that arrived on guest loopback — defense in
    // depth atop each endpoint's own auth (the `/_jkbase/db` splice secret). 404 (not 403)
    // so a probing tenant can't even confirm the endpoint exists.
    if on_loopback && path.starts_with("/_jkbase/") {
        return Ok(box_full(not_found_response()));
    }

    if path == "/_jkbase/health" {
        return Ok(box_full(health_response(&state).await));
    }

    if path == "/_jkbase/db" {
        return Ok(box_full(handle_db_splice(state, req).await));
    }

    if path == "/_jkbase/db/backup" {
        return Ok(box_full(handle_db_backup(state, req).await));
    }

    if path == "/_jkbase/db/restore" {
        return Ok(box_full(handle_db_restore(state, req).await));
    }

    if path == "/_jkbase/db/query" {
        return Ok(box_full(handle_db_query(state, req, DbHttpOp::Query).await));
    }

    if path == "/_jkbase/db/schema" {
        return Ok(box_full(handle_db_query(state, req, DbHttpOp::Schema).await));
    }

    if path == "/_jkbase/db/status" {
        return Ok(box_full(handle_db_query(state, req, DbHttpOp::Status).await));
    }

    if path == "/_jkbase/db/rewrite-covers" {
        return Ok(box_full(handle_db_rewrite_covers(state, req).await));
    }

    if path == "/_jkbase/sync" {
        unsafe { libc::sync() };
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(full_body("{\"synced\":true}"))
            .unwrap());
    }

    if path == "/_jkbase/resync-clock" {
        return Ok(box_full(resync_clock_response(req).await));
    }

    if path == "/_jkbase/logs" || path.starts_with("/_jkbase/logs?") {
        return Ok(box_full(logs_response(&state, &req).await));
    }

    // Walk the tenant route table, dispatching by backend kind. A FUNCTION route is
    // request/response only: an upgrade to it gets 426 (before the body is buffered) and a
    // declared-but-missing function 404s WITHOUT falling through to static — so a misspelled
    // function name can't accidentally serve the static site or probe the metadata image.
    // A SERVER route that matches but has no running backend falls through (unchanged).
    for route in &state.route_config {
        let prefix = route.prefix.trim_end_matches('*');
        if !path.starts_with(prefix) {
            continue;
        }
        match route.kind {
            RouteKind::Server => {
                if let Some(port) = state.containers.get_server_for_route(&route.name).await {
                    return Ok(proxy_to_server(port, req).await);
                }
            }
            RouteKind::Function => {
                if jkbase_wsproxy::is_upgrade_request(req.headers()) {
                    return Ok(box_full(upgrade_required_response()));
                }
                if state.functions.has_function(&route.name) {
                    // Own the name so nothing borrows `state.route_config` across the move.
                    let name = route.name.clone();
                    info!(function = %name, path = %path, "routing to function (route)");
                    return Ok(box_full(invoke_function(state.clone(), &name, req).await));
                }
                return Ok(box_full(not_found_response()));
            }
        }
    }

    // Legacy implicit function route: `/functions/{name}`. Same request/response rules —
    // 426 on upgrade, 404 (no fallthrough) on a missing function.
    if let Some(func_name) = extract_function_name(&path) {
        if jkbase_wsproxy::is_upgrade_request(req.headers()) {
            return Ok(box_full(upgrade_required_response()));
        }
        if state.functions.has_function(&func_name) {
            info!(function = %func_name, path = %path, "routing to function");
            return Ok(box_full(invoke_function(state, &func_name, req).await));
        }
        return Ok(box_full(not_found_response()));
    }

    // Static sites. The proxy sets X-Jkbase-Site (stripped from inbound, so trusted) when
    // the request's hostname is bound to a site; `select_site` mounts that host's root
    // site plus any longer-prefix site, and otherwise picks by prefix alone.
    let host_site = req
        .headers()
        .get("x-jkbase-site")
        .and_then(|v| v.to_str().ok());
    if let Some((site, sub_path)) = select_site(&state.sites, host_site, &path) {
        return static_server::handle_static_with_path(
            &site.root,
            sub_path,
            site.spa,
            &static_server::ReqConds::from_headers(req.headers()),
        )
        .await
        .map(box_full);
    }

    // Fall through to default static file serving. handle_static serves the image
    // ROOT, which holds the host-internal `_`-prefixed control files
    // (`_servers/*.json` carries the app env, plus `_routes`/`_sites`/`_layers`/
    // `_layerpaths`/`_functions`) — so it refuses any request that resolves onto a
    // `_`-prefixed top-level entry, keeping tenant config off the public surface.
    // (Site roots `_site_<name>/` are served via the site paths above, where
    // `_`-prefixed framework dirs like `_next/` remain legitimate.)
    static_server::handle_static(&state.serve_dir, req)
        .await
        .map(box_full)
}

async fn health_response(state: &AgentState) -> Response<Full<Bytes>> {
    let functions = state.functions.list_functions();
    let servers = state.containers.status().await;
    let body = serde_json::json!({
        "status": "ok",
        "pid": std::process::id(),
        "serve_dir": state.serve_dir.display().to_string(),
        "functions_loaded": functions,
        "functions_dir_exists": state.functions_dir.exists(),
        "functions_dir": state.functions_dir.display().to_string(),
        "servers": servers,
        // Echoed so the host's VM re-adoption path can detect agent-protocol skew at adopt
        // time and force-recycle instead of re-adopting an incompatible old agent (§9).
        "agent_protocol": jkbase_common::AGENT_PROTOCOL_VERSION,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header(
            jkbase_common::AGENT_PROTOCOL_HEADER,
            jkbase_common::AGENT_PROTOCOL_VERSION.to_string(),
        )
        .body(Full::new(Bytes::from(
            serde_json::to_vec_pretty(&body).unwrap(),
        )))
        .unwrap()
}

/// Re-discipline the guest wall clock on demand by stepping CLOCK_REALTIME straight
/// to the host's PTP time. The host POSTs this right after resuming a restored
/// snapshot — the guest clock is frozen at snapshot time, so it lags by the paused
/// duration; stepping it now (rather than waiting for chrony's next poll) means the
/// first request after wake already sees correct time. chrony keeps disciplining.
async fn resync_clock_response(_req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let r = clock::resync_now();
    if r.ok {
        info!(detail = %r.detail, "clock resynced (direct PHC step)");
    } else {
        error!(detail = %r.detail, "clock resync failed");
    }
    let body = serde_json::json!({ "ok": r.ok, "detail": r.detail });
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap()
}

async fn logs_response(
    state: &AgentState,
    req: &Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let query = req.uri().query().unwrap_or("");
    let param = |key: &str| -> Option<u64> {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(key))
            .and_then(|v| v.parse().ok())
    };

    // `since` (incremental cursor) takes precedence over `limit` (tail). Read the
    // unified sink directly: it carries both server output and function egress
    // events under one `(boot_id, seq)` cursor space.
    let lines = if let Some(since) = param("since=") {
        state.log_sink.get_logs_since(since).await
    } else {
        let limit = param("limit=").unwrap_or(200) as usize;
        state.log_sink.get_logs(limit).await
    };

    let resp = jkbase_common::logs::LogsResponse {
        boot_id: state.log_sink.boot_id().to_string(),
        lines,
    };
    let body = serde_json::to_vec(&resp).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// `426 Upgrade Required` — a function backend is strictly request/response and cannot be
/// coerced into a long-lived/streaming connection (P0-INGRESS-UPGRADE). Long-lived traffic
/// must target a `server`.
fn upgrade_required_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UPGRADE_REQUIRED)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(
            "upgrade not supported on a function route; use a server backend",
        )))
        .unwrap()
}

/// `404 Not Found` for a declared-but-missing function route. Deliberately does NOT fall
/// through to static serving — a misspelled/undeployed function must not expose the static
/// site or the metadata image's `_`-prefixed control files.
fn not_found_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from("not found")))
        .unwrap()
}

fn extract_function_name(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
    if parts.first() == Some(&"functions") {
        parts.get(1).map(|s| s.to_string())
    } else {
        None
    }
}

async fn proxy_to_server(
    port: u16,
    mut req: Request<hyper::body::Incoming>,
) -> Response<AgentBody> {
    let addr = format!("127.0.0.1:{port}");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    // Capture the client-side upgrade future before the body is consumed.
    let upgrade = jkbase_wsproxy::is_upgrade_request(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));

    let stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(port, error = %e, "failed to connect to server");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("server not available"))
                .unwrap();
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(e) => {
            error!(port, error = %e, "server handshake failed");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("server handshake failed"))
                .unwrap();
        }
    };
    // The connection future must keep running to drive an upgrade; with_upgrades()
    // lets the raw stream be reclaimed from the 101 response.
    if upgrade {
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
    } else {
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }

    let mut builder = Request::builder().method(req.method()).uri(&path);
    for (key, value) in req.headers() {
        builder = builder.header(key, value);
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    match sender.send_request(proxy_req).await {
        Ok(mut resp) if resp.status() == StatusCode::SWITCHING_PROTOCOLS => {
            use jkbase_wsproxy::UpgradeOutcome;
            // The edge proxy sanitizes headers before they reach the client; here we
            // just splice (the container is this tenant's own code — intra-tenant hop).
            match jkbase_wsproxy::spawn_upgrade_relay(
                client_upgrade,
                &mut resp,
                jkbase_wsproxy::DEFAULT_RELAY_IDLE_TIMEOUT,
                upgrade_permits(),
                // In-VM hop inside the tenant's own container — no host idle tracker to
                // re-stamp (the edge proxy owns wake-on-WS keep-warm, not the agent).
                None,
            ) {
                UpgradeOutcome::Relayed => {
                    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
                    for (key, value) in resp.headers() {
                        builder = builder.header(key, value);
                    }
                    builder.body(full_body(Bytes::new())).unwrap()
                }
                UpgradeOutcome::Unsolicited => {
                    error!("container sent 101 without a client upgrade request");
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full_body("unsolicited upgrade"))
                        .unwrap()
                }
                UpgradeOutcome::CapReached => {
                    error!("in-flight upgrade cap reached; refusing relay");
                    Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header("Retry-After", "5")
                        .body(full_body("too many concurrent upgrades"))
                        .unwrap()
                }
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            // Stream the app's response through instead of buffering it: an SSE/chunked feed must
            // flush frame-by-frame (a buffered `collect()` never completes on an endless stream),
            // and a large download must not sit wholly in guest RAM.
            let body = resp.into_body().map_err(std::io::Error::other).boxed();
            let mut builder = Response::builder().status(status);
            for (key, value) in &headers {
                // Drop framing hop-by-hop headers: hyper re-frames the streamed body from its own
                // size hint, so forwarding the backend's Transfer-Encoding/Connection verbatim
                // would double-frame. A finite response's Content-Length is kept (and honoured).
                let k = key.as_str();
                if k.eq_ignore_ascii_case("transfer-encoding")
                    || k.eq_ignore_ascii_case("connection")
                {
                    continue;
                }
                builder = builder.header(key, value);
            }
            builder.body(body).unwrap()
        }
        Err(e) => {
            error!(port, error = %e, "server request failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("server request failed"))
                .unwrap()
        }
    }
}

/// Bound on concurrent in-flight relayed upgrades inside this agent (one tenant VM).
/// A relay holds a permit for its lifetime, so a flood of cheap WebSocket holds can't
/// pin unbounded fds + relay tasks. (Sanitization + the edge-wide cap live at the
/// proxy; this is the intra-VM backstop.)
fn upgrade_permits() -> &'static Arc<tokio::sync::Semaphore> {
    static PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(256)));
    &PERMITS
}

/// Bound on concurrent function invocations inside this agent (one tenant VM). Caps the
/// peak CPU/threads/memory a flood of (possibly slow, fuel-heavy) functions can pin in the
/// process that also serves this project's sites + servers. Waiters queue rather than 503.
fn function_permits() -> &'static Arc<tokio::sync::Semaphore> {
    static PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(32)));
    &PERMITS
}

/// Max request body bytes marshalled into a function (matches the response cap). The body
/// is fully buffered here, upstream of the runtime, so the bound belongs here.
const MAX_REQUEST_BODY: usize = 10 * 1024 * 1024;

async fn invoke_function(
    state: Arc<AgentState>,
    name: &str,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = match Limited::new(req.into_body(), MAX_REQUEST_BODY)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Full::new(Bytes::from("request body too large")))
                .unwrap();
        }
    };

    let func_req = FunctionRequest {
        method,
        path,
        query,
        headers,
        body,
    };

    // Hold a concurrency permit for the duration of the invocation (see function_permits).
    let _permit = function_permits()
        .clone()
        .acquire_owned()
        .await
        .expect("function semaphore is never closed");

    let func_resp = match state.functions.invoke(name, func_req).await {
        Ok(r) => r,
        Err(e) => {
            // Log the detail server-side; return a GENERIC body — the error string can carry
            // request-derived data (headers/paths a caller controls) and must not be
            // reflected back from the platform-trusted agent (review H1).
            error!(function = name, error = %e, "function invocation error");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("function error")))
                .unwrap();
        }
    };

    let mut builder = Response::builder().status(func_resp.status);
    for (key, value) in &func_resp.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    builder
        .body(Full::new(Bytes::from(func_resp.body)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    /// Byte layout of the `RTM_NEWADDR` request — the part a typo would silently break (the kernel
    /// would EINVAL and the agent would fall back to a `127.0.0.1` flow source).
    #[test]
    fn rtm_newaddr_request_layout() {
        let addr = std::net::Ipv4Addr::new(10, 254, 254, 1);
        let m = super::rtm_newaddr_request(1, addr, 7);
        let u16_at = |o: usize| u16::from_ne_bytes([m[o], m[o + 1]]);
        let u32_at = |o: usize| u32::from_ne_bytes([m[o], m[o + 1], m[o + 2], m[o + 3]]);
        assert_eq!(u32_at(0), 40, "nlmsg_len covers the whole message");
        assert_eq!(u16_at(4), 20, "RTM_NEWADDR");
        assert_eq!(
            u16_at(6),
            0x001 | 0x004 | 0x100 | 0x400,
            "REQUEST|ACK|REPLACE|CREATE"
        );
        assert_eq!(u32_at(8), 7, "seq");
        assert_eq!(u32_at(12), 0, "pid 0 = addressed to the kernel");
        assert_eq!(m[16], libc::AF_INET as u8);
        assert_eq!(
            m[17], 32,
            "a /32 — never a prefix that would route a range into lo"
        );
        assert_eq!(
            m[19], 254,
            "host scope: never auto-picked as a source for eth0 traffic"
        );
        assert_eq!(u32_at(20), 1, "ifindex");
        for (off, ty) in [(24, 2u16), (32, 1u16)] {
            assert_eq!(u16_at(off), 8, "rtattr len");
            assert_eq!(u16_at(off + 2), ty, "IFA_LOCAL then IFA_ADDRESS");
            assert_eq!(
                &m[off + 4..off + 8],
                &addr.octets(),
                "address in network order"
            );
        }
    }

    #[test]
    fn netlink_ack_parsing_fails_toward_the_fallback() {
        let ack = |ty: u16, err: i32| {
            let mut b = vec![0u8; 36];
            b[4..6].copy_from_slice(&ty.to_ne_bytes());
            b[16..20].copy_from_slice(&err.to_ne_bytes());
            b
        };
        assert!(super::parse_netlink_ack(&ack(2, 0)).is_ok());
        let eperm = super::parse_netlink_ack(&ack(2, -libc::EPERM)).unwrap_err();
        assert_eq!(eperm.raw_os_error(), Some(libc::EPERM));
        assert!(
            super::parse_netlink_ack(&ack(3, 0)).is_err(),
            "not NLMSG_ERROR"
        );
        assert!(super::parse_netlink_ack(&[0u8; 8]).is_err(), "short read");
    }

    /// The real online grow: a loop-mounted 32 MiB ext4 whose backing file is then extended
    /// to 64 MiB (what the host does) grows to fill it. Needs root + losetup + mkfs.ext4:
    ///   sudo -E cargo test -p jkbase-agent -- --ignored grow_data_fs_fills_a_grown_device
    #[test]
    #[ignore = "needs root + losetup + mkfs.ext4"]
    fn grow_data_fs_fills_a_grown_device() {
        use std::process::Command;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("jkb-grow-{nanos}"));
        let (img, mnt) = (base.join("d.img"), base.join("mnt"));
        std::fs::create_dir_all(&mnt).unwrap();
        let mib = 1024 * 1024u64;
        std::fs::File::create(&img).unwrap().set_len(32 * mib).unwrap();
        assert!(Command::new("mkfs.ext4").args(["-F", "-q"]).arg(&img).status().unwrap().success());
        let out = Command::new("losetup").args(["--find", "--show"]).arg(&img).output().unwrap();
        let dev = String::from_utf8(out.stdout).unwrap().trim().to_string();
        assert!(Command::new("mount").arg(&dev).arg(&mnt).status().unwrap().success());
        let size = || {
            let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
            let c = std::ffi::CString::new(mnt.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::statvfs(c.as_ptr(), &mut st) }, 0);
            st.f_blocks * st.f_frsize
        };
        let before = size();
        // No-op when the fs already fills the device.
        grow_data_fs(&dev, mnt.to_str().unwrap()).unwrap();
        assert_eq!(size(), before);
        // Host side: extend the backing file + refresh the loop size.
        std::fs::OpenOptions::new().write(true).open(&img).unwrap().set_len(64 * mib).unwrap();
        assert!(Command::new("losetup").args(["-c", &dev]).status().unwrap().success());
        grow_data_fs(&dev, mnt.to_str().unwrap()).unwrap();
        let after = size();
        let _ = Command::new("umount").arg(&mnt).status();
        let _ = Command::new("losetup").args(["-d", &dev]).status();
        let _ = std::fs::remove_dir_all(&base);
        assert!(after > before + 28 * mib, "grew {before} -> {after}");
    }

    use super::*;

    #[test]
    fn route_config_maps_kinds_and_drops_unknown() {
        let dir = std::env::temp_dir().join(format!("jkagent-routes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // server + function are typed; an unknown service is dropped (fail-closed), never
        // silently treated as a server.
        std::fs::write(
            dir.join("_routes.json"),
            r#"{
              "/api": {"service":"function","name":"api"},
              "/":    {"service":"server","name":"web"},
              "/x":   {"service":"bogus","name":"x"}
            }"#,
        )
        .unwrap();
        let routes = load_route_config(&dir);
        assert_eq!(routes.len(), 2, "the unknown-service route must be dropped");
        let api = routes.iter().find(|r| r.prefix == "/api").unwrap();
        assert_eq!(api.kind, RouteKind::Function);
        assert_eq!(api.name, "api");
        let web = routes.iter().find(|r| r.prefix == "/").unwrap();
        assert_eq!(web.kind, RouteKind::Server);
        assert!(!routes.iter().any(|r| r.prefix == "/x"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Overlapping route prefixes resolve to the most specific one, whatever order the
    /// unordered `_routes.json` map parses in.
    #[test]
    fn routes_are_ordered_longest_prefix_first() {
        let dir = std::env::temp_dir().join(format!("jkagent-route-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("_routes.json"),
            r#"{
              "/*":             {"service":"server","name":"web"},
              "/api/*":         {"service":"server","name":"accounts"},
              "/api/projects/*":{"service":"server","name":"store"},
              "/api":           {"service":"server","name":"bare"},
              "/":              {"service":"server","name":"root"}
            }"#,
        )
        .unwrap();
        let order: Vec<String> = load_route_config(&dir).into_iter().map(|r| r.prefix).collect();
        assert_eq!(order, ["/api/projects/*", "/api/*", "/api", "/", "/*"]);
        let first = |path: &str| {
            load_route_config(&dir)
                .into_iter()
                .find(|r| path.starts_with(r.prefix.trim_end_matches('*')))
                .map(|r| r.name)
        };
        assert_eq!(first("/api/projects/7").as_deref(), Some("store"));
        assert_eq!(first("/api/me").as_deref(), Some("accounts"));
        assert_eq!(first("/index.html").as_deref(), Some("root"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn site(name: &str, prefix: &str, domain: Option<&str>) -> SiteEntry {
        SiteEntry {
            name: name.into(),
            root: PathBuf::from(format!("/sites/{name}")),
            prefix: prefix.into(),
            spa: true,
            domain: domain.map(Into::into),
        }
    }

    /// `(site, path within it)` for a request, or `None`.
    fn pick(sites: &[SiteEntry], host_site: Option<&str>, path: &str) -> Option<(String, String)> {
        select_site(sites, host_site, path).map(|(s, rest)| (s.name.clone(), rest.to_string()))
    }

    fn at(name: &str, rest: &str) -> Option<(String, String)> {
        Some((name.into(), rest.into()))
    }

    #[test]
    fn prefixes_mount_at_segment_boundaries() {
        assert_eq!(mount("/play", "/play"), Some(""));
        assert_eq!(mount("/play", "/play/"), Some("/"));
        assert_eq!(mount("/play/", "/play/abc/x.js"), Some("/abc/x.js"));
        assert_eq!(mount("/play", "/playground"), None);
        assert_eq!(mount("/f", "/favicon.ico"), None);
        assert_eq!(mount("/", "/anything"), Some("/anything"));
        assert_eq!(mount("", "/anything"), Some("/anything"));
    }

    /// Without a bound host, the longest matching prefix wins, at segment boundaries —
    /// antsome's layout on prod: `/faq` or `/apple` are not under the `/f` or `/app` SPAs
    /// (which used to answer them with their own index.html) but under the root site.
    #[test]
    fn unbound_hosts_pick_the_longest_prefix_at_a_segment_boundary() {
        let sites = [
            site("home", "/", None),
            site("f", "/f", None),
            site("app", "/app", None),
            site("terms", "/terms", None),
        ];
        assert_eq!(pick(&sites, None, "/favicon.ico"), at("home", "/favicon.ico"));
        assert_eq!(pick(&sites, None, "/f/abc"), at("f", "/abc"));
        assert_eq!(pick(&sites, None, "/f"), at("f", ""));
        assert_eq!(pick(&sites, None, "/apple-touch-icon.png"), at("home", "/apple-touch-icon.png"));
        assert_eq!(pick(&sites, None, "/app/settings"), at("app", "/settings"));
        // No root site: an unmatched path has no site.
        assert_eq!(pick(&sites[1..], None, "/other"), None);
    }

    /// The Playweft ask: the domain-bound root site serves the host, and a longer-prefix
    /// site — bound to the same domain or to none — serves its prefix with its own SPA.
    #[test]
    fn a_longer_prefix_site_is_served_on_a_bound_host() {
        for play_domain in [Some("playweft"), None, Some("PlayWeft.")] {
            let sites = [
                site("studio", "/", Some("playweft")),
                site("play", "/play", play_domain),
            ];
            // Whichever site the control plane recorded for the host: the first to claim
            // it, so `play` too when both declare the domain.
            let headers: &[&str] = if play_domain.is_some() { &["studio", "play"] } else { &["studio"] };
            for &header in headers {
                let h = Some(header);
                assert_eq!(pick(&sites, h, "/"), at("studio", "/"), "{play_domain:?} {header}");
                assert_eq!(pick(&sites, h, "/verify"), at("studio", "/verify"));
                assert_eq!(pick(&sites, h, "/play/p123"), at("play", "/p123"));
                assert_eq!(pick(&sites, h, "/play/assets/g.wasm"), at("play", "/assets/g.wasm"));
                assert_eq!(pick(&sites, h, "/playground"), at("studio", "/playground"));
            }
        }
    }

    /// A bound host never serves a site bound to a different domain, and an unbound root
    /// site doesn't displace the bound one.
    #[test]
    fn a_bound_host_only_serves_its_own_and_unbound_sites() {
        let sites = [
            site("www", "/", Some("example.com")),
            site("docs", "/docs", Some("docs.example.com")),
            site("blog", "/blog", None),
            site("fallback", "/", None),
        ];
        let h = Some("www");
        assert_eq!(pick(&sites, h, "/docs/intro"), at("www", "/docs/intro"));
        assert_eq!(pick(&sites, h, "/blog/post"), at("blog", "/post"));
        assert_eq!(pick(&sites, h, "/"), at("www", "/"));
        // On docs' own host, docs is the root (its `/docs` prefix doesn't apply there).
        assert_eq!(pick(&sites, Some("docs"), "/intro"), at("docs", "/intro"));
        assert_eq!(pick(&sites, Some("docs"), "/blog/x"), at("blog", "/x"));
        // The project's own host (no binding): plain prefix routing over every site.
        assert_eq!(pick(&sites, None, "/docs/intro"), at("docs", "/intro"));
        assert_eq!(pick(&sites, None, "/x"), at("fallback", "/x"));
    }

    /// A single domain-bound site is served whole on its host, as before — including
    /// when it declares a prefix of its own.
    #[test]
    fn a_lone_bound_site_still_serves_its_whole_tree() {
        let sites = [site("docs", "/docs", Some("docs")), site("home", "/", None)];
        assert_eq!(pick(&sites, Some("docs"), "/"), at("docs", "/"));
        assert_eq!(pick(&sites, Some("docs"), "/docs/x"), at("docs", "/docs/x"));
        // An API-bound host whose site declares no domain: that site is the root, and
        // unbound longer prefixes still mount.
        let sites = [site("main", "/", None), site("admin", "/admin", None)];
        assert_eq!(pick(&sites, Some("main"), "/admin/users"), at("admin", "/users"));
        assert_eq!(pick(&sites, Some("main"), "/x"), at("main", "/x"));
        // A header naming no deployed site falls back to plain prefix routing.
        assert_eq!(pick(&sites, Some("gone"), "/x"), at("main", "/x"));
    }

    /// Serve `serve_dir` through the agent's real request handler on a loopback port.
    async fn serve_agent(serve_dir: &Path) -> SocketAddr {
        serve_agent_with(serve_dir, None, None, true).await
    }

    /// [`serve_agent`] with the host-only DB secrets baked and the arrival plane chosen
    /// (`on_loopback == false` ⇒ as if the request came in over eth0 from the host).
    async fn serve_agent_with(
        serve_dir: &Path,
        db_splice_secret: Option<&str>,
        db_admin_token: Option<&str>,
        on_loopback: bool,
    ) -> SocketAddr {
        let log_sink = Arc::new(LogSink::new());
        let egress = function_egress::EgressContext::new(
            &jkbase_common::config::PlatformEgress::default(),
            log_sink.clone(),
        )
        .unwrap();
        let state = Arc::new(AgentState {
            serve_dir: serve_dir.to_path_buf(),
            functions_dir: serve_dir.join("_functions"),
            functions: FunctionRuntime::new(egress),
            containers: Arc::new(ContainerSupervisor::new(
                serve_dir.join("_servers"),
                HashMap::new(),
                log_sink.clone(),
            )),
            log_sink,
            route_config: load_route_config(serve_dir),
            sites: load_sites_config(serve_dir),
            db_splice_secret: db_splice_secret.map(str::to_string),
            db_admin_token: db_admin_token.map(str::to_string),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let state = state.clone();
                tokio::spawn(async move {
                    let svc =
                        service_fn(move |req| handle_request(state.clone(), req, on_loopback));
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        addr
    }

    /// `GET path` with an optional proxy-stamped site header → (status, body).
    async fn get(addr: SocketAddr, site: Option<&str>, path: &str) -> (u16, String) {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut req = Request::get(path).header("host", "playweft.jkbase.app");
        if let Some(site) = site {
            req = req.header("x-jkbase-site", site);
        }
        let resp = sender
            .send_request(req.body(http_body_util::Empty::<Bytes>::new()).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// `method path` carrying `x-jkbase-db-secret: secret` (when given) → status.
    async fn db_call(addr: SocketAddr, method: &str, path: &str, secret: Option<&str>) -> u16 {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "10.0.0.2");
        if let Some(s) = secret {
            req = req.header("x-jkbase-db-secret", s);
        }
        let resp = sender
            .send_request(req.body(http_body_util::Empty::<Bytes>::new()).unwrap())
            .await
            .unwrap();
        resp.status().as_u16()
    }

    /// The rewrite-covers seam fails closed before it ever dials the engine: a tenant on guest
    /// loopback, a missing or wrong splice secret, and a VM with no admin token baked all get the
    /// same 404 as an unknown path; a GET with the right secret can't start a mutating pass.
    /// (The engine leg itself is covered in `db_engine::tests`.)
    #[tokio::test]
    async fn rewrite_covers_is_host_only_secret_gated_and_post_only() {
        let dir = std::env::temp_dir().join(format!("jkagent-rwc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = "/_jkbase/db/rewrite-covers";

        let from_tenant = serve_agent_with(&dir, Some("s3cret"), Some("adm"), true).await;
        assert_eq!(db_call(from_tenant, "POST", p, Some("s3cret")).await, 404);

        let host = serve_agent_with(&dir, Some("s3cret"), Some("adm"), false).await;
        assert_eq!(db_call(host, "POST", p, None).await, 404);
        assert_eq!(db_call(host, "POST", p, Some("wrong")).await, 404);
        assert_eq!(db_call(host, "POST", p, Some("s3cre")).await, 404);
        assert_eq!(db_call(host, "GET", p, Some("s3cret")).await, 405);

        let no_db = serve_agent_with(&dir, None, None, false).await;
        assert_eq!(db_call(no_db, "POST", p, Some("s3cret")).await, 404);
        let no_admin = serve_agent_with(&dir, Some("s3cret"), None, false).await;
        assert_eq!(db_call(no_admin, "POST", p, Some("s3cret")).await, 404);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// End to end through the real handler: the Playweft layout — a domain-bound SPA at
    /// the root and a second SPA at `/play` on the same host — plus a site bound to another
    /// domain, which this host must never serve.
    #[tokio::test]
    async fn a_bound_host_serves_a_longer_prefix_site_end_to_end() {
        let dir = std::env::temp_dir().join(format!("jkagent-sites-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (site, files) in [
            ("studio", &[("index.html", "STUDIO"), ("app.js", "studio-js")][..]),
            ("play", &[("index.html", "PLAY"), ("assets/g.js", "play-js")][..]),
            ("docs", &[("index.html", "DOCS")][..]),
        ] {
            for (name, body) in files {
                let f = dir.join(format!("_site_{site}")).join(name);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(f, body).unwrap();
            }
        }
        // As the deploy writes it: resolved sites, longest prefix first.
        std::fs::write(
            dir.join("_sites.json"),
            r#"[
              {"name":"play","public":"p","spa":true,"prefix":"/play","domain":"playweft"},
              {"name":"docs","public":"d","spa":false,"prefix":"/docs","domain":"docs.example.com"},
              {"name":"studio","public":"s","spa":true,"prefix":"/","domain":"playweft"}
            ]"#,
        )
        .unwrap();
        let addr = serve_agent(&dir).await;
        // The control plane may have recorded either site for the host.
        for host_site in ["studio", "play"] {
            let h = Some(host_site);
            assert_eq!(get(addr, h, "/").await, (200, "STUDIO".into()), "{host_site}");
            assert_eq!(get(addr, h, "/app.js").await, (200, "studio-js".into()));
            assert_eq!(get(addr, h, "/verify").await, (200, "STUDIO".into()), "studio SPA fallback");
            assert_eq!(get(addr, h, "/play/p123").await, (200, "PLAY".into()), "play SPA fallback");
            assert_eq!(get(addr, h, "/play/assets/g.js").await, (200, "play-js".into()));
            assert_eq!(get(addr, h, "/playground").await, (200, "STUDIO".into()));
            // docs is bound elsewhere: on this host /docs is just a studio route.
            assert_eq!(get(addr, h, "/docs").await, (200, "STUDIO".into()));
        }
        // docs on its own host is its root.
        assert_eq!(get(addr, Some("docs"), "/").await, (200, "DOCS".into()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn function_name_extraction() {
        assert_eq!(
            extract_function_name("/functions/hello"),
            Some("hello".into())
        );
        assert_eq!(
            extract_function_name("/functions/hello/world"),
            Some("hello".into())
        );
        assert_eq!(extract_function_name("/api/foo"), None);
        assert_eq!(extract_function_name("/"), None);
    }
}
