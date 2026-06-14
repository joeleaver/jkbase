//! In-guest **dm-verity** activation for the shared runtime layers.
//!
//! ## Why dm-verity (and not fs-verity)
//!
//! The shared runtime layers reach the guest as **raw block devices** (Firecracker
//! drives `/dev/vdc..`), and the guest mounts erofs from them. fs-verity is a per-FILE
//! filesystem feature — it cannot protect a raw block device — so the right tool for a
//! block device is dm-verity: a root-hash-pinned Merkle device the kernel verifies on
//! every block read (a tampered block → EIO). The host pre-computes the hash tree
//! (appended to the same content-addressed blob) + the root hash at build time; the
//! agent activates a verity device here and mounts erofs from `/dev/mapper/<name>`.
//! Verification is **fail-closed**: a layer that declares a root hash but won't activate
//! is an error, never a silent fall-through to an unverified mount.
//!
//! ## Layout
//!
//! Each verity'd layer blob is `[ erofs data | dm-verity hash tree ]` in one file (the
//! tree begins at `data_size`, block-aligned, with a one-block verity superblock that
//! `veritysetup` writes there). The agent runs `veritysetup open --hash-offset=<data_size>`
//! against the block device, pinning the explicit `root_hash` from `_layers.json`; the
//! superblock supplies the rest of the tree geometry (and is itself covered by the tree,
//! so a tampered superblock fails verification against the pinned root).
//!
//! We shell out to the battle-tested `veritysetup` (in the agent's runtime image) rather
//! than hand-roll the device-mapper ioctl: dm-verity setup is security-load-bearing and
//! the userland tool is the proven, maintained path; a couple-MB of runtime image is a
//! worthwhile trade for not reimplementing the DM ABI in PID1.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use jkbase_common::layers::VerityParams;

/// The verity tool the agent execs (shipped in the runtime image).
const VERITYSETUP: &str = "veritysetup";
/// dm-verity (and the host's hash-tree build) use a 4096-byte block.
const VERITY_BLOCK_SIZE: u64 = 4096;

/// An active dm-verity mapping. Dropping it tears the mapping down (best-effort), so a
/// failed mount never leaks a dm device. After the erofs mount holds the device, call
/// [`VerityDevice::leak`] so teardown doesn't race the live mount.
pub struct VerityDevice {
    name: String,
    node: PathBuf,
    armed: bool,
}

impl VerityDevice {
    /// The `/dev/mapper/<name>` block device to mount erofs from (reads are
    /// Merkle-verified; a tampered block returns EIO).
    pub fn path(&self) -> &Path {
        &self.node
    }

    /// Disarm teardown-on-drop — the caller takes over the device's lifetime (the erofs
    /// mount now holds it, so it must outlive this handle).
    pub fn leak(mut self) {
        self.armed = false;
    }
}

impl Drop for VerityDevice {
    fn drop(&mut self) {
        if self.armed {
            let _ = close(&self.name);
        }
    }
}

/// `true` iff `s` is non-empty ASCII-hex — so a root hash / salt can never inject an
/// argument or whitespace into the `veritysetup` invocation.
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True iff the device-mapper control interface is present (the kernel has CONFIG_DM)
/// AND `veritysetup` is available — i.e. verity activation is possible in this guest.
pub fn available() -> bool {
    Path::new("/dev/mapper/control").exists() && which_veritysetup().is_some()
}

fn which_veritysetup() -> Option<PathBuf> {
    for d in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        let p = Path::new(d).join(VERITYSETUP);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Activate a dm-verity device named `name` over the block device `data_dev` (which
/// holds erofs data followed by the verity hash tree at `params.data_size`), pinned to
/// `params.root_hash`. Returns a handle whose `.path()` is `/dev/mapper/<name>` to mount
/// erofs from. Fail-closed: any malformed param or a `veritysetup` failure is an error.
pub fn activate(name: &str, data_dev: &Path, params: &VerityParams) -> io::Result<VerityDevice> {
    if !is_hex(&params.root_hash) {
        return Err(io::Error::other(format!("dm-verity: malformed root_hash for {name}")));
    }
    if params.data_size == 0 || !params.data_size.is_multiple_of(VERITY_BLOCK_SIZE) {
        return Err(io::Error::other(format!(
            "dm-verity: data_size {} not a positive multiple of {VERITY_BLOCK_SIZE}",
            params.data_size
        )));
    }
    // The device name is host-controlled (a layer slug), but validate it can't smuggle
    // shell/arg trickery — exec'd argv is not a shell, yet keep it strict.
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(io::Error::other(format!("dm-verity: bad device name {name:?}")));
    }
    let tool = which_veritysetup()
        .ok_or_else(|| io::Error::other("dm-verity: veritysetup not found in the runtime image"))?;

    // `veritysetup open <data_dev> <name> <hash_dev> <root_hash> --hash-offset=<data_size>`.
    // data_dev == hash_dev (one blob); the salt + tree geometry come from the on-blob
    // superblock, but the trust anchor is the explicit, host-pinned root_hash.
    let out = Command::new(&tool)
        .arg("open")
        .arg(data_dev)
        .arg(name)
        .arg(data_dev)
        .arg(&params.root_hash)
        .arg(format!("--hash-offset={}", params.data_size))
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "dm-verity: veritysetup open {name} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(VerityDevice {
        name: name.to_string(),
        node: PathBuf::from(format!("/dev/mapper/{name}")),
        armed: true,
    })
}

/// Tear down a verity mapping by name (`veritysetup close`). Best-effort.
pub fn close(name: &str) -> io::Result<()> {
    let tool = which_veritysetup()
        .ok_or_else(|| io::Error::other("dm-verity: veritysetup not found"))?;
    let _ = Command::new(&tool).arg("close").arg(name).output()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_validation() {
        assert!(is_hex("deadbeef00"));
        assert!(!is_hex(""));
        assert!(!is_hex("dead beef"));
        assert!(!is_hex("xyz"));
    }

    #[test]
    fn activate_rejects_bad_params() {
        let bad_hash = VerityParams { root_hash: "nothex!".into(), salt: "00".into(), data_size: 4096 };
        assert!(activate("jkv", Path::new("/dev/null"), &bad_hash).is_err());
        let bad_size = VerityParams { root_hash: "ab".into(), salt: "cd".into(), data_size: 4097 };
        assert!(activate("jkv", Path::new("/dev/null"), &bad_size).is_err());
        let bad_name = VerityParams { root_hash: "ab".into(), salt: "cd".into(), data_size: 4096 };
        assert!(activate("bad name!", Path::new("/dev/null"), &bad_name).is_err());
    }

    // THE end-to-end proof: a real erofs layer + an appended verity tree, activated by
    // `activate()` and mounted. (1) clean → erofs mounts + the marker reads back; (2) a
    // tampered data block → activation/read FAILS (dm-verity catches it). Runs on the
    // host kernel (same flow the guest agent uses). Root + veritysetup + erofs-utils +
    // losetup required.
    //
    //   sudo $(ls -t target/debug/deps/jkbase_agent-* | grep -v '\.d$' | head -1) \
    //       --ignored --nocapture dmverity_erofs_roundtrip_and_tamper
    #[test]
    #[ignore = "needs root + veritysetup + mkfs.erofs + losetup + /dev/mapper/control"]
    fn dmverity_erofs_roundtrip_and_tamper() {
        use std::process::Command as C;
        if !available() {
            eprintln!("skip: veritysetup / dm not available");
            return;
        }
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("jkvd-{pid}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tree/etc")).unwrap();
        std::fs::write(dir.join("tree/etc/marker"), b"verity-ok\n").unwrap();
        // Multi-block erofs so the hash tree is non-degenerate.
        for i in 0..64 {
            std::fs::write(dir.join(format!("tree/etc/f{i}")), vec![b'x'; 8192]).unwrap();
        }
        let blob = dir.join("layer.erofs");
        assert!(C::new("mkfs.erofs").args(["-zlz4hc", "--all-root"]).arg(&blob).arg(dir.join("tree")).output().unwrap().status.success());
        // 4096-align the erofs blob, then append the verity tree there.
        let sz = std::fs::metadata(&blob).unwrap().len();
        let data_size = sz.div_ceil(4096) * 4096;
        if data_size > sz {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&blob).unwrap();
            f.write_all(&vec![0u8; (data_size - sz) as usize]).unwrap();
        }
        let salt = "ab".repeat(32);
        let fmt = C::new("veritysetup")
            .args(["format", "--data-block-size=4096", "--hash-block-size=4096", &format!("--hash-offset={data_size}"), &format!("--salt={salt}")])
            .arg(&blob).arg(&blob).output().unwrap();
        assert!(fmt.status.success(), "format: {}", String::from_utf8_lossy(&fmt.stderr));
        let stdout = String::from_utf8_lossy(&fmt.stdout);
        let root_hash = stdout.lines().find(|l| l.to_lowercase().contains("root hash"))
            .and_then(|l| l.split_whitespace().find(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())))
            .expect("root hash").to_string();

        let lo = C::new("losetup").args(["-f", "--show"]).arg(&blob).output().unwrap();
        let loopdev = String::from_utf8_lossy(&lo.stdout).trim().to_string();
        let cleanup = || { let _ = C::new("losetup").arg("-d").arg(&loopdev).status(); };
        let params = VerityParams { root_hash: root_hash.clone(), salt: salt.clone(), data_size };
        let mnt = dir.join("mnt");
        std::fs::create_dir_all(&mnt).unwrap();

        // (1) clean activation → erofs mounts → marker reads.
        {
            let dev = activate(&format!("jkvd-ok-{pid}"), Path::new(&loopdev), &params)
                .unwrap_or_else(|e| { cleanup(); panic!("activate(clean): {e}") });
            let m = C::new("mount").args(["-t", "erofs", "-o", "ro"]).arg(dev.path()).arg(&mnt).output().unwrap();
            assert!(m.status.success(), "mount: {}", String::from_utf8_lossy(&m.stderr));
            let marker = std::fs::read_to_string(mnt.join("etc/marker")).unwrap();
            assert_eq!(marker.trim(), "verity-ok");
            let _ = C::new("umount").arg(&mnt).status();
            drop(dev);
        }
        // (2) tamper a data block → activation+read must FAIL (verity catches it).
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new().write(true).open(&blob).unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&[0xff; 4096]).unwrap();
            f.sync_all().unwrap();
            let res = activate(&format!("jkvd-bad-{pid}"), Path::new(&loopdev), &params);
            let failed = match res {
                Err(_) => true, // verity rejected at activation
                Ok(dev) => {
                    let m = C::new("mount").args(["-t", "erofs", "-o", "ro"]).arg(dev.path()).arg(&mnt).output().unwrap();
                    let read_fail = !m.status.success()
                        || std::fs::read_to_string(mnt.join("etc/marker")).is_err();
                    let _ = C::new("umount").arg(&mnt).status();
                    drop(dev);
                    read_fail
                }
            };
            assert!(failed, "a tampered data block MUST fail verity");
        }
        cleanup();
        let _ = std::fs::remove_dir_all(&dir);
        println!("PASS: dm-verity activate → erofs mount + read OK; tampered block fails");
    }
}
