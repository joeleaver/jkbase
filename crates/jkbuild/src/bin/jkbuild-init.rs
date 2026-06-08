//! `jkbuild-init` — the build-VM entrypoint (PID1), baked into the toolchain image
//! as `/sbin/init`. Drives the lifecycle and propagates the build's exit code.
//! When running as PID1 the lifecycle itself writes `/out/status` and reboots
//! (the clean way a Firecracker x86 guest exits), so reaching `exit` here only
//! happens off-VM (e.g. manual debugging).

fn main() {
    let code = match jkbuild::lifecycle::run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("jkbuild-init: fatal: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
