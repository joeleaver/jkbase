mod static_server;

use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

fn mount_filesystems() {
    use std::ffi::CString;
    use std::ptr;

    let mounts = [
        ("/proc", "proc", "proc"),
        ("/sys", "sysfs", "sysfs"),
        ("/dev", "devtmpfs", "devtmpfs"),
    ];

    for (target, fstype, source) in &mounts {
        let _ = std::fs::create_dir_all(target);
        let src = CString::new(*source).unwrap();
        let tgt = CString::new(*target).unwrap();
        let fst = CString::new(*fstype).unwrap();
        unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fst.as_ptr(),
                0,
                ptr::null(),
            );
        }
    }
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

#[tokio::main]
async fn main() -> Result<()> {
    if is_pid1() {
        mount_filesystems();
    }

    tracing_subscriber::fmt::init();

    let serve_dir = PathBuf::from(
        std::env::var("JKBASE_SERVE_DIR").unwrap_or_else(|_| "/srv/www".to_string()),
    );
    let port: u16 = std::env::var("JKBASE_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()?;

    info!("jkbase-agent starting (pid {})", std::process::id());
    info!(dir = %serve_dir.display(), port, "serving static files");

    static_server::serve(serve_dir, port).await
}
