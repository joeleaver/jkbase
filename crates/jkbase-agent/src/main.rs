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

fn mount_content_drive(target: &str) {
    use std::ffi::CString;
    use std::ptr;

    // The content drive is the second virtio block device: /dev/vdb
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

    if is_pid1() {
        mount_content_drive(serve_dir.to_str().unwrap_or("/srv/www"));
    }

    let port: u16 = std::env::var("JKBASE_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()?;

    info!("jkbase-agent starting (pid {})", std::process::id());
    info!(dir = %serve_dir.display(), port, "serving static files");

    static_server::serve(serve_dir, port).await
}
