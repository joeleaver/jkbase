//! The `jkbase-server gen-build-ca [<dir>]` bootstrap subcommand.

use crate::build_ca;
use anyhow::Result;
use std::path::PathBuf;

/// Materialize the shared build-mirror CA (ca.key + ca.crt) and return, so the toolchain bake
/// can inject the public cert before the server proper ever runs.
pub(crate) fn run() -> Result<()> {
    // Resolve the CA dir consistently with the server's {data_dir}/build-ca so a
    // mismatched default can't silently bake one CA while the server mints another:
    //   1) an explicit positional dir, else
    //   2) {--data-dir}/build-ca if --data-dir is on the command line, else
    //   3) /var/jkbase/build-ca (the server's default data dir).
    let argv: Vec<String> = std::env::args().collect();
    let explicit = argv
        .get(2)
        .filter(|a| !a.starts_with("--"))
        .map(PathBuf::from);
    let dir = explicit.unwrap_or_else(|| {
        let data_dir = argv
            .windows(2)
            .find(|w| w[0] == "--data-dir")
            .map(|w| PathBuf::from(&w[1]))
            .unwrap_or_else(|| PathBuf::from("/var/jkbase"));
        data_dir.join("build-ca")
    });
    let ca = build_ca::BuildCa::load_or_generate(&dir)?;
    println!(
        "build-mirror CA ready ({}): key={} cert={} fingerprint={}",
        if ca.generated {
            "generated"
        } else {
            "loaded existing"
        },
        dir.join("ca.key").display(),
        dir.join("ca.crt").display(),
        ca.fingerprint(),
    );
    Ok(())
}
