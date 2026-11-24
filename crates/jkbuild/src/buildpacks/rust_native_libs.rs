//! The Rust buildpack's native-lib closure: ship the non-base shared libs an app's
//! binaries dynamically link (libstdc++, libssl/libcrypto, libz, …) into the app layer,
//! so C/C++-FFI crates run WITHOUT polluting the SHARED `rust` runtime layer. Split out
//! of `rust.rs` by responsibility (ELF/loader tracing is independent of cargo).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};


/// Sonames provided by the shared BASE layer (the glibc closure + `libgcc_s` from
/// the `ld-linux` package). These must NOT be shipped in the app layer — shipping a
/// glibc `.so` would shadow base's and risk a version skew.
fn is_base_lib(soname: &str) -> bool {
    const BASE: &[&str] = &[
        "libc.so",
        "libm.so",
        "libdl.so",
        "libpthread.so",
        "librt.so",
        "libresolv.so",
        "libnsl.so",
        "libutil.so",
        "libcrypt.so",
        "libanl.so",
        "libnss_",
        "libgcc_s.so",
        "ld-linux",
        "linux-vdso",
    ];
    BASE.iter().any(|b| soname.starts_with(b))
}

/// Parse one `ldd` output line into `(soname, resolved-path)`. Returns `None` for
/// the loader line, the vDSO, and `not found`/unresolved entries.
/// e.g. `\tlibssl.so.3 => /usr/lib/libssl.so.3 (0x00007f…)` → `("libssl.so.3","/usr/lib/libssl.so.3")`.
fn parse_ldd_line(line: &str) -> Option<(&str, &str)> {
    let (soname, rest) = line.trim().split_once(" => ")?;
    let path = rest.split(" (").next().unwrap_or("").trim();
    if path.is_empty() || path == "not found" {
        return None;
    }
    Some((soname.trim(), path))
}

/// Read a dynamic ELF's `PT_INTERP` (the dynamic linker the binary uses). `None`
/// for a static binary or a malformed/foreign ELF. 64-bit little-endian only (our
/// only build target); a different arch just falls back to the fixed loader paths.
fn read_pt_interp(bin: &Path) -> Option<String> {
    let data = std::fs::read(bin).ok()?;
    // ELF64, little-endian (e_ident: magic + EI_CLASS=2 + EI_DATA=1).
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return None;
    }
    let rd_u16 = |o: usize| -> Option<usize> {
        Some(u16::from_le_bytes(data.get(o..o + 2)?.try_into().ok()?) as usize)
    };
    let rd_u32 = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
    };
    let rd_u64 = |o: usize| -> Option<usize> {
        Some(u64::from_le_bytes(data.get(o..o + 8)?.try_into().ok()?) as usize)
    };
    let e_phoff = rd_u64(0x20)?;
    let e_phentsize = rd_u16(0x36)?;
    let e_phnum = rd_u16(0x38)?;
    for i in 0..e_phnum {
        let ph = e_phoff + i * e_phentsize;
        if rd_u32(ph)? == 3 {
            // PT_INTERP: p_offset @ +8, p_filesz @ +32.
            let off = rd_u64(ph + 8)?;
            let sz = rd_u64(ph + 32)?;
            let raw = data.get(off..(off + sz).min(data.len()))?;
            let s = String::from_utf8_lossy(raw)
                .trim_end_matches('\0')
                .to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// The dynamic-lib trace for `bin` in ldd's text format. Wolfi's minimal glibc ships
/// NO `ldd` script, but the dynamic linker has a `--list` mode that does the same;
/// invoke the binary's own `PT_INTERP` loader (then fixed fallbacks). `--list` lists
/// deps WITHOUT running the binary (safe for a hostile/server binary), and reports
/// "not a dynamic executable" for a static one.
fn lib_trace(bin: &Path) -> Vec<String> {
    if let Ok(out) = std::process::Command::new("ldd").arg(bin).output()
        && (out.status.success() || String::from_utf8_lossy(&out.stdout).contains(" => "))
    {
        return String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(String::from)
            .collect();
    }
    let mut loaders: Vec<String> = Vec::new();
    if let Some(interp) = read_pt_interp(bin) {
        loaders.push(interp);
    }
    loaders.push("/lib/ld-linux-x86-64.so.2".into());
    loaders.push("/usr/lib/ld-linux-x86-64.so.2".into());
    for loader in loaders {
        if !Path::new(&loader).exists() {
            continue;
        }
        if let Ok(out) = std::process::Command::new(&loader)
            .arg("--list")
            .arg(bin)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains(" => ") || text.contains("not a dynamic") {
                return text.lines().map(String::from).collect();
            }
        }
    }
    Vec::new()
}

/// Ship each binary's non-base dynamic-lib closure into `lib_dir` (the layer's
/// `/usr/lib`), so a Rust app with C/C++ FFI deps runs without polluting the SHARED
/// rust runtime layer. The trace is transitive, so one pass per binary captures the
/// full closure (libstdc++ → its own deps, etc.). A static binary or an empty trace
/// ships nothing — that is correct, not an error. Runs inside the sealed build VM on
/// the tenant's own binary, within the existing VM trust boundary.
pub(super) fn ship_native_lib_closure(
    app_at: &Path,
    bins: &[(String, PathBuf)],
    lib_dir: &Path,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut shipped: std::collections::BTreeSet<String> = Default::default();
    for (name, _) in bins {
        let bin = app_at.join(name);
        for line in lib_trace(&bin) {
            let Some((soname, path)) = parse_ldd_line(&line) else {
                continue;
            };
            if is_base_lib(soname) {
                continue; // base layer provides it; don't shadow
            }
            if !shipped.insert(soname.to_string()) {
                continue; // already shipped (shared across binaries)
            }
            // Copy the fully-resolved real file under the soname the binary NEEDs, so
            // the runtime linker finds it via the default /usr/lib search.
            let real = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
            std::fs::create_dir_all(lib_dir)
                .with_context(|| format!("create app lib dir {}", lib_dir.display()))?;
            let dest = lib_dir.join(soname);
            std::fs::copy(&real, &dest)
                .with_context(|| format!("ship native lib {soname} from {}", real.display()))?;
            let mut perm = std::fs::metadata(&dest)?.permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&dest, perm)?;
        }
    }
    if !shipped.is_empty() {
        eprintln!(
            "jkbuild: shipped native-lib closure into /usr/lib: {}",
            shipped.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ldd_line_extracts_soname_and_path() {
        assert_eq!(
            parse_ldd_line("\tlibssl.so.3 => /usr/lib/libssl.so.3 (0x00007f1234)"),
            Some(("libssl.so.3", "/usr/lib/libssl.so.3"))
        );
        assert_eq!(
            parse_ldd_line("\tlibstdc++.so.6 => /usr/lib/libstdc++.so.6 (0x00007fabcd)"),
            Some(("libstdc++.so.6", "/usr/lib/libstdc++.so.6"))
        );
        // loader + vDSO (no " => ") and unresolved entries are skipped.
        assert_eq!(
            parse_ldd_line("\t/lib/ld-linux-x86-64.so.2 (0x00007f0000)"),
            None
        );
        assert_eq!(parse_ldd_line("\tlinux-vdso.so.1 (0x00007ffd)"), None);
        assert_eq!(parse_ldd_line("\tlibfoo.so.1 => not found"), None);
    }

    #[test]
    fn base_libs_excluded_native_libs_shipped() {
        // glibc closure + libgcc_s + loader come from the base layer (don't ship).
        for b in [
            "libc.so.6",
            "libm.so.6",
            "libgcc_s.so.1",
            "libpthread.so.0",
            "ld-linux-x86-64.so.2",
            "linux-vdso.so.1",
        ] {
            assert!(is_base_lib(b), "{b} should be base-provided");
        }
        // native-FFI libs are shipped per-app into the app layer's /usr/lib.
        for n in [
            "libstdc++.so.6",
            "libssl.so.3",
            "libcrypto.so.3",
            "libz.so.1",
            "libzstd.so.1",
            "libonnxruntime.so",
        ] {
            assert!(!is_base_lib(n), "{n} should be shipped");
        }
    }
}
