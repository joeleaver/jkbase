//! Neutrality grep gate: vendor/backend crate paths must appear ONLY in the
//! backend-impl modules + the factory, never in the trait abstraction (`lib.rs`).
//! If a backend type leaks into a trait signature the whole point of the seam is
//! lost, so this fails the build.

use std::fs;

#[test]
fn no_vendor_crate_paths_leak_into_the_abstraction() {
    let lib = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read src/lib.rs");
    // Storage-vendor crate paths that must stay behind the seam (module names like
    // `redb_control` are fine — only `::`-qualified vendor usage is forbidden).
    let forbidden = [
        "redb::",
        "object_store::",
        "etcd_client::",
        "rusqlite::",
        "aws_sdk",
        "aws_config",
    ];
    for pat in forbidden {
        assert!(
            !lib.contains(pat),
            "vendor/backend path `{pat}` leaked into src/lib.rs (the trait abstraction) — \
             keep it in the backend-impl modules + factory"
        );
    }
}
