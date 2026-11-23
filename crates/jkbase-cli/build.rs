// Bake the target triple in: `jkbase upgrade` downloads the release asset named for it.
fn main() {
    println!(
        "cargo:rustc-env=JKBASE_TARGET={}",
        std::env::var("TARGET").expect("cargo sets TARGET")
    );
}
