//! Compile-fail gate: the four role traits are distinct types, so a backend of
//! one role can never be substituted for another (R3 ≠ R4, etc.). trybuild checks
//! the snippets under tests/ui/ fail to compile with the recorded diagnostics.
//!
//! If a rustc update changes the diagnostic wording, regenerate the expected
//! output with: `TRYBUILD=overwrite cargo test -p jkbase-substrate --test trybuild`.

#[test]
fn role_traits_are_distinct_types() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
