//! Reach-plane e2e probe: connect the REAL `rhypedb-client` over the binary TCP wire to
//! `argv[1]` (a `host:port`), create a `User { name: "alpha" }` if the collection is empty,
//! then read it back — printing `users=<names> count=<n>` exactly like the P0 loopback
//! fixture. In the e2e that `host:port` is the LOCAL listener of `jkbase db proxy`, so a
//! successful round-trip proves the whole reach plane: sidecar -> TLS edge -> agent
//! `/_jkbase/db` splice -> loopback rhypedb, over the genuine client wire.
//!
//! Exit 0 on success (stdout carries the result line); non-zero with a message on stderr
//! otherwise. The e2e test parses stdout and asserts `count=1`.

use rhypedb_client::{Client, Query};

#[derive(serde::Deserialize)]
struct User {
    name: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("rhypedb-probe: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .ok_or("usage: rhypedb-probe <host:port>")?;
    let client = Client::connect(&addr)?;

    // Idempotent seed: only create on an empty collection so a re-run / retry is safe.
    if client.fetch::<User>(&Query::all("User"))?.is_empty() {
        client.query(r#"User.create({ name: "alpha" })"#)?;
    }

    let rows = client.fetch::<User>(&Query::all("User"))?;
    let mut names: Vec<String> = rows.iter().filter_map(|r| r.data.name.clone()).collect();
    names.sort();
    println!("users={} count={}", names.join(","), rows.len());
    Ok(())
}
