//! Reach-plane / backup e2e probe: connect the REAL `rhypedb-client` over the binary TCP wire
//! to `argv[1]` (a `host:port`) and drive a small `User` collection, printing
//! `users=<names> count=<n>` exactly like the P0 loopback fixture. In the e2e that `host:port`
//! is the LOCAL listener of `jkbase db proxy`, so a successful round-trip proves the whole reach
//! plane: sidecar -> TLS edge -> agent `/_jkbase/db` splice -> loopback rhypedb.
//!
//! Commands (argv[2..]):
//!   (none)          seed `alpha` if the collection is empty, then list (idempotent; the
//!                   original reach-plane probe behavior).
//!   create <name>   insert `User { name }`, then list. Used to mutate the DB between a backup
//!                   and a restore so the restore's effect is observable.
//!   list            list only.
//!
//! Exit 0 on success (stdout carries `users=… count=…`); non-zero with a message on stderr.

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
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).ok_or("usage: rhypedb-probe <host:port> [create <name>|list]")?;
    let client = Client::connect(addr)?;

    match args.get(2).map(String::as_str) {
        None => {
            // Idempotent seed: only create on an empty collection so a re-run / retry is safe.
            if client.fetch::<User>(&Query::all("User"))?.is_empty() {
                client.query(r#"User.create({ name: "alpha" })"#)?;
            }
        }
        Some("create") => {
            let name = args.get(3).ok_or("usage: <host:port> create <name>")?;
            // Test-only helper; names come from the test, but keep the wire clean.
            if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err("create <name>: name must be ascii-alphanumeric".into());
            }
            client.query(&format!(r#"User.create({{ name: "{name}" }})"#))?;
        }
        Some("list") => {}
        Some(other) => return Err(format!("unknown command: {other}").into()),
    }

    let rows = client.fetch::<User>(&Query::all("User"))?;
    let mut names: Vec<String> = rows.iter().filter_map(|r| r.data.name.clone()).collect();
    names.sort();
    println!("users={} count={}", names.join(","), rows.len());
    Ok(())
}
