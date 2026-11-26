//! Facts read from a project's live deployment tree: whether it declares volumes or a managed
//! database, its DB tier (co-located vs dedicated) and rules opt-in, and which VM serves its DB
//! reach plane. Every parser is fail-safe: a missing or malformed sidecar reads as the conservative
//! default.

use crate::vm_identity;

use std::path::Path;
pub(crate) fn check_project_has_volumes(data_dir: &Path, project_id: &str) -> bool {
    let servers_dir = data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .join("_servers");
    if !servers_dir.exists() {
        return false;
    }
    for entry in std::fs::read_dir(&servers_dir).into_iter().flatten() {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Ok(content) = std::fs::read_to_string(&path)
            && content.contains("\"volumes\"")
            && content.contains("\"mount\"")
        {
            return true;
        }
    }
    false
}

/// True when the project's live deployment declares a managed database (a host-baked
/// `_database.json`). A managed DB needs a persistent data disk to survive restart and
/// hibernate/wake even if no server declares a volume, so this forces `has_disk` on —
/// without it the DB would write to the ephemeral overlay tmpfs and lose data. Mirrors
/// [`check_project_has_volumes`] (reads the live deployment, set before this boot).
pub(crate) fn check_project_has_database(data_dir: &Path, project_id: &str) -> bool {
    deployment_has_database(&data_dir.join("hosting").join(project_id).join("live"))
}

/// [`check_project_has_database`] for any deployment tree.
pub(crate) fn deployment_has_database(deployment_dir: &Path) -> bool {
    read_tree_sidecar(deployment_dir, "_database.json").is_some()
}

/// A host-read sidecar of a deployment tree, only if it is a REGULAR file: a tenant-planted
/// symlink (a raw deploy tarball keeps them) must not let the tier/rules decisions read a file
/// outside the tree that the tenant can rewrite later. Activation refuses such trees; this
/// covers ones that predate that check.
pub(crate) fn read_tree_sidecar(deployment_dir: &Path, name: &str) -> Option<String> {
    let path = deployment_dir.join(name);
    let md = std::fs::symlink_metadata(&path).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    std::fs::read_to_string(&path).ok()
}

/// The VM id the DB reach plane (external `:443` edge, console query/schema/status, backup relay)
/// must wake + dial for a project's managed DB: the sibling **DB VM** (`{id}.db`) when
/// `tier="dedicated"`, else the **app VM** (`id`) where the DB is co-located on loopback. Keyed by
/// the BASE project id; the DB VM's agent holds the same splice secret, so only the target IP
/// changes (the agent side is loopback-only and unchanged).
pub(crate) fn db_reach_target_vm(data_dir: &Path, project_id: &str) -> String {
    if project_is_dedicated(data_dir, project_id) {
        vm_identity::vm_id(project_id, vm_identity::VmRole::Db)
    } else {
        project_id.to_string()
    }
}

/// True when the project's live deployment declares `[database] tier = "dedicated"` (P2) — its
/// managed DB runs in a sibling DB VM rather than co-located in the app VM. Reads the host-baked
/// `hosting/<project>/live/_database.json` `tier` field (always the BASE project id — the DB VM
/// has no `hosting/<id>.db/`). A missing file / absent-or-other tier ⇒ co-located (the default),
/// so this is fail-safe: only an explicit `"dedicated"` opts a project into the second VM.
pub(crate) fn project_is_dedicated(data_dir: &Path, project_id: &str) -> bool {
    deployment_is_dedicated(&data_dir.join("hosting").join(project_id).join("live"))
}

/// [`project_is_dedicated`] for any deployment tree.
pub(crate) fn deployment_is_dedicated(deployment_dir: &Path) -> bool {
    read_tree_sidecar(deployment_dir, "_database.json")
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| {
            v.get("tier")
                .and_then(serde_json::Value::as_str)
                .map(|t| t.eq_ignore_ascii_case("dedicated"))
        })
        .unwrap_or(false)
}

/// True when the project opts into the P4 security-rules engine via a non-empty
/// `[database].rules` (baked into `_database.json`'s `rules` field). This is the opt-in that
/// turns the managed DB from open-on-loopback into default-deny: only then does the host mint +
/// bake the project's PUBLIC JWKS ([`DbReachFacts::jwks`]) and the agent point
/// `RHYPEDB_RULES`/`RHYPEDB_AUTH_JWKS` at the baked files. Absent/null/empty ⇒ rules-off (the
/// engine stays byte-for-byte unchanged). Mirrors [`project_is_dedicated`] — reads the same
/// host-baked, tenant-unforgeable sidecar.
pub(crate) fn project_db_rules_enabled(data_dir: &Path, project_id: &str) -> bool {
    let live = data_dir.join("hosting").join(project_id).join("live");
    read_tree_sidecar(&live, "_database.json")
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| {
            v.get("rules")
                .and_then(serde_json::Value::as_str)
                .map(|r| !r.trim().is_empty())
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_tier_parsing_is_fail_safe_and_drives_reach_target() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data = std::env::temp_dir().join(format!("jkbase-tier-{nanos}"));
        let live = |id: &str| data.join("hosting").join(id).join("live");
        let write_db = |id: &str, json: &str| {
            std::fs::create_dir_all(live(id)).unwrap();
            std::fs::write(live(id).join("_database.json"), json).unwrap();
        };

        // No _database.json → co-located (a project with no managed DB).
        assert!(!project_is_dedicated(&data, "none"));
        assert_eq!(db_reach_target_vm(&data, "none"), "none");

        // Explicit dedicated → the reach target is the DB VM.
        write_db(
            "ded",
            r#"{"engine":"rhypedb","schema":"s.rhype","tier":"dedicated"}"#,
        );
        assert!(project_is_dedicated(&data, "ded"));
        assert_eq!(db_reach_target_vm(&data, "ded"), "ded.db");

        // Explicit colocated, absent tier, and a garbage value all fail SAFE to co-located
        // (the app VM), so a malformed tier never silently routes reach at a nonexistent VM.
        write_db(
            "colo",
            r#"{"engine":"rhypedb","schema":"s.rhype","tier":"colocated"}"#,
        );
        write_db("notier", r#"{"engine":"rhypedb","schema":"s.rhype"}"#);
        write_db("junk", r#"not even json"#);
        for id in ["colo", "notier", "junk"] {
            assert!(!project_is_dedicated(&data, id), "{id} must be co-located");
            assert_eq!(db_reach_target_vm(&data, id), id);
        }

        let _ = std::fs::remove_dir_all(&data);
    }

    #[test]
    fn db_rules_opt_in_parsing_is_fail_safe() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data = std::env::temp_dir().join(format!("jkbase-dbrules-{nanos}"));
        let live = |id: &str| data.join("hosting").join(id).join("live");
        let write_db = |id: &str, json: &str| {
            std::fs::create_dir_all(live(id)).unwrap();
            std::fs::write(live(id).join("_database.json"), json).unwrap();
        };

        // No _database.json → rules-off (no managed DB, or a DB without rules).
        assert!(!project_db_rules_enabled(&data, "none"));

        // A non-empty `rules` path is the opt-in that makes the host mint + bake the JWKS.
        write_db(
            "on",
            r#"{"engine":"rhypedb","schema":"s.rhype","rules":"rules.rhype"}"#,
        );
        assert!(project_db_rules_enabled(&data, "on"));

        // Absent / null / empty / whitespace `rules`, and garbage, all fail SAFE to rules-off so a
        // malformed sidecar never provisions keys nor half-enables enforcement.
        write_db("norules", r#"{"engine":"rhypedb","schema":"s.rhype"}"#);
        write_db(
            "nullrules",
            r#"{"engine":"rhypedb","schema":"s.rhype","rules":null}"#,
        );
        write_db(
            "emptyrules",
            r#"{"engine":"rhypedb","schema":"s.rhype","rules":""}"#,
        );
        write_db(
            "wsrules",
            r#"{"engine":"rhypedb","schema":"s.rhype","rules":"   "}"#,
        );
        write_db("junk", r#"not even json"#);
        for id in ["norules", "nullrules", "emptyrules", "wsrules", "junk"] {
            assert!(
                !project_db_rules_enabled(&data, id),
                "{id} must be rules-off"
            );
        }

        let _ = std::fs::remove_dir_all(&data);
    }
}
