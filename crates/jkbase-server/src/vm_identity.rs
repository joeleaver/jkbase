//! Per-VM identity for the dedicated-DB-VM model (P2).
//!
//! A project may run up to two Firecrackers: its **App VM** (the tenant's server / site /
//! functions) and — opt-in via `[database] tier = "dedicated"` — a sibling **DB VM** that runs
//! only rhypedb. The two are distinguished by a [`VmRole`] and share nothing on disk or in the
//! platform maps. See `docs/managed-rhypedb-p2-design.md` §7.1.
//!
//! ## The one threading rule
//! - **Base `project_id`** keys the *deployment / store / routes / quota*: `hosting/<id>/live`,
//!   `store.get_project`, quota, active domains, `db-backups/<id>`. The DB VM has **no**
//!   `hosting/<id>.db/` — it reuses the app's deployment tree.
//! - **Rendered [`vm_id`]** keys *per-VM-instance* state: the 5 `PlatformState` maps, `run/<id>`,
//!   `snapshots/<id>`, `content-images/<id>.ext4`, the data disk `<id>.img` + lease scope, the
//!   runtime cgroup leaf, the FC api-sock, the `VmAllocation` row, and `run/<id>/handoff.json`.
//!
//! The **App role renders to the bare `project_id`**, so every pre-existing single-VM path is
//! byte-identical (zero migration for the whole GA fleet); the DB VM is a purely additive `…​.db`
//! keyspace that never existed before.

use serde::{Deserialize, Serialize};

/// The `.db` suffix that renders a DB VM's id. `.` is a legal byte for the data-disk / lease
/// plain-id validators (`[A-Za-z0-9._-]`) but is **forbidden** in a real `project_id`
/// (`is_valid_project_id` restricts ids to `[a-z0-9-]`), so a rendered DB id can never collide
/// with an app project id — the `.` is a namespace escape tenants can't reach. Collision-proof by
/// construction, so no project-name guard is needed.
const DB_SUFFIX: &str = ".db";

/// Which of a project's (up to two) Firecrackers this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmRole {
    /// The tenant's application VM (server / site / functions). **The default** — an absent
    /// `role` in an old `handoff.json` (written before P2) deserializes to this, so the existing
    /// app fleet re-adopts unchanged across the P2 rollout (no `SCHEMA_VERSION` bump).
    #[default]
    App,
    /// The sibling database VM (rhypedb-only), present only for `tier = "dedicated"` projects.
    Db,
}

/// Render a project's per-VM-instance id for `role`: App → the bare `project_id` (unchanged),
/// Db → `"{project_id}.db"`. This is the key for the 5 platform maps, `run/<id>`,
/// `snapshots/<id>`, `content-images/<id>.ext4`, the data disk / lease scope, the cgroup leaf,
/// and the FC api-sock path.
pub fn vm_id(project_id: &str, role: VmRole) -> String {
    match role {
        VmRole::App => project_id.to_string(),
        VmRole::Db => format!("{project_id}{DB_SUFFIX}"),
    }
}

/// Inverse of [`vm_id`]: recover `(base_project_id, role)` from a rendered id. A trailing `.db`
/// ⇒ the DB VM; anything else ⇒ the App VM (whose rendered id IS the base). Safe because a real
/// `project_id` contains no `.`, so `strip_suffix(".db")` never mis-parses an app id — a project
/// literally named `foo-db` ends in `-db`, not `.db`.
pub fn split_vm_id(id: &str) -> (&str, VmRole) {
    match id.strip_suffix(DB_SUFFIX) {
        Some(base) => (base, VmRole::Db),
        None => (id, VmRole::App),
    }
}

/// The base `project_id` a rendered `vm_id` belongs to — the store / deployment / quota key. A
/// no-op for an app id; strips the `.db` suffix for a DB VM id.
pub fn base_project_id(id: &str) -> &str {
    split_vm_id(id).0
}

/// A VM's Firecracker machine sizing (vCPUs + RAM MiB). Threaded through deploy / wake / hibernate
/// so a project's App and DB VMs boot — and snapshot/restore — at their own size. The **hibernate
/// snapshot size MUST equal the restore size** or the mem file won't map; both are sourced from
/// [`vm_size_for`] keyed by the same [`VmRole`], so they can't drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmSize {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
}

/// The App VM's historical fixed sizing (3072 MiB / 4 vCPU) — UNCHANGED, so every pre-existing
/// snapshot restores byte-identical and no running app VM is resized.
pub const APP_VM_SIZE: VmSize = VmSize {
    vcpu_count: 4,
    mem_size_mib: 3072,
};

/// The dedicated DB VM's lean floor (1024 MiB / 1 vCPU). RhypeDB runs lean (ONNX dropped);
/// `@vectorize` schemas may want more later. Proven bootable at the orch layer (512/1) and in the
/// managed-DB smokes (1024/2). Joe's decision #5.
pub const DB_VM_SIZE: VmSize = VmSize {
    vcpu_count: 1,
    mem_size_mib: 1024,
};

/// The [`VmSize`] for `role`: App keeps its historical fixed size; Db gets the lean floor.
pub fn vm_size_for(role: VmRole) -> VmSize {
    match role {
        VmRole::App => APP_VM_SIZE,
        VmRole::Db => DB_VM_SIZE,
    }
}

/// The ERE `pkill -f` pattern anchoring the Firecracker api-sock path segment for a rendered
/// `vm_id` (`/{id}/firecracker\.sock`). The rendered id can contain a literal `.` (the DB `.db`
/// suffix), which is an ERE metacharacter: left unescaped, `foo.db` would match
/// `/fooadb/firecracker.sock` and SIGKILL a **different** tenant's Firecracker (cross-tenant
/// kill). Every `.` in the id is escaped so the segment matches literally. (Base ids are
/// `[a-z0-9-]` with no ERE metacharacters; the role suffix's `.` is the only one.)
pub fn fc_sock_pkill_pattern(id: &str) -> String {
    format!("/{}/firecracker\\.sock", id.replace('.', "\\."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_renders_to_the_bare_id_db_is_suffixed() {
        assert_eq!(vm_id("foo", VmRole::App), "foo");
        assert_eq!(vm_id("foo", VmRole::Db), "foo.db");
        // A hyphenated slug that merely *looks* db-ish stays intact.
        assert_eq!(vm_id("foo-db", VmRole::App), "foo-db");
        assert_eq!(vm_id("foo-db", VmRole::Db), "foo-db.db");
    }

    #[test]
    fn split_is_the_inverse_of_render() {
        for base in ["foo", "a", "my-app", "foo-db", "x1-2-3"] {
            assert_eq!(split_vm_id(&vm_id(base, VmRole::App)), (base, VmRole::App));
            assert_eq!(split_vm_id(&vm_id(base, VmRole::Db)), (base, VmRole::Db));
        }
        // A real project id ending in `-db` is NOT a DB VM.
        assert_eq!(split_vm_id("foo-db"), ("foo-db", VmRole::App));
        assert_eq!(base_project_id("foo.db"), "foo");
        assert_eq!(base_project_id("foo"), "foo");
    }

    #[test]
    fn pkill_pattern_escapes_the_db_dot() {
        // App id: unchanged from the historical pattern.
        assert_eq!(fc_sock_pkill_pattern("foo"), "/foo/firecracker\\.sock");
        // DB id: the `.` is escaped so it can't wildcard-match a sibling tenant.
        assert_eq!(fc_sock_pkill_pattern("foo.db"), "/foo\\.db/firecracker\\.sock");
        // The escaped pattern must NOT be a regex that matches a different literal segment.
        // `foo\.db` matches only `foo.db`, never `fooadb`.
        assert!(!fc_sock_pkill_pattern("foo.db").contains("/foo.db/"));
    }

    #[test]
    fn vm_role_defaults_to_app() {
        assert_eq!(VmRole::default(), VmRole::App);
    }
}
