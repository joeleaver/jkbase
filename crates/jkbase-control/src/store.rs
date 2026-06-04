use crate::auth::{self, ApiToken, Tenant};
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

const PROJECTS: TableDefinition<&str, &[u8]> = TableDefinition::new("projects");
const VM_ALLOCATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("vm_allocations");
const TENANTS: TableDefinition<&str, &[u8]> = TableDefinition::new("tenants");
const API_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("api_tokens");
const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshots");
const DEPLOYMENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("deployments");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    Active,
    Stopped,
    Hibernated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub project_id: String,
    pub snapshot_path: String,
    pub mem_file_path: String,
    pub created_at: u64,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,
    pub current_version: Option<u64>,
    #[serde(default = "default_state")]
    pub state: ProjectState,
    pub vm_ip: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmAllocation {
    pub project_id: String,
    pub ip: String,
    pub tap_device: String,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub project_id: String,
    pub key: String,
    pub value: String,
}

/// Metadata for one immutable deployment of a project. The artifacts live on
/// disk at `{deploy_dir}/{project_id}/deployments/v{version}`; this records the
/// version history so the platform can list past deploys and roll back to one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMeta {
    pub project_id: String,
    pub version: u64,
    pub created_at: u64,
}

fn default_state() -> ProjectState {
    ProjectState::Stopped
}

#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path).context("failed to open database")?;

        let txn = db.begin_write()?;
        let _ = txn.open_table(PROJECTS)?;
        let _ = txn.open_table(VM_ALLOCATIONS)?;
        let _ = txn.open_table(TENANTS)?;
        let _ = txn.open_table(API_TOKENS)?;
        let _ = txn.open_table(SECRETS)?;
        let _ = txn.open_table(SNAPSHOTS)?;
        let _ = txn.open_table(DEPLOYMENTS)?;
        txn.commit()?;

        Ok(Store { db: Arc::new(db) })
    }

    pub fn create_project(&self, project: &Project) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PROJECTS)?;
            let data = serde_json::to_vec(project)?;
            table.insert(project.id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_project(&self, id: &str) -> Result<Option<Project>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROJECTS)?;
        match table.get(id)? {
            Some(data) => {
                let project: Project = serde_json::from_slice(data.value())?;
                Ok(Some(project))
            }
            None => Ok(None),
        }
    }

    pub fn update_project(&self, project: &Project) -> Result<()> {
        self.create_project(project)
    }

    pub fn list_projects(&self) -> Result<Vec<Project>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROJECTS)?;
        let mut projects = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let project: Project = serde_json::from_slice(value.value())?;
            projects.push(project);
        }
        Ok(projects)
    }

    pub fn delete_project(&self, id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(PROJECTS)?;
            table.remove(id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    pub fn save_vm_allocation(&self, alloc: &VmAllocation) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(VM_ALLOCATIONS)?;
            let data = serde_json::to_vec(alloc)?;
            table.insert(alloc.project_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_vm_allocation(&self, project_id: &str) -> Result<Option<VmAllocation>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(VM_ALLOCATIONS)?;
        match table.get(project_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    pub fn list_vm_allocations(&self) -> Result<Vec<VmAllocation>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(VM_ALLOCATIONS)?;
        let mut allocs = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let alloc: VmAllocation = serde_json::from_slice(value.value())?;
            allocs.push(alloc);
        }
        Ok(allocs)
    }

    pub fn remove_vm_allocation(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(VM_ALLOCATIONS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Snapshots --

    pub fn save_snapshot_meta(&self, meta: &SnapshotMeta) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SNAPSHOTS)?;
            let data = serde_json::to_vec(meta)?;
            table.insert(meta.project_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_snapshot_meta(&self, project_id: &str) -> Result<Option<SnapshotMeta>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SNAPSHOTS)?;
        match table.get(project_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    pub fn remove_snapshot_meta(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(SNAPSHOTS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Deployments --

    // Zero-padded so the compound key sorts by version within a project.
    fn deployment_key(project_id: &str, version: u64) -> String {
        format!("{project_id}:{version:020}")
    }

    pub fn save_deployment(&self, meta: &DeploymentMeta) -> Result<()> {
        let key = Self::deployment_key(&meta.project_id, meta.version);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DEPLOYMENTS)?;
            let data = serde_json::to_vec(meta)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_deployment(&self, project_id: &str, version: u64) -> Result<Option<DeploymentMeta>> {
        let key = Self::deployment_key(project_id, version);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DEPLOYMENTS)?;
        match table.get(key.as_str())? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// All deployments for a project, newest version first.
    pub fn list_deployments(&self, project_id: &str) -> Result<Vec<DeploymentMeta>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DEPLOYMENTS)?;
        let prefix = format!("{project_id}:");
        let mut deployments = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            if key.value().starts_with(&prefix) {
                deployments.push(serde_json::from_slice::<DeploymentMeta>(value.value())?);
            }
        }
        deployments.sort_by_key(|d| std::cmp::Reverse(d.version));
        Ok(deployments)
    }

    pub fn remove_deployment(&self, project_id: &str, version: u64) -> Result<bool> {
        let key = Self::deployment_key(project_id, version);
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(DEPLOYMENTS)?;
            table.remove(key.as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    pub fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(TENANTS)?;
            let data = serde_json::to_vec(tenant)?;
            table.insert(tenant.id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_tenant(&self, id: &str) -> Result<Option<Tenant>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TENANTS)?;
        match table.get(id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    pub fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TENANTS)?;
        let mut tenants = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let tenant: Tenant = serde_json::from_slice(value.value())?;
            tenants.push(tenant);
        }
        Ok(tenants)
    }

    pub fn save_api_token(&self, token: &ApiToken) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(API_TOKENS)?;
            let data = serde_json::to_vec(token)?;
            table.insert(token.id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn find_tenant_by_email(&self, email: &str) -> Result<Option<Tenant>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TENANTS)?;
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let tenant: Tenant = serde_json::from_slice(value.value())?;
            if tenant.email == email {
                return Ok(Some(tenant));
            }
        }
        Ok(None)
    }

    pub fn list_projects_for_tenant(&self, tenant_id: &str) -> Result<Vec<Project>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROJECTS)?;
        let mut projects = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let project: Project = serde_json::from_slice(value.value())?;
            if project.tenant_id.as_deref() == Some(tenant_id) {
                projects.push(project);
            }
        }
        Ok(projects)
    }

    // -- Secrets --

    pub fn set_secret(&self, project_id: &str, key: &str, value: &str) -> Result<()> {
        let compound_key = format!("{project_id}:{key}");
        let secret = Secret {
            project_id: project_id.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        };
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SECRETS)?;
            let data = serde_json::to_vec(&secret)?;
            table.insert(compound_key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_secrets(&self, project_id: &str) -> Result<Vec<Secret>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SECRETS)?;
        let prefix = format!("{project_id}:");
        let mut secrets = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            if key.value().starts_with(&prefix) {
                let secret: Secret = serde_json::from_slice(value.value())?;
                secrets.push(secret);
            }
        }
        Ok(secrets)
    }

    pub fn delete_secret(&self, project_id: &str, key: &str) -> Result<bool> {
        let compound_key = format!("{project_id}:{key}");
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(SECRETS)?;
            table.remove(compound_key.as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    pub fn authenticate(&self, raw_token: &str) -> Result<Option<Tenant>> {
        let txn = self.db.begin_read()?;
        let tokens_table = txn.open_table(API_TOKENS)?;
        let tenants_table = txn.open_table(TENANTS)?;

        for entry in tokens_table.iter()? {
            let (_key, value) = entry?;
            let api_token: ApiToken = serde_json::from_slice(value.value())?;
            if auth::verify_token(raw_token, &api_token.token_hash) {
                if let Some(tenant_data) = tenants_table.get(api_token.tenant_id.as_str())? {
                    let tenant: Tenant = serde_json::from_slice(tenant_data.value())?;
                    return Ok(Some(tenant));
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> (Store, std::path::PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("jkbase-store-test-{nanos}.redb"));
        (Store::open(&path).unwrap(), path)
    }

    fn meta(project: &str, version: u64) -> DeploymentMeta {
        DeploymentMeta {
            project_id: project.to_string(),
            version,
            created_at: version, // arbitrary but ordered
        }
    }

    #[test]
    fn deployments_listed_newest_first_and_scoped_per_project() {
        let (store, path) = tmp_db();
        store.save_deployment(&meta("a", 1)).unwrap();
        store.save_deployment(&meta("a", 2)).unwrap();
        store.save_deployment(&meta("a", 10)).unwrap();
        store.save_deployment(&meta("b", 5)).unwrap();

        let a = store.list_deployments("a").unwrap();
        assert_eq!(
            a.iter().map(|d| d.version).collect::<Vec<_>>(),
            vec![10, 2, 1],
            "newest version first"
        );
        let b = store.list_deployments("b").unwrap();
        assert_eq!(b.len(), 1, "other project's deployments excluded");
        assert_eq!(b[0].version, 5);

        assert_eq!(store.get_deployment("a", 2).unwrap().unwrap().version, 2);
        assert!(store.get_deployment("a", 99).unwrap().is_none());

        assert!(store.remove_deployment("a", 2).unwrap());
        assert_eq!(
            store.list_deployments("a").unwrap().iter().map(|d| d.version).collect::<Vec<_>>(),
            vec![10, 1]
        );

        let _ = std::fs::remove_file(&path);
    }
}
