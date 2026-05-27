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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    Active,
    Stopped,
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
