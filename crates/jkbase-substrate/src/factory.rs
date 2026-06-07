//! `build_substrate` — the config-driven factory that assembles the four role
//! backends and **negotiates their honest [`Caps`] against the deployment
//! topology**, refusing a config that can't enforce safety rather than corrupting
//! data later. A single-node box runs the local defaults; a multi-node cluster
//! MUST present cluster-safe exclusivity + replicated metadata, or boot fails.
//!
//! It also refuses to back the cluster's OWN state on jkbase's tenant object store
//! (a circular dependency — the platform can't depend on the product it serves);
//! see [`assert_not_self_referential`], which endpoint-bearing backends (S3, etc.)
//! call as they are added.

use crate::{
    BlobStore, Caps, ControlStore, DataDiskProvider, FlockLease, Lease, LocalFsBlobStore, LocalLoop,
    RedbControlStore, Result, SubstrateError,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Which backend implements each role, plus the topology to negotiate against.
pub struct SubstrateConfig {
    /// Number of hosts sharing this cluster's state. `1` = single node (local
    /// defaults fine); `>1` requires cluster-safe backends.
    pub node_count: u32,
    pub control: ControlBackend,
    pub blob: BlobBackend,
    pub lease: LeaseBackend,
    pub data_disk: DataDiskBackend,
    /// Host of jkbase's OWN tenant object store, which the cluster's state must
    /// never be backed by. `None` disables the circularity check.
    pub tenant_object_store_host: Option<String>,
}

/// R1 backend selection. Cluster backends (e.g. etcd) arrive as feature-gated
/// variants in their own cards.
pub enum ControlBackend {
    Redb { path: PathBuf },
}
/// R4 backend selection.
pub enum BlobBackend {
    LocalFs { root: PathBuf },
    /// Any S3-compatible endpoint (AWS S3 / MinIO / Ceph RGW). Feature `s3`.
    #[cfg(feature = "s3")]
    S3(crate::S3Config),
}
/// R2 backend selection.
pub enum LeaseBackend {
    Flock { dir: PathBuf, source_id: String },
}
/// R3 backend selection.
pub enum DataDiskBackend {
    LocalLoop { dir: PathBuf },
}

/// The assembled set of role backends, ready to hand to the control plane / HA.
pub struct Substrate {
    pub control: Arc<dyn ControlStore>,
    pub blob: Arc<dyn BlobStore>,
    pub lease: Arc<dyn Lease>,
    pub data_disk: Arc<dyn DataDiskProvider>,
}

/// Build the four backends from `cfg`, then refuse the whole config if any backend
/// can't honestly meet the topology's safety requirements.
pub fn build_substrate(cfg: SubstrateConfig) -> Result<Substrate> {
    let control: Arc<dyn ControlStore> = match cfg.control {
        ControlBackend::Redb { path } => Arc::new(RedbControlStore::open(path)?),
    };
    let blob: Arc<dyn BlobStore> = match cfg.blob {
        BlobBackend::LocalFs { root } => Arc::new(LocalFsBlobStore::open(root)?),
        #[cfg(feature = "s3")]
        BlobBackend::S3(s3cfg) => Arc::new(crate::S3CompatBlobStore::connect(s3cfg)?),
    };
    let lease: Arc<dyn Lease> = match cfg.lease {
        LeaseBackend::Flock { dir, source_id } => Arc::new(FlockLease::open(dir, source_id)?),
    };
    let data_disk: Arc<dyn DataDiskProvider> = match cfg.data_disk {
        DataDiskBackend::LocalLoop { dir } => Arc::new(LocalLoop::open(dir)?),
    };

    negotiate(cfg.node_count, control.caps(), lease.caps(), data_disk.caps())?;

    Ok(Substrate {
        control,
        blob,
        lease,
        data_disk,
    })
}

/// Refuse a config whose backends can't honestly meet the topology's safety needs.
fn negotiate(node_count: u32, control: Caps, lease: Caps, data_disk: Caps) -> Result<()> {
    if node_count > 1 {
        needs(control, Caps::REPLICATED_TXN, "control store", node_count)?;
        needs(lease, Caps::CLUSTER_EXCLUSIVE_FENCE, "lease", node_count)?;
        needs(data_disk, Caps::STORAGE_ENFORCED_RWO, "data-disk provider", node_count)?;
    }
    Ok(())
}

fn needs(have: Caps, need: Caps, role: &str, node_count: u32) -> Result<()> {
    if have.contains(need) {
        Ok(())
    } else {
        Err(SubstrateError::Backend(format!(
            "node_count={node_count} requires {need:?} on the {role}, but the configured \
             backend only provides {have:?} — refusing a config that can't enforce safety \
             across nodes"
        )))
    }
}

/// The cluster's own R2/R4 state must never resolve to jkbase's OWN tenant object
/// store (circularity: the platform can't depend on the product it's serving).
/// Endpoint-bearing backends call this at build time.
pub fn assert_not_self_referential(endpoint: &str, tenant_object_store_host: Option<&str>) -> Result<()> {
    if let Some(forbidden) = tenant_object_store_host
        && endpoint_host(endpoint).eq_ignore_ascii_case(forbidden)
    {
        return Err(SubstrateError::Backend(format!(
            "refusing to back cluster state on jkbase's own tenant object store \
             ({forbidden}) — that is a circular dependency"
        )));
    }
    Ok(())
}

/// Extract the bare host from a `scheme://host:port/path`-ish endpoint.
fn endpoint_host(endpoint: &str) -> &str {
    let no_scheme = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    host.split(':').next().unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-factory-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn local_cfg(node_count: u32, base: &Path) -> SubstrateConfig {
        SubstrateConfig {
            node_count,
            control: ControlBackend::Redb { path: base.join("control.redb") },
            blob: BlobBackend::LocalFs { root: base.join("blobs") },
            lease: LeaseBackend::Flock { dir: base.join("leases"), source_id: "node-a".into() },
            data_disk: DataDiskBackend::LocalLoop { dir: base.join("disks") },
            tenant_object_store_host: None,
        }
    }

    #[test]
    fn negotiate_single_node_accepts_local_caps() {
        // Local backends' real caps satisfy a single-node topology.
        assert!(negotiate(
            1,
            Caps::SINGLE_NODE_TXN,
            Caps::MONOTONIC_FENCE | Caps::NODE_LOCAL_EXCLUSIVE,
            Caps::NODE_LOCAL_RWO,
        )
        .is_ok());
    }

    #[test]
    fn negotiate_multi_node_refuses_node_local_backends() {
        let err = negotiate(
            3,
            Caps::SINGLE_NODE_TXN,
            Caps::MONOTONIC_FENCE | Caps::NODE_LOCAL_EXCLUSIVE,
            Caps::NODE_LOCAL_RWO,
        )
        .unwrap_err();
        assert!(matches!(err, SubstrateError::Backend(_)));
    }

    #[test]
    fn negotiate_multi_node_accepts_cluster_caps() {
        assert!(negotiate(
            3,
            Caps::REPLICATED_TXN,
            Caps::CLUSTER_EXCLUSIVE_FENCE,
            Caps::STORAGE_ENFORCED_RWO,
        )
        .is_ok());
    }

    #[test]
    fn build_local_single_node_succeeds() {
        let base = dir("ok");
        let s = build_substrate(local_cfg(1, &base)).unwrap();
        assert_eq!(s.control.backend_name(), "redb");
        assert_eq!(s.blob.backend_name(), "localfs");
        assert_eq!(s.lease.backend_name(), "flock");
        assert_eq!(s.data_disk.backend_name(), "localloop");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn build_local_multi_node_is_refused_at_boot() {
        let base = dir("refuse");
        assert!(matches!(
            build_substrate(local_cfg(2, &base)),
            Err(SubstrateError::Backend(_))
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn self_referential_endpoint_is_rejected() {
        // R4 endpoint pointing at jkbase's own tenant object store => circular.
        assert!(assert_not_self_referential(
            "https://s3.jkbase.app/cluster-state",
            Some("s3.jkbase.app")
        )
        .is_err());
        // A different, external object store is fine.
        assert!(assert_not_self_referential("https://s3.amazonaws.com/x", Some("s3.jkbase.app")).is_ok());
        // No forbidden host configured => no check.
        assert!(assert_not_self_referential("https://s3.jkbase.app/x", None).is_ok());
    }
}
