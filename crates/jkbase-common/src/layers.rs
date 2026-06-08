//! Host→agent runtime-layer contract (`_layers.json`).
//!
//! The host builds a small per-project **metadata** ext4 image and bakes a
//! `_layers.json` into it that tells the in-guest agent how the project's block
//! devices are assigned for this boot:
//!
//!   * which device carries the (RW) data disk, if any, and
//!   * for each server, the ordered list of erofs **layer** devices to overlay.
//!
//! The agent NEVER hardcodes `/dev/vdX` letters — the host owns Firecracker drive
//! ordering, so the host owns this mapping. The layer order is the overlayfs
//! `lowerdir` order: **app first, base last** (`lowerdir=app:runtime:base`), so a
//! higher (tenant) layer shadows the shared platform layers below it.
//!
//! Device layout the host commits to (see `jkbase-orch::vm`): `vda` = agent base
//! rootfs, `vdb` = this metadata image, `vdc..` = the deduplicated erofs layer
//! blobs, then the data disk (drive id `data`) last. Because the host writes the
//! resolved device paths here, the agent is order-agnostic.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The on-metadata-image `_layers.json` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLayers {
    pub schema: u32,
    /// The RW data-disk block device (e.g. `"/dev/vdf"`), or `None` when the
    /// project declares no volumes / has no data disk.
    #[serde(default)]
    pub data_device: Option<String>,
    /// `server name` → its erofs overlay stack. Servers absent from this map have
    /// no layers (they should not exist — every built server is layered).
    #[serde(default)]
    pub servers: BTreeMap<String, ServerLayers>,
}

/// One server's overlay stack: erofs layer block devices in `lowerdir` order
/// (app first, base last).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLayers {
    /// erofs layer block devices, highest (app) first, lowest (base) last.
    pub layers: Vec<String>,
}

impl RuntimeLayers {
    pub const SCHEMA: u32 = 1;
    /// Filename the host writes into the metadata image and the agent reads.
    pub const FILE: &'static str = "_layers.json";

    pub fn new() -> Self {
        Self {
            schema: Self::SCHEMA,
            data_device: None,
            servers: BTreeMap::new(),
        }
    }
}

impl Default for RuntimeLayers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let mut rl = RuntimeLayers::new();
        rl.data_device = Some("/dev/vdf".into());
        rl.servers.insert(
            "api".into(),
            ServerLayers {
                layers: vec!["/dev/vde".into(), "/dev/vdd".into(), "/dev/vdc".into()],
            },
        );
        let json = serde_json::to_string(&rl).unwrap();
        let back: RuntimeLayers = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema, 1);
        assert_eq!(back.data_device.as_deref(), Some("/dev/vdf"));
        assert_eq!(back.servers["api"].layers, vec!["/dev/vde", "/dev/vdd", "/dev/vdc"]);
    }

    #[test]
    fn data_device_optional() {
        let rl: RuntimeLayers = serde_json::from_str(r#"{"schema":1,"servers":{}}"#).unwrap();
        assert!(rl.data_device.is_none());
        assert!(rl.servers.is_empty());
    }
}
