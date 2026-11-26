//! `async_main`'s boot phases, one module per concern. Each holds a phase's body; the call
//! ORDER stays in `main.rs` and is load-bearing for the threat model (e.g. the build reaper
//! runs before any egress proxy binds, VM re-adoption before the proxy serves).

use crate::log_shipper::LogShipper;
use crate::platform::PlatformState;
use jkbase_proxy::DomainMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) mod base_rootfs;
pub(crate) mod builds;
pub(crate) mod control;
pub(crate) mod data_plane;
pub(crate) mod db_wiring;
pub(crate) mod egress_facts;
pub(crate) mod egress_proxies;
pub(crate) mod gen_build_ca;
pub(crate) mod ha;
pub(crate) mod loops;
pub(crate) mod proxy;
pub(crate) mod services;
pub(crate) mod tls;

/// The four runtime handles the lifecycle callbacks, wake seams and loops all share.
#[derive(Clone)]
pub(crate) struct Planes {
    pub(crate) platform: Arc<Mutex<PlatformState>>,
    pub(crate) routing: jkbase_proxy::RoutingTable,
    pub(crate) domains: DomainMap,
    pub(crate) shipper: Arc<LogShipper>,
}
