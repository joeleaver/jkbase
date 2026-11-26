//! The HA cluster loops: leader election, the data-disk self-fence, the host heartbeat and
//! the cluster reconciler. All inert on a single node.

use crate::cli::Args;
use crate::ha_lease::{disk_fence_loop, leader_election_loop};
use crate::ha_placement::{host_heartbeat_loop, reconcile_loop};
use crate::platform::PlatformState;
use jkbase_control::store::{HostCapacity, HostRecord, Store};
use jkbase_substrate::Lease;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::Mutex;

pub(crate) fn spawn_cluster_loops(
    platform: &Arc<Mutex<PlatformState>>,
    lease: Arc<dyn Lease>,
    host_id: String,
    is_leader: Arc<AtomicBool>,
    store: &Store,
    args: &Args,
) {
    // HA P2: elect a single cluster leader (the holder of the `cluster-leader` lease).
    // On a single node this process simply wins and stays leader. Advisory at P2 — P3's
    // placement gate reads `is_leader`; the data-disk self-fence is the real safety net.
    tokio::spawn(leader_election_loop(
        lease.clone(),
        host_id.clone(),
        is_leader.clone(),
    ));

    // HA P2: the data-disk write-boundary self-fence. Renews each held disk lease and
    // self-terminates this host's Firecracker for any project whose lease it loses,
    // before a survivor attaches. Inert on a single node (FlockLease renew always
    // succeeds while we hold the lock).
    tokio::spawn(disk_fence_loop(platform.clone(), lease));

    // HA P3: register THIS host in the fleet (HOSTS) and heartbeat it so peers/the leader
    // know it is alive without a cross-host TCP probe; when leader, it detects stale peers.
    let self_host = HostRecord {
        host_id,
        region: args.region.clone(),
        public_addr: args.public_addr.clone(),
        last_heartbeat: 0,
        cpu_template_id: args.cpu_template_id.clone(),
        kernel_id: args.kernel_id.clone(),
        capacity: HostCapacity {
            vcpus: args.host_vcpus,
            mem_mib: args.host_mem_mib,
            max_vms: args.host_max_vms,
        },
    };
    tokio::spawn(host_heartbeat_loop(
        store.clone(),
        self_host,
        is_leader.clone(),
    ));

    // HA P3: the continuous cluster reconciler — the leader compares desired vs running
    // each tick and surfaces drift (placement applies it, next card). Inert single-node.
    tokio::spawn(reconcile_loop(platform.clone(), is_leader));
}
