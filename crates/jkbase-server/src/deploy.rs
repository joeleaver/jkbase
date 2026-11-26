//! The deploy handler behind `POST /projects/{id}/deploy`: swap the new tree live, (re)boot the
//! project's VM(s) on it and commit them to Running, undoing the swap if the deploy is refused.

use crate::{LogShipper, PlatformState, RUNTIME_CGROUP_PARENT, VmLifecycle, check_project_has_database, check_project_has_volumes, data_disk_mib, deploy_refusal, disk_cap_bytes, fence_data_disk, handoff, layer_plan, project_db_rules_enabled, project_is_dedicated, read_l4_port_decls, record_deployed_tier, register_active_routes, release_data_disk, setup_tap, sync_agent, unix_now, vm_identity, wait_for_agent, write_handoff_record};
use crate::db_vm::{boot_db_vm};
use anyhow::{Context, Result};
use jkbase_control::store::VmAllocation;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_proxy::DomainMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

pub(crate) async fn handle_deploy(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<()> {
    // Wait out any in-flight wake/hibernate before touching the disk: those drop the
    // platform lock during the slow VM op while still holding the data-disk lease, so
    // releasing + re-fencing underneath one would (a) fail transiently with LeaseHeld,
    // or worse (b) for a still-live hibernate, detach the disk its paused-but-alive FC
    // still maps and start a second writer. Budget ~80s to actually outlast hibernate's
    // worst case (3s log-ship + 60s snapshot timeout); on expiry FAIL CLOSED rather than
    // charge ahead into a re-fence under a live peer — deploy is retryable.
    let mut plat = {
        let mut attempt = 0;
        loop {
            let plat = platform.lock().await;
            if matches!(
                plat.vm_states.get(project_id),
                Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
            ) {
                if attempt >= 400 {
                    // Nothing touched yet: typed as a refusal so the control plane puts `live`
                    // back on the version the (still-running) old VM serves.
                    return Err(jkbase_control::api::DeployRefused(format!(
                        "project {project_id} busy (wake/hibernate still in flight after ~80s); retry deploy"
                    ))
                    .into());
                }
                drop(plat);
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            break plat;
        }
    };

    // The refusals the control plane already ran against this tree before swapping `live` to it
    // (`deploy_precheck_callback`), re-checked here under the platform lock as the last line
    // before teardown: a refused deploy must leave the running VM untouched. Typed as a refusal
    // (only ever returned from before teardown) so the control plane undoes the `live` swap —
    // e.g. the owner-host gate can flip between the precheck and here.
    let live_dir = plat.data_dir.join("hosting").join(project_id).join("live");
    deploy_refusal(&plat, project_id, &live_dir)
        .await
        .map_err(|e| jkbase_control::api::DeployRefused(format!("{e:#}")))?;

    // A deploy/rollback supersedes any prior snapshot UNCONDITIONALLY — not only when
    // `Hibernated`. A VM that was restored-then-Running still carries its snapshot (restore
    // doesn't delete it), and the metadata image / layers it baked are about to be rewritten in
    // place; leaving that snapshot would let a later restart restore stale guest RAM against the
    // new bytes if the version happened to re-match (e.g. a rollback). Clearing here closes that
    // window — the `deployment_version` viability gate is then defence in depth, not the only guard.
    {
        info!(project = %project_id, "clearing any stale snapshot for fresh deploy");
        let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
        let _ = std::fs::remove_dir_all(&snapshot_dir);
        let _ = plat.store.remove_snapshot_meta(project_id);
    }

    if let Some(mut old_vm) = plat.vms.remove(project_id) {
        plat.vm_rootfs_hashes.remove(project_id);
        info!(project = %project_id, "syncing and stopping old VM for redeploy");
        if let Ok(Some(alloc)) = plat.store.get_vm_allocation(project_id) {
            let _ = sync_agent(&alloc.ip).await;
            // Capture any final log lines before the old agent goes away.
            shipper.ship(project_id, &alloc.ip).await;
        }
        let _ = old_vm.stop().await;
    }
    plat.vm_incarnations.retire(project_id);
    // The old VM is gone (or being replaced); drop its re-adoption record so a crash between
    // here and the new commit can't leave a handoff pointing at the now-dead old FC. The new
    // VM writes a fresh record at its commit-to-Running below.
    handoff::remove(&plat.data_dir.join("run"), project_id);
    // Release the old VM's data-disk hold (if any) before re-fencing for the new VM —
    // UNCONDITIONALLY: a stop() error or a missing VM handle must not leak the lease
    // (which would then fail the re-fence below with LeaseHeld and brick the redeploy).
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    let content_dir = plat.data_dir.join("hosting").join(project_id).join("live");
    if !content_dir.exists() {
        anyhow::bail!("no deployed content for project {project_id}");
    }

    let alloc = match plat.store.get_vm_allocation(project_id)? {
        Some(existing) => {
            info!(project = %project_id, ip = %existing.ip, "reusing persisted IP");
            existing
        }
        None => {
            let (ip, tap, mac) = plat.allocate_ip()?;
            let alloc = VmAllocation {
                project_id: project_id.to_string(),
                ip,
                tap_device: tap,
                mac,
                // HA P3: the host that first deploys a project owns it (initial placement);
                // the leader reassigns on host death (reconcile_loop). On a single node this
                // is the one live host, so ownership is a no-op for routing.
                host_id: plat.host_id.clone(),
                placement_epoch: 1,
            };
            plat.store.save_vm_allocation(&alloc)?;
            info!(project = %project_id, ip = %alloc.ip, "allocated new IP");
            alloc
        }
    };

    // Read what the slow build + fence + boot need, then DROP the platform lock: the
    // metadata-image build (mkfs + sha256 layer verify), the RWO attach (first-deploy
    // mkfs / reap+300ms / losetup), and the VM boot must NOT head-of-line block every
    // other project on the single platform lock. Re-acquire only to commit.
    // Dedicated projects run their managed DB in a SIBLING VM, so the app VM must NOT be forced a
    // data disk on account of the DB (`check_project_has_database`) — it only fences a disk for its
    // OWN volumes. A co-located project (the default) keeps forcing the disk for the loopback DB.
    let dedicated = project_is_dedicated(&plat.data_dir, project_id);
    let has_disk = check_project_has_volumes(&plat.data_dir, project_id)
        || (!dedicated && check_project_has_database(&plat.data_dir, project_id))
        || plat.data_disk.exists(project_id).await.unwrap_or(false);
    let data_dir = plat.data_dir.clone();
    let dd = plat.data_disk.clone();
    let disk_cap = disk_cap_bytes(&plat.store, project_id);
    let ls = plat.lease.clone();
    let hid = plat.host_id.clone();
    let firecracker_bin = plat.firecracker_bin.clone();
    let kernel_path = plat.kernel_path.clone();
    let rootfs_path = plat.base_rootfs_path.clone();
    let runtime_dir = data_dir.join("run");
    // Project secrets → merged into each server's runtime env in the per-project
    // metadata image below (read here under the platform lock). That image is rebuilt
    // ONLY on deploy; wake/restore reuse the last-deployed image (a restored live
    // process can't be re-env'd), so a secret change takes effect on the next DEPLOY,
    // not on an idle wake/restart.
    let secrets: std::collections::BTreeMap<String, String> = plat
        .store
        .list_secrets(project_id)
        .map(|v| v.into_iter().map(|s| (s.key, s.value)).collect())
        .unwrap_or_default();
    // Host-asserted platform egress facts, stamped into this VM's metadata image as
    // `_platform.json` (the agent's OWN-storage host + Zone-2 deny-set). Read under the lock.
    let platform_egress = plat.platform_egress.clone();
    // Mint (rotate) the project's own-bucket binding credential and write it into the
    // function sidecars' reserved channel below. Owner-bound to the project's CURRENT tenant
    // (the object-store owner re-bind fail-closes a stale one); a fresh secret each deploy.
    // Only when the project has an owner — an ownerless project gets no binding (the SigV4
    // owner re-check would reject it anyway). Best-effort: a mint failure must not fail the
    // deploy (functions just can't use the typed binding until the next deploy).
    let storage_binding: Option<layer_plan::StorageBinding> = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .and_then(|p| p.tenant_id)
        .and_then(|tenant| plat.store.mint_binding_key(project_id, &tenant).ok())
        .map(|k| layer_plan::StorageBinding {
            access_key_id: k.access_key_id,
            secret_key: k.secret_key,
        });
    // Mint (rotate) the per-deploy reach-plane secrets for a project with a managed DB and
    // persist them — the edge reads the splice secret from the control store to present on the
    // `/_jkbase/db` upgrade, and the SAME values are baked into the per-VM image below so the
    // in-VM agent can verify the splice ([R3]) and inject the admin token into the DB env
    // ([RB1]). Best-effort: a mint failure just means the reach plane / backups can't run until
    // the next deploy (fail-closed), never a failed deploy. The admin token rides the reserved
    // channel ONLY — never `_database.json`.
    let db_reach: Option<jkbase_common::config::DbReachFacts> =
        if check_project_has_database(&data_dir, project_id) {
            plat.store
                .mint_db_splice_secret(project_id)
                .ok()
                .map(|splice_secret| {
                    let admin_token = plat
                        .store
                        .mint_db_admin_token(project_id)
                        .unwrap_or_default();
                    // P4: when the project opts into security rules (`[database].rules`), provision
                    // (if needed) + read its PUBLIC JWKS from the jkbase-Auth signing store and bake
                    // it over this reserved channel so the DB VM's engine verifies end-user JWTs
                    // offline (P0-DBA-2/3) — no network on the query path. `ensure_signing_key`
                    // guarantees a NON-EMPTY key set (the engine refuses to start on an empty JWKS),
                    // so a rules-on DB never boots without a verifier. Best-effort like the rest of
                    // this block: a store error leaves `jwks=None`, and the agent then starts the
                    // engine with RHYPEDB_RULES but no JWKS ⇒ the engine fails CLOSED (refuses to
                    // serve an open DB), never silently rules-off. PUBLIC keys only (P0-AUTH-2).
                    let jwks = if project_db_rules_enabled(&data_dir, project_id) {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let _ = plat.store.ensure_signing_key(project_id, now);
                        plat.store
                            .get_jwks(project_id, now)
                            .ok()
                            .filter(|j| !j.keys.is_empty())
                            .and_then(|j| serde_json::to_string(&j).ok())
                    } else {
                        None
                    };
                    jkbase_common::config::DbReachFacts {
                        splice_secret,
                        admin_token,
                        // Base value (the DB VM's own image keeps this); the app VM's copy is
                        // flipped to `dedicated` below so its agent starts the app→DB loopback proxy.
                        dedicated: false,
                        jwks,
                    }
                })
        } else {
            None
        };

    // Raw L4 (UDP/TCP) ingress: for each `[l4.*]` the tenant declared (baked into the new
    // deploy's `_l4_ports.json`), allocate — or sticky-reuse — the PUBLIC `external_port` +
    // in-VM `agent_udp_port`, and author the host→agent reach facts (`_l4.json`) baked into
    // the image below. Neither host-asserted port is tenant-authored [P0-L4-8]; an admin PIN
    // is a pre-existing pinned allocation honored by `allocate_port`'s stickiness. Per-port
    // best-effort: an allocation failure skips that port (fail-closed — no public port) and
    // never fails the deploy. The public edge socket + firewall open land with the runtime
    // relay (design §3(a)); this slice only reserves the port and delivers the facts.
    let l4_decls = read_l4_port_decls(&data_dir, project_id);
    let l4_facts: Option<jkbase_common::config::L4Facts> = {
        let mut facts = Vec::new();
        for decl in &l4_decls {
            let (name, proto, guest_port) = (&decl.name, decl.proto, decl.guest_port);
            match plat.allocate_port(project_id, name, proto, guest_port, None) {
                Ok(a) => facts.push(jkbase_common::config::L4PortFact {
                    name: a.name,
                    proto: a.proto,
                    agent_udp_port: a.agent_udp_port,
                    guest_port: a.guest_port,
                    // Hand the agent the host's per-port idle window so its own flow reaper can
                    // never evict a still-live flow (return-leg nonce blank on re-wake, W0.1).
                    idle_timeout_secs: decl.idle_timeout_secs,
                }),
                Err(e) => warn!(
                    project = %project_id, l4_port = %name, error = %e,
                    "L4 port allocation failed; skipping (no public port opened this deploy)"
                ),
            }
        }
        if facts.is_empty() {
            None
        } else {
            // Per-VM transit secret (sticky) authenticating the host↔guest datagram leg
            // (§3(a-auth)); baked into `_l4.json` for the agent, read from the store by the
            // host relay. Minted independently of `[database]` — a pure-L4 project has no
            // DB splice secret. A mint error ⇒ empty ⇒ the agent starts no land-forward
            // (fail-closed), never a failed deploy.
            let transit_secret = plat.store.l4_transit_secret(project_id).unwrap_or_default();
            Some(jkbase_common::config::L4Facts {
                ports: facts,
                transit_secret,
            })
        }
    };
    // Reconcile: free + quarantine any previously-allocated port whose `[l4.*]` stanza was
    // REMOVED in this deploy, so a stale client of the gone port can't later be admitted
    // into a reused port's new owner [threat M1].
    {
        let declared: HashSet<&str> = l4_decls.iter().map(|d| d.name.as_str()).collect();
        for old in plat
            .store
            .list_port_allocations_for_project(project_id)
            .unwrap_or_default()
        {
            if !declared.contains(old.name.as_str()) {
                let _ = plat.store.remove_port_allocation(project_id, &old.name);
                let _ = plat.store.quarantine_port(old.external_port, unix_now());
            }
        }
    }
    drop(plat);

    setup_tap(&alloc.tap_device).await?;

    // Build the per-project metadata image (device map + manifests + static sites)
    // and resolve the erofs layer blobs to attach. Replaces the flat content image:
    // a layered server's root is an overlay of app:runtime:base, so the runtime VM
    // gets the metadata image (vdb) + the layer blobs (vdc..) instead of one blob.
    let content_images_dir = data_dir.join("content-images");
    tokio::fs::create_dir_all(&content_images_dir).await?;
    let metadata_image_path = content_images_dir.join(format!("{project_id}.ext4"));
    // A dedicated project's app VM image excludes the managed DB (it runs in a sibling VM); a
    // co-located project's app VM carries the rhypedb overlay as before. `db_reach` rides the app
    // image EITHER way — the app reaches its DB on loopback (co-located) or host-mediated via the
    // sibling VM (dedicated), so it needs the splice secret regardless.
    let app_content = if dedicated {
        layer_plan::ImageContent::AppNoDb
    } else {
        layer_plan::ImageContent::All
    };
    // The DB VM boot below reuses the SAME per-deploy reach facts (the splice secret both VMs must
    // present); clone them out before the app build MOVES `db_reach` into its blocking closure. The
    // DB VM's copy keeps `dedicated=false` (it IS the DB — no loopback proxy); flip the APP VM's
    // copy so its agent starts the app→DB in-guest leg (P2 §7.6).
    let db_reach_for_db_vm = db_reach.clone();
    let mut db_reach = db_reach;
    if let Some(r) = db_reach.as_mut() {
        r.dedicated = dedicated;
        // [R5] On a dedicated app VM the rhypedb admin token is dead weight (no co-located DB to
        // inject it into) — and the app→DB leg makes a baked copy ACTIONABLE: a hostile app VM
        // could read `_db_reach.json` and drive `/admin/*` (backup-stream exfil / restore-tamper)
        // against its sibling DB VM through the leg. Strip it so the dedicated app VM is strictly
        // better-isolated than co-located; only the DB VM's own image (`db_reach_for_db_vm`,
        // where no tenant code runs) carries the token.
        if dedicated {
            r.admin_token.clear();
        }
    }
    let plan = {
        let content_dir = content_dir.clone();
        let store_dir = data_dir.join("baselayers");
        let out = metadata_image_path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<layer_plan::LayerPlan> {
            // verify=true: cold-boot deploy re-checks every tenant + platform blob's
            // sha256 before it can be attached to a VM.
            let plan = layer_plan::compute_layer_plan_with(
                &content_dir,
                &store_dir,
                has_disk,
                true,
                app_content,
            )?;
            layer_plan::build_metadata_image_with(
                &content_dir,
                &plan,
                &secrets,
                &platform_egress,
                storage_binding.as_ref(),
                db_reach.as_ref(),
                l4_facts.as_ref(),
                &out,
                app_content,
            )?;
            Ok(plan)
        })
        .await
        .context("metadata image build task")??
    };

    // Fence the data disk read-write-once for projects that declare volumes (or
    // already have a disk): acquire the lease + attach via the RWO provider, preempting
    // any prior writer. Held by an RAII guard until the VM is up, so a boot failure (or
    // a cancelled future) releases the lease instead of bricking the project.
    let disk_guard = if has_disk {
        let disk_mib = data_disk_mib(&data_dir, project_id, !dedicated, disk_cap).await;
        Some(fence_data_disk(&dd, &ls, &hid, project_id, disk_mib).await?)
    } else {
        None
    };

    // `handle_deploy` only ever boots the APP VM (the dedicated DB VM boots via its own helper),
    // so it keeps the historical App sizing. Sourced from VmSize so the DB VM reuses the same
    // plumbing and hibernate/restore can't drift the mem-file size.
    let app_size = vm_identity::vm_size_for(vm_identity::VmRole::App);
    let config = VmConfig {
        firecracker_bin,
        kernel_path,
        rootfs_path,
        metadata_image_path: Some(metadata_image_path),
        layer_paths: plan.layer_paths.clone(),
        data_disk_path: disk_guard.as_ref().map(|g| g.device()),
        vcpu_count: app_size.vcpu_count,
        mem_size_mib: app_size.mem_size_mib,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
        runtime_cgroup_parent: Some(PathBuf::from(RUNTIME_CGROUP_PARENT)),
    };
    // If start fails, release the fenced disk + lease AWAITED (not via the Drop
    // backstop) so an immediate re-deploy/re-wake can't race a fire-and-forget cleanup
    // and fail transiently with LeaseHeld/RwoUnsafe.
    let mut vm = match VmInstance::start(project_id, &config, &runtime_dir).await {
        Ok(vm) => vm,
        Err(e) => {
            if let Some(g) = disk_guard {
                g.release().await;
            }
            return Err(e);
        }
    };

    // Re-acquire to commit the running VM: record Firecracker's PID as the data-disk
    // writer (so a future attach's liveness check tracks the real writer, not this
    // server), then DISARM the guard and hand the token to disk_tokens.
    let mut plat = platform.lock().await;
    let fc_pid = vm.pid();
    // Capture the disk fence facts for the handoff, and make the writer-pid commit FATAL: the
    // holder must record the FC pid (so attach_rwo's liveness gate + re-adoption track the real
    // writer) before the handoff names it. On failure, KILL the FC synchronously-to-death FIRST
    // (so the loop it maps is free) THEN release the guard AWAITED, and bail (deploy is
    // retryable) — never commit a VM whose holder still names this server, never detach a loop a
    // live FC still writes.
    let (loop_dev, lease_epoch) = if let Some(guard) = disk_guard {
        if let Some(pid) = fc_pid
            && let Err(e) = dd.set_writer_pid(project_id, guard.token(), pid).await
        {
            drop(plat);
            let _ = vm.stop().await;
            guard.release().await;
            return Err(anyhow::anyhow!("commit set_writer_pid {project_id}: {e}"));
        }
        let dev = guard.device().to_string_lossy().into_owned();
        let epoch = guard.token().epoch;
        plat.disk_tokens
            .insert(project_id.to_string(), guard.disarm());
        (Some(dev), Some(epoch))
    } else {
        (None, None)
    };
    plat.vms.insert(project_id.to_string(), vm);
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Running);
    plat.vm_incarnations.commit(project_id);
    // [R4] Stamp the tier this deploy committed so the NEXT deploy can detect an in-place flip.
    // Stamped HERE, at commit-to-Running — not after `wait_for_agent`/`boot_db_vm` — because the
    // VM can already be writing its DB from this point: a later failure leaves this tree live (a
    // failed deploy is not rolled back) and an unstamped project would let the next deploy flip
    // tiers unrefused. A dedicated stamp before its DB VM writes anything can only over-refuse
    // (the safe direction). Record only for a managed-DB project (nothing to strand otherwise),
    // and KEEP the record when a deploy drops `[database]`: the data stays on its tier's disk
    // (neither disk is reaped by a config edit), so re-adding the DB at the OTHER tier is the
    // same stranding flip. Deleting it here let colocated → no DB → dedicated launder past R4.
    // Only project deletion clears it.
    record_deployed_tier(
        &plat.store,
        project_id,
        &plat.data_dir.join("hosting").join(project_id).join("live"),
    );
    // Cold boot always runs the CURRENT rootfs; track it so a later hibernate stamps the truthful
    // hash (and keeps the GC reference set honest). Clear any wake-failure throttle: this project
    // is now freshly booted, so a stale entry mustn't fast-fail a routing-miss request.
    let ran_hash = plat.base_rootfs_hash.clone();
    plat.vm_rootfs_hashes
        .insert(project_id.to_string(), ran_hash.clone());
    plat.wake_failures.remove(project_id);
    let deployment_version = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .and_then(|p| p.current_version);
    let active_domains = plat
        .store
        .list_active_domains_for_project(project_id)
        .unwrap_or_default();
    drop(plat);

    // Persist the re-adoption record so a future jkbase-server upgrade re-adopts this VM (no
    // bounce) instead of draining → cold-restoring it. Removed on every teardown. Best-effort:
    // a write failure just means this VM cold-boots on the next restart (the prior behavior).
    write_handoff_record(
        &runtime_dir,
        project_id,
        fc_pid,
        &alloc,
        loop_dev,
        lease_epoch,
        ran_hash,
        deployment_version,
    );

    wait_for_agent(&alloc.ip).await?;

    register_active_routes(
        &routing,
        &domain_map,
        &active_domains,
        project_id,
        &alloc.ip,
    )
    .await;

    info!(project = %project_id, ip = %alloc.ip, "VM ready, routing active");

    // A dedicated project runs its managed DB in a SIBLING VM (`{project_id}.db`); boot it now that
    // the app VM is up. A DB-VM boot failure fails the whole deploy (retryable) rather than leaving
    // a half-provisioned dedicated project whose app can't reach a DB. Co-located projects skip
    // this entirely (their DB is the loopback process inside the app VM booted above).
    if dedicated {
        boot_db_vm(project_id, &platform, db_reach_for_db_vm.as_ref()).await?;
    }
    Ok(())
}
