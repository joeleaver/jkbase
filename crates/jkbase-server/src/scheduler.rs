//! Host-driven cron for scheduled functions: each tick reads the durable SCHEDULES registry and
//! wakes + invokes every function that is due, with a bounded catch-up after downtime.

use crate::{LogShipper, PlatformState, wake_project};
use anyhow::Result;
use chrono::{TimeZone, Utc};
use cron::Schedule as CronSchedule;
use jkbase_proxy::{ActivityTracker, DomainMap};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Coarse fixed tick. 30s gives `*/1 * * * *` schedules <=30s firing latency.
pub(crate) const SCHED_TICK: Duration = Duration::from_secs(30);

/// Max simultaneous in-flight fires (each can wake a hibernated VM = seconds).
pub(crate) const MAX_CONCURRENT_FIRES: usize = 4;

/// Never replay further back than this after downtime; collapse backlog to one fire.
pub(crate) const CATCHUP_CAP_SECS: u64 = 3600;

/// Parse a 5-field UNIX cron. The `cron` crate is 6-field (field 0 = seconds), so
/// a standard 5-field expression is left-padded with "0 " to fire at second 0.
/// Must stay in sync with the deploy-time validation in jkbase-control.
pub(crate) fn parse_unix_5field(expr: &str) -> Result<CronSchedule, cron::error::Error> {
    use std::str::FromStr;
    CronSchedule::from_str(&format!("0 {expr}"))
}

/// Fire instants strictly after `last_run`, up to and including `now` (epoch secs).
pub(crate) fn due_since(sched: &CronSchedule, last_run: u64, now: u64) -> Vec<u64> {
    let Some(after) = Utc.timestamp_opt(last_run as i64, 0).single() else {
        return Vec::new();
    };
    sched
        .after(&after)
        .take_while(|t| t.timestamp() as u64 <= now)
        .map(|t| t.timestamp() as u64)
        .collect()
}

/// Host-driven cron loop. Reads the durable SCHEDULES registry each tick (the
/// single source of truth), computes occurrences due since each schedule's
/// last_run, and fires them — waking the project if hibernated. Gated, in future
/// HA, to projects this host owns; today single-host owns all.
pub(crate) async fn scheduler_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
    activity: ActivityTracker,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FIRES));
    let in_flight: Arc<Mutex<HashSet<(String, String)>>> = Arc::new(Mutex::new(HashSet::new()));

    loop {
        tokio::time::sleep(SCHED_TICK).await;
        let now = jkbase_control::auth::timestamp();

        // Snapshot the registry under the lock, then release it before per-project
        // work (wake/invoke must not hold the platform lock).
        let schedules = {
            let plat = platform.lock().await;
            match plat.store.list_schedules() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "scheduler: failed to read schedules");
                    continue;
                }
            }
        };

        for sched in schedules {
            let Ok(parsed) = parse_unix_5field(&sched.cron) else {
                continue;
            };

            // Catch-up cap: clamp the replay origin so a long outage doesn't
            // stampede, and collapse any backlog to a single fire.
            let last = sched.last_run.unwrap_or(now);
            let effective_last = last.max(now.saturating_sub(CATCHUP_CAP_SECS));
            let due = due_since(&parsed, effective_last, now);
            let Some(&fire_at) = due.last() else {
                continue;
            };

            let key = (sched.project_id.clone(), sched.function.clone());
            {
                let mut inf = in_flight.lock().await;
                if !inf.insert(key.clone()) {
                    continue; // already firing from a previous tick
                }
            }

            let platform = platform.clone();
            let routing = routing.clone();
            let domain_map = domain_map.clone();
            let shipper = shipper.clone();
            let sem = sem.clone();
            let in_flight = in_flight.clone();
            let activity = activity.clone();

            tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                let result = fire_schedule(
                    &sched.project_id,
                    &sched.function,
                    platform.clone(),
                    routing,
                    domain_map,
                    shipper,
                )
                .await;

                match result {
                    Ok(()) => {
                        let plat = platform.lock().await;
                        let _ = plat.store.update_schedule_last_run(
                            &sched.project_id,
                            &sched.function,
                            fire_at,
                        );
                        drop(plat);
                        // Count the fire as activity so the project re-hibernates
                        // idle_timeout AFTER the last fire (frequent crons stay warm;
                        // sparse crons scale to zero between fires) rather than
                        // churning on the idle loop's seeded baseline.
                        activity
                            .write()
                            .await
                            .insert(sched.project_id.clone(), Instant::now());
                    }
                    Err(e) => {
                        // last_run unadvanced -> retried next tick (bounded by the cap).
                        tracing::error!(project = %sched.project_id, function = %sched.function,
                            error = %e, "scheduled invoke failed; will retry next tick");
                    }
                }
                in_flight.lock().await.remove(&key);
            });
        }
    }
}

/// Wake `project_id` if needed, then invoke `name` over plain HTTP. Lock-free
/// during the call (wake_project drops the platform lock before returning the IP).
pub(crate) async fn fire_schedule(
    project_id: &str,
    name: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<()> {
    let ip = wake_project(project_id, platform, routing, domain_map, shipper)
        .await
        .map_err(|e| anyhow::anyhow!("wake failed: {e:?}"))?;

    let call = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80")).await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("http://{ip}:80/functions/{name}"))
            .header("x-jkbase-trigger", "schedule")
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        let resp = sender.send_request(req).await?;
        Ok::<_, anyhow::Error>(resp.status())
    };

    let status = match tokio::time::timeout(Duration::from_secs(30), call).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("scheduled fn {name} for {project_id} timed out"),
    };
    if !status.is_success() {
        anyhow::bail!("scheduled fn {name} returned {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_parse_5field_and_due_since() {
        // 5-field UNIX cron parses (via the "0 " seconds shim); junk + wrong
        // arity do not.
        assert!(parse_unix_5field("*/5 * * * *").is_ok());
        assert!(parse_unix_5field("0 9 * * *").is_ok());
        assert!(parse_unix_5field("not a cron").is_err());
        assert!(parse_unix_5field("*/5 * * *").is_err()); // only 4 fields

        // 2021-01-01T00:00:00Z. Occurrences are strictly AFTER last_run, so the
        // 00:00:00 instant itself is excluded.
        let base: u64 = 1_609_459_200;
        let due = due_since(
            &parse_unix_5field("*/5 * * * *").unwrap(),
            base,
            base + 12 * 60,
        );
        assert_eq!(due, vec![base + 5 * 60, base + 10 * 60]);
        // The loop fires only the latest (collapse-to-one catch-up).
        assert_eq!(due.last().copied(), Some(base + 10 * 60));

        // Window with no occurrence yields nothing (a daily cron over one minute).
        let none = due_since(&parse_unix_5field("0 0 * * *").unwrap(), base, base + 60);
        assert!(none.is_empty());
    }
}
