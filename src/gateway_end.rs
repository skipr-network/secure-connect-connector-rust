//! Gateway-end reports (TT-2464, spec §B.18). When an entitlement refresh ends a device's active
//! admitted flow(s) to a Private Gateway (`reconcile_dropped_entitlements` in `main`), this
//! Connector records one report for that gateway and device. Every heartbeat request carries the
//! pending reports in `ended_flows`, and Portal turns each accepted one into the
//! `ended_gateway_access` event the client shows as **Access removed** / **Access expired**.
//!
//! A report is removed from the queue only after a heartbeat that carried it succeeded, so a
//! failed heartbeat resends it; Portal accepts each `report_id` once. The queue is kept in a file
//! next to the audit log so reports survive a restart (TT-1734: an ended flow must produce an
//! event). A report that still hasn't been delivered after the 24-hour serving window is dropped
//! unsent - the event could no longer be shown by then anyway.

use anyhow::{Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;
use tracing::warn;

/// How long Portal serves an event after its flow ended (spec §B.18 point 4). Past this, an
/// undelivered report is useless and is dropped from the queue.
pub const SERVING_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

/// The most reports one heartbeat carries, oldest first; the rest go on the following heartbeats.
/// Keeps the request far below Agent's heartbeat body limit (256 KB, `ConnectorHeartbeatBodySizeFilter`)
/// even after a mass revoke: one report is roughly 300 bytes, so 200 is about 60 KB. Without a cap,
/// enough queued reports would get every heartbeat rejected - policy refresh included.
pub const MAX_REPORTS_PER_HEARTBEAT: usize = 200;

/// Field names are part of the heartbeat contract (Connector -> Agent -> Portal).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayEndReport {
    pub report_id: String,
    pub gateway_id: String,
    /// From the entitlement row the device was admitted under - never a caller-supplied value.
    pub user_id: String,
    pub device_public_key: String,
    /// Epoch milliseconds.
    pub ended_at: i64,
    pub flows_ended: usize,
}

/// A random (version 4) UUID, formatted the usual way. Generated here rather than via a `uuid`
/// dependency since this is its only use.
pub fn new_report_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub struct GatewayEndQueue {
    path: PathBuf,
    // Held across the file write so the file always matches memory.
    reports: Mutex<Vec<GatewayEndReport>>,
}

impl GatewayEndQueue {
    /// An empty queue backed by `path`, without reading it - `load` is the startup path.
    #[cfg(test)]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            reports: Mutex::new(Vec::new()),
        }
    }

    /// Reads the reports a previous run left undelivered. A missing file is the normal first-run
    /// case. An unreadable or corrupt file is logged and treated as empty rather than blocking
    /// startup: the Connector's access decisions never depend on this queue.
    pub async fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let reports = match tokio::fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<Vec<GatewayEndReport>>(&bytes) {
                Ok(reports) => reports,
                Err(error) => {
                    warn!(%error, path = %path.display(), "gateway-end report queue file is corrupt - starting empty");
                    Vec::new()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                warn!(%error, path = %path.display(), "could not read the gateway-end report queue file - starting empty");
                Vec::new()
            }
        };
        Self {
            path,
            reports: Mutex::new(reports),
        }
    }

    /// The reports to send on the next heartbeat - at most `MAX_REPORTS_PER_HEARTBEAT`, oldest
    /// first - after dropping any past the serving window.
    pub async fn pending(&self, now_ms: i64) -> Vec<GatewayEndReport> {
        let mut reports = self.reports.lock().await;
        let before = reports.len();
        reports.retain(|report| now_ms - report.ended_at < SERVING_WINDOW_MS);
        let dropped = before - reports.len();
        if dropped > 0 {
            warn!(
                dropped,
                "dropped gateway-end reports never delivered within the serving window"
            );
            if let Err(error) = persist(&self.path, &reports).await {
                warn!(%error, "failed to save the gateway-end report queue");
            }
        }
        reports
            .iter()
            .take(MAX_REPORTS_PER_HEARTBEAT)
            .cloned()
            .collect()
    }

    /// Adds new reports and saves the queue. On a write failure the reports are still queued in
    /// memory and sent; only a restart before delivery would lose them.
    pub async fn enqueue(&self, new_reports: Vec<GatewayEndReport>) -> Result<()> {
        if new_reports.is_empty() {
            return Ok(());
        }
        let mut reports = self.reports.lock().await;
        reports.extend(new_reports);
        persist(&self.path, &reports).await
    }

    /// Removes the reports a successful heartbeat carried, and saves the queue.
    pub async fn acknowledge(&self, delivered_ids: &[String]) -> Result<()> {
        if delivered_ids.is_empty() {
            return Ok(());
        }
        let mut reports = self.reports.lock().await;
        reports.retain(|report| !delivered_ids.contains(&report.report_id));
        persist(&self.path, &reports).await
    }
}

/// Writes to a temporary file and renames it over the queue file, so a crash mid-write never
/// leaves a truncated queue behind.
async fn persist(path: &Path, reports: &[GatewayEndReport]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "failed to create the gateway-end queue directory: {}",
                parent.display()
            )
        })?;
    }
    let bytes =
        serde_json::to_vec(reports).context("failed to serialize the gateway-end report queue")?;
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(id: &str, ended_at: i64) -> GatewayEndReport {
        GatewayEndReport {
            report_id: id.to_string(),
            gateway_id: "gw-1".to_string(),
            user_id: "u-1".to_string(),
            device_public_key: "dev-A".to_string(),
            ended_at,
            flows_ended: 1,
        }
    }

    #[test]
    fn new_report_id_is_a_version_4_uuid() {
        let id = new_report_id();
        assert_eq!(id.len(), 36);
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(matches!(
            parts[3].chars().next(),
            Some('8' | '9' | 'a' | 'b')
        ));
        assert_ne!(id, new_report_id());
    }

    #[tokio::test]
    async fn load_of_a_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let queue = GatewayEndQueue::load(dir.path().join("queue.json")).await;
        assert!(queue.pending(0).await.is_empty());
    }

    #[tokio::test]
    async fn load_of_a_corrupt_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        std::fs::write(&path, b"not json").unwrap();
        let queue = GatewayEndQueue::load(&path).await;
        assert!(queue.pending(0).await.is_empty());
    }

    /// The reason the queue is a file at all (TT-1734): a restart before delivery must not lose
    /// a report.
    #[tokio::test]
    async fn enqueued_reports_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("queue.json");
        let queue = GatewayEndQueue::load(&path).await;
        queue
            .enqueue(vec![report("r-1", 1_000), report("r-2", 2_000)])
            .await
            .unwrap();

        let reloaded = GatewayEndQueue::load(&path).await;
        assert_eq!(
            reloaded.pending(3_000).await,
            vec![report("r-1", 1_000), report("r-2", 2_000)]
        );
        assert!(!path.with_extension("tmp").exists());
    }

    #[tokio::test]
    async fn acknowledge_removes_only_the_delivered_reports_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let queue = GatewayEndQueue::load(&path).await;
        queue
            .enqueue(vec![report("r-1", 1_000), report("r-2", 2_000)])
            .await
            .unwrap();

        queue.acknowledge(&["r-1".to_string()]).await.unwrap();

        assert_eq!(queue.pending(3_000).await, vec![report("r-2", 2_000)]);
        let reloaded = GatewayEndQueue::load(&path).await;
        assert_eq!(reloaded.pending(3_000).await, vec![report("r-2", 2_000)]);
    }

    #[tokio::test]
    async fn pending_drops_reports_past_the_serving_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let queue = GatewayEndQueue::load(&path).await;
        queue
            .enqueue(vec![report("old", 0), report("fresh", 10_000)])
            .await
            .unwrap();

        let now = SERVING_WINDOW_MS + 5_000;
        assert_eq!(queue.pending(now).await, vec![report("fresh", 10_000)]);
        let reloaded = GatewayEndQueue::load(&path).await;
        assert_eq!(reloaded.pending(now).await, vec![report("fresh", 10_000)]);
    }

    #[tokio::test]
    async fn pending_carries_at_most_the_per_heartbeat_cap_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let queue = GatewayEndQueue::new(dir.path().join("q.json"));
        let reports: Vec<_> = (0..MAX_REPORTS_PER_HEARTBEAT + 5)
            .map(|i| report(&format!("r-{i}"), i as i64))
            .collect();
        queue.enqueue(reports.clone()).await.unwrap();

        let first = queue.pending(1_000).await;
        assert_eq!(first, reports[..MAX_REPORTS_PER_HEARTBEAT].to_vec());

        let ids: Vec<String> = first.iter().map(|r| r.report_id.clone()).collect();
        queue.acknowledge(&ids).await.unwrap();
        assert_eq!(
            queue.pending(1_000).await,
            reports[MAX_REPORTS_PER_HEARTBEAT..].to_vec()
        );
    }

    #[tokio::test]
    async fn a_report_exactly_at_the_window_edge_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let queue = GatewayEndQueue::new(dir.path().join("q.json"));
        queue.enqueue(vec![report("edge", 0)]).await.unwrap();
        assert!(queue.pending(SERVING_WINDOW_MS).await.is_empty());
    }
}
