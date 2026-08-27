//! Local audit trail (TT-1732 acceptance criteria: "Connector applies a
//! package or makes an allow/deny decision... the action completes... a
//! local audit entry is recorded"). Append-only JSON-lines file so entries
//! survive a restart, mirroring `identity`'s pattern of a local file being
//! the Connector's own durable state - there's no assumption of a database
//! or remote log sink available on the enterprise network it runs in.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    PolicyApplied {
        connector_id: String,
        gateway_count: usize,
        node_count: usize,
    },
    PolicyRejected {
        reason: String,
    },
    AccessAllowed {
        gateway_id: String,
        user_id: String,
    },
    AccessRefused {
        gateway_id: String,
        user_id: String,
        reason: String,
    },
}

#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    timestamp: String,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

pub struct AuditLog {
    path: PathBuf,
    // One log line is one write(); this only prevents this process's own
    // concurrent record() calls from interleaving mid-line, it isn't a
    // cross-process lock (each heartbeat/access decision opens in append
    // mode, which is atomic for a single write() up to PIPE_BUF on unix).
    write_lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    pub fn record(&self, event: AuditEvent) -> Result<()> {
        self.record_at(event, Utc::now())
    }

    fn record_at(&self, event: AuditEvent, now: DateTime<Utc>) -> Result<()> {
        let record = AuditRecord {
            timestamp: now.to_rfc3339(),
            event: &event,
        };
        let line = serde_json::to_string(&record).context("failed to serialize audit record")?;

        let _guard = self.write_lock.lock().expect("audit log lock poisoned");
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create audit log directory: {}", parent.display())
            })?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open audit log file: {}", self.path.display()))?;
        writeln!(file, "{line}")
            .with_context(|| format!("failed to write audit entry to {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn records_a_policy_applied_event_with_a_timestamp() {
        let dir = tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.log"));
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();

        log.record_at(
            AuditEvent::PolicyApplied {
                connector_id: "c-1".to_string(),
                gateway_count: 2,
                node_count: 3,
            },
            now,
        )
        .unwrap();

        let entries = read_lines(&dir.path().join("audit.log"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["timestamp"], "2026-08-27T10:00:00+00:00");
        assert_eq!(entries[0]["event"], "policy_applied");
        assert_eq!(entries[0]["connector_id"], "c-1");
        assert_eq!(entries[0]["gateway_count"], 2);
        assert_eq!(entries[0]["node_count"], 3);
    }

    #[test]
    fn records_a_policy_rejected_event() {
        let dir = tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.log"));

        log.record(AuditEvent::PolicyRejected {
            reason: "heartbeat package expired".to_string(),
        })
        .unwrap();

        let entries = read_lines(&dir.path().join("audit.log"));
        assert_eq!(entries[0]["event"], "policy_rejected");
        assert_eq!(entries[0]["reason"], "heartbeat package expired");
    }

    #[test]
    fn records_access_allowed_and_refused_events() {
        let dir = tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.log"));

        log.record(AuditEvent::AccessAllowed {
            gateway_id: "gw-1".to_string(),
            user_id: "u-1".to_string(),
        })
        .unwrap();
        log.record(AuditEvent::AccessRefused {
            gateway_id: "gw-1".to_string(),
            user_id: "u-ghost".to_string(),
            reason: "not_entitled".to_string(),
        })
        .unwrap();

        let entries = read_lines(&dir.path().join("audit.log"));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["event"], "access_allowed");
        assert_eq!(entries[1]["event"], "access_refused");
        assert_eq!(entries[1]["reason"], "not_entitled");
    }

    #[test]
    fn appends_across_multiple_record_calls_without_truncating() {
        let dir = tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.log"));

        for index in 0..5 {
            log.record(AuditEvent::AccessAllowed {
                gateway_id: "gw-1".to_string(),
                user_id: format!("u-{index}"),
            })
            .unwrap();
        }

        let entries = read_lines(&dir.path().join("audit.log"));
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[4]["user_id"], "u-4");
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempdir().unwrap();
        let nested_path = dir.path().join("nested/deeper/audit.log");
        let log = AuditLog::new(&nested_path);

        log.record(AuditEvent::PolicyRejected {
            reason: "test".to_string(),
        })
        .unwrap();

        assert!(nested_path.exists());
    }

    #[test]
    fn errors_when_the_path_has_no_writable_parent() {
        let log = AuditLog::new("/this/path/does/not/exist/and/cannot/be/created/audit.log");

        let result = log.record(AuditEvent::PolicyRejected {
            reason: "test".to_string(),
        });

        assert!(result.is_err());
    }
}
