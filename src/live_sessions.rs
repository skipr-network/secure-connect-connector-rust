//! Lease-bound admission (TT-3770, spec §B.9 point 1).
//!
//! The signed data a flow admission presents is the client's signed provisioning request. It has no
//! nonce and no expiry, so on its own a captured proof would admit traffic for as long as its key
//! stays entitled. With the Zero Trust module on, the proof therefore also counts only while the
//! lease of the session it was signed for lives: the signed data carries that session's one-time
//! `provision_token`, and each heartbeat reply carries the live-session snapshot - for each device
//! key on this Connector's entitlement lists, the SHA-256 digests of the tokens of that key's live
//! leases. A flow is admitted only if the digest of its token is in the snapshot for its key.
//!
//! The snapshot is kept apart from the entitlement lists (`PolicyStore`'s bundles), so a session
//! ending never runs through the dropped-entitlement path (§B.18).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, watch};

/// Lease-binding settings (spec §B.9 point 1), all configurable - see `config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveSessionSettings {
    /// Most key-digest entries a snapshot may hold; a larger one is refused whole.
    pub max_entries: usize,
    /// How long a kept snapshot may be used: three heartbeat intervals.
    pub max_age: Duration,
    /// How long a flow with an unknown digest waits for a fresh snapshot - below Gatekeeper's
    /// flow-admission timeout (10 s).
    pub flow_wait: Duration,
    /// Shortest gap between two off-schedule heartbeats.
    pub off_schedule_min_interval: Duration,
}

pub const DEFAULT_MAX_ENTRIES: usize = 20_000;
pub const DEFAULT_FLOW_WAIT: Duration = Duration::from_secs(8);
/// Below `DEFAULT_FLOW_WAIT`, so a device that connects just after another one's off-schedule
/// heartbeat has its own heartbeat start within its flow's wait; the snapshot arrives in time when
/// that heartbeat takes under the wait minus this interval (3 s at the defaults). With the 60-second
/// heartbeat that is
/// at most 54 proven requests in the 241 seconds the Agent remembers each one, inside the Agent's
/// default `max-proofs-per-connector` of 60.
pub const DEFAULT_OFF_SCHEDULE_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// The kept snapshot's maximum age, in heartbeat intervals.
pub const MAX_AGE_IN_HEARTBEAT_INTERVALS: u32 = 3;

impl Default for LiveSessionSettings {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_age: Duration::from_secs(60) * MAX_AGE_IN_HEARTBEAT_INTERVALS,
            flow_wait: DEFAULT_FLOW_WAIT,
            off_schedule_min_interval: DEFAULT_OFF_SCHEDULE_MIN_INTERVAL,
        }
    }
}

/// Lower-case hex SHA-256 of the token's UTF-8 bytes - the digest the Portal stores and sends.
pub fn token_digest(token: &str) -> String {
    hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        token.as_bytes(),
    ))
}

/// The digest of the `provision_token` in a signed provisioning request (JSON, as the device signed
/// it); `None` when the signed data is not such a request or carries no token.
pub fn session_digest(signed_message: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(signed_message).ok()?;
    let token = value.get("provision_token")?.as_str()?;
    if token.is_empty() {
        return None;
    }
    Some(token_digest(token))
}

/// What a heartbeat reply did to the snapshot - `run_heartbeat` records the ones that need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotUpdate {
    /// A fresh snapshot was accepted; open flows whose digest is not in it end.
    Accepted { entries: usize },
    /// The reply says the module is off: admission is signature-only.
    ModuleOff,
    /// The reply carries no snapshot and none was ever accepted (an older Agent or Portal, or the
    /// module reported on without one): admission stays signature-only.
    NoneYet,
    /// The reply carries no snapshot, so the last accepted one is kept.
    Missing,
    /// The snapshot is over the size limit and was refused whole; the last accepted one is kept.
    Refused { entries: usize, limit: usize },
}

/// The lease check of one admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseCheck {
    /// Signature-only (no snapshot yet, or module off), or the digest is in the snapshot.
    Admit,
    /// Refused, with the local audit reason.
    Refuse(&'static str),
    /// The digest is not in the snapshot yet: a fresher one is needed.
    Unknown,
}

/// Local audit reasons of the refusals this binding makes (spec §B.10).
pub const REASON_NOT_IN_SNAPSHOT: &str = "session_digest_not_in_snapshot";
pub const REASON_NO_SNAPSHOT_IN_TIME: &str = "no_snapshot_in_time";
pub const REASON_NO_TOKEN: &str = "signed_data_without_session_token";
pub const REASON_SNAPSHOT_TOO_OLD: &str = "snapshot_too_old";

enum Mode {
    /// No snapshot was ever accepted: signature-only.
    NoneYet,
    /// The latest reply said the module is off: signature-only.
    Off,
    On {
        sessions: HashMap<String, HashSet<String>>,
        accepted_at: Instant,
    },
}

/// The snapshot state shared by the heartbeat loop (writer) and the admission tasks (readers).
pub struct LiveSessions {
    settings: LiveSessionSettings,
    mode: Mutex<Mode>,
    /// When the request of the latest snapshot change was sent - waiters look for one sent after
    /// their admission arrived.
    changed: watch::Sender<Option<Instant>>,
    refresh_requested: AtomicBool,
    refresh_notify: Notify,
}

impl LiveSessions {
    pub fn new(settings: LiveSessionSettings) -> Self {
        Self {
            settings,
            mode: Mutex::new(Mode::NoneYet),
            changed: watch::channel(None).0,
            refresh_requested: AtomicBool::new(false),
            refresh_notify: Notify::new(),
        }
    }

    pub fn settings(&self) -> LiveSessionSettings {
        self.settings
    }

    /// Applies one verified, in-force heartbeat reply's module flag and snapshot. `requested_at` is
    /// when that heartbeat's request was sent.
    pub fn update(
        &self,
        zero_trust_enabled: Option<bool>,
        snapshot: Option<HashMap<String, Vec<String>>>,
        requested_at: Instant,
    ) -> SnapshotUpdate {
        let mut mode = self.mode.lock().expect("live sessions lock poisoned");
        if zero_trust_enabled == Some(false) {
            *mode = Mode::Off;
            drop(mode);
            self.changed.send_replace(Some(requested_at));
            return SnapshotUpdate::ModuleOff;
        }
        let had_one = matches!(*mode, Mode::On { .. });
        let Some(snapshot) = snapshot else {
            return if had_one {
                SnapshotUpdate::Missing
            } else {
                SnapshotUpdate::NoneYet
            };
        };
        let entries: usize = snapshot.values().map(Vec::len).sum();
        if entries > self.settings.max_entries {
            return SnapshotUpdate::Refused {
                entries,
                limit: self.settings.max_entries,
            };
        }
        *mode = Mode::On {
            sessions: snapshot
                .into_iter()
                .map(|(key, digests)| (key, digests.into_iter().collect()))
                .collect(),
            accepted_at: Instant::now(),
        };
        drop(mode);
        self.changed.send_replace(Some(requested_at));
        SnapshotUpdate::Accepted { entries }
    }

    /// The lease check for an entitled key with a valid signature. `digest` is the digest of the
    /// token in its signed data, if it carries one.
    pub fn check(&self, device_public_key: &str, digest: Option<&str>) -> LeaseCheck {
        let mode = self.mode.lock().expect("live sessions lock poisoned");
        let Mode::On {
            sessions,
            accepted_at,
        } = &*mode
        else {
            return LeaseCheck::Admit;
        };
        let Some(digest) = digest else {
            return LeaseCheck::Refuse(REASON_NO_TOKEN);
        };
        if accepted_at.elapsed() > self.settings.max_age {
            return LeaseCheck::Refuse(REASON_SNAPSHOT_TOO_OLD);
        }
        if sessions
            .get(device_public_key)
            .is_some_and(|digests| digests.contains(digest))
        {
            LeaseCheck::Admit
        } else {
            LeaseCheck::Unknown
        }
    }

    /// Whether a flow admitted with `digest` for `device_public_key` still has a live session.
    /// Only meaningful right after an accepted snapshot; true when no snapshot is in force.
    pub fn is_live(&self, device_public_key: &str, digest: Option<&str>) -> bool {
        let mode = self.mode.lock().expect("live sessions lock poisoned");
        match &*mode {
            Mode::On { sessions, .. } => digest.is_some_and(|digest| {
                sessions
                    .get(device_public_key)
                    .is_some_and(|digests| digests.contains(digest))
            }),
            _ => true,
        }
    }

    /// Asks the heartbeat loop for one off-schedule heartbeat. However many admissions ask, one
    /// request is pending at a time; the loop decides when it may run.
    pub fn request_refresh(&self) {
        if !self.refresh_requested.swap(true, Ordering::AcqRel) {
            self.refresh_notify.notify_one();
        }
    }

    /// Waits until an off-schedule heartbeat is asked for. A request that a heartbeat already
    /// answered (see `clear_refresh_request`) is skipped.
    pub async fn refresh_requested(&self) {
        loop {
            self.refresh_notify.notified().await;
            if self.refresh_requested.load(Ordering::Acquire) {
                return;
            }
        }
    }

    /// Called as any heartbeat starts: its reply answers every request made before it.
    pub fn clear_refresh_request(&self) {
        self.refresh_requested.store(false, Ordering::Release);
    }

    /// Follows snapshot changes: each value is when the heartbeat behind the latest change was
    /// requested (`None` before any change).
    pub fn subscribe(&self) -> watch::Receiver<Option<Instant>> {
        self.changed.subscribe()
    }
}

/// When the heartbeat loop may run an off-schedule heartbeat (TT-3770, spec §B.9 point 1): only when
/// one was asked for, at most one per minimum interval, and after a failure with a gap that doubles
/// up to the regular interval.
pub struct OffSchedule {
    min_interval: Duration,
    max_gap: Duration,
    gap: Duration,
    last_start: Option<tokio::time::Instant>,
}

impl OffSchedule {
    pub fn new(min_interval: Duration, regular_interval: Duration) -> Self {
        Self {
            min_interval,
            max_gap: regular_interval.max(min_interval),
            gap: min_interval,
            last_start: None,
        }
    }

    /// Resolves when an off-schedule heartbeat should start now.
    pub async fn ready(&mut self, sessions: &LiveSessions) {
        sessions.refresh_requested().await;
        if let Some(last_start) = self.last_start {
            tokio::time::sleep_until(last_start + self.gap).await;
        }
        self.last_start = Some(tokio::time::Instant::now());
    }

    /// Records how the off-schedule heartbeat that `ready` started went.
    pub fn ran(&mut self, succeeded: bool) {
        self.gap = if succeeded {
            self.min_interval
        } else {
            (self.gap * 2).min(self.max_gap)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "device-key-1";

    fn settings() -> LiveSessionSettings {
        LiveSessionSettings {
            max_entries: 3,
            max_age: Duration::from_secs(180),
            flow_wait: Duration::from_millis(200),
            off_schedule_min_interval: Duration::from_secs(20),
        }
    }

    fn snapshot(entries: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(key, digests)| {
                (
                    key.to_string(),
                    digests.iter().map(ToString::to_string).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn the_digest_is_lower_case_hex_sha256_of_the_token() {
        // printf '%s' abc | sha256sum
        assert_eq!(
            token_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_session_digest_comes_from_the_signed_requests_provision_token() {
        let signed =
            br#"{"device_id":"d","public_key":"k","provision_token":"abc","gateway_id":"g"}"#;
        assert_eq!(session_digest(signed), Some(token_digest("abc")));
        assert_eq!(session_digest(br#"{"device_id":"d"}"#), None);
        assert_eq!(session_digest(br#"{"provision_token":null}"#), None);
        assert_eq!(session_digest(br#"{"provision_token":""}"#), None);
        assert_eq!(session_digest(b"session-nonce-1"), None);
    }

    #[test]
    fn before_any_snapshot_admission_is_signature_only() {
        let sessions = LiveSessions::new(settings());
        assert_eq!(sessions.check(KEY, None), LeaseCheck::Admit);
        assert_eq!(
            sessions.update(None, None, Instant::now()),
            SnapshotUpdate::NoneYet
        );
        assert_eq!(
            sessions.update(Some(true), None, Instant::now()),
            SnapshotUpdate::NoneYet
        );
        assert_eq!(sessions.check(KEY, Some("x")), LeaseCheck::Admit);
    }

    #[test]
    fn with_a_snapshot_only_a_listed_digest_of_that_key_is_admitted() {
        let sessions = LiveSessions::new(settings());
        assert_eq!(
            sessions.update(
                Some(true),
                Some(snapshot(&[(KEY, &["d1", "d2"]), ("other", &["d3"])])),
                Instant::now()
            ),
            SnapshotUpdate::Accepted { entries: 3 }
        );
        assert_eq!(sessions.check(KEY, Some("d2")), LeaseCheck::Admit);
        assert_eq!(sessions.check(KEY, Some("d3")), LeaseCheck::Unknown);
        assert_eq!(
            sessions.check("unknown-key", Some("d1")),
            LeaseCheck::Unknown
        );
        assert_eq!(
            sessions.check(KEY, None),
            LeaseCheck::Refuse(REASON_NO_TOKEN)
        );
    }

    #[test]
    fn a_reply_without_a_snapshot_keeps_the_last_one() {
        let sessions = LiveSessions::new(settings());
        sessions.update(
            Some(true),
            Some(snapshot(&[(KEY, &["d1"])])),
            Instant::now(),
        );
        assert_eq!(
            sessions.update(None, None, Instant::now()),
            SnapshotUpdate::Missing
        );
        assert_eq!(sessions.check(KEY, Some("d1")), LeaseCheck::Admit);
        assert_eq!(sessions.check(KEY, Some("d9")), LeaseCheck::Unknown);
    }

    #[test]
    fn a_snapshot_over_the_limit_is_refused_whole_and_the_last_one_kept() {
        let sessions = LiveSessions::new(settings());
        sessions.update(
            Some(true),
            Some(snapshot(&[(KEY, &["d1"])])),
            Instant::now(),
        );
        assert_eq!(
            sessions.update(
                Some(true),
                Some(snapshot(&[(KEY, &["a", "b"]), ("other", &["c", "d"])])),
                Instant::now()
            ),
            SnapshotUpdate::Refused {
                entries: 4,
                limit: 3
            }
        );
        assert_eq!(sessions.check(KEY, Some("d1")), LeaseCheck::Admit);
        assert_eq!(sessions.check(KEY, Some("a")), LeaseCheck::Unknown);
    }

    #[test]
    fn module_off_makes_admission_signature_only() {
        let sessions = LiveSessions::new(settings());
        sessions.update(
            Some(true),
            Some(snapshot(&[(KEY, &["d1"])])),
            Instant::now(),
        );
        assert_eq!(
            sessions.update(Some(false), None, Instant::now()),
            SnapshotUpdate::ModuleOff
        );
        assert_eq!(sessions.check(KEY, None), LeaseCheck::Admit);
        assert!(sessions.is_live(KEY, None));
    }

    #[test]
    fn a_kept_snapshot_older_than_its_maximum_age_refuses_new_flows() {
        let sessions = LiveSessions::new(LiveSessionSettings {
            max_age: Duration::ZERO,
            ..settings()
        });
        sessions.update(
            Some(true),
            Some(snapshot(&[(KEY, &["d1"])])),
            Instant::now(),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            sessions.check(KEY, Some("d1")),
            LeaseCheck::Refuse(REASON_SNAPSHOT_TOO_OLD)
        );
    }

    #[test]
    fn is_live_tells_which_admitted_flows_a_snapshot_still_covers() {
        let sessions = LiveSessions::new(settings());
        assert!(sessions.is_live(KEY, None));
        sessions.update(
            Some(true),
            Some(snapshot(&[(KEY, &["d1"])])),
            Instant::now(),
        );
        assert!(sessions.is_live(KEY, Some("d1")));
        assert!(!sessions.is_live(KEY, Some("d2")));
        assert!(!sessions.is_live(KEY, None));
        assert!(!sessions.is_live("other", Some("d1")));
    }

    #[test]
    fn a_subscriber_sees_when_the_latest_change_was_requested() {
        let sessions = LiveSessions::new(settings());
        let mut changes = sessions.subscribe();
        assert_eq!(*changes.borrow_and_update(), None);
        let requested_at = Instant::now();
        sessions.update(Some(true), Some(snapshot(&[(KEY, &["d1"])])), requested_at);
        assert!(changes.has_changed().unwrap());
        assert_eq!(*changes.borrow_and_update(), Some(requested_at));
        // No snapshot in the reply: nothing changes.
        sessions.update(None, None, Instant::now());
        assert!(!changes.has_changed().unwrap());
    }

    /// Worst case: a device connects just after another device's off-schedule heartbeat started. Its
    /// own heartbeat starts within its flow's wait, leaving the wait minus the interval (3 s at the
    /// defaults) for the round trip.
    #[tokio::test(start_paused = true)]
    async fn a_device_connecting_just_after_another_has_its_heartbeat_start_within_the_flow_wait() {
        let sessions = LiveSessions::new(settings());
        let mut off_schedule =
            OffSchedule::new(DEFAULT_OFF_SCHEDULE_MIN_INTERVAL, Duration::from_secs(60));

        sessions.request_refresh();
        off_schedule.ready(&sessions).await;
        sessions.clear_refresh_request();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let second_arrived = tokio::time::Instant::now();
        off_schedule.ran(true);
        sessions.request_refresh();
        off_schedule.ready(&sessions).await;
        let started_after = second_arrived.elapsed();
        assert_eq!(
            started_after,
            DEFAULT_OFF_SCHEDULE_MIN_INTERVAL - Duration::from_millis(100)
        );
        assert!(DEFAULT_FLOW_WAIT - started_after >= Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn off_schedule_heartbeats_keep_the_minimum_interval_and_back_off_after_a_failure() {
        let sessions = LiveSessions::new(settings());
        let mut off_schedule = OffSchedule::new(Duration::from_secs(20), Duration::from_secs(60));
        let start = tokio::time::Instant::now();

        sessions.request_refresh();
        off_schedule.ready(&sessions).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        sessions.clear_refresh_request();
        off_schedule.ran(false);

        // After a failure the gap doubles: 40 s.
        sessions.request_refresh();
        off_schedule.ready(&sessions).await;
        assert_eq!(start.elapsed(), Duration::from_secs(40));
        sessions.clear_refresh_request();
        off_schedule.ran(false);

        // Doubled again, but never past the regular interval: 60 s.
        sessions.request_refresh();
        off_schedule.ready(&sessions).await;
        assert_eq!(start.elapsed(), Duration::from_secs(100));
        sessions.clear_refresh_request();
        off_schedule.ran(true);

        // A success brings it back to the minimum interval.
        sessions.request_refresh();
        off_schedule.ready(&sessions).await;
        assert_eq!(start.elapsed(), Duration::from_secs(120));
    }

    #[tokio::test]
    async fn many_refresh_requests_make_one_pending_request() {
        let sessions = LiveSessions::new(settings());
        sessions.request_refresh();
        sessions.request_refresh();
        tokio::time::timeout(Duration::from_secs(1), sessions.refresh_requested())
            .await
            .expect("a request is pending");
        sessions.clear_refresh_request();
        // The second request was coalesced into the first; a cleared request is not run again.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), sessions.refresh_requested())
                .await
                .is_err()
        );
    }
}
