//! Private Gateway connection events (TT-2250, spec §B.22). The Connector reports one fact per
//! connection - one device's admitted access to one Private Gateway within one session - so the
//! Enterprise sees it in its Audit Trail and SIEM: `established` when the first flow of the
//! connection is admitted, `ended` when the Connector observes the access end, and `denied` at
//! once on the first refusal of a device, gateway and reason, with one follow-up row for
//! its repeats when the window closes (TT-2250 comment 71741). DNS lookups,
//! requests, packets and bytes create nothing, and no periodic message is added: the events ride
//! the existing heartbeat.
//!
//! Everything lives in one state file next to the local audit log - the open connections, the
//! queued reports, the held denials and the lost counter - written whole to a temporary file and
//! renamed over the old one, so a crash never leaves a connection without its establishment in
//! the queue or the other way round (§B.22 point 5). A report leaves the queue only on the
//! Portal's result for it (`accepted` or `rejected`); anything else is sent again.
//!
//! The pure bookkeeping is in [`State`], which takes the time as an argument so it can be tested
//! without a clock; [`ConnectionEvents`] wraps it with the lock and the file.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;
use tracing::warn;

use crate::gateway_end::new_report_id;

/// How long a report waits for the Portal before it is dropped and counted as lost (§B.22 point 5).
pub const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// The most reports the queue holds; over it, denials go first, then the oldest establishment
/// with its end (§B.22 point 5).
pub const MAX_QUEUED: usize = 10_000;
/// The most connection events one heartbeat carries (§B.22 point 5): about 84 KB, which with the
/// unresolved-host list keeps the request under the Agent's 256 KiB heartbeat body limit.
pub const MAX_PER_HEARTBEAT: usize = 200;
/// The most denials held at once; a new one beyond that closes the oldest early (§B.22 point 3).
pub const MAX_HELD_DENIALS: usize = 1_000;
/// A denial's window closes once no repeat has come for this long... (TT-2250 comment 71741)
pub const DENIAL_QUIET_MS: i64 = 10 * 60 * 1000;
/// ...or this long after its first refusal at the latest (TT-2250 comment 71741).
pub const DENIAL_MAX_MS: i64 = 60 * 60 * 1000;
/// A repeat of a held denial only updates memory; such updates reach the file at most this often,
/// so a crash loses at most those repeat counts (§B.22 point 5).
pub const REPEAT_FLUSH_MS: i64 = 10_000;

/// The kind of a report; field values are part of the heartbeat contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Established,
    Ended,
    Denied,
}

/// What the Connector saw end a connection (§B.22 point 2) - never a reason the user sees; the
/// Portal turns it into one. When one heartbeat gives a connection more than one, the first in
/// declaration order counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    GatewayRemoved,
    EntitlementRemoved,
    SessionEnded,
    NodeRemoved,
    ConnectorRestart,
}

impl Observation {
    /// A removal of access: its end is also the §B.18 gateway-end report, from which the Portal
    /// makes the device's notice, and it goes ahead of every other report.
    pub fn is_removal(self) -> bool {
        matches!(self, Self::GatewayRemoved | Self::EntitlementRemoved)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GatewayRemoved => "gateway_removed",
            Self::EntitlementRemoved => "entitlement_removed",
            Self::SessionEnded => "session_ended",
            Self::NodeRemoved => "node_removed",
            Self::ConnectorRestart => "connector_restart",
        }
    }
}

/// One report on the heartbeat (`connection_events`, §B.22 point 5). Identifiers and a technical
/// outcome only: names and snapshots are the Portal's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub report_id: String,
    pub kind: Kind,
    pub gateway_id: String,
    pub device_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Epoch milliseconds: when the connection was established or ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<Observation>,
    /// For a removal end: how many flows the end closed (0 when none was open).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flows_ended: Option<usize>,
    /// True only for the removal end of an unreported connection: the Portal makes the device's
    /// notice from it and no Audit Trail record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_only: Option<bool>,
    /// For a denial: the normalised refusal reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<i64>,
    /// For a denial: 1 on the first row; on the follow-up row, the repeats after the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// On a denial's follow-up row: the `report_id` of the window's first row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat_of: Option<String>,
}

impl ConnectionEvent {
    /// The time retention is measured from.
    fn time(&self) -> i64 {
        self.at.or(self.last_at).unwrap_or(0)
    }

    fn is_removal_end(&self) -> bool {
        self.kind == Kind::Ended && self.observation.is_some_and(Observation::is_removal)
    }
}

/// The frozen count of reports this Connector had to drop (`connection_events_lost`). Frozen when
/// sent, so a resend never changes a report the Portal may already have; drops after that start a
/// new counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LostReport {
    pub report_id: String,
    pub count: u64,
    pub first_at: i64,
    pub last_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Establishment {
    /// Its establishment is queued or in flight.
    Pending,
    Accepted,
    /// Its establishment was rejected or dropped: it reports nothing more, except a removal end
    /// as a notice-only end.
    Unreported,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenConnection {
    pub connection_id: String,
    pub gateway_id: String,
    pub device_public_key: String,
    pub session_digest: Option<String>,
    pub user_id: String,
    /// The node of its last admitted flow.
    pub node_id: String,
    pub established_at: i64,
    establishment: Establishment,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct HeldDenial {
    gateway_id: String,
    device_public_key: String,
    session_digest: Option<String>,
    reason: String,
    /// The window's first row, already queued.
    first_report_id: String,
    first_at: i64,
    last_at: i64,
    /// Repeats after the first refusal.
    repeats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LostCounter {
    count: u64,
    first_at: i64,
    last_at: i64,
}

/// A connection the Connector ended, for the local audit log (`connection_ended`).
#[derive(Debug, Clone, PartialEq)]
pub struct EndedConnection {
    pub connection_id: String,
    pub gateway_id: String,
    pub device_public_key: String,
    pub observation: Observation,
    /// The report queued for it; `None` when an unreported connection ends without one.
    pub report_id: Option<String>,
}

/// What one heartbeat sends: the connection events and, when anything was dropped, the frozen
/// lost count.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Batch {
    pub events: Vec<ConnectionEvent>,
    pub lost: Option<LostReport>,
}

/// What applying the Portal's results did, for the local audit log.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResultsApplied {
    pub rejected: Vec<String>,
}

/// The bookkeeping, without the file or the lock.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct State {
    open: Vec<OpenConnection>,
    queue: Vec<ConnectionEvent>,
    held: Vec<HeldDenial>,
    lost: Option<LostCounter>,
    frozen_lost: Option<LostReport>,
    /// Drops not yet written to the local audit log (`connection_events_dropped`).
    #[serde(default)]
    unlogged_drops: u64,
}

impl State {
    #[cfg(test)]
    pub fn open_connections(&self) -> &[OpenConnection] {
        &self.open
    }

    #[cfg(test)]
    pub fn queued(&self) -> &[ConnectionEvent] {
        &self.queue
    }

    #[cfg(test)]
    pub fn lost_count(&self) -> u64 {
        self.lost.as_ref().map_or(0, |lost| lost.count)
    }

    /// A flow of this key was admitted and entered in the flow table. Opens a connection, and
    /// queues its establishment, when none of this key is open; otherwise only remembers the node.
    /// Returns the new connection's id.
    #[allow(clippy::too_many_arguments)]
    pub fn flow_admitted(
        &mut self,
        gateway_id: &str,
        device_public_key: &str,
        session_digest: Option<&str>,
        user_id: &str,
        node_id: &str,
        now_ms: i64,
    ) -> Option<String> {
        if let Some(open) = self.open.iter_mut().find(|c| {
            c.gateway_id == gateway_id
                && c.device_public_key == device_public_key
                && c.session_digest.as_deref() == session_digest
        }) {
            open.node_id = node_id.to_string();
            return None;
        }
        let connection_id = new_report_id();
        self.open.push(OpenConnection {
            connection_id: connection_id.clone(),
            gateway_id: gateway_id.to_string(),
            device_public_key: device_public_key.to_string(),
            session_digest: session_digest.map(str::to_string),
            user_id: user_id.to_string(),
            node_id: node_id.to_string(),
            established_at: now_ms,
            establishment: Establishment::Pending,
        });
        self.push(
            ConnectionEvent {
                connection_id: Some(connection_id.clone()),
                user_id: Some(user_id.to_string()),
                at: Some(now_ms),
                ..event(
                    Kind::Established,
                    gateway_id,
                    device_public_key,
                    session_digest,
                )
            },
            now_ms,
        );
        Some(connection_id)
    }

    /// A refusal the event covers (§B.22 point 3). The first refusal of a key queues its row at
    /// once and opens a window; a repeat within the window only counts. Returns true when a row
    /// was queued (the file must be written), false for a repeat (memory only).
    pub fn denied(
        &mut self,
        gateway_id: &str,
        device_public_key: &str,
        session_digest: Option<&str>,
        reason: &str,
        now_ms: i64,
    ) -> bool {
        // One window per device, gateway and reason (TT-2250 "Collect repeated denials"); the
        // session is reported but does not split the window. A window already due closes first, so
        // this refusal opens a new one and is queued at once.
        if let Some(index) = self.held.iter().position(|h| {
            h.gateway_id == gateway_id
                && h.device_public_key == device_public_key
                && h.reason == reason
        }) && window_due(&self.held[index], now_ms)
        {
            let held = self.held.remove(index);
            self.close_window(held, now_ms);
        }
        if let Some(held) = self.held.iter_mut().find(|h| {
            h.gateway_id == gateway_id
                && h.device_public_key == device_public_key
                && h.reason == reason
        }) {
            held.repeats += 1;
            held.last_at = now_ms;
            return false;
        }
        if self.held.len() >= MAX_HELD_DENIALS {
            let oldest = self
                .held
                .iter()
                .enumerate()
                .min_by_key(|(_, held)| held.first_at)
                .map(|(index, _)| index)
                .expect("the held list is full, so not empty");
            let held = self.held.remove(oldest);
            self.close_window(held, now_ms);
        }
        let first = ConnectionEvent {
            reason: Some(reason.to_string()),
            first_at: Some(now_ms),
            last_at: Some(now_ms),
            count: Some(1),
            ..event(Kind::Denied, gateway_id, device_public_key, session_digest)
        };
        let first_report_id = first.report_id.clone();
        self.push(first, now_ms);
        self.held.push(HeldDenial {
            gateway_id: gateway_id.to_string(),
            device_public_key: device_public_key.to_string(),
            session_digest: session_digest.map(str::to_string),
            reason: reason.to_string(),
            first_report_id,
            first_at: now_ms,
            last_at: now_ms,
            repeats: 0,
        });
        true
    }

    /// Closes every denial window that is due, queuing a follow-up row for those with repeats.
    /// Returns how many windows closed.
    pub fn close_due_denials(&mut self, now_ms: i64) -> usize {
        let (due, kept): (Vec<HeldDenial>, Vec<HeldDenial>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|held| window_due(held, now_ms));
        self.held = kept;
        let closed = due.len();
        for held in due {
            self.close_window(held, now_ms);
        }
        closed
    }

    /// Ends every open connection `observe` gives an observation for, with that observation and
    /// the number of flows the end closed, and queues what each one reports (§B.22 points 2 and 5).
    pub fn end_connections(
        &mut self,
        at_ms: i64,
        mut observe: impl FnMut(&OpenConnection) -> Option<(Observation, usize)>,
    ) -> Vec<EndedConnection> {
        let mut ended = Vec::new();
        let mut kept = Vec::with_capacity(self.open.len());
        for connection in std::mem::take(&mut self.open) {
            match observe(&connection) {
                Some((observation, flows_ended)) => {
                    let report_id = self.queue_end(&connection, observation, flows_ended, at_ms);
                    ended.push(EndedConnection {
                        connection_id: connection.connection_id,
                        gateway_id: connection.gateway_id,
                        device_public_key: connection.device_public_key,
                        observation,
                        report_id,
                    });
                }
                None => kept.push(connection),
            }
        }
        self.open = kept;
        ended
    }

    /// A removal ended flows of a device that has no open connection here (its flow was admitted
    /// while the connection was still being opened): the notice still needs its end, so a
    /// notice-only removal end is queued (§B.22 point 5). Returns its report id.
    pub fn notice_only_end(
        &mut self,
        gateway_id: &str,
        device_public_key: &str,
        user_id: &str,
        observation: Observation,
        flows_ended: usize,
        at_ms: i64,
    ) -> String {
        let end = ConnectionEvent {
            user_id: Some(user_id.to_string()),
            at: Some(at_ms),
            observation: Some(observation),
            flows_ended: Some(flows_ended),
            notice_only: Some(true),
            ..event(Kind::Ended, gateway_id, device_public_key, None)
        };
        let report_id = end.report_id.clone();
        self.push(end, at_ms);
        report_id
    }

    /// At start: every connection still open ends as `connector_restart` at the start time, and
    /// every held denial closes (§B.22 points 2 and 3).
    pub fn restart(&mut self, now_ms: i64) -> Vec<EndedConnection> {
        let ended = self.end_connections(now_ms, |_| Some((Observation::ConnectorRestart, 0)));
        for held in std::mem::take(&mut self.held) {
            self.close_window(held, now_ms);
        }
        ended
    }

    /// The reports to send on the next heartbeat, after dropping those past the retention
    /// (§B.22 point 5). Order: notice-only ends, then removal ends (each right after its own
    /// establishment when that is still queued), then everything else in queue order. An end is
    /// sent only after its establishment was accepted, or in the same batch right after it.
    pub fn batch(&mut self, now_ms: i64) -> Batch {
        self.drop_expired(now_ms);
        if self.frozen_lost.is_none()
            && let Some(lost) = self.lost.take()
        {
            self.frozen_lost = Some(LostReport {
                report_id: new_report_id(),
                count: lost.count,
                first_at: lost.first_at,
                last_at: lost.last_at,
            });
        }

        let establishment_index: HashMap<&str, usize> = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, e)| e.kind == Kind::Established)
            .filter_map(|(index, e)| e.connection_id.as_deref().map(|id| (id, index)))
            .collect();
        let mut taken: Vec<usize> = Vec::new();
        let mut is_taken = HashSet::new();
        let mut take = |index: usize, taken: &mut Vec<usize>| {
            if is_taken.insert(index) {
                taken.push(index);
            }
        };

        // Notice-only ends need no establishment.
        for (index, event) in self.queue.iter().enumerate() {
            if taken.len() >= MAX_PER_HEARTBEAT {
                break;
            }
            if event.notice_only == Some(true) {
                take(index, &mut taken);
            }
        }
        // Removal ends, each after its establishment when that is still queued.
        for (index, event) in self.queue.iter().enumerate() {
            if !event.is_removal_end() || event.notice_only == Some(true) {
                continue;
            }
            let establishment = event
                .connection_id
                .as_deref()
                .and_then(|id| establishment_index.get(id).copied());
            let needed = if establishment.is_some_and(|e| !taken.contains(&e)) {
                2
            } else {
                1
            };
            if taken.len() + needed > MAX_PER_HEARTBEAT {
                break;
            }
            if let Some(establishment) = establishment {
                take(establishment, &mut taken);
            }
            take(index, &mut taken);
        }
        // Everything else, in queue order.
        for (index, event) in self.queue.iter().enumerate() {
            if taken.len() >= MAX_PER_HEARTBEAT {
                break;
            }
            if taken.contains(&index) {
                continue;
            }
            if event.kind == Kind::Ended
                && let Some(establishment) = event
                    .connection_id
                    .as_deref()
                    .and_then(|id| establishment_index.get(id).copied())
                && !taken.contains(&establishment)
            {
                continue;
            }
            // A denial's follow-up goes only after its first denial was answered, or in the same
            // batch right after it, so the Portal can link the two.
            if let Some(first) = event.repeat_of.as_deref()
                && let Some(first_index) = self.queue.iter().position(|e| e.report_id == first)
                && !taken.contains(&first_index)
            {
                continue;
            }
            take(index, &mut taken);
        }

        Batch {
            events: taken
                .iter()
                .map(|&index| self.queue[index].clone())
                .collect(),
            lost: self.frozen_lost.clone(),
        }
    }

    /// Applies the Portal's result for each report `sent` carried (§B.22 point 6): `accepted` and
    /// `rejected` remove it, anything else (`retry`, no result, an unknown value) keeps it. A
    /// result for a report that was not sent is ignored.
    pub fn apply_results(
        &mut self,
        sent: &Batch,
        results: &HashMap<String, String>,
    ) -> ResultsApplied {
        let mut applied = ResultsApplied::default();
        let is_final = |id: &str| {
            matches!(
                results.get(id).map(String::as_str),
                Some("accepted" | "rejected")
            )
        };
        // An end sent with its establishment counts only once the establishment has a final
        // result: until then the Portal could not place the end, whatever it answered for it.
        let undecided_establishments: HashSet<String> = sent
            .events
            .iter()
            .filter(|e| e.kind == Kind::Established && !is_final(&e.report_id))
            .filter_map(|e| e.connection_id.clone())
            .collect();
        for event in &sent.events {
            if event.kind == Kind::Ended
                && event.notice_only != Some(true)
                && event
                    .connection_id
                    .as_ref()
                    .is_some_and(|id| undecided_establishments.contains(id))
            {
                continue;
            }
            let Some(result) = results.get(&event.report_id).map(String::as_str) else {
                continue;
            };
            let accepted = match result {
                "accepted" => true,
                "rejected" => false,
                _ => continue,
            };
            let Some(index) = self
                .queue
                .iter()
                .position(|e| e.report_id == event.report_id)
            else {
                continue;
            };
            let event = self.queue.remove(index);
            if !accepted {
                applied.rejected.push(event.report_id.clone());
            }
            if event.kind == Kind::Established
                && let Some(connection_id) = event.connection_id.as_deref()
            {
                if accepted {
                    if let Some(open) = self
                        .open
                        .iter_mut()
                        .find(|c| c.connection_id == connection_id)
                    {
                        open.establishment = Establishment::Accepted;
                    }
                } else {
                    self.unreport(connection_id, None);
                }
            }
        }
        if let (Some(lost), Some(frozen)) = (&sent.lost, &self.frozen_lost)
            && lost.report_id == frozen.report_id
            && matches!(
                results.get(&lost.report_id).map(String::as_str),
                Some("accepted" | "rejected")
            )
        {
            self.frozen_lost = None;
        }
        applied
    }

    /// A closed window with repeats gets its follow-up row; one without repeats needs none.
    fn close_window(&mut self, held: HeldDenial, now_ms: i64) {
        if held.repeats == 0 {
            return;
        }
        self.push(
            ConnectionEvent {
                reason: Some(held.reason),
                first_at: Some(held.first_at),
                last_at: Some(held.last_at),
                count: Some(held.repeats),
                repeat_of: Some(held.first_report_id),
                ..event(
                    Kind::Denied,
                    &held.gateway_id,
                    &held.device_public_key,
                    held.session_digest.as_deref(),
                )
            },
            now_ms,
        );
    }

    /// Queues what an ended connection reports, returning the report's id.
    fn queue_end(
        &mut self,
        connection: &OpenConnection,
        observation: Observation,
        flows_ended: usize,
        at_ms: i64,
    ) -> Option<String> {
        let notice_only = match connection.establishment {
            Establishment::Pending | Establishment::Accepted => false,
            // Its establishment never reached the Portal: only a removal still reports, for the notice.
            Establishment::Unreported if observation.is_removal() => true,
            Establishment::Unreported => return None,
        };
        let report_id = new_report_id();
        self.push(
            ConnectionEvent {
                report_id: report_id.clone(),
                connection_id: Some(connection.connection_id.clone()),
                user_id: Some(connection.user_id.clone()),
                at: Some(at_ms),
                observation: Some(observation),
                flows_ended: observation.is_removal().then_some(flows_ended),
                notice_only: notice_only.then_some(true),
                ..event(
                    Kind::Ended,
                    &connection.gateway_id,
                    &connection.device_public_key,
                    connection.session_digest.as_deref(),
                )
            },
            at_ms,
        );
        Some(report_id)
    }

    /// An establishment was rejected or dropped: the connection, if still open, reports nothing
    /// more; a queued removal end becomes notice-only, any other queued end is dropped (and counted
    /// as lost when `lost_at` is given).
    fn unreport(&mut self, connection_id: &str, lost_at: Option<i64>) {
        if let Some(open) = self
            .open
            .iter_mut()
            .find(|c| c.connection_id == connection_id)
        {
            open.establishment = Establishment::Unreported;
        }
        let mut dropped = 0;
        self.queue.retain_mut(|event| {
            if event.kind != Kind::Ended || event.connection_id.as_deref() != Some(connection_id) {
                return true;
            }
            if event.is_removal_end() {
                // A new id: the Portal keeps its final result per report_id, so the notice-only end
                // must not reuse the id of an end it has already answered.
                if event.notice_only != Some(true) {
                    event.notice_only = Some(true);
                    event.report_id = new_report_id();
                }
                true
            } else {
                dropped += 1;
                false
            }
        });
        if let Some(now_ms) = lost_at {
            self.count_lost(dropped, now_ms);
        }
    }

    fn push(&mut self, event: ConnectionEvent, now_ms: i64) {
        self.queue.push(event);
        while self.queue.len() > MAX_QUEUED {
            self.drop_one_for_room(now_ms);
        }
    }

    /// Over the limit: the oldest denial first, then the oldest establishment with its end.
    fn drop_one_for_room(&mut self, now_ms: i64) {
        if let Some(index) = self.queue.iter().position(|e| e.kind == Kind::Denied) {
            self.queue.remove(index);
            self.count_lost(1, now_ms);
            return;
        }
        if let Some(index) = self.queue.iter().position(|e| e.kind == Kind::Established) {
            let event = self.queue.remove(index);
            self.count_lost(1, now_ms);
            if let Some(connection_id) = event.connection_id.as_deref() {
                self.unreport(connection_id, Some(now_ms));
            }
            return;
        }
        // Only ends left: the oldest.
        self.queue.remove(0);
        self.count_lost(1, now_ms);
    }

    fn drop_expired(&mut self, now_ms: i64) {
        let mut dropped = 0;
        let mut unreported = Vec::new();
        self.queue.retain(|e| {
            if now_ms - e.time() < RETENTION_MS {
                return true;
            }
            dropped += 1;
            if e.kind == Kind::Established
                && let Some(connection_id) = &e.connection_id
            {
                unreported.push(connection_id.clone());
            }
            false
        });
        self.count_lost(dropped, now_ms);
        for connection_id in unreported {
            self.unreport(&connection_id, Some(now_ms));
        }
    }

    fn count_lost(&mut self, count: u64, now_ms: i64) {
        if count == 0 {
            return;
        }
        let lost = self.lost.get_or_insert(LostCounter {
            count: 0,
            first_at: now_ms,
            last_at: now_ms,
        });
        lost.count += count;
        lost.last_at = now_ms;
        self.unlogged_drops += count;
    }
}

fn window_due(held: &HeldDenial, now_ms: i64) -> bool {
    now_ms - held.last_at >= DENIAL_QUIET_MS || now_ms - held.first_at >= DENIAL_MAX_MS
}

fn event(
    kind: Kind,
    gateway_id: &str,
    device_public_key: &str,
    session_digest: Option<&str>,
) -> ConnectionEvent {
    ConnectionEvent {
        report_id: new_report_id(),
        kind,
        gateway_id: gateway_id.to_string(),
        device_public_key: device_public_key.to_string(),
        session_digest: session_digest.map(str::to_string),
        connection_id: None,
        user_id: None,
        at: None,
        observation: None,
        flows_ended: None,
        notice_only: None,
        reason: None,
        first_at: None,
        last_at: None,
        count: None,
        repeat_of: None,
    }
}

/// [`State`] behind a lock, kept in its file.
pub struct ConnectionEvents {
    path: PathBuf,
    inner: Mutex<Inner>,
}

struct Inner {
    state: State,
    /// When a repeat of a held denial first went unsaved; `None` when the file is current.
    unsaved_since: Option<i64>,
}

impl ConnectionEvents {
    /// Reads the state a previous run left. A missing file is the first run; an unreadable or
    /// corrupt one is logged and treated as empty, since no access decision depends on it.
    pub async fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let state = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<State>(&bytes).unwrap_or_else(|error| {
                warn!(%error, path = %path.display(), "connection-event state file is corrupt - starting empty");
                State::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(error) => {
                warn!(%error, path = %path.display(), "could not read the connection-event state file - starting empty");
                State::default()
            }
        };
        Self {
            path,
            inner: Mutex::new(Inner {
                state,
                unsaved_since: None,
            }),
        }
    }

    /// See [`State::restart`]; called once at start.
    pub async fn restart(&self, now_ms: i64) -> Vec<EndedConnection> {
        self.write(|state| state.restart(now_ms)).await
    }

    /// See [`State::flow_admitted`].
    #[allow(clippy::too_many_arguments)]
    pub async fn flow_admitted(
        &self,
        gateway_id: &str,
        device_public_key: &str,
        session_digest: Option<&str>,
        user_id: &str,
        node_id: &str,
        now_ms: i64,
    ) -> Option<String> {
        let mut inner = self.inner.lock().await;
        let opened = inner.state.flow_admitted(
            gateway_id,
            device_public_key,
            session_digest,
            user_id,
            node_id,
            now_ms,
        );
        if opened.is_some() {
            self.save(&mut inner).await;
        }
        opened
    }

    /// See [`State::denied`]. A repeat is saved with the next write, or after
    /// [`REPEAT_FLUSH_MS`] at the latest.
    pub async fn denied(
        &self,
        gateway_id: &str,
        device_public_key: &str,
        session_digest: Option<&str>,
        reason: &str,
        now_ms: i64,
    ) {
        let mut inner = self.inner.lock().await;
        if inner.state.denied(
            gateway_id,
            device_public_key,
            session_digest,
            reason,
            now_ms,
        ) || inner
            .unsaved_since
            .is_some_and(|since| now_ms - since >= REPEAT_FLUSH_MS)
        {
            self.save(&mut inner).await;
        } else if inner.unsaved_since.is_none() {
            inner.unsaved_since = Some(now_ms);
        }
    }

    /// See [`State::notice_only_end`].
    pub async fn notice_only_end(
        &self,
        gateway_id: &str,
        device_public_key: &str,
        user_id: &str,
        observation: Observation,
        flows_ended: usize,
        at_ms: i64,
    ) -> String {
        self.write(|state| {
            state.notice_only_end(
                gateway_id,
                device_public_key,
                user_id,
                observation,
                flows_ended,
                at_ms,
            )
        })
        .await
    }

    /// See [`State::end_connections`].
    pub async fn end_connections(
        &self,
        at_ms: i64,
        observe: impl FnMut(&OpenConnection) -> Option<(Observation, usize)>,
    ) -> Vec<EndedConnection> {
        self.write(|state| state.end_connections(at_ms, observe))
            .await
    }

    /// Closes due denials, then returns what the next heartbeat sends.
    pub async fn batch(&self, now_ms: i64) -> Batch {
        self.write(|state| {
            state.close_due_denials(now_ms);
            state.batch(now_ms)
        })
        .await
    }

    /// The drops since the last call, for the local audit log.
    pub async fn take_unlogged_drops(&self) -> u64 {
        let mut inner = self.inner.lock().await;
        let drops = std::mem::take(&mut inner.state.unlogged_drops);
        if drops > 0 {
            self.save(&mut inner).await;
        }
        drops
    }

    /// See [`State::apply_results`].
    pub async fn apply_results(
        &self,
        sent: &Batch,
        results: &HashMap<String, String>,
    ) -> ResultsApplied {
        self.write(|state| state.apply_results(sent, results)).await
    }

    async fn write<T>(&self, change: impl FnOnce(&mut State) -> T) -> T {
        // Saves every time instead of cloning and comparing the whole state: these calls run a few
        // times per heartbeat, so one serialisation is the cheaper side.
        let mut inner = self.inner.lock().await;
        let result = change(&mut inner.state);
        self.save(&mut inner).await;
        result
    }

    async fn save(&self, inner: &mut Inner) {
        match persist(&self.path, &inner.state).await {
            Ok(()) => inner.unsaved_since = None,
            Err(error) => {
                warn!(%error, "failed to save the connection-event state - kept in memory only")
            }
        }
    }
}

/// Writes to a temporary file and renames it over the state file, so a crash mid-write never
/// leaves a truncated file behind.
async fn persist(path: &Path, state: &State) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes =
        serde_json::to_vec(state).context("failed to serialize the connection-event state")?;
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

    const T0: i64 = 1_700_000_000_000;

    fn results(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn admit(
        state: &mut State,
        gateway: &str,
        device: &str,
        digest: Option<&str>,
        at: i64,
    ) -> Option<String> {
        state.flow_admitted(gateway, device, digest, "user-1", "node-1", at)
    }

    #[test]
    fn the_first_flow_of_a_key_establishes_a_connection_and_further_flows_do_not() {
        let mut state = State::default();
        assert!(admit(&mut state, "gw-1", "dev-A", Some("d1"), T0).is_some());
        assert!(admit(&mut state, "gw-1", "dev-A", Some("d1"), T0 + 1).is_none());
        assert_eq!(state.queued().len(), 1);
        let established = &state.queued()[0];
        assert_eq!(established.kind, Kind::Established);
        assert_eq!(established.user_id.as_deref(), Some("user-1"));
        assert_eq!(established.at, Some(T0));
        assert_eq!(established.session_digest.as_deref(), Some("d1"));
    }

    #[test]
    fn another_session_or_gateway_is_another_connection() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", Some("d1"), T0);
        admit(&mut state, "gw-1", "dev-A", Some("d2"), T0);
        admit(&mut state, "gw-2", "dev-A", Some("d1"), T0);
        assert_eq!(state.open_connections().len(), 3);
    }

    #[test]
    fn an_end_carries_the_connection_id_and_a_new_flow_after_it_is_a_new_connection() {
        let mut state = State::default();
        let id = admit(&mut state, "gw-1", "dev-A", Some("d1"), T0).unwrap();
        let ended = state.end_connections(T0 + 5, |_| Some((Observation::SessionEnded, 0)));
        assert_eq!(ended.len(), 1);
        let end = state.queued().last().unwrap();
        assert_eq!(end.kind, Kind::Ended);
        assert_eq!(end.connection_id.as_deref(), Some(id.as_str()));
        assert_eq!(end.observation, Some(Observation::SessionEnded));
        assert_eq!(
            end.flows_ended, None,
            "only a removal end carries flows_ended"
        );
        let again = admit(&mut state, "gw-1", "dev-A", Some("d1"), T0 + 6).unwrap();
        assert_ne!(again, id);
    }

    #[test]
    fn a_removal_end_carries_the_flows_it_closed() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", Some("d1"), T0);
        state.end_connections(T0 + 5, |_| Some((Observation::EntitlementRemoved, 3)));
        assert_eq!(state.queued().last().unwrap().flows_ended, Some(3));
    }

    #[test]
    fn the_first_denial_is_queued_at_once_and_its_repeats_in_one_follow_up_row() {
        let mut state = State::default();
        assert!(state.denied("gw-1", "dev-A", Some("d1"), "not_entitled", T0));
        assert_eq!(
            state.queued().len(),
            1,
            "the first row is written straight away"
        );
        let first = state.queued()[0].clone();
        assert_eq!(
            (
                first.count,
                first.first_at,
                first.last_at,
                first.repeat_of.clone()
            ),
            (Some(1), Some(T0), Some(T0), None)
        );
        assert!(!state.denied("gw-1", "dev-A", Some("d1"), "not_entitled", T0 + 1_000));
        assert!(!state.denied("gw-1", "dev-A", Some("d1"), "not_entitled", T0 + 2_000));
        assert!(
            state.denied("gw-1", "dev-A", Some("d1"), "unknown_gateway", T0),
            "another reason is another window"
        );
        assert!(
            !state.denied("gw-1", "dev-A", Some("d2"), "not_entitled", T0 + 2_000),
            "another session is the same window"
        );
        assert_eq!(state.queued().len(), 2);
        assert_eq!(state.close_due_denials(T0 + DENIAL_QUIET_MS - 1), 0);
        assert_eq!(state.close_due_denials(T0 + 2_000 + DENIAL_QUIET_MS), 2);
        // Only the window with repeats gets a follow-up row.
        assert_eq!(state.queued().len(), 3);
        let follow_up = state.queued().last().unwrap();
        assert_eq!(
            follow_up.repeat_of.as_deref(),
            Some(first.report_id.as_str())
        );
        assert_eq!(
            (follow_up.count, follow_up.first_at, follow_up.last_at),
            (Some(3), Some(T0), Some(T0 + 2_000))
        );
        // A repeat after the window starts a new one, with a first row again.
        assert!(state.denied(
            "gw-1",
            "dev-A",
            Some("d1"),
            "not_entitled",
            T0 + 2_000 + DENIAL_QUIET_MS + 1
        ));
        assert_eq!(state.queued().last().unwrap().count, Some(1));
    }

    #[test]
    fn a_denial_that_keeps_repeating_closes_at_its_maximum_period() {
        let mut state = State::default();
        let mut now = T0;
        state.denied("gw-1", "dev-A", None, "not_entitled", now);
        while now + 60_000 < T0 + DENIAL_MAX_MS {
            now += 60_000;
            state.denied("gw-1", "dev-A", None, "not_entitled", now);
            assert_eq!(state.close_due_denials(now), 0);
        }
        now += 60_000;
        assert_eq!(state.close_due_denials(now), 1);
    }

    #[test]
    fn a_full_held_list_closes_its_oldest_window_early() {
        let mut state = State::default();
        for i in 0..MAX_HELD_DENIALS {
            state.denied(
                "gw-1",
                &format!("dev-{i}"),
                None,
                "not_entitled",
                T0 + i as i64,
            );
        }
        state.denied("gw-1", "dev-0", None, "not_entitled", T0 + 4_000); // a repeat in the oldest window
        let before = state.queued().len();
        state.denied("gw-1", "dev-new", None, "not_entitled", T0 + 5_000);
        let added: Vec<&ConnectionEvent> = state.queued()[before..].iter().collect();
        assert_eq!(
            added.len(),
            2,
            "the oldest window's follow-up row, then the new first row"
        );
        assert_eq!(
            (added[0].device_public_key.as_str(), added[0].count),
            ("dev-0", Some(1))
        );
        assert_eq!(added[1].device_public_key, "dev-new");
    }

    #[test]
    fn a_restart_ends_every_open_connection_and_closes_every_held_denial() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", Some("d1"), T0);
        state.denied("gw-1", "dev-B", None, "not_entitled", T0);
        state.denied("gw-1", "dev-B", None, "not_entitled", T0 + 1);
        let ended = state.restart(T0 + 99);
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].observation, Observation::ConnectorRestart);
        assert!(state.open_connections().is_empty());
        let kinds: Vec<Kind> = state.queued().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![Kind::Established, Kind::Denied, Kind::Ended, Kind::Denied]
        );
        assert_eq!(state.queued()[2].at, Some(T0 + 99));
        assert!(state.queued()[3].repeat_of.is_some());
    }

    #[test]
    fn removal_ends_go_first_right_after_their_own_pending_establishment() {
        let mut state = State::default();
        state.denied("gw-9", "dev-Z", None, "not_entitled", T0);
        admit(&mut state, "gw-1", "dev-A", Some("d1"), T0 + 1);
        admit(&mut state, "gw-2", "dev-B", Some("d1"), T0 + 2);
        state.end_connections(T0 + 3, |c| {
            (c.gateway_id == "gw-2").then_some((Observation::GatewayRemoved, 1))
        });
        let batch = state.batch(T0 + 4);
        let order: Vec<(Kind, &str)> = batch
            .events
            .iter()
            .map(|e| (e.kind, e.gateway_id.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                (Kind::Established, "gw-2"),
                (Kind::Ended, "gw-2"),
                (Kind::Denied, "gw-9"),
                (Kind::Established, "gw-1"),
            ]
        );
    }

    #[test]
    fn an_end_waits_for_its_establishment_when_that_does_not_fit_the_batch() {
        let mut state = State::default();
        for i in 0..MAX_PER_HEARTBEAT {
            admit(&mut state, "gw-1", &format!("dev-{i}"), None, T0);
        }
        admit(&mut state, "gw-1", "dev-last", None, T0);
        state.end_connections(T0 + 1, |c| {
            (c.device_public_key == "dev-last").then_some((Observation::SessionEnded, 0))
        });
        let batch = state.batch(T0 + 2);
        assert_eq!(batch.events.len(), MAX_PER_HEARTBEAT);
        assert!(batch.events.iter().all(|e| e.kind == Kind::Established));
        assert!(
            !batch
                .events
                .iter()
                .any(|e| e.device_public_key == "dev-last")
        );
    }

    #[test]
    fn a_follow_up_waits_for_its_first_denial() {
        let mut state = State::default();
        for i in 0..MAX_PER_HEARTBEAT {
            admit(&mut state, "gw-1", &format!("dev-{i}"), None, T0);
        }
        state.denied("gw-1", "dev-X", None, "not_entitled", T0);
        state.denied("gw-1", "dev-X", None, "not_entitled", T0 + 1);
        state.close_due_denials(T0 + DENIAL_MAX_MS);
        let batch = state.batch(T0 + DENIAL_MAX_MS);
        assert!(
            !batch.events.iter().any(|e| e.kind == Kind::Denied),
            "neither the first nor its follow-up fits"
        );
        let results: HashMap<String, String> = batch
            .events
            .iter()
            .map(|e| (e.report_id.clone(), "accepted".to_string()))
            .collect();
        state.apply_results(&batch, &results);
        let next = state.batch(T0 + DENIAL_MAX_MS + 1);
        let kinds: Vec<Option<u64>> = next.events.iter().map(|e| e.count).collect();
        assert_eq!(
            kinds,
            vec![Some(1), Some(1)],
            "the first denial, then its follow-up"
        );
        assert!(next.events[1].repeat_of.is_some());
    }

    #[test]
    fn a_rejected_establishment_sent_with_its_removal_end_leaves_a_notice_only_end_with_a_new_id() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        state.end_connections(T0 + 1, |_| Some((Observation::EntitlementRemoved, 2)));
        let batch = state.batch(T0 + 2);
        assert_eq!(batch.events.len(), 2);
        let both_rejected: HashMap<String, String> = batch
            .events
            .iter()
            .map(|e| (e.report_id.clone(), "rejected".to_string()))
            .collect();
        state.apply_results(&batch, &both_rejected);
        assert_eq!(state.queued().len(), 1);
        let notice = &state.queued()[0];
        assert_eq!(notice.notice_only, Some(true));
        assert!(batch.events.iter().all(|e| e.report_id != notice.report_id));
    }

    #[test]
    fn an_end_sent_with_an_establishment_that_got_retry_is_kept() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        state.end_connections(T0 + 1, |_| Some((Observation::SessionEnded, 0)));
        let batch = state.batch(T0 + 2);
        let answers = results(&[
            (&batch.events[0].report_id, "retry"),
            (&batch.events[1].report_id, "rejected"),
        ]);
        state.apply_results(&batch, &answers);
        assert_eq!(
            state.queued().len(),
            2,
            "the end waits for its establishment"
        );
    }

    #[test]
    fn a_refusal_after_a_due_window_opens_a_new_one_at_once() {
        let mut state = State::default();
        state.denied("gw-1", "dev-A", None, "not_entitled", T0);
        state.denied("gw-1", "dev-A", None, "not_entitled", T0 + 1);
        // No heartbeat closed the window, but it is due: this refusal is a new first row.
        assert!(state.denied(
            "gw-1",
            "dev-A",
            None,
            "not_entitled",
            T0 + 1 + DENIAL_QUIET_MS
        ));
        let counts: Vec<(Option<u64>, bool)> = state
            .queued()
            .iter()
            .map(|e| (e.count, e.repeat_of.is_some()))
            .collect();
        assert_eq!(
            counts,
            vec![(Some(1), false), (Some(1), true), (Some(1), false)]
        );
    }

    #[test]
    fn a_removal_without_an_open_connection_queues_a_notice_only_end() {
        let mut state = State::default();
        let id = state.notice_only_end(
            "gw-1",
            "dev-A",
            "user-1",
            Observation::EntitlementRemoved,
            1,
            T0,
        );
        let end = &state.queued()[0];
        assert_eq!(
            (end.report_id.as_str(), end.notice_only, end.flows_ended),
            (id.as_str(), Some(true), Some(1))
        );
        assert_eq!(state.batch(T0 + 1).events.len(), 1);
    }

    #[test]
    fn accepted_and_rejected_results_remove_reports_and_retry_keeps_them() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        admit(&mut state, "gw-1", "dev-B", None, T0);
        admit(&mut state, "gw-1", "dev-C", None, T0);
        let batch = state.batch(T0 + 1);
        let ids: Vec<&str> = batch.events.iter().map(|e| e.report_id.as_str()).collect();
        let applied = state.apply_results(
            &batch,
            &results(&[
                (ids[0], "accepted"),
                (ids[1], "rejected"),
                (ids[2], "retry"),
                ("someone-else", "accepted"),
            ]),
        );
        assert_eq!(applied.rejected, vec![ids[1].to_string()]);
        assert_eq!(state.queued().len(), 1);
        assert_eq!(state.queued()[0].report_id, ids[2]);
    }

    #[test]
    fn no_results_keep_every_report() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        let batch = state.batch(T0 + 1);
        state.apply_results(&batch, &HashMap::new());
        assert_eq!(state.queued().len(), 1);
    }

    #[test]
    fn a_rejected_establishment_leaves_the_connection_unreported() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", Some("d1"), T0);
        let batch = state.batch(T0 + 1);
        state.apply_results(
            &batch,
            &results(&[(&batch.events[0].report_id, "rejected")]),
        );
        // Further flows do not establish it again.
        assert!(admit(&mut state, "gw-1", "dev-A", Some("d1"), T0 + 2).is_none());
        assert!(state.queued().is_empty());
        // A session end is dropped silently...
        let ended = state.end_connections(T0 + 3, |_| Some((Observation::SessionEnded, 0)));
        assert_eq!(ended[0].report_id, None);
        assert!(state.queued().is_empty());
        assert_eq!(state.lost_count(), 0, "a rejected report is not lost");
    }

    #[test]
    fn an_unreported_connections_removal_end_is_sent_notice_only_and_first() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", Some("d1"), T0);
        let batch = state.batch(T0 + 1);
        state.apply_results(
            &batch,
            &results(&[(&batch.events[0].report_id, "rejected")]),
        );
        admit(&mut state, "gw-2", "dev-B", None, T0 + 2);
        state.end_connections(T0 + 3, |c| {
            (c.gateway_id == "gw-1").then_some((Observation::EntitlementRemoved, 2))
        });
        let batch = state.batch(T0 + 4);
        assert_eq!(batch.events[0].notice_only, Some(true));
        assert_eq!(batch.events[0].flows_ended, Some(2));
        assert_eq!(batch.events[1].gateway_id, "gw-2");
    }

    #[test]
    fn a_queued_removal_end_becomes_notice_only_when_its_establishment_is_rejected() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        let establishment = state.batch(T0 + 1);
        state.end_connections(T0 + 2, |_| Some((Observation::EntitlementRemoved, 1)));
        state.apply_results(
            &establishment,
            &results(&[(&establishment.events[0].report_id, "rejected")]),
        );
        assert_eq!(state.queued().len(), 1);
        assert_eq!(state.queued()[0].notice_only, Some(true));
    }

    #[test]
    fn reports_past_the_retention_are_dropped_counted_and_frozen_into_one_lost_report() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        state.end_connections(T0 + 1, |_| Some((Observation::SessionEnded, 0)));
        let batch = state.batch(T0 + RETENTION_MS + 2);
        assert!(batch.events.is_empty());
        let lost = batch.lost.clone().expect("a lost report");
        assert_eq!(
            lost.count, 2,
            "the establishment and the end dropped with it"
        );
        // Resent unchanged until the Portal answers it.
        assert_eq!(state.batch(T0 + RETENTION_MS + 3).lost, Some(lost.clone()));
        state.apply_results(&batch, &results(&[(&lost.report_id, "accepted")]));
        assert_eq!(state.batch(T0 + RETENTION_MS + 4).lost, None);
    }

    #[test]
    fn drops_after_freezing_start_a_new_counter() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        let first = state.batch(T0 + RETENTION_MS + 1).lost.unwrap();
        admit(&mut state, "gw-1", "dev-B", None, T0 + 10);
        let resent = state.batch(T0 + RETENTION_MS + 20).lost.unwrap();
        assert_eq!(resent, first, "the frozen report never changes");
        state.apply_results(
            &Batch {
                events: vec![],
                lost: Some(first.clone()),
            },
            &results(&[(&first.report_id, "accepted")]),
        );
        let next = state.batch(T0 + RETENTION_MS + 21).lost.unwrap();
        assert_ne!(next.report_id, first.report_id);
        assert_eq!(next.count, 1);
    }

    #[test]
    fn over_the_limit_denials_are_dropped_before_connections() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        for i in 0..MAX_QUEUED {
            state.denied("gw-1", &format!("dev-{i}"), None, "not_entitled", T0);
            state.close_due_denials(T0 + DENIAL_MAX_MS); // keeps the held list small
        }
        assert_eq!(state.queued().len(), MAX_QUEUED);
        assert_eq!(state.queued()[0].kind, Kind::Established);
        assert_eq!(state.lost_count(), 1);
    }

    #[test]
    fn the_wire_form_leaves_out_fields_a_kind_does_not_have() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        let json = serde_json::to_value(&state.queued()[0]).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut keys = keys;
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "at",
                "connection_id",
                "device_public_key",
                "gateway_id",
                "kind",
                "report_id",
                "user_id"
            ]
        );
        assert_eq!(json["kind"], "established");
    }

    #[tokio::test]
    async fn the_state_survives_a_restart_and_the_restart_ends_open_connections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        let events = ConnectionEvents::load(&path).await;
        events
            .flow_admitted("gw-1", "dev-A", Some("d1"), "user-1", "node-1", T0)
            .await;
        drop(events);

        let events = ConnectionEvents::load(&path).await;
        let ended = events.restart(T0 + 50).await;
        assert_eq!(ended.len(), 1);
        let batch = events.batch(T0 + 51).await;
        let kinds: Vec<Kind> = batch.events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![Kind::Established, Kind::Ended]);
    }

    #[tokio::test]
    async fn a_corrupt_state_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        tokio::fs::write(&path, b"{not json").await.unwrap();
        let events = ConnectionEvents::load(&path).await;
        assert!(
            events
                .inner
                .lock()
                .await
                .state
                .open_connections()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_repeat_of_a_held_denial_is_saved_with_the_next_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        let events = ConnectionEvents::load(&path).await;
        events
            .denied("gw-1", "dev-A", None, "not_entitled", T0)
            .await;
        events
            .denied("gw-1", "dev-A", None, "not_entitled", T0 + 1)
            .await; // memory only
        let on_disk: State =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        assert_eq!(on_disk.held[0].repeats, 0);
        events
            .denied(
                "gw-1",
                "dev-A",
                None,
                "not_entitled",
                T0 + REPEAT_FLUSH_MS + 1,
            )
            .await;
        let on_disk: State =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        assert_eq!(on_disk.held[0].repeats, 2);
    }
}
