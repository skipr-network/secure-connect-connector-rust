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
//! without a clock; [`ConnectionEvents`] wraps it with the lock and the file. Callers change memory
//! only and never wait for the disk: an admission's reply must not wait for a disk write (TT-2514).
//! A background writer ([`ConnectionEvents::run_writer`]) saves one consistent snapshot of the whole
//! state, taken under the lock and written after it is released, whenever a [`State`] method reports
//! a change.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;
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
/// A repeat of a held denial only updates memory; such updates reach the file within this long, so
/// a crash loses at most those repeat counts (§B.22 point 5). Also the retry delay after a failed
/// write.
pub const REPEAT_FLUSH: Duration = Duration::from_secs(10);

/// How soon a change of the state must reach the file (§B.22 point 5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Change {
    #[default]
    None,
    /// Memory only for now, written within [`REPEAT_FLUSH`]: a repeat of a held denial, or the node
    /// of a connection's latest flow.
    Deferred,
    /// Written at once: a connection opened or ended, a denial window opened or closed, a report
    /// queued or removed, the lost counter changed.
    Prompt,
}

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
    /// The strongest change since the wrapper last asked; never saved. Every mutator sets it, so
    /// the file is written only when something changed (TT-2250 review).
    #[serde(skip)]
    change: Change,
}

impl State {
    fn mark(&mut self, change: Change) {
        self.change = self.change.max(change);
    }

    fn take_change(&mut self) -> Change {
        std::mem::take(&mut self.change)
    }

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
            if open.node_id != node_id {
                open.node_id = node_id.to_string();
                self.mark(Change::Deferred);
            }
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
            self.mark(Change::Deferred);
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
    ///
    /// The open list stays in place while the ends are queued (TT-2250 review): queueing an end
    /// can overflow the queue and drop an establishment, and `unreport` must then find that
    /// connection - ending in this heartbeat or not - to mark it unreported.
    pub fn end_connections(
        &mut self,
        at_ms: i64,
        mut observe: impl FnMut(&OpenConnection) -> Option<(Observation, usize)>,
    ) -> Vec<EndedConnection> {
        let observed: Vec<(String, Observation, usize)> = self
            .open
            .iter()
            .filter_map(|connection| {
                observe(connection).map(|(observation, flows_ended)| {
                    (connection.connection_id.clone(), observation, flows_ended)
                })
            })
            .collect();
        if observed.is_empty() {
            return Vec::new();
        }
        let mut ended = Vec::with_capacity(observed.len());
        for (connection_id, observation, flows_ended) in observed {
            // Read afresh: an earlier end in this loop may have left it unreported.
            let Some(connection) = self
                .open
                .iter()
                .find(|c| c.connection_id == connection_id)
                .cloned()
            else {
                continue;
            };
            let report_id = self.queue_end(&connection, observation, flows_ended, at_ms);
            ended.push(EndedConnection {
                connection_id: connection.connection_id,
                gateway_id: connection.gateway_id,
                device_public_key: connection.device_public_key,
                observation,
                report_id,
            });
        }
        let ended_ids: HashSet<&str> = ended.iter().map(|c| c.connection_id.as_str()).collect();
        self.open
            .retain(|c| !ended_ids.contains(c.connection_id.as_str()));
        // A later end's overflow may have dropped an end queued here or made it notice-only under
        // a new id; the local audit log names the report actually queued.
        for connection in &mut ended {
            if connection.report_id.is_some() {
                connection.report_id = self
                    .queue
                    .iter()
                    .find(|e| {
                        e.kind == Kind::Ended
                            && e.connection_id.as_deref() == Some(connection.connection_id.as_str())
                    })
                    .map(|e| e.report_id.clone());
            }
        }
        self.mark(Change::Prompt);
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
            self.mark(Change::Prompt);
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
            self.mark(Change::Prompt);
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
            self.mark(Change::Prompt);
        }
        applied
    }

    /// A closed window with repeats gets its follow-up row; one without repeats needs none.
    fn close_window(&mut self, held: HeldDenial, now_ms: i64) {
        self.mark(Change::Prompt);
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
        self.mark(Change::Prompt);
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
        self.mark(Change::Prompt);
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
        self.mark(Change::Prompt);
    }

    /// The drops not yet written to the local audit log, now taken.
    fn take_unlogged_drops(&mut self) -> u64 {
        let drops = std::mem::take(&mut self.unlogged_drops);
        if drops > 0 {
            self.mark(Change::Prompt);
        }
        drops
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

/// [`State`] behind a lock, kept in its file by a background writer.
pub struct ConnectionEvents {
    path: PathBuf,
    // A std mutex, never held across an await: every caller only changes memory under it.
    inner: Mutex<Inner>,
    /// Wakes the writer: a prompt change, or a new deadline for a deferred one.
    wake: Notify,
    /// One file write at a time. A snapshot is taken only once this is held, so the file is never
    /// replaced by an older snapshot than the one it holds.
    writing: tokio::sync::Mutex<()>,
}

struct Inner {
    state: State,
    /// Bumped by every change; `saved` is the generation the file holds.
    generation: u64,
    saved: u64,
    /// A change the writer must save at once.
    prompt: bool,
    /// When unsaved deferred changes (or a failed write) must be written at the latest.
    due: Option<Instant>,
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
                generation: 0,
                saved: 0,
                prompt: false,
                due: None,
            }),
            wake: Notify::new(),
            writing: tokio::sync::Mutex::new(()),
        }
    }

    /// See [`State::restart`]; called once at start.
    pub fn restart(&self, now_ms: i64) -> Vec<EndedConnection> {
        self.update(|state| state.restart(now_ms))
    }

    /// See [`State::flow_admitted`]. Memory only: the writer saves a new connection at once, in
    /// the background, so the admission's reply never waits for the disk (TT-2514).
    #[allow(clippy::too_many_arguments)]
    pub fn flow_admitted(
        &self,
        gateway_id: &str,
        device_public_key: &str,
        session_digest: Option<&str>,
        user_id: &str,
        node_id: &str,
        now_ms: i64,
    ) -> Option<String> {
        self.update(|state| {
            state.flow_admitted(
                gateway_id,
                device_public_key,
                session_digest,
                user_id,
                node_id,
                now_ms,
            )
        })
    }

    /// See [`State::denied`]. Memory only: the writer saves a first denial at once and a repeat
    /// within [`REPEAT_FLUSH`] (§B.22 point 5).
    pub fn denied(
        &self,
        gateway_id: &str,
        device_public_key: &str,
        session_digest: Option<&str>,
        reason: &str,
        now_ms: i64,
    ) {
        self.update(|state| {
            state.denied(
                gateway_id,
                device_public_key,
                session_digest,
                reason,
                now_ms,
            )
        });
    }

    /// See [`State::notice_only_end`].
    pub fn notice_only_end(
        &self,
        gateway_id: &str,
        device_public_key: &str,
        user_id: &str,
        observation: Observation,
        flows_ended: usize,
        at_ms: i64,
    ) -> String {
        self.update(|state| {
            state.notice_only_end(
                gateway_id,
                device_public_key,
                user_id,
                observation,
                flows_ended,
                at_ms,
            )
        })
    }

    /// See [`State::end_connections`].
    pub fn end_connections(
        &self,
        at_ms: i64,
        observe: impl FnMut(&OpenConnection) -> Option<(Observation, usize)>,
    ) -> Vec<EndedConnection> {
        self.update(|state| state.end_connections(at_ms, observe))
    }

    /// Closes due denials, then returns what the next heartbeat sends.
    pub fn batch(&self, now_ms: i64) -> Batch {
        self.update(|state| {
            state.close_due_denials(now_ms);
            state.batch(now_ms)
        })
    }

    /// The drops since the last call, for the local audit log.
    pub fn take_unlogged_drops(&self) -> u64 {
        self.update(State::take_unlogged_drops)
    }

    /// See [`State::apply_results`].
    pub fn apply_results(&self, sent: &Batch, results: &HashMap<String, String>) -> ResultsApplied {
        self.update(|state| state.apply_results(sent, results))
    }

    /// Saves whatever is not saved yet and returns once it is written; for a graceful shutdown.
    pub async fn flush(&self) {
        self.save().await;
    }

    /// The background writer: saves a prompt change at once and deferred changes once due. Runs
    /// for the life of the process.
    pub async fn run_writer(&self) {
        loop {
            let (ready, due) = {
                let inner = self.lock();
                (
                    inner.prompt || inner.due.is_some_and(|due| due <= Instant::now()),
                    inner.due,
                )
            };
            if ready {
                self.save().await;
                continue;
            }
            // A wake that comes between the check above and this wait is kept by `Notify`.
            match due {
                Some(due) => {
                    tokio::select! {
                        _ = self.wake.notified() => {}
                        _ = tokio::time::sleep_until(due) => {}
                    }
                }
                None => self.wake.notified().await,
            }
        }
    }

    /// Applies `change` to the state in memory and tells the writer what it changed.
    fn update<T>(&self, change: impl FnOnce(&mut State) -> T) -> T {
        let mut inner = self.lock();
        let result = change(&mut inner.state);
        let wake = match inner.state.take_change() {
            Change::None => false,
            Change::Deferred => {
                inner.generation += 1;
                // Only a new deadline needs the writer's attention; an existing one stands.
                let new_deadline = inner.due.is_none();
                if new_deadline {
                    inner.due = Some(Instant::now() + REPEAT_FLUSH);
                }
                new_deadline
            }
            Change::Prompt => {
                inner.generation += 1;
                inner.prompt = true;
                true
            }
        };
        drop(inner);
        if wake {
            self.wake.notify_one();
        }
        result
    }

    /// Writes one consistent snapshot of the whole state, serialised under the lock and written
    /// after it is released, so an establishment and the queue never get out of step in the file
    /// (§B.22 point 5) and no caller waits for the disk.
    ///
    /// The whole state is serialised under the lock: with a full queue (10,000 reports, a few MB)
    /// that holds admissions for milliseconds per save, which is bounded (one save at a time) and
    /// far less than the disk write the admission used to wait for.
    async fn save(&self) {
        let _writing = self.writing.lock().await;
        let (bytes, generation) = {
            let mut inner = self.lock();
            inner.prompt = false;
            if inner.generation == inner.saved {
                inner.due = None;
                return;
            }
            match serde_json::to_vec(&inner.state) {
                Ok(bytes) => (bytes, inner.generation),
                Err(error) => {
                    warn!(%error, "failed to serialize the connection-event state - kept in memory only");
                    inner.due = Some(Instant::now() + REPEAT_FLUSH);
                    return;
                }
            }
        };
        let written = crate::state_file::write_atomically(&self.path, &bytes).await;
        let mut inner = self.lock();
        match written {
            Ok(()) => {
                inner.saved = generation;
                // Changes made while this was written keep their own deadline or wake.
                if inner.generation == generation {
                    inner.due = None;
                }
            }
            Err(error) => {
                warn!(error = %format!("{error:#}"), "failed to save the connection-event state - kept in memory, retrying");
                let retry = Instant::now() + REPEAT_FLUSH;
                inner.due = Some(inner.due.map_or(retry, |due| due.min(retry)));
            }
        }
    }

    /// The state is plain data, so a panic elsewhere while the lock was held leaves nothing half
    /// done that matters more than keeping admissions answered: a poisoned lock is taken as is.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
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

    /// TT-2250 review: two ends in one heartbeat on a full queue. Each end drops the oldest queued
    /// establishment; the connections those belong to must be marked unreported even while the
    /// ends are being queued, so their later removal ends go notice-only instead of being sent
    /// without an establishment the Portal could place.
    #[test]
    fn ends_that_overflow_a_full_queue_leave_the_dropped_establishments_connections_unreported() {
        let mut state = State::default();
        for i in 0..MAX_QUEUED {
            admit(&mut state, "gw-1", &format!("dev-{i}"), None, T0 + i as i64);
        }
        assert_eq!(state.queued().len(), MAX_QUEUED);
        let last = MAX_QUEUED - 1;
        let ending = [format!("dev-{}", last - 1), format!("dev-{last}")];
        let ended = state.end_connections(T0 + 20_000, |c| {
            ending
                .contains(&c.device_public_key)
                .then_some((Observation::SessionEnded, 0))
        });
        assert_eq!(ended.len(), 2);
        assert_eq!(state.queued().len(), MAX_QUEUED);
        for device in ["dev-0", "dev-1"] {
            let open = state
                .open_connections()
                .iter()
                .find(|c| c.device_public_key == device)
                .unwrap();
            assert_eq!(
                open.establishment,
                Establishment::Unreported,
                "{device}'s establishment was dropped for room"
            );
        }
        assert_eq!(state.lost_count(), 2);

        // Their later removal ends are sent notice-only, so the device still gets its notice.
        state.end_connections(T0 + 30_000, |c| {
            ["dev-0", "dev-1"]
                .contains(&c.device_public_key.as_str())
                .then_some((Observation::EntitlementRemoved, 1))
        });
        let removal_ends: Vec<&ConnectionEvent> = state
            .queued()
            .iter()
            .filter(|e| e.is_removal_end())
            .collect();
        assert_eq!(removal_ends.len(), 2);
        assert!(removal_ends.iter().all(|e| e.notice_only == Some(true)));
    }

    /// An end queued in a heartbeat whose own establishment a later end of that heartbeat drops is
    /// dropped too, and the local audit log is told no report was queued for it.
    #[test]
    fn an_end_whose_establishment_a_later_end_drops_is_dropped_with_it() {
        let mut state = State::default();
        for i in 0..MAX_QUEUED {
            admit(&mut state, "gw-1", &format!("dev-{i}"), None, T0 + i as i64);
        }
        let last = format!("dev-{}", MAX_QUEUED - 1);
        let ended = state.end_connections(T0 + 20_000, |c| {
            (c.device_public_key == "dev-0" || c.device_public_key == last)
                .then_some((Observation::SessionEnded, 0))
        });
        let dev_0 = ended
            .iter()
            .find(|c| c.device_public_key == "dev-0")
            .unwrap();
        assert_eq!(dev_0.report_id, None);
        assert!(
            !state
                .queued()
                .iter()
                .any(|e| e.device_public_key == "dev-0")
        );
    }

    /// TT-2250 review: the file is written only when a method reports a change; a heartbeat with
    /// nothing new changes nothing, and a repeat or a node update is only a deferred change.
    #[test]
    fn only_a_real_change_asks_for_a_save() {
        let mut state = State::default();
        admit(&mut state, "gw-1", "dev-A", None, T0);
        assert_eq!(state.take_change(), Change::Prompt);
        assert_eq!(state.take_change(), Change::None);

        state.close_due_denials(T0 + 1);
        let batch = state.batch(T0 + 1);
        state.apply_results(&batch, &HashMap::new());
        state.end_connections(T0 + 1, |_| None);
        assert_eq!(state.take_unlogged_drops(), 0);
        assert!(admit(&mut state, "gw-1", "dev-A", None, T0 + 2).is_none());
        assert_eq!(state.take_change(), Change::None, "nothing changed");

        state.flow_admitted("gw-1", "dev-A", None, "user-1", "node-2", T0 + 3);
        assert_eq!(state.take_change(), Change::Deferred, "the node only");

        state.denied("gw-1", "dev-B", None, "not_entitled", T0 + 4);
        assert_eq!(state.take_change(), Change::Prompt, "a first denial");
        state.denied("gw-1", "dev-B", None, "not_entitled", T0 + 5);
        assert_eq!(state.take_change(), Change::Deferred, "a repeat");

        state.apply_results(
            &batch,
            &results(&[(&batch.events[0].report_id, "accepted")]),
        );
        assert_eq!(state.take_change(), Change::Prompt, "a report removed");
    }

    fn on_disk(path: &std::path::Path) -> Option<State> {
        std::fs::read(path)
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    /// Lets the writer run until the file holds every change made so far.
    async fn settle(events: &ConnectionEvents) {
        for _ in 0..1_000 {
            {
                let inner = events.lock();
                if inner.generation == inner.saved {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the writer did not save the state");
    }

    #[tokio::test]
    async fn the_state_survives_a_restart_and_the_restart_ends_open_connections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        let events = ConnectionEvents::load(&path).await;
        events.flow_admitted("gw-1", "dev-A", Some("d1"), "user-1", "node-1", T0);
        events.flush().await;
        drop(events);

        let events = ConnectionEvents::load(&path).await;
        let ended = events.restart(T0 + 50);
        assert_eq!(ended.len(), 1);
        let batch = events.batch(T0 + 51);
        let kinds: Vec<Kind> = batch.events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![Kind::Established, Kind::Ended]);
    }

    #[tokio::test]
    async fn a_corrupt_state_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        tokio::fs::write(&path, b"{not json").await.unwrap();
        let events = ConnectionEvents::load(&path).await;
        assert!(events.lock().state.open_connections().is_empty());
    }

    /// TT-2514 rule (TT-2250 review): an admission changes memory only; the background writer
    /// saves the new connection, with its establishment, promptly and in one snapshot.
    #[tokio::test]
    async fn an_admission_changes_memory_only_and_the_writer_saves_it_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        let events = std::sync::Arc::new(ConnectionEvents::load(&path).await);
        events.flow_admitted("gw-1", "dev-A", None, "user-1", "node-1", T0);
        assert!(on_disk(&path).is_none(), "no write on the admission path");

        let writer = tokio::spawn({
            let events = events.clone();
            async move { events.run_writer().await }
        });
        settle(&events).await;
        let saved = on_disk(&path).unwrap();
        assert_eq!(saved.open_connections().len(), 1);
        assert_eq!(
            saved.queued().len(),
            1,
            "the establishment with its connection"
        );
        writer.abort();
    }

    /// TT-2250 review (§B.22 point 5): a single repeat of a held denial followed by silence still
    /// reaches the file within 10 seconds, with no later denial or heartbeat to carry it.
    #[tokio::test(start_paused = true)]
    async fn a_single_repeat_followed_by_silence_is_saved_within_ten_seconds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        let events = std::sync::Arc::new(ConnectionEvents::load(&path).await);
        let writer = tokio::spawn({
            let events = events.clone();
            async move { events.run_writer().await }
        });
        events.denied("gw-1", "dev-A", None, "not_entitled", T0);
        settle(&events).await;
        assert_eq!(on_disk(&path).unwrap().held[0].repeats, 0);

        events.denied("gw-1", "dev-A", None, "not_entitled", T0 + 1);
        tokio::time::sleep(REPEAT_FLUSH - Duration::from_secs(1)).await;
        assert_eq!(
            on_disk(&path).unwrap().held[0].repeats,
            0,
            "a repeat waits, memory only"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        settle(&events).await;
        assert_eq!(on_disk(&path).unwrap().held[0].repeats, 1);
        writer.abort();
    }

    #[tokio::test]
    async fn flush_saves_what_the_writer_has_not_saved_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection-events.json");
        let events = ConnectionEvents::load(&path).await;
        events.denied("gw-1", "dev-A", None, "not_entitled", T0);
        events.denied("gw-1", "dev-A", None, "not_entitled", T0 + 1);
        events.flush().await;
        assert_eq!(on_disk(&path).unwrap().held[0].repeats, 1);
    }
}
