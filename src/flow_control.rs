//! Connector<->Gatekeeper flow-admission/release decision logic - the agreed contract from the
//! TT-1732 comment thread (2026-08-24 to 2026-08-26), transport-agnostic on purpose (fully testable
//! without a real socket).
//!
//! **TT-2144: this module no longer runs an HTTP server.** Gatekeeper used to call an axum router
//! exposed here directly, dialing *into* this Connector - which required an inbound firewall rule
//! on the Connector host, silently violating the spec's "no inbound port ever opened on the
//! customer's side" principle (found live: a Connector whose own `ufw` had no rule for the
//! admission port made every flow fail closed with an opaque timeout). The channel is now
//! Connector-initiated instead - see `admission_poller`, which calls [`handle_flow_admission`] and
//! [`handle_flow_release`] directly after receiving a message over its own outbound long-poll to
//! Gatekeeper, rather than these being invoked from an axum handler here. [`ControlPlaneState`]
//! stays as the shared bundle both that module and this one's own tests need.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::access::{AccessDecision, decide_access, record_access_decision};
use crate::audit::{AuditEvent, AuditLog};
use crate::crypto;
use crate::dto::PortRule;
use crate::flow_table::{Dialled, FlowTable, Transport};
use crate::live_sessions::{self, LeaseCheck};
use crate::policy::PolicyStore;

#[derive(Debug, Clone, Deserialize)]
pub struct FlowAdmissionRequest {
    pub flow_id: String,
    pub gateway_id: String,
    /// Which node this flow's traffic arrives on - together with `port`,
    /// identifies the flow for the real packet-forwarding loops to gate on
    /// (`flow_table`, TT-1732 review, Tasneem finding #1).
    pub node_id: String,
    /// The translated source port Gatekeeper's NAT assigned this flow (spec
    /// §B.8) - with `node_id` and the dialled identity below, the flow's key in
    /// `flow_table`; without that identity (an older node), its key alongside
    /// `node_id` alone, as before TT-2639.
    pub port: u16,
    /// All three nullable together (TT-2145): Gatekeeper legitimately sends
    /// `null` for these when a flow's device isn't resolvable yet (spec
    /// §B.9's "relaying without a session signature" case) - typing them as
    /// required `String` made serde reject the entire request with a 422
    /// before any admission logic ever ran, so the intended "no signature ->
    /// refuse this flow" decision (with its own audit entry) was never
    /// reached; a schema-validation failure was masquerading as a real
    /// admission outcome.
    pub user_public_key: Option<String>,
    pub signature: Option<String>,
    pub signed_data: Option<String>,
    /// TT-2639 (spec §B.8): what the user dialled - with `node_id` and `port`, the flow's identity.
    /// Read leniently (`dialled`), never as required or typed fields: a node that predates them
    /// sends none, and one bad value must not reject the whole admission (the TT-2145 lesson above).
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub gateway_address: Option<String>,
    #[serde(default)]
    pub destination_port: Option<u16>,
}

impl FlowAdmissionRequest {
    /// The dialled identity, if the admission carries all of it in a usable form; `None` for a node
    /// that predates it (or sent something unusable), whose flow is then handled as before.
    pub fn dialled(&self) -> Option<Dialled> {
        Some(Dialled {
            transport: Transport::from_wire(self.transport.as_deref()?)?,
            gateway_address: self.gateway_address.as_deref()?.parse().ok()?,
            destination_port: self.destination_port?,
        })
    }
}

/// What recording an allowed flow in the flow table came to (`handle_flow_admission`).
enum Recorded {
    Admitted,
    AdmittedWithoutDialledIdentity,
    AlreadyReleased,
    /// TT-3770: a heartbeat accepted a snapshot without this flow's session between its lease check
    /// and here - that heartbeat's reconcile has already run, so admitting it now would outlive it.
    SessionEnded,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FlowAdmissionResponse {
    pub flow_id: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlowReleaseRequest {
    pub flow_id: String,
    pub gateway_id: String,
    #[allow(dead_code)]
    pub port: u16,
}

/// Relayed from Gatekeeper's DNS resolver (spec §B.13, TT-2227) to ask whether a query for one of
/// this Connector's Private Gateway hostnames may be resolved for the querying session.
/// Deliberately shaped like `FlowAdmissionRequest` minus the flow-specific fields (`flow_id`,
/// `node_id`, `port`) - this is a resolve/don't-resolve decision against the same entitlement
/// data, not a NAT admission, so there is no flow to track. `hostname` isn't consulted by the
/// entitlement check itself (only `gateway_id` is - see `authenticate_and_decide`); it rides
/// along purely for this Connector's own logging, since Gatekeeper already resolved it to a
/// `gateway_id` before this request was ever sent.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsAdmissionRequest {
    /// Gatekeeper-generated opaque id that must be echoed back in the admission-result POST so
    /// Gatekeeper can match the decision to the waiting DNS query. Keyed on the same
    /// `/api/connector/{connector_id}/admission-result` endpoint that flow admission uses.
    pub correlation_id: String,
    pub gateway_id: String,
    pub hostname: String,
    pub user_public_key: Option<String>,
    pub signature: Option<String>,
    pub signed_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DnsAdmissionResponse {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct ControlPlaneState {
    pub policy_store: Arc<PolicyStore>,
    pub audit_log: Arc<AuditLog>,
    pub flow_table: Arc<Mutex<FlowTable>>,
    /// Hands a packet `admission_poller` reclaimed via `FlowTable::take_pending` back to
    /// `main::run_wireguard_receive_loop` - the only task allowed to write to the TUN device (see
    /// its own doc comment) - for forwarding, instead of that poller task needing TUN write access
    /// it was never given. `(node_id, packet_bytes)`. Tests that don't exercise this path construct
    /// this from an `unbounded_channel()` and just drop the receiver half - sending into a channel
    /// with no live receiver is a harmless no-op error this code ignores.
    pub recovered_packet_tx: tokio::sync::mpsc::UnboundedSender<(String, Vec<u8>)>,
    /// TT-2250 (spec §B.22): where admissions record connections and denials. `None` in tests that
    /// do not exercise connection events.
    pub connection_events: Option<Arc<crate::connection_events::ConnectionEvents>>,
}

/// What `authenticate_and_decide` resolves to - shared between flow admission and DNS admission,
/// since both are "prove who's asking, then check the same entitlement list" against the same
/// `gateway_id`, just with a different thing to do once admitted (track a flow vs. answer a DNS
/// query).
enum AdmissionOutcome {
    Allowed {
        device_public_key: String,
        /// TT-2250: from the matched entitlement row, never from the caller.
        user_id: String,
        rules: Vec<PortRule>,
        /// TT-3770: the digest of the session token the signed data carried, if any.
        session_digest: Option<String>,
    },
    Refused(&'static str),
    /// TT-3770 (spec §B.9 point 1), DNS only: no decision - the session's digest did not turn up
    /// within the DNS wait, or the kept snapshot is too old. Nothing is posted, so the node answers
    /// SERVFAIL on its own timeout, which clients do not cache as "does not exist" (§B.13 points 4
    /// and 5).
    Undecided(&'static str),
}

/// Which admission the lease check is for: a flow waits up to `flow_wait` for a fresher snapshot, a
/// DNS check up to the shorter `dns_wait`, below the node's DNS admission timeout.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AdmissionKind {
    Flow,
    Dns,
}

/// The lease binding's answer for a key the entitlement check allowed (TT-3770, spec §B.9 point 1).
enum LeaseOutcome {
    Admit,
    Refuse(&'static str),
    Undecided(&'static str),
}

/// TT-3770 (spec §B.9 point 1): the lease check, after the signature and entitlement checks. A digest
/// not in the snapshot asks for one off-schedule heartbeat. A flow then waits, until `flow_wait` after
/// it arrived, and is re-checked on every snapshot change: admitted once its digest is there, refused
/// once a snapshot requested after it arrived still lacks it - with no second fetch. A DNS check waits
/// the same way until `dns_wait` after it arrived, and gets no decision instead of a refusal. Either
/// drops its admission `slot` while it waits, so waiting admissions never stall the node's other
/// admissions and releases.
async fn lease_decision(
    policy_store: &PolicyStore,
    device_public_key: &str,
    digest: Option<&str>,
    arrived: std::time::Instant,
    kind: AdmissionKind,
    slot: &mut Option<AdmissionSlot>,
) -> LeaseOutcome {
    let sessions = policy_store.live_sessions();
    let wait = match kind {
        AdmissionKind::Flow => sessions.settings().flow_wait,
        AdmissionKind::Dns => sessions.settings().dns_wait,
    };
    let deadline = tokio::time::Instant::from_std(arrived + wait);
    let mut changes = sessions.subscribe();
    let mut asked = false;
    loop {
        // Read before the check: a change landing in between is seen on the next round.
        let latest_requested_at = *changes.borrow_and_update();
        match sessions.check(device_public_key, digest) {
            LeaseCheck::Admit => return LeaseOutcome::Admit,
            LeaseCheck::Refuse(reason)
                if kind == AdmissionKind::Dns
                    && reason == live_sessions::REASON_SNAPSHOT_TOO_OLD =>
            {
                return LeaseOutcome::Undecided(reason);
            }
            LeaseCheck::Refuse(reason) => return LeaseOutcome::Refuse(reason),
            LeaseCheck::Unknown => {}
        }
        // Absent from a snapshot fetched after the admission arrived: decided, nothing to fetch.
        if latest_requested_at.is_some_and(|requested_at| requested_at > arrived) {
            return match kind {
                AdmissionKind::Flow => LeaseOutcome::Refuse(live_sessions::REASON_NOT_IN_SNAPSHOT),
                AdmissionKind::Dns => {
                    LeaseOutcome::Undecided(live_sessions::REASON_NOT_IN_SNAPSHOT)
                }
            };
        }
        if !asked {
            asked = true;
            sessions.request_refresh();
            if let Some(slot) = slot.as_mut() {
                slot.release();
            }
        }
        let changed = tokio::time::timeout_at(deadline, changes.changed()).await;
        if !matches!(changed, Ok(Ok(()))) {
            return match kind {
                AdmissionKind::Flow => {
                    LeaseOutcome::Refuse(live_sessions::REASON_NO_SNAPSHOT_IN_TIME)
                }
                AdmissionKind::Dns => {
                    LeaseOutcome::Undecided(live_sessions::REASON_NO_SNAPSHOT_IN_TIME)
                }
            };
        }
    }
}

/// The node's admission slot an admission holds (`admission_poller`, TT-2298). A flow waiting for a
/// fresher live-session snapshot gives it back while it waits and takes one again before it goes
/// on, so waiting flows never stall the node's other admissions and releases (TT-3770).
pub(crate) struct AdmissionSlot {
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl AdmissionSlot {
    pub(crate) fn new(
        semaphore: std::sync::Arc<tokio::sync::Semaphore>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Self {
        Self {
            semaphore,
            permit: Some(permit),
        }
    }

    fn release(&mut self) {
        self.permit = None;
    }

    async fn reacquire(&mut self) {
        if self.permit.is_none() {
            self.permit = self.semaphore.clone().acquire_owned().await.ok();
        }
    }
}

/// The fixed wire reason (TT-1732 contract) for a lease-binding refusal: a missing token is an
/// authentication failure; a session whose lease is not live is an expired entitlement.
fn lease_wire_reason(reason: &str) -> &'static str {
    if reason == live_sessions::REASON_NO_TOKEN {
        "invalid_signature"
    } else {
        "expired_entitlement"
    }
}

/// Authentication and entitlement decision shared by `handle_flow_admission` and
/// `handle_dns_admission` - the exact same proof-of-identity and entitlement check spec §B.9
/// describes, independent of what's being admitted (a flow's NAT'd port vs. a DNS answer).
/// Extracted from `handle_flow_admission` (TT-2227) rather than duplicated, so the two admission
/// paths can never drift on what counts as a valid signature or a matching entitlement.
#[allow(clippy::too_many_arguments)]
async fn authenticate_and_decide(
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    gateway_id: &str,
    user_public_key: Option<String>,
    signature: Option<String>,
    signed_data: Option<String>,
    kind: AdmissionKind,
    slot: &mut Option<AdmissionSlot>,
    events: Option<&crate::connection_events::ConnectionEvents>,
) -> AdmissionOutcome {
    let arrived = std::time::Instant::now();
    // TT-2145: a null signature triple is a normal, anticipated input (spec
    // §B.9), not a malformed request - handle it as a considered "no
    // signature presented -> refuse" decision, with its own audit entry,
    // before ever touching decoding/verification. Deliberately not folded
    // into the invalid_signature branch below: that one always has a
    // device_public_key to record, this one usually doesn't.
    let audit_key_if_missing = user_public_key.clone().unwrap_or_default();
    let (Some(user_public_key), Some(signature), Some(signed_data)) =
        (user_public_key, signature, signed_data)
    else {
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: gateway_id.to_string(),
                device_public_key: audit_key_if_missing,
                reason: "no_signature_presented".to_string(),
            })
            .await
        {
            tracing::error!(%error, "failed to write no-signature audit entry");
        }
        // Fixed four-value wire vocabulary (TT-1732 contract) has no
        // dedicated "no signature" value - same bucket as any other
        // authentication failure from the caller's perspective.
        return AdmissionOutcome::Refused("invalid_signature");
    };

    // Authentication first (spec §B.9): proves possession of user_public_key,
    // not a claimed name. A request that fails this never reaches the
    // entitlement lookup below, regardless of what gateway_id it names.
    //
    // `signed_data` on the wire is itself the base64 *encoding* of the JSON
    // payload the device actually signed (TT-2107) - not the signed bytes
    // themselves, the way `heartbeat.rs`'s `body_bytes` already are for
    // Agent's own signature. Passing the wire string's own bytes straight
    // through (the bug this replaces) verifies against the wrong message
    // every time, regardless of how correct the key/curve/signature parsing
    // otherwise is - confirmed live: a real captured (key, signature,
    // signed_data) triple only verifies once signed_data is base64-decoded
    // first. A decode failure here is treated the same as any other
    // malformed-signature input - refused, not propagated.
    let Ok(signed_message) = BASE64.decode(&signed_data) else {
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: gateway_id.to_string(),
                device_public_key: user_public_key.clone(),
                reason: "invalid_signature".to_string(),
            })
            .await
        {
            tracing::error!(%error, "failed to write invalid-signature audit entry");
        }
        return AdmissionOutcome::Refused("invalid_signature");
    };
    if !crypto::verify_base64(&user_public_key, &signed_message, &signature) {
        // This is itself a deny decision (acceptance criteria: "Connector...
        // makes an allow/deny decision... a local audit entry is recorded"),
        // not just an early exit - best-effort, same as decide_access_and_audit.
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: gateway_id.to_string(),
                device_public_key: user_public_key.clone(),
                reason: "invalid_signature".to_string(),
            })
            .await
        {
            tracing::error!(%error, "failed to write invalid-signature audit entry");
        }
        return AdmissionOutcome::Refused("invalid_signature");
    }

    // A cryptographically valid signature proves possession of
    // user_public_key (spec §B.9); which gateway_id it's presented for is
    // not something the Connector restricts here. TT-1732's original
    // cross-gateway-replay guard (Tasneem's finding) bound a session
    // signature to only the *first* gateway_id it touched, but the spec
    // (§B.5/§B.9, and TT-1732's own acceptance criteria - "it stores
    // policies, entitlement lists, and node list for all attached
    // gateways") requires one session to reach every Private Gateway at
    // this Connector's single Location without reconnecting; a Connector
    // process never serves more than one Location, so there is nothing to
    // gain security-wise from refusing a valid signature reused across
    // gateways it's already legitimately presenting to on this same
    // Connector. Authorization is still decided per request below, against
    // the current entitlement list for the named gateway_id specifically -
    // this only removes a same-Connector restriction the spec never called
    // for.
    // TT-3770: the session the signed data was made for; TT-2250 reports it with a denial too.
    let session_digest = live_sessions::session_digest(&signed_message);
    let decision = decide_access(policy_store, gateway_id, &user_public_key);
    let (rules, user_id) = match &decision {
        AccessDecision::Allowed { rules, user_id } => (rules.clone(), user_id.clone()),
        AccessDecision::Refused(reason) => {
            let reason = *reason;
            record_access_decision(
                audit_log,
                gateway_id,
                &user_public_key,
                &decision,
                Some(reason.as_audit_str()),
            )
            .await;
            record_denial(
                events,
                gateway_id,
                &user_public_key,
                session_digest.as_deref(),
                reason.as_audit_str(),
            )
            .await;
            return AdmissionOutcome::Refused(reason.as_wire_str());
        }
    };

    // TT-3770 (spec §B.9 point 1): with the Zero Trust module on, the proof counts only while the
    // lease of the session it was signed for lives. Checked after the entitlement, so an unknown
    // digest only ever costs a heartbeat for a key that is entitled; audited once decided.
    let lease = lease_decision(
        policy_store,
        &user_public_key,
        session_digest.as_deref(),
        arrived,
        kind,
        slot,
    )
    .await;
    // An undecided DNS check posts nothing, so it needs no slot back.
    if !matches!(lease, LeaseOutcome::Undecided(_))
        && let Some(slot) = slot.as_mut()
    {
        slot.reacquire().await;
    }
    match lease {
        LeaseOutcome::Admit => {
            record_access_decision(audit_log, gateway_id, &user_public_key, &decision, None).await;
            AdmissionOutcome::Allowed {
                device_public_key: user_public_key,
                user_id,
                rules,
                session_digest,
            }
        }
        LeaseOutcome::Refuse(reason) => {
            record_access_decision(
                audit_log,
                gateway_id,
                &user_public_key,
                &decision,
                Some(reason),
            )
            .await;
            record_denial(
                events,
                gateway_id,
                &user_public_key,
                session_digest.as_deref(),
                reason,
            )
            .await;
            AdmissionOutcome::Refused(lease_wire_reason(reason))
        }
        LeaseOutcome::Undecided(reason) => AdmissionOutcome::Undecided(reason),
    }
}

/// TT-2250 (spec §B.22 point 3): an entitlement or lease refusal becomes a denied connection event.
/// A signature refusal never reaches here: its key is unproven.
async fn record_denial(
    events: Option<&crate::connection_events::ConnectionEvents>,
    gateway_id: &str,
    device_public_key: &str,
    session_digest: Option<&str>,
    reason: &str,
) {
    if let Some(events) = events {
        events
            .denied(
                gateway_id,
                device_public_key,
                session_digest,
                reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .await;
    }
}

/// The decision logic `admission_poller` calls once it has received one admission message over its
/// own long-poll to Gatekeeper - previously invoked from an axum handler here directly (pre-TT-2144),
/// now called from that module's own task after HTTP JSON extraction happens there instead. Public
/// so it stays independently testable (as its own unit tests below do) without an HTTP round trip.
#[cfg(test)]
pub(crate) async fn handle_flow_admission(
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    flow_table: &Mutex<FlowTable>,
    request: FlowAdmissionRequest,
) -> FlowAdmissionResponse {
    handle_flow_admission_in_slot(
        policy_store,
        audit_log,
        flow_table,
        request,
        &mut None,
        None,
    )
    .await
}

/// `handle_flow_admission`, holding the node's admission `slot` (`admission_poller`), which it drops
/// while it waits for a fresher live-session snapshot (TT-3770).
pub(crate) async fn handle_flow_admission_in_slot(
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    flow_table: &Mutex<FlowTable>,
    request: FlowAdmissionRequest,
    slot: &mut Option<AdmissionSlot>,
    events: Option<&crate::connection_events::ConnectionEvents>,
) -> FlowAdmissionResponse {
    let dialled = request.dialled();
    let outcome = authenticate_and_decide(
        policy_store,
        audit_log,
        &request.gateway_id,
        request.user_public_key,
        request.signature,
        request.signed_data,
        AdmissionKind::Flow,
        slot,
        events,
    )
    .await;

    match outcome {
        AdmissionOutcome::Allowed {
            device_public_key,
            user_id,
            rules,
            session_digest,
        } => {
            // The real forwarding loops (`main`) only forward traffic for a
            // (node_id, port) pair present here, in both directions
            // (forward: TT-1732 review finding #1 - "a refused, or never
            // checked, device's traffic could still be forwarded once its
            // IP was learned"; reverse/reply routing: TT-1847) - nothing is
            // forwardable or routable until it's recorded as admitted right
            // here. The gateway's port rules ride along so the forwarding loop
            // can also check *where* traffic is headed, not just that the flow
            // is admitted (TT-2046, TT-2514) - being entitled to a gateway says
            // nothing about which ports it opens or where they lead.
            // TT-2298: admissions run concurrently with the poll loop, so this flow's release may
            // already have been handled. Checked under the same lock as the admit below, so a
            // release cannot slip in between; admitting it now would leave a closed flow admitted.
            // TT-2639: identified by what the user dialled too, when the node sends it (spec §B.8).
            // The lock is scoped to this block: its guard must not be held across an await.
            // TT-2514: the rule this flow's packets will be forwarded by, named in the log below.
            let admitted_device_key = device_public_key.clone();
            let admitted_session = session_digest.clone();
            let (recorded, rule) = {
                let mut table = flow_table.lock().expect("flow table lock poisoned");
                // TT-2514 review: a heartbeat may have changed the gateway's rules since they were
                // read above. Those it applied are taken here, under the lock `update_rules` holds,
                // so this flow is never admitted by a rule that heartbeat removed.
                let rules = table
                    .current_rules(&request.gateway_id)
                    .map(<[PortRule]>::to_vec)
                    .unwrap_or(rules);
                let rule = dialled.map(|dialled| {
                    crate::flow_table::matching_rule(
                        &rules,
                        Some(dialled.transport),
                        dialled.destination_port,
                    )
                    .map(ToString::to_string)
                });
                // TT-3770: under the lock `reconcile_lease_ends` also holds, so the flow is either
                // inserted before that reconcile (which then ends it) or refused here.
                let recorded = if table.was_recently_released(&request.flow_id) {
                    Recorded::AlreadyReleased
                } else if !policy_store
                    .live_sessions()
                    .is_live(&device_public_key, session_digest.as_deref())
                {
                    Recorded::SessionEnded
                } else {
                    table.admit_session_flow(
                        request.node_id.clone(),
                        request.port,
                        dialled,
                        request.gateway_id.clone(),
                        request.flow_id.clone(),
                        device_public_key,
                        rules,
                        session_digest,
                    );
                    match dialled {
                        Some(_) => Recorded::Admitted,
                        None => Recorded::AdmittedWithoutDialledIdentity,
                    }
                };
                (recorded, rule)
            };
            // TT-2519 (spec §B.10): the rule serving the flow goes to the local audit log too.
            let (port_rule, warning) = match (&recorded, rule.clone().flatten()) {
                (Recorded::Admitted, Some(rule)) => (Some(rule), None),
                (Recorded::Admitted, None) => (
                    None,
                    Some("no single port rule serves the flow's transport and port".to_string()),
                ),
                (Recorded::AdmittedWithoutDialledIdentity, _) => (
                    None,
                    Some(
                        "the node sent no dialled port; only rules with equal ports serve the flow"
                            .to_string(),
                    ),
                ),
                (Recorded::AlreadyReleased | Recorded::SessionEnded, _) => (None, None),
            };
            if !matches!(recorded, Recorded::AlreadyReleased | Recorded::SessionEnded) {
                // In the background (TT-2514 review): the admission's reply must not wait for a
                // second disk write - the access decision above is already recorded.
                let audit_log = audit_log.clone();
                let event = AuditEvent::FlowAdmitted {
                    flow_id: request.flow_id.clone(),
                    gateway_id: request.gateway_id.clone(),
                    device_public_key: admitted_device_key.clone(),
                    port_rule,
                    warning,
                };
                tokio::spawn(async move {
                    if let Err(error) = audit_log.record(event).await {
                        tracing::error!(%error, "failed to write flow-admitted audit entry");
                    }
                });
            }
            // TT-2250 (spec §B.22 point 1): the first flow of a connection entered in the table
            // establishes it.
            if let Some(events) = events
                && matches!(
                    recorded,
                    Recorded::Admitted | Recorded::AdmittedWithoutDialledIdentity
                )
                && let Some(connection_id) = events
                    .flow_admitted(
                        &request.gateway_id,
                        &admitted_device_key,
                        admitted_session.as_deref(),
                        &user_id,
                        &request.node_id,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await
            {
                let audit_log = audit_log.clone();
                let event = AuditEvent::ConnectionEstablished {
                    connection_id,
                    gateway_id: request.gateway_id.clone(),
                    device_public_key: admitted_device_key.clone(),
                };
                tokio::spawn(async move {
                    if let Err(error) = audit_log.record(event).await {
                        tracing::error!(%error, "failed to write connection-established audit entry");
                    }
                });
            }
            match recorded {
                Recorded::SessionEnded => {
                    tracing::info!(flow_id = %request.flow_id, "the flow's session ended while it was being admitted - not admitting it");
                    record_denial(
                        events,
                        &request.gateway_id,
                        &admitted_device_key,
                        admitted_session.as_deref(),
                        live_sessions::REASON_NOT_IN_SNAPSHOT,
                    )
                    .await;
                    let audit_log = audit_log.clone();
                    let event = AuditEvent::AccessRefused {
                        gateway_id: request.gateway_id.clone(),
                        device_public_key: admitted_device_key,
                        reason: live_sessions::REASON_NOT_IN_SNAPSHOT.to_string(),
                    };
                    tokio::spawn(async move {
                        if let Err(error) = audit_log.record(event).await {
                            tracing::error!(%error, "failed to write session-ended audit entry");
                        }
                    });
                    return FlowAdmissionResponse {
                        flow_id: request.flow_id,
                        decision: "refuse".to_string(),
                        reason: Some("expired_entitlement".to_string()),
                    };
                }
                Recorded::AlreadyReleased => {
                    tracing::warn!(flow_id = %request.flow_id, "flow was released before its admission finished - not admitting it");
                    return FlowAdmissionResponse {
                        flow_id: request.flow_id,
                        decision: "refuse".to_string(),
                        reason: Some("flow_already_released".to_string()),
                    };
                }
                Recorded::AdmittedWithoutDialledIdentity => tracing::warn!(
                    flow_id = %request.flow_id,
                    node_id = %request.node_id,
                    "admission carries no usable transport/gateway_address/destination_port - identifying this flow by node and translated port only; the node's Gatekeeper should be updated (TT-2639)"
                ),
                Recorded::Admitted => match rule.flatten() {
                    Some(rule) => tracing::info!(
                        flow_id = %request.flow_id,
                        gateway_id = %request.gateway_id,
                        %rule,
                        "flow admitted"
                    ),
                    None => tracing::warn!(
                        flow_id = %request.flow_id,
                        gateway_id = %request.gateway_id,
                        "flow admitted, but no single port rule of its gateway serves its transport and port - its packets will be dropped"
                    ),
                },
            }
            FlowAdmissionResponse {
                flow_id: request.flow_id,
                decision: "admit".to_string(),
                reason: None,
            }
        }
        AdmissionOutcome::Refused(reason) => FlowAdmissionResponse {
            flow_id: request.flow_id,
            decision: "refuse".to_string(),
            reason: Some(reason.to_string()),
        },
        // Never for a flow (it waits and is then decided); fail closed all the same.
        AdmissionOutcome::Undecided(_) => FlowAdmissionResponse {
            flow_id: request.flow_id,
            decision: "refuse".to_string(),
            reason: Some("expired_entitlement".to_string()),
        },
    }
}

/// TT-2227: the same proof-of-identity and entitlement check `handle_flow_admission` already
/// applies to a NAT'd flow, applied instead to "may this hostname be resolved for this session" -
/// no flow to track, so nothing here touches `FlowTable`. Called by `admission_poller` when it
/// receives a `dns_admission` message over the Connector-initiated long-poll channel (TT-2144),
/// not from an inbound HTTP route.
///
/// `None` (TT-3770, spec §B.9 point 1) is no decision: nothing is posted back, so the node answers
/// SERVFAIL on its own timeout rather than an NXDOMAIN a client would cache.
#[cfg(test)]
pub(crate) async fn handle_dns_admission(
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    request: DnsAdmissionRequest,
) -> Option<DnsAdmissionResponse> {
    handle_dns_admission_in_slot(policy_store, audit_log, request, &mut None, None).await
}

/// `handle_dns_admission` holding the node's admission `slot`, which it gives back while it waits
/// for a fresher live-session snapshot (TT-3770).
pub(crate) async fn handle_dns_admission_in_slot(
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    request: DnsAdmissionRequest,
    slot: &mut Option<AdmissionSlot>,
    events: Option<&crate::connection_events::ConnectionEvents>,
) -> Option<DnsAdmissionResponse> {
    let outcome = authenticate_and_decide(
        policy_store,
        audit_log,
        &request.gateway_id,
        request.user_public_key,
        request.signature,
        request.signed_data,
        AdmissionKind::Dns,
        slot,
        events,
    )
    .await;

    match outcome {
        AdmissionOutcome::Allowed { .. } => {
            tracing::info!(hostname = %request.hostname, gateway_id = %request.gateway_id, "DNS resolution admitted");
            Some(DnsAdmissionResponse {
                decision: "admit".to_string(),
                reason: None,
            })
        }
        AdmissionOutcome::Refused(reason) => {
            tracing::info!(hostname = %request.hostname, gateway_id = %request.gateway_id, %reason, "DNS resolution refused");
            Some(DnsAdmissionResponse {
                decision: "refuse".to_string(),
                reason: Some(reason.to_string()),
            })
        }
        AdmissionOutcome::Undecided(reason) => {
            tracing::info!(hostname = %request.hostname, gateway_id = %request.gateway_id, %reason, "DNS resolution not decided - no live-session snapshot held the session in time");
            None
        }
    }
}

/// Real per-flow state (matching a release to the exact admitted flow, not
/// just its port) needs the actual traffic-forwarding slice to exist first -
/// there's nothing to release yet. For now this closes the loop on the
/// acceptance criteria's audit requirement ("Local audit is written... the
/// action completes"). `admission_poller` also removes the flow from
/// `flow_table` itself, right before calling this - this function only
/// handles the audit side, mirroring the pre-TT-2144 handler's own split.
pub(crate) async fn handle_flow_release(audit_log: &AuditLog, request: FlowReleaseRequest) {
    if let Err(error) = audit_log
        .record(AuditEvent::FlowReleased {
            flow_id: request.flow_id,
            gateway_id: request.gateway_id,
        })
        .await
    {
        tracing::error!(%error, "failed to write flow-release audit entry");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{ConnectorHeartbeatResponse, Entitlement, PolicyBundle, PolicyBundleEndpoint};

    fn store_with_entitled_device(
        gateway_id: &str,
        user_id: &str,
        device_public_key: &str,
    ) -> PolicyStore {
        let store = PolicyStore::new();
        store
            .apply(ConnectorHeartbeatResponse {
                connector_id: "c-1".to_string(),
                connector_public_key: None,
                connector_virtual_ip: Some("10.98.0.1".to_string()),
                generated_at: "2026-08-27T10:00:00Z".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                nonce: "n1".to_string(),
                policy_bundles: vec![PolicyBundle {
                    gateway_id: gateway_id.to_string(),
                    location: "Amsterdam".to_string(),
                    hostname: "crm.internal.example.com".to_string(),
                    access_mode: "SELECTED_USERS".to_string(),
                    endpoints: vec![PolicyBundleEndpoint {
                        host: "10.0.0.5".to_string(),
                        port: 443,
                    }],
                    port_rules: None,
                    gateway_address: None,
                    entitlement_list: vec![Entitlement {
                        user_id: user_id.to_string(),
                        device_public_key: Some(device_public_key.to_string()),
                    }],
                }],
                node_list: vec![],
                zero_trust_enabled: None,
                live_sessions: None,
                connection_event_results: None,
            })
            .unwrap();
        store
    }

    /// `message` is the logical content a device would sign (e.g. a session
    /// nonce) - on the wire, `signed_data` carries its base64 *encoding*, not
    /// the raw bytes themselves (TT-2107: confirmed against a real captured
    /// mobile-app request), so this signs `message`'s raw bytes but stores
    /// `signed_data` as that signature's own base64-encoded input, matching
    /// `handle_flow_admission`'s real base64-decode-then-verify contract.
    fn admission_request(
        gateway_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
        public_key_hex: &str,
        message: &str,
    ) -> FlowAdmissionRequest {
        FlowAdmissionRequest {
            flow_id: "flow-1".to_string(),
            gateway_id: gateway_id.to_string(),
            node_id: "n-1".to_string(),
            port: 51820,
            user_public_key: Some(public_key_hex.to_string()),
            signature: Some(crypto::sign_to_base64(signing_key, message.as_bytes())),
            signed_data: Some(BASE64.encode(message)),
            transport: None,
            gateway_address: None,
            destination_port: None,
        }
    }

    fn flow_table() -> Mutex<FlowTable> {
        Mutex::new(FlowTable::new())
    }

    /// Mirrors `admission_request`'s signing convention - see its own doc comment for why
    /// `signed_data` carries `message`'s base64 *encoding*, not its raw bytes.
    fn dns_admission_request(
        gateway_id: &str,
        hostname: &str,
        signing_key: &ed25519_dalek::SigningKey,
        public_key_hex: &str,
        message: &str,
    ) -> DnsAdmissionRequest {
        DnsAdmissionRequest {
            correlation_id: "test-corr-1".to_string(),
            gateway_id: gateway_id.to_string(),
            hostname: hostname.to_string(),
            user_public_key: Some(public_key_hex.to_string()),
            signature: Some(crypto::sign_to_base64(signing_key, message.as_bytes())),
            signed_data: Some(BASE64.encode(message)),
        }
    }

    #[tokio::test]
    async fn admits_an_entitled_devices_dns_request() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = dns_admission_request(
            "gw-1",
            "app.internal",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_dns_admission(&store, &audit_log, request).await;

        assert_eq!(
            response,
            Some(DnsAdmissionResponse {
                decision: "admit".to_string(),
                reason: None,
            })
        );
    }

    #[tokio::test]
    async fn refuses_an_unentitled_devices_dns_request() {
        let device = crypto::generate_keypair();
        let store = PolicyStore::new();
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = dns_admission_request(
            "gw-1",
            "app.internal",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_dns_admission(&store, &audit_log, request).await;

        assert_eq!(
            response,
            Some(DnsAdmissionResponse {
                decision: "refuse".to_string(),
                reason: Some("not_entitled".to_string()),
            })
        );
    }

    #[tokio::test]
    async fn admits_an_entitled_devices_correctly_signed_flow() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(
            response,
            FlowAdmissionResponse {
                flow_id: "flow-1".to_string(),
                decision: "admit".to_string(),
                reason: None,
            }
        );
    }

    /// Real values captured live via `tcpdump` from an actual mobile-app
    /// `/api/user/create` call, then relayed through Gatekeeper as-is
    /// (TT-2107) - confirms this Connector's signature verification is
    /// genuinely interoperable with the real client, not just internally
    /// consistent with its own test fixtures. Signature verification alone is
    /// what's being proven here (the device isn't entitled to any gateway in
    /// this test's `PolicyStore`, so the response is still a refusal - but
    /// specifically `not_entitled`, never `invalid_signature`).
    #[tokio::test]
    async fn verifies_a_real_captured_mobile_app_ecdsa_p256_signature() {
        let store = PolicyStore::new();
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = FlowAdmissionRequest {
            flow_id: "flow-1".to_string(),
            gateway_id: "132f62aa-ac29-49ae-b527-c048530be935".to_string(),
            node_id: "n-1".to_string(),
            port: 51820,
            user_public_key: Some("047fc7980b4735d2efa3492cb4312e0d1cdf4e23174d8bf8ade7e6a964a705211cf283eff432a12fabdb227d4529ef1fb3f0c6828181a54b9d1ad3194c6a9f490d".to_string()),
            signature: Some("MEUCIHrp5diOwIHlLi8EFX4oE51tBN6361tP0BViMlKW0gdYAiEAo27/MSQpQNeodLixoaJ77dHP+mK8WatNXmAs+uwggOA=".to_string()),
            signed_data: Some("eyJkZXZpY2VfaWQiOiI1ODVjYjU0MjYzZWU5YzNmYjM1MjYwZWYxMzM1NGE2NWIzZGNkYjk4IiwicHVibGljX2tleSI6IjA0N2ZjNzk4MGI0NzM1ZDJlZmEzNDkyY2I0MzEyZTBkMWNkZjRlMjMxNzRkOGJmOGFkZTdlNmE5NjRhNzA1MjExY2YyODNlZmY0MzJhMTJmYWJkYjIyN2Q0NTI5ZWYxZmIzZjBjNjgyODE4MWE1NGI5ZDFhZDMxOTRjNmE5ZjQ5MGQiLCJzZXJ2aWNlX3R5cGUiOiJpbnN0YW50IiwicmVnaW9uIjoiYXAtc291dGgtMSIsImlwX2FkZHJlc3MiOiI0NS4xMTMuMTA4LjEyNyIsImlzX2lwX2FkZHJlc3Nfc3RhdGljIjpmYWxzZSwicHJvdG9jb2wiOiJvcGVudnBuIiwic2Vzc2lvbl9pZCI6bnVsbCwicHJvdmlzaW9uX3Rva2VuIjoiX2l3VzlKQVZtNUQtSHYwdFpfMVdwOUIydGs1bzRwZERTbUo4TTA0MFYzUSIsImdhdGV3YXlfaWQiOiIxMzJmNjJhYS1hYzI5LTQ5YWUtYjUyNy1jMDQ4NTMwYmU5MzUifQ==".to_string()),
            transport: None,
            gateway_address: None,
            destination_port: None,
        };

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason, Some("not_entitled".to_string()));
    }

    #[tokio::test]
    async fn an_admitted_flow_is_recorded_in_the_flow_table_for_the_real_forwarding_loops_to_gate_on()
     {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        handle_flow_admission(&store, &audit_log, &table, request).await;

        assert_eq!(
            table.lock().unwrap().gateway_for("n-1", 51820),
            Some("gw-1")
        );
    }

    /// TT-2298: admissions run concurrently with the poll loop, so a short-lived flow's release can
    /// be handled before its own admission finishes. That admission must not record the flow.
    #[tokio::test]
    async fn a_flow_released_before_its_admission_finishes_is_not_admitted() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        table.lock().unwrap().release("flow-1");
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_flow_admission(&store, &audit_log, &table, request).await;

        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason.as_deref(), Some("flow_already_released"));
        assert!(table.lock().unwrap().gateway_for("n-1", 51820).is_none());
    }

    /// Only that flow's own release counts - another flow's release does not block this admission.
    #[tokio::test]
    async fn another_flows_release_does_not_block_an_admission() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        table.lock().unwrap().release("flow-other");
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_flow_admission(&store, &audit_log, &table, request).await;

        assert_eq!(response.decision, "admit");
        assert_eq!(
            table.lock().unwrap().gateway_for("n-1", 51820),
            Some("gw-1")
        );
    }

    #[tokio::test]
    async fn an_admitted_flows_endpoints_flow_through_to_the_flow_table_for_destination_enforcement()
     {
        // TT-2046: `AccessDecision::Allowed`'s endpoints must actually reach
        // `FlowTable`, not just gateway_id/flow_id - otherwise the real
        // forwarding loop has nothing to check a packet's destination
        // against.
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        handle_flow_admission(&store, &audit_log, &table, request).await;

        // store_with_entitled_device's gw-1 bundle configures 10.0.0.5:443.
        let dns_cache = crate::dns_cache::DnsCache::new();
        assert_eq!(
            table
                .lock()
                .unwrap()
                .forward_target("n-1", 51820, 443, &dns_cache),
            crate::flow_table::ForwardOutcome::Forward("10.0.0.5".parse().unwrap())
        );
        assert_eq!(
            table
                .lock()
                .unwrap()
                .forward_target("n-1", 51820, 8080, &dns_cache),
            crate::flow_table::ForwardOutcome::PortNotConfigured
        );
    }

    #[tokio::test]
    async fn a_refused_flow_is_never_recorded_in_the_flow_table() {
        let device = crypto::generate_keypair();
        // Not entitled - the admission decision refuses.
        let store = store_with_entitled_device("gw-1", "u-1", "some-other-device-key");
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        handle_flow_admission(&store, &audit_log, &table, request).await;

        assert!(table.lock().unwrap().gateway_for("n-1", 51820).is_none());
    }

    #[tokio::test]
    async fn releasing_a_flow_removes_it_from_the_flow_table() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );
        handle_flow_admission(&store, &audit_log, &table, request).await;
        assert!(table.lock().unwrap().gateway_for("n-1", 51820).is_some());

        table.lock().unwrap().release("flow-1");

        assert!(table.lock().unwrap().gateway_for("n-1", 51820).is_none());
    }

    #[tokio::test]
    async fn the_same_session_signature_admits_a_second_flow_to_the_same_gateway() {
        // The spec's own model: signed_data is signed once per Gatekeeper
        // session, not per flow - reusing it for a second flow to the SAME
        // gateway within that session is legitimate, not a replay.
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let mut request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let first = handle_flow_admission(&store, &audit_log, &flow_table(), request.clone()).await;
        request.flow_id = "flow-2".to_string();
        let second = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(first.decision, "admit");
        assert_eq!(second.decision, "admit");
    }

    /// Regression test for a live-reproduced bug (2026-09-23): a device entitled to two Private
    /// Gateways behind the same Connector (necessarily the same Location - a Connector process
    /// never serves more than one) got refused switching from one to the other using its still-
    /// valid session signature, and only worked again after a full reconnect. The spec (§B.5/§B.9,
    /// and TT-1732's own acceptance criteria) requires one session to reach every Private Gateway
    /// at that Location without reconnecting - the old cross-gateway `SignatureBindingGuard` (TT-2144
    /// review: removed with this fix) was stricter than that.
    #[tokio::test]
    async fn the_same_session_signature_admits_a_flow_to_a_second_gateway_on_the_same_connector() {
        let device = crypto::generate_keypair();
        // Entitled to BOTH gateways, so this isolates the fix from a coincidental entitlement
        // failure.
        let store = PolicyStore::new();
        store
            .apply(ConnectorHeartbeatResponse {
                connector_id: "c-1".to_string(),
                connector_public_key: None,
                connector_virtual_ip: Some("10.98.0.1".to_string()),
                generated_at: "2026-08-27T10:00:00Z".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                nonce: "n1".to_string(),
                policy_bundles: vec![
                    PolicyBundle {
                        gateway_id: "gw-1".to_string(),
                        location: "Amsterdam".to_string(),
                        hostname: "crm.internal.example.com".to_string(),
                        access_mode: "SELECTED_USERS".to_string(),
                        endpoints: vec![PolicyBundleEndpoint {
                            host: "10.0.0.5".to_string(),
                            port: 443,
                        }],
                        port_rules: None,
                        gateway_address: None,
                        entitlement_list: vec![Entitlement {
                            user_id: "u-1".to_string(),
                            device_public_key: Some(device.public_key_hex.clone()),
                        }],
                    },
                    PolicyBundle {
                        gateway_id: "gw-2".to_string(),
                        location: "Amsterdam".to_string(),
                        hostname: "erp.internal.example.com".to_string(),
                        access_mode: "SELECTED_USERS".to_string(),
                        endpoints: vec![PolicyBundleEndpoint {
                            host: "10.0.0.6".to_string(),
                            port: 443,
                        }],
                        port_rules: None,
                        gateway_address: None,
                        entitlement_list: vec![Entitlement {
                            user_id: "u-1".to_string(),
                            device_public_key: Some(device.public_key_hex.clone()),
                        }],
                    },
                ],
                node_list: vec![],
                zero_trust_enabled: None,
                live_sessions: None,
                connection_event_results: None,
            })
            .unwrap();
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let first_request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );
        let mut second_request = first_request.clone();
        second_request.gateway_id = "gw-2".to_string();
        second_request.flow_id = "flow-2".to_string();

        let first = handle_flow_admission(&store, &audit_log, &flow_table(), first_request).await;
        let second = handle_flow_admission(&store, &audit_log, &flow_table(), second_request).await;

        assert_eq!(first.decision, "admit");
        assert_eq!(second.decision, "admit");
    }

    #[tokio::test]
    async fn refuses_a_flow_whose_signature_triple_is_null_without_panicking_or_erroring() {
        // TT-2145: Gatekeeper legitimately relays a flow with no known device
        // yet (spec §B.9's "relaying without a session signature" case) by
        // sending null for all three fields - this must be a considered
        // refusal, not a request-parsing failure.
        let store = store_with_entitled_device("gw-1", "u-1", "some-device-key");
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let request = FlowAdmissionRequest {
            flow_id: "flow-1".to_string(),
            gateway_id: "gw-1".to_string(),
            node_id: "n-1".to_string(),
            port: 51820,
            user_public_key: None,
            signature: None,
            signed_data: None,
            transport: None,
            gateway_address: None,
            destination_port: None,
        };

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(
            response,
            FlowAdmissionResponse {
                flow_id: "flow-1".to_string(),
                decision: "refuse".to_string(),
                reason: Some("invalid_signature".to_string()),
            }
        );
        let entry: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(dir.path().join("audit.log"))
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(entry["event"], "access_refused");
        assert_eq!(entry["reason"], "no_signature_presented");
        assert_eq!(entry["device_public_key"], "");
    }

    /// The flow's `flow_admitted` entry, written in the background - waits for it briefly.
    async fn flow_admitted_entry(dir: &std::path::Path) -> serde_json::Value {
        for _ in 0..200 {
            if let Some(entry) = std::fs::read_to_string(dir.join("audit.log"))
                .ok()
                .and_then(|log| {
                    log.lines()
                        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                        .find(|entry| entry["event"] == "flow_admitted")
                })
            {
                return entry;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no flow_admitted entry");
    }

    /// TT-2519 (spec §B.10): an admitted flow's local audit entry names the rule that serves it.
    #[tokio::test]
    async fn an_admitted_flow_records_the_port_rule_that_serves_it() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let mut request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );
        request.transport = Some("tcp".to_string());
        request.gateway_address = Some("10.99.0.3".to_string());
        request.destination_port = Some(443);

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(response.decision, "admit");
        let admitted = flow_admitted_entry(dir.path()).await;
        assert_eq!(admitted["flow_id"], "flow-1");
        assert_eq!(admitted["port_rule"], "TCP+UDP 443 -> 10.0.0.5:443");
        assert!(admitted.get("warning").is_none());
    }

    /// TT-2514 review: an admission decided against rules a heartbeat has since changed takes the
    /// rules that heartbeat applied - it is never admitted by a rule the heartbeat removed.
    #[tokio::test]
    async fn an_admission_overlapping_a_heartbeat_takes_the_rules_it_applied() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let table = flow_table();
        // The heartbeat removed port 443 after the store was read (simulated: store still has it).
        table.lock().unwrap().update_rules(
            "gw-1",
            &[PortRule {
                transport: crate::dto::RuleTransport::Tcp,
                external_port: 22,
                internal_host: "10.0.0.5".to_string(),
                internal_port: 22,
            }],
        );
        let mut request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );
        request.transport = Some("tcp".to_string());
        request.gateway_address = Some("10.99.0.3".to_string());
        request.destination_port = Some(443);

        handle_flow_admission(&store, &audit_log, &table, request).await;

        let admitted = flow_admitted_entry(dir.path()).await;
        assert!(admitted.get("port_rule").is_none());
        assert_eq!(
            admitted["warning"],
            "no single port rule serves the flow's transport and port"
        );
    }

    /// Without a single serving rule there is no rule to name, so the entry says why.
    #[tokio::test]
    async fn an_admitted_flow_on_a_port_with_no_rule_records_a_warning() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let mut request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );
        request.transport = Some("tcp".to_string());
        request.gateway_address = Some("10.99.0.3".to_string());
        request.destination_port = Some(8080);

        handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        let admitted = flow_admitted_entry(dir.path()).await;
        assert!(admitted.get("port_rule").is_none());
        assert_eq!(
            admitted["warning"],
            "no single port rule serves the flow's transport and port"
        );
    }

    #[tokio::test]
    async fn refuses_a_flow_with_an_invalid_signature_before_ever_checking_entitlement() {
        let device = crypto::generate_keypair();
        let impostor = crypto::generate_keypair();
        // Store has this device entitled - proves the refusal is really about
        // the signature, not about entitlement.
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        // Signed by a different key than the one presented as user_public_key.
        let mut request = admission_request(
            "gw-1",
            &impostor.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );
        request.user_public_key = Some(device.public_key_hex.clone());

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(
            response,
            FlowAdmissionResponse {
                flow_id: "flow-1".to_string(),
                decision: "refuse".to_string(),
                reason: Some("invalid_signature".to_string()),
            }
        );
        // A bad signature is itself a deny decision - it must be audited too,
        // not just short-circuited silently.
        let entry: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(dir.path().join("audit.log"))
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(entry["event"], "access_refused");
        assert_eq!(entry["reason"], "invalid_signature");
        assert_eq!(entry["device_public_key"], device.public_key_hex);
    }

    #[tokio::test]
    async fn refuses_a_correctly_signed_but_unentitled_device() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", "some-other-device-key");
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(
            response,
            FlowAdmissionResponse {
                flow_id: "flow-1".to_string(),
                decision: "refuse".to_string(),
                reason: Some("not_entitled".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn refuses_an_unknown_gateway_with_the_wire_level_reason() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = admission_request(
            "gw-UNKNOWN",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason, Some("unknown_gateway".to_string()));
    }

    #[tokio::test]
    async fn refuses_when_no_policy_has_ever_been_applied_using_the_not_entitled_wire_value() {
        let device = crypto::generate_keypair();
        let store = PolicyStore::new();
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        // NoPolicyApplied has no dedicated wire value - collapses to
        // not_entitled (see RefusalReason::as_wire_str).
        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason, Some("not_entitled".to_string()));
    }

    // --- TT-2639: the dialled flow identity ---

    fn with_dialled(
        mut request: FlowAdmissionRequest,
        transport: &str,
        gateway_address: &str,
        destination_port: u16,
    ) -> FlowAdmissionRequest {
        request.transport = Some(transport.to_string());
        request.gateway_address = Some(gateway_address.to_string());
        request.destination_port = Some(destination_port);
        request
    }

    fn unsigned_request() -> FlowAdmissionRequest {
        FlowAdmissionRequest {
            flow_id: "flow-1".to_string(),
            gateway_id: "gw-1".to_string(),
            node_id: "n-1".to_string(),
            port: 40100,
            user_public_key: None,
            signature: None,
            signed_data: None,
            transport: None,
            gateway_address: None,
            destination_port: None,
        }
    }

    #[test]
    fn the_dialled_identity_is_read_when_all_three_fields_are_usable() {
        let request = with_dialled(unsigned_request(), "udp", "10.99.0.2", 53);

        assert_eq!(
            request.dialled(),
            Some(Dialled {
                transport: Transport::Udp,
                gateway_address: "10.99.0.2".parse().unwrap(),
                destination_port: 53,
            })
        );
    }

    #[test]
    fn no_dialled_identity_without_all_three_fields_usable() {
        let mut missing_port = with_dialled(unsigned_request(), "tcp", "10.99.0.3", 80);
        missing_port.destination_port = None;

        assert_eq!(unsigned_request().dialled(), None);
        assert_eq!(missing_port.dialled(), None);
        assert_eq!(
            with_dialled(unsigned_request(), "sctp", "10.99.0.3", 80).dialled(),
            None
        );
        assert_eq!(
            with_dialled(unsigned_request(), "tcp", "not-an-address", 80).dialled(),
            None
        );
    }

    /// The TT-2145 lesson: an admission from an older node (no fields), or one with an unusable value,
    /// must still be read, never rejected as a whole before any admission logic runs.
    #[test]
    fn an_admission_without_or_with_unusable_dialled_fields_is_still_read() {
        let older: FlowAdmissionRequest = serde_json::from_str(
            r#"{"flow_id":"f","gateway_id":"g","node_id":"n","port":40100,"user_public_key":null,"signature":null,"signed_data":null}"#,
        )
        .unwrap();
        let unusable: FlowAdmissionRequest = serde_json::from_str(
            r#"{"flow_id":"f","gateway_id":"g","node_id":"n","port":40100,"transport":"tcp","gateway_address":"nonsense","destination_port":80,"user_public_key":null,"signature":null,"signed_data":null}"#,
        )
        .unwrap();

        assert_eq!(older.dialled(), None);
        assert_eq!(unusable.dialled(), None);
    }

    #[tokio::test]
    async fn an_admission_with_its_dialled_identity_is_recorded_under_it() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        let request = with_dialled(
            admission_request(
                "gw-1",
                &device.signing_key,
                &device.public_key_hex,
                "session-nonce-1",
            ),
            "tcp",
            "10.99.0.1",
            443,
        );

        let response = handle_flow_admission(&store, &audit_log, &table, request).await;

        assert_eq!(response.decision, "admit");
        let dialled = Dialled {
            transport: Transport::Tcp,
            gateway_address: "10.99.0.1".parse().unwrap(),
            destination_port: 443,
        };
        let mut table = table.lock().unwrap();
        assert!(matches!(
            table.dialled_forward_target("n-1", 51820, dialled, &crate::dns_cache::DnsCache::new()),
            Some(crate::flow_table::DialledForward::Forward { address, .. }) if address == "10.0.0.5".parse::<std::net::Ipv4Addr>().unwrap()
        ));
        assert!(
            table.gateway_for("n-1", 51820).is_none(),
            "not also recorded by node and port alone"
        );
    }

    #[tokio::test]
    async fn release_records_an_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        handle_flow_release(
            &audit_log,
            FlowReleaseRequest {
                flow_id: "flow-1".to_string(),
                gateway_id: "gw-1".to_string(),
                port: 51820,
            },
        )
        .await;

        let entries: Vec<serde_json::Value> = std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(entries[0]["event"], "flow_released");
        assert_eq!(entries[0]["flow_id"], "flow-1");
    }

    #[tokio::test]
    async fn release_does_not_panic_when_the_audit_write_fails() {
        // Best-effort, same as everywhere else audit writes happen - a bad
        // path must not crash the release handler.
        let audit_log = AuditLog::new("/this/path/does/not/exist/and/cannot/be/created/audit.log");

        handle_flow_release(
            &audit_log,
            FlowReleaseRequest {
                flow_id: "flow-1".to_string(),
                gateway_id: "gw-1".to_string(),
                port: 51820,
            },
        )
        .await;
    }

    // TT-3770 (spec §B.9 point 1): lease-bound admission.

    const TOKEN: &str = "_iwW9JAVm5D-Hv0tZ_1Wp9B2tk5o4pdDSmJ8M040V3Q";

    fn signed_request(token: Option<&str>) -> String {
        match token {
            Some(token) => format!(
                r#"{{"device_id":"d-1","public_key":"k","protocol":"openvpn","provision_token":"{token}","gateway_id":"gw-1"}}"#
            ),
            None => {
                r#"{"device_id":"d-1","public_key":"k","protocol":"openvpn","gateway_id":"gw-1"}"#
                    .to_string()
            }
        }
    }

    fn lease_store(wait: std::time::Duration) -> PolicyStore {
        PolicyStore::with_live_session_settings(crate::live_sessions::LiveSessionSettings {
            flow_wait: wait,
            dns_wait: wait,
            ..Default::default()
        })
    }

    /// Applies a package entitling `device_public_key` on gw-1, with the module on and a snapshot
    /// holding `digests` for that key (or, with `zero_trust_enabled: false`, the module off).
    fn apply_snapshot(
        store: &PolicyStore,
        device_public_key: &str,
        zero_trust_enabled: bool,
        digests: &[String],
    ) {
        store
            .apply(ConnectorHeartbeatResponse {
                connector_id: "c-1".to_string(),
                connector_public_key: None,
                connector_virtual_ip: Some("10.98.0.1".to_string()),
                generated_at: "2026-08-27T10:00:00Z".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                nonce: "n1".to_string(),
                policy_bundles: vec![PolicyBundle {
                    gateway_id: "gw-1".to_string(),
                    location: "Amsterdam".to_string(),
                    hostname: "crm.internal.example.com".to_string(),
                    access_mode: "SELECTED_USERS".to_string(),
                    endpoints: vec![],
                    port_rules: None,
                    gateway_address: None,
                    entitlement_list: vec![Entitlement {
                        user_id: "u-1".to_string(),
                        device_public_key: Some(device_public_key.to_string()),
                    }],
                }],
                node_list: vec![],
                zero_trust_enabled: Some(zero_trust_enabled),
                live_sessions: zero_trust_enabled.then(|| {
                    std::collections::HashMap::from([(
                        device_public_key.to_string(),
                        digests.to_vec(),
                    )])
                }),
                connection_event_results: None,
            })
            .unwrap();
    }

    fn audit_reasons(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|entry| entry["event"] == "access_refused")
            .map(|entry| entry["reason"].as_str().unwrap().to_string())
            .collect()
    }

    async fn refresh_was_requested(store: &PolicyStore) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            store.live_sessions().refresh_requested(),
        )
        .await
        .is_ok()
    }

    #[tokio::test]
    async fn admits_a_flow_whose_session_is_in_the_snapshot_and_remembers_its_session() {
        let device = crypto::generate_keypair();
        let store = lease_store(std::time::Duration::from_millis(300));
        let digest = crate::live_sessions::token_digest(TOKEN);
        apply_snapshot(
            &store,
            &device.public_key_hex,
            true,
            std::slice::from_ref(&digest),
        );
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let table = flow_table();
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );

        let response = handle_flow_admission(&store, &audit_log, &table, request).await;

        assert_eq!(response.decision, "admit");
        assert!(!refresh_was_requested(&store).await);
        let ended = table
            .lock()
            .unwrap()
            .end_flows_without_live_session(|_, session| session != Some(digest.as_str()));
        assert_eq!(
            ended.len(),
            1,
            "the flow must remember its session's digest"
        );
    }

    #[tokio::test]
    async fn an_unknown_session_asks_for_a_snapshot_and_is_admitted_when_it_brings_it() {
        let device = crypto::generate_keypair();
        let store = std::sync::Arc::new(lease_store(std::time::Duration::from_secs(5)));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );
        let key = device.public_key_hex.clone();
        let refresher = {
            let store = store.clone();
            tokio::spawn(async move {
                store.live_sessions().refresh_requested().await;
                store.live_sessions().clear_refresh_request();
                apply_snapshot(
                    &store,
                    &key,
                    true,
                    &[crate::live_sessions::token_digest(TOKEN)],
                );
            })
        };

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        refresher.await.unwrap();
        assert_eq!(response.decision, "admit");
    }

    #[tokio::test]
    async fn a_session_still_unknown_after_a_fresh_snapshot_is_refused_without_another_fetch() {
        let device = crypto::generate_keypair();
        let store = std::sync::Arc::new(lease_store(std::time::Duration::from_secs(5)));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );
        let key = device.public_key_hex.clone();
        let refresher = {
            let store = store.clone();
            tokio::spawn(async move {
                store.live_sessions().refresh_requested().await;
                store.live_sessions().clear_refresh_request();
                apply_snapshot(&store, &key, true, &["another-session".to_string()]);
            })
        };

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        refresher.await.unwrap();
        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason.as_deref(), Some("expired_entitlement"));
        assert!(!refresh_was_requested(&store).await);
        assert_eq!(
            audit_reasons(&dir.path().join("audit.log")),
            vec![crate::live_sessions::REASON_NOT_IN_SNAPSHOT]
        );
    }

    #[tokio::test]
    async fn an_unknown_session_with_no_snapshot_in_time_is_refused() {
        let device = crypto::generate_keypair();
        let store = lease_store(std::time::Duration::from_millis(50));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason.as_deref(), Some("expired_entitlement"));
        assert!(refresh_was_requested(&store).await);
        assert_eq!(
            audit_reasons(&dir.path().join("audit.log")),
            vec![crate::live_sessions::REASON_NO_SNAPSHOT_IN_TIME]
        );
    }

    #[tokio::test]
    async fn signed_data_without_a_session_token_is_refused_outright() {
        let device = crypto::generate_keypair();
        let store = lease_store(std::time::Duration::from_secs(5));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(None),
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason.as_deref(), Some("invalid_signature"));
        assert!(!refresh_was_requested(&store).await);
        assert_eq!(
            audit_reasons(&dir.path().join("audit.log")),
            vec![crate::live_sessions::REASON_NO_TOKEN]
        );
    }

    #[tokio::test]
    async fn the_entitlement_check_comes_first_and_an_unentitled_key_asks_for_nothing() {
        let device = crypto::generate_keypair();
        let stranger = crypto::generate_keypair();
        let store = lease_store(std::time::Duration::from_secs(5));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &stranger.signing_key,
            &stranger.public_key_hex,
            &signed_request(Some(TOKEN)),
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(response.reason.as_deref(), Some("not_entitled"));
        assert!(!refresh_was_requested(&store).await);
    }

    #[tokio::test]
    async fn with_the_module_off_a_flow_is_admitted_on_its_signature_alone() {
        let device = crypto::generate_keypair();
        let store = lease_store(std::time::Duration::from_secs(5));
        apply_snapshot(&store, &device.public_key_hex, false, &[]);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(None),
        );

        let response = handle_flow_admission(&store, &audit_log, &flow_table(), request).await;

        assert_eq!(response.decision, "admit");
    }

    /// Review (TT-3770): a DNS check waits for the snapshot it asked for, up to its wait, and only
    /// then gets no decision - never a refusal for an unknown session.
    #[tokio::test]
    async fn a_dns_check_for_an_unknown_session_asks_for_a_snapshot_and_gets_no_decision_if_none_comes_in_time()
     {
        let device = crypto::generate_keypair();
        let store = lease_store(std::time::Duration::from_millis(100));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let request = dns_admission_request(
            "gw-1",
            "app.internal",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );

        let response = handle_dns_admission(&store, &audit_log, request).await;

        assert_eq!(response, None);
        assert!(refresh_was_requested(&store).await);
        assert!(audit_reasons(&dir.path().join("audit.log")).is_empty());
    }

    /// Review (TT-3770): a device that has just connected resolves its gateway hostname - the DNS
    /// check waits for the snapshot that brings its session instead of leaving the node to answer
    /// SERVFAIL.
    #[tokio::test]
    async fn a_dns_check_for_an_unknown_session_is_admitted_when_the_snapshot_it_asked_for_brings_it()
     {
        let device = crypto::generate_keypair();
        let store = std::sync::Arc::new(lease_store(std::time::Duration::from_secs(5)));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = dns_admission_request(
            "gw-1",
            "app.internal",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );
        let key = device.public_key_hex.clone();
        let refresher = {
            let store = store.clone();
            tokio::spawn(async move {
                store.live_sessions().refresh_requested().await;
                store.live_sessions().clear_refresh_request();
                apply_snapshot(
                    &store,
                    &key,
                    true,
                    &[crate::live_sessions::token_digest(TOKEN)],
                );
            })
        };

        let response = handle_dns_admission(&store, &audit_log, request).await;

        refresher.await.unwrap();
        assert_eq!(
            response.map(|response| response.decision),
            Some("admit".to_string())
        );
    }

    #[tokio::test]
    async fn a_dns_check_for_a_live_session_is_admitted() {
        let device = crypto::generate_keypair();
        let store = lease_store(std::time::Duration::from_secs(5));
        apply_snapshot(
            &store,
            &device.public_key_hex,
            true,
            &[crate::live_sessions::token_digest(TOKEN)],
        );
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = dns_admission_request(
            "gw-1",
            "app.internal",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );

        let response = handle_dns_admission(&store, &audit_log, request).await;

        assert_eq!(
            response.map(|response| response.decision),
            Some("admit".to_string())
        );
    }

    #[tokio::test]
    async fn a_dns_check_against_a_snapshot_too_old_gets_no_decision() {
        let device = crypto::generate_keypair();
        let store =
            PolicyStore::with_live_session_settings(crate::live_sessions::LiveSessionSettings {
                max_age: std::time::Duration::ZERO,
                ..Default::default()
            });
        apply_snapshot(
            &store,
            &device.public_key_hex,
            true,
            &[crate::live_sessions::token_digest(TOKEN)],
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let audit_log = AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
        let request = dns_admission_request(
            "gw-1",
            "app.internal",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );

        let response = handle_dns_admission(&store, &audit_log, request).await;

        assert_eq!(response, None);
    }

    /// Review (TT-3770): a heartbeat already in flight when the admission arrived may bring its
    /// session; the flow is admitted on it instead of waiting out a refresh it cannot get yet.
    #[tokio::test]
    async fn a_flow_is_admitted_on_a_snapshot_requested_just_before_it_arrived() {
        let device = crypto::generate_keypair();
        let store = std::sync::Arc::new(lease_store(std::time::Duration::from_secs(5)));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let in_flight_since = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );
        let admission = {
            let store = store.clone();
            tokio::spawn(async move {
                let audit_log =
                    AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
                handle_flow_admission(&store, &audit_log, &flow_table(), request).await
            })
        };
        store.live_sessions().refresh_requested().await;

        // The reply of the heartbeat requested before the admission arrived holds the session.
        let mut response = apply_response(&device.public_key_hex);
        response.live_sessions = Some(std::collections::HashMap::from([(
            device.public_key_hex.clone(),
            vec![crate::live_sessions::token_digest(TOKEN)],
        )]));
        store.apply_requested_at(response, in_flight_since).unwrap();

        assert_eq!(admission.await.unwrap().decision, "admit");
    }

    /// Review (TT-3770): a flow gives its admission slot back while it waits, and holds one again
    /// once decided.
    #[tokio::test]
    async fn a_waiting_flow_gives_its_admission_slot_back_while_it_waits() {
        let device = crypto::generate_keypair();
        let store = std::sync::Arc::new(lease_store(std::time::Duration::from_millis(300)));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );
        let admission = {
            let store = store.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                let audit_log =
                    AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
                let mut slot = Some(AdmissionSlot::new(semaphore.clone(), permit));
                let response = handle_flow_admission_in_slot(
                    &store,
                    &audit_log,
                    &flow_table(),
                    request,
                    &mut slot,
                    None,
                )
                .await;
                (response, semaphore.available_permits())
            })
        };
        store.live_sessions().refresh_requested().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            semaphore.available_permits(),
            1,
            "the slot is free while the flow waits"
        );

        let (response, available_after) = admission.await.unwrap();
        assert_eq!(response.decision, "refuse");
        assert_eq!(available_after, 0, "the slot is held again once decided");
    }

    /// Review (TT-3770): a DNS check gives its admission slot back while it waits too.
    #[tokio::test]
    async fn a_waiting_dns_check_gives_its_admission_slot_back_while_it_waits() {
        let device = crypto::generate_keypair();
        let store = std::sync::Arc::new(lease_store(std::time::Duration::from_millis(300)));
        apply_snapshot(&store, &device.public_key_hex, true, &[]);
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let request = dns_admission_request(
            "gw-1",
            "app.internal",
            &device.signing_key,
            &device.public_key_hex,
            &signed_request(Some(TOKEN)),
        );
        let admission = {
            let store = store.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                let audit_log =
                    AuditLog::new(tempfile::tempdir().unwrap().path().join("audit.log"));
                let mut slot = Some(AdmissionSlot::new(semaphore.clone(), permit));
                let response =
                    handle_dns_admission_in_slot(&store, &audit_log, request, &mut slot, None)
                        .await;
                (response, semaphore.available_permits())
            })
        };
        store.live_sessions().refresh_requested().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            semaphore.available_permits(),
            1,
            "the slot is free while the DNS check waits"
        );

        let (response, available_after) = admission.await.unwrap();
        assert_eq!(response, None);
        assert_eq!(
            available_after, 1,
            "an undecided DNS check posts nothing, so it does not take a slot back"
        );
    }

    /// The package `apply_snapshot` applies, with the module on and no snapshot.
    fn apply_response(device_public_key: &str) -> ConnectorHeartbeatResponse {
        ConnectorHeartbeatResponse {
            connector_id: "c-1".to_string(),
            connector_public_key: None,
            connector_virtual_ip: Some("10.98.0.1".to_string()),
            generated_at: "2026-08-27T10:00:00Z".to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            nonce: "n1".to_string(),
            policy_bundles: vec![PolicyBundle {
                gateway_id: "gw-1".to_string(),
                location: "Amsterdam".to_string(),
                hostname: "crm.internal.example.com".to_string(),
                access_mode: "SELECTED_USERS".to_string(),
                endpoints: vec![],
                port_rules: None,
                gateway_address: None,
                entitlement_list: vec![Entitlement {
                    user_id: "u-1".to_string(),
                    device_public_key: Some(device_public_key.to_string()),
                }],
            }],
            node_list: vec![],
            zero_trust_enabled: Some(true),
            live_sessions: None,
            connection_event_results: None,
        }
    }
}
