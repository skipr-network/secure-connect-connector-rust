//! Access-decision logic (TT-1732 acceptance criteria: "Entitled user is
//! allowed... Connector forwards traffic to the configured internal
//! endpoint" / "Unentitled user is refused... Connector refuses the flow").
//!
//! This module only makes the allow/refuse decision and, when allowed,
//! names which endpoints traffic may be forwarded to - it does not dial or
//! forward anything itself. `main` calls this via `flow_control`'s handlers
//! once Gatekeeper actually relays a flow-admission request; the endpoints
//! an `Allowed` decision names aren't dialed anywhere yet (that needs real
//! packet forwarding through the tunnel, still out of scope - see
//! `tunnel`'s module doc comment).

use chrono::{DateTime, Utc};

use crate::audit::{AuditEvent, AuditLog};
use crate::dto::PolicyBundleEndpoint;
use crate::policy::PolicyStore;

#[derive(Debug, Clone, PartialEq)]
pub enum AccessDecision {
    Allowed {
        /// From the matched `Entitlement` row, never from a caller-supplied
        /// value - see `decide_access`'s doc comment for why.
        user_id: String,
        endpoints: Vec<PolicyBundleEndpoint>,
    },
    Refused(RefusalReason),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RefusalReason {
    NoPolicyApplied,
    PolicyExpired,
    UnknownGateway,
    NotEntitled,
}

impl RefusalReason {
    fn as_audit_str(self) -> &'static str {
        match self {
            RefusalReason::NoPolicyApplied => "no_policy_applied",
            RefusalReason::PolicyExpired => "policy_expired",
            RefusalReason::UnknownGateway => "unknown_gateway",
            RefusalReason::NotEntitled => "not_entitled",
        }
    }

    /// The wire-level `FlowAdmissionResponse.reason` vocabulary is fixed to
    /// four values by the agreed Connector<->Gatekeeper contract (TT-1732
    /// comment thread, 2026-08-26): "not_entitled" | "invalid_signature" |
    /// "expired_entitlement" | "unknown_gateway" - `invalid_signature` is
    /// produced by the caller (signature verification fails before this type
    /// is even reached), not by a `RefusalReason` variant. `NoPolicyApplied`
    /// has no dedicated wire value; it collapses to `not_entitled` since
    /// there being no policy to check against is, from Gatekeeper's
    /// perspective, indistinguishable from nothing having matched - the more
    /// granular distinction still exists in the local audit log
    /// (`as_audit_str`), which isn't bound by this external contract.
    pub(crate) fn as_wire_str(self) -> &'static str {
        match self {
            RefusalReason::NoPolicyApplied | RefusalReason::NotEntitled => "not_entitled",
            RefusalReason::PolicyExpired => "expired_entitlement",
            RefusalReason::UnknownGateway => "unknown_gateway",
        }
    }
}

/// Takes `device_public_key` only, never a `user_id` parameter - per the
/// agreed Connector<->Gatekeeper contract (TT-1732 comment thread,
/// 2026-08-26), the flow-admission message a caller presents carries a
/// `user_public_key` proven by signature, never a `user_id`. Trusting a
/// caller-asserted `user_id` here would let anyone claim to be anyone; the
/// `user_id` returned in `Allowed` comes only from the matching
/// `Entitlement` row, i.e. from our own data, never from the caller.
pub fn decide_access(
    store: &PolicyStore,
    gateway_id: &str,
    device_public_key: &str,
) -> AccessDecision {
    decide_access_at(store, gateway_id, device_public_key, Utc::now())
}

/// Pairs `decide_access` with TT-1820's audit trail - the acceptance
/// criteria requires an audit entry for every allow/deny decision, not just
/// the decision itself. Called by `flow_control`'s admission handler.
pub async fn decide_access_and_audit(
    store: &PolicyStore,
    audit_log: &AuditLog,
    gateway_id: &str,
    device_public_key: &str,
) -> AccessDecision {
    let decision = decide_access(store, gateway_id, device_public_key);

    let event = match &decision {
        AccessDecision::Allowed { user_id, .. } => AuditEvent::AccessAllowed {
            gateway_id: gateway_id.to_string(),
            user_id: user_id.clone(),
            device_public_key: device_public_key.to_string(),
        },
        AccessDecision::Refused(reason) => AuditEvent::AccessRefused {
            gateway_id: gateway_id.to_string(),
            device_public_key: device_public_key.to_string(),
            reason: reason.as_audit_str().to_string(),
        },
    };
    // Best-effort: an audit-write failure must not itself block or flip an
    // access decision that's already been made.
    if let Err(error) = audit_log.record(event).await {
        tracing::error!(%error, "failed to write access-decision audit entry");
    }

    decision
}

fn decide_access_at(
    store: &PolicyStore,
    gateway_id: &str,
    device_public_key: &str,
    now: DateTime<Utc>,
) -> AccessDecision {
    let Some(state) = store.current() else {
        return AccessDecision::Refused(RefusalReason::NoPolicyApplied);
    };

    // PolicyStore::apply already validated expires_at as a parseable RFC3339
    // timestamp before ever storing it - this can't fail on genuinely stored
    // state. Re-checked here (not just at apply time) because a policy valid
    // when applied can go stale while it's still the "current" state, e.g. if
    // Agent stops heartbeating and no fresher package ever replaces it.
    let expires_at = DateTime::parse_from_rfc3339(&state.expires_at)
        .expect("PolicyStore only ever stores an already-validated expires_at");
    if now >= expires_at {
        return AccessDecision::Refused(RefusalReason::PolicyExpired);
    }

    let Some(bundle) = state
        .policy_bundles
        .iter()
        .find(|bundle| bundle.gateway_id == gateway_id)
    else {
        return AccessDecision::Refused(RefusalReason::UnknownGateway);
    };

    let matched = bundle
        .entitlement_list
        .iter()
        .find(|entitlement| entitlement.device_public_key == device_public_key);

    match matched {
        Some(entitlement) => AccessDecision::Allowed {
            user_id: entitlement.user_id.clone(),
            endpoints: bundle.endpoints.clone(),
        },
        None => AccessDecision::Refused(RefusalReason::NotEntitled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{ConnectorHeartbeatResponse, Entitlement, PolicyBundle};
    use chrono::Duration;

    fn bundle(gateway_id: &str, entitlements: Vec<Entitlement>) -> PolicyBundle {
        PolicyBundle {
            gateway_id: gateway_id.to_string(),
            location: "Amsterdam".to_string(),
            hostname: "crm.internal.example.com".to_string(),
            access_mode: "SELECTED_USERS".to_string(),
            endpoints: vec![PolicyBundleEndpoint {
                host: "10.0.0.5".to_string(),
                port: 443,
            }],
            entitlement_list: entitlements,
        }
    }

    fn response(expires_at: &str, bundles: Vec<PolicyBundle>) -> ConnectorHeartbeatResponse {
        ConnectorHeartbeatResponse {
            connector_id: "c-1".to_string(),
            connector_virtual_ip: Some("10.98.0.1".to_string()),
            generated_at: "2026-08-27T10:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            nonce: "n1".to_string(),
            policy_bundles: bundles,
            node_list: vec![],
        }
    }

    #[test]
    fn refuses_when_no_policy_has_ever_been_applied() {
        let store = PolicyStore::new();

        let decision = decide_access_at(&store, "gw-1", "device-key-1", Utc::now());

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NoPolicyApplied)
        );
    }

    #[test]
    fn allows_an_entitled_device_and_returns_its_user_id_and_the_gateways_endpoints() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        let entitled = Entitlement {
            user_id: "u-1".to_string(),
            device_public_key: "device-key-1".to_string(),
        };
        store
            .apply_at(
                response(
                    &(now + Duration::minutes(5)).to_rfc3339(),
                    vec![bundle("gw-1", vec![entitled])],
                ),
                now,
            )
            .unwrap();

        let decision = decide_access_at(&store, "gw-1", "device-key-1", now);

        assert_eq!(
            decision,
            AccessDecision::Allowed {
                user_id: "u-1".to_string(),
                endpoints: vec![PolicyBundleEndpoint {
                    host: "10.0.0.5".to_string(),
                    port: 443
                }]
            }
        );
    }

    #[test]
    fn refuses_a_device_that_is_not_in_the_entitlement_list() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        let entitled = Entitlement {
            user_id: "u-1".to_string(),
            device_public_key: "device-key-1".to_string(),
        };
        store
            .apply_at(
                response(
                    &(now + Duration::minutes(5)).to_rfc3339(),
                    vec![bundle("gw-1", vec![entitled])],
                ),
                now,
            )
            .unwrap();

        // A different device than the one actually entitled - there is no
        // caller-asserted user_id to even compare against anymore; only the
        // presented device key matters.
        let decision = decide_access_at(&store, "gw-1", "device-key-EVIL", now);

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NotEntitled)
        );
    }

    #[test]
    fn refuses_a_device_when_the_entitlement_list_is_empty() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        store
            .apply_at(
                response(
                    &(now + Duration::minutes(5)).to_rfc3339(),
                    vec![bundle("gw-1", vec![])],
                ),
                now,
            )
            .unwrap();

        let decision = decide_access_at(&store, "gw-1", "device-key-ghost", now);

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NotEntitled)
        );
    }

    #[test]
    fn refuses_for_a_gateway_id_not_in_the_applied_policy() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        let entitled = Entitlement {
            user_id: "u-1".to_string(),
            device_public_key: "device-key-1".to_string(),
        };
        store
            .apply_at(
                response(
                    &(now + Duration::minutes(5)).to_rfc3339(),
                    vec![bundle("gw-1", vec![entitled])],
                ),
                now,
            )
            .unwrap();

        let decision = decide_access_at(&store, "gw-UNKNOWN", "device-key-1", now);

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::UnknownGateway)
        );
    }

    #[test]
    fn refuses_once_the_applied_policy_has_gone_stale_even_though_its_still_current() {
        let store = PolicyStore::new();
        let applied_at = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        let entitled = Entitlement {
            user_id: "u-1".to_string(),
            device_public_key: "device-key-1".to_string(),
        };
        // Valid for 5 minutes when applied.
        store
            .apply_at(
                response(
                    &(applied_at + Duration::minutes(5)).to_rfc3339(),
                    vec![bundle("gw-1", vec![entitled])],
                ),
                applied_at,
            )
            .unwrap();

        // Nothing ever refreshed it, and real time has since moved past that
        // 5-minute window - still "current" in the store, but stale.
        let decision_time = applied_at + Duration::minutes(10);
        let decision = decide_access_at(&store, "gw-1", "device-key-1", decision_time);

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::PolicyExpired)
        );
    }

    #[test]
    fn a_decision_exactly_at_the_expiry_instant_is_treated_as_expired() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        let expiry = now + Duration::minutes(5);
        let entitled = Entitlement {
            user_id: "u-1".to_string(),
            device_public_key: "device-key-1".to_string(),
        };
        store
            .apply_at(
                response(&expiry.to_rfc3339(), vec![bundle("gw-1", vec![entitled])]),
                now,
            )
            .unwrap();

        let decision = decide_access_at(&store, "gw-1", "device-key-1", expiry);

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::PolicyExpired)
        );
    }

    #[tokio::test]
    async fn decide_access_and_audit_records_an_allowed_decision_with_the_resolved_user_id() {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let store = PolicyStore::new();
        let entitled = Entitlement {
            user_id: "u-1".to_string(),
            device_public_key: "device-key-1".to_string(),
        };
        // decide_access_and_audit calls decide_access, which checks against the
        // real Utc::now() (not an injectable one) - the applied package must
        // stay valid regardless of when this test actually runs.
        store
            .apply(response(
                "2099-01-01T00:00:00Z",
                vec![bundle("gw-1", vec![entitled])],
            ))
            .unwrap();

        let decision = decide_access_and_audit(&store, &audit_log, "gw-1", "device-key-1").await;

        assert_eq!(
            decision,
            AccessDecision::Allowed {
                user_id: "u-1".to_string(),
                endpoints: vec![PolicyBundleEndpoint {
                    host: "10.0.0.5".to_string(),
                    port: 443
                }]
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
        assert_eq!(entry["event"], "access_allowed");
        assert_eq!(entry["gateway_id"], "gw-1");
        assert_eq!(entry["user_id"], "u-1");
        assert_eq!(entry["device_public_key"], "device-key-1");
    }

    #[tokio::test]
    async fn decide_access_and_audit_records_not_entitled_and_unknown_gateway_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let store = PolicyStore::new();
        let entitled = Entitlement {
            user_id: "u-1".to_string(),
            device_public_key: "device-key-1".to_string(),
        };
        store
            .apply(response(
                "2099-01-01T00:00:00Z",
                vec![bundle("gw-1", vec![entitled])],
            ))
            .unwrap();

        let not_entitled =
            decide_access_and_audit(&store, &audit_log, "gw-1", "device-key-ghost").await;
        let unknown_gateway =
            decide_access_and_audit(&store, &audit_log, "gw-UNKNOWN", "device-key-1").await;

        assert_eq!(
            not_entitled,
            AccessDecision::Refused(RefusalReason::NotEntitled)
        );
        assert_eq!(
            unknown_gateway,
            AccessDecision::Refused(RefusalReason::UnknownGateway)
        );
        let entries: Vec<serde_json::Value> = std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(entries[0]["reason"], "not_entitled");
        assert_eq!(entries[1]["reason"], "unknown_gateway");
    }

    #[tokio::test]
    async fn decide_access_and_audit_still_returns_the_decision_when_the_audit_write_fails() {
        // Audit logging is best-effort (see the comment on decide_access_and_audit) -
        // a write failure must not swallow or change the actual access decision.
        let audit_log = AuditLog::new("/this/path/does/not/exist/and/cannot/be/created/audit.log");
        let store = PolicyStore::new();

        let decision =
            decide_access_and_audit(&store, &audit_log, "gw-1", "device-key-ghost").await;

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NoPolicyApplied)
        );
    }

    #[tokio::test]
    async fn decide_access_and_audit_records_a_refused_decision_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let store = PolicyStore::new();

        let decision =
            decide_access_and_audit(&store, &audit_log, "gw-1", "device-key-ghost").await;

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NoPolicyApplied)
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
        assert_eq!(entry["reason"], "no_policy_applied");
        assert_eq!(entry["device_public_key"], "device-key-ghost");
    }

    #[test]
    fn decide_access_uses_the_real_clock() {
        // Smoke test for the pub wrapper that isn't unit-testable at a fixed
        // instant: no policy has ever been applied, so the real current time
        // doesn't matter - it must still refuse.
        let store = PolicyStore::new();

        let decision = decide_access(&store, "gw-1", "device-key-1");

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NoPolicyApplied)
        );
    }
}
