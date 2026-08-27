//! Access-decision logic (TT-1732 acceptance criteria: "Entitled user is
//! allowed... Connector forwards traffic to the configured internal
//! endpoint" / "Unentitled user is refused... Connector refuses the flow").
//!
//! This module only makes the allow/refuse decision and, when allowed,
//! names which endpoints traffic may be forwarded to - it does not dial or
//! forward anything itself. That needs the node-tunnel slice (not yet
//! built), so `decide_access` has no caller in `main` yet either.

use chrono::{DateTime, Utc};

use crate::dto::PolicyBundleEndpoint;
use crate::policy::PolicyStore;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum AccessDecision {
    Allowed {
        endpoints: Vec<PolicyBundleEndpoint>,
    },
    Refused(RefusalReason),
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum RefusalReason {
    NoPolicyApplied,
    PolicyExpired,
    UnknownGateway,
    NotEntitled,
}

/// Matches on both `user_id` and `device_public_key` - an `Entitlement` row
/// authorizes a specific user's specific device, not the user account in
/// general, so a user's device that isn't itself listed must be refused
/// even if that same user has a different, entitled device.
#[allow(dead_code)]
pub fn decide_access(
    store: &PolicyStore,
    gateway_id: &str,
    user_id: &str,
    device_public_key: &str,
) -> AccessDecision {
    decide_access_at(store, gateway_id, user_id, device_public_key, Utc::now())
}

fn decide_access_at(
    store: &PolicyStore,
    gateway_id: &str,
    user_id: &str,
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

    let is_entitled = bundle.entitlement_list.iter().any(|entitlement| {
        entitlement.user_id == user_id && entitlement.device_public_key == device_public_key
    });

    if is_entitled {
        AccessDecision::Allowed {
            endpoints: bundle.endpoints.clone(),
        }
    } else {
        AccessDecision::Refused(RefusalReason::NotEntitled)
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

        let decision = decide_access_at(&store, "gw-1", "u-1", "device-key-1", Utc::now());

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NoPolicyApplied)
        );
    }

    #[test]
    fn allows_an_entitled_user_and_returns_the_gateways_endpoints() {
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

        let decision = decide_access_at(&store, "gw-1", "u-1", "device-key-1", now);

        assert_eq!(
            decision,
            AccessDecision::Allowed {
                endpoints: vec![PolicyBundleEndpoint {
                    host: "10.0.0.5".to_string(),
                    port: 443
                }]
            }
        );
    }

    #[test]
    fn refuses_a_user_whose_device_is_not_the_entitled_one() {
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

        // Same user_id, but a different device than the one actually entitled.
        let decision = decide_access_at(&store, "gw-1", "u-1", "device-key-EVIL", now);

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NotEntitled)
        );
    }

    #[test]
    fn refuses_a_user_missing_from_the_entitlement_list_entirely() {
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

        let decision = decide_access_at(&store, "gw-1", "u-ghost", "device-key-1", now);

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

        let decision = decide_access_at(&store, "gw-UNKNOWN", "u-1", "device-key-1", now);

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
        let decision = decide_access_at(&store, "gw-1", "u-1", "device-key-1", decision_time);

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

        let decision = decide_access_at(&store, "gw-1", "u-1", "device-key-1", expiry);

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::PolicyExpired)
        );
    }

    #[test]
    fn decide_access_uses_the_real_clock() {
        // Smoke test for the pub wrapper that isn't unit-testable at a fixed
        // instant: no policy has ever been applied, so the real current time
        // doesn't matter - it must still refuse.
        let store = PolicyStore::new();

        let decision = decide_access(&store, "gw-1", "u-1", "device-key-1");

        assert_eq!(
            decision,
            AccessDecision::Refused(RefusalReason::NoPolicyApplied)
        );
    }
}
