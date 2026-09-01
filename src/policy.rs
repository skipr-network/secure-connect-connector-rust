//! Holds the Connector's local policy state - the last verified, non-expired
//! heartbeat package (TT-1732 acceptance criteria: "Connector applies gateway
//! data... stores policies, entitlement lists, and node list for all attached
//! gateways").
//!
//! A package can be *cryptographically valid* (signature checked in
//! `heartbeat::fetch_and_verify`) and still be rejected here for being expired -
//! the acceptance criteria treats "invalid signature" and "expired payload" as
//! the same class of rejection: don't apply it, don't touch existing state.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use std::sync::RwLock;

use crate::dto::{ConnectorHeartbeatResponse, HeartbeatNode, PolicyBundle};

#[derive(Debug, Clone)]
pub struct PolicyState {
    /// Not read anywhere in production yet - `access::decide_access_at` only
    /// needs `expires_at`/`policy_bundles`. Read in tests to confirm apply
    /// behavior; genuinely useful once diagnostics/audit context needs it.
    #[allow(dead_code)]
    pub connector_id: String,
    #[allow(dead_code)]
    pub generated_at: String,
    pub expires_at: String,
    pub policy_bundles: Vec<PolicyBundle>,
    /// Not read in production yet - the node-tunnel slice (`tunnel.rs`)
    /// reads `node_list` straight off the heartbeat response in `main`
    /// (before it's stored here), not back out of `PolicyState`.
    #[allow(dead_code)]
    pub node_list: Vec<HeartbeatNode>,
}

pub struct PolicyStore {
    state: RwLock<Option<PolicyState>>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(None),
        }
    }

    /// Applies a verified heartbeat response as the new local policy state,
    /// unless it's already expired - an expired package leaves whatever state
    /// was already stored completely untouched, same as a signature failure.
    pub fn apply(&self, response: ConnectorHeartbeatResponse) -> Result<()> {
        self.apply_at(response, Utc::now())
    }

    /// `pub(crate)` (not just test-private) so other in-crate modules' tests -
    /// e.g. `access`'s - can set up precisely timed scenarios through the
    /// real validated-apply path instead of hand-building a `PolicyState`.
    pub(crate) fn apply_at(
        &self,
        response: ConnectorHeartbeatResponse,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let expires_at = DateTime::parse_from_rfc3339(&response.expires_at).with_context(|| {
            format!(
                "heartbeat package has an unparseable expires_at: {}",
                response.expires_at
            )
        })?;

        if now >= expires_at {
            bail!(
                "heartbeat package expired at {} (now {now}) - rejecting, not updating local policy state",
                response.expires_at
            );
        }

        let mut guard = self.state.write().expect("policy store lock poisoned");
        *guard = Some(PolicyState {
            connector_id: response.connector_id,
            generated_at: response.generated_at,
            expires_at: response.expires_at,
            policy_bundles: response.policy_bundles,
            node_list: response.node_list,
        });
        Ok(())
    }

    /// A snapshot of the currently applied policy state, or `None` if no
    /// verified, non-expired package has ever been successfully applied.
    /// Called by `access::decide_access_at` on every flow-admission check.
    pub fn current(&self) -> Option<PolicyState> {
        self.state
            .read()
            .expect("policy store lock poisoned")
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn response(expires_at: &str) -> ConnectorHeartbeatResponse {
        ConnectorHeartbeatResponse {
            connector_id: "c-1".to_string(),
            connector_virtual_ip: Some("10.98.0.1".to_string()),
            generated_at: "2026-08-27T10:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            nonce: "n1".to_string(),
            policy_bundles: vec![],
            node_list: vec![],
        }
    }

    #[test]
    fn current_is_none_before_anything_is_applied() {
        let store = PolicyStore::new();
        assert!(store.current().is_none());
    }

    #[test]
    fn applies_a_not_yet_expired_package() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        let expires_at = (now + Duration::minutes(5)).to_rfc3339();

        store.apply_at(response(&expires_at), now).unwrap();

        let state = store.current().unwrap();
        assert_eq!(state.connector_id, "c-1");
    }

    #[test]
    fn rejects_a_package_that_is_already_expired_and_does_not_touch_prior_state() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();

        // First, apply a genuinely valid package so there's real prior state to protect.
        let still_valid_expiry = (now + Duration::minutes(5)).to_rfc3339();
        store.apply_at(response(&still_valid_expiry), now).unwrap();
        let prior_state = store.current().unwrap();

        // Then attempt to apply an already-expired one.
        let already_expired = (now - Duration::minutes(1)).to_rfc3339();
        let mut expired_response = response(&already_expired);
        expired_response.connector_id = "c-EVIL-OR-STALE".to_string();
        let result = store.apply_at(expired_response, now);

        assert!(result.is_err());
        let state_after = store.current().unwrap();
        assert_eq!(state_after.connector_id, prior_state.connector_id);
        assert_eq!(state_after.expires_at, prior_state.expires_at);
    }

    #[test]
    fn a_package_expiring_at_exactly_now_is_treated_as_expired() {
        // Boundary: expires_at == now is not "still valid for an instant", it's
        // already expired - fail closed on the exact boundary.
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();

        let result = store.apply_at(response(&now.to_rfc3339()), now);

        assert!(result.is_err());
        assert!(store.current().is_none());
    }

    #[test]
    fn rejects_a_package_with_an_unparseable_expiry() {
        let store = PolicyStore::new();
        let now = Utc::now();

        let result = store.apply_at(response("not-a-timestamp"), now);

        assert!(result.is_err());
        assert!(store.current().is_none());
    }

    #[test]
    fn a_later_apply_replaces_rather_than_merges_with_prior_state() {
        let store = PolicyStore::new();
        let now = DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .unwrap()
            .to_utc();
        let expiry = (now + Duration::minutes(5)).to_rfc3339();

        let mut first = response(&expiry);
        first.node_list = vec![HeartbeatNode {
            node_id: "n-1".to_string(),
            ip_address: "10.0.0.10".to_string(),
            wireguard_public_key: None,
        }];
        store.apply_at(first, now).unwrap();

        let second = response(&expiry);
        store.apply_at(second, now).unwrap();

        let state = store.current().unwrap();
        assert!(
            state.node_list.is_empty(),
            "second apply should fully replace the first, not merge node lists"
        );
    }
}
