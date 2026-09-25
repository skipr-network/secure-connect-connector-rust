//! Wire types for the Connector <-> Agent heartbeat contract (TT-1363/TT-1707,
//! spec §B.4/§B.9). Field names are part of the contract on both hops - Portal's
//! own DTOs use the same snake_case names and Agent relays them unchanged, so these
//! mirror `ConnectorHeartbeatResponseDTO` and friends in secure-connect-backend-agent
//! field-for-field, deserialized from the exact raw bytes the signature was computed
//! over (see `heartbeat::fetch_and_verify`).

use serde::{Deserialize, Serialize};

/// The heartbeat request body (TT-2069) - previously an empty `POST`, now carrying this
/// Connector's own identity and observed state back to Agent/Portal. Unsigned, same as the rest of
/// this request: the endpoint has never had per-request authentication (see `heartbeat`'s module
/// doc), so this adds no new trust boundary - worst case a spoofed request causes a spurious
/// "unresolved" badge in Portal's UI for a gateway, not an access-control issue.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct ConnectorHeartbeatRequest {
    /// This Connector's own public key (TT-2210) - how Agent and Portal find it. It is the only
    /// identity the Connector has before an admin registers it, and the only one it ever needs:
    /// Agent answers "not registered" until the admin pastes this key into Portal, and the very
    /// next heartbeat after that is served, with nothing reconfigured on this host.
    pub connector_public_key: String,
    /// Endpoint hosts, from the *previous* heartbeat's policy bundles, that `dns_cache` still had
    /// no resolved address for as of the last successful `dns_cache.refresh` (not necessarily last
    /// cycle: a heartbeat that fails before reaching `dns_cache.refresh` leaves this reporting a
    /// cache that's a cycle or more stale - harmless, since the next successful cycle catches up,
    /// but the field is never a live "as of right now" read). Never a literal IPv4 (those always
    /// resolve, see `DnsCache::resolve`), only ever a hostname DNS hasn't answered for - and not
    /// necessarily the moment DNS starts failing either: `dns_cache` deliberately keeps trusting a
    /// hostname's last-known address for up to `MAX_CONSECUTIVE_FAILURES` refresh cycles before
    /// evicting it, so a host only shows up here once that fail-soft window has been exhausted.
    ///
    /// `None` - not `Some(vec![])` - on the very first heartbeat after any process start (fresh
    /// boot, upgrade, or crash-loop restart): there is no previous cycle's bundles to have
    /// refreshed `dns_cache` against yet, so this Connector genuinely has no information to report,
    /// as distinct from a confirmed "nothing is unresolved". Portal (via Agent) must treat the two
    /// differently - `None` means "leave existing marks alone", `Some(vec![])` means "clear every
    /// mark, everything resolves". Collapsing them into the same "clear everything" signal would
    /// wipe a real, still-true unresolved-host warning off Portal's UI on every restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unresolved_endpoint_hosts: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConnectorHeartbeatResponse {
    pub connector_id: String,
    /// TT-2210: the public key Agent composed this envelope for, inside the signed body -
    /// `heartbeat::fetch_and_verify` refuses a verified envelope carrying any key but this
    /// Connector's own, since this Connector no longer knows its `connector_id` to check against.
    #[serde(default)]
    pub connector_public_key: Option<String>,
    /// TT-1838: this Connector's one stable control-channel address, assigned by Portal and
    /// relayed unchanged through Agent. `None` until Portal has assigned one (or against an
    /// older Agent that doesn't send it yet) - `main` treats that as "not ready", since the TUN
    /// device can't be created without a real address to bind.
    pub connector_virtual_ip: Option<String>,
    pub generated_at: String,
    pub expires_at: String,
    pub nonce: String,
    pub policy_bundles: Vec<PolicyBundle>,
    pub node_list: Vec<HeartbeatNode>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PolicyBundle {
    pub gateway_id: String,
    pub location: String,
    pub hostname: String,
    pub access_mode: String,
    pub endpoints: Vec<PolicyBundleEndpoint>,
    pub entitlement_list: Vec<Entitlement>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PolicyBundleEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Entitlement {
    pub user_id: String,
    /// `None` when this user is entitled but hasn't paired any device yet (a normal,
    /// expected state Portal can produce - access can be granted by role before a device
    /// ever registers) - never treat a missing key as an empty string, and never match it
    /// against a real connecting device's key (see `access::decide_access_at`).
    pub device_public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HeartbeatNode {
    pub node_id: String,
    pub ip_address: String,
    /// `null` until the node's key has been reported to Registry (TT-1745/TT-1761) -
    /// the Connector cannot dial a node it doesn't have this for yet.
    pub wireguard_public_key: Option<String>,
}

/// Registry's `GET /api/agents/{ipAddress}/permitted-key` response (TT-1742).
#[derive(Debug, Deserialize)]
pub struct AgentPermittedKeyResponse {
    pub permitted_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_request_serializes_its_unresolved_hosts() {
        let request = ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            unresolved_endpoint_hosts: Some(vec!["crm.internal.example.com".to_string()]),
        };

        let json = serde_json::to_string(&request).unwrap();

        assert_eq!(
            json,
            r#"{"connector_public_key":"pk-1","unresolved_endpoint_hosts":["crm.internal.example.com"]}"#
        );
    }

    #[test]
    fn heartbeat_request_serializes_a_confirmed_empty_list_as_an_explicit_empty_array() {
        // Some(vec![]) - "refreshed, nothing unresolved" - must stay a real `[]` on the wire, not
        // get skipped the way `None` is: Portal treats an explicit `[]` as "clear every mark" and
        // an absent field as "no information, leave marks alone" (TT-2069 review finding #1).
        let request = ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            unresolved_endpoint_hosts: Some(vec![]),
        };

        let json = serde_json::to_string(&request).unwrap();

        assert_eq!(
            json,
            r#"{"connector_public_key":"pk-1","unresolved_endpoint_hosts":[]}"#
        );
    }

    #[test]
    fn heartbeat_request_omits_the_field_entirely_when_there_is_no_previous_cycle_to_report() {
        let request = ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            unresolved_endpoint_hosts: None,
        };

        let json = serde_json::to_string(&request).unwrap();

        assert_eq!(json, r#"{"connector_public_key":"pk-1"}"#);
    }

    #[test]
    fn heartbeat_request_default_has_no_unresolved_hosts() {
        assert_eq!(
            ConnectorHeartbeatRequest::default(),
            ConnectorHeartbeatRequest {
                connector_public_key: String::new(),
                unresolved_endpoint_hosts: None
            }
        );
    }

    #[test]
    fn deserializes_a_realistic_heartbeat_response() {
        let json = r#"{
            "connector_id": "c-1",
            "generated_at": "2026-08-27T10:00:00Z",
            "expires_at": "2026-08-27T10:05:00Z",
            "nonce": "abc123",
            "policy_bundles": [{
                "gateway_id": "gw-1",
                "location": "Amsterdam",
                "hostname": "crm.internal.example.com",
                "access_mode": "SELECTED_USERS",
                "endpoints": [{"host": "10.0.0.5", "port": 443}],
                "entitlement_list": [{"user_id": "u-1", "device_public_key": "abcd"}]
            }],
            "node_list": [{"node_id": "n-1", "ip_address": "10.0.0.10", "wireguard_public_key": "wgkey="}]
        }"#;

        let response: ConnectorHeartbeatResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.connector_id, "c-1");
        assert_eq!(response.policy_bundles.len(), 1);
        assert_eq!(response.policy_bundles[0].endpoints[0].port, 443);
        assert_eq!(
            response.node_list[0].wireguard_public_key.as_deref(),
            Some("wgkey=")
        );
    }

    /// Regression test: an entitled user with no paired device yet is a real, expected state
    /// Portal can send (access granted by role before a device ever registers) - a `null`
    /// `device_public_key` here previously failed the *entire* heartbeat response's
    /// deserialization (not just that one entitlement), silently breaking every subsequent
    /// heartbeat cycle for the whole Connector until the offending entitlement was removed.
    #[test]
    fn deserializes_an_entitlement_with_no_device_public_key_yet() {
        let json = r#"{
            "connector_id": "c-1",
            "generated_at": "2026-08-27T10:00:00Z",
            "expires_at": "2026-08-27T10:05:00Z",
            "nonce": "abc123",
            "policy_bundles": [{
                "gateway_id": "gw-1",
                "location": "Amsterdam",
                "hostname": "crm.internal.example.com",
                "access_mode": "SELECTED_USERS",
                "endpoints": [],
                "entitlement_list": [
                    {"user_id": "u-1", "device_public_key": null},
                    {"user_id": "u-2", "device_public_key": "abcd"}
                ]
            }],
            "node_list": []
        }"#;

        let response: ConnectorHeartbeatResponse = serde_json::from_str(json).unwrap();

        let entitlements = &response.policy_bundles[0].entitlement_list;
        assert_eq!(entitlements[0].device_public_key, None);
        assert_eq!(entitlements[1].device_public_key.as_deref(), Some("abcd"));
    }

    #[test]
    fn connector_virtual_ip_is_populated_when_present() {
        let json = r#"{
            "connector_id": "c-1",
            "connector_virtual_ip": "10.98.0.7",
            "generated_at": "2026-08-27T10:00:00Z",
            "expires_at": "2026-08-27T10:05:00Z",
            "nonce": "abc123",
            "policy_bundles": [],
            "node_list": []
        }"#;

        let response: ConnectorHeartbeatResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.connector_virtual_ip.as_deref(), Some("10.98.0.7"));
    }

    #[test]
    fn connector_virtual_ip_defaults_to_none_when_absent() {
        let json = r#"{
            "connector_id": "c-1",
            "generated_at": "2026-08-27T10:00:00Z",
            "expires_at": "2026-08-27T10:05:00Z",
            "nonce": "abc123",
            "policy_bundles": [],
            "node_list": []
        }"#;

        let response: ConnectorHeartbeatResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.connector_virtual_ip, None);
    }

    #[test]
    fn node_list_wireguard_public_key_is_optional() {
        let json = r#"{
            "connector_id": "c-1",
            "generated_at": "2026-08-27T10:00:00Z",
            "expires_at": "2026-08-27T10:05:00Z",
            "nonce": "abc123",
            "policy_bundles": [],
            "node_list": [{"node_id": "n-1", "ip_address": "10.0.0.10", "wireguard_public_key": null}]
        }"#;

        let response: ConnectorHeartbeatResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.node_list[0].wireguard_public_key, None);
    }
}
