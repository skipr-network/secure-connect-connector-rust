//! Wire types for the Connector <-> Agent heartbeat contract (TT-1363/TT-1707,
//! spec §B.4/§B.9). Field names are part of the contract on both hops - Portal's
//! own DTOs use the same snake_case names and Agent relays them unchanged, so these
//! mirror `ConnectorHeartbeatResponseDTO` and friends in secure-connect-backend-agent
//! field-for-field, deserialized from the exact raw bytes the signature was computed
//! over (see `heartbeat::fetch_and_verify`).

use serde::{Deserialize, Serialize};

/// The heartbeat request body (TT-2069) - previously an empty `POST`, now carrying this
/// Connector's own observed state back to Agent/Portal. Unsigned, same as the rest of this
/// request: the endpoint already accepts a heartbeat for any `connector_id` with no per-request
/// authentication (see `heartbeat`'s module doc), so this adds no new trust boundary - worst case
/// a spoofed request causes a spurious "unresolved" badge in Portal's UI for a gateway, not an
/// access-control or information-disclosure issue.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct ConnectorHeartbeatRequest {
    /// Endpoint hosts, from the *previous* heartbeat's policy bundles, that `dns_cache` still has
    /// no resolved address for as of right now - never a literal IPv4 (those always resolve, see
    /// `DnsCache::resolve`), only ever a hostname DNS hasn't answered for. Reported so Portal can
    /// eventually show an admin that a gateway's endpoint is unreachable, instead of the only
    /// signal being a `warn!` on this box's own log (TT-2066 review finding #8, TT-2069). Empty on
    /// the very first heartbeat - nothing was configured yet to have failed to resolve.
    pub unresolved_endpoint_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConnectorHeartbeatResponse {
    pub connector_id: String,
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
    pub device_public_key: String,
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
            unresolved_endpoint_hosts: vec!["crm.internal.example.com".to_string()],
        };

        let json = serde_json::to_string(&request).unwrap();

        assert_eq!(
            json,
            r#"{"unresolved_endpoint_hosts":["crm.internal.example.com"]}"#
        );
    }

    #[test]
    fn heartbeat_request_default_has_no_unresolved_hosts() {
        assert_eq!(
            ConnectorHeartbeatRequest::default(),
            ConnectorHeartbeatRequest {
                unresolved_endpoint_hosts: vec![]
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
