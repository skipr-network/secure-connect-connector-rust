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
    /// TT-2464 (spec §B.18): gateway-end reports still waiting for a successful heartbeat - see
    /// `gateway_end`. Omitted when empty, so a heartbeat with nothing to report is byte-for-byte
    /// what it was before this field existed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ended_flows: Vec<crate::gateway_end::GatewayEndReport>,
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
    /// Transitional (TT-2514): Portal fills it with only the port rules a Connector that predates
    /// rules serves exactly - TCP + UDP with equal ports. Used only when `port_rules` is absent.
    pub endpoints: Vec<PolicyBundleEndpoint>,
    /// TT-2514: the gateway's port rules. `None` from a Portal or Agent that predates them, which
    /// relays no such field - see `PolicyBundle::rules`. A rule that doesn't parse is skipped with a
    /// warning rather than failing the whole heartbeat, which would stop every gateway here.
    #[serde(default, deserialize_with = "deserialize_port_rules")]
    pub port_rules: Option<Vec<PortRule>>,
    pub entitlement_list: Vec<Entitlement>,
}

impl PolicyBundle {
    /// The rules this gateway is served by: its `port_rules`, or - from a Portal or Agent that
    /// predates them - each endpoint as a TCP + UDP rule with equal external and internal port,
    /// which is exactly what an endpoint meant (TT-2514).
    pub fn rules(&self) -> Vec<PortRule> {
        match &self.port_rules {
            Some(rules) => rules.clone(),
            None => self.endpoints.iter().map(PortRule::from).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PolicyBundleEndpoint {
    pub host: String,
    pub port: u16,
}

/// Which transports a port rule opens (TT-2514). A value this Connector doesn't know is kept as
/// `Unknown` with the value as sent, rather than failing the whole heartbeat: such a rule never
/// matches a flow, and the audit log records what was actually sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTransport {
    Tcp,
    Udp,
    TcpUdp,
    Unknown(String),
}

impl RuleTransport {
    pub fn as_wire(&self) -> &str {
        match self {
            RuleTransport::Tcp => "TCP",
            RuleTransport::Udp => "UDP",
            RuleTransport::TcpUdp => "TCP_UDP",
            RuleTransport::Unknown(value) => value,
        }
    }
}

impl<'de> Deserialize<'de> for RuleTransport {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "TCP" => RuleTransport::Tcp,
            "UDP" => RuleTransport::Udp,
            "TCP_UDP" => RuleTransport::TcpUdp,
            _ => RuleTransport::Unknown(value),
        })
    }
}

impl Serialize for RuleTransport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire())
    }
}

/// Parses each port rule on its own, so one a newer or faulty sender got wrong (a null field, a
/// port above 65535) is dropped with a warning and the gateway's other rules still apply.
fn deserialize_port_rules<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<PortRule>>, D::Error> {
    let raw: Option<Vec<serde_json::Value>> = Option::deserialize(deserializer)?;
    Ok(raw.map(|values| {
        values
            .into_iter()
            .filter_map(|value| match PortRule::deserialize(&value) {
                Ok(rule) => Some(rule),
                Err(error) => {
                    tracing::warn!(rule = %value, %error, "Skipped a port rule that doesn't parse");
                    None
                }
            })
            .collect()
    }))
}

/// One port a gateway opens and where it leads (TT-2514): a flow on `transport` to the gateway's
/// `external_port` is forwarded to `internal_host:internal_port`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PortRule {
    pub transport: RuleTransport,
    pub external_port: u16,
    pub internal_host: String,
    pub internal_port: u16,
}

/// How a rule is named in the Connector's logs, as Portal's Audit Trail names it:
/// `TCP 443 -> 10.0.0.5:8443`.
impl std::fmt::Display for PortRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let transport = match &self.transport {
            RuleTransport::Tcp => "TCP",
            RuleTransport::Udp => "UDP",
            RuleTransport::TcpUdp => "TCP+UDP",
            RuleTransport::Unknown(value) => value,
        };
        write!(
            f,
            "{transport} {} -> {}:{}",
            self.external_port, self.internal_host, self.internal_port
        )
    }
}

impl From<&PolicyBundleEndpoint> for PortRule {
    fn from(endpoint: &PolicyBundleEndpoint) -> Self {
        PortRule {
            transport: RuleTransport::TcpUdp,
            external_port: endpoint.port,
            internal_host: endpoint.host.clone(),
            internal_port: endpoint.port,
        }
    }
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

/// `POST /api/connectors/deregister` body (TT-2126, spec §B.19 point 4): this Connector's own public key, the
/// only identity it has.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ConnectorDeregisterRequest {
    pub connector_public_key: String,
}

/// Agent's signed confirmation that Portal accepted the deregistration - checked like a heartbeat response
/// (signature, this Connector's own key) and for expiry before the host removes anything.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConnectorDeregisterResponse {
    pub connector_id: String,
    pub connector_public_key: String,
    pub status: String,
    pub generated_at: String,
    pub expires_at: String,
    pub nonce: String,
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
            ended_flows: vec![],
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
            ended_flows: vec![],
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
            ended_flows: vec![],
        };

        let json = serde_json::to_string(&request).unwrap();

        assert_eq!(json, r#"{"connector_public_key":"pk-1"}"#);
    }

    /// TT-2464: the field names Agent relays and Portal reads (spec §B.18 point 1).
    #[test]
    fn heartbeat_request_serializes_gateway_end_reports_with_the_contract_field_names() {
        let request = ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            unresolved_endpoint_hosts: None,
            ended_flows: vec![crate::gateway_end::GatewayEndReport {
                report_id: "r-1".to_string(),
                gateway_id: "gw-1".to_string(),
                user_id: "u-1".to_string(),
                device_public_key: "dev-A".to_string(),
                ended_at: 1_234,
                flows_ended: 2,
            }],
        };

        let json = serde_json::to_string(&request).unwrap();

        assert_eq!(
            json,
            r#"{"connector_public_key":"pk-1","ended_flows":[{"report_id":"r-1","gateway_id":"gw-1","user_id":"u-1","device_public_key":"dev-A","ended_at":1234,"flows_ended":2}]}"#
        );
    }

    #[test]
    fn heartbeat_request_default_has_no_unresolved_hosts() {
        assert_eq!(
            ConnectorHeartbeatRequest::default(),
            ConnectorHeartbeatRequest {
                connector_public_key: String::new(),
                unresolved_endpoint_hosts: None,
                ended_flows: vec![],
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

    /// TT-2514: the port rules as Agent relays them from Portal.
    #[test]
    fn deserializes_port_rules_and_prefers_them_over_the_endpoints() {
        let json = r#"{
            "gateway_id": "gw-1", "location": "Amsterdam", "hostname": "crm.acme.internal",
            "access_mode": "SELECTED", "endpoints": [{"host": "10.0.0.5", "port": 443}],
            "port_rules": [
                {"transport": "TCP_UDP", "external_port": 443, "internal_host": "10.0.0.5", "internal_port": 443},
                {"transport": "TCP", "external_port": 2222, "internal_host": "10.0.0.7", "internal_port": 22},
                {"transport": "UDP", "external_port": 514, "internal_host": "syslog.internal", "internal_port": 514}
            ],
            "entitlement_list": []
        }"#;

        let bundle: PolicyBundle = serde_json::from_str(json).unwrap();

        assert_eq!(
            bundle.rules(),
            vec![
                PortRule {
                    transport: RuleTransport::TcpUdp,
                    external_port: 443,
                    internal_host: "10.0.0.5".to_string(),
                    internal_port: 443
                },
                PortRule {
                    transport: RuleTransport::Tcp,
                    external_port: 2222,
                    internal_host: "10.0.0.7".to_string(),
                    internal_port: 22
                },
                PortRule {
                    transport: RuleTransport::Udp,
                    external_port: 514,
                    internal_host: "syslog.internal".to_string(),
                    internal_port: 514
                },
            ]
        );
    }

    /// TT-2514: a Portal or Agent that predates port rules sends only endpoints - each one serves as
    /// a TCP + UDP rule with equal ports, exactly what it meant before.
    #[test]
    fn a_bundle_without_port_rules_uses_its_endpoints_as_tcp_and_udp_rules() {
        let json = r#"{
            "gateway_id": "gw-1", "location": "Amsterdam", "hostname": "crm.acme.internal",
            "access_mode": "SELECTED", "endpoints": [{"host": "erp.internal", "port": 8080}],
            "entitlement_list": []
        }"#;

        let bundle: PolicyBundle = serde_json::from_str(json).unwrap();

        assert_eq!(bundle.port_rules, None);
        assert_eq!(
            bundle.rules(),
            vec![PortRule {
                transport: RuleTransport::TcpUdp,
                external_port: 8080,
                internal_host: "erp.internal".to_string(),
                internal_port: 8080
            }]
        );
    }

    /// A transport value from a newer Portal must not fail the whole heartbeat (the nullable
    /// device_public_key lesson): the rule parses as `Unknown`, which matches no flow, and keeps
    /// the value sent so the audit log shows it.
    #[test]
    fn an_unknown_transport_does_not_fail_the_heartbeat_and_is_kept_as_sent() {
        let json = r#"{"transport": "SCTP", "external_port": 443, "internal_host": "10.0.0.5", "internal_port": 443}"#;

        let rule: PortRule = serde_json::from_str(json).unwrap();

        assert_eq!(rule.transport, RuleTransport::Unknown("SCTP".to_string()));
        assert_eq!(serde_json::to_value(&rule.transport).unwrap(), "SCTP");
    }

    #[test]
    fn known_transports_serialize_as_portal_sends_them() {
        for wire in ["TCP", "UDP", "TCP_UDP"] {
            let transport: RuleTransport = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(serde_json::to_value(&transport).unwrap(), wire);
        }
    }

    /// One rule a sender got wrong must not fail the heartbeat for every gateway on this
    /// Connector (TT-2514 review): it is skipped, the others still apply.
    #[test]
    fn a_port_rule_that_does_not_parse_is_skipped_and_the_others_kept() {
        let json = r#"{
            "gateway_id": "gw-1", "location": "Mumbai", "hostname": "erp.internal", "access_mode": "ALL",
            "endpoints": [],
            "port_rules": [
                {"transport": "TCP", "external_port": 443, "internal_host": "10.0.0.5", "internal_port": 8443},
                {"transport": "TCP", "external_port": 70000, "internal_host": "10.0.0.5", "internal_port": 22},
                {"transport": "UDP", "external_port": null, "internal_host": "10.0.0.5", "internal_port": 53},
                null,
                {"transport": "UDP", "external_port": 514, "internal_host": "10.0.0.6", "internal_port": 514}
            ],
            "entitlement_list": []
        }"#;

        let bundle: PolicyBundle = serde_json::from_str(json).unwrap();

        assert_eq!(
            bundle.port_rules.unwrap(),
            vec![
                PortRule {
                    transport: RuleTransport::Tcp,
                    external_port: 443,
                    internal_host: "10.0.0.5".to_string(),
                    internal_port: 8443,
                },
                PortRule {
                    transport: RuleTransport::Udp,
                    external_port: 514,
                    internal_host: "10.0.0.6".to_string(),
                    internal_port: 514,
                },
            ]
        );
    }

    #[test]
    fn a_null_port_rules_field_is_treated_as_absent() {
        let json = r#"{
            "gateway_id": "gw-1", "location": "Mumbai", "hostname": "erp.internal", "access_mode": "ALL",
            "endpoints": [], "port_rules": null, "entitlement_list": []
        }"#;

        let bundle: PolicyBundle = serde_json::from_str(json).unwrap();

        assert_eq!(bundle.port_rules, None);
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
