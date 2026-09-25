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

use crate::access::{AccessDecision, decide_access_and_audit};
use crate::audit::{AuditEvent, AuditLog};
use crate::crypto;
use crate::flow_table::FlowTable;
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
    /// §B.8) - `flow_table`'s real key alongside `node_id`, both for gating
    /// forwarded traffic and, since TT-1847, for routing reply traffic back
    /// to the right node.
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

#[derive(Clone)]
pub struct ControlPlaneState {
    pub policy_store: Arc<PolicyStore>,
    pub audit_log: Arc<AuditLog>,
    pub flow_table: Arc<Mutex<FlowTable>>,
    /// Hands a packet `admission_poller` reclaimed via `FlowTable::take_pending_packet` back to
    /// `main::run_wireguard_receive_loop` - the only task allowed to write to the TUN device (see
    /// its own doc comment) - for forwarding, instead of that poller task needing TUN write access
    /// it was never given. `(node_id, packet_bytes)`. Tests that don't exercise this path construct
    /// this from an `unbounded_channel()` and just drop the receiver half - sending into a channel
    /// with no live receiver is a harmless no-op error this code ignores.
    pub recovered_packet_tx: tokio::sync::mpsc::UnboundedSender<(String, Vec<u8>)>,
}

/// The decision logic `admission_poller` calls once it has received one admission message over its
/// own long-poll to Gatekeeper - previously invoked from an axum handler here directly (pre-TT-2144),
/// now called from that module's own task after HTTP JSON extraction happens there instead. Public
/// so it stays independently testable (as its own unit tests below do) without an HTTP round trip.
pub(crate) async fn handle_flow_admission(
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    flow_table: &Mutex<FlowTable>,
    request: FlowAdmissionRequest,
) -> FlowAdmissionResponse {
    // TT-2145: a null signature triple is a normal, anticipated input (spec
    // §B.9), not a malformed request - handle it as a considered "no
    // signature presented -> refuse" decision, with its own audit entry,
    // before ever touching decoding/verification. Deliberately not folded
    // into the invalid_signature branch below: that one always has a
    // device_public_key to record, this one usually doesn't.
    let (Some(user_public_key), Some(signature), Some(signed_data)) = (
        request.user_public_key.clone(),
        request.signature.clone(),
        request.signed_data.clone(),
    ) else {
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: request.gateway_id.clone(),
                device_public_key: request.user_public_key.clone().unwrap_or_default(),
                reason: "no_signature_presented".to_string(),
            })
            .await
        {
            tracing::error!(%error, "failed to write no-signature audit entry");
        }
        return FlowAdmissionResponse {
            flow_id: request.flow_id,
            decision: "refuse".to_string(),
            // Fixed four-value wire vocabulary (TT-1732 contract) has no
            // dedicated "no signature" value - same bucket as any other
            // authentication failure from the caller's perspective.
            reason: Some("invalid_signature".to_string()),
        };
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
                gateway_id: request.gateway_id.clone(),
                device_public_key: user_public_key.clone(),
                reason: "invalid_signature".to_string(),
            })
            .await
        {
            tracing::error!(%error, "failed to write invalid-signature audit entry");
        }
        return FlowAdmissionResponse {
            flow_id: request.flow_id,
            decision: "refuse".to_string(),
            reason: Some("invalid_signature".to_string()),
        };
    };
    if !crypto::verify_base64(&user_public_key, &signed_message, &signature) {
        // This is itself a deny decision (acceptance criteria: "Connector...
        // makes an allow/deny decision... a local audit entry is recorded"),
        // not just an early exit - best-effort, same as decide_access_and_audit.
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: request.gateway_id.clone(),
                device_public_key: user_public_key.clone(),
                reason: "invalid_signature".to_string(),
            })
            .await
        {
            tracing::error!(%error, "failed to write invalid-signature audit entry");
        }
        return FlowAdmissionResponse {
            flow_id: request.flow_id,
            decision: "refuse".to_string(),
            reason: Some("invalid_signature".to_string()),
        };
    }

    // A cryptographically valid signature proves possession of
    // user_public_key (spec §B.9); which gateway_id it's presented for is
    // not something the Connector restricts here (TT-2143: the original
    // cross-gateway-replay guard bound a session signature to only the
    // *first* gateway_id it touched, but the spec - §B.5/§B.9, and TT-1732's
    // own acceptance criteria, "it stores policies, entitlement lists, and
    // node list for all attached gateways" - requires one session to reach
    // every Private Gateway at this Connector's single Location without
    // reconnecting; a Connector process never serves more than one
    // Location, so there is nothing to gain security-wise from refusing a
    // valid signature reused across gateways it's already legitimately
    // presenting to on this same Connector). Authorization is still decided
    // per request below, against the current entitlement list for the named
    // gateway_id specifically.
    let decision = decide_access_and_audit(
        policy_store,
        audit_log,
        &request.gateway_id,
        &user_public_key,
    )
    .await;

    match decision {
        AccessDecision::Allowed { endpoints, .. } => {
            // The real forwarding loops (`main`) only forward traffic for a
            // (node_id, port) pair present here, in both directions
            // (forward: TT-1732 review finding #1 - "a refused, or never
            // checked, device's traffic could still be forwarded once its
            // IP was learned"; reverse/reply routing: TT-1847) - nothing is
            // forwardable or routable until it's recorded as admitted right
            // here. `endpoints` rides along so the forwarding loop can also
            // check *where* traffic is headed, not just that the flow is
            // admitted (TT-2046) - being entitled to a gateway says nothing
            // about which address that gateway is actually configured to
            // expose.
            flow_table.lock().expect("flow table lock poisoned").admit(
                request.node_id.clone(),
                request.port,
                request.gateway_id.clone(),
                request.flow_id.clone(),
                user_public_key.clone(),
                endpoints,
            );
            FlowAdmissionResponse {
                flow_id: request.flow_id,
                decision: "admit".to_string(),
                reason: None,
            }
        }
        AccessDecision::Refused(reason) => FlowAdmissionResponse {
            flow_id: request.flow_id,
            decision: "refuse".to_string(),
            reason: Some(reason.as_wire_str().to_string()),
        },
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
                    entitlement_list: vec![Entitlement {
                        user_id: user_id.to_string(),
                        device_public_key: Some(device_public_key.to_string()),
                    }],
                }],
                node_list: vec![],
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
        }
    }

    fn flow_table() -> Mutex<FlowTable> {
        Mutex::new(FlowTable::new())
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
                        entitlement_list: vec![Entitlement {
                            user_id: "u-1".to_string(),
                            device_public_key: Some(device.public_key_hex.clone()),
                        }],
                    },
                ],
                node_list: vec![],
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
}
