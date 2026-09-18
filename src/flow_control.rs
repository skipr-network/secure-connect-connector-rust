//! Connector<->Gatekeeper flow-admission/release control plane - the agreed
//! contract from the TT-1732 comment thread (2026-08-24 to 2026-08-26).
//! Gatekeeper calls these endpoints on the Connector whenever a user's flow
//! gets a new port, or when that flow closes, routed through the private
//! WireGuard tunnel rather than the public internet.
//!
//! Transport-agnostic on purpose: this module only builds the axum `Router`
//! and its handlers, fully testable without a real socket - `main` binds it
//! to `connector_virtual_ip:Config::control_plane_port`. What actually
//! restricts these endpoints to genuine Gatekeeper peers is that the tunnel
//! network isn't reachable from anywhere else (Konyk's final comment on
//! TT-1732) - and since TT-1838, that's a real guarantee rather than an
//! aspiration: the listener binds to `connector_virtual_ip` itself, the
//! Connector's own address on its TUN interface, which only receives
//! traffic that arrived through an established WireGuard session with a
//! node whose wg0 `allowed-ips` includes this Connector's address
//! specifically (Gatekeeper's `WireGuardPeerProvisioner`, TT-1838). Before
//! that, this listener bound to a wildcard/loopback address configured
//! independently of any tunnel-internal address, so it was reachable at
//! whatever address the process happened to be configured with - an honest
//! limitation, not a security design, and now closed.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::access::{AccessDecision, decide_access_and_audit};
use crate::audit::{AuditEvent, AuditLog};
use crate::crypto;
use crate::flow_table::FlowTable;
use crate::policy::PolicyStore;
use crate::signature_binding::SignatureBindingGuard;

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
    pub user_public_key: String,
    pub signature: String,
    pub signed_data: String,
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
    pub signature_binding: Arc<Mutex<SignatureBindingGuard>>,
    pub flow_table: Arc<Mutex<FlowTable>>,
}

pub fn router(state: ControlPlaneState) -> Router {
    Router::new()
        .route("/api/flow/admit", post(admit_flow))
        .route("/api/flow/release", post(release_flow))
        .with_state(state)
}

async fn admit_flow(
    State(state): State<ControlPlaneState>,
    Json(request): Json<FlowAdmissionRequest>,
) -> Json<FlowAdmissionResponse> {
    Json(
        handle_flow_admission(
            &state.policy_store,
            &state.audit_log,
            &state.signature_binding,
            &state.flow_table,
            request,
        )
        .await,
    )
}

/// Extracted from the axum handler so it's directly unit-testable without
/// going through HTTP extraction.
async fn handle_flow_admission(
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    signature_binding: &Mutex<SignatureBindingGuard>,
    flow_table: &Mutex<FlowTable>,
    request: FlowAdmissionRequest,
) -> FlowAdmissionResponse {
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
    let Ok(signed_message) = BASE64.decode(&request.signed_data) else {
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: request.gateway_id.clone(),
                device_public_key: request.user_public_key.clone(),
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
    if !crypto::verify_base64(
        &request.user_public_key,
        &signed_message,
        &request.signature,
    ) {
        // This is itself a deny decision (acceptance criteria: "Connector...
        // makes an allow/deny decision... a local audit entry is recorded"),
        // not just an early exit - best-effort, same as decide_access_and_audit.
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: request.gateway_id.clone(),
                device_public_key: request.user_public_key.clone(),
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

    // A cryptographically valid signature can still be a captured one being
    // replayed against a gateway it was never presented for (TT-1732
    // review, Tasneem) - refused with the same wire-level reason as any
    // other signature problem, since from the caller's perspective it's
    // still "your signature doesn't check out for this request" (the fixed
    // wire vocabulary has no dedicated "replay" value; see
    // `signature_binding`'s module doc for why this can't bind to
    // flow_id/node_id/port instead).
    let bound_to_this_gateway = {
        let mut guard = signature_binding
            .lock()
            .expect("signature binding guard lock poisoned");
        guard.check_and_bind(
            &request.user_public_key,
            &request.signature,
            &request.gateway_id,
        )
    };
    if !bound_to_this_gateway {
        if let Err(error) = audit_log
            .record(AuditEvent::AccessRefused {
                gateway_id: request.gateway_id.clone(),
                device_public_key: request.user_public_key.clone(),
                reason: "signature_reused_for_different_gateway".to_string(),
            })
            .await
        {
            tracing::error!(%error, "failed to write signature-replay audit entry");
        }
        return FlowAdmissionResponse {
            flow_id: request.flow_id,
            decision: "refuse".to_string(),
            reason: Some("invalid_signature".to_string()),
        };
    }

    let decision = decide_access_and_audit(
        policy_store,
        audit_log,
        &request.gateway_id,
        &request.user_public_key,
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
                request.user_public_key.clone(),
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

async fn release_flow(
    State(state): State<ControlPlaneState>,
    Json(request): Json<FlowReleaseRequest>,
) -> impl IntoResponse {
    state
        .flow_table
        .lock()
        .expect("flow table lock poisoned")
        .release(&request.flow_id);
    handle_flow_release(&state.audit_log, request).await;
    StatusCode::NO_CONTENT
}

/// Real per-flow state (matching a release to the exact admitted flow, not
/// just its port) needs the actual traffic-forwarding slice to exist first -
/// there's nothing to release yet. For now this closes the loop on the
/// acceptance criteria's audit requirement ("Local audit is written... the
/// action completes").
async fn handle_flow_release(audit_log: &AuditLog, request: FlowReleaseRequest) {
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
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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
                        device_public_key: device_public_key.to_string(),
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
            user_public_key: public_key_hex.to_string(),
            signature: crypto::sign_to_base64(signing_key, message.as_bytes()),
            signed_data: BASE64.encode(message),
        }
    }

    fn signature_binding() -> Mutex<SignatureBindingGuard> {
        Mutex::new(SignatureBindingGuard::new())
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

        let response = handle_flow_admission(
            &store,
            &audit_log,
            &signature_binding(),
            &flow_table(),
            request,
        )
        .await;

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
            user_public_key: "047fc7980b4735d2efa3492cb4312e0d1cdf4e23174d8bf8ade7e6a964a705211cf283eff432a12fabdb227d4529ef1fb3f0c6828181a54b9d1ad3194c6a9f490d".to_string(),
            signature: "MEUCIHrp5diOwIHlLi8EFX4oE51tBN6361tP0BViMlKW0gdYAiEAo27/MSQpQNeodLixoaJ77dHP+mK8WatNXmAs+uwggOA=".to_string(),
            signed_data: "eyJkZXZpY2VfaWQiOiI1ODVjYjU0MjYzZWU5YzNmYjM1MjYwZWYxMzM1NGE2NWIzZGNkYjk4IiwicHVibGljX2tleSI6IjA0N2ZjNzk4MGI0NzM1ZDJlZmEzNDkyY2I0MzEyZTBkMWNkZjRlMjMxNzRkOGJmOGFkZTdlNmE5NjRhNzA1MjExY2YyODNlZmY0MzJhMTJmYWJkYjIyN2Q0NTI5ZWYxZmIzZjBjNjgyODE4MWE1NGI5ZDFhZDMxOTRjNmE5ZjQ5MGQiLCJzZXJ2aWNlX3R5cGUiOiJpbnN0YW50IiwicmVnaW9uIjoiYXAtc291dGgtMSIsImlwX2FkZHJlc3MiOiI0NS4xMTMuMTA4LjEyNyIsImlzX2lwX2FkZHJlc3Nfc3RhdGljIjpmYWxzZSwicHJvdG9jb2wiOiJvcGVudnBuIiwic2Vzc2lvbl9pZCI6bnVsbCwicHJvdmlzaW9uX3Rva2VuIjoiX2l3VzlKQVZtNUQtSHYwdFpfMVdwOUIydGs1bzRwZERTbUo4TTA0MFYzUSIsImdhdGV3YXlfaWQiOiIxMzJmNjJhYS1hYzI5LTQ5YWUtYjUyNy1jMDQ4NTMwYmU5MzUifQ==".to_string(),
        };

        let response = handle_flow_admission(
            &store,
            &audit_log,
            &signature_binding(),
            &flow_table(),
            request,
        )
        .await;

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

        handle_flow_admission(&store, &audit_log, &signature_binding(), &table, request).await;

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

        handle_flow_admission(&store, &audit_log, &signature_binding(), &table, request).await;

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

        handle_flow_admission(&store, &audit_log, &signature_binding(), &table, request).await;

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
        handle_flow_admission(&store, &audit_log, &signature_binding(), &table, request).await;
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
        let binding = signature_binding();
        let mut request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );

        let first =
            handle_flow_admission(&store, &audit_log, &binding, &flow_table(), request.clone())
                .await;
        request.flow_id = "flow-2".to_string();
        let second =
            handle_flow_admission(&store, &audit_log, &binding, &flow_table(), request).await;

        assert_eq!(first.decision, "admit");
        assert_eq!(second.decision, "admit");
    }

    #[tokio::test]
    async fn the_same_session_signature_replayed_for_a_different_gateway_is_refused() {
        let device = crypto::generate_keypair();
        // Entitled to BOTH gateways, so a refusal here can only be the
        // replay guard - not a coincidental entitlement failure.
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
                            device_public_key: device.public_key_hex.clone(),
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
                            device_public_key: device.public_key_hex.clone(),
                        }],
                    },
                ],
                node_list: vec![],
            })
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let binding = signature_binding();
        let first_request = admission_request(
            "gw-1",
            &device.signing_key,
            &device.public_key_hex,
            "session-nonce-1",
        );
        let mut replayed_request = first_request.clone();
        replayed_request.gateway_id = "gw-2".to_string();
        replayed_request.flow_id = "flow-2".to_string();

        let first =
            handle_flow_admission(&store, &audit_log, &binding, &flow_table(), first_request).await;
        let replayed = handle_flow_admission(
            &store,
            &audit_log,
            &binding,
            &flow_table(),
            replayed_request,
        )
        .await;

        assert_eq!(first.decision, "admit");
        assert_eq!(replayed.decision, "refuse");
        assert_eq!(replayed.reason, Some("invalid_signature".to_string()));

        let entries: Vec<serde_json::Value> = std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            entries[1]["reason"],
            "signature_reused_for_different_gateway"
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
        request.user_public_key = device.public_key_hex.clone();

        let response = handle_flow_admission(
            &store,
            &audit_log,
            &signature_binding(),
            &flow_table(),
            request,
        )
        .await;

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

        let response = handle_flow_admission(
            &store,
            &audit_log,
            &signature_binding(),
            &flow_table(),
            request,
        )
        .await;

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

        let response = handle_flow_admission(
            &store,
            &audit_log,
            &signature_binding(),
            &flow_table(),
            request,
        )
        .await;

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

        let response = handle_flow_admission(
            &store,
            &audit_log,
            &signature_binding(),
            &flow_table(),
            request,
        )
        .await;

        // NoPolicyApplied has no dedicated wire value - collapses to
        // not_entitled (see RefusalReason::as_wire_str).
        assert_eq!(response.decision, "refuse");
        assert_eq!(response.reason, Some("not_entitled".to_string()));
    }

    #[tokio::test]
    async fn release_records_an_audit_entry_and_the_router_returns_204() {
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

    #[tokio::test]
    async fn the_router_wires_admit_and_release_end_to_end_over_real_http_extraction() {
        let device = crypto::generate_keypair();
        let store = store_with_entitled_device("gw-1", "u-1", &device.public_key_hex);
        let dir = tempfile::tempdir().unwrap();
        let state = ControlPlaneState {
            policy_store: Arc::new(store),
            audit_log: Arc::new(AuditLog::new(dir.path().join("audit.log"))),
            signature_binding: Arc::new(signature_binding()),
            flow_table: Arc::new(flow_table()),
        };
        let app = router(state);

        let signature = crypto::sign_to_base64(&device.signing_key, b"session-nonce-1");
        // signed_data carries the base64 *encoding* of what was actually
        // signed (TT-2107) - see admission_request's doc comment.
        let http_request = Request::builder()
            .method("POST")
            .uri("/api/flow/admit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "flow_id": "flow-1",
                    "gateway_id": "gw-1",
                    "node_id": "n-1",
                    "port": 51820,
                    "user_public_key": device.public_key_hex,
                    "signature": signature,
                    "signed_data": BASE64.encode("session-nonce-1")
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.clone().oneshot(http_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["decision"], "admit");

        let release_request = Request::builder()
            .method("POST")
            .uri("/api/flow/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "flow_id": "flow-1",
                    "gateway_id": "gw-1",
                    "port": 51820
                }))
                .unwrap(),
            ))
            .unwrap();

        let release_response = app.oneshot(release_request).await.unwrap();
        assert_eq!(release_response.status(), StatusCode::NO_CONTENT);
    }
}
