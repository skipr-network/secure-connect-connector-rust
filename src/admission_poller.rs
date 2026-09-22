//! TT-2144: the Connector-initiated flow-admission/release control channel client - the active
//! counterpart to `flow_control`'s pure decision logic.
//!
//! Gatekeeper used to dial *into* this Connector for every flow (`ConnectorFlowRelayClient`,
//! `http://connector_virtual_ip:8443/api/flow/admit`/`/release`) - which required an inbound
//! firewall rule on the Connector host, silently violating the spec's "no inbound port ever opened
//! on the customer's side" principle (found live: a Connector whose own `ufw` had no rule for that
//! port made every flow fail closed with an opaque timeout, needing a manual firewall edit the
//! product's install story was never supposed to require).
//!
//! This module flips the direction: one task per currently-paired Node holds a plain outbound HTTP
//! long-poll open to that Node's Gatekeeper (`GET /api/connector/{connector_id}/poll`), and posts
//! its decision back (`POST /api/connector/{connector_id}/admission-result`). This never opens a
//! listening socket on the Connector at all, so no inbound firewall rule is ever needed for this
//! channel again.
//!
//! **Why a plain outbound HTTP call, not routed through the userspace WireGuard tunnel itself**:
//! the spec's "no inbound port ever opened" principle is specifically about the *customer's own*
//! Connector VM never needing an inbound rule - it says nothing about how our own Gatekeeper node's
//! already-reachable HTTP API is dialed. `tunnel.rs`'s raw WireGuard handshake already dials
//! `node.ip_address` directly, over the same plain network, to establish the tunnel in the first
//! place - a Node's address being reachable by an authorized Connector is an existing, accepted
//! part of this system's trust model, not something this channel needs to additionally protect
//! against. This mirrors `heartbeat.rs`/`registry_client.rs`'s own outbound-only HTTP clients.
//!
//! Poller lifecycle is deliberately independent of `TunnelManager`'s tunnel-established state
//! (`sync` below runs against the raw heartbeat node list directly, not gated on a reported
//! WireGuard key) - Gatekeeper simply never generates an admission request for a node whose tunnel
//! isn't up on its own side yet, so an idle poller against such a node just receives repeated
//! "none" responses until real traffic exists. Coupling this channel's liveness to tunnel state
//! would only add complexity for no behavioral benefit.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::Deserialize;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::dto::HeartbeatNode;
use crate::flow_control::{
    ControlPlaneState, FlowAdmissionRequest, FlowReleaseRequest, handle_flow_admission,
    handle_flow_release,
};

/// Backoff between poll attempts after a transport failure (connection refused, timeout, non-2xx
/// status, unparseable body) - distinct from the poll call's own long-poll timeout, which is
/// Gatekeeper's own affair (`gatekeeper.connector.control-channel.poll-timeout-ms`, default 25s on
/// that side). Short enough that a Gatekeeper node coming back up is noticed quickly, long enough
/// not to hammer a genuinely-down node on every iteration.
const POLL_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Bounds the poll HTTP request itself - comfortably longer than Gatekeeper's own long-poll
/// timeout, so a slow-but-alive Gatekeeper legitimately holding the connection open close to its
/// own full timeout isn't itself mistaken for a transport failure and retried into a needless
/// reconnect.
const POLL_REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

#[derive(Debug, Deserialize)]
struct ConnectorPollResponse {
    #[serde(rename = "type")]
    kind: String,
    admission: Option<FlowAdmissionRequest>,
    release: Option<FlowReleaseRequest>,
}

/// Tracks one long-poll task per currently-paired Node, spawned/aborted to match each heartbeat's
/// own `node_list` (see `sync`). Owns the `ControlPlaneState` and HTTP client every poller task
/// shares - both are cheaply `Clone` (`Arc`-backed / `reqwest::Client`'s own internal `Arc`).
pub struct AdmissionPollers {
    http: reqwest::Client,
    connector_id: String,
    gatekeeper_http_port: u16,
    state: ControlPlaneState,
    tasks: HashMap<String, JoinHandle<()>>,
}

impl AdmissionPollers {
    pub fn new(
        http: reqwest::Client,
        connector_id: String,
        gatekeeper_http_port: u16,
        state: ControlPlaneState,
    ) -> Self {
        Self {
            http,
            connector_id,
            gatekeeper_http_port,
            state,
            tasks: HashMap::new(),
        }
    }

    /// Spawns a poller for every node in `nodes` that doesn't already have one running, and aborts
    /// any running poller for a node no longer present - called on every heartbeat, mirroring
    /// `TunnelManager::sync_nodes`'s own add/drop shape but against the raw node list directly (see
    /// the module doc for why this is deliberately not gated on a reported WireGuard key).
    pub fn sync(&mut self, nodes: &[HeartbeatNode]) {
        let seen: HashSet<&str> = nodes.iter().map(|node| node.node_id.as_str()).collect();

        self.tasks.retain(|node_id, handle| {
            if seen.contains(node_id.as_str()) {
                true
            } else {
                info!(%node_id, "node no longer present in heartbeat's node list - stopping its admission poller");
                handle.abort();
                false
            }
        });

        for node in nodes {
            if self.tasks.contains_key(&node.node_id) {
                continue;
            }
            info!(node_id = %node.node_id, ip_address = %node.ip_address, "starting admission poller for node");
            let handle = tokio::spawn(run_poller(
                self.http.clone(),
                node.node_id.clone(),
                node.ip_address.clone(),
                self.gatekeeper_http_port,
                self.connector_id.clone(),
                self.state.clone(),
            ));
            self.tasks.insert(node.node_id.clone(), handle);
        }
    }

    #[cfg(test)]
    fn running_node_ids(&self) -> HashSet<String> {
        self.tasks.keys().cloned().collect()
    }
}

impl Drop for AdmissionPollers {
    fn drop(&mut self) {
        for handle in self.tasks.values() {
            handle.abort();
        }
    }
}

async fn run_poller(
    http: reqwest::Client,
    node_id: String,
    node_ip: String,
    gatekeeper_http_port: u16,
    connector_id: String,
    state: ControlPlaneState,
) {
    let base_url = format!("http://{node_ip}:{gatekeeper_http_port}/api/connector/{connector_id}");
    let poll_url = format!("{base_url}/poll");
    loop {
        match http
            .get(&poll_url)
            .timeout(POLL_REQUEST_TIMEOUT)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                match response.json::<ConnectorPollResponse>().await {
                    Ok(message) => {
                        handle_message(&http, &base_url, &node_id, &state, message).await;
                        // No sleep: the long-poll itself paces this loop - a "none" response
                        // already waited out Gatekeeper's own poll-timeout before returning.
                    }
                    Err(error) => {
                        error!(%error, %node_id, "could not parse poll response from Gatekeeper - retrying after a backoff");
                        tokio::time::sleep(POLL_RETRY_BACKOFF).await;
                    }
                }
            }
            Ok(response) => {
                warn!(status = %response.status(), %node_id, %poll_url, "poll to Gatekeeper returned a non-success status - retrying after a backoff");
                tokio::time::sleep(POLL_RETRY_BACKOFF).await;
            }
            Err(error) => {
                warn!(%error, %node_id, %poll_url, "could not reach Gatekeeper to poll for flow-admission work - retrying after a backoff");
                tokio::time::sleep(POLL_RETRY_BACKOFF).await;
            }
        }
    }
}

async fn handle_message(
    http: &reqwest::Client,
    base_url: &str,
    node_id: &str,
    state: &ControlPlaneState,
    message: ConnectorPollResponse,
) {
    match message.kind.as_str() {
        "admission" => handle_admission(http, base_url, node_id, state, message.admission).await,
        "release" => handle_release(state, message.release).await,
        "none" => {}
        other => {
            warn!(kind = %other, %node_id, "unrecognized poll response type - ignoring");
        }
    }
}

async fn handle_admission(
    http: &reqwest::Client,
    base_url: &str,
    node_id: &str,
    state: &ControlPlaneState,
    request: Option<FlowAdmissionRequest>,
) {
    let Some(request) = request else {
        error!(%node_id, "poll response claimed type=admission but carried no admission body - ignoring");
        return;
    };
    let flow_id = request.flow_id.clone();
    let port = request.port;
    let response = handle_flow_admission(
        &state.policy_store,
        &state.audit_log,
        &state.signature_binding,
        &state.flow_table,
        request,
    )
    .await;

    // Same reclaim-on-admit behavior the pre-TT-2144 HTTP handler had: only on an actual admit, a
    // refused flow's buffered packet stays dropped (fail-closed) and is simply left to age out on
    // its own via the shared TTL sweep - no need to explicitly clear it here.
    if response.decision == "admit"
        && let Some(packet) = state
            .flow_table
            .lock()
            .expect("flow table lock poisoned")
            .take_pending_packet(node_id, port, std::time::Instant::now())
        && let Err(error) = state
            .recovered_packet_tx
            .send((node_id.to_string(), packet))
    {
        error!(%error, "could not hand a reclaimed packet back for forwarding - the receiving task appears to have exited");
    }

    let result_url = format!("{base_url}/admission-result");
    if let Err(error) = http.post(&result_url).json(&response).send().await {
        error!(%error, %node_id, %flow_id, "could not post admission result back to Gatekeeper - it will fail closed on its own timeout for this flow");
    }
}

async fn handle_release(state: &ControlPlaneState, request: Option<FlowReleaseRequest>) {
    let Some(request) = request else {
        error!("poll response claimed type=release but carried no release body - ignoring");
        return;
    };
    state
        .flow_table
        .lock()
        .expect("flow table lock poisoned")
        .release(&request.flow_id);
    handle_flow_release(&state.audit_log, request).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::flow_table::FlowTable;
    use crate::policy::PolicyStore;
    use crate::signature_binding::SignatureBindingGuard;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn state() -> (
        ControlPlaneState,
        tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let dir = tempfile::tempdir().unwrap();
        (
            ControlPlaneState {
                policy_store: Arc::new(PolicyStore::new()),
                audit_log: Arc::new(AuditLog::new(dir.path().join("audit.log"))),
                signature_binding: Arc::new(Mutex::new(SignatureBindingGuard::new())),
                flow_table: Arc::new(Mutex::new(FlowTable::new())),
                recovered_packet_tx: tx,
            },
            rx,
        )
    }

    fn node(node_id: &str, ip: &str) -> HeartbeatNode {
        HeartbeatNode {
            node_id: node_id.to_string(),
            ip_address: ip.to_string(),
            wireguard_public_key: None,
        }
    }

    #[test]
    fn sync_starts_a_poller_for_each_new_node_and_stops_it_when_the_node_disappears() {
        let (state, _rx) = state();
        // A Tokio runtime is needed to spawn tasks on, but this test never actually drives them -
        // no server is mocked, so any spawned poller just sits retrying against a closed
        // connection, exercised only for its lifecycle bookkeeping (tasks map), not its behavior.
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _guard = runtime.enter();

        let mut pollers =
            AdmissionPollers::new(reqwest::Client::new(), "c-1".to_string(), 4000, state);
        pollers.sync(&[node("n-1", "10.0.0.1"), node("n-2", "10.0.0.2")]);
        assert_eq!(
            pollers.running_node_ids(),
            HashSet::from(["n-1".to_string(), "n-2".to_string()])
        );

        pollers.sync(&[node("n-1", "10.0.0.1")]);
        assert_eq!(
            pollers.running_node_ids(),
            HashSet::from(["n-1".to_string()])
        );

        pollers.sync(&[node("n-1", "10.0.0.1"), node("n-3", "10.0.0.3")]);
        assert_eq!(
            pollers.running_node_ids(),
            HashSet::from(["n-1".to_string(), "n-3".to_string()])
        );
    }

    #[test]
    fn sync_does_not_restart_an_already_running_poller_for_the_same_node() {
        let (state, _rx) = state();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _guard = runtime.enter();
        let mut pollers =
            AdmissionPollers::new(reqwest::Client::new(), "c-1".to_string(), 4000, state);

        pollers.sync(&[node("n-1", "10.0.0.1")]);
        let first_id = pollers.tasks.get("n-1").unwrap().id();
        pollers.sync(&[node("n-1", "10.0.0.1")]);
        let second_id = pollers.tasks.get("n-1").unwrap().id();

        assert_eq!(
            first_id, second_id,
            "resyncing the same node must not spawn a new task"
        );
    }

    /// TT-2144's own version of the TT-2145 regression this codebase already learned from once: a
    /// null signature triple must deserialize into `ConnectorPollResponse` and reach
    /// `handle_flow_admission` as a considered refusal, not fail JSON extraction outright - now at
    /// this module's own deserialization boundary instead of an axum-extracted request, since
    /// that's where the equivalent risk moved to once Gatekeeper stopped calling into the Connector
    /// directly.
    #[tokio::test]
    async fn a_null_signature_triple_in_a_polled_admission_gets_a_real_refusal_not_a_parse_failure()
    {
        let (state, _rx) = state();
        let raw = serde_json::json!({
            "type": "admission",
            "admission": {
                "flow_id": "flow-1",
                "gateway_id": "gw-1",
                "node_id": "n-1",
                "port": 51820,
                "user_public_key": null,
                "signature": null,
                "signed_data": null
            }
        });
        let message: ConnectorPollResponse = serde_json::from_value(raw)
            .expect("a null signature triple must deserialize, not fail parsing");

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connector/c-1/admission-result"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let base_url = format!("{}/api/connector/c-1", server.uri());

        handle_message(&reqwest::Client::new(), &base_url, "n-1", &state, message).await;

        let requests = server.received_requests().await.unwrap();
        let result_call = requests
            .iter()
            .find(|r| r.url.path() == "/api/connector/c-1/admission-result")
            .expect("admission-result must have been posted back");
        let body: serde_json::Value = serde_json::from_slice(&result_call.body).unwrap();
        assert_eq!(body["decision"], "refuse");
        assert_eq!(body["reason"], "invalid_signature");
    }

    #[tokio::test]
    async fn an_admitted_flow_hands_a_reclaimed_pending_packet_back_over_the_recovered_channel() {
        let (state, mut rx) = state();
        // MockServer::start() does real network I/O (binding a TCP listener) and can occasionally
        // take a noticeable moment under a large parallel test run - set it up *before* buffering
        // the pending packet, not after, so the 300ms TTL clock only starts once everything else
        // is already ready and the only thing left is the actual admission call.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connector/c-1/admission-result"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let base_url = format!("{}/api/connector/c-1", server.uri());
        // Warms the audit log's lazy first-write path (file creation, tokio's blocking-thread-pool
        // cold start) outside the timed window below - otherwise that one-time cost can occasionally
        // eat enough of the 300ms TTL under a large parallel test run to make this flaky for reasons
        // that have nothing to do with the actual behavior under test.
        state
            .audit_log
            .record(crate::audit::AuditEvent::FlowReleased {
                flow_id: "warm-up".to_string(),
                gateway_id: "warm-up".to_string(),
            })
            .await
            .unwrap();
        let device = crate::crypto::generate_keypair();
        state
            .policy_store
            .apply(crate::dto::ConnectorHeartbeatResponse {
                connector_id: "c-1".to_string(),
                connector_virtual_ip: Some("10.98.0.1".to_string()),
                generated_at: "2026-08-27T10:00:00Z".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                nonce: "n1".to_string(),
                policy_bundles: vec![crate::dto::PolicyBundle {
                    gateway_id: "gw-1".to_string(),
                    location: "Amsterdam".to_string(),
                    hostname: "crm.internal.example.com".to_string(),
                    access_mode: "SELECTED_USERS".to_string(),
                    endpoints: vec![],
                    entitlement_list: vec![crate::dto::Entitlement {
                        user_id: "u-1".to_string(),
                        device_public_key: device.public_key_hex.clone(),
                    }],
                }],
                node_list: vec![],
            })
            .unwrap();
        let signature = crate::crypto::sign_to_base64(&device.signing_key, b"session-nonce-1");
        use base64::Engine as _;
        let signed_data = base64::engine::general_purpose::STANDARD.encode("session-nonce-1");

        // The gap between buffering and this function's own internal reclaim check
        // (`take_pending_packet`) spans a real `.await` on `handle_flow_admission` - including a
        // genuine disk write via `decide_access_and_audit`'s audit entry - which a sufficiently
        // busy parallel test run (many other tests' own spawn_blocking work contending for the
        // same pool) can occasionally push past the 300ms production TTL, for reasons that have
        // nothing to do with whether the reclaim wiring itself is correct. Retried a few times
        // with a fresh buffer+flow_id each attempt rather than lengthened, since the TTL itself is
        // a fixed production value this test must exercise as-is, not something to relax.
        let http = reqwest::Client::new();
        let mut recovered = None;
        for attempt in 0..5 {
            let flow_id = format!("flow-{attempt}");
            let request = FlowAdmissionRequest {
                flow_id,
                gateway_id: "gw-1".to_string(),
                node_id: "n-1".to_string(),
                port: 51820,
                user_public_key: Some(device.public_key_hex.clone()),
                signature: Some(signature.clone()),
                signed_data: Some(signed_data.clone()),
            };
            state.flow_table.lock().unwrap().buffer_pending_packet(
                "n-1",
                51820,
                vec![9, 8, 7],
                std::time::Instant::now(),
            );
            handle_admission(&http, &base_url, "n-1", &state, Some(request)).await;
            if let Ok(result) = rx.try_recv() {
                recovered = Some(result);
                break;
            }
        }

        let (recovered_node_id, recovered_packet) = recovered.expect(
            "the buffered packet for this now-admitted (node_id, port) should have been handed back for forwarding, across every retry attempt",
        );
        assert_eq!(recovered_node_id, "n-1");
        assert_eq!(recovered_packet, vec![9, 8, 7]);
    }

    #[tokio::test]
    async fn a_refused_admission_does_not_forward_a_pending_packet() {
        let (state, mut rx) = state();
        state.flow_table.lock().unwrap().buffer_pending_packet(
            "n-1",
            51820,
            vec![9, 8, 7],
            std::time::Instant::now(),
        );
        let request = FlowAdmissionRequest {
            flow_id: "flow-1".to_string(),
            gateway_id: "gw-1".to_string(),
            node_id: "n-1".to_string(),
            port: 51820,
            user_public_key: None,
            signature: None,
            signed_data: None,
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connector/c-1/admission-result"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let base_url = format!("{}/api/connector/c-1", server.uri());

        handle_admission(
            &reqwest::Client::new(),
            &base_url,
            "n-1",
            &state,
            Some(request),
        )
        .await;

        assert!(
            rx.try_recv().is_err(),
            "a refused flow's buffered packet must never be handed back for forwarding"
        );
    }

    #[tokio::test]
    async fn a_release_message_removes_the_flow_and_records_an_audit_entry() {
        let (state, _rx) = state();
        state.flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            51820,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-key".to_string(),
            vec![],
        );
        assert!(
            state
                .flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 51820)
                .is_some()
        );

        handle_release(
            &state,
            Some(FlowReleaseRequest {
                flow_id: "flow-1".to_string(),
                gateway_id: "gw-1".to_string(),
                port: 51820,
            }),
        )
        .await;

        assert!(
            state
                .flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 51820)
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_none_message_does_nothing() {
        let (state, _rx) = state();

        handle_message(
            &reqwest::Client::new(),
            "http://unused",
            "n-1",
            &state,
            ConnectorPollResponse {
                kind: "none".to_string(),
                admission: None,
                release: None,
            },
        )
        .await;
        // No assertion beyond "this returns without touching anything" - covered by the absence of
        // any mock server needing to be hit at all.
    }
}
