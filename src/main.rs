mod access;
mod audit;
mod config;
mod crypto;
mod dto;
mod flow_control;
mod heartbeat;
mod identity;
mod policy;
mod registry_client;
mod tunnel;

use std::sync::Arc;

use anyhow::Context;
use audit::{AuditEvent, AuditLog};
use config::Config;
use dto::HeartbeatNode;
use flow_control::ControlPlaneState;
use heartbeat::HeartbeatClient;
use policy::PolicyStore;
use registry_client::RegistryClient;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tunnel::{TunnelEvent, TunnelManager};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    let connector_identity = identity::load_or_generate(&config.identity_key_path)?;
    info!(
        connector_id = %config.connector_id,
        public_key = %connector_identity.public_key_base64,
        "Connector identity ready"
    );

    let http = reqwest::Client::new();
    let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
    let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
    let policy_store = Arc::new(PolicyStore::new());
    let audit_log = Arc::new(AuditLog::new(&config.audit_log_path));
    // Moves connector_identity.secret - nothing else needs the identity after
    // the "ready" log line above.
    let tunnel_manager = Arc::new(Mutex::new(TunnelManager::new(connector_identity.secret)));

    // Ephemeral local port: the Connector dials out to nodes, not the other
    // way around (a standard road-warrior WireGuard pattern - no inbound
    // port needed on the customer's side for this leg, per the spec).
    let wg_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("failed to bind the WireGuard UDP socket")?,
    );
    tokio::spawn(run_wireguard_receive_loop(
        wg_socket.clone(),
        tunnel_manager.clone(),
    ));

    let control_plane_listener = tokio::net::TcpListener::bind(&config.control_plane_listen_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind the flow-admission control-plane listener on {}",
                config.control_plane_listen_addr
            )
        })?;
    info!(
        addr = %config.control_plane_listen_addr,
        "flow-admission control plane listening"
    );
    let control_plane_router = flow_control::router(ControlPlaneState {
        policy_store: policy_store.clone(),
        audit_log: audit_log.clone(),
    });
    tokio::spawn(async move {
        if let Err(error) = axum::serve(control_plane_listener, control_plane_router).await {
            error!(%error, "flow-admission control plane server stopped");
        }
    });

    let mut interval = tokio::time::interval(config.heartbeat_interval);
    loop {
        interval.tick().await;
        if let Err(error) = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
        )
        .await
        {
            error!(%error, "heartbeat cycle failed");
        }
    }
}

async fn run_heartbeat(
    config: &Config,
    registry_client: &RegistryClient,
    heartbeat_client: &HeartbeatClient,
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    tunnel_manager: &Mutex<TunnelManager>,
    wg_socket: &UdpSocket,
) -> anyhow::Result<()> {
    let agent_public_key = registry_client
        .get_agent_permitted_key(&config.agent_ip_address)
        .await?;
    let response = heartbeat_client
        .fetch_and_verify(&config.connector_id, &agent_public_key)
        .await?;

    let gateways = response.policy_bundles.len();
    let nodes = response.node_list.len();
    let node_list = response.node_list.clone();
    let nodes_without_key = node_list
        .iter()
        .filter(|node| node.wireguard_public_key.is_none())
        .count();

    // Applying can still reject the package (e.g. an already-expired one) even
    // though the signature verified - don't touch existing local state on that.
    let apply_result = policy_store.apply(response);

    // Audited either way (TT-1820), and best-effort: a failure to *write* the
    // audit entry must not itself change or hide the underlying apply outcome.
    let audit_event = match &apply_result {
        Ok(()) => AuditEvent::PolicyApplied {
            connector_id: config.connector_id.clone(),
            gateway_count: gateways,
            node_count: nodes,
        },
        Err(error) => AuditEvent::PolicyRejected {
            reason: error.to_string(),
        },
    };
    if let Err(audit_error) = audit_log.record(audit_event) {
        error!(error = %audit_error, "failed to write policy audit entry");
    }

    apply_result?;

    info!(gateways, nodes, "Applied verified heartbeat package");
    if nodes_without_key > 0 {
        warn!(
            nodes_without_key,
            "some nodes have no reported WireGuard public key yet - cannot be dialed until Orchestrator reports one"
        );
    }

    dial_new_nodes(tunnel_manager, wg_socket, &node_list).await;

    Ok(())
}

/// Syncs the tunnel set to this heartbeat's node list, then kicks off a
/// handshake for any node that doesn't have an established session yet.
/// Established tunnels are left alone entirely - re-dialing them would
/// discard a working session for no reason.
async fn dial_new_nodes(
    tunnel_manager: &Mutex<TunnelManager>,
    wg_socket: &UdpSocket,
    nodes: &[HeartbeatNode],
) {
    let mut manager = tunnel_manager.lock().await;
    manager.sync_nodes(nodes);

    for node in nodes {
        let Some(tunnel) = manager.tunnel_for(&node.node_id) else {
            continue;
        };
        if tunnel.is_established() {
            continue;
        }
        if let TunnelEvent::SendToNode(packet) = tunnel.initiate_handshake() {
            let addr = tunnel.addr;
            if let Err(error) = wg_socket.send_to(&packet, addr).await {
                error!(%error, node_id = %node.node_id, %addr, "failed to send WireGuard handshake initiation");
            }
        }
    }
}

/// Drives every node tunnel's WireGuard session from the network side:
/// receives a datagram, matches it to the node it came from, feeds it to
/// that tunnel, and sends back whatever the tunnel produces in response
/// (e.g. the initiator's post-handshake keepalive). Runs for the lifetime of
/// the process; a single receive error is logged and the loop continues -
/// one bad datagram must not take down every node's tunnel.
async fn run_wireguard_receive_loop(
    wg_socket: Arc<UdpSocket>,
    tunnel_manager: Arc<Mutex<TunnelManager>>,
) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, src) = match wg_socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(error) => {
                error!(%error, "failed to receive on the WireGuard UDP socket");
                continue;
            }
        };

        let mut manager = tunnel_manager.lock().await;
        let Some(tunnel) = manager.tunnel_for_addr(src) else {
            warn!(%src, "received a WireGuard datagram from an unrecognized peer address");
            continue;
        };

        match tunnel.receive(&buf[..len]) {
            TunnelEvent::SendToNode(packet) => {
                if let Err(error) = wg_socket.send_to(&packet, src).await {
                    error!(%error, %src, "failed to send WireGuard response packet");
                }
            }
            TunnelEvent::ProtocolError(protocol_error) => {
                warn!(error = %protocol_error, %src, "WireGuard protocol error");
            }
            TunnelEvent::DecryptedData(_) | TunnelEvent::Nothing => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(registry_base_url: String, agent_base_url: String) -> Config {
        Config {
            connector_id: "c-1".to_string(),
            agent_base_url,
            agent_ip_address: "10.0.0.5".to_string(),
            registry_base_url,
            identity_key_path: "/tmp/unused-in-this-test".into(),
            audit_log_path: "/tmp/unused-in-this-test-audit.log".into(),
            control_plane_listen_addr: "127.0.0.1:0".to_string(),
            heartbeat_interval: Duration::from_secs(60),
        }
    }

    async fn wg_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    fn read_audit_lines(dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.path().join("audit.log"))
            .map(|contents| {
                contents
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn run_heartbeat_succeeds_against_a_correctly_signed_response() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(policy_store.current().unwrap().connector_id, "c-1");
        let entries = read_audit_lines(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["event"], "policy_applied");
        assert_eq!(entries[0]["gateway_count"], 0);
    }

    #[tokio::test]
    async fn run_heartbeat_surfaces_a_registry_lookup_failure() {
        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&registry_server)
            .await;

        let config = config(registry_server.uri(), "http://127.0.0.1:1".to_string());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
        )
        .await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
        // Failed before ever reaching policy application - nothing to audit yet.
        assert!(read_audit_lines(&dir).is_empty());
    }

    #[tokio::test]
    async fn run_heartbeat_surfaces_a_signature_verification_failure() {
        let agent_identity = crypto::generate_keypair();
        let impostor_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let wrong_signature =
            crypto::sign_to_base64(&impostor_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", wrong_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
        )
        .await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
        // Signature verification failed before policy application - nothing to audit yet.
        assert!(read_audit_lines(&dir).is_empty());
    }

    #[tokio::test]
    async fn run_heartbeat_rejects_an_already_expired_package_and_does_not_apply_it() {
        let agent_identity = crypto::generate_keypair();
        // 2020 is always in the past relative to any real run of this test.
        let body = r#"{"connector_id":"c-1","generated_at":"2020-01-01T09:55:00Z","expires_at":"2020-01-01T10:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
        )
        .await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
        let entries = read_audit_lines(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["event"], "policy_rejected");
    }

    #[tokio::test]
    async fn run_heartbeat_succeeds_and_warns_when_some_nodes_have_no_wireguard_key_yet() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[{"node_id":"n-1","ip_address":"10.0.0.10","wireguard_public_key":null}]}"#;
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;

        // Nodes-without-key is only a warning, not a failure - the cycle still
        // succeeds (there's simply nothing to dial yet for that node).
        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(policy_store.current().unwrap().node_list.len(), 1);
        // No key reported for this node yet, so nothing to dial.
        assert_eq!(tunnel_manager.lock().await.node_count(), 0);
    }

    #[tokio::test]
    async fn run_heartbeat_dials_a_node_that_has_a_reported_wireguard_key() {
        let agent_identity = crypto::generate_keypair();
        let node_identity = boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng);
        let node_public_key_base64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .encode(boringtun::x25519::PublicKey::from(&node_identity).as_bytes())
        };

        // The "node" in this test is a real bound UDP socket, standing in for
        // what a Gatekeeper-side WireGuard interface would receive. Bound to
        // the real WireGuard port, since that's where TunnelManager actually
        // sends - an ephemeral port here would never receive anything.
        let node_socket = UdpSocket::bind(format!("127.0.0.1:{}", tunnel::WIREGUARD_PORT))
            .await
            .unwrap();
        let node_addr = node_socket.local_addr().unwrap();
        let body = format!(
            r#"{{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[{{"node_id":"n-1","ip_address":"{}","wireguard_public_key":"{}"}}]}}"#,
            node_addr.ip(),
            node_public_key_base64
        );
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(tunnel_manager.lock().await.node_count(), 1);

        // A real handshake-initiation packet should have actually arrived at
        // the node's socket.
        let mut buf = [0u8; 2048];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(1), node_socket.recv_from(&mut buf))
                .await
                .expect("handshake initiation packet never arrived")
                .unwrap();
        assert!(len > 0);
        assert_eq!(from, wg_socket.local_addr().unwrap());
    }
}
