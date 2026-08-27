mod access;
mod config;
mod crypto;
mod dto;
mod heartbeat;
mod identity;
mod policy;
mod registry_client;

use config::Config;
use heartbeat::HeartbeatClient;
use policy::PolicyStore;
use registry_client::RegistryClient;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    let connector_identity = identity::load_or_generate(&config.identity_key_path)?;
    info!(
        connector_id = %config.connector_id,
        public_key = %connector_identity.public_key_hex,
        "Connector identity ready"
    );

    let http = reqwest::Client::new();
    let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
    let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
    let policy_store = PolicyStore::new();

    let mut interval = tokio::time::interval(config.heartbeat_interval);
    loop {
        interval.tick().await;
        if let Err(error) =
            run_heartbeat(&config, &registry_client, &heartbeat_client, &policy_store).await
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
) -> anyhow::Result<()> {
    let agent_public_key = registry_client
        .get_agent_permitted_key(&config.agent_ip_address)
        .await?;
    let response = heartbeat_client
        .fetch_and_verify(&config.connector_id, &agent_public_key)
        .await?;

    let gateways = response.policy_bundles.len();
    let nodes = response.node_list.len();
    let nodes_without_key = response
        .node_list
        .iter()
        .filter(|node| node.wireguard_public_key.is_none())
        .count();

    // Applying can still reject the package (e.g. an already-expired one) even
    // though the signature verified - don't touch existing local state on that.
    policy_store.apply(response)?;

    info!(gateways, nodes, "Applied verified heartbeat package");
    if nodes_without_key > 0 {
        warn!(
            nodes_without_key,
            "some nodes have no reported WireGuard public key yet - cannot be dialed until Orchestrator reports one"
        );
    }

    // Node tunnels and traffic enforcement land in later TT-1732 slices.
    Ok(())
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
            heartbeat_interval: Duration::from_secs(60),
        }
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

        let result =
            run_heartbeat(&config, &registry_client, &heartbeat_client, &policy_store).await;

        assert!(result.is_ok());
        assert_eq!(policy_store.current().unwrap().connector_id, "c-1");
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

        let result =
            run_heartbeat(&config, &registry_client, &heartbeat_client, &policy_store).await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
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

        let result =
            run_heartbeat(&config, &registry_client, &heartbeat_client, &policy_store).await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
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

        let result =
            run_heartbeat(&config, &registry_client, &heartbeat_client, &policy_store).await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
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

        // Nodes-without-key is only a warning, not a failure - the cycle still
        // succeeds (there's simply nothing to dial yet for that node).
        let result =
            run_heartbeat(&config, &registry_client, &heartbeat_client, &policy_store).await;

        assert!(result.is_ok());
        assert_eq!(policy_store.current().unwrap().node_list.len(), 1);
    }
}
