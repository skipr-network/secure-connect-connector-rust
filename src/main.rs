mod config;
mod crypto;
mod dto;
mod heartbeat;
mod identity;
mod registry_client;

use config::Config;
use heartbeat::HeartbeatClient;
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

    let mut interval = tokio::time::interval(config.heartbeat_interval);
    loop {
        interval.tick().await;
        if let Err(error) = run_heartbeat(&config, &registry_client, &heartbeat_client).await {
            error!(%error, "heartbeat cycle failed");
        }
    }
}

async fn run_heartbeat(
    config: &Config,
    registry_client: &RegistryClient,
    heartbeat_client: &HeartbeatClient,
) -> anyhow::Result<()> {
    let agent_public_key = registry_client
        .get_agent_permitted_key(&config.agent_ip_address)
        .await?;
    let response = heartbeat_client
        .fetch_and_verify(&config.connector_id, &agent_public_key)
        .await?;

    info!(
        gateways = response.policy_bundles.len(),
        nodes = response.node_list.len(),
        expires_at = %response.expires_at,
        "Verified heartbeat package received"
    );

    let nodes_without_key = response
        .node_list
        .iter()
        .filter(|node| node.wireguard_public_key.is_none())
        .count();
    if nodes_without_key > 0 {
        warn!(
            nodes_without_key,
            "some nodes have no reported WireGuard public key yet - cannot be dialed until Orchestrator reports one"
        );
    }

    // Policy application, node tunnels, and enforcement land in later TT-1732 slices.
    Ok(())
}
