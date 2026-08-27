//! Registry client for the one call the Connector needs today: looking up its
//! paired Agent's Ed25519 public key by IP (TT-1742), so the Connector verifies
//! a heartbeat response against that specific Agent - never any registered Agent
//! globally, per the confirmed TT-1732 contract decision.

use anyhow::{Context, Result, bail};
use reqwest::Client;

use crate::dto::AgentPermittedKeyResponse;

pub struct RegistryClient {
    http: Client,
    base_url: String,
}

impl RegistryClient {
    pub fn new(http: Client, base_url: String) -> Self {
        Self { http, base_url }
    }

    /// `GET /api/agents/{ipAddress}/permitted-key`
    pub async fn get_agent_permitted_key(&self, agent_ip_address: &str) -> Result<String> {
        let url = format!(
            "{}/api/agents/{}/permitted-key",
            self.base_url.trim_end_matches('/'),
            agent_ip_address
        );
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?;

        if !response.status().is_success() {
            bail!("Registry returned {} for {url}", response.status());
        }

        let body: AgentPermittedKeyResponse = response
            .json()
            .await
            .with_context(|| format!("failed to parse Registry response from {url}"))?;
        Ok(body.permitted_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn fetches_the_permitted_key_for_an_agent_ip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": "abc123"
            })))
            .mount(&server)
            .await;

        let client = RegistryClient::new(Client::new(), server.uri());
        let key = client.get_agent_permitted_key("10.0.0.5").await.unwrap();

        assert_eq!(key, "abc123");
    }

    #[tokio::test]
    async fn returns_an_error_when_registry_responds_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.99/permitted-key"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = RegistryClient::new(Client::new(), server.uri());

        assert!(client.get_agent_permitted_key("10.0.0.99").await.is_err());
    }

    #[tokio::test]
    async fn returns_an_error_when_registry_is_unreachable() {
        // A genuine transport-level failure (connection refused), distinct from
        // an HTTP-level error status.
        let client = RegistryClient::new(Client::new(), "http://127.0.0.1:1".to_string());

        assert!(client.get_agent_permitted_key("10.0.0.5").await.is_err());
    }

    #[tokio::test]
    async fn returns_an_error_when_the_response_body_is_not_valid_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = RegistryClient::new(Client::new(), server.uri());

        assert!(client.get_agent_permitted_key("10.0.0.5").await.is_err());
    }
}
