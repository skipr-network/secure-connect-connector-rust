//! Calls Agent's `POST /api/connectors/{connectorId}/heartbeat` (TT-1707) and
//! verifies the response before trusting it (TT-1732 acceptance criteria: "verifies
//! the signature before applying the package" / "rejects the package and does not
//! update local policy state" on an invalid signature).
//!
//! The signature travels in the `X-Signature` response header and covers the raw
//! response body bytes exactly as sent - so this verifies against the raw bytes
//! *before* any JSON deserialization, never against a re-serialized copy, which
//! could legitimately produce different bytes (field order, whitespace) than what
//! Agent actually signed.

use anyhow::{Context, Result, bail};
use reqwest::Client;

use crate::crypto;
use crate::dto::ConnectorHeartbeatResponse;

const SIGNATURE_HEADER: &str = "X-Signature";

pub struct HeartbeatClient {
    http: Client,
    agent_base_url: String,
}

impl HeartbeatClient {
    pub fn new(http: Client, agent_base_url: String) -> Self {
        Self {
            http,
            agent_base_url,
        }
    }

    /// Fetches, verifies, and deserializes a Connector heartbeat. `agent_public_key_hex`
    /// must be the specific paired Agent's key (Registry's per-Agent lookup, TT-1742) -
    /// never any registered Agent's key.
    pub async fn fetch_and_verify(
        &self,
        connector_id: &str,
        agent_public_key_hex: &str,
    ) -> Result<ConnectorHeartbeatResponse> {
        let url = format!(
            "{}/api/connectors/{}/heartbeat",
            self.agent_base_url.trim_end_matches('/'),
            connector_id
        );
        let response = self
            .http
            .post(&url)
            .send()
            .await
            .with_context(|| format!("heartbeat request to {url} failed"))?;

        if !response.status().is_success() {
            bail!(
                "Agent returned {} for heartbeat at {url}",
                response.status()
            );
        }

        let signature_base64 = response
            .headers()
            .get(SIGNATURE_HEADER)
            .context("Agent heartbeat response is missing the X-Signature header")?
            .to_str()
            .context("X-Signature header is not valid UTF-8")?
            .to_string();

        let body_bytes = response
            .bytes()
            .await
            .context("failed to read heartbeat response body")?;

        if !crypto::verify_base64(agent_public_key_hex, &body_bytes, &signature_base64) {
            bail!(
                "heartbeat response signature verification failed - rejecting package, not updating local policy state"
            );
        }

        serde_json::from_slice(&body_bytes)
            .context("failed to parse verified heartbeat response body")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SAMPLE_BODY: &str = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2026-08-27T10:05:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;

    #[tokio::test]
    async fn accepts_a_correctly_signed_response() {
        let agent_identity = crypto::generate_keypair();
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, SAMPLE_BODY.as_bytes());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(SAMPLE_BODY, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&server)
            .await;

        let client = HeartbeatClient::new(Client::new(), server.uri());
        let result = client
            .fetch_and_verify("c-1", &agent_identity.public_key_hex)
            .await
            .unwrap();

        assert_eq!(result.connector_id, "c-1");
    }

    #[tokio::test]
    async fn rejects_a_response_signed_by_a_different_key() {
        let agent_identity = crypto::generate_keypair();
        let impostor_identity = crypto::generate_keypair();
        let signature =
            crypto::sign_to_base64(&impostor_identity.signing_key, SAMPLE_BODY.as_bytes());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(SAMPLE_BODY, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&server)
            .await;

        let client = HeartbeatClient::new(Client::new(), server.uri());
        let result = client
            .fetch_and_verify("c-1", &agent_identity.public_key_hex)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_response_missing_the_signature_header() {
        let agent_identity = crypto::generate_keypair();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(SAMPLE_BODY, "application/json"))
            .mount(&server)
            .await;

        let client = HeartbeatClient::new(Client::new(), server.uri());
        let result = client
            .fetch_and_verify("c-1", &agent_identity.public_key_hex)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_tampered_body_even_with_a_valid_signature_for_the_original() {
        let agent_identity = crypto::generate_keypair();
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, SAMPLE_BODY.as_bytes());
        let tampered_body = r#"{"connector_id":"c-EVIL","generated_at":"2026-08-27T10:00:00Z","expires_at":"2026-08-27T10:05:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(tampered_body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&server)
            .await;

        let client = HeartbeatClient::new(Client::new(), server.uri());
        let result = client
            .fetch_and_verify("c-1", &agent_identity.public_key_hex)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn propagates_an_error_on_non_success_status() {
        let agent_identity = crypto::generate_keypair();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = HeartbeatClient::new(Client::new(), server.uri());
        let result = client
            .fetch_and_verify("c-1", &agent_identity.public_key_hex)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn returns_an_error_when_agent_is_unreachable() {
        let agent_identity = crypto::generate_keypair();
        let client = HeartbeatClient::new(Client::new(), "http://127.0.0.1:1".to_string());

        let result = client
            .fetch_and_verify("c-1", &agent_identity.public_key_hex)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_verified_response_whose_body_does_not_match_the_expected_shape() {
        let agent_identity = crypto::generate_keypair();
        let malformed_body = r#"{"unexpected":"shape"}"#;
        let signature =
            crypto::sign_to_base64(&agent_identity.signing_key, malformed_body.as_bytes());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(malformed_body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&server)
            .await;

        let client = HeartbeatClient::new(Client::new(), server.uri());
        let result = client
            .fetch_and_verify("c-1", &agent_identity.public_key_hex)
            .await;

        assert!(result.is_err());
    }
}
