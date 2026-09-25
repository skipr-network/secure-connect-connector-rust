//! Calls Agent's `POST /api/connectors/heartbeat` (TT-1707, keyed by public key since TT-2210)
//! and verifies the response before trusting it (TT-1732 acceptance criteria: "verifies the
//! signature before applying the package" / "rejects the package and does not update local
//! policy state" on an invalid signature).
//!
//! The signature travels in the `X-Signature` response header and covers the raw
//! response body bytes exactly as sent - so this verifies against the raw bytes
//! *before* any JSON deserialization, never against a re-serialized copy, which
//! could legitimately produce different bytes (field order, whitespace) than what
//! Agent actually signed.
//!
//! The Connector identifies itself by its own public key in the request body (TT-2210) rather
//! than a `connector_id` in the path: that key is the only identity it has before an admin
//! registers it, so nothing has to be configured on its host afterwards. Until then Agent answers
//! "not registered" (spec §B.4 point 1) - see [`AgentRejected`].
//!
//! The request itself (`ConnectorHeartbeatRequest`, TT-2069) carries no signature the other
//! direction - this call has never had any per-request authentication (any caller who can reach
//! this URL for a given Connector already gets back that connector's real, signed policy bundle),
//! so a request body doesn't introduce a new trust boundary, only extends the existing one it
//! already operates under.

use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Client, StatusCode};

use crate::crypto;
use crate::dto::{ConnectorHeartbeatRequest, ConnectorHeartbeatResponse};

const SIGNATURE_HEADER: &str = "X-Signature";

/// Bounds one heartbeat round trip, which includes Agent's own composition call to Portal. The
/// shared client only bounds connecting (see `main`); without an overall cap, an Agent that
/// accepted the connection and then hung would stall the whole cycle - and failover to another
/// Agent with it - indefinitely.
const HEARTBEAT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Portal's reason code for a public key no admin has registered yet, relayed unchanged by Agent.
const NOT_REGISTERED_REASON: &str = "connectornotregistered";

/// Agent answered, and the answer is a refusal (HTTP 400): a decision, not an outage - the most
/// common one being "not registered" for a key no admin has pasted into Portal yet. Kept distinct
/// from every other failure so the caller doesn't fail over to a different Agent for it (any Agent
/// would say the same) and can log it as the expected waiting state it is.
#[derive(Debug)]
pub struct AgentRejected {
    pub status: StatusCode,
    pub reason: Option<String>,
}

impl AgentRejected {
    pub fn is_not_registered(&self) -> bool {
        self.reason
            .as_deref()
            .is_some_and(|reason| reason.contains(NOT_REGISTERED_REASON))
    }
}

impl fmt::Display for AgentRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            Some(reason) => write!(f, "Agent refused the heartbeat ({}): {reason}", self.status),
            None => write!(f, "Agent refused the heartbeat ({})", self.status),
        }
    }
}

impl std::error::Error for AgentRejected {}

pub struct HeartbeatClient {
    http: Client,
}

impl HeartbeatClient {
    pub fn new(http: Client) -> Self {
        Self { http }
    }

    /// Fetches, verifies, and deserializes a Connector heartbeat from the Agent at
    /// `agent_base_url`. `agent_public_key_hex` must be that specific Agent's key (Registry's
    /// per-Agent lookup, TT-1742) - never any registered Agent's key. `request` carries this
    /// Connector's own public key and observed state (TT-2069) - the hosts, if any, `dns_cache`
    /// still couldn't resolve as of the previous cycle.
    ///
    /// Fails with [`AgentRejected`] when Agent answers with a refusal, and with a plain error for
    /// anything else (unreachable, 5xx, bad signature, wrong shape).
    pub async fn fetch_and_verify(
        &self,
        agent_base_url: &str,
        agent_public_key_hex: &str,
        request: &ConnectorHeartbeatRequest,
    ) -> Result<ConnectorHeartbeatResponse> {
        let url = format!(
            "{}/api/connectors/heartbeat",
            agent_base_url.trim_end_matches('/')
        );
        let response = self
            .http
            .post(&url)
            .timeout(HEARTBEAT_REQUEST_TIMEOUT)
            .json(request)
            .send()
            .await
            .with_context(|| format!("heartbeat request to {url} failed"))?;

        let status = response.status();
        if status == StatusCode::BAD_REQUEST {
            let reason = response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|body| body.get("reason")?.as_str().map(str::to_string));
            return Err(AgentRejected { status, reason }.into());
        }
        if !status.is_success() {
            bail!("Agent returned {status} for heartbeat at {url}");
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

        let parsed: ConnectorHeartbeatResponse = serde_json::from_slice(&body_bytes)
            .context("failed to parse verified heartbeat response body")?;

        // Genuinely signed by this Agent, but only trustworthy as *this* Connector's policy if it
        // was composed for this Connector's own key - the connector_id in it is Portal's, not
        // something this Connector knows to compare against.
        if parsed.connector_public_key.as_deref() != Some(request.connector_public_key.as_str()) {
            bail!(
                "verified heartbeat response is for public key {:?}, not this Connector's - rejecting package, not updating local policy state",
                parsed.connector_public_key
            );
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SAMPLE_BODY: &str = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2026-08-27T10:05:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;

    fn request() -> ConnectorHeartbeatRequest {
        ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            unresolved_endpoint_hosts: None,
        }
    }

    async fn agent_answering(body: &str, signature: Option<&str>) -> MockServer {
        let server = MockServer::start().await;
        let mut template = ResponseTemplate::new(200).set_body_raw(body, "application/json");
        if let Some(signature) = signature {
            template = template.insert_header("X-Signature", signature);
        }
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(template)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn accepts_a_correctly_signed_response() {
        let agent_identity = crypto::generate_keypair();
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, SAMPLE_BODY.as_bytes());
        let server = agent_answering(SAMPLE_BODY, Some(&signature)).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await
            .unwrap();

        assert_eq!(result.connector_id, "c-1");
        assert_eq!(result.connector_public_key.as_deref(), Some("pk-1"));
    }

    #[tokio::test]
    async fn rejects_a_response_signed_by_a_different_key() {
        let agent_identity = crypto::generate_keypair();
        let impostor_identity = crypto::generate_keypair();
        let signature =
            crypto::sign_to_base64(&impostor_identity.signing_key, SAMPLE_BODY.as_bytes());
        let server = agent_answering(SAMPLE_BODY, Some(&signature)).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_response_missing_the_signature_header() {
        let agent_identity = crypto::generate_keypair();
        let server = agent_answering(SAMPLE_BODY, None).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_tampered_body_even_with_a_valid_signature_for_the_original() {
        let agent_identity = crypto::generate_keypair();
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, SAMPLE_BODY.as_bytes());
        let tampered_body = r#"{"connector_id":"c-EVIL","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2026-08-27T10:05:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let server = agent_answering(tampered_body, Some(&signature)).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await;

        assert!(result.is_err());
    }

    /// TT-2210: a genuinely signed envelope composed for some other Connector's key must never be
    /// applied as this Connector's policy.
    #[tokio::test]
    async fn rejects_a_verified_response_composed_for_a_different_public_key() {
        let agent_identity = crypto::generate_keypair();
        let other_connectors_body = r#"{"connector_id":"c-2","connector_public_key":"pk-2","generated_at":"2026-08-27T10:00:00Z","expires_at":"2026-08-27T10:05:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let signature = crypto::sign_to_base64(
            &agent_identity.signing_key,
            other_connectors_body.as_bytes(),
        );
        let server = agent_answering(other_connectors_body, Some(&signature)).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_verified_response_that_names_no_public_key() {
        let agent_identity = crypto::generate_keypair();
        let keyless_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2026-08-27T10:05:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let signature =
            crypto::sign_to_base64(&agent_identity.signing_key, keyless_body.as_bytes());
        let server = agent_answering(keyless_body, Some(&signature)).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn propagates_an_error_on_non_success_status() {
        let agent_identity = crypto::generate_keypair();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let error = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await
            .unwrap_err();

        assert!(
            error.downcast_ref::<AgentRejected>().is_none(),
            "a 5xx is an outage, not a refusal - it must stay eligible for failover"
        );
    }

    /// Spec §B.4 point 1: an unregistered key is a refusal Agent relays from Portal, told apart
    /// from an outage so the caller keeps waiting instead of failing over.
    #[tokio::test]
    async fn reports_not_registered_as_an_agent_rejection() {
        let agent_identity = crypto::generate_keypair();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "title": "The portal refused the request.",
                "reason": "error.connectornotregistered"
            })))
            .mount(&server)
            .await;

        let error = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await
            .unwrap_err();

        let rejection = error.downcast_ref::<AgentRejected>().unwrap();
        assert!(rejection.is_not_registered());
    }

    #[tokio::test]
    async fn a_400_with_any_other_reason_is_a_rejection_but_not_not_registered() {
        let agent_identity = crypto::generate_keypair();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(ResponseTemplate::new(400).set_body_string("not json"))
            .mount(&server)
            .await;

        let error = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await
            .unwrap_err();

        let rejection = error.downcast_ref::<AgentRejected>().unwrap();
        assert!(!rejection.is_not_registered());
        assert_eq!(rejection.reason, None);
    }

    #[tokio::test]
    async fn returns_an_error_when_agent_is_unreachable() {
        let agent_identity = crypto::generate_keypair();

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(
                "http://127.0.0.1:1",
                &agent_identity.public_key_hex,
                &request(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_verified_response_whose_body_does_not_match_the_expected_shape() {
        let agent_identity = crypto::generate_keypair();
        let malformed_body = r#"{"unexpected":"shape"}"#;
        let signature =
            crypto::sign_to_base64(&agent_identity.signing_key, malformed_body.as_bytes());
        let server = agent_answering(malformed_body, Some(&signature)).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sends_the_public_key_and_unresolved_endpoint_hosts_in_the_request_body() {
        // TT-2069/TT-2210: proven against the actual request Agent receives, not just that
        // ConnectorHeartbeatRequest serializes correctly in isolation (dto.rs already covers
        // that) - this is what closes the loop on the request ever actually reaching Agent.
        let agent_identity = crypto::generate_keypair();
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, SAMPLE_BODY.as_bytes());
        let request = ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            unresolved_endpoint_hosts: Some(vec!["crm.internal.example.com".to_string()]),
        };

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .and(body_json(&request))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(SAMPLE_BODY, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&server)
            .await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(&server.uri(), &agent_identity.public_key_hex, &request)
            .await;

        assert!(
            result.is_ok(),
            "request body must match exactly what was passed in, or wiremock's body_json \
             matcher above would have refused the request with a 404"
        );
    }
}
