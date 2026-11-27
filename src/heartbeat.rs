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
//! TT-3717 (spec §B.4 point 4): each request carries the Connector request proof when the caller
//! has a key for that Agent - a MAC over the exact body bytes sent, so the body is serialized once
//! and those bytes are both MACed and sent. The Agent refuses a bad proof with `401` and a
//! `reason`, read here into [`ProofRefused`] - unlike [`AgentRejected`], a refusal for this Agent
//! instance only, so the caller moves on to the next one.
//!
//! TT-3767: the Agent answers `429` (`connectorratelimited`, with `Retry-After`) when it rate
//! limits proof checking - read here into [`RateLimited`] only so the caller can log it as what it
//! is; it is still handled like any other failure of that Agent.

use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Client, Response, StatusCode};
use serde::Serialize;

use crate::crypto;
use crate::dto::{
    ConnectorDeregisterRequest, ConnectorDeregisterResponse, ConnectorHeartbeatRequest,
    ConnectorHeartbeatResponse,
};
use crate::request_proof::AgentProofKey;

/// Also the path MACed into the request proof (spec §B.4 point 4).
pub const HEARTBEAT_PATH: &str = "/api/connectors/heartbeat";
pub const DEREGISTER_PATH: &str = "/api/connectors/deregister";

const SIGNATURE_HEADER: &str = "X-Signature";

/// Bounds one heartbeat round trip, which includes Agent's own composition call to Portal. The
/// shared client only bounds connecting (see `main`); without an overall cap, an Agent that
/// accepted the connection and then hung would stall the whole cycle - and failover to another
/// Agent with it - indefinitely.
const HEARTBEAT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Portal's reason code for a public key no admin has registered yet, relayed unchanged by Agent.
const NOT_REGISTERED_REASON: &str = "connectornotregistered";

/// TT-2126: Portal's reason code for a deregistration of a Connector no admin has confirmed for decommissioning.
const NOT_DECOMMISSIONING_REASON: &str = "connectornotdecommissioning";

/// TT-2126: the only deregistration status the host acts on.
const DEREGISTERED_STATUS: &str = "DEREGISTERED";

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

    pub fn is_not_decommissioning(&self) -> bool {
        self.reason
            .as_deref()
            .is_some_and(|reason| reason.contains(NOT_DECOMMISSIONING_REASON))
    }
}

impl fmt::Display for AgentRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            Some(reason) => write!(f, "Agent refused the request ({}): {reason}", self.status),
            None => write!(f, "Agent refused the request ({})", self.status),
        }
    }
}

impl std::error::Error for AgentRejected {}

/// TT-3717: why an Agent refused the Connector request proof (spec §B.4 point 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRefusal {
    /// MAC wrong, malformed, partial or unknown version - possibly a rotated Agent key.
    Invalid,
    /// Timestamp outside the Agent's window - most likely this host's clock.
    Expired,
    Replayed,
    /// No proof, after the migration end date or from a Connector that has proven itself before.
    Required,
}

impl ProofRefusal {
    fn from_reason(reason: &str) -> Option<Self> {
        // `contains`, like the reasons above: they may arrive prefixed (`error.`).
        [
            ("connectorproofinvalid", Self::Invalid),
            ("connectorproofexpired", Self::Expired),
            ("connectorproofreplayed", Self::Replayed),
            ("connectorproofrequired", Self::Required),
        ]
        .into_iter()
        .find_map(|(code, refusal)| reason.contains(code).then_some(refusal))
    }
}

/// TT-3717: the Agent answered `401` with a proof refusal. Unlike [`AgentRejected`] this is about
/// this Agent instance (each has its own key), so the caller moves on to the next one.
#[derive(Debug)]
pub struct ProofRefused {
    pub refusal: ProofRefusal,
    pub reason: String,
}

impl fmt::Display for ProofRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Agent refused the request proof: {}", self.reason)
    }
}

impl std::error::Error for ProofRefused {}

/// TT-3767 (TT-3717): the Agent answered `429` - it rate limits proof checking per address, per
/// Connector key and by concurrent verifications. A limit of this Agent instance, so the caller
/// moves on to the next Agent as for any other failure; kept distinct only so it is logged as rate
/// limiting rather than as an Agent that did not answer. `Retry-After` is logged, not honoured.
#[derive(Debug)]
pub struct RateLimited {
    pub retry_after: Option<String>,
    pub reason: Option<String>,
}

impl RateLimited {
    async fn from_response(response: Response) -> Self {
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let reason = reason_of(response).await;
        Self {
            retry_after,
            reason,
        }
    }
}

impl fmt::Display for RateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Agent rate limited the request")?;
        if let Some(reason) = &self.reason {
            write!(f, " ({reason})")?;
        }
        if let Some(retry_after) = &self.retry_after {
            write!(f, ", Retry-After {retry_after}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RateLimited {}

async fn reason_of(response: Response) -> Option<String> {
    response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|body| body.get("reason")?.as_str().map(str::to_string))
}

/// A `401` naming a proof refusal becomes [`ProofRefused`]; any other `401` stays a plain error.
async fn proof_refused_or_unauthorized(response: Response, url: &str) -> anyhow::Error {
    match reason_of(response).await {
        Some(reason) => match ProofRefusal::from_reason(&reason) {
            Some(refusal) => ProofRefused { refusal, reason }.into(),
            None => anyhow::anyhow!("Agent returned 401 ({reason}) at {url}"),
        },
        None => anyhow::anyhow!("Agent returned 401 at {url}"),
    }
}

pub struct HeartbeatClient {
    http: Client,
}

impl HeartbeatClient {
    pub fn new(http: Client) -> Self {
        Self { http }
    }

    /// Posts `body` as JSON, with the request proof for this Agent when there is a key for it.
    /// The body is serialized once: the proof covers exactly the bytes sent.
    async fn post(
        &self,
        agent_base_url: &str,
        path: &str,
        body: &impl Serialize,
        proof_key: Option<&AgentProofKey>,
    ) -> Result<(String, Response)> {
        let url = format!("{}{path}", agent_base_url.trim_end_matches('/'));
        let body = serde_json::to_vec(body).context("failed to serialize the request body")?;
        let mut request = self
            .http
            .post(&url)
            .timeout(HEARTBEAT_REQUEST_TIMEOUT)
            .header(CONTENT_TYPE, "application/json");
        if let Some(proof_key) = proof_key {
            // A new timestamp on every attempt: the Agent refuses a MAC it has already accepted.
            let timestamp_ms = chrono::Utc::now().timestamp_millis();
            for (name, value) in proof_key.headers("POST", path, &body, timestamp_ms) {
                request = request.header(name, value);
            }
        }
        let response = request
            .body(body)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?;
        Ok((url, response))
    }

    /// Fetches, verifies, and deserializes a Connector heartbeat from the Agent at
    /// `agent_base_url`. `agent_public_key_hex` must be that specific Agent's key (Registry's
    /// per-Agent lookup, TT-1742) - never any registered Agent's key. `request` carries this
    /// Connector's own public key and observed state (TT-2069) - the hosts, if any, `dns_cache`
    /// still couldn't resolve as of the previous cycle.
    ///
    /// `proof_key` is this Agent's request-proof key (TT-3717); `None` sends no proof.
    ///
    /// Fails with [`AgentRejected`] when Agent answers with a refusal, with [`ProofRefused`] when
    /// it refuses the proof, with [`RateLimited`] on a `429`, and with a plain error for anything
    /// else (unreachable, 5xx, bad signature, wrong shape).
    pub async fn fetch_and_verify(
        &self,
        agent_base_url: &str,
        agent_public_key_hex: &str,
        proof_key: Option<&AgentProofKey>,
        request: &ConnectorHeartbeatRequest,
    ) -> Result<ConnectorHeartbeatResponse> {
        let (url, response) = self
            .post(agent_base_url, HEARTBEAT_PATH, request, proof_key)
            .await
            .context("heartbeat request failed")?;

        let status = response.status();
        if status == StatusCode::BAD_REQUEST {
            let reason = reason_of(response).await;
            return Err(AgentRejected { status, reason }.into());
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(proof_refused_or_unauthorized(response, &url).await);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(RateLimited::from_response(response).await.into());
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

    /// TT-2126 (spec §B.19 point 4): asks Agent to deregister this Connector during its guided decommissioning,
    /// and accepts the answer only as a heartbeat response would be accepted - signed by this Agent, for this
    /// Connector's own key - and only while it has not expired: the host removes its service and key on it.
    ///
    /// Fails with [`AgentRejected`] for Portal's refusals (400 `connectornotregistered`, 409
    /// `connectornotdecommissioning`), with [`ProofRefused`] when the Agent refuses the request
    /// proof (TT-3717), with [`RateLimited`] on a `429` (TT-3767), and with a plain error for
    /// anything else.
    pub async fn deregister_and_verify(
        &self,
        agent_base_url: &str,
        agent_public_key_hex: &str,
        proof_key: Option<&AgentProofKey>,
        request: &ConnectorDeregisterRequest,
    ) -> Result<ConnectorDeregisterResponse> {
        let (url, response) = self
            .post(agent_base_url, DEREGISTER_PATH, request, proof_key)
            .await
            .context("deregistration request failed")?;

        let status = response.status();
        if status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT {
            let reason = reason_of(response).await;
            return Err(AgentRejected { status, reason }.into());
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(proof_refused_or_unauthorized(response, &url).await);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(RateLimited::from_response(response).await.into());
        }
        if !status.is_success() {
            bail!("Agent returned {status} for the deregistration at {url}");
        }

        let signature_base64 = response
            .headers()
            .get(SIGNATURE_HEADER)
            .context("Agent deregistration response is missing the X-Signature header")?
            .to_str()
            .context("X-Signature header is not valid UTF-8")?
            .to_string();
        let body_bytes = response
            .bytes()
            .await
            .context("failed to read the deregistration response body")?;
        if !crypto::verify_base64(agent_public_key_hex, &body_bytes, &signature_base64) {
            bail!("deregistration response signature verification failed - not trusting it");
        }
        let parsed: ConnectorDeregisterResponse = serde_json::from_slice(&body_bytes)
            .context("failed to parse the verified deregistration response")?;
        if parsed.connector_public_key != request.connector_public_key {
            bail!(
                "verified deregistration response is for public key {:?}, not this Connector's - not trusting it",
                parsed.connector_public_key
            );
        }
        // The host removes its service, key and configuration on this answer: act only on the one status that
        // means the Portal record is gone.
        if parsed.status != DEREGISTERED_STATUS {
            bail!(
                "deregistration response has status {:?}, not {DEREGISTERED_STATUS} - not trusting it",
                parsed.status
            );
        }
        let expires_at =
            chrono::DateTime::parse_from_rfc3339(&parsed.expires_at).with_context(|| {
                format!(
                    "deregistration response expires_at {:?} is not a timestamp",
                    parsed.expires_at
                )
            })?;
        if expires_at <= chrono::Utc::now() {
            bail!("deregistration response expired at {expires_at} - not trusting it");
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
            ended_flows: vec![],
            connection_events: Vec::new(),
            connection_events_lost: None,
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_a_response_missing_the_signature_header() {
        let agent_identity = crypto::generate_keypair();
        let server = agent_answering(SAMPLE_BODY, None).await;

        let result = HeartbeatClient::new(Client::new())
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
            .await
            .unwrap_err();

        let rejection = error.downcast_ref::<AgentRejected>().unwrap();
        assert!(rejection.is_not_registered());
    }

    /// TT-3717: a proof refusal is read from a 401 and kept apart from a refusal every Agent
    /// would give (`AgentRejected`).
    #[tokio::test]
    async fn reads_each_proof_refusal_from_a_401() {
        for (reason, refusal) in [
            ("error.connectorproofinvalid", ProofRefusal::Invalid),
            ("error.connectorproofexpired", ProofRefusal::Expired),
            ("error.connectorproofreplayed", ProofRefusal::Replayed),
            ("error.connectorproofrequired", ProofRefusal::Required),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/connectors/heartbeat"))
                .respond_with(
                    ResponseTemplate::new(401)
                        .set_body_json(serde_json::json!({ "reason": reason })),
                )
                .mount(&server)
                .await;

            let error = HeartbeatClient::new(Client::new())
                .fetch_and_verify(&server.uri(), "unused", None, &request())
                .await
                .unwrap_err();

            assert_eq!(
                error.downcast_ref::<ProofRefused>().unwrap().refusal,
                refusal
            );
            assert!(error.downcast_ref::<AgentRejected>().is_none());
        }
    }

    #[tokio::test]
    async fn a_401_without_a_proof_reason_is_a_plain_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/deregister"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let error = HeartbeatClient::new(Client::new())
            .deregister_and_verify(&server.uri(), "unused", None, &deregister_request())
            .await
            .unwrap_err();

        assert!(error.downcast_ref::<ProofRefused>().is_none());
        assert!(error.downcast_ref::<AgentRejected>().is_none());
    }

    /// TT-3767: a `429` is read as rate limiting - with the Agent's reason and `Retry-After` - on
    /// both routes, and is neither a refusal nor a proof refusal.
    #[tokio::test]
    async fn reads_a_429_as_rate_limited_on_both_routes() {
        for route in [HEARTBEAT_PATH, DEREGISTER_PATH] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(
                    ResponseTemplate::new(429)
                        .insert_header("Retry-After", "30")
                        .set_body_json(serde_json::json!({ "reason": "connectorratelimited" })),
                )
                .mount(&server)
                .await;
            let client = HeartbeatClient::new(Client::new());

            let error = if route == HEARTBEAT_PATH {
                client
                    .fetch_and_verify(&server.uri(), "unused", None, &request())
                    .await
                    .unwrap_err()
            } else {
                client
                    .deregister_and_verify(&server.uri(), "unused", None, &deregister_request())
                    .await
                    .unwrap_err()
            };

            let limited = error.downcast_ref::<RateLimited>().expect(route);
            assert_eq!(limited.retry_after.as_deref(), Some("30"), "{route}");
            assert_eq!(limited.reason.as_deref(), Some("connectorratelimited"));
            assert!(error.downcast_ref::<AgentRejected>().is_none(), "{route}");
            assert!(error.downcast_ref::<ProofRefused>().is_none(), "{route}");
            assert_eq!(
                error.to_string(),
                "Agent rate limited the request (connectorratelimited), Retry-After 30"
            );
        }
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
                None,
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request(),
            )
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
            ended_flows: vec![],
            connection_events: Vec::new(),
            connection_events_lost: None,
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
            .fetch_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &request,
            )
            .await;

        assert!(
            result.is_ok(),
            "request body must match exactly what was passed in, or wiremock's body_json \
             matcher above would have refused the request with a 404"
        );
    }

    // --- TT-2126: deregistration (spec §B.19 point 4) ---

    fn deregister_request() -> ConnectorDeregisterRequest {
        ConnectorDeregisterRequest {
            connector_public_key: "pk-1".to_string(),
        }
    }

    fn confirmation(public_key: &str, expires_at: &str) -> String {
        format!(
            r#"{{"connector_id":"c-1","connector_public_key":"{public_key}","status":"DEREGISTERED","generated_at":"2026-10-13T10:00:00Z","expires_at":"{expires_at}","nonce":"n1"}}"#
        )
    }

    async fn agent_deregistering(template: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/deregister"))
            .and(body_json(
                serde_json::json!({ "connector_public_key": "pk-1" }),
            ))
            .respond_with(template)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn accepts_a_signed_current_deregistration_for_its_own_key() {
        let agent_identity = crypto::generate_keypair();
        let body = confirmation("pk-1", "2099-01-01T00:00:00Z");
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());
        let server = agent_deregistering(
            ResponseTemplate::new(200)
                .set_body_raw(body, "application/json")
                .insert_header("X-Signature", signature.as_str()),
        )
        .await;

        let confirmed = HeartbeatClient::new(Client::new())
            .deregister_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &deregister_request(),
            )
            .await
            .unwrap();

        assert_eq!(confirmed.connector_id, "c-1");
        assert_eq!(confirmed.status, "DEREGISTERED");
    }

    #[tokio::test]
    async fn rejects_a_deregistration_signed_by_another_key() {
        let agent_identity = crypto::generate_keypair();
        let impostor = crypto::generate_keypair();
        let body = confirmation("pk-1", "2099-01-01T00:00:00Z");
        let signature = crypto::sign_to_base64(&impostor.signing_key, body.as_bytes());
        let server = agent_deregistering(
            ResponseTemplate::new(200)
                .set_body_raw(body, "application/json")
                .insert_header("X-Signature", signature.as_str()),
        )
        .await;

        let error = HeartbeatClient::new(Client::new())
            .deregister_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &deregister_request(),
            )
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("signature verification failed"));
    }

    #[tokio::test]
    async fn rejects_a_deregistration_for_another_connectors_key() {
        let agent_identity = crypto::generate_keypair();
        let body = confirmation("pk-other", "2099-01-01T00:00:00Z");
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());
        let server = agent_deregistering(
            ResponseTemplate::new(200)
                .set_body_raw(body, "application/json")
                .insert_header("X-Signature", signature.as_str()),
        )
        .await;

        let error = HeartbeatClient::new(Client::new())
            .deregister_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &deregister_request(),
            )
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("not this Connector's"));
    }

    /// A captured old confirmation replayed later must not make a host remove its key.
    #[tokio::test]
    async fn rejects_an_expired_deregistration() {
        let agent_identity = crypto::generate_keypair();
        let body = confirmation("pk-1", "2026-01-01T00:00:00Z");
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());
        let server = agent_deregistering(
            ResponseTemplate::new(200)
                .set_body_raw(body, "application/json")
                .insert_header("X-Signature", signature.as_str()),
        )
        .await;

        let error = HeartbeatClient::new(Client::new())
            .deregister_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &deregister_request(),
            )
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("expired"));
    }

    /// A signed, current answer for its own key with any other status removes nothing.
    #[tokio::test]
    async fn rejects_a_deregistration_with_another_status() {
        let agent_identity = crypto::generate_keypair();
        let body = confirmation("pk-1", "2099-01-01T00:00:00Z").replace("DEREGISTERED", "PENDING");
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());
        let server = agent_deregistering(
            ResponseTemplate::new(200)
                .set_body_raw(body, "application/json")
                .insert_header("X-Signature", signature.as_str()),
        )
        .await;

        let error = HeartbeatClient::new(Client::new())
            .deregister_and_verify(
                &server.uri(),
                &agent_identity.public_key_hex,
                None,
                &deregister_request(),
            )
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("not DEREGISTERED"));
    }

    #[tokio::test]
    async fn a_409_not_decommissioning_is_an_agent_refusal() {
        let server =
            agent_deregistering(ResponseTemplate::new(409).set_body_json(
                serde_json::json!({ "reason": "error.connectornotdecommissioning" }),
            ))
            .await;

        let error = HeartbeatClient::new(Client::new())
            .deregister_and_verify(&server.uri(), "unused", None, &deregister_request())
            .await
            .unwrap_err();

        let rejected = error.downcast_ref::<AgentRejected>().expect("a refusal");
        assert!(rejected.is_not_decommissioning());
        assert!(!rejected.is_not_registered());
    }

    #[tokio::test]
    async fn a_400_not_registered_is_an_agent_refusal() {
        let server = agent_deregistering(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "reason": "error.connectornotregistered" })),
        )
        .await;

        let error = HeartbeatClient::new(Client::new())
            .deregister_and_verify(&server.uri(), "unused", None, &deregister_request())
            .await
            .unwrap_err();

        assert!(
            error
                .downcast_ref::<AgentRejected>()
                .expect("a refusal")
                .is_not_registered()
        );
    }
}
