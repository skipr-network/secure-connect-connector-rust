//! Which Agent to heartbeat through (TT-2210, spec §B.4: "any closest, publicly available
//! instance (stateless, no per-Connector affinity)").
//!
//! The Connector used to be pinned to one configured Agent address, with no way to notice that
//! instance rotating away - it would retry the dead address forever. Agents are semi-stable and do
//! rotate; the environment's `agents.json` (the same list clients resolve Agents from) is the
//! source of truth for which ones are live. So instead of a stored address, every heartbeat cycle:
//!
//! 1. re-reads `agents.json` and keeps the entries whose `status` is `operational`;
//! 2. tries the Agent that last answered first, as long as it is still listed - stickiness only,
//!    never affinity, so an Agent that drops off the list is left immediately even if it still
//!    answers;
//! 3. on an outage (unreachable, 5xx, unknown to Registry, bad signature) moves on to the next
//!    operational Agent *within the same cycle*.
//!
//! That bounds recovery from an Agent rotation to the cycle in which `agents.json` first lists the
//! replacement - at most about two heartbeat intervals end to end (the TT-2229 target), never an
//! unbounded retry against a dead address. A refusal ([`AgentRejected`], e.g. "not registered") is
//! an answer, not an outage: every Agent would give the same one, so there is no failover for it.
//!
//! If `agents.json` itself can't be fetched, the last list that could be is used instead - an S3
//! blip must not take down Connectors whose Agent is perfectly healthy.
//!
//! TT-3717 (spec §B.4 point 4): each request carries the Connector request proof for the Agent it
//! goes to, keyed by that Agent's `x25519_public_key` from Registry. A proof refusal concerns that
//! instance only (each has its own key), so it is handled like an outage, not like a refusal - with
//! one exception: on `connectorproofinvalid` the Agent's key may have rotated, so it is fetched
//! again and that Agent retried once with a new proof before moving on.
//!
//! TT-3767: a `429` ([`RateLimited`]) is a limit of that Agent instance too - moved on from like
//! an outage, without a retry, but logged as rate limiting rather than as "did not answer".

use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::Deserialize;
use tracing::warn;

use crate::dto::{
    ConnectorDeregisterRequest, ConnectorDeregisterResponse, ConnectorHeartbeatRequest,
    ConnectorHeartbeatResponse,
};
use crate::heartbeat::{AgentRejected, HeartbeatClient, ProofRefusal, ProofRefused, RateLimited};
use crate::registry_client::RegistryClient;
use crate::request_proof::{AgentProofKey, RequestProver};

const AGENTS_JSON_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATIONAL_STATUS: &str = "operational";

#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    /// What Registry knows the Agent's signing key by.
    pub ip_address: String,
    pub base_url: String,
}

#[derive(Deserialize)]
struct AgentsJson {
    #[serde(default)]
    agents: Vec<AgentsJsonEntry>,
}

#[derive(Deserialize)]
struct AgentsJsonEntry {
    #[serde(default)]
    ip_address: String,
    #[serde(default)]
    status: String,
}

#[derive(Default)]
struct DirectoryState {
    last_listed: Vec<Agent>,
    last_answered: Option<Agent>,
}

type BaseUrlFor = Box<dyn Fn(&str) -> String + Send + Sync>;

pub struct AgentDirectory {
    http: Client,
    agents_json_url: String,
    base_url_for: BaseUrlFor,
    state: Mutex<DirectoryState>,
    /// TT-3717: `None` sends no request proof to any Agent.
    prover: Option<RequestProver>,
}

impl AgentDirectory {
    pub fn new(http: Client, agents_json_url: String) -> Self {
        // Agent serves its public API on 443 at the address agents.json lists.
        Self::with_base_url_for(
            http,
            agents_json_url,
            Box::new(|ip_address| format!("https://{ip_address}")),
        )
    }

    pub(crate) fn with_base_url_for(
        http: Client,
        agents_json_url: String,
        base_url_for: BaseUrlFor,
    ) -> Self {
        Self {
            http,
            agents_json_url,
            base_url_for,
            state: Mutex::new(DirectoryState::default()),
            prover: None,
        }
    }

    /// TT-3717: proves every request to an Agent with this Connector's identity.
    pub fn with_request_prover(mut self, prover: RequestProver) -> Self {
        self.prover = Some(prover);
        self
    }

    /// Heartbeats through the first operational Agent that answers - see the module doc for the
    /// order they are tried in and what counts as an answer.
    pub async fn heartbeat(
        &self,
        registry_client: &RegistryClient,
        heartbeat_client: &HeartbeatClient,
        request: &ConnectorHeartbeatRequest,
    ) -> Result<ConnectorHeartbeatResponse> {
        let candidates = self.candidates().await?;
        let mut failures = Vec::new();
        for agent in candidates {
            // Per Agent, never one key for all of them: the response must verify against the
            // specific Agent that sent it (TT-1742), and the proof is made for it (TT-3717).
            let base_url = agent.base_url.as_str();
            let attempt =
                self.call_with_proof(&agent, registry_client, |agent_key, proof_key| async move {
                    heartbeat_client
                        .fetch_and_verify(base_url, &agent_key, proof_key.as_ref(), request)
                        .await
                });
            match attempt.await {
                Ok(response) => {
                    self.remember_answered(&agent);
                    return Ok(response);
                }
                Err(error) if error.downcast_ref::<AgentRejected>().is_some() => {
                    // Reachable and answering - worth staying on, even though the answer is no.
                    self.remember_answered(&agent);
                    return Err(error);
                }
                Err(error) if error.downcast_ref::<ProofRefused>().is_some() => {
                    warn_proof_refused(&agent, &error, "heartbeat");
                    failures.push(format!("{}: {error:#}", agent.ip_address));
                }
                Err(error) if error.downcast_ref::<RateLimited>().is_some() => {
                    warn!(agent = %agent.ip_address, error = %format!("{error:#}"), "Agent rate limited the heartbeat - trying the next operational Agent");
                    failures.push(format!("{}: {error:#}", agent.ip_address));
                }
                Err(error) => {
                    warn!(agent = %agent.ip_address, error = %format!("{error:#}"), "Agent did not answer the heartbeat - trying the next operational Agent");
                    failures.push(format!("{}: {error:#}", agent.ip_address));
                }
            }
        }
        bail!(
            "no operational Agent answered the heartbeat ({})",
            failures.join("; ")
        )
    }

    /// TT-2126: deregisters this Connector through the first operational Agent that answers, verifying the answer
    /// against that Agent's own Registry key - the same failover and trust as [`Self::heartbeat`]. A refusal is
    /// an answer: any Agent would relay the same one from Portal.
    pub async fn deregister(
        &self,
        registry_client: &RegistryClient,
        heartbeat_client: &HeartbeatClient,
        request: &ConnectorDeregisterRequest,
    ) -> Result<ConnectorDeregisterResponse> {
        let candidates = self.candidates().await?;
        let mut failures = Vec::new();
        for agent in candidates {
            let base_url = agent.base_url.as_str();
            let attempt =
                self.call_with_proof(&agent, registry_client, |agent_key, proof_key| async move {
                    heartbeat_client
                        .deregister_and_verify(base_url, &agent_key, proof_key.as_ref(), request)
                        .await
                });
            match attempt.await {
                Ok(response) => return Ok(response),
                Err(error) if error.downcast_ref::<AgentRejected>().is_some() => return Err(error),
                Err(error) if error.downcast_ref::<ProofRefused>().is_some() => {
                    warn_proof_refused(&agent, &error, "deregistration");
                    failures.push(format!("{}: {error:#}", agent.ip_address));
                }
                Err(error) if error.downcast_ref::<RateLimited>().is_some() => {
                    warn!(agent = %agent.ip_address, error = %format!("{error:#}"), "Agent rate limited the deregistration - trying the next operational Agent");
                    failures.push(format!("{}: {error:#}", agent.ip_address));
                }
                Err(error) => {
                    warn!(agent = %agent.ip_address, error = %format!("{error:#}"), "Agent did not answer the deregistration - trying the next operational Agent");
                    failures.push(format!("{}: {error:#}", agent.ip_address));
                }
            }
        }
        bail!(
            "no operational Agent answered the deregistration ({})",
            failures.join("; ")
        )
    }

    /// Every currently-operational Agent, the last one that answered first while it is still
    /// listed. Falls back to the last successfully fetched list if `agents.json` can't be read.
    async fn candidates(&self) -> Result<Vec<Agent>> {
        let listed = match self.fetch_operational_agents().await {
            Ok(listed) => {
                self.state.lock().unwrap().last_listed = listed.clone();
                listed
            }
            Err(error) => {
                let cached = self.state.lock().unwrap().last_listed.clone();
                if cached.is_empty() {
                    return Err(error);
                }
                warn!(error = %format!("{error:#}"), "could not refresh agents.json - using the last Agent list that could be fetched");
                cached
            }
        };
        if listed.is_empty() {
            bail!(
                "agents.json at {} lists no operational Agent",
                self.agents_json_url
            );
        }

        let last_answered = self.state.lock().unwrap().last_answered.clone();
        let mut ordered = listed;
        if let Some(position) =
            last_answered.and_then(|agent| ordered.iter().position(|listed| *listed == agent))
        {
            let sticky = ordered.remove(position);
            ordered.insert(0, sticky);
        }
        Ok(ordered)
    }

    async fn fetch_operational_agents(&self) -> Result<Vec<Agent>> {
        let response = self
            .http
            .get(&self.agents_json_url)
            .timeout(AGENTS_JSON_TIMEOUT)
            .send()
            .await
            .with_context(|| format!("request to {} failed", self.agents_json_url))?;
        if !response.status().is_success() {
            bail!(
                "agents.json at {} returned {}",
                self.agents_json_url,
                response.status()
            );
        }
        let parsed: AgentsJson = response.json().await.with_context(|| {
            format!("failed to parse agents.json from {}", self.agents_json_url)
        })?;

        let mut agents: Vec<Agent> = Vec::new();
        for entry in parsed.agents {
            let ip_address = entry.ip_address.trim();
            if !entry.status.trim().eq_ignore_ascii_case(OPERATIONAL_STATUS)
                || ip_address.is_empty()
            {
                continue;
            }
            let agent = Agent {
                ip_address: ip_address.to_string(),
                base_url: (self.base_url_for)(ip_address),
            };
            if !agents.contains(&agent) {
                agents.push(agent);
            }
        }
        Ok(agents)
    }

    fn remember_answered(&self, agent: &Agent) {
        self.state.lock().unwrap().last_answered = Some(agent.clone());
    }

    /// Calls `agent` with its Registry signing key and, when there is one, its request-proof key
    /// (TT-3717). On `connectorproofinvalid` both keys are fetched again - the Agent's key may
    /// have rotated - and the call is retried once, with a new proof; any refusal after that is
    /// returned for the caller to move on to the next Agent.
    async fn call_with_proof<T, F, Fut>(
        &self,
        agent: &Agent,
        registry_client: &RegistryClient,
        call: F,
    ) -> Result<T>
    where
        F: Fn(String, Option<AgentProofKey>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let keys = registry_client.get_agent_keys(&agent.ip_address).await?;
        let proof_key = self.proof_key_for(agent, keys.x25519_public_key.as_deref());
        let result = call(keys.permitted_key, proof_key).await;
        if proof_refusal(&result) != Some(ProofRefusal::Invalid) {
            return result;
        }
        warn!(agent = %agent.ip_address, "Agent refused the request proof as invalid - fetching its key again and retrying it once");
        let keys = registry_client.get_agent_keys(&agent.ip_address).await?;
        let proof_key = self.proof_key_for(agent, keys.x25519_public_key.as_deref());
        call(keys.permitted_key, proof_key).await
    }

    fn proof_key_for(&self, agent: &Agent, published: Option<&str>) -> Option<AgentProofKey> {
        self.prover
            .as_ref()?
            .key_for_agent(&agent.ip_address, published)
    }
}

/// One warning per refused attempt; `connectorproofexpired` names the likely cause, the clock.
fn warn_proof_refused(agent: &Agent, error: &anyhow::Error, request: &str) {
    let expired = error
        .downcast_ref::<ProofRefused>()
        .is_some_and(|refused| refused.refusal == ProofRefusal::Expired);
    if expired {
        warn!(agent = %agent.ip_address, error = %format!("{error:#}"), "Agent refused the {request}'s request proof as expired - this host's clock is most likely wrong, keep it synchronised (NTP); trying the next operational Agent");
    } else {
        warn!(agent = %agent.ip_address, error = %format!("{error:#}"), "Agent refused the {request}'s request proof - trying the next operational Agent");
    }
}

fn proof_refusal<T>(result: &Result<T>) -> Option<ProofRefusal> {
    let refused = result.as_ref().err()?.downcast_ref::<ProofRefused>()?;
    Some(refused.refusal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use std::collections::HashMap;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BODY: &str = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;

    fn request() -> ConnectorHeartbeatRequest {
        ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            unresolved_endpoint_hosts: None,
            ended_flows: vec![],
        }
    }

    struct Env {
        agents_json: MockServer,
        registry: MockServer,
        /// ip_address -> the mock server standing in for that Agent.
        agents: HashMap<String, MockServer>,
    }

    impl Env {
        async fn new() -> Self {
            Self {
                agents_json: MockServer::start().await,
                registry: MockServer::start().await,
                agents: HashMap::new(),
            }
        }

        async fn list(&self, entries: serde_json::Value) {
            self.agents_json.reset().await;
            Mock::given(method("GET"))
                .and(path("/agents.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(entries))
                .mount(&self.agents_json)
                .await;
        }

        /// A healthy Agent at `ip`, known to Registry, answering a correctly signed heartbeat.
        async fn healthy_agent(&mut self, ip: &str) {
            let identity = crypto::generate_keypair();
            let signature = crypto::sign_to_base64(&identity.signing_key, BODY.as_bytes());
            Mock::given(method("GET"))
                .and(path(format!("/api/agents/{ip}/permitted-key")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ip_address": ip,
                    "permitted_key": identity.public_key_hex
                })))
                .mount(&self.registry)
                .await;
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/connectors/heartbeat"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(BODY, "application/json")
                        .insert_header("X-Signature", signature.as_str()),
                )
                .mount(&server)
                .await;
            self.agents.insert(ip.to_string(), server);
        }

        fn directory(&self) -> AgentDirectory {
            let uris: HashMap<String, String> = self
                .agents
                .iter()
                .map(|(ip, server)| (ip.clone(), server.uri()))
                .collect();
            let uris = Arc::new(uris);
            AgentDirectory::with_base_url_for(
                Client::new(),
                format!("{}/agents.json", self.agents_json.uri()),
                // An Agent with no mock server stands for a dead instance: nothing listens there.
                Box::new(move |ip| {
                    uris.get(ip)
                        .cloned()
                        .unwrap_or_else(|| "http://127.0.0.1:1".to_string())
                }),
            )
        }

        fn registry_client(&self) -> RegistryClient {
            RegistryClient::new(Client::new(), self.registry.uri())
        }

        async fn heartbeat_count(&self, ip: &str) -> usize {
            self.agents[ip].received_requests().await.unwrap().len()
        }
    }

    fn entry(ip: &str, status: &str) -> serde_json::Value {
        serde_json::json!({ "ip_address": ip, "status": status, "zone": "ap-south-1a" })
    }

    #[tokio::test]
    async fn heartbeats_through_an_operational_agent_and_skips_non_operational_ones() {
        let mut env = Env::new().await;
        env.healthy_agent("10.0.0.2").await;
        env.healthy_agent("10.0.0.3").await;
        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "maintenance"), entry("10.0.0.3", "operational")] }))
            .await;
        let directory = env.directory();

        let response = directory
            .heartbeat(
                &env.registry_client(),
                &HeartbeatClient::new(Client::new()),
                &request(),
            )
            .await
            .unwrap();

        assert_eq!(response.connector_id, "c-1");
        assert_eq!(env.heartbeat_count("10.0.0.2").await, 0);
        assert_eq!(env.heartbeat_count("10.0.0.3").await, 1);
    }

    /// The TT-2210 acceptance criterion: an Agent that disappears is replaced within the same
    /// heartbeat cycle, without any retry against the dead address on later cycles.
    #[tokio::test]
    async fn fails_over_to_the_next_operational_agent_in_the_same_cycle_when_one_is_dead() {
        let mut env = Env::new().await;
        env.healthy_agent("10.0.0.3").await;
        // 10.0.0.2 is listed but nothing answers there.
        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "operational"), entry("10.0.0.3", "operational")] }))
            .await;
        let directory = env.directory();
        let heartbeat_client = HeartbeatClient::new(Client::new());

        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();
        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();

        // The second cycle went straight to the Agent that answered, not back to the dead one first.
        assert_eq!(env.heartbeat_count("10.0.0.3").await, 2);
        let registry_lookups = env.registry.received_requests().await.unwrap();
        let dead_lookups = registry_lookups
            .iter()
            .filter(|request| request.url.path().contains("10.0.0.2"))
            .count();
        assert_eq!(
            dead_lookups, 1,
            "the dead Agent is only tried once, in the first cycle"
        );
    }

    /// Rotation: the Agent in use is marked non-operational and a new one appears - the very next
    /// cycle moves to the new one, even though the old one would still have answered.
    #[tokio::test]
    async fn moves_off_an_agent_as_soon_as_agents_json_stops_listing_it_as_operational() {
        let mut env = Env::new().await;
        env.healthy_agent("10.0.0.2").await;
        env.healthy_agent("10.0.0.3").await;
        let directory = env.directory();
        let heartbeat_client = HeartbeatClient::new(Client::new());

        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "operational")] }))
            .await;
        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();

        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "retired"), entry("10.0.0.3", "operational")] }))
            .await;
        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();

        assert_eq!(env.heartbeat_count("10.0.0.2").await, 1);
        assert_eq!(env.heartbeat_count("10.0.0.3").await, 1);
    }

    #[tokio::test]
    async fn stays_on_the_agent_that_last_answered_while_it_is_still_listed() {
        let mut env = Env::new().await;
        env.healthy_agent("10.0.0.2").await;
        env.healthy_agent("10.0.0.3").await;
        env.list(serde_json::json!({ "agents": [entry("10.0.0.3", "operational")] }))
            .await;
        let directory = env.directory();
        let heartbeat_client = HeartbeatClient::new(Client::new());
        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();

        // A new Agent listed ahead of it doesn't pull the Connector away from one that works.
        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "operational"), entry("10.0.0.3", "operational")] }))
            .await;
        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();

        assert_eq!(env.heartbeat_count("10.0.0.2").await, 0);
        assert_eq!(env.heartbeat_count("10.0.0.3").await, 2);
    }

    /// "Not registered" is an answer every Agent would give - no failover, and the error keeps its
    /// type so the caller can tell the admin what to do.
    #[tokio::test]
    async fn does_not_fail_over_on_a_refusal() {
        let mut env = Env::new().await;
        env.healthy_agent("10.0.0.3").await;
        let identity = crypto::generate_keypair();
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.2/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.2",
                "permitted_key": identity.public_key_hex
            })))
            .mount(&env.registry)
            .await;
        let refusing = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "reason": "error.connectornotregistered"
            })))
            .mount(&refusing)
            .await;
        env.agents.insert("10.0.0.2".to_string(), refusing);
        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "operational"), entry("10.0.0.3", "operational")] }))
            .await;

        let error = env
            .directory()
            .heartbeat(
                &env.registry_client(),
                &HeartbeatClient::new(Client::new()),
                &request(),
            )
            .await
            .unwrap_err();

        assert!(
            error
                .downcast_ref::<AgentRejected>()
                .unwrap()
                .is_not_registered()
        );
        assert_eq!(env.heartbeat_count("10.0.0.3").await, 0);
    }

    /// Spec §B.4 / TT-2210 acceptance: the same running process is told "not registered" until the
    /// admin pastes its key, and its very next heartbeat after that succeeds - no restart, no
    /// reconfiguration, same directory and clients throughout.
    #[tokio::test]
    async fn a_not_registered_connector_succeeds_on_the_next_cycle_once_registered() {
        let env = Env::new().await;
        let identity = crypto::generate_keypair();
        let signature = crypto::sign_to_base64(&identity.signing_key, BODY.as_bytes());
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.2/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.2",
                "permitted_key": identity.public_key_hex
            })))
            .mount(&env.registry)
            .await;
        let agent = MockServer::start().await;
        // Before the admin's paste: Portal (via Agent) says "not registered", once.
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "reason": "error.connectornotregistered"
            })))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&agent)
            .await;
        // After it: the normal signed envelope.
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(BODY, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent)
            .await;
        let agent_uri = agent.uri();
        let directory = AgentDirectory::with_base_url_for(
            Client::new(),
            format!("{}/agents.json", env.agents_json.uri()),
            Box::new(move |_| agent_uri.clone()),
        );
        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "operational")] }))
            .await;
        let registry_client = env.registry_client();
        let heartbeat_client = HeartbeatClient::new(Client::new());

        let first = directory
            .heartbeat(&registry_client, &heartbeat_client, &request())
            .await
            .unwrap_err();
        assert!(
            first
                .downcast_ref::<AgentRejected>()
                .unwrap()
                .is_not_registered()
        );

        let second = directory
            .heartbeat(&registry_client, &heartbeat_client, &request())
            .await
            .unwrap();
        assert_eq!(second.connector_id, "c-1");
    }

    #[tokio::test]
    async fn keeps_using_the_last_fetched_list_when_agents_json_is_unavailable() {
        let mut env = Env::new().await;
        env.healthy_agent("10.0.0.3").await;
        env.list(serde_json::json!({ "agents": [entry("10.0.0.3", "operational")] }))
            .await;
        let directory = env.directory();
        let heartbeat_client = HeartbeatClient::new(Client::new());
        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();

        env.agents_json.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&env.agents_json)
            .await;
        directory
            .heartbeat(&env.registry_client(), &heartbeat_client, &request())
            .await
            .unwrap();

        assert_eq!(env.heartbeat_count("10.0.0.3").await, 2);
    }

    #[tokio::test]
    async fn fails_when_agents_json_has_never_been_fetched() {
        let env = Env::new().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&env.agents_json)
            .await;

        let result = env
            .directory()
            .heartbeat(
                &env.registry_client(),
                &HeartbeatClient::new(Client::new()),
                &request(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fails_when_no_listed_agent_is_operational() {
        let mut env = Env::new().await;
        env.healthy_agent("10.0.0.2").await;
        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "maintenance")] }))
            .await;

        let error = env
            .directory()
            .heartbeat(
                &env.registry_client(),
                &HeartbeatClient::new(Client::new()),
                &request(),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("no operational Agent"));
    }

    #[tokio::test]
    async fn fails_listing_every_agent_tried_when_none_answers() {
        let env = Env::new().await;
        env.list(serde_json::json!({ "agents": [entry("10.0.0.2", "operational"), entry("10.0.0.3", "operational")] }))
            .await;

        let error = env
            .directory()
            .heartbeat(
                &env.registry_client(),
                &HeartbeatClient::new(Client::new()),
                &request(),
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("10.0.0.2") && error.contains("10.0.0.3"),
            "{error}"
        );
    }

    /// The real test-environment file's shape (extra fields, "operational" status).
    #[tokio::test]
    async fn parses_the_real_agents_json_shape_and_builds_an_https_base_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agents.json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "agents" : [ {
                    "zone" : "ap-south-1a", "provider" : "aws", "region" : "ap-south-1",
                    "ip_address" : "13.233.148.23",
                    "address" : "201:bb15:e845:7273:8437:d895:ca2e:785",
                    "status" : "operational", "minimal_version" : "1.3.0",
                    "permitted_key" : "5746cb94d75e2fc6a248d3adca5a8cfe871df378fa329857d6dd17d46fdf50b7"
                  }, { "ip_address" : "", "status" : "operational" },
                     { "ip_address" : "13.233.148.23", "status" : "OPERATIONAL" } ],
                  "valid_from" : "2026-07-16 08:00:03"
                }"#,
                "application/json",
            ))
            .mount(&server)
            .await;
        let directory = AgentDirectory::new(Client::new(), format!("{}/agents.json", server.uri()));

        let agents = directory.fetch_operational_agents().await.unwrap();

        assert_eq!(
            agents,
            vec![Agent {
                ip_address: "13.233.148.23".to_string(),
                base_url: "https://13.233.148.23".to_string(),
            }]
        );
    }
}

/// TT-3717 (spec §B.4 point 4): the request proof each Agent gets, and what a proof refusal does.
#[cfg(test)]
mod proof_tests {
    use super::*;
    use crate::crypto::{self, KeyPair};
    use crate::dto::ConnectorDeregisterRequest;
    use crate::request_proof::tests::expected_proof;
    use crate::request_proof::{
        PROOF_HEADER, PROOF_VERSION_HEADER, PUBLIC_KEY_HEADER, TIMESTAMP_HEADER,
        kept_agent_keys_path,
    };
    use rand_core::OsRng;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};
    use x25519_dalek::{PublicKey, StaticSecret};

    const HEARTBEAT: &str = "/api/connectors/heartbeat";
    const DEREGISTER: &str = "/api/connectors/deregister";

    /// One Agent instance: its Ed25519 signing identity and its X25519 key-agreement key.
    struct AgentKeys {
        signing: KeyPair,
        agreement: StaticSecret,
    }

    impl AgentKeys {
        fn new() -> Self {
            Self {
                signing: crypto::generate_keypair(),
                agreement: StaticSecret::random_from_rng(OsRng),
            }
        }

        fn x25519_hex(&self) -> String {
            hex::encode(PublicKey::from(&self.agreement).as_bytes())
        }
    }

    struct Env {
        agents_json: MockServer,
        registry: MockServer,
        agents: HashMap<String, MockServer>,
        connector_public_key: String,
        connector_secret: StaticSecret,
        /// Stands for the identity key's directory.
        keys_dir: TempDir,
    }

    impl Env {
        async fn new(ips: &[&str]) -> Self {
            let agents_json = MockServer::start().await;
            let entries: Vec<_> = ips
                .iter()
                .map(|ip| serde_json::json!({ "ip_address": ip, "status": "operational" }))
                .collect();
            Mock::given(method("GET"))
                .and(path("/agents.json"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "agents": entries })),
                )
                .mount(&agents_json)
                .await;
            let mut agents = HashMap::new();
            for ip in ips {
                agents.insert(ip.to_string(), MockServer::start().await);
            }
            let connector_secret = StaticSecret::random_from_rng(OsRng);
            let connector_public_key = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .encode(PublicKey::from(&connector_secret).as_bytes())
            };
            Self {
                agents_json,
                registry: MockServer::start().await,
                agents,
                connector_public_key,
                connector_secret,
                keys_dir: tempfile::tempdir().unwrap(),
            }
        }

        /// Registry's answer for `ip`; `times` limits it to the first lookups, ahead of a later
        /// answer mounted without a limit.
        async fn registry_answers(
            &self,
            ip: &str,
            keys: &AgentKeys,
            x25519_published: bool,
            times: Option<u64>,
        ) {
            let mut body = serde_json::json!({
                "ip_address": ip,
                "permitted_key": keys.signing.public_key_hex,
            });
            if x25519_published {
                body["x25519_public_key"] = keys.x25519_hex().into();
            }
            let mock = Mock::given(method("GET"))
                .and(path(format!("/api/agents/{ip}/permitted-key")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body));
            match times {
                Some(times) => mock.up_to_n_times(times).with_priority(1),
                None => mock,
            }
            .mount(&self.registry)
            .await;
        }

        /// The Agent at `ip` answers `route` with `template`, for the first `times` requests when
        /// given, ahead of a later answer mounted without a limit.
        async fn agent_answers(
            &self,
            ip: &str,
            route: &str,
            template: ResponseTemplate,
            times: Option<u64>,
        ) {
            let mock = Mock::given(method("POST"))
                .and(path(route.to_string()))
                .respond_with(template);
            match times {
                Some(times) => mock.up_to_n_times(times).with_priority(1),
                None => mock,
            }
            .mount(&self.agents[ip])
            .await;
        }

        fn heartbeat_ok(&self, keys: &AgentKeys) -> ResponseTemplate {
            let body = format!(
                r#"{{"connector_id":"c-1","connector_public_key":"{}","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}}"#,
                self.connector_public_key
            );
            signed(keys, body)
        }

        fn deregister_ok(&self, keys: &AgentKeys) -> ResponseTemplate {
            let body = format!(
                r#"{{"connector_id":"c-1","connector_public_key":"{}","status":"DEREGISTERED","generated_at":"2026-10-13T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1"}}"#,
                self.connector_public_key
            );
            signed(keys, body)
        }

        fn directory(&self) -> AgentDirectory {
            let uris: HashMap<String, String> = self
                .agents
                .iter()
                .map(|(ip, server)| (ip.clone(), server.uri()))
                .collect();
            let uris = Arc::new(uris);
            AgentDirectory::with_base_url_for(
                Client::new(),
                format!("{}/agents.json", self.agents_json.uri()),
                Box::new(move |ip| uris[ip].clone()),
            )
            .with_request_prover(RequestProver::new(
                self.connector_secret.clone(),
                kept_agent_keys_path(&self.keys_dir.path().join("identity.key")),
            ))
        }

        async fn heartbeat(
            &self,
            directory: &AgentDirectory,
        ) -> Result<ConnectorHeartbeatResponse> {
            directory
                .heartbeat(
                    &RegistryClient::new(Client::new(), self.registry.uri()),
                    &HeartbeatClient::new(Client::new()),
                    &ConnectorHeartbeatRequest {
                        connector_public_key: self.connector_public_key.clone(),
                        unresolved_endpoint_hosts: None,
                        ended_flows: vec![],
                    },
                )
                .await
        }

        async fn deregister(
            &self,
            directory: &AgentDirectory,
        ) -> Result<ConnectorDeregisterResponse> {
            directory
                .deregister(
                    &RegistryClient::new(Client::new(), self.registry.uri()),
                    &HeartbeatClient::new(Client::new()),
                    &ConnectorDeregisterRequest {
                        connector_public_key: self.connector_public_key.clone(),
                    },
                )
                .await
        }

        async fn requests_to(&self, ip: &str) -> Vec<Request> {
            self.agents[ip].received_requests().await.unwrap()
        }

        async fn registry_lookups(&self, ip: &str) -> usize {
            self.registry
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.url.path().contains(ip))
                .count()
        }
    }

    fn signed(keys: &AgentKeys, body: String) -> ResponseTemplate {
        let signature = crypto::sign_to_base64(&keys.signing.signing_key, body.as_bytes());
        ResponseTemplate::new(200)
            .set_body_raw(body, "application/json")
            .insert_header("X-Signature", signature.as_str())
    }

    fn refused(reason: &str) -> ResponseTemplate {
        ResponseTemplate::new(401).set_body_json(serde_json::json!({ "reason": reason }))
    }

    fn header(request: &Request, name: &str) -> Option<String> {
        request
            .headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_string())
    }

    /// Checks the proof as the Agent holding `keys` would, over the body bytes it received.
    fn assert_proven_for(request: &Request, keys: &AgentKeys, route: &str, connector_key: &str) {
        assert_eq!(header(request, PROOF_VERSION_HEADER).as_deref(), Some("1"));
        assert_eq!(
            header(request, PUBLIC_KEY_HEADER).as_deref(),
            Some(connector_key)
        );
        let timestamp = header(request, TIMESTAMP_HEADER).unwrap();
        assert!(timestamp.parse::<i64>().unwrap() > 0 && !timestamp.starts_with('0'));
        assert_eq!(
            header(request, PROOF_HEADER).unwrap(),
            expected_proof(
                &keys.agreement,
                connector_key,
                "POST",
                route,
                &timestamp,
                &request.body
            ),
            "the MAC covers exactly the body bytes sent, for this Agent's key"
        );
    }

    fn assert_unproven(request: &Request) {
        for name in [
            PROOF_VERSION_HEADER,
            PUBLIC_KEY_HEADER,
            TIMESTAMP_HEADER,
            PROOF_HEADER,
        ] {
            assert_eq!(header(request, name), None, "{name}");
        }
    }

    #[tokio::test]
    async fn sends_a_proof_over_the_exact_body_bytes_that_the_agent_can_verify() {
        let env = Env::new(&["10.0.0.2"]).await;
        let keys = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, true, None).await;
        env.agent_answers("10.0.0.2", HEARTBEAT, env.heartbeat_ok(&keys), None)
            .await;

        env.heartbeat(&env.directory()).await.unwrap();

        let requests = env.requests_to("10.0.0.2").await;
        assert_proven_for(&requests[0], &keys, HEARTBEAT, &env.connector_public_key);
        assert_eq!(
            header(&requests[0], "content-type").as_deref(),
            Some("application/json")
        );
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["connector_public_key"], env.connector_public_key);
    }

    #[tokio::test]
    async fn sends_no_proof_to_an_agent_without_a_key() {
        let env = Env::new(&["10.0.0.2"]).await;
        let keys = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, false, None).await;
        env.agent_answers("10.0.0.2", HEARTBEAT, env.heartbeat_ok(&keys), None)
            .await;

        env.heartbeat(&env.directory()).await.unwrap();

        assert_unproven(&env.requests_to("10.0.0.2").await[0]);
    }

    /// A key missing from the Registry later (a rollback, a cleared entry) does not lock out a
    /// Connector that has proven itself - also across a restart.
    #[tokio::test]
    async fn uses_the_kept_key_when_the_registry_returns_none() {
        let env = Env::new(&["10.0.0.2"]).await;
        let keys = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, true, Some(1)).await;
        env.registry_answers("10.0.0.2", &keys, false, None).await;
        env.agent_answers("10.0.0.2", HEARTBEAT, env.heartbeat_ok(&keys), None)
            .await;

        env.heartbeat(&env.directory()).await.unwrap();
        // A restart: a new directory, reading only the kept file.
        env.heartbeat(&env.directory()).await.unwrap();

        let requests = env.requests_to("10.0.0.2").await;
        assert_eq!(requests.len(), 2);
        assert_proven_for(&requests[1], &keys, HEARTBEAT, &env.connector_public_key);
    }

    /// The Agent's key rotated: the Connector fetches it again and retries that Agent once with
    /// a new proof, without moving on.
    #[tokio::test]
    async fn refetches_the_key_and_retries_the_same_agent_once_on_connectorproofinvalid() {
        let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
        let old_keys = AgentKeys::new();
        let rotated = AgentKeys {
            signing: KeyPair {
                signing_key: old_keys.signing.signing_key.clone(),
                public_key_hex: old_keys.signing.public_key_hex.clone(),
            },
            agreement: StaticSecret::random_from_rng(OsRng),
        };
        env.registry_answers("10.0.0.2", &old_keys, true, Some(1))
            .await;
        env.registry_answers("10.0.0.2", &rotated, true, None).await;
        env.agent_answers(
            "10.0.0.2",
            HEARTBEAT,
            refused("error.connectorproofinvalid"),
            Some(1),
        )
        .await;
        env.agent_answers("10.0.0.2", HEARTBEAT, env.heartbeat_ok(&rotated), None)
            .await;

        env.heartbeat(&env.directory()).await.unwrap();

        let requests = env.requests_to("10.0.0.2").await;
        assert_eq!(requests.len(), 2);
        assert_proven_for(
            &requests[0],
            &old_keys,
            HEARTBEAT,
            &env.connector_public_key,
        );
        assert_proven_for(&requests[1], &rotated, HEARTBEAT, &env.connector_public_key);
        assert_ne!(
            header(&requests[0], PROOF_HEADER),
            header(&requests[1], PROOF_HEADER)
        );
        assert_eq!(env.registry_lookups("10.0.0.2").await, 2);
        assert!(env.requests_to("10.0.0.3").await.is_empty());
    }

    #[tokio::test]
    async fn moves_on_to_the_next_agent_when_the_retry_is_refused_too() {
        let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
        let refusing = AgentKeys::new();
        let healthy = AgentKeys::new();
        env.registry_answers("10.0.0.2", &refusing, true, None)
            .await;
        env.registry_answers("10.0.0.3", &healthy, true, None).await;
        env.agent_answers(
            "10.0.0.2",
            HEARTBEAT,
            refused("error.connectorproofinvalid"),
            None,
        )
        .await;
        env.agent_answers("10.0.0.3", HEARTBEAT, env.heartbeat_ok(&healthy), None)
            .await;

        env.heartbeat(&env.directory()).await.unwrap();

        assert_eq!(env.requests_to("10.0.0.2").await.len(), 2, "retried once");
        assert_eq!(env.requests_to("10.0.0.3").await.len(), 1);
    }

    /// Unlike `connectornotregistered`, no proof refusal ends the heartbeat, and only
    /// `connectorproofinvalid` is retried.
    #[tokio::test]
    async fn moves_on_without_a_retry_on_every_other_proof_refusal() {
        for reason in [
            "error.connectorproofexpired",
            "error.connectorproofreplayed",
            "error.connectorproofrequired",
        ] {
            let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
            let refusing = AgentKeys::new();
            let healthy = AgentKeys::new();
            env.registry_answers("10.0.0.2", &refusing, true, None)
                .await;
            env.registry_answers("10.0.0.3", &healthy, true, None).await;
            env.agent_answers("10.0.0.2", HEARTBEAT, refused(reason), None)
                .await;
            env.agent_answers("10.0.0.3", HEARTBEAT, env.heartbeat_ok(&healthy), None)
                .await;

            env.heartbeat(&env.directory()).await.unwrap();

            assert_eq!(env.requests_to("10.0.0.2").await.len(), 1, "{reason}");
            assert_eq!(env.registry_lookups("10.0.0.2").await, 1, "{reason}");
            assert_eq!(env.requests_to("10.0.0.3").await.len(), 1, "{reason}");
        }
    }

    #[tokio::test]
    async fn fails_with_every_refusal_when_no_agent_accepts_the_proof() {
        let env = Env::new(&["10.0.0.2"]).await;
        let keys = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, true, None).await;
        env.agent_answers(
            "10.0.0.2",
            HEARTBEAT,
            refused("error.connectorproofrequired"),
            None,
        )
        .await;

        let error = env.heartbeat(&env.directory()).await.unwrap_err();

        assert!(error.downcast_ref::<AgentRejected>().is_none());
        assert!(
            error.to_string().contains("connectorproofrequired"),
            "{error}"
        );
    }

    /// The Registry cannot be reached for the refetch: that Agent counts as not answering.
    #[tokio::test]
    async fn moves_on_when_the_registry_refetch_fails_during_the_retry() {
        let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
        let refusing = AgentKeys::new();
        let healthy = AgentKeys::new();
        env.registry_answers("10.0.0.2", &refusing, true, Some(1))
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.2/permitted-key"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&env.registry)
            .await;
        env.registry_answers("10.0.0.3", &healthy, true, None).await;
        env.agent_answers(
            "10.0.0.2",
            HEARTBEAT,
            refused("error.connectorproofinvalid"),
            None,
        )
        .await;
        env.agent_answers("10.0.0.3", HEARTBEAT, env.heartbeat_ok(&healthy), None)
            .await;

        env.heartbeat(&env.directory()).await.unwrap();

        assert_eq!(env.registry_lookups("10.0.0.2").await, 2);
        assert_eq!(
            env.requests_to("10.0.0.2").await.len(),
            1,
            "no retry without a key"
        );
        assert_eq!(env.requests_to("10.0.0.3").await.len(), 1);
    }

    /// A refusal every Agent would give, answered on the retry, still ends the heartbeat.
    #[tokio::test]
    async fn a_not_registered_answer_on_the_retry_ends_the_heartbeat_as_before() {
        let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
        let keys = AgentKeys::new();
        let other = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, true, None).await;
        env.registry_answers("10.0.0.3", &other, true, None).await;
        env.agent_answers(
            "10.0.0.2",
            HEARTBEAT,
            refused("error.connectorproofinvalid"),
            Some(1),
        )
        .await;
        env.agent_answers(
            "10.0.0.2",
            HEARTBEAT,
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "reason": "error.connectornotregistered" })),
            None,
        )
        .await;
        env.agent_answers("10.0.0.3", HEARTBEAT, env.heartbeat_ok(&other), None)
            .await;

        let error = env.heartbeat(&env.directory()).await.unwrap_err();

        assert!(
            error
                .downcast_ref::<AgentRejected>()
                .unwrap()
                .is_not_registered()
        );
        assert_eq!(env.requests_to("10.0.0.2").await.len(), 2);
        assert!(env.requests_to("10.0.0.3").await.is_empty());
    }

    fn rate_limited() -> ResponseTemplate {
        ResponseTemplate::new(429)
            .insert_header("Retry-After", "30")
            .set_body_json(serde_json::json!({ "reason": "connectorratelimited" }))
    }

    /// TT-3767: a `429` moves on to the next Agent like any other failure of that Agent - no
    /// retry on it, the heartbeat does not end - and is reported as rate limiting.
    #[tokio::test]
    async fn moves_on_to_the_next_agent_when_one_rate_limits_the_heartbeat() {
        let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
        let limiting = AgentKeys::new();
        let healthy = AgentKeys::new();
        env.registry_answers("10.0.0.2", &limiting, true, None)
            .await;
        env.registry_answers("10.0.0.3", &healthy, true, None).await;
        env.agent_answers("10.0.0.2", HEARTBEAT, rate_limited(), None)
            .await;
        env.agent_answers("10.0.0.3", HEARTBEAT, env.heartbeat_ok(&healthy), None)
            .await;

        env.heartbeat(&env.directory()).await.unwrap();

        assert_eq!(env.requests_to("10.0.0.2").await.len(), 1, "no retry");
        assert_eq!(env.requests_to("10.0.0.3").await.len(), 1);
    }

    #[tokio::test]
    async fn reports_rate_limiting_when_every_agent_rate_limits() {
        let env = Env::new(&["10.0.0.2"]).await;
        let keys = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, true, None).await;
        env.agent_answers("10.0.0.2", HEARTBEAT, rate_limited(), None)
            .await;
        env.agent_answers("10.0.0.2", DEREGISTER, rate_limited(), None)
            .await;

        let heartbeat = env.heartbeat(&env.directory()).await.unwrap_err();
        let deregistration = env.deregister(&env.directory()).await.unwrap_err();

        for error in [heartbeat, deregistration] {
            assert!(error.downcast_ref::<AgentRejected>().is_none());
            assert!(
                error.to_string().contains(
                    "10.0.0.2: Agent rate limited the request (connectorratelimited), Retry-After 30"
                ),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn moves_on_to_the_next_agent_when_one_rate_limits_the_deregistration() {
        let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
        let limiting = AgentKeys::new();
        let healthy = AgentKeys::new();
        env.registry_answers("10.0.0.2", &limiting, true, None)
            .await;
        env.registry_answers("10.0.0.3", &healthy, true, None).await;
        env.agent_answers("10.0.0.2", DEREGISTER, rate_limited(), None)
            .await;
        env.agent_answers("10.0.0.3", DEREGISTER, env.deregister_ok(&healthy), None)
            .await;

        env.deregister(&env.directory()).await.unwrap();

        assert_eq!(env.requests_to("10.0.0.2").await.len(), 1, "no retry");
        assert_eq!(env.requests_to("10.0.0.3").await.len(), 1);
    }

    #[tokio::test]
    async fn proves_the_deregistration_too() {
        let env = Env::new(&["10.0.0.2"]).await;
        let keys = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, true, None).await;
        env.agent_answers("10.0.0.2", DEREGISTER, env.deregister_ok(&keys), None)
            .await;

        env.deregister(&env.directory()).await.unwrap();

        assert_proven_for(
            &env.requests_to("10.0.0.2").await[0],
            &keys,
            DEREGISTER,
            &env.connector_public_key,
        );
    }

    #[tokio::test]
    async fn retries_a_deregistration_once_then_moves_on_to_the_next_agent() {
        let env = Env::new(&["10.0.0.2", "10.0.0.3"]).await;
        let refusing = AgentKeys::new();
        let healthy = AgentKeys::new();
        env.registry_answers("10.0.0.2", &refusing, true, None)
            .await;
        env.registry_answers("10.0.0.3", &healthy, true, None).await;
        env.agent_answers(
            "10.0.0.2",
            DEREGISTER,
            refused("error.connectorproofinvalid"),
            None,
        )
        .await;
        env.agent_answers("10.0.0.3", DEREGISTER, env.deregister_ok(&healthy), None)
            .await;

        env.deregister(&env.directory()).await.unwrap();

        assert_eq!(env.requests_to("10.0.0.2").await.len(), 2, "retried once");
        assert_eq!(env.registry_lookups("10.0.0.2").await, 2);
        assert_proven_for(
            &env.requests_to("10.0.0.3").await[0],
            &healthy,
            DEREGISTER,
            &env.connector_public_key,
        );
    }

    #[tokio::test]
    async fn sends_no_deregistration_proof_to_an_agent_without_a_key() {
        let env = Env::new(&["10.0.0.2"]).await;
        let keys = AgentKeys::new();
        env.registry_answers("10.0.0.2", &keys, false, None).await;
        env.agent_answers("10.0.0.2", DEREGISTER, env.deregister_ok(&keys), None)
            .await;

        env.deregister(&env.directory()).await.unwrap();

        assert_unproven(&env.requests_to("10.0.0.2").await[0]);
    }
}
