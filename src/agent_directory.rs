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

use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::Deserialize;
use tracing::warn;

use crate::dto::{ConnectorHeartbeatRequest, ConnectorHeartbeatResponse};
use crate::heartbeat::{AgentRejected, HeartbeatClient};
use crate::registry_client::RegistryClient;

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
        }
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
            match heartbeat_through(&agent, registry_client, heartbeat_client, request).await {
                Ok(response) => {
                    self.remember_answered(&agent);
                    return Ok(response);
                }
                Err(error) if error.downcast_ref::<AgentRejected>().is_some() => {
                    // Reachable and answering - worth staying on, even though the answer is no.
                    self.remember_answered(&agent);
                    return Err(error);
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
}

async fn heartbeat_through(
    agent: &Agent,
    registry_client: &RegistryClient,
    heartbeat_client: &HeartbeatClient,
    request: &ConnectorHeartbeatRequest,
) -> Result<ConnectorHeartbeatResponse> {
    // Per Agent, never one key for all of them: the response must verify against the specific
    // Agent that sent it (TT-1742).
    let agent_public_key = registry_client
        .get_agent_permitted_key(&agent.ip_address)
        .await?;
    heartbeat_client
        .fetch_and_verify(&agent.base_url, &agent_public_key, request)
        .await
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
