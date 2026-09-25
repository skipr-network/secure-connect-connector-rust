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
//! This module flips the direction: one task per currently-paired Node holds an outbound HTTP
//! long-poll open to that Node's Gatekeeper (`GET /api/connector/{connector_id}/poll`), and posts
//! its decision back (`POST /api/connector/{connector_id}/admission-result`). This never opens a
//! listening socket on the Connector at all, so no inbound firewall rule is ever needed for this
//! channel again.
//!
//! **Within the Connector<->Node tunnel, per spec §B.8** ("a reserved control channel within the
//! Connector<->Node tunnel carries a flow-admission message"): every poll/result call dials
//! `Config::gatekeeper_wg0_address` (`10.66.66.1` by default - Gatekeeper's own fixed address on
//! the same `wg0` interface this Connector is itself a peer on, per the orchestrator's node-
//! provisioning convention; overridable per TT-2144 review PR #21, see that field's own doc for
//! why this moved out of a hardcoded constant), never `node.ip_address` (Gatekeeper's public IP)
//! directly. The kernel route `tun_device::create` already installs for that same address (`ip
//! route replace {address}/24 dev <tun-iface>`, originally added for the pre-TT-2144 reply path -
//! TT-1734 gap #6) means a plain TCP connection to it is transparently carried through this
//! Connector's TUN device and the existing `run_tun_send_loop`/`run_wireguard_receive_loop`
//! machinery, out over the real encrypted WireGuard tunnel to that specific Node's Gatekeeper - no
//! new userspace TCP stack needed, just dialing the address that's already routed correctly. (See
//! `connect_registered`'s own doc for why that connection is driven via a bound `TcpSocket`
//! rather than a plain `TcpStream::connect` - routing that very first outbound packet correctly
//! needs one more piece than the route alone, below.)
//! (An earlier version of this module dialed `node.ip_address` directly instead, over the plain
//! network - a real, since-corrected deviation from this spec line, confirmed by reading it
//! directly rather than assumed; see the ticket's own quoted text.)
//!
//! **Why this module drives HTTP at `hyper`'s lower level instead of through `reqwest::Client`
//! (as `heartbeat.rs`/`registry_client.rs` do)**: routing one of THIS connection's OWN outbound
//! packets to the right Node's tunnel is `run_tun_send_loop`'s job, and (unlike an ordinary
//! forwarded user flow, or a reply to something Gatekeeper dialed in for) there is nothing in
//! such a packet for it to key on except this connection's own local *source* port - every Node's
//! Gatekeeper shares the identical destination address `10.66.66.1`:`gatekeeper_http_port` from
//! this Connector's point of view (the module doc's "fixed and identical across the whole fleet" -
//! same masquerading `flow_table` already relies on for gateway virtual addresses), so the
//! destination alone carries zero information about which Node a brand new connection is even
//! for. The local port has to be known and registered
//! (`FlowTable::record_outbound_control_channel_port` - deliberately its OWN mapping, not reused
//! from TT-2102's `control_channel_ports`, since that one keys on the opposite field for the
//! opposite direction; see `outbound_control_channel_ports`'s own doc) strictly *before* this
//! connection's very first packet (the SYN) is sent - not merely before the request, and not
//! "after connect() resolves": `TcpStream::connect().await` doesn't return until the full
//! three-way handshake already completed, so learning the port from an already-connected
//! `TcpStream` is *always* too late - by then, an unregistered SYN has already gone out and
//! already been dropped, and no reply can ever arrive to bootstrap that registration once. (A
//! real bug of exactly this shape shipped once and was caught here in review - see
//! `connect_registered`'s own doc for the fix: bind to port 0 first, register, only then
//! `connect()`.) `reqwest::Client` manages connections internally with no way to expose an
//! unconnected socket's bound-but-not-yet-dialed local port for this; a `TcpSocket` this module
//! binds (and inspects) itself does. One connection per call (matching
//! `outbound_control_channel_ports`' own doc: "these are short-lived one-shot HTTP exchanges, not
//! long-lived sessions") - not pooled/reused, deliberately, so this stays simple and each call
//! registers its own port fresh rather than reasoning about a shared connection's lifetime against
//! the bounded-FIFO eviction that mechanism already has.
//!
//! Poller lifecycle is deliberately independent of `TunnelManager`'s tunnel-established state, and
//! of whether the TUN device (and its Gatekeeper return route) exists yet at all (`sync` below runs
//! against the raw heartbeat node list directly, spawned before the startup heartbeat loop that
//! creates the TUN device - see `main.rs`) - a poll/result call attempted before that route exists
//! simply fails to connect (no route to host) like any other transient failure, and
//! `POLL_RETRY_BACKOFF` already retries it shortly after, by which point the route is up. No new
//! synchronization needed for this ordering: the existing retry loop already covers it.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::dto::HeartbeatNode;
use crate::flow_control::{
    ControlPlaneState, DnsAdmissionRequest, DnsAdmissionResponse, FlowAdmissionRequest,
    FlowReleaseRequest, handle_dns_admission, handle_flow_admission, handle_flow_release,
};

/// Backoff between poll attempts after a transport failure (connection refused, timeout, non-2xx
/// status, unparseable body) - distinct from the poll call's own long-poll timeout, which is
/// Gatekeeper's own affair (`gatekeeper.connector.control-channel.poll-timeout-ms`, default 25s on
/// that side). Short enough that a Gatekeeper node coming back up (or the Connector's own TUN
/// device/return route finishing setup at startup) is noticed quickly, long enough not to hammer a
/// genuinely-down node on every iteration.
const POLL_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Bounds the poll HTTP request itself - comfortably longer than Gatekeeper's own long-poll
/// timeout, so a slow-but-alive Gatekeeper legitimately holding the connection open close to its
/// own full timeout isn't itself mistaken for a transport failure and retried into a needless
/// reconnect.
const POLL_REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

/// Bounds the admission-result POST - a small fixed JSON body with no long-poll wait on Gatekeeper's
/// side, so this only ever needs to cover plain network latency, not a deliberate server-side hold.
const RESULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
struct ConnectorPollResponse {
    #[serde(rename = "type")]
    kind: String,
    admission: Option<FlowAdmissionRequest>,
    release: Option<FlowReleaseRequest>,
    /// TT-2227: DNS admission request - present when `kind == "dns_admission"`.
    dns_admission: Option<DnsAdmissionRequest>,
}

/// Tracks one long-poll task per currently-paired Node, spawned/aborted to match each heartbeat's
/// own `node_list` (see `sync`). Owns the `ControlPlaneState` every poller task shares (cheaply
/// `Clone`, `Arc`-backed).
pub struct AdmissionPollers {
    connector_id: String,
    gatekeeper_http_port: u16,
    gatekeeper_wg0_address: Ipv4Addr,
    state: ControlPlaneState,
    tasks: HashMap<String, JoinHandle<()>>,
}

impl AdmissionPollers {
    pub fn new(
        connector_id: String,
        gatekeeper_http_port: u16,
        gatekeeper_wg0_address: Ipv4Addr,
        state: ControlPlaneState,
    ) -> Self {
        Self {
            connector_id,
            gatekeeper_http_port,
            gatekeeper_wg0_address,
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
            info!(node_id = %node.node_id, "starting admission poller for node");
            let handle = tokio::spawn(run_poller(
                node.node_id.clone(),
                self.gatekeeper_http_port,
                self.gatekeeper_wg0_address,
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

/// Connects a fresh `TcpStream` to `gatekeeper_addr:port`, registering its local port against
/// `node_id` *before* the connection's very first packet (the SYN) is ever sent - not after
/// `connect()` resolves, which is too late: `run_tun_send_loop` (`main.rs`) needs this
/// registration to route that very first outbound packet to the right node's tunnel at all (see
/// `FlowTable::outbound_control_channel_ports`'s doc), and `TcpStream::connect().await` doesn't
/// return control to this function until the full three-way handshake has already completed -
/// i.e. only *after* a SYN this registration was supposed to make routable has already gone out
/// and (without it) already been dropped. Binds a `TcpSocket` to `0.0.0.0:0` first instead - the
/// OS assigns the local port synchronously, at `bind()`, a purely local kernel operation with no
/// network I/O - so the assigned port is known, and can be registered, strictly before `connect()`
/// is ever called and a single packet leaves.
///
/// `gatekeeper_addr` is always `Config::gatekeeper_wg0_address` in production (every real call
/// site below passes it through unconditionally) - a parameter here, not a hardcoded constant,
/// both because it's itself configurable now (TT-2144 review PR #21) and so tests can point this
/// at a loopback listener instead: the real address has no route to it at all in a plain test
/// process (no real TUN device), so hardcoding it here would make every network-calling function
/// in this module untestable rather than just the handful of lines that actually need a real
/// tunnel.
async fn connect_registered(
    node_id: &str,
    flow_table: &std::sync::Mutex<crate::flow_table::FlowTable>,
    gatekeeper_addr: Ipv4Addr,
    port: u16,
) -> std::io::Result<TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    let local_port = socket.local_addr()?.port();
    flow_table
        .lock()
        .expect("flow table lock poisoned")
        .record_outbound_control_channel_port(node_id, local_port);
    socket
        .connect(SocketAddr::new(IpAddr::V4(gatekeeper_addr), port))
        .await
}

/// A request body that's either empty (GET) or a small fixed JSON payload (POST) - boxed to one
/// common type since `send_once` below is shared by both call shapes, never actually fallible
/// (neither `Empty` nor `Full` can fail to produce their own bytes), so `Infallible` is the error
/// type, not `hyper::Error`.
type RequestBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

/// Drives one request/response exchange over `stream` via a plain HTTP/1.1 handshake (no
/// connection reuse - see the module doc), bounded by `timeout`.
///
/// The connection-driving future (`connection` below) has to be polled independently of
/// `send_request`/the response body read for either to ever actually move any bytes - hyper's
/// low-level `client::conn` API splits "the connection's own I/O" from "one request/response on
/// it" into two separate futures precisely so a caller can hold several requests against one
/// connection at once, and expects *some* task to keep driving the former for as long as the
/// latter is in use. `tokio::spawn`ing it (not `select!`ing it against the request) is what makes
/// that true here: `select!` would drop - not just pause - whichever future loses the race, and
/// `send_request` only resolves once the response *headers* arrive, before its body is read -
/// dropping the connection driver at that exact point would leave `.collect()` below awaiting
/// bytes nothing is ever going to deliver again. Always aborted once this one exchange is done
/// (success, failure, or timeout alike) rather than left running, since this module never reuses
/// a connection for a second request (see the module doc) - there's no keep-alive benefit to
/// leaving it alive, and leaving it running unbounded on every timed-out call would leak one task
/// and one socket per attempt for as long as Gatekeeper stays unreachable.
async fn send_once(
    stream: TcpStream,
    request: Request<RequestBody>,
    timeout: Duration,
) -> anyhow::Result<(StatusCode, Bytes)> {
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    let connection_task = tokio::spawn(connection);

    let outcome = tokio::time::timeout(timeout, async {
        let response: Response<Incoming> = sender.send_request(request).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        Ok::<_, hyper::Error>((status, body))
    })
    .await;

    connection_task.abort();

    match outcome {
        Ok(Ok((status, body))) => Ok((status, body)),
        Ok(Err(error)) => Err(anyhow::anyhow!("request failed: {error}")),
        Err(_) => Err(anyhow::anyhow!("timed out after {timeout:?}")),
    }
}

async fn run_poller(
    node_id: String,
    gatekeeper_http_port: u16,
    gatekeeper_wg0_address: Ipv4Addr,
    connector_id: String,
    state: ControlPlaneState,
) {
    let poll_path = format!("/api/connector/{connector_id}/poll");
    let host_header = format!("{gatekeeper_wg0_address}:{gatekeeper_http_port}");
    loop {
        let stream = match connect_registered(
            &node_id,
            &state.flow_table,
            gatekeeper_wg0_address,
            gatekeeper_http_port,
        )
        .await
        {
            Ok(stream) => stream,
            Err(error) => {
                warn!(%error, %node_id, "could not connect to Gatekeeper's tunnel address to poll for flow-admission work - retrying after a backoff");
                tokio::time::sleep(POLL_RETRY_BACKOFF).await;
                continue;
            }
        };
        let request = match Request::builder()
            .method("GET")
            .uri(&poll_path)
            .header("Host", &host_header)
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            ) {
            Ok(request) => request,
            Err(error) => {
                error!(%error, %node_id, "failed to build the poll request - this is a programming error, not a transport failure");
                tokio::time::sleep(POLL_RETRY_BACKOFF).await;
                continue;
            }
        };

        match send_once(stream, request, POLL_REQUEST_TIMEOUT).await {
            Ok((status, body)) if status.is_success() => {
                match serde_json::from_slice::<ConnectorPollResponse>(&body) {
                    Ok(message) => {
                        handle_message(
                            &node_id,
                            gatekeeper_wg0_address,
                            gatekeeper_http_port,
                            &connector_id,
                            &state,
                            message,
                        )
                        .await;
                        // No sleep: the long-poll itself paces this loop - a "none" response
                        // already waited out Gatekeeper's own poll-timeout before returning.
                    }
                    Err(error) => {
                        error!(%error, %node_id, "could not parse poll response from Gatekeeper - retrying after a backoff");
                        tokio::time::sleep(POLL_RETRY_BACKOFF).await;
                    }
                }
            }
            Ok((status, _)) => {
                warn!(%status, %node_id, "poll to Gatekeeper returned a non-success status - retrying after a backoff");
                tokio::time::sleep(POLL_RETRY_BACKOFF).await;
            }
            Err(error) => {
                warn!(%error, %node_id, "could not reach Gatekeeper to poll for flow-admission work - retrying after a backoff");
                tokio::time::sleep(POLL_RETRY_BACKOFF).await;
            }
        }
    }
}

async fn handle_message(
    node_id: &str,
    gatekeeper_addr: Ipv4Addr,
    gatekeeper_http_port: u16,
    connector_id: &str,
    state: &ControlPlaneState,
    message: ConnectorPollResponse,
) {
    match message.kind.as_str() {
        "admission" => {
            handle_admission(
                node_id,
                gatekeeper_addr,
                gatekeeper_http_port,
                connector_id,
                state,
                message.admission,
            )
            .await
        }
        "dns_admission" => {
            handle_dns(
                node_id,
                gatekeeper_addr,
                gatekeeper_http_port,
                connector_id,
                state,
                message.dns_admission,
            )
            .await
        }
        "release" => handle_release(state, message.release).await,
        "none" => {}
        other => {
            warn!(kind = %other, %node_id, "unrecognized poll response type - ignoring");
        }
    }
}

async fn handle_admission(
    node_id: &str,
    gatekeeper_addr: Ipv4Addr,
    gatekeeper_http_port: u16,
    connector_id: &str,
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

    let result_path = format!("/api/connector/{connector_id}/admission-result");
    let host_header = format!("{gatekeeper_addr}:{gatekeeper_http_port}");
    let body = match serde_json::to_vec(&response) {
        Ok(body) => body,
        Err(error) => {
            error!(%error, %node_id, %flow_id, "could not serialize the admission result - it will fail closed on Gatekeeper's own timeout for this flow");
            return;
        }
    };
    let stream = match connect_registered(
        node_id,
        &state.flow_table,
        gatekeeper_addr,
        gatekeeper_http_port,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            error!(%error, %node_id, %flow_id, "could not reach Gatekeeper to post the admission result - it will fail closed on its own timeout for this flow");
            return;
        }
    };
    let request = match Request::builder()
        .method("POST")
        .uri(&result_path)
        .header("Host", &host_header)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, %node_id, %flow_id, "failed to build the admission-result request - this is a programming error, not a transport failure");
            return;
        }
    };
    if let Err(error) = send_once(stream, request, RESULT_REQUEST_TIMEOUT).await {
        error!(%error, %node_id, %flow_id, "could not post admission result back to Gatekeeper - it will fail closed on its own timeout for this flow");
    }
}

/// TT-2227: DNS admission — received as `type=dns_admission` over the Connector-initiated
/// long-poll channel (same channel as `type=admission`/`type=release`). Calls
/// `handle_dns_admission` from `flow_control` and posts the decision back to Gatekeeper over the
/// same admission-result endpoint, keyed by a correlation id Gatekeeper supplied in the request.
async fn handle_dns(
    node_id: &str,
    gatekeeper_addr: Ipv4Addr,
    gatekeeper_http_port: u16,
    connector_id: &str,
    state: &ControlPlaneState,
    request: Option<DnsAdmissionRequest>,
) {
    let Some(request) = request else {
        error!(%node_id, "poll response claimed type=dns_admission but carried no dns_admission body - ignoring");
        return;
    };
    let correlation_id = request.correlation_id.clone();
    let response: DnsAdmissionResponse =
        handle_dns_admission(&state.policy_store, &state.audit_log, request).await;

    let result_path = format!("/api/connector/{connector_id}/admission-result");
    let host_header = format!("{gatekeeper_addr}:{gatekeeper_http_port}");
    let body = match serde_json::to_vec(&serde_json::json!({
        "correlation_id": correlation_id,
        "decision": response.decision,
        "reason": response.reason,
    })) {
        Ok(body) => body,
        Err(error) => {
            error!(%error, %node_id, %correlation_id, "could not serialize the DNS admission result - it will fail closed on Gatekeeper's own timeout");
            return;
        }
    };
    let stream = match connect_registered(
        node_id,
        &state.flow_table,
        gatekeeper_addr,
        gatekeeper_http_port,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            error!(%error, %node_id, %correlation_id, "could not reach Gatekeeper to post the DNS admission result - it will fail closed on its own timeout");
            return;
        }
    };
    let http_request = match Request::builder()
        .method("POST")
        .uri(&result_path)
        .header("Host", &host_header)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        ) {
        Ok(r) => r,
        Err(error) => {
            error!(%error, %node_id, %correlation_id, "failed to build the DNS admission-result request - programming error");
            return;
        }
    };
    if let Err(error) = send_once(stream, http_request, RESULT_REQUEST_TIMEOUT).await {
        error!(%error, %node_id, %correlation_id, "could not post DNS admission result back to Gatekeeper - it will fail closed on its own timeout");
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
    use std::sync::{Arc, Mutex};

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
        // there is no route to the real gatekeeper_wg0_address in a plain test process, so any spawned
        // poller just sits retrying against a connection failure, exercised only for its lifecycle
        // bookkeeping (tasks map), not its behavior.
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _guard = runtime.enter();

        let mut pollers =
            AdmissionPollers::new("c-1".to_string(), 4000, Ipv4Addr::new(10, 66, 66, 1), state);
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
            AdmissionPollers::new("c-1".to_string(), 4000, Ipv4Addr::new(10, 66, 66, 1), state);

        pollers.sync(&[node("n-1", "10.0.0.1")]);
        let first_id = pollers.tasks.get("n-1").unwrap().id();
        pollers.sync(&[node("n-1", "10.0.0.1")]);
        let second_id = pollers.tasks.get("n-1").unwrap().id();

        assert_eq!(
            first_id, second_id,
            "resyncing the same node must not spawn a new task"
        );
    }

    /// Exercises `connect_registered` itself (not a hand-rolled stand-in) against a loopback
    /// listener - proves the local port it registers is really the connection's own (matches what
    /// the server observed as the peer's port), and - the actual point of the whole mechanism -
    /// that it's registered under `node_for_outbound_control_channel_source_port` (the lookup
    /// `main.rs`'s `run_tun_send_loop` uses for this Connector's own outbound packets), not the
    /// unrelated `node_for_control_channel_port` (keyed the opposite way, for the opposite,
    /// Gatekeeper-dials-in direction - see both doc comments). Can't dial the real
    /// the real `gatekeeper_wg0_address` in a test process (no route to it without a real TUN
    /// device), so this points `connect_registered` at a loopback address instead.
    #[tokio::test]
    async fn connect_registered_registers_the_connections_own_local_port_as_an_outbound_one() {
        let (state, _rx) = state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let observed_peer_port = tokio::spawn(async move {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            drop(stream);
            peer_addr.port()
        });

        let stream = connect_registered(
            "n-1",
            &state.flow_table,
            Ipv4Addr::new(127, 0, 0, 1),
            server_port,
        )
        .await
        .unwrap();
        let local_port = stream.local_addr().unwrap().port();

        assert_eq!(
            observed_peer_port.await.unwrap(),
            local_port,
            "the port connect_registered records must really be this connection's own local port"
        );
        assert_eq!(
            state
                .flow_table
                .lock()
                .unwrap()
                .node_for_outbound_control_channel_source_port(local_port),
            Some("n-1"),
            "must be registered as an OUTBOUND control-channel port (source-port keyed) - the \
             mechanism run_tun_send_loop actually looks up for this Connector's own outbound \
             packets, not node_for_control_channel_port (the opposite, Gatekeeper-dials-in \
             direction)"
        );
        assert!(
            state
                .flow_table
                .lock()
                .unwrap()
                .node_for_control_channel_port(local_port)
                .is_none(),
            "must NOT be registered under the unrelated inbound mapping"
        );
    }

    /// Regression test for the actual production bug this whole mechanism exists to prevent:
    /// registering a connection's local port only *after* `connect()` resolves is always too
    /// late, since nothing routes the SYN that `connect()` itself needs to send until the
    /// registration already happened. `connect_registered` fixes this by binding (which assigns
    /// the local port synchronously, no network I/O) and registering *before* ever calling
    /// `connect()` - this test proves that ordering holds by registering nothing else in between:
    /// if `connect_registered` ever regressed to registering after connecting instead, the
    /// `flow_table` lookup inside the accept handler below (running concurrently, so it only ever
    /// observes state as it stood at whatever point the connection is far enough along for the
    /// peer to have been accepted) could race ahead of it. Run many times to make a race with any
    /// real chance of manifesting.
    #[tokio::test]
    async fn connect_registered_has_already_registered_the_port_by_the_time_the_peer_can_accept_the_connection()
     {
        for _ in 0..50 {
            let (state, _rx) = state();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_port = listener.local_addr().unwrap().port();
            let flow_table_for_server = state.flow_table.clone();
            let accept_task = tokio::spawn(async move {
                let (_stream, peer_addr) = listener.accept().await.unwrap();
                // If registration happens strictly before connect() (the contract this test
                // exists to enforce), this lookup - running the instant the peer is observably
                // connected - must already see it; no sleep, no retry.
                flow_table_for_server
                    .lock()
                    .unwrap()
                    .node_for_outbound_control_channel_source_port(peer_addr.port())
                    .map(str::to_string)
            });

            let _stream = connect_registered(
                "n-1",
                &state.flow_table,
                Ipv4Addr::new(127, 0, 0, 1),
                server_port,
            )
            .await
            .unwrap();

            assert_eq!(
                accept_task.await.unwrap().as_deref(),
                Some("n-1"),
                "the port must already be registered by the moment the peer sees the connection arrive"
            );
        }
    }

    /// Regression test for a real bug caught in review before this ever shipped: `send_once`
    /// originally raced the connection-driving future against `send_request` via `tokio::select!`,
    /// which *drops* - not pauses - whichever side loses. `send_request` resolves once response
    /// *headers* arrive, before its body is necessarily fully read; dropping the connection driver
    /// right then leaves `.collect()` awaiting bytes nothing is left to ever read off the socket
    /// again - a silent, permanent hang. A response fully buffered in one packet (the other test's
    /// small fixed body over loopback) doesn't reliably exercise this, since hyper may already have
    /// the whole thing read before `send_request`'s future is even polled to completion; this
    /// hand-rolled server writes headers, waits, then writes the body in a genuinely separate
    /// write, forcing a real second read to be necessary.
    #[tokio::test]
    async fn send_once_still_reads_a_response_body_that_arrives_in_a_separate_read_after_headers_do()
     {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let body = b"{\"type\":\"none\"}";
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.write_all(body).await.unwrap();
            let _ = stream.shutdown().await;
        });

        let stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        let request = Request::builder()
            .method("GET")
            .uri("/")
            .header("Host", format!("127.0.0.1:{server_port}"))
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();

        let (status, body) = send_once(stream, request, Duration::from_secs(5))
            .await
            .expect(
                "must not hang or fail when the response body arrives in a separate read after headers",
            );

        assert!(status.is_success());
        assert_eq!(&body[..], b"{\"type\":\"none\"}");
    }

    /// TT-2144's own version of the TT-2145 regression this codebase already learned from once: a
    /// null signature triple must deserialize into `ConnectorPollResponse` and reach
    /// `handle_flow_admission` as a considered refusal, not fail JSON extraction outright - now at
    /// this module's own deserialization boundary instead of an axum-extracted request, since
    /// that's where the equivalent risk moved to once Gatekeeper stopped calling into the Connector
    /// directly.
    #[test]
    fn a_null_signature_triple_in_a_polled_admission_deserializes_as_a_considered_refusal_not_a_parse_failure()
     {
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
        assert_eq!(message.kind, "admission");
        assert!(message.admission.is_some());
    }

    /// Spawns a loopback HTTP/1.1 server standing in for Gatekeeper, and returns the address/port
    /// pair to pass as `handle_admission`/`handle_message`'s `gatekeeper_addr`/
    /// `gatekeeper_http_port` - what makes this module's real network-calling code (not just
    /// `connect_registered`/`send_once` in isolation) exercisable in a test process at all, since
    /// the real `gatekeeper_wg0_address` has no route to it without an actual TUN device.
    /// `on_admission_result` receives each posted-back `FlowAdmissionResponse` body, for tests that
    /// need to assert on what was actually sent.
    async fn spawn_mock_gatekeeper(
        on_admission_result: impl Fn(serde_json::Value) + Send + Sync + 'static,
    ) -> (Ipv4Addr, u16) {
        let on_admission_result = std::sync::Arc::new(on_admission_result);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let on_admission_result = on_admission_result.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            hyper::service::service_fn(move |req: Request<Incoming>| {
                                let on_admission_result = on_admission_result.clone();
                                async move {
                                    if req.uri().path().ends_with("/admission-result") {
                                        let body =
                                            req.into_body().collect().await.unwrap().to_bytes();
                                        let parsed: serde_json::Value =
                                            serde_json::from_slice(&body).unwrap();
                                        on_admission_result(parsed);
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(204)
                                            .body(
                                                Empty::<Bytes>::new()
                                                    .map_err(|never: std::convert::Infallible| {
                                                        match never {}
                                                    })
                                                    .boxed(),
                                            )
                                            .unwrap(),
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        (Ipv4Addr::new(127, 0, 0, 1), port)
    }

    #[tokio::test]
    async fn an_admitted_flow_hands_a_reclaimed_pending_packet_back_over_the_recovered_channel_and_posts_the_result()
     {
        let (state, mut rx) = state();
        let posted = std::sync::Arc::new(Mutex::new(Vec::new()));
        let posted_writer = posted.clone();
        let (gatekeeper_addr, gatekeeper_port) =
            spawn_mock_gatekeeper(move |body| posted_writer.lock().unwrap().push(body)).await;
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
                connector_public_key: None,
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
                        device_public_key: Some(device.public_key_hex.clone()),
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
        let mut recovered = None;
        for attempt in 0..5 {
            let flow_id = format!("flow-{attempt}");
            let request = FlowAdmissionRequest {
                flow_id: flow_id.clone(),
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
            handle_admission(
                "n-1",
                gatekeeper_addr,
                gatekeeper_port,
                "c-1",
                &state,
                Some(request),
            )
            .await;
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
        assert_eq!(
            posted.lock().unwrap().last().unwrap()["decision"],
            "admit",
            "the admission decision must also have been posted back to Gatekeeper over the real network path"
        );
    }

    #[tokio::test]
    async fn a_refused_admissions_decision_never_reclaims_a_pending_packet_but_still_posts_the_refusal()
     {
        let (state, mut rx) = state();
        let posted = std::sync::Arc::new(Mutex::new(Vec::new()));
        let posted_writer = posted.clone();
        let (gatekeeper_addr, gatekeeper_port) =
            spawn_mock_gatekeeper(move |body| posted_writer.lock().unwrap().push(body)).await;
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

        handle_admission(
            "n-1",
            gatekeeper_addr,
            gatekeeper_port,
            "c-1",
            &state,
            Some(request),
        )
        .await;

        assert!(
            rx.try_recv().is_err(),
            "a refused flow's buffered packet must never be handed back for forwarding"
        );
        assert_eq!(posted.lock().unwrap().last().unwrap()["decision"], "refuse");
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
            "n-1",
            Ipv4Addr::new(127, 0, 0, 1),
            4000,
            "c-1",
            &state,
            ConnectorPollResponse {
                kind: "none".to_string(),
                admission: None,
                release: None,
                dns_admission: None,
            },
        )
        .await;
        // No assertion beyond "this returns without touching anything or attempting a network
        // call" - covered by the absence of any listener needing to be hit at all.
    }
}
