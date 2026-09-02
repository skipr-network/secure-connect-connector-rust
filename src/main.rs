mod access;
mod audit;
mod config;
mod crypto;
mod dto;
mod flow_control;
mod flow_table;
mod heartbeat;
mod identity;
mod policy;
mod registry_client;
mod signature_binding;
mod tun_device;
mod tunnel;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use audit::{AuditEvent, AuditLog};
use boringtun::noise::Tunn;
use config::Config;
use dto::{HeartbeatNode, PolicyBundle};
use flow_control::ControlPlaneState;
use flow_table::FlowTable;
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

    // Shared with the flow-admission control plane below: only a (node_id, port) pair recorded
    // here by an actual "admit" decision may have its packets forwarded (TT-1732 review, Tasneem
    // finding #1). Created before the startup heartbeat loop below (not after, like the TUN
    // device) since run_heartbeat's node-dialing needs it too, to evict a departed node's flows
    // (TT-1732 review, Tasneem, TT-1847 finding #1).
    let flow_table = Arc::new(std::sync::Mutex::new(FlowTable::new()));

    // TT-1838: the TUN device's own address is connector_virtual_ip - Portal's registered,
    // per-Connector control-channel address - not a locally guessed default anymore, so it can
    // only be known once the first heartbeat succeeds. Retries at the configured heartbeat
    // cadence (the same cadence steady-state heartbeats already use) rather than a separate,
    // invented backoff. The heartbeat's other effects (policy application, node dialing) also
    // run here on the very first successful attempt - nothing is fetched twice.
    let connector_virtual_ip = loop {
        match run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
        )
        .await
        {
            Ok(Some(ip)) => break ip,
            Ok(None) => {
                warn!(
                    "heartbeat succeeded but Portal has not assigned a connector_virtual_ip yet - cannot create the TUN device until it does, retrying"
                );
            }
            Err(error) => {
                error!(%error, "initial heartbeat failed - cannot create the TUN device until one succeeds, retrying");
            }
        }
        tokio::time::sleep(config.heartbeat_interval).await;
    };

    // Real packet forwarding (TT-1827): needs CAP_NET_ADMIN + /dev/net/tun,
    // proven for real via two Docker containers exchanging genuine ICMP
    // traffic through actual WireGuard encryption before this was wired in
    // (see tunnel.rs's module doc comment).
    let (tun_reader, tun_writer) =
        tun_device::create(connector_virtual_ip, config.tun_netmask, 1400)
            .context("failed to create the Connector's TUN device")?;
    info!(tun_addr = %connector_virtual_ip, tun_netmask = %config.tun_netmask, "TUN device ready");

    tokio::spawn(run_wireguard_receive_loop(
        wg_socket.clone(),
        tunnel_manager.clone(),
        tun_writer,
        flow_table.clone(),
        std::net::IpAddr::V4(connector_virtual_ip),
    ));
    tokio::spawn(run_tun_send_loop(
        tun_reader,
        wg_socket.clone(),
        tunnel_manager.clone(),
        flow_table.clone(),
    ));
    tokio::spawn(run_timer_loop(wg_socket.clone(), tunnel_manager.clone()));

    // TT-1838: bind to connector_virtual_ip itself, not a wildcard/loopback address - this is
    // what actually restricts these endpoints to genuine Gatekeeper peers (see flow_control.rs's
    // module doc). Only the port stays configurable.
    let control_plane_bind_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(connector_virtual_ip),
        config.control_plane_port,
    );
    let control_plane_listener = tokio::net::TcpListener::bind(control_plane_bind_addr)
        .await
        .with_context(|| format!("failed to bind the flow-admission control-plane listener on {control_plane_bind_addr}"))?;
    info!(
        addr = %control_plane_bind_addr,
        "flow-admission control plane listening"
    );
    let control_plane_router = flow_control::router(ControlPlaneState {
        policy_store: policy_store.clone(),
        audit_log: audit_log.clone(),
        signature_binding: Arc::new(std::sync::Mutex::new(
            signature_binding::SignatureBindingGuard::new(),
        )),
        flow_table: flow_table.clone(),
    });
    tokio::spawn(async move {
        if let Err(error) = axum::serve(control_plane_listener, control_plane_router).await {
            error!(%error, "flow-admission control plane server stopped");
        }
    });

    let mut interval = tokio::time::interval(config.heartbeat_interval);
    // The startup loop above already ran one successful heartbeat to learn
    // connector_virtual_ip - without this, interval's own first tick fires
    // immediately, re-running a heartbeat right away instead of waiting a
    // full interval like every subsequent one does.
    interval.reset();
    loop {
        interval.tick().await;
        match run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
        )
        .await
        {
            // A steady-state heartbeat reporting a different connector_virtual_ip than the one
            // the TUN device and control-plane listener were already created with (TT-1838) -
            // rebinding either live isn't supported, so this can only be surfaced, not applied.
            Ok(Some(latest)) if latest != connector_virtual_ip => {
                error!(
                    started_with = %connector_virtual_ip,
                    now_reported = %latest,
                    "Portal reported a different connector_virtual_ip than the one this process is bound to - restart the Connector to pick it up"
                );
            }
            Ok(_) => {}
            Err(error) => {
                error!(%error, "heartbeat cycle failed");
            }
        }
    }
}

/// Returns the Connector's own control-channel address if this heartbeat carried one - `main`
/// uses the very first successful heartbeat's value to create the TUN device (TT-1838), since
/// nothing local can guess it anymore (Portal is the sole source of truth). `None` means Portal
/// hasn't assigned one yet (or an older Agent didn't relay it) - not an error in itself, but
/// `main`'s startup loop treats it as "not ready" and keeps retrying.
// Each param is a genuinely distinct dependency this function needs (not an arbitrary pile) -
// bundling them into a struct would just move the same count into a constructor call at every
// site instead of removing it.
#[allow(clippy::too_many_arguments)]
async fn run_heartbeat(
    config: &Config,
    registry_client: &RegistryClient,
    heartbeat_client: &HeartbeatClient,
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    tunnel_manager: &Mutex<TunnelManager>,
    wg_socket: &UdpSocket,
    flow_table: &std::sync::Mutex<FlowTable>,
) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
    let agent_public_key = registry_client
        .get_agent_permitted_key(&config.agent_ip_address)
        .await?;
    let response = heartbeat_client
        .fetch_and_verify(&config.connector_id, &agent_public_key)
        .await?;

    let gateways = response.policy_bundles.len();
    let nodes = response.node_list.len();
    let node_list = response.node_list.clone();
    // Snapshotted before `policy_store.apply(response)` replaces it and before `response` is moved
    // (TT-1640): the entitlement lists this Connector had *before* this heartbeat, diffed after a
    // successful apply against what it has *now* - see `reconcile_dropped_entitlements`. `None` on
    // the very first heartbeat (nothing was ever admitted before any policy existed, so nothing to
    // diff against).
    let old_bundles = policy_store.current().map(|state| state.policy_bundles);
    let new_bundles = response.policy_bundles.clone();
    let nodes_without_key = node_list
        .iter()
        .filter(|node| node.wireguard_public_key.is_none())
        .count();
    let connector_virtual_ip = match &response.connector_virtual_ip {
        Some(raw) => match raw.parse::<std::net::Ipv4Addr>() {
            Ok(parsed) => Some(parsed),
            Err(error) => {
                error!(%error, value = %raw, "connector_virtual_ip in the heartbeat response is not a valid IPv4 address");
                None
            }
        },
        None => None,
    };

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
    if let Err(audit_error) = audit_log.record(audit_event).await {
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

    dial_new_nodes(tunnel_manager, wg_socket, &node_list, flow_table).await;
    if let Some(old_bundles) = old_bundles {
        reconcile_dropped_entitlements(flow_table, &old_bundles, &new_bundles);
    }

    Ok(connector_virtual_ip)
}

/// Tears down every already-admitted flow whose device dropped out of its gateway's entitlement
/// list in this heartbeat (TT-1640, "Revoke User Active Session From Gateway Through Connector",
/// spec §B.9.3: "each heartbeat's entitlement-list refresh tears down any open flow whose key has
/// dropped out"). Before this, dropping a user from `entitlement_list` (an admin revoking gateway
/// access, or an end-user being blocked) only blocked *new* admissions on the *next* heartbeat - an
/// already-admitted flow just kept forwarding traffic indefinitely, since nothing ever re-checked it
/// against a freshly-applied policy (`decide_access_at` is only consulted on `admit_flow`).
///
/// Diffs old vs. new per gateway: a device present in the old bundle's `entitlement_list` but not in
/// the new one - including when the whole gateway bundle disappeared entirely (gateway disabled,
/// Connector no longer attached to it, ...) - had its access revoked, so any admitted flow it still
/// holds on that gateway is evicted. A device that's still entitled, or a gateway that's unchanged,
/// is left completely alone. Idempotent and order-independent - evicting a device with no admitted
/// flow is a no-op (`FlowTable::evict_gateway_device`).
fn reconcile_dropped_entitlements(
    flow_table: &std::sync::Mutex<FlowTable>,
    old_bundles: &[PolicyBundle],
    new_bundles: &[PolicyBundle],
) {
    let mut table = flow_table.lock().expect("flow table lock poisoned");
    for old_bundle in old_bundles {
        let still_entitled: std::collections::HashSet<&str> = new_bundles
            .iter()
            .find(|bundle| bundle.gateway_id == old_bundle.gateway_id)
            .map(|bundle| {
                bundle
                    .entitlement_list
                    .iter()
                    .map(|e| e.device_public_key.as_str())
                    .collect()
            })
            .unwrap_or_default();
        for entitlement in &old_bundle.entitlement_list {
            if still_entitled.contains(entitlement.device_public_key.as_str()) {
                continue;
            }
            let evicted =
                table.evict_gateway_device(&old_bundle.gateway_id, &entitlement.device_public_key);
            if evicted > 0 {
                info!(
                    gateway_id = %old_bundle.gateway_id,
                    device_public_key = %entitlement.device_public_key,
                    evicted,
                    "entitlement dropped: tore down admitted flow(s) for this gateway"
                );
            }
        }
    }
}

/// Syncs the tunnel set to this heartbeat's node list, then kicks off a
/// handshake for any node that doesn't have an established session yet.
/// Established tunnels are left alone entirely - re-dialing them would
/// discard a working session for no reason. Also evicts `flow_table`'s
/// entries for any node this sync dropped (TT-1847 finding #1).
///
/// Collects the handshake packets to send *while* holding the
/// `tunnel_manager` lock (mutating each tunnel's state needs `&mut`), then
/// releases the lock before actually sending anything - the lock must never
/// be held across a network `.await`, or it serializes this heartbeat
/// dial-out against unrelated live traffic forwarding sharing the same
/// `TunnelManager` (TT-1732 review, Tasneem).
async fn dial_new_nodes(
    tunnel_manager: &Mutex<TunnelManager>,
    wg_socket: &UdpSocket,
    nodes: &[HeartbeatNode],
    flow_table: &std::sync::Mutex<FlowTable>,
) {
    let mut handshakes_to_send = Vec::new();
    let dropped = {
        let mut manager = tunnel_manager.lock().await;
        let dropped = manager.sync_nodes(nodes);

        for node in nodes {
            let Some(tunnel) = manager.tunnel_for(&node.node_id) else {
                continue;
            };
            if tunnel.is_established() {
                continue;
            }
            if let TunnelEvent::SendToNode(packet) = tunnel.initiate_handshake() {
                handshakes_to_send.push((packet, tunnel.addr, node.node_id.clone()));
            }
        }
        dropped
    };

    // A node this Connector no longer has a tunnel for can't have its flows released cleanly by
    // Gatekeeper either - evict them here instead of leaving permanent ghost entries (TT-1732
    // review, Tasneem, TT-1847 finding #1).
    if !dropped.is_empty() {
        let mut table = flow_table.lock().expect("flow table lock poisoned");
        for node_id in &dropped {
            info!(%node_id, "node no longer present in heartbeat's node list - evicting its admitted flows");
            table.evict_node(node_id);
        }
    }

    for (packet, addr, node_id) in handshakes_to_send {
        if let Err(error) = wg_socket.send_to(&packet, addr).await {
            error!(%error, %node_id, %addr, "failed to send WireGuard handshake initiation");
        }
    }
}

/// Drives every node tunnel's WireGuard session from the network side:
/// receives a datagram, matches it to the node it came from, feeds it to
/// that tunnel, and either sends back whatever the tunnel produces in
/// response (e.g. the initiator's post-handshake keepalive) or, for real
/// decrypted payload data, writes it to the TUN device so the OS's own IP
/// stack delivers it onward. Two distinct cases (TT-1838), gated
/// differently:
/// - Addressed to `connector_virtual_ip` itself: Gatekeeper's flow-admission/
///   release control channel, always forwarded - see the inline comment at
///   the gate for why no flow_table check applies here.
/// - Addressed anywhere else: forwarded traffic for admitted user flows,
///   still gated on `flow_table` (TT-1827, TT-1732 review, Tasneem finding
///   #1: decrypting successfully proves the packet came from a genuine node
///   tunnel, but says nothing about whether Gatekeeper's flow-admission
///   relay ever admitted this specific device/gateway; before that fix, ANY
///   decrypted traffic was forwarded regardless).
///
/// Runs for the lifetime of the process; a single receive error is logged
/// and the loop continues - one bad datagram must not take down every
/// node's tunnel.
async fn run_wireguard_receive_loop(
    wg_socket: Arc<UdpSocket>,
    tunnel_manager: Arc<Mutex<TunnelManager>>,
    mut tun_writer: tun_device::TunWriter,
    flow_table: Arc<std::sync::Mutex<FlowTable>>,
    connector_virtual_ip: std::net::IpAddr,
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
        let node_id = tunnel.node_id.clone();
        let event = tunnel.receive(&buf[..len]);
        drop(manager);

        let mut forwardable = false;
        if let TunnelEvent::DecryptedData(ref packet) = event {
            if Tunn::dst_address(packet) == Some(connector_virtual_ip) {
                // Addressed to the Connector's own control-channel address (TT-1838) - Gatekeeper
                // calling this Connector's own flow-admission/release API, not traffic being
                // forwarded onward to some internal endpoint. The flow_table gate below exists to
                // authorize *forwarded* traffic; it has no entry for this because this packet
                // *is* the thing that would create one. Reachability through the tunnel is itself
                // the trust boundary here (Konyk, TT-1732 thread) - now a real one, since this
                // address is no longer reachable by anything other than the genuine peer whose
                // wg0 allowed-ips include it.
                forwardable = true;
            } else {
                match tunnel::parse_source_port(packet) {
                    Some(source_port) => {
                        let is_admitted = flow_table
                            .lock()
                            .expect("flow table lock poisoned")
                            .gateway_for(&node_id, source_port)
                            .is_some();
                        if is_admitted {
                            forwardable = true;
                        } else {
                            warn!(
                                %node_id, source_port,
                                "decrypted packet has no matching admitted flow - dropping"
                            );
                        }
                    }
                    None => {
                        warn!(%node_id, "decrypted packet has no parseable source port - dropping");
                    }
                }
            }
        }

        match event {
            TunnelEvent::SendToNode(packet) => {
                if let Err(error) = wg_socket.send_to(&packet, src).await {
                    error!(%error, %src, "failed to send WireGuard response packet");
                }
            }
            TunnelEvent::DecryptedData(packet) => {
                if forwardable && let Err(error) = tun_writer.write_packet(&packet).await {
                    error!(%error, node_id = %node_id, "failed to write decrypted packet to TUN device");
                }
            }
            TunnelEvent::ProtocolError(protocol_error) => {
                warn!(error = %protocol_error, %src, "WireGuard protocol error");
            }
            TunnelEvent::Nothing => {}
        }
    }
}

/// Reads outbound IP packets the OS routed to the TUN device (e.g. return
/// traffic from an internal endpoint) and encrypts+sends each one to the
/// right node's tunnel (TT-1847). The destination *address* on this leg is
/// a masqueraded wg0 address identical across the whole fleet (`flow_table`'s
/// module doc) and carries no node identity - the destination *port* is the
/// only reliable signal left, resolved back to a node through `flow_table`'s
/// own admission state (told explicitly by Gatekeeper, never inferred from
/// traffic). A port with no unambiguous admitted node - never admitted, or
/// currently admitted on two different nodes at once - is dropped: there's
/// genuinely nowhere defensible to send it, not a bug to work around.
async fn run_tun_send_loop(
    mut tun_reader: tun_device::TunReader,
    wg_socket: Arc<UdpSocket>,
    tunnel_manager: Arc<Mutex<TunnelManager>>,
    flow_table: Arc<std::sync::Mutex<FlowTable>>,
) {
    let mut buf = [0u8; 2048];
    loop {
        let len = match tun_reader.read_packet(&mut buf).await {
            Ok(len) => len,
            Err(error) => {
                error!(%error, "failed to read from TUN device");
                continue;
            }
        };
        let Some(destination_port) = tunnel::parse_destination_port(&buf[..len]) else {
            continue;
        };

        // tunnel_manager is locked FIRST, and flow_table is looked up while still holding it, so
        // the admission check and the tunnel lookup are atomic with respect to each other - no
        // window where a concurrent release or node departure could invalidate node_id between
        // resolving it and using it (TT-1732 review, Tasneem, TT-1847 finding #2). flow_table's
        // std::sync::Mutex is only ever held for the synchronous lookup below, never across an
        // `.await`.
        let mut manager = tunnel_manager.lock().await;
        let node_id = {
            let table = flow_table.lock().expect("flow table lock poisoned");
            match table.node_for_port(destination_port) {
                Some(node_id) => node_id.to_string(),
                None => {
                    warn!(
                        destination_port,
                        "no unambiguous admitted node for outbound packet's port - dropping"
                    );
                    continue;
                }
            }
        };
        let Some(tunnel) = manager.tunnel_for(&node_id) else {
            warn!(%node_id, destination_port, "admitted node has no active tunnel - dropping");
            continue;
        };
        let event = tunnel.encapsulate(&buf[..len]);
        let addr = tunnel.addr;
        // Released before the send below - must never be held across a
        // network `.await` (TT-1732 review, Tasneem).
        drop(manager);

        if let TunnelEvent::SendToNode(packet) = event
            && let Err(error) = wg_socket.send_to(&packet, addr).await
        {
            error!(%error, %addr, %node_id, destination_port, "failed to send encrypted outbound packet");
        }
    }
}

/// Periodically drives every tunnel's WireGuard timers - required for
/// sessions to stay alive at all; boringtun does nothing on its own to
/// rekey or detect expiry unless this is called regularly (TT-1732 review,
/// Tasneem: `Tunn::update_timers` was never called anywhere before this
/// fix, so a session would silently go stale after a few minutes and never
/// be re-dialed). Interval matches boringtun's own documented usage
/// convention of roughly once per second.
async fn run_timer_loop(wg_socket: Arc<UdpSocket>, tunnel_manager: Arc<Mutex<TunnelManager>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let packets = {
            let mut manager = tunnel_manager.lock().await;
            manager.drive_all_timers()
        };
        for (packet, addr) in packets {
            if let Err(error) = wg_socket.send_to(&packet, addr).await {
                error!(%error, %addr, "failed to send WireGuard timer-driven packet");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dto::Entitlement;
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
            control_plane_port: 0,
            tun_netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
        )
        .await;

        // No connector_virtual_ip in this response body - Ok(None), not an error.
        assert_eq!(result.unwrap(), None);
        assert_eq!(policy_store.current().unwrap().connector_id, "c-1");
        let entries = read_audit_lines(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["event"], "policy_applied");
        assert_eq!(entries[0]["gateway_count"], 0);
    }

    /// TT-1838: `main` uses this returned value to create the TUN device - must be the real
    /// parsed address, not just "heartbeat succeeded".
    #[tokio::test]
    async fn run_heartbeat_returns_the_parsed_connector_virtual_ip_when_present() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","connector_virtual_ip":"10.98.0.7","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
        )
        .await;

        assert_eq!(result.unwrap(), Some(std::net::Ipv4Addr::new(10, 98, 0, 7)));
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

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
            &flow_table,
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
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

    fn bundle(gateway_id: &str, entitled_device_keys: &[&str]) -> PolicyBundle {
        PolicyBundle {
            gateway_id: gateway_id.to_string(),
            location: "Amsterdam".to_string(),
            hostname: "crm.internal.example.com".to_string(),
            access_mode: "SELECTED_USERS".to_string(),
            endpoints: vec![],
            entitlement_list: entitled_device_keys
                .iter()
                .map(|key| Entitlement {
                    user_id: "u-1".to_string(),
                    device_public_key: key.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn reconcile_dropped_entitlements_evicts_a_device_no_longer_entitled_to_its_gateway() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &[])];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none()
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_leaves_a_still_entitled_device_alone() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &["dev-A"])];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert_eq!(
            flow_table.lock().unwrap().gateway_for("n-1", 40001),
            Some("gw-1")
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_leaves_the_same_devices_other_gateway_flow_alone() {
        // The AC this whole feature exists for: revoking one gateway's access must never touch the
        // user's wider SecureConnect session, including their other Private Gateway access.
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
        );
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40002,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-A".to_string(),
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"]), bundle("gw-2", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &[]), bundle("gw-2", &["dev-A"])];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none()
        );
        assert_eq!(
            flow_table.lock().unwrap().gateway_for("n-1", 40002),
            Some("gw-2")
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_evicts_every_flow_when_the_whole_gateway_bundle_disappears() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles: Vec<PolicyBundle> = vec![];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none()
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_with_no_prior_bundles_is_a_no_op() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        reconcile_dropped_entitlements(&flow_table, &[], &[bundle("gw-1", &["dev-A"])]);
    }

    /// End-to-end through two real `run_heartbeat` calls: entitlement present on the first, dropped
    /// on the second - proving the diff actually runs off `PolicyStore`'s real before/after state,
    /// not just the pure reconciliation function above.
    #[tokio::test]
    async fn a_second_heartbeat_evicts_a_flow_whose_device_dropped_out_of_entitlement_list() {
        let agent_identity = crypto::generate_keypair();
        let first_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]},{"gateway_id":"gw-2","location":"Amsterdam","hostname":"erp.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
        let second_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:01:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n2","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[]},{"gateway_id":"gw-2","location":"Amsterdam","hostname":"erp.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
        let first_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, first_body.as_bytes());
        let second_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, second_body.as_bytes());

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
                    .set_body_raw(first_body, "application/json")
                    .insert_header("X-Signature", first_signature.as_str()),
            )
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(second_body, "application/json")
                    .insert_header("X-Signature", second_signature.as_str()),
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
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
        )
        .await
        .unwrap();
        // Simulates Gatekeeper admitting the flows during the window this Connector was entitled -
        // this must not be evicted by the *first* heartbeat's own apply (nothing to diff against yet).
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
        );
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40002,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-A".to_string(),
        );

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
        )
        .await;

        assert!(result.is_ok());
        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none(),
            "the flow on the gateway whose entitlement was dropped must be torn down"
        );
        assert_eq!(
            flow_table.lock().unwrap().gateway_for("n-1", 40002),
            Some("gw-2"),
            "the same device's flow on a gateway it's still entitled to must survive"
        );
    }
}
