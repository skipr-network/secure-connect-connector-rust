//! WireGuard session establishment with each node in the Connector's
//! Location (TT-1732 acceptance criterion, spec §B.5: "The Connector dials
//! every currently-live EndpointNode in its Location over WireGuard
//! (BoringTun, embedded)").
//!
//! Handles both the WireGuard *session* (handshake) with each node and,
//! since TT-1827, routing decrypted/outbound packets to the right node once
//! a real TUN device (`tun_device.rs`) is wired in from `main`. Encryption
//! itself is verified with a real, live two-sided handshake test below -
//! not mocked: two genuine `Tunn` instances actually completing the
//! Noise-protocol exchange against each other. Real end-to-end packet
//! forwarding (TUN device + actual routed IP traffic) was proven separately,
//! outside this crate, before this file wired it in: two Docker containers,
//! each with a real TUN device and a real `Tunn`, exchanged genuine ICMP
//! traffic through actual WireGuard encryption between two separate network
//! namespaces (TT-1732 session notes, 2026-08-27).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::dto::HeartbeatNode;

/// WireGuard's IANA-assigned default port. Not specified anywhere in the
/// spec or the agreed Connector<->Gatekeeper contract - every node in this
/// fleet uses the standard port, same as any ordinary WireGuard deployment;
/// nothing found so far suggests a different convention.
pub(crate) const WIREGUARD_PORT: u16 = 51820;

/// Outcome of feeding a tunnel a network event, translated from boringtun's
/// borrowed `TunnResult` into owned bytes so callers don't fight lifetimes.
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelEvent {
    /// Bytes that must be sent back out over the socket to this node.
    SendToNode(Vec<u8>),
    /// Decrypted tunnel payload data - `main`'s receive loop learns a route
    /// from its source address and writes it to the TUN device (TT-1827).
    DecryptedData(Vec<u8>),
    /// Nothing to send, nothing decoded - e.g. a keepalive, or a handshake
    /// already in progress.
    Nothing,
    /// The tunnel reported a protocol-level error (bad packet, expired
    /// session, etc.) - never a panic, always surfaced as data.
    ProtocolError(String),
}

impl From<TunnResult<'_>> for TunnelEvent {
    fn from(result: TunnResult<'_>) -> Self {
        match result {
            TunnResult::WriteToNetwork(packet) => TunnelEvent::SendToNode(packet.to_vec()),
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                TunnelEvent::DecryptedData(packet.to_vec())
            }
            TunnResult::Done => TunnelEvent::Nothing,
            TunnResult::Err(error) => TunnelEvent::ProtocolError(format!("{error:?}")),
        }
    }
}

pub struct NodeTunnel {
    tunn: Tunn,
    /// Read by `main`'s receive loop to learn which node a decrypted
    /// packet's source address is reachable through (TT-1827).
    pub node_id: String,
    pub addr: SocketAddr,
}

impl NodeTunnel {
    /// Produces the handshake-initiation packet to send to this node.
    pub fn initiate_handshake(&mut self) -> TunnelEvent {
        let mut buf = [0u8; 2048];
        self.tunn
            .format_handshake_initiation(&mut buf, false)
            .into()
    }

    /// Feeds a datagram received from this node into the tunnel - a
    /// handshake response, an established session's keepalive/data packet,
    /// or a malformed/unexpected one (surfaced as `ProtocolError`, never a
    /// panic).
    pub fn receive(&mut self, datagram: &[u8]) -> TunnelEvent {
        let mut buf = [0u8; 2048];
        self.tunn
            .decapsulate(Some(self.addr.ip()), datagram, &mut buf)
            .into()
    }

    /// A session has completed its handshake at least once. Per
    /// `Tunn::stats`'s own doc comment, the first element is "time since
    /// last handshake" - `None` until one has actually succeeded.
    pub fn is_established(&self) -> bool {
        self.tunn.stats().0.is_some()
    }

    /// Encrypts an outbound IP packet (read from the TUN device) for sending
    /// to this node. If no session is established yet, boringtun queues the
    /// packet internally and this produces a handshake-initiation instead -
    /// the queued packet is sent automatically once the handshake completes.
    pub fn encapsulate(&mut self, packet: &[u8]) -> TunnelEvent {
        let mut buf = [0u8; 2048];
        self.tunn.encapsulate(packet, &mut buf).into()
    }
}

/// Parses the source address from a raw IPv4/IPv6 packet - the counterpart
/// to `Tunn::dst_address` (which boringtun exposes publicly; there's no
/// source-address equivalent), needed to learn which node a decrypted
/// packet's sender is reachable through. Same header byte offsets
/// boringtun's own (private) parsing uses internally.
pub fn parse_source_address(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
        6 if packet.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
        _ => None,
    }
}

/// Builds and maintains one `NodeTunnel` per node currently reachable in the
/// Connector's Location, from the identity established in TT-1822.
pub struct TunnelManager {
    identity_secret: StaticSecret,
    rate_limiter: Arc<RateLimiter>,
    tunnels: HashMap<String, NodeTunnel>,
    next_index: u32,
    /// Destination IP -> node_id, learned from the source IP of decrypted
    /// packets actually received from that node's tunnel (TT-1827). Not a
    /// statically configured AllowedIPs/addressing table: nothing in the
    /// spec or the agreed Connector<->Gatekeeper contract defines a virtual
    /// addressing scheme for the Connector<->Node leg, so routing return
    /// traffic by "which node did we last hear this IP from" is the
    /// defensible minimum rather than inventing an unagreed addressing plan.
    routes: HashMap<IpAddr, String>,
}

impl TunnelManager {
    pub fn new(identity_secret: StaticSecret) -> Self {
        let identity_public = PublicKey::from(&identity_secret);
        Self {
            identity_secret,
            rate_limiter: Arc::new(RateLimiter::new(&identity_public, 10)),
            tunnels: HashMap::new(),
            next_index: 0,
            routes: HashMap::new(),
        }
    }

    /// Adds a tunnel for each node with a reported WireGuard key that isn't
    /// already configured, and drops tunnels for nodes no longer in the
    /// list. Deliberately leaves existing tunnels for still-present nodes
    /// untouched - rebuilding one would throw away an established session
    /// (and restart the handshake) for no reason. A node whose key fails to
    /// decode is logged and skipped, not fatal to the rest of the sync.
    pub fn sync_nodes(&mut self, nodes: &[HeartbeatNode]) {
        let mut seen = HashSet::new();
        for node in nodes {
            let Some(wireguard_public_key) = &node.wireguard_public_key else {
                continue;
            };
            seen.insert(node.node_id.clone());
            if self.tunnels.contains_key(&node.node_id) {
                continue;
            }
            match self.build_tunnel(node, wireguard_public_key) {
                Ok(tunnel) => {
                    self.tunnels.insert(node.node_id.clone(), tunnel);
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        node_id = %node.node_id,
                        "failed to configure WireGuard tunnel for node"
                    );
                }
            }
        }
        self.tunnels.retain(|node_id, _| seen.contains(node_id));
    }

    fn build_tunnel(
        &mut self,
        node: &HeartbeatNode,
        public_key_base64: &str,
    ) -> Result<NodeTunnel> {
        let public_key = decode_public_base64(public_key_base64).with_context(|| {
            format!("node {} has an unusable WireGuard public key", node.node_id)
        })?;
        let ip: IpAddr = node.ip_address.parse().with_context(|| {
            format!(
                "node {} has an unparseable ip_address: {}",
                node.node_id, node.ip_address
            )
        })?;

        let index = self.next_index;
        self.next_index = self.next_index.wrapping_add(1);
        let tunn = Tunn::new(
            self.identity_secret.clone(),
            public_key,
            None,
            None,
            index,
            Some(self.rate_limiter.clone()),
        );

        Ok(NodeTunnel {
            tunn,
            node_id: node.node_id.clone(),
            addr: SocketAddr::new(ip, WIREGUARD_PORT),
        })
    }

    pub fn tunnel_for(&mut self, node_id: &str) -> Option<&mut NodeTunnel> {
        self.tunnels.get_mut(node_id)
    }

    /// Matches an incoming UDP datagram's source address back to the node it
    /// came from - a real socket has no other way to know which `NodeTunnel`
    /// should process a given packet.
    pub fn tunnel_for_addr(&mut self, addr: SocketAddr) -> Option<&mut NodeTunnel> {
        self.tunnels.values_mut().find(|tunnel| tunnel.addr == addr)
    }

    #[allow(dead_code)]
    pub fn node_count(&self) -> usize {
        self.tunnels.len()
    }

    /// Records that `source_ip` is reachable via `node_id`'s tunnel - called
    /// after successfully decrypting a packet from that node, so return
    /// traffic (or anything else destined to it) can be routed correctly.
    pub fn learn_route(&mut self, node_id: &str, source_ip: IpAddr) {
        self.routes.insert(source_ip, node_id.to_string());
    }

    /// Looks up which node's tunnel an outbound packet (by its destination
    /// IP) should be routed through. `None` means we've never seen traffic
    /// from that address, so there's genuinely nowhere defensible to send
    /// it - the caller drops the packet rather than guessing.
    pub fn route_for(&mut self, destination_ip: IpAddr) -> Option<&mut NodeTunnel> {
        let node_id = self.routes.get(&destination_ip)?.clone();
        self.tunnels.get_mut(&node_id)
    }
}

fn decode_public_base64(value: &str) -> Result<PublicKey> {
    let bytes = BASE64
        .decode(value)
        .context("WireGuard public key is not valid base64")?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard public key must be exactly 32 bytes"))?;
    Ok(PublicKey::from(array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::StaticSecret as WgStaticSecret;
    use rand_core::OsRng;

    fn node(node_id: &str, ip: &str, public_key_base64: Option<&str>) -> HeartbeatNode {
        HeartbeatNode {
            node_id: node_id.to_string(),
            ip_address: ip.to_string(),
            wireguard_public_key: public_key_base64.map(|value| value.to_string()),
        }
    }

    fn random_public_key_base64() -> String {
        let secret = WgStaticSecret::random_from_rng(OsRng);
        BASE64.encode(PublicKey::from(&secret).as_bytes())
    }

    #[test]
    fn sync_nodes_skips_a_node_with_no_reported_key_yet() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));

        manager.sync_nodes(&[node("n-1", "10.0.0.10", None)]);

        assert_eq!(manager.node_count(), 0);
    }

    #[test]
    fn sync_nodes_configures_a_tunnel_for_a_node_with_a_valid_key() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();

        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        assert_eq!(manager.node_count(), 1);
        assert!(manager.tunnel_for("n-1").is_some());
    }

    #[test]
    fn sync_nodes_skips_and_logs_a_node_with_an_undecodable_key_without_failing_the_rest() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let valid_key = random_public_key_base64();

        manager.sync_nodes(&[
            node("n-bad", "10.0.0.10", Some("not-valid-base64!!")),
            node("n-good", "10.0.0.11", Some(&valid_key)),
        ]);

        assert_eq!(manager.node_count(), 1);
        assert!(manager.tunnel_for("n-good").is_some());
        assert!(manager.tunnel_for("n-bad").is_none());
    }

    #[test]
    fn tunnel_for_addr_finds_the_tunnel_matching_that_source_address() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        let expected_addr = manager.tunnel_for("n-1").unwrap().addr;

        let found = manager.tunnel_for_addr(expected_addr).unwrap();

        assert_eq!(found.node_id, "n-1");
    }

    #[test]
    fn tunnel_for_addr_returns_none_for_an_unrecognized_address() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        let found = manager.tunnel_for_addr("10.0.0.99:51820".parse().unwrap());

        assert!(found.is_none());
    }

    #[test]
    fn sync_nodes_skips_a_node_with_an_unparseable_ip_address() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();

        manager.sync_nodes(&[node("n-1", "not-an-ip", Some(&key))]);

        assert_eq!(manager.node_count(), 0);
    }

    #[test]
    fn sync_nodes_drops_a_tunnel_for_a_node_no_longer_present() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        assert_eq!(manager.node_count(), 1);

        manager.sync_nodes(&[]);

        assert_eq!(manager.node_count(), 0);
    }

    #[test]
    fn sync_nodes_preserves_an_existing_tunnel_for_a_still_present_node_rather_than_rebuilding_it()
    {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        // Start (and partially complete, in spirit) a handshake so there's
        // real per-tunnel state that a rebuild would visibly discard.
        manager.tunnel_for("n-1").unwrap().initiate_handshake();

        // A second sync with the same node present - same key, same node_id.
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        // A freshly-built tunnel would not yet have a handshake in progress,
        // so asking it to initiate again would produce a new packet rather
        // than Nothing (a handshake already in progress is Done/Nothing).
        let second_attempt = manager.tunnel_for("n-1").unwrap().initiate_handshake();
        assert_eq!(second_attempt, TunnelEvent::Nothing);
    }

    #[test]
    fn parse_source_address_reads_an_ipv4_header() {
        // A minimal 20-byte IPv4 header: version/IHL, then bytes up to the
        // source address field (offset 12-16), destination (16-20) unused
        // here.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // version 4, IHL 5
        packet[12..16].copy_from_slice(&[10, 0, 0, 5]);

        let source = parse_source_address(&packet);

        assert_eq!(source, Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn parse_source_address_reads_an_ipv6_header() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // version 6
        packet[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let source = parse_source_address(&packet);

        assert_eq!(source, Some("::1".parse().unwrap()));
    }

    #[test]
    fn parse_source_address_returns_none_for_a_truncated_or_empty_packet() {
        assert_eq!(parse_source_address(&[]), None);
        assert_eq!(parse_source_address(&[0x45, 0, 0]), None);
    }

    #[test]
    fn route_for_returns_none_when_nothing_has_ever_been_learned() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));

        let route = manager.route_for("10.0.0.5".parse().unwrap());

        assert!(route.is_none());
    }

    #[test]
    fn learn_route_then_route_for_finds_the_right_tunnel() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        let destination: IpAddr = "10.0.0.5".parse().unwrap();

        manager.learn_route("n-1", destination);
        let route = manager.route_for(destination);

        assert!(route.is_some());
    }

    #[test]
    fn route_for_returns_none_if_the_learned_nodes_tunnel_was_since_dropped() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        let destination: IpAddr = "10.0.0.5".parse().unwrap();
        manager.learn_route("n-1", destination);

        // The node disappears from a later heartbeat's node_list.
        manager.sync_nodes(&[]);

        assert!(manager.route_for(destination).is_none());
    }

    #[test]
    fn encapsulate_without_an_established_session_starts_a_handshake_instead() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        let tunnel = manager.tunnel_for("n-1").unwrap();

        // No handshake has happened yet, so encapsulating a data packet
        // queues it internally and produces a handshake-initiation instead -
        // boringtun's own behavior, not something this code decides.
        let event = tunnel.encapsulate(b"not a real ip packet, just payload bytes");

        assert!(matches!(event, TunnelEvent::SendToNode(_)));
    }

    #[test]
    fn a_real_handshake_completes_end_to_end_between_two_tunnels() {
        // Not a mock: two genuine Tunn instances, configured exactly the way
        // this Connector configures its side, actually completing the
        // Noise-protocol handshake against each other.
        let connector_secret = WgStaticSecret::random_from_rng(OsRng);
        let connector_public = PublicKey::from(&connector_secret);
        let node_secret = WgStaticSecret::random_from_rng(OsRng);
        let node_public = PublicKey::from(&node_secret);

        let mut connector_manager = TunnelManager::new(connector_secret);
        connector_manager.sync_nodes(&[node(
            "n-1",
            "127.0.0.1",
            Some(&BASE64.encode(node_public.as_bytes())),
        )]);
        let connector_side = connector_manager.tunnel_for("n-1").unwrap();

        // The node's side isn't built by this Connector - simulated here as
        // a bare Tunn standing in for what Gatekeeper's own WireGuard
        // interface does.
        let mut node_side = Tunn::new(node_secret, connector_public, None, None, 0, None);

        let handshake_init = match connector_side.initiate_handshake() {
            TunnelEvent::SendToNode(bytes) => bytes,
            other => panic!("expected a handshake-initiation packet, got {other:?}"),
        };

        let mut buf = [0u8; 2048];
        let handshake_response = match node_side.decapsulate(None, &handshake_init, &mut buf) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("expected the node to respond, got {other:?}"),
        };

        let keepalive = match connector_side.receive(&handshake_response) {
            TunnelEvent::SendToNode(bytes) => bytes,
            other => panic!("expected the connector to send a keepalive, got {other:?}"),
        };
        assert!(connector_side.is_established());

        let final_event = node_side.decapsulate(None, &keepalive, &mut buf);
        assert!(matches!(final_event, TunnResult::Done));

        // Now prove real data forwarding over the established session - not
        // just the handshake: a fake IPv4 packet, encrypted by the
        // Connector side, decrypted by the node side, and confirmed to
        // still contain exactly the source address the Connector would
        // learn a route from.
        let mut fake_ip_packet = vec![0u8; 20];
        fake_ip_packet[0] = 0x45;
        fake_ip_packet[2..4].copy_from_slice(&20u16.to_be_bytes()); // total length
        fake_ip_packet[12..16].copy_from_slice(&[10, 99, 0, 1]); // source
        fake_ip_packet[16..20].copy_from_slice(&[10, 99, 0, 2]); // destination

        let encrypted = match connector_side.encapsulate(&fake_ip_packet) {
            TunnelEvent::SendToNode(bytes) => bytes,
            other => panic!("expected an encrypted data packet, got {other:?}"),
        };

        let decrypted = match node_side.decapsulate(None, &encrypted, &mut buf) {
            TunnResult::WriteToTunnelV4(bytes, _) => bytes.to_vec(),
            other => panic!("expected the node to decrypt a tunnel payload, got {other:?}"),
        };

        assert_eq!(decrypted, fake_ip_packet);
        assert_eq!(
            parse_source_address(&decrypted),
            Some("10.99.0.1".parse().unwrap())
        );
    }
}
