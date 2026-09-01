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
use std::time::Duration;

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

/// Mirrors boringtun's own `REJECT_AFTER_TIME` (`noise::timers`, `pub(crate)`
/// there so not importable here) - a WireGuard session is no longer usable
/// once this much time has passed since its last successful handshake. Kept
/// in sync here so `NodeTunnel::is_established` stays consistent with when
/// boringtun itself actually considers the session dead, rather than "a
/// handshake completed at some point in this process's lifetime, however
/// long ago" (TT-1732 review, Tasneem).
const SESSION_REJECT_AFTER: Duration = Duration::from_secs(180);

/// Outcome of feeding a tunnel a network event, translated from boringtun's
/// borrowed `TunnResult` into owned bytes so callers don't fight lifetimes.
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelEvent {
    /// Bytes that must be sent back out over the socket to this node.
    SendToNode(Vec<u8>),
    /// Decrypted tunnel payload data - `main`'s receive loop checks it
    /// against `flow_table` and writes it to the TUN device if admitted
    /// (TT-1827, TT-1847).
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
    /// Which node this tunnel connects to - the key `flow_table` admission
    /// state is looked up under (TT-1827, TT-1847).
    pub node_id: String,
    pub addr: SocketAddr,
    /// The base64 WireGuard public key this tunnel was built with - compared
    /// against each heartbeat's reported key so `sync_nodes` can detect a
    /// rotation and rebuild rather than silently keep dialing a stale key.
    key_base64: String,
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

    /// A session has completed a handshake *and that session is still within
    /// its validity window* - not just "a handshake succeeded at some point
    /// in this process's lifetime", which per `Tunn::stats`'s own doc
    /// comment (element 0: time since last handshake, `None` until one has
    /// ever succeeded) would stay `true` forever after the first handshake,
    /// even long after the session has actually expired and nothing is
    /// re-dialing it (TT-1732 review, Tasneem - see `drive_timers`, which
    /// must be called periodically for boringtun to proactively rekey
    /// before this window closes).
    pub fn is_established(&self) -> bool {
        matches!(self.tunn.stats().0, Some(elapsed) if elapsed < SESSION_REJECT_AFTER)
    }

    /// Drives this tunnel's internal WireGuard timers - keepalives,
    /// proactive rekeying, and session-expiry detection. Must be called
    /// periodically (boringtun's own documented convention: roughly once
    /// per second) or a session silently goes stale with nothing to notice
    /// or recover it (TT-1732 review, Tasneem: `Tunn::update_timers` was
    /// never called anywhere in this codebase before this fix).
    pub fn drive_timers(&mut self) -> TunnelEvent {
        let mut buf = [0u8; 2048];
        self.tunn.update_timers(&mut buf).into()
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

/// Shared TCP/UDP header parsing for `parse_source_port`/`parse_destination_port` -
/// `field_offset` is 0 for the source port, 2 for the destination port (the two
/// fields are adjacent, first 4 bytes of either header). Same pragmatic scope
/// throughout: IPv4 accounts for a variable IHL, IPv6 assumes no extension
/// headers. `None` for anything that isn't TCP or UDP, or too short to contain
/// the requested port field - callers must treat that as "can't identify a
/// flow" (refuse), never as "no flow" (allow).
fn parse_l4_port(packet: &[u8], field_offset: usize) -> Option<u16> {
    let first_byte = *packet.first()?;
    let (protocol, l4_offset) = match first_byte >> 4 {
        4 => {
            let ihl = usize::from(first_byte & 0x0F) * 4;
            if ihl < 20 || packet.len() < ihl + 4 {
                return None;
            }
            (*packet.get(9)?, ihl)
        }
        6 => {
            if packet.len() < 44 {
                return None;
            }
            (*packet.get(6)?, 40)
        }
        _ => return None,
    };
    // 6 = TCP, 17 = UDP - both have source/destination port as the first
    // four bytes of their header, so no protocol-specific parsing is needed
    // beyond this.
    if protocol != 6 && protocol != 17 {
        return None;
    }
    let offset = l4_offset + field_offset;
    let port_bytes: [u8; 2] = packet.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(port_bytes))
}

/// Parses the source TCP/UDP port from a raw IPv4/IPv6 packet - the field
/// that identifies which admitted flow a decrypted packet belongs to (spec
/// §B.8: "distinguished by translated source port", `flow_table`).
pub fn parse_source_port(packet: &[u8]) -> Option<u16> {
    parse_l4_port(packet, 0)
}

/// Parses the destination TCP/UDP port from a raw IPv4/IPv6 packet - for a
/// reply packet arriving from the TUN side, this is the same translated port
/// the original flow was admitted on, and (TT-1847) the only reliable key
/// left for routing it back to the right node's tunnel: the packet's
/// destination *address* is a node's masqueraded wg0 address, which is
/// identical across the whole fleet (`FlowTable`'s own module doc) and so
/// carries no node identity at all.
pub fn parse_destination_port(packet: &[u8]) -> Option<u16> {
    parse_l4_port(packet, 2)
}

/// Builds and maintains one `NodeTunnel` per node currently reachable in the
/// Connector's Location, from the identity established in TT-1822.
pub struct TunnelManager {
    identity_secret: StaticSecret,
    rate_limiter: Arc<RateLimiter>,
    tunnels: HashMap<String, NodeTunnel>,
    next_index: u32,
}

impl TunnelManager {
    pub fn new(identity_secret: StaticSecret) -> Self {
        let identity_public = PublicKey::from(&identity_secret);
        Self {
            identity_secret,
            rate_limiter: Arc::new(RateLimiter::new(&identity_public, 10)),
            tunnels: HashMap::new(),
            next_index: 0,
        }
    }

    /// Adds a tunnel for each node with a reported WireGuard key that isn't
    /// already configured, and drops tunnels for nodes no longer in the
    /// list. A still-present node whose reported key or IP is unchanged from
    /// what its existing tunnel was built with is left alone entirely -
    /// rebuilding it would throw away an established session (and restart
    /// the handshake) for no reason. But a still-present node whose key or
    /// IP *did* change (a rotation) is rebuilt - otherwise the Connector
    /// would keep dialing a stale address/key indefinitely (TT-1732 review,
    /// Tasneem). A node whose key fails to decode is logged and skipped, not
    /// fatal to the rest of the sync - and never tears down a working
    /// existing tunnel just because a rebuild attempt failed.
    ///
    /// Returns the node_ids that were dropped by this sync (present before,
    /// gone now) - `main` uses this to evict their entries from `FlowTable`
    /// too (TT-1732 review, Tasneem, TT-1847 finding #1), so a flow for a
    /// node that's simply vanished doesn't linger forever.
    pub fn sync_nodes(&mut self, nodes: &[HeartbeatNode]) -> Vec<String> {
        let mut seen = HashSet::new();
        for node in nodes {
            let Some(wireguard_public_key) = &node.wireguard_public_key else {
                continue;
            };
            seen.insert(node.node_id.clone());

            if let Some(existing) = self.tunnels.get(&node.node_id) {
                let addr_unchanged = node
                    .ip_address
                    .parse::<IpAddr>()
                    .map(|ip| SocketAddr::new(ip, WIREGUARD_PORT) == existing.addr)
                    .unwrap_or(false);
                if addr_unchanged && existing.key_base64 == *wireguard_public_key {
                    continue;
                }
                tracing::info!(
                    node_id = %node.node_id,
                    "node's WireGuard key or address changed - rebuilding its tunnel"
                );
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
        let dropped: Vec<String> = self
            .tunnels
            .keys()
            .filter(|node_id| !seen.contains(*node_id))
            .cloned()
            .collect();
        self.tunnels.retain(|node_id, _| seen.contains(node_id));
        dropped
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
            key_base64: public_key_base64.to_string(),
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

    /// Drives every tunnel's WireGuard timers and collects any resulting
    /// packets to send - called periodically from `main` (TT-1732 review,
    /// Tasneem). Returns owned data rather than borrowing tunnels out, so
    /// the caller can send without holding this manager's own lock across
    /// the network `.await`.
    pub fn drive_all_timers(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
        let mut packets = Vec::new();
        for tunnel in self.tunnels.values_mut() {
            if let TunnelEvent::SendToNode(packet) = tunnel.drive_timers() {
                packets.push((packet, tunnel.addr));
            }
        }
        packets
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
    fn sync_nodes_rebuilds_a_tunnel_when_a_still_present_nodes_key_rotates() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let old_key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&old_key))]);
        manager.tunnel_for("n-1").unwrap().initiate_handshake();
        assert_eq!(manager.node_count(), 1);

        let new_key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&new_key))]);

        assert_eq!(manager.node_count(), 1);
        // A freshly-built tunnel has no handshake in progress yet, so it
        // produces a real initiation packet again rather than Nothing - the
        // old (stale-keyed) tunnel's in-progress state was discarded.
        let event = manager.tunnel_for("n-1").unwrap().initiate_handshake();
        assert!(matches!(event, TunnelEvent::SendToNode(_)));
    }

    #[test]
    fn sync_nodes_rebuilds_a_tunnel_when_a_still_present_nodes_ip_rotates() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        let old_addr = manager.tunnel_for("n-1").unwrap().addr;

        manager.sync_nodes(&[node("n-1", "10.0.0.99", Some(&key))]);

        let new_addr = manager.tunnel_for("n-1").unwrap().addr;
        assert_ne!(new_addr, old_addr);
        assert_eq!(new_addr.ip().to_string(), "10.0.0.99");
    }

    #[test]
    fn sync_nodes_leaves_an_existing_tunnel_alone_when_the_reported_key_and_ip_are_unchanged() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);
        manager.tunnel_for("n-1").unwrap().initiate_handshake();

        // Same node_id, same IP, same key - a second, identical sync.
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        // A rebuilt tunnel would not yet have a handshake in progress; this
        // one does, proving it's still the same tunnel instance.
        let event = manager.tunnel_for("n-1").unwrap().initiate_handshake();
        assert_eq!(event, TunnelEvent::Nothing);
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
    fn sync_nodes_returns_the_node_ids_it_dropped() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        let dropped = manager.sync_nodes(&[]);

        assert_eq!(dropped, vec!["n-1".to_string()]);
    }

    #[test]
    fn sync_nodes_returns_nothing_dropped_when_every_node_is_still_present() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        let dropped = manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        assert!(dropped.is_empty());
    }

    #[test]
    fn sync_nodes_does_not_report_a_rebuild_as_a_drop() {
        // A key/IP rotation rebuilds the tunnel in place - the node is still
        // present, just reconfigured, not gone.
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        let dropped = manager.sync_nodes(&[node("n-1", "10.0.0.99", Some(&key))]);

        assert!(dropped.is_empty());
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
    fn is_established_is_false_before_any_handshake() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        assert!(!manager.tunnel_for("n-1").unwrap().is_established());
    }

    #[test]
    fn drive_timers_on_an_unestablished_tunnel_does_not_panic() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));
        let key = random_public_key_base64();
        manager.sync_nodes(&[node("n-1", "10.0.0.10", Some(&key))]);

        // No assertion on the exact event - boringtun's own behavior before
        // any handshake has been attempted; this just proves the plumbing
        // (drive_timers callable on a fresh tunnel) doesn't crash.
        manager.tunnel_for("n-1").unwrap().drive_timers();
    }

    #[test]
    fn drive_all_timers_returns_no_packets_when_no_tunnels_exist() {
        let mut manager = TunnelManager::new(WgStaticSecret::random_from_rng(OsRng));

        assert!(manager.drive_all_timers().is_empty());
    }

    #[test]
    fn drive_all_timers_does_not_immediately_resend_a_freshly_established_session() {
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
        connector_side.receive(&handshake_response);
        assert!(connector_side.is_established());

        // Immediately after establishment, nothing needs rekeying or a
        // keepalive yet.
        assert!(connector_manager.drive_all_timers().is_empty());
    }

    fn udp_packet_with_source_port(source_port: u16) -> Vec<u8> {
        // Minimal 20-byte IPv4 header (IHL=5, protocol=17/UDP) followed by
        // an 8-byte UDP header whose first 2 bytes are the source port.
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet
    }

    #[test]
    fn parse_source_port_reads_a_udp_ipv4_packets_source_port() {
        let packet = udp_packet_with_source_port(40001);

        assert_eq!(parse_source_port(&packet), Some(40001));
    }

    #[test]
    fn parse_source_port_reads_a_tcp_ipv4_packets_source_port() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = 6; // TCP
        packet[20..22].copy_from_slice(&51234u16.to_be_bytes());

        assert_eq!(parse_source_port(&packet), Some(51234));
    }

    #[test]
    fn parse_source_port_accounts_for_a_non_default_ipv4_header_length() {
        // IHL=6 (24-byte header, i.e. one 4-byte options word) - the source
        // port must be read from offset 24, not the default offset 20.
        let mut packet = vec![0u8; 32];
        packet[0] = 0x46;
        packet[9] = 17;
        packet[24..26].copy_from_slice(&12345u16.to_be_bytes());

        assert_eq!(parse_source_port(&packet), Some(12345));
    }

    #[test]
    fn parse_source_port_returns_none_for_a_non_tcp_udp_protocol() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1; // ICMP
        packet[20..22].copy_from_slice(&40001u16.to_be_bytes());

        assert_eq!(parse_source_port(&packet), None);
    }

    #[test]
    fn parse_source_port_returns_none_for_a_truncated_or_empty_packet() {
        assert_eq!(parse_source_port(&[]), None);
        assert_eq!(parse_source_port(&[0x45, 0, 0, 0, 0, 0, 0, 0, 0, 17]), None);
    }

    #[test]
    fn parse_destination_port_reads_a_udp_ipv4_packets_destination_port() {
        // Same fixture as the source-port UDP test, but the destination
        // port occupies the next 2 bytes (offset 22..24, not 20..22).
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[22..24].copy_from_slice(&51820u16.to_be_bytes());

        assert_eq!(parse_destination_port(&packet), Some(51820));
    }

    #[test]
    fn parse_destination_port_reads_a_tcp_ipv4_packets_destination_port() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = 6; // TCP
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());

        assert_eq!(parse_destination_port(&packet), Some(443));
    }

    #[test]
    fn parse_source_and_destination_port_read_different_fields_of_the_same_packet() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[20..22].copy_from_slice(&40001u16.to_be_bytes());
        packet[22..24].copy_from_slice(&51820u16.to_be_bytes());

        assert_eq!(parse_source_port(&packet), Some(40001));
        assert_eq!(parse_destination_port(&packet), Some(51820));
    }

    #[test]
    fn parse_destination_port_returns_none_for_a_non_tcp_udp_protocol() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1; // ICMP
        packet[22..24].copy_from_slice(&40001u16.to_be_bytes());

        assert_eq!(parse_destination_port(&packet), None);
    }

    #[test]
    fn parse_destination_port_returns_none_for_a_truncated_or_empty_packet() {
        assert_eq!(parse_destination_port(&[]), None);
        assert_eq!(
            parse_destination_port(&[0x45, 0, 0, 0, 0, 0, 0, 0, 0, 17]),
            None
        );
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
        // still contain exactly the source address it was sent with.
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

        // Byte-for-byte identity already proves the source address field
        // (bytes 12..16) round-tripped intact through real encryption and
        // decryption - no separate field-level assertion needed.
        assert_eq!(decrypted, fake_ip_packet);
    }
}
