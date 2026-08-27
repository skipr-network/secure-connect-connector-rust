//! WireGuard session establishment with each node in the Connector's
//! Location (TT-1732 acceptance criterion, spec §B.5: "The Connector dials
//! every currently-live EndpointNode in its Location over WireGuard
//! (BoringTun, embedded)").
//!
//! Scoped to establishing and maintaining the WireGuard *session* with each
//! node - the handshake - not routing arbitrary IP traffic through it. Real
//! packet forwarding needs a TUN device, which needs OS privileges this
//! doesn't assume (and this environment doesn't have); per the spec's own
//! "first release scope: relay plus the control protocol specified here,
//! nothing more" and matching `flow_control`'s precedent (there's nothing to
//! forward yet either), that's explicitly out of scope here. What this
//! proves instead: the actual Noise-protocol handshake completing, end to
//! end, between two real `Tunn` instances configured the way this Connector
//! configures them - not a mock of the protocol, the real thing.

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
const WIREGUARD_PORT: u16 = 51820;

/// Outcome of feeding a tunnel a network event, translated from boringtun's
/// borrowed `TunnResult` into owned bytes so callers don't fight lifetimes.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum TunnelEvent {
    /// Bytes that must be sent back out over the socket to this node.
    SendToNode(Vec<u8>),
    /// Decrypted tunnel payload data - not acted on yet, see the module doc
    /// comment; kept distinct from `Nothing` so a future forwarding slice
    /// has something concrete to match on instead of silently dropping it.
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

#[allow(dead_code)]
pub struct NodeTunnel {
    tunn: Tunn,
    pub node_id: String,
    pub addr: SocketAddr,
}

impl NodeTunnel {
    /// Produces the handshake-initiation packet to send to this node.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn receive(&mut self, datagram: &[u8]) -> TunnelEvent {
        let mut buf = [0u8; 2048];
        self.tunn
            .decapsulate(Some(self.addr.ip()), datagram, &mut buf)
            .into()
    }

    /// A session has completed its handshake at least once. Per
    /// `Tunn::stats`'s own doc comment, the first element is "time since
    /// last handshake" - `None` until one has actually succeeded.
    #[allow(dead_code)]
    pub fn is_established(&self) -> bool {
        self.tunn.stats().0.is_some()
    }
}

/// Builds and maintains one `NodeTunnel` per node currently reachable in the
/// Connector's Location, from the identity established in TT-1822.
#[allow(dead_code)]
pub struct TunnelManager {
    identity_secret: StaticSecret,
    rate_limiter: Arc<RateLimiter>,
    tunnels: HashMap<String, NodeTunnel>,
    next_index: u32,
}

impl TunnelManager {
    #[allow(dead_code)]
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
    /// list. Deliberately leaves existing tunnels for still-present nodes
    /// untouched - rebuilding one would throw away an established session
    /// (and restart the handshake) for no reason. A node whose key fails to
    /// decode is logged and skipped, not fatal to the rest of the sync.
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn tunnel_for(&mut self, node_id: &str) -> Option<&mut NodeTunnel> {
        self.tunnels.get_mut(node_id)
    }

    #[allow(dead_code)]
    pub fn node_count(&self) -> usize {
        self.tunnels.len()
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
    }
}
