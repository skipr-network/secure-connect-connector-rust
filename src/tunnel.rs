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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

/// Only the first fragment of a fragmented IPv4 datagram carries a transport-layer header - later
/// fragments are pure payload continuation, with no port fields, checksum, or anything else this
/// module expects to find at these offsets (TT-2046 review finding #2). Nothing upstream of this
/// checks for fragmentation, so without this, a later fragment's raw payload bytes get silently
/// misread as port numbers on the parse side, and on the rewrite side a "checksum fixup" write can
/// land on and corrupt real payload bytes. `packet` must already be confirmed IPv4 (version
/// nibble already checked) before calling this - it doesn't re-check that itself. Too short to
/// even read the field is treated as "yes, a later fragment" - the safe direction (refuse), not
/// "assume it's fine".
fn is_non_first_ipv4_fragment(packet: &[u8]) -> bool {
    match (packet.get(6), packet.get(7)) {
        (Some(&byte6), Some(&byte7)) => (u16::from(byte6 & 0x1F) << 8 | u16::from(byte7)) != 0,
        _ => true,
    }
}

/// Shared TCP/UDP header parsing for `parse_source_port`/`parse_destination_port` -
/// `field_offset` is 0 for the source port, 2 for the destination port (the two
/// fields are adjacent, first 4 bytes of either header). Same pragmatic scope
/// throughout: IPv4 accounts for a variable IHL, IPv6 assumes no extension
/// headers. `None` for anything that isn't TCP or UDP, too short to contain
/// the requested port field, or (IPv4) a non-first fragment - callers must
/// treat that as "can't identify a flow" (refuse), never as "no flow" (allow).
fn parse_l4_port(packet: &[u8], field_offset: usize) -> Option<u16> {
    let first_byte = *packet.first()?;
    let (protocol, l4_offset) = match first_byte >> 4 {
        4 => {
            let ihl = usize::from(first_byte & 0x0F) * 4;
            if ihl < 20 || packet.len() < ihl + 4 {
                return None;
            }
            if is_non_first_ipv4_fragment(packet) {
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

fn read_u16(packet: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

fn write_u16(packet: &mut [u8], offset: usize, value: u16) {
    packet[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

/// RFC 1624 incremental checksum update: the standard technique for updating
/// a ones-complement checksum (an IPv4 header checksum, or a TCP/UDP
/// checksum via its pseudo-header) after replacing one 16-bit word, without
/// needing to re-sum anything else the checksum covers - in particular,
/// without ever touching an L4 payload that could be arbitrarily large.
/// `HC' = ~(~HC + ~m + m')`.
fn checksum_adjust(old_checksum: u16, old_word: u16, new_word: u16) -> u16 {
    let mut sum = u32::from(!old_checksum) + u32::from(!old_word) + u32::from(new_word);
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Shared implementation for `rewrite_destination_ipv4`/`rewrite_source_ipv4` - `field_offset` is
/// 16 for the destination address, 12 for the source, the only difference between the two calls:
/// both the IPv4 header checksum and the TCP/UDP pseudo-header checksum cover either address
/// field identically, so the same incremental update applies regardless of which one changed.
///
/// Updates the IPv4 header checksum and, for TCP/UDP, the L4 checksum too (its pseudo-header
/// covers both address fields) - both via `checksum_adjust`'s incremental update, not a full
/// recompute, so this never needs to read or understand the L4 payload itself. UDP's checksum is
/// optional (RFC 768): a `0` there means "none computed" and is left alone; TCP's is mandatory and
/// always updated. For UDP specifically, if the *updated* checksum itself computes to `0`, it's
/// written as `0xFFFF` instead (RFC 768's own rule for a genuinely-zero checksum) - otherwise it
/// would be indistinguishable from "no checksum computed".
///
/// v1 scope: IPv4 packets only - `new_addr` itself is always a concrete `Ipv4Addr` by the time
/// this is called, whether the configured `PolicyBundleEndpoint.host` was a literal IP or a
/// hostname `dns_cache` already resolved (TT-2066); this function never sees the host string
/// itself. Returns `false` (packet left completely untouched) for an IPv6 *packet*, a non-TCP/UDP
/// protocol, a non-first IPv4 fragment (TT-2046 review finding #2 - no L4 header to update at
/// all), or anything too short to safely contain the fields being touched - callers must treat
/// that as "can't forward this", never as "forwarded unchanged".
fn rewrite_ipv4_address(packet: &mut [u8], field_offset: usize, new_addr: Ipv4Addr) -> bool {
    let Some(&first_byte) = packet.first() else {
        return false;
    };
    if first_byte >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(first_byte & 0x0F) * 4;
    if ihl < 20 || packet.len() < ihl {
        return false;
    }
    if is_non_first_ipv4_fragment(packet) {
        return false;
    }
    let Some(&protocol) = packet.get(9) else {
        return false;
    };
    if protocol != 6 && protocol != 17 {
        return false;
    }
    let l4_checksum_offset = match protocol {
        6 => ihl + 16, // TCP
        17 => ihl + 6, // UDP
        _ => unreachable!("checked above"),
    };
    if packet.len() < l4_checksum_offset + 2 {
        return false;
    }

    let old_hi = read_u16(packet, field_offset);
    let old_lo = read_u16(packet, field_offset + 2);
    let new_octets = new_addr.octets();
    let new_hi = u16::from_be_bytes([new_octets[0], new_octets[1]]);
    let new_lo = u16::from_be_bytes([new_octets[2], new_octets[3]]);

    // IPv4 header checksum - fixed offset 10..12, always inside the base
    // 20-byte header regardless of IHL.
    let ip_checksum = read_u16(packet, 10);
    let ip_checksum = checksum_adjust(ip_checksum, old_hi, new_hi);
    let ip_checksum = checksum_adjust(ip_checksum, old_lo, new_lo);
    write_u16(packet, 10, ip_checksum);

    let l4_checksum = read_u16(packet, l4_checksum_offset);
    if protocol == 6 || l4_checksum != 0 {
        let l4_checksum = checksum_adjust(l4_checksum, old_hi, new_hi);
        let l4_checksum = checksum_adjust(l4_checksum, old_lo, new_lo);
        // RFC 768: a UDP checksum that genuinely computes to 0 must be transmitted as
        // 0xFFFF - 0x0000 on the wire means "no checksum was computed" instead. TCP has
        // no such rule (0 is a plain valid TCP checksum), so this only applies to UDP.
        let l4_checksum = if protocol == 17 && l4_checksum == 0 {
            0xFFFF
        } else {
            l4_checksum
        };
        write_u16(packet, l4_checksum_offset, l4_checksum);
    }

    packet[field_offset..field_offset + 4].copy_from_slice(&new_octets);
    true
}

/// Rewrites a decrypted packet's IPv4 destination address in place - the
/// step that actually makes forwarded traffic reach a Private Gateway's real
/// configured internal endpoint, rather than Gatekeeper's invented,
/// unroutable virtual gateway address (TT-2046; see `GatewayVirtualAddressRegistry`
/// on the Gatekeeper side - "zero relationship to any real internal address,
/// the whole point is Gatekeeper never learns the internal host:port
/// allowlist"). `flow_table::forward_target` resolves *which* real address to
/// rewrite to; this does the actual byte-level rewrite. See `rewrite_ipv4_address`
/// for the shared mechanics and full behavior contract.
pub fn rewrite_destination_ipv4(packet: &mut [u8], new_dst: Ipv4Addr) -> bool {
    rewrite_ipv4_address(packet, 16, new_dst)
}

/// Rewrites a reply packet's IPv4 *source* address in place, on the way back out to a node
/// (`main::run_tun_send_loop`) - the other half of TT-2046's translation, without which a reply
/// arrives at the client carrying the real internal address as its source instead of the virtual
/// address the client actually dialed. A real kernel DNAT gets this reversal for free via
/// conntrack; this rewrite happens in userspace with no conntrack entry to reverse it
/// automatically, so it has to be done explicitly, symmetrically to `rewrite_destination_ipv4`
/// (TT-2046 review finding #1). `flow_table`'s recorded `virtual_address` for the flow is what
/// `new_src` should be. See `rewrite_ipv4_address` for the shared mechanics and full behavior
/// contract.
pub fn rewrite_source_ipv4(packet: &mut [u8], new_src: Ipv4Addr) -> bool {
    rewrite_ipv4_address(packet, 12, new_src)
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
    fn checksum_adjust_matches_a_hand_computed_example() {
        // old_checksum is the correct ones'-complement checksum of just {0x1234, 0x5678}:
        // sum = 0x68AC, checksum = !0x68AC = 0x9753. Replacing the first word with 0x1235 (the
        // destination-address-rewrite case, one word of a multi-word field) must produce exactly
        // the checksum a full recompute over {0x1235, 0x5678} would give: sum = 0x68AD,
        // checksum = 0x9752.
        assert_eq!(checksum_adjust(0x9753, 0x1234, 0x1235), 0x9752);
    }

    /// Independent reference implementation (deliberately not calling any production checksum
    /// code) of the standard ones'-complement checksum sum - used two ways: computed over bytes
    /// with the checksum field zeroed, `!result` is the value to write there; computed over bytes
    /// that already contain a correct checksum, `result` itself must equal `0xFFFF` exactly (the
    /// standard verification trick, since a word and its ones'-complement always sum to all-ones).
    fn reference_ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u32::from(u16::from_be_bytes(*c)))
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16
    }

    /// Builds a well-formed IPv4/UDP packet with genuinely correct checksums (both the IP header
    /// and the UDP checksum), computed via `reference_ones_complement_sum` - not by calling
    /// anything `rewrite_destination_ipv4` itself depends on.
    fn valid_ipv4_udp_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let payload = b"ping";
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        let ip_checksum = !reference_ones_complement_sum(&packet[0..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..28 + payload.len()].copy_from_slice(payload);

        let mut pseudo_and_segment = Vec::new();
        pseudo_and_segment.extend_from_slice(&src.octets());
        pseudo_and_segment.extend_from_slice(&dst.octets());
        pseudo_and_segment.push(0);
        pseudo_and_segment.push(17);
        pseudo_and_segment.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo_and_segment.extend_from_slice(&packet[20..20 + udp_len]);
        let udp_checksum = !reference_ones_complement_sum(&pseudo_and_segment);
        packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());

        packet
    }

    #[test]
    fn rewrite_destination_ipv4_writes_the_new_destination_address() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );

        assert!(rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));

        assert_eq!(&packet[16..20], &[10, 0, 0, 5]);
    }

    #[test]
    fn rewrite_destination_ipv4_keeps_the_ip_header_checksum_valid() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );

        assert!(rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));

        // The standard verification trick: summing a header that already contains its own
        // correct checksum always yields all-ones (0xFFFF), independent of what the header's
        // other contents are.
        assert_eq!(reference_ones_complement_sum(&packet[0..20]), 0xFFFF);
    }

    #[test]
    fn rewrite_destination_ipv4_keeps_the_udp_checksum_valid() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );
        let new_dst = Ipv4Addr::new(10, 0, 0, 5);

        assert!(rewrite_destination_ipv4(&mut packet, new_dst));

        let mut pseudo_and_segment = Vec::new();
        pseudo_and_segment.extend_from_slice(&[10, 66, 66, 1]);
        pseudo_and_segment.extend_from_slice(&new_dst.octets());
        pseudo_and_segment.push(0);
        pseudo_and_segment.push(17);
        let udp_len = (packet.len() - 20) as u16;
        pseudo_and_segment.extend_from_slice(&udp_len.to_be_bytes());
        pseudo_and_segment.extend_from_slice(&packet[20..]);
        assert_eq!(reference_ones_complement_sum(&pseudo_and_segment), 0xFFFF);
    }

    #[test]
    fn rewrite_destination_ipv4_leaves_a_zero_udp_checksum_as_zero() {
        // RFC 768: 0 means "no checksum computed" for UDP - must never turn a genuinely
        // checksum-less packet into one with a checksum that doesn't cover its own payload.
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );
        packet[26..28].copy_from_slice(&0u16.to_be_bytes());

        assert!(rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));

        assert_eq!(&packet[26..28], &[0, 0]);
    }

    #[test]
    fn rewrite_destination_ipv4_maps_a_genuinely_zero_computed_udp_checksum_to_0xffff() {
        // RFC 768: when the *computed* checksum happens to be 0x0000, the sender must
        // transmit 0xFFFF instead - 0x0000 on the wire means "no checksum was computed",
        // which would misrepresent a packet that genuinely has one. Search the space of
        // destination addresses for one that actually lands on this rare case for a fixed
        // src/ports, rather than relying on a hand-picked value that might stop
        // reproducing it if the packet template above ever changes.
        let src = Ipv4Addr::new(10, 66, 66, 1);
        let dst = Ipv4Addr::new(10, 99, 0, 1);
        let packet_template = valid_ipv4_udp_packet(src, dst, 51234, 443);
        let old_dst_hi = read_u16(&packet_template, 16);
        let old_dst_lo = read_u16(&packet_template, 18);
        let old_l4_checksum = read_u16(&packet_template, 26);

        let new_dst = (0..=255u8)
            .flat_map(|a| (0..=255u8).map(move |b| Ipv4Addr::new(10, 0, a, b)))
            .find(|candidate| {
                let octets = candidate.octets();
                let new_hi = u16::from_be_bytes([octets[0], octets[1]]);
                let new_lo = u16::from_be_bytes([octets[2], octets[3]]);
                let adjusted = checksum_adjust(
                    checksum_adjust(old_l4_checksum, old_dst_hi, new_hi),
                    old_dst_lo,
                    new_lo,
                );
                adjusted == 0
            })
            .expect("a destination producing a zero computed UDP checksum must exist in this search space");

        let mut packet = packet_template;
        assert!(rewrite_destination_ipv4(&mut packet, new_dst));

        assert_eq!(
            &packet[26..28],
            &[0xFF, 0xFF],
            "a genuinely-zero-computed UDP checksum must be transmitted as 0xFFFF, not 0x0000"
        );

        // The verification trick still holds for the substituted 0xFFFF value: a checksum
        // field containing either ones'-complement representation of zero (0x0000 or
        // 0xFFFF) folds the full sum to 0xFFFF.
        let mut pseudo_and_segment = Vec::new();
        pseudo_and_segment.extend_from_slice(&src.octets());
        pseudo_and_segment.extend_from_slice(&new_dst.octets());
        pseudo_and_segment.push(0);
        pseudo_and_segment.push(17);
        let udp_len = (packet.len() - 20) as u16;
        pseudo_and_segment.extend_from_slice(&udp_len.to_be_bytes());
        pseudo_and_segment.extend_from_slice(&packet[20..]);
        assert_eq!(reference_ones_complement_sum(&pseudo_and_segment), 0xFFFF);
    }

    fn valid_ipv4_tcp_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let tcp_len = 20; // no options, no payload
        let total_len = 20 + tcp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        let ip_checksum = !reference_ones_complement_sum(&packet[0..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[32] = 0x50; // data offset = 5 words, no flags

        let mut pseudo_and_segment = Vec::new();
        pseudo_and_segment.extend_from_slice(&src.octets());
        pseudo_and_segment.extend_from_slice(&dst.octets());
        pseudo_and_segment.push(0);
        pseudo_and_segment.push(6);
        pseudo_and_segment.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo_and_segment.extend_from_slice(&packet[20..20 + tcp_len]);
        let tcp_checksum = !reference_ones_complement_sum(&pseudo_and_segment);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
    }

    #[test]
    fn rewrite_destination_ipv4_keeps_the_tcp_checksum_valid() {
        let mut packet = valid_ipv4_tcp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );
        let new_dst = Ipv4Addr::new(10, 0, 0, 5);

        assert!(rewrite_destination_ipv4(&mut packet, new_dst));

        let mut pseudo_and_segment = Vec::new();
        pseudo_and_segment.extend_from_slice(&[10, 66, 66, 1]);
        pseudo_and_segment.extend_from_slice(&new_dst.octets());
        pseudo_and_segment.push(0);
        pseudo_and_segment.push(6);
        let tcp_len = (packet.len() - 20) as u16;
        pseudo_and_segment.extend_from_slice(&tcp_len.to_be_bytes());
        pseudo_and_segment.extend_from_slice(&packet[20..]);
        assert_eq!(reference_ones_complement_sum(&pseudo_and_segment), 0xFFFF);
    }

    #[test]
    fn rewrite_destination_ipv4_returns_false_for_a_non_tcp_udp_protocol() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1; // ICMP

        assert!(!rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));
        // Left completely untouched, including the destination address.
        assert_eq!(&packet[16..20], &[0, 0, 0, 0]);
    }

    #[test]
    fn rewrite_destination_ipv4_returns_false_for_an_ipv6_packet() {
        let mut packet = vec![0u8; 44];
        packet[0] = 0x60; // IPv6

        assert!(!rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));
    }

    #[test]
    fn rewrite_destination_ipv4_returns_false_for_a_packet_too_short_to_hold_a_checksum_field() {
        let mut packet = vec![0u8; 24]; // IPv4 header + 4 bytes, short of UDP's 8-byte header
        packet[0] = 0x45;
        packet[9] = 17;

        assert!(!rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));
    }

    #[test]
    fn rewrite_source_ipv4_writes_the_new_source_address() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 66, 66, 1),
            443,
            51234,
        );

        assert!(rewrite_source_ipv4(
            &mut packet,
            Ipv4Addr::new(172, 16, 0, 9)
        ));

        assert_eq!(&packet[12..16], &[172, 16, 0, 9]);
    }

    #[test]
    fn rewrite_source_ipv4_keeps_the_ip_header_and_udp_checksums_valid() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 66, 66, 1),
            443,
            51234,
        );
        let new_src = Ipv4Addr::new(172, 16, 0, 9);

        assert!(rewrite_source_ipv4(&mut packet, new_src));

        assert_eq!(reference_ones_complement_sum(&packet[0..20]), 0xFFFF);
        let mut pseudo_and_segment = Vec::new();
        pseudo_and_segment.extend_from_slice(&new_src.octets());
        pseudo_and_segment.extend_from_slice(&[10, 66, 66, 1]);
        pseudo_and_segment.push(0);
        pseudo_and_segment.push(17);
        let udp_len = (packet.len() - 20) as u16;
        pseudo_and_segment.extend_from_slice(&udp_len.to_be_bytes());
        pseudo_and_segment.extend_from_slice(&packet[20..]);
        assert_eq!(reference_ones_complement_sum(&pseudo_and_segment), 0xFFFF);
    }

    #[test]
    fn rewrite_destination_ipv4_returns_false_for_a_non_first_ipv4_fragment() {
        // TT-2046 review finding #2: only the first fragment of a fragmented datagram carries a
        // real L4 header - a non-zero fragment offset means later fragments must never be treated
        // as if they had one (misreading payload as ports, or worse, corrupting payload bytes by
        // writing a "checksum fixup" into them).
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );
        packet[6] = 0x00;
        packet[7] = 0x01; // fragment offset = 1 (in 8-byte units) - not the first fragment
        let original = packet.clone();

        assert!(!rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));
        assert_eq!(
            packet, original,
            "a non-first fragment must be left completely untouched"
        );
    }

    #[test]
    fn rewrite_source_ipv4_returns_false_for_a_non_first_ipv4_fragment() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 66, 66, 1),
            443,
            51234,
        );
        packet[6] = 0x00;
        packet[7] = 0x01; // fragment offset = 1 - not the first fragment

        assert!(!rewrite_source_ipv4(
            &mut packet,
            Ipv4Addr::new(172, 16, 0, 9)
        ));
    }

    #[test]
    fn rewrite_destination_ipv4_still_rewrites_the_first_fragment_of_a_fragmented_datagram() {
        // The first fragment (offset 0) DOES carry a real L4 header, even with the "more
        // fragments" flag set - only later fragments (offset != 0) are the ones to reject.
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );
        packet[6] = 0x20; // MF flag set, fragment offset = 0 - this IS the first fragment

        assert!(rewrite_destination_ipv4(
            &mut packet,
            Ipv4Addr::new(10, 0, 0, 5)
        ));
        assert_eq!(&packet[16..20], &[10, 0, 0, 5]);
    }

    #[test]
    fn parse_source_port_returns_none_for_a_non_first_ipv4_fragment() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );
        packet[6] = 0x00;
        packet[7] = 0x01; // fragment offset = 1 - not the first fragment

        assert_eq!(parse_source_port(&packet), None);
    }

    #[test]
    fn parse_destination_port_returns_none_for_a_non_first_ipv4_fragment() {
        let mut packet = valid_ipv4_udp_packet(
            Ipv4Addr::new(10, 66, 66, 1),
            Ipv4Addr::new(10, 99, 0, 1),
            51234,
            443,
        );
        packet[6] = 0x00;
        packet[7] = 0x01; // fragment offset = 1 - not the first fragment

        assert_eq!(parse_destination_port(&packet), None);
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
