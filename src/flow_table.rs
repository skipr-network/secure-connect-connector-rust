//! Tracks currently-admitted flows so the real packet-forwarding loops
//! (`main`) can gate on them (TT-1732 review, Tasneem, finding #1 - "the
//! sharpest gap"): access decisions from `access.rs`/`flow_control.rs` were
//! never consulted by the actual forwarding loops, which routed purely by
//! learned IP with no entitlement check at all - a refused, or never
//! checked, device's traffic could still be forwarded once its IP was
//! observed once on the wire.
//!
//! A flow is identified by node, transport, translated source port, gateway virtual address and
//! destination port (spec §B.8, TT-2639): the node's NAT keeps a client's source port whenever only
//! the gateway, the port or the transport differs, so the translated port alone mixed up flows to
//! different gateways (reproduced on TEST, TT-2651). Each such flow gets a source port this
//! Connector allocates for the internal network, which is also how its replies find it
//! (`dialled_reply`). A flow admitted without that identity - from a node that predates it - is
//! still identified by `(node_id, port)` as before (`admit`, `forward_target`, `node_for_port`).
//! Release only ever carries `flow_id`, so entries are also looked up by `flow_id` for removal - a
//! linear scan, not a second index, since the number of concurrently admitted flows on one
//! Connector is bounded by real concurrent user sessions, not internet-scale traffic.
//!
//! **Also the source of truth for routing return traffic** (TT-1847): every
//! node in the fleet masquerades outbound traffic behind the identical wg0
//! address (`10.66.66.1`, hardcoded fleet-wide - confirmed in both
//! dev-server and production installer scripts), so a reply packet's
//! address carries no usable node identity at all, only ever a port. The
//! previous approach (`tunnel.rs`'s `routes`/`learn_route`/`route_for`)
//! tried to infer node identity from that degenerate address and was
//! silently broken any time a Connector served 2+ live nodes at once - a
//! normal, expected case, not an edge case. `node_for_port` replaces it: the
//! admission state recorded here (told explicitly by Gatekeeper, never
//! inferred) is the only thing this Connector can trust for that lookup.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::dto::PolicyBundleEndpoint;

/// How long a decrypted packet dropped for `ForwardOutcome::NotAdmitted` stays buffered, waiting
/// for its own flow's admission decision to arrive (see `pending_packets`'s doc). Gatekeeper
/// forwards a new flow's raw packets through the tunnel independently of, and often slightly
/// *before*, the admission relay round-trip that decides whether the flow is even allowed -
/// confirmed live (2026-09-22 session notes): the Connector's own "no admitted flow" warning
/// consistently preceded Gatekeeper's matching admit/refuse log line by 15-35ms, and none of
/// those flows' packets ever reached the real backend afterward, even though the flow sat
/// genuinely admitted for minutes - nothing ever gave the already-in-flight decision a chance to
/// catch up with the packet that lost the race.
///
/// TT-2298: 2s, up from 300ms. That 15-35ms figure is one admission on its own; a page opening many
/// connections at once queues several, and one measured on test took 510ms - past the old 300ms, so
/// its SYN was dropped and the client waited ~1s (then ~3s) to resend. 2s covers a burst without a
/// held packet ever being forwarded unless its flow is admitted.
const PENDING_PACKET_TTL: Duration = Duration::from_secs(2);

/// TT-2298: how long a released flow_id is remembered (`FlowTable::release`). Admissions now run
/// concurrently with the poll loop, so a short-lived flow's release can be handled before its own
/// admission finishes; the admission then sees the flow was already released and does not record
/// it. Comfortably above Gatekeeper's own admission-result timeout (10s by default), after which
/// no late admission can still be in flight.
const RELEASED_FLOW_MEMORY: Duration = Duration::from_secs(30);

/// TT-2298: most packets held for a pending admission at once. A longer `PENDING_PACKET_TTL` would
/// otherwise let a client firing many connections that are never admitted (a port scan, say) keep
/// that many more packets in memory. When full, a new packet is simply not held - the pre-buffering
/// behaviour - and nothing unadmitted is ever forwarded either way.
const MAX_PENDING_PACKETS: usize = 1024;

/// The source ports this Connector allocates for dialled flows (TT-2639, spec §B.8): every
/// non-system port, unique among the flows to one internal host:port on one transport - so two live
/// connections to the same internal service never look alike to it.
const SOURCE_PORT_RANGE: std::ops::RangeInclusive<u16> = 1024..=65535;

/// A flow's transport (spec §B.8): part of what identifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    /// From the admission message's `transport` field; `None` for anything but `tcp`/`udp`.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    /// From an IP header's protocol number (6 = TCP, 17 = UDP).
    pub fn from_ip_protocol(protocol: u8) -> Option<Self> {
        match protocol {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// What the user dialled (TT-2639, spec §B.8): with the node and the translated port, it
/// identifies a flow. Gatekeeper sends it on admission; the Connector reads the same values from
/// each packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dialled {
    pub transport: Transport,
    pub gateway_address: Ipv4Addr,
    pub destination_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DialledKey {
    node_id: String,
    port: u16,
    dialled: Dialled,
}

/// A flow admitted with its dialled identity (TT-2639).
#[derive(Debug, Clone, PartialEq)]
struct DialledFlow {
    flow: AdmittedFlow,
    /// Where its packets go on the internal network and the source port they carry there. Set when
    /// its first packet is forwarded - the internal address is only known then (a configured host
    /// can be a name still being resolved) - and replaced if that address changes.
    allocation: Option<Allocation>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Allocation {
    /// The internal address and port - a reply must come from exactly there.
    target: (Ipv4Addr, u16),
    /// The source port, unique among this Connector's flows to `target` on that transport.
    port: u16,
}

/// How to forward a packet on a dialled flow (`FlowTable::dialled_forward_target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialledForward {
    /// Rewrite the destination to `address` (the dialled port is unchanged) and the source port to
    /// `source_port`.
    Forward { address: Ipv4Addr, source_port: u16 },
    /// Why not: any `ForwardOutcome` but `Forward`/`NotAdmitted`.
    Refused(ForwardOutcome),
}

/// How to restore a reply from the internal service before sending it to its flow's node
/// (TT-2639): the gateway address and dialled port become its source again, and the translated
/// port its destination port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialledReply {
    pub node_id: String,
    pub gateway_address: Ipv4Addr,
    pub destination_port: u16,
    pub translated_port: u16,
}

#[derive(Debug, Clone, PartialEq)]
struct AdmittedFlow {
    gateway_id: String,
    flow_id: String,
    /// The device's signing key, as presented (and verified) on the admission
    /// request that created this entry (TT-1640). Not used for routing -
    /// `gateway_for`/`node_for_port` never touch it - only for
    /// `evict_gateway_device`, which needs to find "this device's admitted
    /// flows on this gateway" without anything Gatekeeper's release contract
    /// already carries (`flow_id`/`port` alone can't answer "which user").
    device_public_key: String,
    /// The entitled gateway's configured internal endpoints, from the same
    /// `PolicyBundle.endpoints` `AccessDecision::Allowed` already resolved at
    /// admission time (TT-2046). Being admitted only proves the device is
    /// entitled to this *gateway* - it says nothing about which internal
    /// address the gateway is actually configured to expose. `forward_target`
    /// uses this both to refuse a packet outright and to know what address to
    /// rewrite an allowed one to - the address the packet already carries on
    /// arrival is never the real endpoint (see `forward_target`'s doc
    /// comment), so nothing downstream can work at all without this.
    endpoints: Vec<PolicyBundleEndpoint>,
    /// The fake/virtual destination address this flow's packets actually arrive addressed to
    /// (Gatekeeper's invented per-gateway address). For a flow from an older node it is learned from
    /// the first forwarded packet, since that admission carries no such field; a flow admitted with
    /// its dialled identity has it from admission (TT-2639) and its replies use that. Needed to
    /// rewrite a *reply* packet's source back to what the client actually dialed before sending it
    /// back through the tunnel (TT-2046 review finding #1): a real kernel DNAT gets this reversal
    /// for free via conntrack; this rewrite happens in userspace with no conntrack entry to
    /// reverse it automatically, so the Connector has to remember it explicitly. For an older node's
    /// flow, `None` until its first forwarded packet has been seen.
    virtual_address: Option<Ipv4Addr>,
}

/// Why a decrypted packet can or can't be forwarded, returned by `forward_target` instead of a
/// bare `Option<Ipv4Addr>` (TT-2046 review finding #5) so the caller can log a message specific to
/// which of several genuinely different situations occurred, rather than one generic line that
/// makes them indistinguishable on-call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// Resolved to a real address - rewrite the packet's destination to this and forward it.
    Forward(Ipv4Addr),
    /// No admitted flow at all for `(node_id, port)` - a security event: decrypting successfully
    /// proves the packet came from a genuine node tunnel, but says nothing about whether
    /// Gatekeeper's flow-admission relay ever admitted this specific device/gateway.
    NotAdmitted,
    /// Admitted, but none of the gateway's configured endpoints exposes the packet's destination
    /// port - misconfiguration or probing, not a security event.
    PortNotConfigured,
    /// Admitted and the port matches, but more than one of the gateway's configured endpoints
    /// shares that port - genuinely ambiguous which one the client meant, not something to guess
    /// at (matches `node_for_port`'s own precedent for the same shape of ambiguity: refuse, don't
    /// silently pick one).
    AmbiguousEndpoint,
    /// Admitted, the port matches exactly one endpoint, but `dns_cache` has no resolved address
    /// for its host (TT-2066) - a literal IPv4 always resolves, so this only happens for a
    /// hostname that hasn't been looked up yet, has failed every refresh so far, or was evicted
    /// after too many consecutive failures (`dns_cache::MAX_CONSECUTIVE_FAILURES`). Silently
    /// black-holes every packet for that gateway until it resolves, so this needs its own loud,
    /// specific message rather than folding into a generic "can't forward" line.
    HostUnresolved,
    /// TT-2639: admitted and resolved, but every source port toward that internal host:port on that
    /// transport is in use, so the flow could not be kept apart from the others there. Dropped (fail
    /// closed); a later packet gets a port once one is freed.
    NoFreeSourcePort,
}

#[derive(Default)]
pub struct FlowTable {
    flows: HashMap<(String, u16), AdmittedFlow>,
    /// Reverse index (TT-1732 review, Tasneem, TT-1847 finding #3): `port ->
    /// the node_id(s) currently holding it`, kept incrementally in sync with
    /// `flows` on every admit/release/evict. Without this, `node_for_port` -
    /// called on every single outbound packet, under a lock also shared with
    /// the flow-admission/release control plane - would need to scan every
    /// admitted flow on this Connector on every packet.
    nodes_by_port: HashMap<u16, HashSet<String>>,
    /// `port -> node_id` for a direct connection to *this Connector's own* control-plane API
    /// (Gatekeeper's flow-admission/release relay, TT-1839/TT-2102) - genuinely different from
    /// `flows`/`nodes_by_port` above: there is no gateway, no device, no endpoint and no address
    /// rewrite involved, just "which node is on the other end of this one connection", needed
    /// because every node in the fleet masquerades behind the identical wg0 address (see the
    /// module doc) so a reply packet's address alone can never answer that.
    ///
    /// Recorded when the inbound receive loop forwards a packet addressed to
    /// `connector_virtual_ip` itself (TT-2102: previously this branch recorded nothing at all, so
    /// the admission *decision's own reply* had no way to ever route back to Gatekeeper, even
    /// though the client flow it decided about was admitted correctly). Deliberately never
    /// removed on lookup - one connection's admission request/response exchange is several
    /// packets (SYN-ACK, then the HTTP response itself, possibly more than one segment), all of
    /// which need this same mapping. Gatekeeper has no "I'm done with this port" signal the way
    /// `release` gives one for admitted flows, so entries are bounded by
    /// `MAX_TRACKED_CONTROL_CHANNEL_PORTS` and evicted oldest-first instead - these are short-lived
    /// one-shot HTTP exchanges, not long-lived sessions, so a bounded FIFO is enough to never grow
    /// unboundedly over a long uptime without needing real TCP-close detection.
    control_channel_ports: HashMap<u16, String>,
    control_channel_port_order: VecDeque<u16>,
    /// `port -> node_id` for the reverse direction (TT-2144): this Connector's OWN chosen local
    /// port when IT dials out to Gatekeeper (`admission_poller`'s poll/admission-result calls),
    /// not Gatekeeper's port as seen from an inbound connection. Genuinely a different mapping
    /// from `control_channel_ports` above, not just the same data recorded earlier: an outbound
    /// packet on one of these connections carries this port as its own *source* port, never its
    /// destination - the destination is Gatekeeper's fixed HTTP port, identical across every node
    /// (see the module doc's masquerading note), which by itself carries zero information about
    /// which node a brand new outbound connection is even for. `run_tun_send_loop` needs a lookup
    /// keyed the opposite way from `control_channel_ports`'s own destination-port lookup to route
    /// such a connection's packets to the right node's tunnel at all - see
    /// `node_for_outbound_control_channel_source_port`.
    ///
    /// Recorded by `admission_poller::connect_registered` *before* the connection's `connect()`
    /// call ever sends a SYN (not after, the way `control_channel_ports` above is recorded after
    /// its own triggering packet already arrived) - the local port must already be known and
    /// routable before the very first packet of the connection exists, or that first packet has
    /// nothing to match against and is dropped as an "unroutable outbound packet", which is
    /// exactly the bug this mechanism exists to fix. Same bounded-FIFO eviction shape as
    /// `control_channel_ports` and for the same reason (no explicit "I'm done" signal for a
    /// one-shot HTTP exchange).
    outbound_control_channel_ports: HashMap<u16, String>,
    outbound_control_channel_port_order: VecDeque<u16>,
    /// A decrypted packet that lost the race against its own flow's admission decision (see
    /// `PENDING_PACKET_TTL`'s doc) - held here briefly instead of being dropped outright, so
    /// `take_pending_packet` can hand it back for forwarding if admission catches up in time.
    /// Only the most recent packet per `(node_id, port)` is kept: for the TCP handshakes this
    /// exists to rescue, any single copy of the client's SYN reaching the real destination once
    /// is enough - there's nothing to gain from remembering more than one.
    pending_packets: HashMap<(String, u16), (Vec<u8>, Instant)>,
    /// TT-2298: flow_ids released within `RELEASED_FLOW_MEMORY`, with when - see that constant.
    recently_released: HashMap<String, Instant>,
    /// TT-2639: flows admitted with their dialled identity - see the module doc.
    dialled_flows: HashMap<DialledKey, DialledFlow>,
    /// TT-2639: `(transport, internal address, internal port, allocated port) -> flow` - a reply's
    /// own transport, source and destination port, so it matches exactly one flow.
    dialled_by_allocation: HashMap<(Transport, Ipv4Addr, u16, u16), DialledKey>,
    /// TT-2639: where the next source-port search starts, per transport and internal host:port (so a
    /// freed port is not reused at once while its old connection may still be closing there).
    next_source_port: HashMap<(Transport, Ipv4Addr, u16), u16>,
    /// TT-2639: the allocatable range - `SOURCE_PORT_RANGE` except in tests of exhaustion.
    source_port_range: Option<std::ops::RangeInclusive<u16>>,
    /// TT-2639: packets buffered for a pending admission under their dialled key, the counterpart
    /// of `pending_packets`, sharing its TTL and capacity.
    pending_dialled_packets: HashMap<DialledKey, (Vec<u8>, Instant)>,
    /// TT-2639: nodes that have sent an admission with its dialled identity - updated nodes. On such a
    /// node a flow admitted without the identity (before the update) is used only by packets to the
    /// gateway address it was first seen with (`legacy_flow_accepts`).
    dialled_nodes: HashSet<String>,
}

/// How many distinct control-channel connections' worth of routing state to remember at once
/// (see `control_channel_ports`'s doc) - generously above any realistic number of concurrent
/// admission/release calls in flight on one Connector at a time.
const MAX_TRACKED_CONTROL_CHANNEL_PORTS: usize = 256;

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// A table allocating source ports from `range` only - for testing exhaustion.
    #[cfg(test)]
    pub(crate) fn with_source_port_range(range: std::ops::RangeInclusive<u16>) -> Self {
        Self {
            source_port_range: Some(range),
            ..Self::default()
        }
    }

    /// Shared bounded-FIFO insert behind both `control_channel_ports` and
    /// `outbound_control_channel_ports` - identical eviction shape, different map/order pair.
    fn record_bounded_port(
        map: &mut HashMap<u16, String>,
        order: &mut VecDeque<u16>,
        node_id: &str,
        port: u16,
    ) {
        if map.insert(port, node_id.to_string()).is_none() {
            order.push_back(port);
            if order.len() > MAX_TRACKED_CONTROL_CHANNEL_PORTS
                && let Some(oldest) = order.pop_front()
            {
                map.remove(&oldest);
            }
        }
    }

    /// Records that a direct connection to this Connector's own control-plane API on `port`
    /// belongs to `node_id`, so a reply on that port can be routed back to the right node (TT-2102).
    /// Safe to call repeatedly for the same port (a retried request reusing it, or the OS handing
    /// out a recently-freed ephemeral port again) - always just overwrites in place without
    /// growing `control_channel_port_order`.
    pub fn record_control_channel_port(&mut self, node_id: &str, port: u16) {
        Self::record_bounded_port(
            &mut self.control_channel_ports,
            &mut self.control_channel_port_order,
            node_id,
            port,
        );
    }

    /// The node a reply on this control-channel port should route back to, if any was ever
    /// recorded (TT-2102). `None` for any ordinary port, including every admitted gateway flow's
    /// own port - those are answered by `node_for_port` instead, never this.
    pub fn node_for_control_channel_port(&self, port: u16) -> Option<&str> {
        self.control_channel_ports.get(&port).map(String::as_str)
    }

    /// Records that `port` is this Connector's own local port for a connection it is itself
    /// dialing out to Gatekeeper on `node_id`'s behalf (TT-2144) - see
    /// `outbound_control_channel_ports`'s doc for why this is a genuinely different mapping from
    /// `record_control_channel_port` above, not a duplicate. Same overwrite-in-place/no-growth
    /// behavior on a repeated port for the same reasons.
    pub fn record_outbound_control_channel_port(&mut self, node_id: &str, port: u16) {
        Self::record_bounded_port(
            &mut self.outbound_control_channel_ports,
            &mut self.outbound_control_channel_port_order,
            node_id,
            port,
        );
    }

    /// The node an outbound packet whose own *source* port is `port` belongs to, if this
    /// Connector itself registered that port for a connection it dialed out (TT-2144). Checked
    /// against a packet's source port, never its destination - see
    /// `outbound_control_channel_ports`'s doc for why the destination alone can't disambiguate
    /// this direction at all.
    pub fn node_for_outbound_control_channel_source_port(&self, port: u16) -> Option<&str> {
        self.outbound_control_channel_ports
            .get(&port)
            .map(String::as_str)
    }

    pub fn admit(
        &mut self,
        node_id: String,
        port: u16,
        gateway_id: String,
        flow_id: String,
        device_public_key: String,
        endpoints: Vec<PolicyBundleEndpoint>,
    ) {
        self.nodes_by_port
            .entry(port)
            .or_default()
            .insert(node_id.clone());
        self.flows.insert(
            (node_id, port),
            AdmittedFlow {
                gateway_id,
                flow_id,
                device_public_key,
                endpoints,
                virtual_address: None,
            },
        );
    }

    /// TT-2639: admits a flow with its dialled identity (spec §B.8). Its source port toward the
    /// internal network is allocated when its first packet is forwarded (`dialled_forward_target`).
    /// Re-admitting the same identity (its release never arrived) replaces the old entry and frees
    /// its port.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_dialled(
        &mut self,
        node_id: String,
        port: u16,
        dialled: Dialled,
        gateway_id: String,
        flow_id: String,
        device_public_key: String,
        endpoints: Vec<PolicyBundleEndpoint>,
    ) {
        self.dialled_nodes.insert(node_id.clone());
        let key = DialledKey {
            node_id,
            port,
            dialled,
        };
        self.remove_dialled(&key);
        self.dialled_flows.insert(
            key,
            DialledFlow {
                flow: AdmittedFlow {
                    gateway_id,
                    flow_id,
                    device_public_key,
                    endpoints,
                    virtual_address: Some(dialled.gateway_address),
                },
                allocation: None,
            },
        );
    }

    /// The next free source port toward `target` on `transport`, searching on from the last one
    /// handed out there. A field-level function so it can run while one flow is borrowed.
    fn allocate_source_port(
        allocations: &HashMap<(Transport, Ipv4Addr, u16, u16), DialledKey>,
        cursors: &mut HashMap<(Transport, Ipv4Addr, u16), u16>,
        range: std::ops::RangeInclusive<u16>,
        transport: Transport,
        target: (Ipv4Addr, u16),
    ) -> Option<u16> {
        let (first, last) = (*range.start(), *range.end());
        let size = u32::from(last - first) + 1;
        let cursor = (transport, target.0, target.1);
        let start = cursors
            .get(&cursor)
            .copied()
            .filter(|port| range.contains(port))
            .unwrap_or(first);
        for offset in 0..size {
            let candidate = first + ((u32::from(start - first) + offset) % size) as u16;
            if !allocations.contains_key(&(transport, target.0, target.1, candidate)) {
                let next = if candidate == last {
                    first
                } else {
                    candidate + 1
                };
                cursors.insert(cursor, next);
                return Some(candidate);
            }
        }
        None
    }

    /// Removes a dialled flow and frees its allocated port; a no-op if it isn't admitted.
    fn remove_dialled(&mut self, key: &DialledKey) {
        if let Some(Allocation { target, port }) = self
            .dialled_flows
            .remove(key)
            .and_then(|removed| removed.allocation)
        {
            self.dialled_by_allocation
                .remove(&(key.dialled.transport, target.0, target.1, port));
        }
    }

    /// Removes every dialled flow `drop_it` selects and frees their ports; returns how many.
    fn remove_dialled_where(
        &mut self,
        drop_it: impl Fn(&DialledKey, &AdmittedFlow) -> bool,
    ) -> usize {
        let removed: Vec<DialledKey> = self
            .dialled_flows
            .iter()
            .filter(|(key, entry)| drop_it(key, &entry.flow))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &removed {
            self.remove_dialled(key);
        }
        removed.len()
    }

    pub fn release(&mut self, flow_id: &str) {
        self.remove_dialled_where(|_, flow| flow.flow_id == flow_id);
        let mut removed = Vec::new();
        self.flows.retain(|key, flow| {
            let keep = flow.flow_id != flow_id;
            if !keep {
                removed.push(key.clone());
            }
            keep
        });
        for (node_id, port) in removed {
            self.deindex(&node_id, port);
        }
        let now = Instant::now();
        self.recently_released
            .retain(|_, released_at| now.duration_since(*released_at) <= RELEASED_FLOW_MEMORY);
        self.recently_released.insert(flow_id.to_string(), now);
    }

    /// TT-2298: whether `flow_id` was released within `RELEASED_FLOW_MEMORY` - checked by the
    /// admission path, under the same lock as its `admit`, so a release that overtook its own
    /// admission cannot leave the flow admitted.
    pub fn was_recently_released(&self, flow_id: &str) -> bool {
        self.recently_released
            .get(flow_id)
            .is_some_and(|released_at| released_at.elapsed() <= RELEASED_FLOW_MEMORY)
    }

    /// Drops every flow admitted for `node_id` (TT-1732 review, Tasneem, TT-1847
    /// finding #1) - called once a heartbeat's node list no longer includes it
    /// (`TunnelManager::sync_nodes`'s return value). Without this, a flow whose
    /// node simply disappears (rather than being cleanly released by Gatekeeper)
    /// leaves a permanent ghost entry: harmless for `gateway_for` (still keyed by
    /// the now-gone node_id, so it'll just never match again), but a real problem
    /// for `node_for_port`'s collision check - a stale entry can make a *different*,
    /// currently-live node's use of that same port look ambiguous forever.
    pub fn evict_node(&mut self, node_id: &str) {
        let removed_ports: Vec<u16> = self
            .flows
            .keys()
            .filter(|(n, _)| n == node_id)
            .map(|(_, port)| *port)
            .collect();
        self.flows.retain(|(n, _), _| n != node_id);
        for port in removed_ports {
            self.deindex(node_id, port);
        }
        self.remove_dialled_where(|key, _| key.node_id == node_id);
        self.dialled_nodes.remove(node_id);
        // TT-2297: a departed node's control-channel ports route to a tunnel that no longer
        // exists - left in place, a packet matching one is dropped instead of reaching the node
        // that now owns that port.
        Self::forget_node_ports(
            &mut self.control_channel_ports,
            &mut self.control_channel_port_order,
            node_id,
        );
        Self::forget_node_ports(
            &mut self.outbound_control_channel_ports,
            &mut self.outbound_control_channel_port_order,
            node_id,
        );
    }

    fn forget_node_ports(map: &mut HashMap<u16, String>, order: &mut VecDeque<u16>, node_id: &str) {
        map.retain(|_, owner| owner != node_id);
        order.retain(|port| map.contains_key(port));
    }

    /// Drops every currently-admitted flow for one device on one gateway
    /// (TT-1640, "Revoke User Active Session From Gateway"), leaving every
    /// other flow - including that same device's flows to a *different*
    /// gateway - untouched. This is the only piece of the revoke feature
    /// that lives here: everything upstream of this (who to revoke, when)
    /// is decided by Portal and carried down through the heartbeat's
    /// `revoked_sessions`/entitlement-diff reconciliation in `main`. Returns
    /// the number of flows evicted, purely for logging - callers must not
    /// branch on it, since "nothing to evict" (the device already
    /// disconnected, or reconciled on a previous heartbeat) is a normal,
    /// expected outcome, not a failure.
    pub fn evict_gateway_device(&mut self, gateway_id: &str, device_public_key: &str) -> usize {
        let removed: Vec<(String, u16)> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                flow.gateway_id == gateway_id && flow.device_public_key == device_public_key
            })
            .map(|(key, _)| key.clone())
            .collect();
        for (node_id, port) in &removed {
            self.flows.remove(&(node_id.clone(), *port));
            self.deindex(node_id, *port);
        }
        removed.len()
            + self.remove_dialled_where(|_, flow| {
                flow.gateway_id == gateway_id && flow.device_public_key == device_public_key
            })
    }

    /// Refreshes every currently-admitted flow's remembered endpoint list for one gateway to this
    /// heartbeat's freshly-applied configuration (TT-2046 review finding #4): endpoints are
    /// otherwise only ever snapshotted once, at `admit` time, so an admin repointing or removing an
    /// endpoint on a gateway with an open flow was silently ignored - `forward_target` kept using
    /// the stale list - for as long as that flow stayed open. Mirrors `main::
    /// reconcile_dropped_entitlements`'s per-heartbeat refresh, but for endpoint config rather than
    /// entitlement: a flow that's still entitled keeps forwarding, just against whatever the
    /// gateway is configured to expose *now*, not what it exposed when the flow was admitted. A
    /// no-op for a gateway with no currently-admitted flow, or one whose endpoint list didn't
    /// change - both normal, expected cases, not something to log.
    pub fn update_endpoints(&mut self, gateway_id: &str, endpoints: &[PolicyBundleEndpoint]) {
        let dialled = self.dialled_flows.values_mut().map(|entry| &mut entry.flow);
        for flow in self.flows.values_mut().chain(dialled) {
            if flow.gateway_id == gateway_id {
                flow.endpoints = endpoints.to_vec();
            }
        }
    }

    fn deindex(&mut self, node_id: &str, port: u16) {
        if let Some(nodes) = self.nodes_by_port.get_mut(&port) {
            nodes.remove(node_id);
            if nodes.is_empty() {
                self.nodes_by_port.remove(&port);
            }
        }
    }

    /// The gateway this (node_id, port) pair is currently admitted for, or
    /// `None` if there's no matching admitted flow at all - callers must
    /// treat that as "refuse", never as "admit anyway". Not called by
    /// production code any more (TT-2046): `run_wireguard_receive_loop`'s
    /// real gate is now `forward_target`, which is admission-checking,
    /// endpoint-matching, and address resolution in one call. Kept and still genuinely
    /// useful: most existing tests are about admission/eviction bookkeeping
    /// itself, not endpoint enforcement, and asserting on the resolved
    /// gateway_id directly is more precise there than routing everything
    /// through a destination match.
    #[allow(dead_code)]
    pub fn gateway_for(&self, node_id: &str, port: u16) -> Option<&str> {
        self.flows
            .get(&(node_id.to_string(), port))
            .map(|flow| flow.gateway_id.as_str())
    }

    /// Resolves the real internal address a forwarded packet should be
    /// rewritten to reach, or the specific reason it can't be forwarded at all
    /// (TT-1732 review, Tasneem finding #1 - same admission check `gateway_for`
    /// used to do, refined by TT-2046 review finding #5 into a typed reason
    /// instead of a bare `None`).
    ///
    /// Matched by `packet_destination_port` alone, **not** by the packet's
    /// current destination *address* (TT-2046): on arrival that address is
    /// never the real endpoint - it's the fake, per-node virtual address
    /// Gatekeeper invented for DNS resolution purposes only
    /// (`GatewayVirtualAddressRegistry` on the Gatekeeper side: "zero
    /// relationship to any real internal address - the whole point is
    /// Gatekeeper never learns the internal host:port allowlist"). Gatekeeper
    /// never translates the destination *port*, though - the client dials
    /// the real target port directly - so it's the only part of "where is
    /// this packet headed" that's trustworthy at this point, and the actual
    /// address rewrite (`tunnel::rewrite_destination_ipv4`) happens after
    /// this call, using the `Ipv4Addr` a `ForwardOutcome::Forward` carries.
    ///
    /// Two or more configured endpoints sharing `packet_destination_port` is
    /// `AmbiguousEndpoint`, never "pick the first one silently" (TT-2046
    /// review finding #3) - the same shape of ambiguity `node_for_port`
    /// already refuses to guess at, for the same reason: nothing here can
    /// tell which one the client actually meant.
    ///
    /// `PolicyBundleEndpoint.host` is resolved via `dns_cache` (TT-2066) - a literal IPv4
    /// resolves to itself with no lookup; a hostname resolves to whatever `dns_cache` last
    /// successfully looked up for it (refreshed once per heartbeat, never synchronously here -
    /// see `dns_cache`'s module doc), or `ForwardOutcome::HostUnresolved` if it's never resolved
    /// successfully, which is the safe direction to fail in (refuse, not silently admit).
    pub fn forward_target(
        &self,
        node_id: &str,
        port: u16,
        packet_destination_port: u16,
        dns_cache: &crate::dns_cache::DnsCache,
    ) -> ForwardOutcome {
        let Some(flow) = self.flows.get(&(node_id.to_string(), port)) else {
            return ForwardOutcome::NotAdmitted;
        };
        resolve_endpoint(&flow.endpoints, packet_destination_port, dns_cache)
    }

    /// TT-2639: whether a packet to `destination` may use the flow admitted on `(node_id, port)`
    /// without a dialled identity, once no flow matched its full identity. Such a flow, from before
    /// its node was updated, says nothing about which gateway it is for except the address its first
    /// packet carried: only a packet to that same address may use it. Before any address is known, a
    /// packet from an updated node is refused - it may be another gateway's first packet, and using
    /// the flow would also record that gateway's address on it - while one from a node not yet updated
    /// is accepted and its address recorded, as before (spec §B.8, Compatibility). `true` when there is
    /// no such flow: `forward_target` then reports it as not admitted.
    pub fn legacy_flow_accepts(&self, node_id: &str, port: u16, destination: Ipv4Addr) -> bool {
        match self.flows.get(&(node_id.to_string(), port)) {
            None => true,
            Some(flow) => match flow.virtual_address {
                Some(address) => address == destination,
                None => !self.dialled_nodes.contains(node_id),
            },
        }
    }

    /// TT-2639: the same decision as `forward_target`, for a flow admitted with its dialled
    /// identity - matched on everything that identifies it (spec §B.8), so a packet addressed to one
    /// gateway can never match a flow admitted for another. `None` if no flow is admitted for exactly
    /// this identity, so the caller can fall back to a flow from an older node (`forward_target`).
    ///
    /// On the first packet, or once the flow's internal address has changed (an endpoint update or a
    /// new DNS answer), allocates the source port its packets carry there - unique among this
    /// Connector's flows to that internal host:port on that transport - freeing any previous one.
    pub fn dialled_forward_target(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Dialled,
        dns_cache: &crate::dns_cache::DnsCache,
    ) -> Option<DialledForward> {
        let key = DialledKey {
            node_id: node_id.to_string(),
            port,
            dialled,
        };
        let entry = self.dialled_flows.get_mut(&key)?;
        let address =
            match resolve_endpoint(&entry.flow.endpoints, dialled.destination_port, dns_cache) {
                ForwardOutcome::Forward(address) => address,
                refused => return Some(DialledForward::Refused(refused)),
            };
        let target = (address, dialled.destination_port);
        if let Some(allocation) = entry.allocation
            && allocation.target == target
        {
            return Some(DialledForward::Forward {
                address,
                source_port: allocation.port,
            });
        }
        let transport = dialled.transport;
        if let Some(Allocation {
            target: old,
            port: old_port,
        }) = entry.allocation.take()
        {
            self.dialled_by_allocation
                .remove(&(transport, old.0, old.1, old_port));
        }
        let range = self.source_port_range.clone().unwrap_or(SOURCE_PORT_RANGE);
        let Some(source_port) = Self::allocate_source_port(
            &self.dialled_by_allocation,
            &mut self.next_source_port,
            range,
            transport,
            target,
        ) else {
            return Some(DialledForward::Refused(ForwardOutcome::NoFreeSourcePort));
        };
        entry.allocation = Some(Allocation {
            target,
            port: source_port,
        });
        self.dialled_by_allocation
            .insert((transport, target.0, target.1, source_port), key);
        Some(DialledForward::Forward {
            address,
            source_port,
        })
    }

    /// TT-2639: the flow a reply read from the TUN device belongs to - by its transport, its source
    /// (an internal host:port a flow's packets were forwarded to) and its destination port (the
    /// source port allocated to that flow there). `None` otherwise, for the caller's other lookups
    /// (a flow from an older node, or a control-channel connection).
    pub fn dialled_reply(
        &self,
        transport: Transport,
        source: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Option<DialledReply> {
        let key =
            self.dialled_by_allocation
                .get(&(transport, source, source_port, destination_port))?;
        self.dialled_flows.get(key)?;
        Some(DialledReply {
            node_id: key.node_id.clone(),
            gateway_address: key.dialled.gateway_address,
            destination_port: key.dialled.destination_port,
            translated_port: key.port,
        })
    }

    /// Buffers one decrypted packet that hit `ForwardOutcome::NotAdmitted`, in case its own
    /// flow's admission decision is already in flight and arrives within `PENDING_PACKET_TTL`
    /// (see that constant's doc for why this race exists and why it's worth rescuing). Overwrites
    /// any previously-buffered packet for the same `(node_id, port)` - only the latest matters.
    ///
    /// Also opportunistically sweeps every *other* entry past its own TTL, so a packet whose flow
    /// is ultimately refused (or never decided at all) doesn't linger here forever - there's no
    /// separate release/expiry signal for a pending packet the way there is for an admitted flow,
    /// so this is the only place that cleanup can happen without a dedicated background sweep.
    pub fn buffer_pending_packet(
        &mut self,
        node_id: &str,
        port: u16,
        packet: Vec<u8>,
        now: Instant,
    ) {
        self.sweep_pending_packets(now);
        let key = (node_id.to_string(), port);
        if self.pending_packet_count() >= MAX_PENDING_PACKETS
            && !self.pending_packets.contains_key(&key)
        {
            return;
        }
        self.pending_packets.insert(key, (packet, now));
    }

    /// TT-2639: `buffer_pending_packet` for a packet whose dialled identity could be read, held
    /// under that identity so only the admission of exactly that flow reclaims it.
    pub fn buffer_pending_dialled_packet(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Dialled,
        packet: Vec<u8>,
        now: Instant,
    ) {
        self.sweep_pending_packets(now);
        let key = DialledKey {
            node_id: node_id.to_string(),
            port,
            dialled,
        };
        if self.pending_packet_count() >= MAX_PENDING_PACKETS
            && !self.pending_dialled_packets.contains_key(&key)
        {
            return;
        }
        self.pending_dialled_packets.insert(key, (packet, now));
    }

    /// TT-2639: `take_pending_packet` for a flow admitted with its dialled identity.
    pub fn take_pending_dialled_packet(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Dialled,
        now: Instant,
    ) -> Option<Vec<u8>> {
        let key = DialledKey {
            node_id: node_id.to_string(),
            port,
            dialled,
        };
        let (packet, buffered_at) = self.pending_dialled_packets.remove(&key)?;
        (now.duration_since(buffered_at) <= PENDING_PACKET_TTL).then_some(packet)
    }

    fn sweep_pending_packets(&mut self, now: Instant) {
        let fresh = |buffered_at: &Instant| now.duration_since(*buffered_at) <= PENDING_PACKET_TTL;
        self.pending_packets.retain(|_, (_, at)| fresh(at));
        self.pending_dialled_packets.retain(|_, (_, at)| fresh(at));
    }

    fn pending_packet_count(&self) -> usize {
        self.pending_packets.len() + self.pending_dialled_packets.len()
    }

    /// Reclaims a packet `buffer_pending_packet` held for `(node_id, port)`, if one exists and is
    /// still within `PENDING_PACKET_TTL` - called right after `admit()` records that same flow as
    /// admitted, so the caller can push the rescued packet through the normal forwarding path
    /// instead of leaving it lost. Removes the entry either way (a stale one is just as done being
    /// useful as one just claimed), so this can't return the same packet twice.
    pub fn take_pending_packet(
        &mut self,
        node_id: &str,
        port: u16,
        now: Instant,
    ) -> Option<Vec<u8>> {
        // TT-2639: a packet whose dialled identity could be read is held under it, even when it
        // comes from a node that predates it; that node's admission (without the identity) reclaims
        // it by node and port alone, as before.
        let (packet, buffered_at) = match self.pending_packets.remove(&(node_id.to_string(), port))
        {
            Some(held) => held,
            None => {
                let key = self
                    .pending_dialled_packets
                    .keys()
                    .find(|key| key.node_id == node_id && key.port == port)
                    .cloned()?;
                self.pending_dialled_packets.remove(&key)?
            }
        };
        (now.duration_since(buffered_at) <= PENDING_PACKET_TTL).then_some(packet)
    }

    /// Records the fake/virtual address a flow's packets actually arrive addressed to (TT-2046
    /// review finding #1) - called once `forward_target` has confirmed the flow is genuinely
    /// forwardable, from the packet's own pre-rewrite destination address. A no-op if `(node_id,
    /// port)` isn't (or is no longer) an admitted flow.
    pub fn record_virtual_address(&mut self, node_id: &str, port: u16, virtual_address: Ipv4Addr) {
        if let Some(flow) = self.flows.get_mut(&(node_id.to_string(), port)) {
            flow.virtual_address = Some(virtual_address);
        }
    }

    /// The virtual address `record_virtual_address` last recorded for this flow, or `None` if
    /// none has been recorded yet (no forward-direction packet has been seen for it) - used by
    /// the reverse path (`main::run_tun_send_loop`) to restore a reply packet's source address to
    /// what the client actually dialed, since nothing downstream can undo the forward rewrite
    /// automatically (TT-2046 review finding #1; see `tunnel::rewrite_source_ipv4`).
    pub fn virtual_address_for(&self, node_id: &str, port: u16) -> Option<Ipv4Addr> {
        self.flows
            .get(&(node_id.to_string(), port))?
            .virtual_address
    }

    /// Reverse of admission (TT-1847): given only a port - all a reply packet
    /// arriving from the TUN side carries, since every node's masqueraded
    /// source address is identical fleet-wide and so carries no node
    /// identity - finds the single node currently holding an admitted flow
    /// on it. O(1) via `nodes_by_port`, not a scan of every admitted flow
    /// (TT-1732 review, Tasneem, TT-1847 finding #3) - this runs on every
    /// outbound packet, under a lock also shared with the control plane.
    ///
    /// Ports are assigned independently per node (Oleksandr Konyk, TT-1732
    /// thread, 2026-09-01: "the same port can exist on different nodes at
    /// the same time... port must be treated as node-local, not globally
    /// unique"), so a bare port can legitimately be admitted on two
    /// different nodes at once. When that happens there is nothing left in
    /// a reply packet to disambiguate with, so this returns `None` rather
    /// than guessing - the caller must drop the packet, not misroute it to
    /// an arbitrary one of the colliding nodes.
    pub fn node_for_port(&self, port: u16) -> Option<&str> {
        let nodes = self.nodes_by_port.get(&port)?;
        if nodes.len() != 1 {
            return None;
        }
        nodes.iter().next().map(String::as_str)
    }
}

/// Which configured endpoint a packet to `destination_port` goes to, resolved to an address -
/// shared by `forward_target` and `dialled_forward_target`; see `forward_target`'s doc.
fn resolve_endpoint(
    endpoints: &[PolicyBundleEndpoint],
    destination_port: u16,
    dns_cache: &crate::dns_cache::DnsCache,
) -> ForwardOutcome {
    let matching: Vec<&PolicyBundleEndpoint> = endpoints
        .iter()
        .filter(|endpoint| endpoint.port == destination_port)
        .collect();
    match matching.as_slice() {
        [] => ForwardOutcome::PortNotConfigured,
        [endpoint] => match dns_cache.resolve(&endpoint.host) {
            Some(ip) => ForwardOutcome::Forward(ip),
            None => ForwardOutcome::HostUnresolved,
        },
        _ => ForwardOutcome::AmbiguousEndpoint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unadmitted_node_and_port_has_no_gateway() {
        let table = FlowTable::new();

        assert!(table.gateway_for("n-1", 40001).is_none());
    }

    #[test]
    fn an_admitted_flow_resolves_to_its_gateway() {
        let mut table = FlowTable::new();

        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert_eq!(table.gateway_for("n-1", 40001), Some("gw-1"));
    }

    #[test]
    fn the_same_port_on_a_different_node_is_a_different_flow() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert!(table.gateway_for("n-2", 40001).is_none());
    }

    #[test]
    fn control_channel_port_has_no_node_until_recorded() {
        let table = FlowTable::new();

        assert!(table.node_for_control_channel_port(51234).is_none());
    }

    #[test]
    fn a_recorded_control_channel_port_resolves_to_its_node() {
        let mut table = FlowTable::new();

        table.record_control_channel_port("n-1", 51234);

        assert_eq!(table.node_for_control_channel_port(51234), Some("n-1"));
    }

    #[test]
    fn recording_a_control_channel_port_twice_for_the_same_node_is_a_no_op_not_a_growth() {
        let mut table = FlowTable::new();

        table.record_control_channel_port("n-1", 51234);
        table.record_control_channel_port("n-1", 51234);

        assert_eq!(table.control_channel_port_order.len(), 1);
    }

    #[test]
    fn re_recording_a_control_channel_port_for_a_different_node_overwrites_it() {
        // A port genuinely can be reused for a new connection once the OS frees it - the newer
        // node's admission traffic must win, not a stale mapping from whoever held it before.
        let mut table = FlowTable::new();
        table.record_control_channel_port("n-1", 51234);

        table.record_control_channel_port("n-2", 51234);

        assert_eq!(table.node_for_control_channel_port(51234), Some("n-2"));
    }

    #[test]
    fn a_control_channel_port_lookup_does_not_remove_the_entry() {
        // One connection's admission exchange is several reply packets (SYN-ACK, then the HTTP
        // response itself) - looking one up must not forget it before the rest arrive.
        let mut table = FlowTable::new();
        table.record_control_channel_port("n-1", 51234);

        table.node_for_control_channel_port(51234);

        assert_eq!(table.node_for_control_channel_port(51234), Some("n-1"));
    }

    #[test]
    fn the_oldest_control_channel_port_is_evicted_once_the_cap_is_exceeded() {
        let mut table = FlowTable::new();
        for port in 0..MAX_TRACKED_CONTROL_CHANNEL_PORTS as u16 {
            table.record_control_channel_port("n-1", port);
        }
        assert!(table.node_for_control_channel_port(0).is_some());

        table.record_control_channel_port("n-1", MAX_TRACKED_CONTROL_CHANNEL_PORTS as u16);

        assert!(
            table.node_for_control_channel_port(0).is_none(),
            "the oldest entry must be evicted once the cap is exceeded"
        );
        assert_eq!(
            table.node_for_control_channel_port(MAX_TRACKED_CONTROL_CHANNEL_PORTS as u16),
            Some("n-1")
        );
    }

    #[test]
    fn outbound_control_channel_port_has_no_node_until_recorded() {
        let table = FlowTable::new();

        assert!(
            table
                .node_for_outbound_control_channel_source_port(51234)
                .is_none()
        );
    }

    #[test]
    fn a_recorded_outbound_control_channel_port_resolves_to_its_node() {
        let mut table = FlowTable::new();

        table.record_outbound_control_channel_port("n-1", 51234);

        assert_eq!(
            table.node_for_outbound_control_channel_source_port(51234),
            Some("n-1")
        );
    }

    /// The inbound and outbound mappings are genuinely separate state, not two views of the same
    /// data - a port recorded for one direction must never resolve through the other's lookup,
    /// since the two directions key on opposite fields of a packet (destination vs. source port)
    /// for reasons that would silently misroute a real packet if the tables were ever conflated.
    #[test]
    fn an_inbound_control_channel_port_and_an_outbound_one_are_independent_even_at_the_same_port_number()
     {
        let mut table = FlowTable::new();

        table.record_control_channel_port("n-1", 51234);
        table.record_outbound_control_channel_port("n-2", 51234);

        assert_eq!(table.node_for_control_channel_port(51234), Some("n-1"));
        assert_eq!(
            table.node_for_outbound_control_channel_source_port(51234),
            Some("n-2")
        );
    }

    #[test]
    fn re_recording_an_outbound_control_channel_port_for_a_different_node_overwrites_it() {
        let mut table = FlowTable::new();
        table.record_outbound_control_channel_port("n-1", 51234);

        table.record_outbound_control_channel_port("n-2", 51234);

        assert_eq!(
            table.node_for_outbound_control_channel_source_port(51234),
            Some("n-2")
        );
    }

    #[test]
    fn the_oldest_outbound_control_channel_port_is_evicted_once_the_cap_is_exceeded() {
        let mut table = FlowTable::new();
        for port in 0..MAX_TRACKED_CONTROL_CHANNEL_PORTS as u16 {
            table.record_outbound_control_channel_port("n-1", port);
        }
        assert!(
            table
                .node_for_outbound_control_channel_source_port(0)
                .is_some()
        );

        table.record_outbound_control_channel_port("n-1", MAX_TRACKED_CONTROL_CHANNEL_PORTS as u16);

        assert!(
            table
                .node_for_outbound_control_channel_source_port(0)
                .is_none(),
            "the oldest entry must be evicted once the cap is exceeded"
        );
        assert_eq!(
            table.node_for_outbound_control_channel_source_port(
                MAX_TRACKED_CONTROL_CHANNEL_PORTS as u16
            ),
            Some("n-1")
        );
    }

    #[test]
    fn releasing_by_flow_id_removes_the_matching_entry() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.release("flow-1");

        assert!(table.gateway_for("n-1", 40001).is_none());
    }

    #[test]
    fn releasing_an_unknown_flow_id_is_a_no_op() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.release("flow-does-not-exist");

        assert_eq!(table.gateway_for("n-1", 40001), Some("gw-1"));
    }

    #[test]
    fn releasing_one_flow_does_not_affect_a_different_flow() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.release("flow-1");

        assert!(table.gateway_for("n-1", 40001).is_none());
        assert_eq!(table.gateway_for("n-1", 40002), Some("gw-1"));
    }

    #[test]
    fn node_for_port_returns_none_when_the_port_has_never_been_admitted() {
        let table = FlowTable::new();

        assert!(table.node_for_port(40001).is_none());
    }

    #[test]
    fn node_for_port_finds_the_single_node_holding_that_port() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert_eq!(table.node_for_port(40001), Some("n-1"));
    }

    #[test]
    fn node_for_port_returns_none_when_two_nodes_hold_the_same_port_at_once() {
        // TT-1847: ports are assigned independently per node, so two
        // different nodes can legitimately hold the same port number for
        // two different flows at the same time - there is nothing left to
        // disambiguate a reply packet with, so this must refuse rather than
        // guess.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert!(table.node_for_port(40001).is_none());
    }

    #[test]
    fn node_for_port_recovers_once_the_colliding_flow_is_released() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.release("flow-2");

        assert_eq!(table.node_for_port(40001), Some("n-1"));
    }

    #[test]
    fn node_for_port_is_unaffected_by_a_different_ports_admission() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert_eq!(table.node_for_port(40001), Some("n-1"));
        assert_eq!(table.node_for_port(40002), Some("n-1"));
    }

    /// TT-2298: a first packet held while several admissions are queued is still forwarded well
    /// after the old 300ms limit.
    #[test]
    fn a_pending_packet_is_still_reclaimable_after_one_and_a_half_seconds() {
        let mut table = FlowTable::new();
        let buffered_at = Instant::now();
        table.buffer_pending_packet("n-1", 40001, vec![1, 2, 3], buffered_at);

        let reclaimed =
            table.take_pending_packet("n-1", 40001, buffered_at + Duration::from_millis(1500));

        assert_eq!(reclaimed, Some(vec![1, 2, 3]));
    }

    #[test]
    fn a_pending_packet_expires_after_two_seconds() {
        let mut table = FlowTable::new();
        let buffered_at = Instant::now();
        table.buffer_pending_packet("n-1", 40001, vec![1, 2, 3], buffered_at);

        let reclaimed =
            table.take_pending_packet("n-1", 40001, buffered_at + Duration::from_millis(2001));

        assert_eq!(reclaimed, None);
    }

    /// TT-2298: the held-packet buffer is bounded - once full, a packet for a new (node, port) is not
    /// held, while an already-held one can still be replaced by its latest packet.
    #[test]
    fn the_pending_packet_buffer_is_capped() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        for port in 0..MAX_PENDING_PACKETS {
            table.buffer_pending_packet("n-1", port as u16, vec![1], now);
        }

        table.buffer_pending_packet("n-1", 60000, vec![2], now);
        table.buffer_pending_packet("n-1", 0, vec![3], now);

        assert_eq!(table.take_pending_packet("n-1", 60000, now), None);
        assert_eq!(table.take_pending_packet("n-1", 0, now), Some(vec![3]));
    }

    /// TT-2298: release remembers the flow_id, so a late admission for it can be told apart.
    #[test]
    fn release_remembers_only_the_released_flow_id() {
        let mut table = FlowTable::new();
        assert!(!table.was_recently_released("flow-1"));

        table.release("flow-1");

        assert!(table.was_recently_released("flow-1"));
        assert!(!table.was_recently_released("flow-2"));
    }

    #[test]
    fn evict_node_removes_all_of_that_nodes_flows() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.evict_node("n-1");

        assert!(table.gateway_for("n-1", 40001).is_none());
        assert!(table.gateway_for("n-1", 40002).is_none());
    }

    /// TT-2297: a departed node's control-channel ports must not keep routing to its (gone)
    /// tunnel, and another node's entries must survive.
    #[test]
    fn evict_node_forgets_that_nodes_control_channel_ports_only() {
        let mut table = FlowTable::new();
        table.record_control_channel_port("n-1", 4000);
        table.record_outbound_control_channel_port("n-1", 50001);
        table.record_outbound_control_channel_port("n-2", 50002);

        table.evict_node("n-1");

        assert!(table.node_for_control_channel_port(4000).is_none());
        assert!(
            table
                .node_for_outbound_control_channel_source_port(50001)
                .is_none()
        );
        assert_eq!(
            table.node_for_outbound_control_channel_source_port(50002),
            Some("n-2")
        );
        table.record_outbound_control_channel_port("n-1", 50001);
        assert_eq!(
            table.node_for_outbound_control_channel_source_port(50001),
            Some("n-1"),
            "a forgotten port must be recordable again"
        );
    }

    #[test]
    fn evict_node_does_not_affect_a_different_nodes_flows() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        table.admit(
            "n-2".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.evict_node("n-1");

        assert_eq!(table.gateway_for("n-2", 40002), Some("gw-1"));
    }

    #[test]
    fn evicting_a_node_resolves_a_collision_for_the_survivor() {
        // TT-1847 finding #1: a stale entry from a departed node must not
        // permanently poison node_for_port's collision check for a port a
        // still-live node legitimately holds.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        assert!(table.node_for_port(40001).is_none());

        table.evict_node("n-1");

        assert_eq!(table.node_for_port(40001), Some("n-2"));
    }

    #[test]
    fn evicting_an_unknown_node_is_a_no_op() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.evict_node("n-does-not-exist");

        assert_eq!(table.gateway_for("n-1", 40001), Some("gw-1"));
    }

    #[test]
    fn releasing_a_flow_clears_it_from_the_port_index_too() {
        // Regression guard for the nodes_by_port index specifically: not just
        // that gateway_for stops matching, but that node_for_port (which
        // reads the index, not `flows`) also stops seeing this node for this
        // port, and a differently-admitted node isn't wrongly reported as a
        // collision afterward.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.release("flow-1");
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert_eq!(table.node_for_port(40001), Some("n-2"));
    }

    #[test]
    fn evict_gateway_device_removes_only_that_devices_flows_on_that_gateway() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
            "dev-B".to_string(),
            vec![],
        );

        let evicted = table.evict_gateway_device("gw-1", "dev-A");

        assert_eq!(evicted, 1);
        assert!(table.gateway_for("n-1", 40001).is_none());
        assert_eq!(table.gateway_for("n-1", 40002), Some("gw-1"));
    }

    #[test]
    fn evict_gateway_device_does_not_touch_the_same_devices_flow_on_a_different_gateway() {
        // The single most important property of this feature: revoking one
        // gateway's session must never touch the user's wider SecureConnect
        // session, including their other Private Gateway access.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-A".to_string(),
            vec![],
        );

        table.evict_gateway_device("gw-1", "dev-A");

        assert!(table.gateway_for("n-1", 40001).is_none());
        assert_eq!(table.gateway_for("n-1", 40002), Some("gw-2"));
    }

    #[test]
    fn evict_gateway_device_evicts_every_admitted_port_for_that_device_on_that_gateway() {
        // One device can legitimately hold several admitted flows to the
        // same gateway at once (e.g. several concurrent connections) - all
        // of them must go.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
            "dev-A".to_string(),
            vec![],
        );

        let evicted = table.evict_gateway_device("gw-1", "dev-A");

        assert_eq!(evicted, 2);
        assert!(table.gateway_for("n-1", 40001).is_none());
        assert!(table.gateway_for("n-1", 40002).is_none());
    }

    #[test]
    fn evict_gateway_device_clears_the_port_index_too() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );

        table.evict_gateway_device("gw-1", "dev-A");
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-B".to_string(),
            vec![],
        );

        assert_eq!(table.node_for_port(40001), Some("n-2"));
    }

    #[test]
    fn evicting_a_device_with_no_admitted_flow_is_a_harmless_no_op() {
        let mut table = FlowTable::new();

        let evicted = table.evict_gateway_device("gw-1", "dev-never-connected");

        assert_eq!(evicted, 0);
    }

    #[test]
    fn re_admitting_the_same_node_and_port_replaces_the_previous_flow() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        // The port is reused for a new flow (e.g. after the first was
        // released and Gatekeeper reassigned the same translated port).
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert_eq!(table.gateway_for("n-1", 40001), Some("gw-2"));
    }

    #[test]
    fn update_endpoints_changes_what_an_already_admitted_flow_forwards_to() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![endpoint("10.0.0.1", 443)],
        );

        table.update_endpoints("gw-1", &[endpoint("10.0.0.2", 443)]);
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::Forward("10.0.0.2".parse().unwrap())
        );
    }

    #[test]
    fn update_endpoints_does_not_touch_a_different_gateways_flow() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![endpoint("10.0.0.1", 443)],
        );

        table.update_endpoints("gw-2", &[endpoint("10.0.0.2", 443)]);
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::Forward("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn update_endpoints_is_a_no_op_for_a_gateway_with_no_admitted_flow() {
        let mut table = FlowTable::new();

        table.update_endpoints("gw-1", &[endpoint("10.0.0.2", 443)]);
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::NotAdmitted
        );
    }

    #[test]
    fn update_endpoints_can_remove_an_endpoint_a_flow_was_relying_on() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![endpoint("10.0.0.1", 443)],
        );

        table.update_endpoints("gw-1", &[]);
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::PortNotConfigured
        );
    }

    fn endpoint(host: &str, port: u16) -> PolicyBundleEndpoint {
        PolicyBundleEndpoint {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn forward_target_is_not_admitted_for_an_unadmitted_flow() {
        let table = FlowTable::new();
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::NotAdmitted
        );
    }

    #[test]
    fn forward_target_resolves_a_configured_endpoints_real_address() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![endpoint("10.0.0.5", 443)],
        );
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::Forward("10.0.0.5".parse().unwrap())
        );
    }

    #[test]
    fn forward_target_is_port_not_configured_when_the_flow_is_admitted_but_no_endpoint_matches_the_port()
     {
        // TT-2046: the sharpest case - the flow itself is legitimately
        // admitted (the user is entitled to the gateway), but the client
        // dialed a port the gateway was never configured to expose.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![endpoint("10.0.0.5", 443)],
        );
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 8080, &dns_cache),
            ForwardOutcome::PortNotConfigured
        );
    }

    #[test]
    fn forward_target_matches_the_right_one_of_several_configured_endpoints_by_port() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![endpoint("10.0.0.5", 443), endpoint("10.0.0.6", 8443)],
        );
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 8443, &dns_cache),
            ForwardOutcome::Forward("10.0.0.6".parse().unwrap())
        );
    }

    #[test]
    fn forward_target_is_ambiguous_endpoint_when_two_endpoints_share_the_same_port() {
        // TT-2046 review finding #3: same shape of ambiguity node_for_port already refuses to
        // guess at - refuse and log loudly, never silently pick whichever came first.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![endpoint("10.0.0.5", 443), endpoint("10.0.0.6", 443)],
        );
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::AmbiguousEndpoint
        );
    }

    #[test]
    fn forward_target_is_host_unresolved_for_a_hostname_not_yet_resolved_in_the_dns_cache() {
        // TT-2066: a hostname endpoint is enforceable once resolved, but never trusted before
        // that - refuse, the safe direction, same as an unadmitted flow. Also covers what used to
        // be a separate "non-IP-literal host" case (TT-2046): before TT-2066, any hostname was
        // categorically unsupported; now it's just unresolved until a heartbeat's DNS refresh
        // succeeds for it, so the two cases collapsed into one.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![endpoint("crm.internal.example.com", 443)],
        );
        let dns_cache = crate::dns_cache::DnsCache::new();

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::HostUnresolved
        );
    }

    #[tokio::test]
    async fn forward_target_resolves_a_hostname_endpoint_once_the_dns_cache_has_it() {
        // TT-2066: the whole point - a hostname endpoint (Portal always allowed configuring one)
        // now actually forwards, once the Connector's own DNS cache has resolved it.
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![endpoint("crm.internal.example.com", 443)],
        );
        let dns_cache = crate::dns_cache::DnsCache::new();
        dns_cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec!["10.0.0.5".parse().unwrap()])
            })
            .await;

        assert_eq!(
            table.forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::Forward("10.0.0.5".parse().unwrap())
        );
    }

    #[test]
    fn virtual_address_for_is_none_until_recorded() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert_eq!(table.virtual_address_for("n-1", 40001), None);
    }

    #[test]
    fn record_virtual_address_makes_it_available_via_virtual_address_for() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        table.record_virtual_address("n-1", 40001, "172.16.0.9".parse().unwrap());

        assert_eq!(
            table.virtual_address_for("n-1", 40001),
            Some("172.16.0.9".parse().unwrap())
        );
    }

    #[test]
    fn record_virtual_address_is_a_no_op_for_an_unadmitted_flow() {
        let mut table = FlowTable::new();

        table.record_virtual_address("n-1", 40001, "172.16.0.9".parse().unwrap());

        assert_eq!(table.virtual_address_for("n-1", 40001), None);
    }

    #[test]
    fn a_pending_packet_is_reclaimed_within_the_ttl() {
        let mut table = FlowTable::new();
        let buffered_at = Instant::now();

        table.buffer_pending_packet("n-1", 40001, vec![1, 2, 3], buffered_at);

        let reclaimed =
            table.take_pending_packet("n-1", 40001, buffered_at + Duration::from_millis(100));

        assert_eq!(reclaimed, Some(vec![1, 2, 3]));
    }

    #[test]
    fn a_pending_packet_past_the_ttl_is_not_reclaimed() {
        let mut table = FlowTable::new();
        let buffered_at = Instant::now();

        table.buffer_pending_packet("n-1", 40001, vec![1, 2, 3], buffered_at);

        let reclaimed = table.take_pending_packet(
            "n-1",
            40001,
            buffered_at + PENDING_PACKET_TTL + Duration::from_millis(1),
        );

        assert_eq!(reclaimed, None);
    }

    #[test]
    fn take_pending_packet_removes_it_so_it_cannot_be_reclaimed_twice() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        table.buffer_pending_packet("n-1", 40001, vec![1, 2, 3], now);

        assert_eq!(
            table.take_pending_packet("n-1", 40001, now),
            Some(vec![1, 2, 3])
        );
        assert_eq!(table.take_pending_packet("n-1", 40001, now), None);
    }

    #[test]
    fn take_pending_packet_is_none_when_nothing_was_ever_buffered() {
        let mut table = FlowTable::new();

        assert_eq!(
            table.take_pending_packet("n-1", 40001, Instant::now()),
            None
        );
    }

    #[test]
    fn buffering_a_new_pending_packet_for_the_same_key_overwrites_the_previous_one() {
        let mut table = FlowTable::new();
        let now = Instant::now();

        table.buffer_pending_packet("n-1", 40001, vec![1], now);
        table.buffer_pending_packet("n-1", 40001, vec![2], now);

        assert_eq!(table.take_pending_packet("n-1", 40001, now), Some(vec![2]));
    }

    #[test]
    fn buffering_a_pending_packet_sweeps_other_entries_that_have_already_expired() {
        let mut table = FlowTable::new();
        let stale_at = Instant::now();
        table.buffer_pending_packet("n-1", 40001, vec![1], stale_at);

        // A second, unrelated flow's packet arrives well past the first one's TTL - the sweep
        // inside buffer_pending_packet should have already dropped the stale entry, not just left
        // it there for take_pending_packet to reject later.
        let fresh_at = stale_at + PENDING_PACKET_TTL + Duration::from_millis(50);
        table.buffer_pending_packet("n-2", 40002, vec![2], fresh_at);

        assert_eq!(table.take_pending_packet("n-1", 40001, fresh_at), None);
        assert_eq!(
            table.take_pending_packet("n-2", 40002, fresh_at),
            Some(vec![2])
        );
    }

    #[test]
    fn admit_does_not_by_itself_clear_a_pending_packet() {
        // take_pending_packet is a deliberate, separate step the caller must take after admit()
        // (see main.rs's use of both together) - admit() itself has no knowledge of buffered
        // packets at all, so this just documents that the two are independent.
        let mut table = FlowTable::new();
        let now = Instant::now();
        table.buffer_pending_packet("n-1", 40001, vec![1, 2, 3], now);

        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );

        assert_eq!(
            table.take_pending_packet("n-1", 40001, now),
            Some(vec![1, 2, 3])
        );
    }

    // --- TT-2639: flows identified by what the user dialled, with an allocated source port ---

    const ERP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 3);
    const FIN: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
    const ERP_HOST: Ipv4Addr = Ipv4Addr::new(172, 31, 4, 176);
    const FIN_HOST: Ipv4Addr = Ipv4Addr::new(172, 31, 11, 207);

    fn dialled(transport: Transport, gateway_address: Ipv4Addr, destination_port: u16) -> Dialled {
        Dialled {
            transport,
            gateway_address,
            destination_port,
        }
    }

    fn admit_dialled(
        table: &mut FlowTable,
        node_id: &str,
        port: u16,
        to: Dialled,
        gateway_id: &str,
        flow_id: &str,
        host: Ipv4Addr,
    ) {
        table.admit_dialled(
            node_id.to_string(),
            port,
            to,
            gateway_id.to_string(),
            flow_id.to_string(),
            "dev-1".to_string(),
            vec![endpoint(&host.to_string(), to.destination_port)],
        );
    }

    fn forward(
        table: &mut FlowTable,
        node_id: &str,
        port: u16,
        to: Dialled,
    ) -> Option<DialledForward> {
        table.dialled_forward_target(node_id, port, to, &crate::dns_cache::DnsCache::new())
    }

    /// The source port a forwarded packet gets, panicking if it isn't forwarded.
    fn source_port(table: &mut FlowTable, node_id: &str, port: u16, to: Dialled) -> u16 {
        match forward(table, node_id, port, to) {
            Some(DialledForward::Forward { source_port, .. }) => source_port,
            other => panic!("expected a forward, got {other:?}"),
        }
    }

    /// TT-2651's reproduction: one translated port, two gateways on the same destination port.
    #[test]
    fn two_gateways_on_one_translated_port_are_two_flows() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        let fin = dialled(Transport::Tcp, FIN, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-erp", ERP_HOST,
        );
        admit_dialled(
            &mut table, "n-1", 40100, fin, "gw-fin", "flow-fin", FIN_HOST,
        );

        assert!(matches!(
            forward(&mut table, "n-1", 40100, erp),
            Some(DialledForward::Forward {
                address: ERP_HOST,
                ..
            })
        ));
        assert!(matches!(
            forward(&mut table, "n-1", 40100, fin),
            Some(DialledForward::Forward {
                address: FIN_HOST,
                ..
            })
        ));
    }

    #[test]
    fn a_packet_to_another_gateway_never_matches_an_admitted_flow() {
        let mut table = FlowTable::new();
        admit_dialled(
            &mut table,
            "n-1",
            40100,
            dialled(Transport::Tcp, ERP, 80),
            "gw-erp",
            "flow-erp",
            ERP_HOST,
        );

        assert_eq!(
            forward(&mut table, "n-1", 40100, dialled(Transport::Tcp, FIN, 80)),
            None
        );
        assert_eq!(
            forward(&mut table, "n-1", 40100, dialled(Transport::Tcp, ERP, 22)),
            None
        );
        assert_eq!(
            forward(&mut table, "n-1", 40100, dialled(Transport::Udp, ERP, 80)),
            None
        );
        assert_eq!(
            forward(&mut table, "n-2", 40100, dialled(Transport::Tcp, ERP, 80)),
            None
        );
    }

    #[test]
    fn two_ports_of_one_gateway_and_tcp_and_udp_are_separate_flows() {
        let mut table = FlowTable::new();
        let https = dialled(Transport::Tcp, ERP, 443);
        let ssh = dialled(Transport::Tcp, ERP, 22);
        let quic = dialled(Transport::Udp, ERP, 443);
        admit_dialled(
            &mut table,
            "n-1",
            40100,
            https,
            "gw-erp",
            "flow-https",
            ERP_HOST,
        );
        admit_dialled(
            &mut table, "n-1", 40100, ssh, "gw-erp", "flow-ssh", ERP_HOST,
        );
        admit_dialled(
            &mut table,
            "n-1",
            40100,
            quic,
            "gw-erp",
            "flow-quic",
            ERP_HOST,
        );
        let https_port = source_port(&mut table, "n-1", 40100, https);
        let ssh_port = source_port(&mut table, "n-1", 40100, ssh);
        let quic_port = source_port(&mut table, "n-1", 40100, quic);

        let https_reply = table
            .dialled_reply(Transport::Tcp, ERP_HOST, 443, https_port)
            .unwrap();
        let ssh_reply = table
            .dialled_reply(Transport::Tcp, ERP_HOST, 22, ssh_port)
            .unwrap();
        let quic_reply = table
            .dialled_reply(Transport::Udp, ERP_HOST, 443, quic_port)
            .unwrap();
        assert_eq!(https_reply.destination_port, 443);
        assert_eq!(ssh_reply.destination_port, 22);
        assert_eq!(quic_reply.destination_port, 443);
        assert_eq!(table.dialled_by_allocation.len(), 3);
    }

    /// Two nodes using the same translated port: each reply goes back to its own node, where
    /// `node_for_port` had to drop both as ambiguous.
    #[test]
    fn replies_on_two_nodes_with_the_same_translated_port_go_to_their_own_node() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(&mut table, "n-1", 40100, erp, "gw-erp", "flow-1", ERP_HOST);
        admit_dialled(&mut table, "n-2", 40100, erp, "gw-erp", "flow-2", ERP_HOST);
        let port_1 = source_port(&mut table, "n-1", 40100, erp);
        let port_2 = source_port(&mut table, "n-2", 40100, erp);

        assert_ne!(
            port_1, port_2,
            "same internal service, so different source ports"
        );
        assert_eq!(
            table
                .dialled_reply(Transport::Tcp, ERP_HOST, 80, port_2)
                .unwrap()
                .node_id,
            "n-2"
        );
        assert_eq!(
            table.dialled_reply(Transport::Tcp, ERP_HOST, 80, port_1),
            Some(DialledReply {
                node_id: "n-1".to_string(),
                gateway_address: ERP,
                destination_port: 80,
                translated_port: 40100,
            })
        );
    }

    /// Two gateways pointing to the same internal service: the allocated ports keep the two
    /// connections apart there, and each reply finds its own gateway.
    #[test]
    fn two_gateways_to_the_same_internal_service_get_their_own_replies() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        let fin = dialled(Transport::Tcp, FIN, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-erp", ERP_HOST,
        );
        admit_dialled(
            &mut table, "n-1", 40100, fin, "gw-fin", "flow-fin", ERP_HOST,
        );
        let erp_port = source_port(&mut table, "n-1", 40100, erp);
        let fin_port = source_port(&mut table, "n-1", 40100, fin);

        assert_ne!(erp_port, fin_port);
        assert_eq!(
            table
                .dialled_reply(Transport::Tcp, ERP_HOST, 80, erp_port)
                .map(|r| r.gateway_address),
            Some(ERP)
        );
        assert_eq!(
            table
                .dialled_reply(Transport::Tcp, ERP_HOST, 80, fin_port)
                .map(|r| r.gateway_address),
            Some(FIN)
        );
    }

    /// Ports are unique per internal host:port (the ticket's design): flows to different internal
    /// services may use the same source port, since their replies come from different places.
    #[test]
    fn flows_to_different_internal_services_can_share_a_source_port() {
        let mut table = FlowTable::with_source_port_range(2000..=2000);
        let erp = dialled(Transport::Tcp, ERP, 80);
        let fin = dialled(Transport::Tcp, FIN, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-erp", ERP_HOST,
        );
        admit_dialled(
            &mut table, "n-1", 40100, fin, "gw-fin", "flow-fin", FIN_HOST,
        );

        assert_eq!(source_port(&mut table, "n-1", 40100, erp), 2000);
        assert_eq!(source_port(&mut table, "n-1", 40100, fin), 2000);
        assert_eq!(
            table
                .dialled_reply(Transport::Tcp, ERP_HOST, 80, 2000)
                .map(|r| r.gateway_address),
            Some(ERP)
        );
        assert_eq!(
            table
                .dialled_reply(Transport::Tcp, FIN_HOST, 80, 2000)
                .map(|r| r.gateway_address),
            Some(FIN)
        );
    }

    #[test]
    fn a_reply_from_anywhere_but_the_flows_internal_service_is_not_matched() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-erp", ERP_HOST,
        );
        let port = source_port(&mut table, "n-1", 40100, erp);

        assert_eq!(
            table.dialled_reply(Transport::Tcp, FIN_HOST, 80, port),
            None
        );
        assert_eq!(
            table.dialled_reply(Transport::Tcp, ERP_HOST, 81, port),
            None
        );
        assert_eq!(
            table.dialled_reply(Transport::Udp, ERP_HOST, 80, port),
            None
        );
        assert!(
            table
                .dialled_reply(Transport::Tcp, ERP_HOST, 80, port)
                .is_some()
        );
    }

    #[test]
    fn no_reply_matches_before_the_first_packet_is_forwarded() {
        let mut table = FlowTable::with_source_port_range(2000..=2000);
        admit_dialled(
            &mut table,
            "n-1",
            40100,
            dialled(Transport::Tcp, ERP, 80),
            "gw-erp",
            "flow-erp",
            ERP_HOST,
        );

        assert_eq!(
            table.dialled_reply(Transport::Tcp, ERP_HOST, 80, 2000),
            None
        );
    }

    #[test]
    fn release_frees_the_allocated_port_and_forgets_the_flow() {
        let mut table = FlowTable::with_source_port_range(2000..=2000);
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-erp", ERP_HOST,
        );
        source_port(&mut table, "n-1", 40100, erp);

        table.release("flow-erp");
        admit_dialled(&mut table, "n-1", 40200, erp, "gw-erp", "flow-2", ERP_HOST);

        assert_eq!(forward(&mut table, "n-1", 40100, erp), None);
        assert_eq!(source_port(&mut table, "n-1", 40200, erp), 2000);
    }

    #[test]
    fn with_no_free_source_port_to_that_service_the_packet_is_not_forwarded() {
        let mut table = FlowTable::with_source_port_range(2000..=2000);
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(&mut table, "n-1", 40100, erp, "gw-erp", "flow-1", ERP_HOST);
        admit_dialled(&mut table, "n-1", 40101, erp, "gw-erp", "flow-2", ERP_HOST);
        source_port(&mut table, "n-1", 40100, erp);

        assert_eq!(
            forward(&mut table, "n-1", 40101, erp),
            Some(DialledForward::Refused(ForwardOutcome::NoFreeSourcePort))
        );

        table.release("flow-1");
        assert_eq!(
            source_port(&mut table, "n-1", 40101, erp),
            2000,
            "gets a port once one is freed"
        );
    }

    #[test]
    fn a_freed_port_is_not_handed_out_again_at_once() {
        let mut table = FlowTable::with_source_port_range(2000..=2002);
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(&mut table, "n-1", 40100, erp, "gw-erp", "flow-1", ERP_HOST);
        let first = source_port(&mut table, "n-1", 40100, erp);
        table.release("flow-1");
        admit_dialled(&mut table, "n-1", 40101, erp, "gw-erp", "flow-2", ERP_HOST);

        let second = source_port(&mut table, "n-1", 40101, erp);

        assert_eq!(first, 2000);
        assert_eq!(second, 2001);
    }

    #[test]
    fn later_packets_of_a_flow_keep_its_source_port() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-erp", ERP_HOST,
        );

        let first = source_port(&mut table, "n-1", 40100, erp);

        assert_eq!(source_port(&mut table, "n-1", 40100, erp), first);
        assert_eq!(table.dialled_by_allocation.len(), 1);
    }

    #[test]
    fn a_flow_whose_internal_address_changes_moves_its_port_there() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-erp", ERP_HOST,
        );
        let port = source_port(&mut table, "n-1", 40100, erp);

        table.update_endpoints("gw-erp", &[endpoint("172.31.9.9", 80)]);
        let moved = source_port(&mut table, "n-1", 40100, erp);

        assert_eq!(
            table.dialled_reply(Transport::Tcp, ERP_HOST, 80, port),
            None,
            "the old one is freed"
        );
        assert!(
            table
                .dialled_reply(Transport::Tcp, Ipv4Addr::new(172, 31, 9, 9), 80, moved)
                .is_some()
        );
        assert_eq!(table.dialled_by_allocation.len(), 1);
    }

    #[test]
    fn re_admitting_the_same_identity_replaces_the_flow_and_frees_its_old_port() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-old", ERP_HOST,
        );
        source_port(&mut table, "n-1", 40100, erp);

        admit_dialled(
            &mut table, "n-1", 40100, erp, "gw-erp", "flow-new", ERP_HOST,
        );
        table.release("flow-old");

        assert!(table.dialled_by_allocation.is_empty());
        assert!(
            forward(&mut table, "n-1", 40100, erp).is_some(),
            "flow-new is still admitted"
        );
    }

    #[test]
    fn evicting_a_node_or_a_device_frees_the_ports_of_its_dialled_flows() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 80);
        let fin = dialled(Transport::Tcp, FIN, 80);
        admit_dialled(&mut table, "n-1", 40100, erp, "gw-erp", "flow-1", ERP_HOST);
        admit_dialled(&mut table, "n-2", 40100, erp, "gw-erp", "flow-2", ERP_HOST);
        admit_dialled(&mut table, "n-3", 40100, fin, "gw-fin", "flow-3", FIN_HOST);
        for node in ["n-1", "n-2"] {
            source_port(&mut table, node, 40100, erp);
        }
        source_port(&mut table, "n-3", 40100, fin);

        table.evict_node("n-1");
        let evicted = table.evict_gateway_device("gw-erp", "dev-1");

        assert_eq!(evicted, 1, "n-2's flow; n-1's was already gone");
        assert_eq!(forward(&mut table, "n-1", 40100, erp), None);
        assert_eq!(forward(&mut table, "n-2", 40100, erp), None);
        assert_eq!(
            table.dialled_by_allocation.len(),
            1,
            "only n-3's Finance flow holds a port"
        );
    }

    #[test]
    fn a_pending_packet_is_reclaimed_only_by_the_admission_of_exactly_its_flow() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        table.buffer_pending_dialled_packet(
            "n-1",
            40100,
            dialled(Transport::Tcp, FIN, 80),
            vec![1],
            now,
        );

        assert_eq!(
            table.take_pending_dialled_packet("n-1", 40100, dialled(Transport::Tcp, ERP, 80), now),
            None
        );
        assert_eq!(
            table.take_pending_dialled_packet("n-1", 40100, dialled(Transport::Tcp, FIN, 80), now),
            Some(vec![1])
        );
    }

    /// A node that predates the dialled identity: its admission (node and port only) still reclaims a
    /// packet that was held under the identity read from the packet.
    #[test]
    fn an_older_nodes_admission_reclaims_a_packet_held_under_its_dialled_identity() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        table.buffer_pending_dialled_packet(
            "n-1",
            40100,
            dialled(Transport::Tcp, ERP, 80),
            vec![7],
            now,
        );

        assert_eq!(table.take_pending_packet("n-1", 40100, now), Some(vec![7]));
        assert_eq!(table.take_pending_packet("n-1", 40100, now), None);
    }

    #[test]
    fn pending_packets_of_both_kinds_share_one_capacity() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        for port in 0..MAX_PENDING_PACKETS as u16 {
            table.buffer_pending_packet("n-1", port, vec![0], now);
        }

        table.buffer_pending_dialled_packet(
            "n-1",
            60000,
            dialled(Transport::Tcp, ERP, 80),
            vec![1],
            now,
        );

        assert_eq!(
            table.take_pending_dialled_packet("n-1", 60000, dialled(Transport::Tcp, ERP, 80), now),
            None
        );
    }

    // --- TT-2639 review: flows admitted before their node was updated ---

    fn admit_legacy(table: &mut FlowTable, node_id: &str, port: u16, gateway_id: &str) {
        table.admit(
            node_id.to_string(),
            port,
            gateway_id.to_string(),
            format!("legacy-{gateway_id}"),
            "dev-1".to_string(),
            vec![endpoint(&ERP_HOST.to_string(), 80)],
        );
    }

    /// The node has since been updated (it sent a dialled admission).
    fn mark_node_updated(table: &mut FlowTable, node_id: &str) {
        admit_dialled(
            table,
            node_id,
            1,
            dialled(Transport::Tcp, ERP, 1),
            "gw-other",
            "flow-marker",
            ERP_HOST,
        );
    }

    #[test]
    fn a_legacy_flow_is_used_only_by_packets_to_the_gateway_it_was_first_seen_with() {
        let mut table = FlowTable::new();
        admit_legacy(&mut table, "n-1", 40100, "gw-erp");
        table.record_virtual_address("n-1", 40100, ERP);
        mark_node_updated(&mut table, "n-1");

        assert!(table.legacy_flow_accepts("n-1", 40100, ERP));
        assert!(
            !table.legacy_flow_accepts("n-1", 40100, FIN),
            "another gateway's packet must not use it"
        );
    }

    #[test]
    fn on_an_updated_node_a_legacy_flow_with_no_address_yet_is_not_used() {
        let mut table = FlowTable::new();
        admit_legacy(&mut table, "n-1", 40100, "gw-erp");
        mark_node_updated(&mut table, "n-1");

        assert!(!table.legacy_flow_accepts("n-1", 40100, FIN));
        assert!(!table.legacy_flow_accepts("n-1", 40100, ERP));
    }

    /// A node not yet updated keeps today's behaviour: its flows' first packet records the address.
    #[test]
    fn on_a_node_not_yet_updated_a_legacy_flow_with_no_address_yet_is_used() {
        let mut table = FlowTable::new();
        admit_legacy(&mut table, "n-1", 40100, "gw-erp");
        mark_node_updated(&mut table, "n-2");

        assert!(table.legacy_flow_accepts("n-1", 40100, ERP));
    }

    #[test]
    fn a_node_evicted_and_seen_again_is_not_assumed_updated() {
        let mut table = FlowTable::new();
        mark_node_updated(&mut table, "n-1");
        table.evict_node("n-1");
        admit_legacy(&mut table, "n-1", 40100, "gw-erp");

        assert!(table.legacy_flow_accepts("n-1", 40100, ERP));
    }
}
