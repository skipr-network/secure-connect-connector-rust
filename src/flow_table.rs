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
//! (`route_reply`). A flow admitted without that identity - from a node that predates it - is
//! still identified by `(node_id, port)` as before, in the same table (`FlowKey` with no
//! identity); once every node is updated that case is dead code and can be removed (TT-2673).
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
//! normal, expected case, not an edge case. `route_reply` replaces it: the
//! admission state recorded here (told explicitly by Gatekeeper, never
//! inferred) is the only thing this Connector can trust for that lookup.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[cfg(test)]
use crate::dto::PolicyBundleEndpoint;
use crate::dto::{PortRule, RuleTransport};

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

/// What identifies an admitted flow (spec §B.8): its node and translated port, plus what the user
/// dialled when the node sent it (TT-2639). A flow admitted by a node that predates the identity
/// has none, and is told apart by node and port alone until every node is updated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    node_id: String,
    port: u16,
    dialled: Option<Dialled>,
}

impl FlowKey {
    fn new(node_id: &str, port: u16, dialled: Option<Dialled>) -> Self {
        Self {
            node_id: node_id.to_string(),
            port,
            dialled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Allocation {
    /// The internal address and port - a reply must come from exactly there.
    target: (Ipv4Addr, u16),
    /// The source port, unique among this Connector's flows to `target` on that transport.
    port: u16,
}

/// How to forward one decrypted packet (`FlowTable::forward`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forwarding {
    /// Rewrite the destination to `address`, its port to `destination_port` when the matched rule
    /// translates it (TT-2514), and, for a flow with its dialled identity, the source port to
    /// `source_port` (TT-2639).
    Forward {
        address: Ipv4Addr,
        destination_port: Option<u16>,
        source_port: Option<u16>,
    },
    /// No admitted flow may carry it: hold it briefly in case its own admission is in flight
    /// (`FlowTable::buffer_pending`).
    NotAdmitted,
    /// Admitted, but it can't be forwarded: any `ForwardOutcome` but `Forward`/`NotAdmitted`.
    Refused(ForwardOutcome),
}

/// Where a packet read from the TUN device goes (`FlowTable::route_reply`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyRoute {
    /// A connection of the control channel: sent to `node_id` unchanged.
    Unchanged { node_id: String },
    /// A reply on an admitted flow: its source address becomes `source` (what the client dialled)
    /// and, for a flow with its dialled identity, its source port the dialled port and its
    /// destination port the translated port (TT-2639).
    Restore {
        node_id: String,
        source: Ipv4Addr,
        source_port: Option<u16>,
        destination_port: Option<u16>,
    },
}

/// Why a packet read from the TUN device has nowhere to go (`FlowTable::route_reply`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyMiss {
    /// No flow, and no node unambiguously holding its port (never admitted, or admitted on two
    /// nodes at once by nodes that predate the dialled identity).
    NoFlow,
    /// A flow from a node that predates the dialled identity whose gateway address hasn't been seen
    /// yet - the client would never accept the reply.
    NoAddressYet { node_id: String },
}

/// `FlowTable::dialled_forward_target`'s result, kept for the tests of a flow with its identity.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialledForward {
    Forward { address: Ipv4Addr, source_port: u16 },
    Refused(ForwardOutcome),
}

/// `FlowTable::dialled_reply`'s result, kept for the tests of a flow with its identity.
#[cfg(test)]
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
    /// request that created this entry (TT-1640). Not used for routing - only for
    /// `evict_gateway_device`, which needs to find "this device's admitted
    /// flows on this gateway" without anything Gatekeeper's release contract
    /// already carries (`flow_id`/`port` alone can't answer "which user").
    device_public_key: String,
    /// The entitled gateway's port rules (TT-2514; its endpoints before that, TT-2046), from the
    /// same `PolicyBundle::rules` `AccessDecision::Allowed` already resolved at admission time. Being admitted only proves the device is
    /// entitled to this *gateway* - it says nothing about which internal
    /// address the gateway is actually configured to expose. `forward` uses this
    /// both to refuse a packet outright and to know what address to rewrite an
    /// allowed one to - the address the packet already carries on arrival is
    /// never the real endpoint, so nothing downstream can work at all without this.
    rules: Vec<PortRule>,
    /// The fake/virtual destination address this flow's packets actually arrive addressed to
    /// (Gatekeeper's invented per-gateway address). A flow admitted with its dialled identity has it
    /// from admission (TT-2639); for a flow from a node that predates the identity it is learned
    /// from the forwarded packets, since that admission carries no such field. Needed to rewrite a
    /// *reply* packet's source back to what the client actually dialed (TT-2046 review finding #1):
    /// a real kernel DNAT gets this reversal for free via conntrack; this rewrite happens in
    /// userspace with no conntrack entry to reverse it, so the Connector has to remember it. For a
    /// flow without an identity, `None` until its first forwarded packet has been seen.
    virtual_address: Option<Ipv4Addr>,
    /// TT-2639, a flow with its dialled identity only: where its packets go on the internal network
    /// and the source port they carry there. Set when its first packet is forwarded - the internal
    /// address is only known then (a configured host can be a name still being resolved) - and
    /// replaced if that address changes.
    allocation: Option<Allocation>,
}

/// Why a decrypted packet can or can't be forwarded, returned by `forward_target` instead of a
/// bare `Option<Ipv4Addr>` (TT-2046 review finding #5) so the caller can log a message specific to
/// which of several genuinely different situations occurred, rather than one generic line that
/// makes them indistinguishable on-call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// Resolved to a real address - only `forward_target`, kept for the tests, still returns it;
    /// production code gets `Forwarding::Forward`.
    #[cfg_attr(not(test), allow(dead_code))]
    Forward(Ipv4Addr),
    /// No admitted flow at all for `(node_id, port)` - a security event: decrypting successfully
    /// proves the packet came from a genuine node tunnel, but says nothing about whether
    /// Gatekeeper's flow-admission relay ever admitted this specific device/gateway. Since TT-2639
    /// production code reports this as `Forwarding::NotAdmitted`; only `forward_target`, kept for
    /// the tests, still returns it.
    #[cfg_attr(not(test), allow(dead_code))]
    NotAdmitted,
    /// Admitted, but no port rule of the gateway opens the packet's transport and destination port
    /// (TT-2514; its endpoints before that) - misconfiguration or probing, not a security event.
    PortNotConfigured,
    /// Admitted, but more than one port rule opens the packet's transport and port (Portal allows
    /// only one; endpoints sharing a port did before TT-2514) - genuinely ambiguous which one the client meant, not something to guess
    /// at (matches `node_for_port`'s own precedent for the same shape of ambiguity: refuse, don't
    /// silently pick one).
    AmbiguousEndpoint,
    /// TT-2514: admitted, but the matching rule forwards to a different internal port and the flow
    /// came from a node that predates the dialled identity (TT-2639) - its replies could not get the
    /// dialled port back, so it is only served by rules with equal ports.
    PortTranslationNeedsUpdatedNode,
    /// Admitted, exactly one port rule matches, but `dns_cache` has no resolved address for its
    /// internal host (TT-2066) - a literal IPv4 always resolves, so this only happens for a
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
    /// Every admitted flow, with or without its dialled identity (TT-2639) - see the module doc.
    flows: HashMap<FlowKey, AdmittedFlow>,
    /// Reverse index for flows without a dialled identity (TT-1732 review, Tasneem, TT-1847 finding
    /// #3): `port -> the node_id(s) currently holding it`, kept incrementally in sync with `flows` on
    /// every admit/release/evict. Their replies carry nothing but that port, and without this
    /// `route_reply` - called on every outbound packet, under a lock also shared with the
    /// flow-admission/release control plane - would need to scan every admitted flow.
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
    /// `take_pending` can hand it back for forwarding if admission catches up in time. Held under
    /// the flow key the packet itself gives - with its dialled identity when it can be read
    /// (TT-2639), so only exactly that flow's admission reclaims it. Only the most recent packet per
    /// key is kept: for the TCP handshakes this exists to rescue, any single copy of the client's SYN
    /// reaching the real destination once is enough.
    pending_packets: HashMap<FlowKey, (Vec<u8>, Instant)>,
    /// TT-2298: flow_ids released within `RELEASED_FLOW_MEMORY`, with when - see that constant.
    recently_released: HashMap<String, Instant>,
    /// TT-2639: `(transport, internal address, internal port, allocated port) -> flow` - a reply's
    /// own transport, source and destination port, so it matches exactly one flow.
    dialled_by_allocation: HashMap<(Transport, Ipv4Addr, u16, u16), FlowKey>,
    /// TT-2639: where the next source-port search starts, per transport and internal host:port (so a
    /// freed port is not reused at once while its old connection may still be closing there).
    next_source_port: HashMap<(Transport, Ipv4Addr, u16), u16>,
    /// TT-2639: the allocatable range - `SOURCE_PORT_RANGE` except in tests of exhaustion.
    source_port_range: Option<std::ops::RangeInclusive<u16>>,
    /// TT-2639: nodes that have sent an admission with its dialled identity - updated nodes. On such a
    /// node a flow admitted without the identity (before the update) is used only by packets to the
    /// gateway address it was first seen with (`legacy_flow_accepts`).
    dialled_nodes: HashSet<String>,
    /// TT-2514 review: each gateway's port rules as the latest heartbeat applied them
    /// (`update_rules`). An admission decided against the policy store just before a heartbeat
    /// changed them takes these instead (`current_rules`), under the same lock, so it never admits
    /// a flow by a rule that heartbeat removed.
    gateway_rules: HashMap<String, Vec<PortRule>>,
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

    /// Records an admitted flow (spec §B.8): with its dialled identity when the node sent it
    /// (TT-2639), otherwise by node and translated port alone, as before. Re-admitting the same key
    /// (its release never arrived) replaces the old entry and frees its source port. A flow with an
    /// identity gets its source port when its first packet is forwarded (`forward`).
    #[allow(clippy::too_many_arguments)]
    pub fn admit_flow(
        &mut self,
        node_id: String,
        port: u16,
        dialled: Option<Dialled>,
        gateway_id: String,
        flow_id: String,
        device_public_key: String,
        rules: Vec<PortRule>,
    ) {
        let key = FlowKey {
            node_id,
            port,
            dialled,
        };
        self.remove_flow(&key);
        match dialled {
            Some(_) => {
                self.dialled_nodes.insert(key.node_id.clone());
            }
            None => {
                self.nodes_by_port
                    .entry(port)
                    .or_default()
                    .insert(key.node_id.clone());
            }
        }
        self.flows.insert(
            key,
            AdmittedFlow {
                gateway_id,
                flow_id,
                device_public_key,
                rules,
                virtual_address: dialled.map(|dialled| dialled.gateway_address),
                allocation: None,
            },
        );
    }

    /// Removes one flow, freeing its allocated source port or its `nodes_by_port` entry; a no-op if
    /// it isn't admitted.
    fn remove_flow(&mut self, key: &FlowKey) {
        let Some(removed) = self.flows.remove(key) else {
            return;
        };
        match (key.dialled, removed.allocation) {
            (Some(dialled), Some(Allocation { target, port })) => {
                self.dialled_by_allocation
                    .remove(&(dialled.transport, target.0, target.1, port));
            }
            (Some(_), None) => {}
            (None, _) => self.deindex(&key.node_id, key.port),
        }
    }

    /// Removes every flow `drop_it` selects; returns how many.
    fn remove_flows_where(&mut self, drop_it: impl Fn(&FlowKey, &AdmittedFlow) -> bool) -> usize {
        let removed: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(key, flow)| drop_it(key, flow))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &removed {
            self.remove_flow(key);
        }
        removed.len()
    }

    pub fn release(&mut self, flow_id: &str) {
        self.remove_flows_where(|_, flow| flow.flow_id == flow_id);
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
        self.remove_flows_where(|key, _| key.node_id == node_id);
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
        self.remove_flows_where(|_, flow| {
            flow.gateway_id == gateway_id && flow.device_public_key == device_public_key
        })
    }

    /// Refreshes every currently-admitted flow's remembered port rules (its endpoints before TT-2514)
    /// for one gateway to this heartbeat's freshly-applied configuration (TT-2046 review finding
    /// #4): they are
    /// otherwise only ever snapshotted once, at `admit` time, so an admin repointing or removing an
    /// endpoint on a gateway with an open flow was silently ignored - `forward_target` kept using
    /// the stale list - for as long as that flow stayed open. Mirrors `main::
    /// reconcile_dropped_entitlements`'s per-heartbeat refresh, but for endpoint config rather than
    /// entitlement: a flow that's still entitled keeps forwarding, just against whatever the
    /// gateway is configured to expose *now*, not what it exposed when the flow was admitted. A
    /// no-op for a gateway with no currently-admitted flow, or one whose endpoint list didn't
    /// change - both normal, expected cases, not something to log.
    pub fn update_rules(&mut self, gateway_id: &str, rules: &[PortRule]) {
        self.gateway_rules
            .insert(gateway_id.to_string(), rules.to_vec());
        for flow in self.flows.values_mut() {
            if flow.gateway_id == gateway_id {
                flow.rules = rules.to_vec();
            }
        }
    }

    /// The gateway's port rules as the latest heartbeat applied them, if one has - see
    /// `gateway_rules`.
    pub fn current_rules(&self, gateway_id: &str) -> Option<&[PortRule]> {
        self.gateway_rules.get(gateway_id).map(Vec::as_slice)
    }

    /// Forgets the rules of gateways the latest heartbeat no longer lists.
    pub fn retain_gateway_rules(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.gateway_rules.retain(|gateway_id, _| keep(gateway_id));
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
            .get(&FlowKey::new(node_id, port, None))
            .map(|flow| flow.gateway_id.as_str())
    }

    /// Decides how one decrypted packet from `node_id` is forwarded (TT-1732 review, Tasneem finding
    /// #1; TT-2046; TT-2639): `dialled` is the packet's own identity when it can be read - its
    /// transport, its destination address (the gateway it was addressed to) and `destination_port`.
    ///
    /// 1. A flow admitted with exactly that identity: forwarded to its rule's internal address and
    ///    port with its
    ///    allocated source port (allocated on the first packet, or moved if the internal address
    ///    changed), so a packet addressed to one gateway can never match another gateway's flow.
    /// 2. Otherwise a flow admitted on `(node_id, port)` without an identity - only if the
    ///    transition rule allows it (`legacy_flow_accepts`): on an updated node it must have been
    ///    first seen with this packet's gateway address. Forwarded with the source port unchanged,
    ///    and the gateway address recorded for its replies - by a rule with equal ports only, since
    ///    its replies never get a port back (TT-2514).
    /// 3. Otherwise `NotAdmitted`: the caller holds the packet briefly for its own admission.
    ///
    /// The rule is matched by transport and `destination_port` and resolved via `dns_cache` - see
    /// `resolve_rule`.
    pub fn forward(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Option<Dialled>,
        destination_port: u16,
        dns_cache: &crate::dns_cache::DnsCache,
    ) -> Forwarding {
        if let Some(packet_dialled) = dialled {
            let key = FlowKey::new(node_id, port, Some(packet_dialled));
            if self.flows.contains_key(&key) {
                return self.forward_with_identity(key, packet_dialled, dns_cache);
            }
            if !self.legacy_flow_accepts(node_id, port, packet_dialled.gateway_address) {
                return Forwarding::NotAdmitted;
            }
        }
        let Some(flow) = self.flows.get_mut(&FlowKey::new(node_id, port, None)) else {
            return Forwarding::NotAdmitted;
        };
        let transport = dialled.map(|packet_dialled| packet_dialled.transport);
        match resolve_rule(&flow.rules, transport, destination_port, dns_cache) {
            // Its replies are only given the gateway address back, never a port (TT-2639), so a
            // rule that translates the port can't serve it (TT-2514).
            Ok((_, internal_port)) if internal_port != destination_port => {
                Forwarding::Refused(ForwardOutcome::PortTranslationNeedsUpdatedNode)
            }
            Ok((address, _)) => {
                if let Some(packet_dialled) = dialled {
                    flow.virtual_address = Some(packet_dialled.gateway_address);
                }
                Forwarding::Forward {
                    address,
                    destination_port: None,
                    source_port: None,
                }
            }
            Err(refused) => Forwarding::Refused(refused),
        }
    }

    /// `forward` for a flow admitted with its dialled identity: resolves its rule's internal address
    /// and port and returns the source port its packets carry there, allocating one - unique among
    /// this Connector's flows to that internal host:port on that transport - on the first packet or
    /// once the internal address or port has changed (a rule update or a new DNS answer), freeing any
    /// previous one.
    fn forward_with_identity(
        &mut self,
        key: FlowKey,
        dialled: Dialled,
        dns_cache: &crate::dns_cache::DnsCache,
    ) -> Forwarding {
        let Some(flow) = self.flows.get_mut(&key) else {
            return Forwarding::NotAdmitted;
        };
        let (address, internal_port) = match resolve_rule(
            &flow.rules,
            Some(dialled.transport),
            dialled.destination_port,
            dns_cache,
        ) {
            Ok(resolved) => resolved,
            Err(refused) => return Forwarding::Refused(refused),
        };
        // The source port is unique per internal host:port (TT-2639) - the rule's internal port,
        // which a reply comes from, not the dialled one (TT-2514).
        let target = (address, internal_port);
        let destination_port = (internal_port != dialled.destination_port).then_some(internal_port);
        if let Some(allocation) = flow.allocation
            && allocation.target == target
        {
            return Forwarding::Forward {
                address,
                destination_port,
                source_port: Some(allocation.port),
            };
        }
        let transport = dialled.transport;
        if let Some(Allocation {
            target: old,
            port: old_port,
        }) = flow.allocation.take()
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
            return Forwarding::Refused(ForwardOutcome::NoFreeSourcePort);
        };
        flow.allocation = Some(Allocation {
            target,
            port: source_port,
        });
        self.dialled_by_allocation
            .insert((transport, target.0, target.1, source_port), key);
        Forwarding::Forward {
            address,
            destination_port,
            source_port: Some(source_port),
        }
    }

    /// The next free source port toward `target` on `transport`, searching on from the last one
    /// handed out there. A field-level function so it can run while one flow is borrowed.
    fn allocate_source_port(
        allocations: &HashMap<(Transport, Ipv4Addr, u16, u16), FlowKey>,
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

    /// TT-2639: whether a packet to `destination` may use the flow admitted on `(node_id, port)`
    /// without a dialled identity, once no flow matched its full identity. Such a flow, from before
    /// its node was updated, says nothing about which gateway it is for except the address its first
    /// packet carried: only a packet to that same address may use it. Before any address is known, a
    /// packet from an updated node is refused - it may be another gateway's first packet, and using
    /// the flow would also record that gateway's address on it - while one from a node not yet updated
    /// is accepted and its address recorded, as before (spec §B.8, Compatibility). `true` when there is
    /// no such flow: `forward` then reports it as not admitted.
    fn legacy_flow_accepts(&self, node_id: &str, port: u16, destination: Ipv4Addr) -> bool {
        match self.flows.get(&FlowKey::new(node_id, port, None)) {
            None => true,
            Some(flow) => match flow.virtual_address {
                Some(address) => address == destination,
                None => !self.dialled_nodes.contains(node_id),
            },
        }
    }

    /// Decides where one packet read from the TUN device (a reply from an internal endpoint, or a
    /// packet of the control channel) goes, from its transport, source address and source port when
    /// they can be read and its `destination_port` - in this order:
    ///
    /// 1. TT-2639: a reply on a flow admitted with its dialled identity - matched on its transport,
    ///    its destination port (the source port allocated to that flow) and its source, which must be
    ///    exactly the internal address and port that flow was forwarded to. It can only match the one
    ///    flow it belongs to, never a control-channel connection (those come from this Connector's own
    ///    address, never an internal service's). Restores what the client dialled as the source and
    ///    the translated port the node knows the flow by as the destination port.
    /// 2. TT-2144: this Connector's OWN outbound connection to Gatekeeper's tunnel address (the
    ///    admission poller's poll/admission-result calls) - matched on the packet's own *source* port,
    ///    never its destination (Gatekeeper's fixed HTTP port, identical across every node). It
    ///    already carries this Connector's real address, so it goes unchanged. TT-2297: before the
    ///    destination-port lookup below - the source port was registered before the connection's
    ///    first packet and belongs to exactly one connection.
    /// 3. TT-2102: a reply on a connection Gatekeeper opened to this Connector's own control-plane
    ///    address - forwarded unchanged on the way in, so unchanged on the way back.
    /// 4. A flow admitted without a dialled identity: the node holding `destination_port` (the
    ///    translated port), if exactly one does (TT-1847), with the gateway address its packets were
    ///    seen with restored as the source (TT-2046 review finding #1).
    pub fn route_reply(
        &self,
        transport: Option<Transport>,
        source: Option<Ipv4Addr>,
        source_port: Option<u16>,
        destination_port: u16,
    ) -> Result<ReplyRoute, ReplyMiss> {
        if let (Some(transport), Some(source), Some(source_port)) = (transport, source, source_port)
            && let Some(key) =
                self.dialled_by_allocation
                    .get(&(transport, source, source_port, destination_port))
            && let Some(dialled) = key.dialled
            && self.flows.contains_key(key)
        {
            return Ok(ReplyRoute::Restore {
                node_id: key.node_id.clone(),
                source: dialled.gateway_address,
                source_port: Some(dialled.destination_port),
                destination_port: Some(key.port),
            });
        }
        if let Some(source_port) = source_port
            && let Some(node_id) = self.node_for_outbound_control_channel_source_port(source_port)
        {
            return Ok(ReplyRoute::Unchanged {
                node_id: node_id.to_string(),
            });
        }
        if let Some(node_id) = self.node_for_control_channel_port(destination_port) {
            return Ok(ReplyRoute::Unchanged {
                node_id: node_id.to_string(),
            });
        }
        let node_id = self
            .node_for_port(destination_port)
            .ok_or(ReplyMiss::NoFlow)?
            .to_string();
        match self
            .flows
            .get(&FlowKey::new(&node_id, destination_port, None))
            .and_then(|flow| flow.virtual_address)
        {
            Some(source) => Ok(ReplyRoute::Restore {
                node_id,
                source,
                source_port: None,
                destination_port: None,
            }),
            None => Err(ReplyMiss::NoAddressYet { node_id }),
        }
    }

    /// Buffers one decrypted packet that hit `ForwardOutcome::NotAdmitted`, in case its own
    /// flow's admission decision is already in flight and arrives within `PENDING_PACKET_TTL`
    /// (see that constant's doc for why this race exists and why it's worth rescuing). Held under the key
    /// the packet itself gives - with its dialled identity when it can be read (TT-2639). Overwrites
    /// any previously-buffered packet for the same key - only the latest matters.
    ///
    /// Also opportunistically sweeps every *other* entry past its own TTL, so a packet whose flow
    /// is ultimately refused (or never decided at all) doesn't linger here forever - there's no
    /// separate release/expiry signal for a pending packet the way there is for an admitted flow,
    /// so this is the only place that cleanup can happen without a dedicated background sweep.
    pub fn buffer_pending(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Option<Dialled>,
        packet: Vec<u8>,
        now: Instant,
    ) {
        self.pending_packets
            .retain(|_, (_, buffered_at)| now.duration_since(*buffered_at) <= PENDING_PACKET_TTL);
        let key = FlowKey::new(node_id, port, dialled);
        if self.pending_packets.len() >= MAX_PENDING_PACKETS
            && !self.pending_packets.contains_key(&key)
        {
            return;
        }
        self.pending_packets.insert(key, (packet, now));
    }

    /// Reclaims a packet `buffer_pending` held for a flow just admitted, if one exists and is still
    /// within `PENDING_PACKET_TTL` - so the caller can push it through the normal forwarding path
    /// instead of leaving it lost. A flow admitted with its dialled identity reclaims only the packet
    /// held under exactly that identity (TT-2639); one admitted without it, by a node that predates
    /// the identity, reclaims the packet held for its node and port, whatever identity was read from
    /// it. Removes the entry either way, so this can't return the same packet twice.
    pub fn take_pending(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Option<Dialled>,
        now: Instant,
    ) -> Option<Vec<u8>> {
        let key = match dialled {
            Some(_) => FlowKey::new(node_id, port, dialled),
            None => {
                let exact = FlowKey::new(node_id, port, None);
                if self.pending_packets.contains_key(&exact) {
                    exact
                } else {
                    self.pending_packets
                        .keys()
                        .find(|key| key.node_id == node_id && key.port == port)
                        .cloned()?
                }
            }
        };
        let (packet, buffered_at) = self.pending_packets.remove(&key)?;
        (now.duration_since(buffered_at) <= PENDING_PACKET_TTL).then_some(packet)
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
    fn node_for_port(&self, port: u16) -> Option<&str> {
        let nodes = self.nodes_by_port.get(&port)?;
        if nodes.len() != 1 {
            return None;
        }
        nodes.iter().next().map(String::as_str)
    }
}

/// The entry points the tests were written against before TT-2639 merged the two flow tables - thin
/// wrappers over the single mechanism above, so the same tests keep checking unchanged behaviour.
#[cfg(test)]
impl FlowTable {
    pub fn update_endpoints(&mut self, gateway_id: &str, endpoints: &[PolicyBundleEndpoint]) {
        let rules: Vec<PortRule> = endpoints.iter().map(PortRule::from).collect();
        self.update_rules(gateway_id, &rules);
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
        self.admit_flow(
            node_id,
            port,
            None,
            gateway_id,
            flow_id,
            device_public_key,
            endpoints.iter().map(PortRule::from).collect(),
        );
    }

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
        self.admit_flow(
            node_id,
            port,
            Some(dialled),
            gateway_id,
            flow_id,
            device_public_key,
            endpoints.iter().map(PortRule::from).collect(),
        );
    }

    /// For a flow admitted without a dialled identity: resolves the real internal address a forwarded packet should be
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
        let Some(flow) = self.flows.get(&FlowKey::new(node_id, port, None)) else {
            return ForwardOutcome::NotAdmitted;
        };
        match resolve_rule(&flow.rules, None, packet_destination_port, dns_cache) {
            Ok((address, _)) => ForwardOutcome::Forward(address),
            Err(refused) => refused,
        }
    }

    /// `forward` for exactly a flow admitted with this dialled identity; `None` if there is none.
    pub fn dialled_forward_target(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Dialled,
        dns_cache: &crate::dns_cache::DnsCache,
    ) -> Option<DialledForward> {
        let key = FlowKey::new(node_id, port, Some(dialled));
        if !self.flows.contains_key(&key) {
            return None;
        }
        Some(match self.forward_with_identity(key, dialled, dns_cache) {
            Forwarding::Forward {
                address,
                source_port: Some(source_port),
                ..
            } => DialledForward::Forward {
                address,
                source_port,
            },
            Forwarding::Refused(outcome) => DialledForward::Refused(outcome),
            other => panic!("a flow with an identity always has a source port: {other:?}"),
        })
    }

    /// `route_reply`'s first step alone: a reply on a flow admitted with its dialled identity.
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
        let dialled = key.dialled?;
        self.flows.get(key)?;
        Some(DialledReply {
            node_id: key.node_id.clone(),
            gateway_address: dialled.gateway_address,
            destination_port: dialled.destination_port,
            translated_port: key.port,
        })
    }

    pub fn buffer_pending_packet(
        &mut self,
        node_id: &str,
        port: u16,
        packet: Vec<u8>,
        now: Instant,
    ) {
        self.buffer_pending(node_id, port, None, packet, now);
    }

    pub fn buffer_pending_dialled_packet(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Dialled,
        packet: Vec<u8>,
        now: Instant,
    ) {
        self.buffer_pending(node_id, port, Some(dialled), packet, now);
    }

    pub fn take_pending_packet(
        &mut self,
        node_id: &str,
        port: u16,
        now: Instant,
    ) -> Option<Vec<u8>> {
        self.take_pending(node_id, port, None, now)
    }

    pub fn take_pending_dialled_packet(
        &mut self,
        node_id: &str,
        port: u16,
        dialled: Dialled,
        now: Instant,
    ) -> Option<Vec<u8>> {
        self.take_pending(node_id, port, Some(dialled), now)
    }

    /// Sets the gateway address a flow without a dialled identity was seen with - what `forward`
    /// records from its first packet.
    pub fn record_virtual_address(&mut self, node_id: &str, port: u16, virtual_address: Ipv4Addr) {
        if let Some(flow) = self.flows.get_mut(&FlowKey::new(node_id, port, None)) {
            flow.virtual_address = Some(virtual_address);
        }
    }

    pub fn virtual_address_for(&self, node_id: &str, port: u16) -> Option<Ipv4Addr> {
        self.flows
            .get(&FlowKey::new(node_id, port, None))?
            .virtual_address
    }
}

/// Whether a rule opens `transport`; an unknown transport - a packet whose transport could not be
/// read - is only covered by a rule opening both.
fn rule_opens(rule: &RuleTransport, transport: Option<Transport>) -> bool {
    matches!(
        (rule, transport),
        (RuleTransport::TcpUdp, _)
            | (RuleTransport::Tcp, Some(Transport::Tcp))
            | (RuleTransport::Udp, Some(Transport::Udp))
    )
}

/// The one rule serving `transport` to `destination_port`, or `None` when no rule or more than one
/// matches - what `resolve_rule` forwards by, before resolving its host. Used to name a flow's rule
/// in the logs at admission (TT-2514).
pub fn matching_rule(
    rules: &[PortRule],
    transport: Option<Transport>,
    destination_port: u16,
) -> Option<&PortRule> {
    let mut matching = rules.iter().filter(|rule| {
        rule.external_port == destination_port && rule_opens(&rule.transport, transport)
    });
    match (matching.next(), matching.next()) {
        (Some(rule), None) => Some(rule),
        _ => None,
    }
}

/// The rule a packet on `transport` to `destination_port` is served by, resolved to its internal
/// address and port (TT-2514; endpoints matched by port alone before that, TT-2046). Matched by
/// transport and the dialled port, never by the packet's destination address, which on arrival is
/// the gateway address, not anything internal. Portal allows one rule per transport and external
/// port; if a bundle still carries two that both match, that's `AmbiguousEndpoint` - refused, never
/// guessed (TT-2046 review finding #3). The internal host is resolved via `dns_cache` (TT-2066) -
/// a literal IPv4 resolves to itself, a hostname to its last successful lookup, otherwise
/// `HostUnresolved`.
fn resolve_rule(
    rules: &[PortRule],
    transport: Option<Transport>,
    destination_port: u16,
    dns_cache: &crate::dns_cache::DnsCache,
) -> Result<(Ipv4Addr, u16), ForwardOutcome> {
    let matching: Vec<&PortRule> = rules
        .iter()
        .filter(|rule| {
            rule.external_port == destination_port && rule_opens(&rule.transport, transport)
        })
        .collect();
    match matching.as_slice() {
        [] => Err(ForwardOutcome::PortNotConfigured),
        [rule] => dns_cache
            .resolve(&rule.internal_host)
            .map(|address| (address, rule.internal_port))
            .ok_or(ForwardOutcome::HostUnresolved),
        _ => Err(ForwardOutcome::AmbiguousEndpoint),
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

    // --- TT-2514: port rules - selected by transport and dialled port, port rewritten ---

    fn rule(
        transport: RuleTransport,
        external_port: u16,
        host: Ipv4Addr,
        internal_port: u16,
    ) -> PortRule {
        PortRule {
            transport,
            external_port,
            internal_host: host.to_string(),
            internal_port,
        }
    }

    fn admit_with_rules(
        table: &mut FlowTable,
        port: u16,
        dialled: Option<Dialled>,
        rules: Vec<PortRule>,
    ) {
        table.admit_flow(
            "n-1".to_string(),
            port,
            dialled,
            "gw-erp".to_string(),
            format!("flow-{port}"),
            "dev-1".to_string(),
            rules,
        );
    }

    fn forward_packet(table: &mut FlowTable, port: u16, dialled: Dialled) -> Forwarding {
        table.forward(
            "n-1",
            port,
            Some(dialled),
            dialled.destination_port,
            &crate::dns_cache::DnsCache::new(),
        )
    }

    #[test]
    fn a_translated_rule_forwards_to_its_internal_port_and_a_reply_gets_the_dialled_port_back() {
        let mut table = FlowTable::new();
        let https = dialled(Transport::Tcp, ERP, 443);
        admit_with_rules(
            &mut table,
            40100,
            Some(https),
            vec![rule(RuleTransport::Tcp, 443, ERP_HOST, 8443)],
        );

        let Forwarding::Forward {
            address,
            destination_port,
            source_port: Some(source_port),
        } = forward_packet(&mut table, 40100, https)
        else {
            panic!("expected a forward");
        };

        assert_eq!(address, ERP_HOST);
        assert_eq!(destination_port, Some(8443));
        // The reply comes from the internal port, and goes back as the dialled one.
        assert_eq!(
            table.route_reply(
                Some(Transport::Tcp),
                Some(ERP_HOST),
                Some(8443),
                source_port
            ),
            Ok(ReplyRoute::Restore {
                node_id: "n-1".to_string(),
                source: ERP,
                source_port: Some(443),
                destination_port: Some(40100),
            })
        );
        assert_eq!(
            table.route_reply(Some(Transport::Tcp), Some(ERP_HOST), Some(443), source_port),
            Err(ReplyMiss::NoFlow),
            "a reply from the dialled port is not from the rule's service"
        );
    }

    #[test]
    fn a_rule_with_equal_ports_does_not_rewrite_the_port() {
        let mut table = FlowTable::new();
        let to = dialled(Transport::Udp, ERP, 514);
        admit_with_rules(
            &mut table,
            40100,
            Some(to),
            vec![rule(RuleTransport::TcpUdp, 514, ERP_HOST, 514)],
        );

        assert!(matches!(
            forward_packet(&mut table, 40100, to),
            Forwarding::Forward {
                address: ERP_HOST,
                destination_port: None,
                source_port: Some(_)
            }
        ));
    }

    #[test]
    fn a_rule_only_serves_the_transports_it_opens() {
        let rules = vec![
            rule(RuleTransport::Tcp, 22, ERP_HOST, 22),
            rule(RuleTransport::Udp, 514, FIN_HOST, 514),
        ];
        let cases = [
            (Transport::Tcp, 22, true),
            (Transport::Udp, 22, false),
            (Transport::Udp, 514, true),
            (Transport::Tcp, 514, false),
        ];
        for (index, (transport, port, forwarded)) in cases.into_iter().enumerate() {
            let mut table = FlowTable::new();
            let to = dialled(transport, ERP, port);
            admit_with_rules(&mut table, 40100 + index as u16, Some(to), rules.clone());

            let outcome = forward_packet(&mut table, 40100 + index as u16, to);

            if forwarded {
                assert!(
                    matches!(outcome, Forwarding::Forward { .. }),
                    "{transport:?} {port}: {outcome:?}"
                );
            } else {
                assert_eq!(
                    outcome,
                    Forwarding::Refused(ForwardOutcome::PortNotConfigured),
                    "{transport:?} {port}"
                );
            }
        }
    }

    #[test]
    fn two_rules_of_one_gateway_lead_to_their_own_hosts_and_ports() {
        let mut table = FlowTable::new();
        let rules = vec![
            rule(RuleTransport::Tcp, 443, ERP_HOST, 8443),
            rule(RuleTransport::Tcp, 2222, FIN_HOST, 22),
        ];
        let web = dialled(Transport::Tcp, ERP, 443);
        let ssh = dialled(Transport::Tcp, ERP, 2222);
        admit_with_rules(&mut table, 40100, Some(web), rules.clone());
        admit_with_rules(&mut table, 40101, Some(ssh), rules);

        assert!(matches!(
            forward_packet(&mut table, 40100, web),
            Forwarding::Forward {
                address: ERP_HOST,
                destination_port: Some(8443),
                ..
            }
        ));
        assert!(matches!(
            forward_packet(&mut table, 40101, ssh),
            Forwarding::Forward {
                address: FIN_HOST,
                destination_port: Some(22),
                ..
            }
        ));
    }

    #[test]
    fn rules_that_both_match_are_refused_rather_than_guessed() {
        let mut table = FlowTable::new();
        let rules = vec![
            rule(RuleTransport::Tcp, 443, ERP_HOST, 443),
            rule(RuleTransport::TcpUdp, 443, FIN_HOST, 443),
        ];
        let tcp = dialled(Transport::Tcp, ERP, 443);
        let udp = dialled(Transport::Udp, ERP, 443);
        admit_with_rules(&mut table, 40100, Some(tcp), rules.clone());
        admit_with_rules(&mut table, 40101, Some(udp), rules);

        assert_eq!(
            forward_packet(&mut table, 40100, tcp),
            Forwarding::Refused(ForwardOutcome::AmbiguousEndpoint)
        );
        // Only the TCP + UDP rule opens UDP, so that one is not ambiguous.
        assert!(matches!(
            forward_packet(&mut table, 40101, udp),
            Forwarding::Forward {
                address: FIN_HOST,
                ..
            }
        ));
    }

    #[test]
    fn a_rule_with_a_transport_this_connector_does_not_know_matches_nothing() {
        let mut table = FlowTable::new();
        let to = dialled(Transport::Tcp, ERP, 443);
        admit_with_rules(
            &mut table,
            40100,
            Some(to),
            vec![rule(
                RuleTransport::Unknown("SCTP".to_string()),
                443,
                ERP_HOST,
                443,
            )],
        );

        assert_eq!(
            forward_packet(&mut table, 40100, to),
            Forwarding::Refused(ForwardOutcome::PortNotConfigured)
        );
    }

    /// A flow from a node that predates the dialled identity gets only the gateway address back on
    /// its replies, never a port - so it is served by rules with equal ports only.
    #[test]
    fn a_flow_without_a_dialled_identity_is_served_only_by_rules_with_equal_ports() {
        let mut table = FlowTable::new();
        admit_with_rules(
            &mut table,
            40100,
            None,
            vec![
                rule(RuleTransport::Tcp, 443, ERP_HOST, 8443),
                rule(RuleTransport::Tcp, 22, ERP_HOST, 22),
            ],
        );

        assert_eq!(
            forward_packet(&mut table, 40100, dialled(Transport::Tcp, ERP, 443)),
            Forwarding::Refused(ForwardOutcome::PortTranslationNeedsUpdatedNode)
        );
        assert_eq!(
            forward_packet(&mut table, 40100, dialled(Transport::Tcp, ERP, 22)),
            Forwarding::Forward {
                address: ERP_HOST,
                destination_port: None,
                source_port: None,
            }
        );
    }

    /// A rule change on the next heartbeat reaches an already admitted flow: its packets go to the
    /// new internal port, with a source port allocated toward that port, and replies follow.
    #[test]
    fn a_rule_change_moves_an_admitted_flow_to_the_new_internal_port() {
        let mut table = FlowTable::new();
        let https = dialled(Transport::Tcp, ERP, 443);
        admit_with_rules(
            &mut table,
            40100,
            Some(https),
            vec![rule(RuleTransport::Tcp, 443, ERP_HOST, 8443)],
        );
        let Forwarding::Forward {
            source_port: Some(before),
            ..
        } = forward_packet(&mut table, 40100, https)
        else {
            panic!("expected a forward");
        };

        table.update_rules("gw-erp", &[rule(RuleTransport::Tcp, 443, ERP_HOST, 9443)]);
        let Forwarding::Forward {
            destination_port: Some(9443),
            source_port: Some(after),
            ..
        } = forward_packet(&mut table, 40100, https)
        else {
            panic!("expected a forward to 9443");
        };

        assert!(
            table
                .route_reply(Some(Transport::Tcp), Some(ERP_HOST), Some(9443), after)
                .is_ok()
        );
        assert_eq!(
            table.route_reply(Some(Transport::Tcp), Some(ERP_HOST), Some(8443), before),
            Err(ReplyMiss::NoFlow),
            "the old allocation toward 8443 is freed"
        );

        table.update_rules("gw-erp", &[]);
        assert_eq!(
            forward_packet(&mut table, 40100, https),
            Forwarding::Refused(ForwardOutcome::PortNotConfigured)
        );
    }

    /// GW-INV-8 with translated ports: two gateways on one Connector, both with a TCP 443 rule to
    /// different internal services, dialled from the same node and translated port, stay apart.
    #[test]
    fn two_gateways_with_translated_rules_on_one_port_stay_apart() {
        let mut table = FlowTable::new();
        let erp = dialled(Transport::Tcp, ERP, 443);
        let fin = dialled(Transport::Tcp, FIN, 443);
        table.admit_flow(
            "n-1".to_string(),
            40100,
            Some(erp),
            "gw-erp".to_string(),
            "flow-erp".to_string(),
            "dev-1".to_string(),
            vec![rule(RuleTransport::Tcp, 443, ERP_HOST, 8443)],
        );
        table.admit_flow(
            "n-1".to_string(),
            40100,
            Some(fin),
            "gw-fin".to_string(),
            "flow-fin".to_string(),
            "dev-2".to_string(),
            vec![rule(RuleTransport::Tcp, 443, FIN_HOST, 9443)],
        );

        let Forwarding::Forward {
            address: erp_host,
            destination_port: Some(8443),
            source_port: Some(erp_port),
        } = forward_packet(&mut table, 40100, erp)
        else {
            panic!("expected ERP forward");
        };
        let Forwarding::Forward {
            address: fin_host,
            destination_port: Some(9443),
            source_port: Some(fin_port),
        } = forward_packet(&mut table, 40100, fin)
        else {
            panic!("expected FIN forward");
        };

        assert_eq!((erp_host, fin_host), (ERP_HOST, FIN_HOST));
        assert!(matches!(
            table.route_reply(Some(Transport::Tcp), Some(ERP_HOST), Some(8443), erp_port),
            Ok(ReplyRoute::Restore {
                source: ERP,
                source_port: Some(443),
                ..
            })
        ));
        assert!(matches!(
            table.route_reply(Some(Transport::Tcp), Some(FIN_HOST), Some(9443), fin_port),
            Ok(ReplyRoute::Restore {
                source: FIN,
                source_port: Some(443),
                ..
            })
        ));
    }

    #[test]
    fn matching_rule_names_the_one_rule_a_flow_uses_and_nothing_when_none_or_two_match() {
        let rules = vec![
            rule(RuleTransport::Tcp, 443, ERP_HOST, 8443),
            rule(RuleTransport::TcpUdp, 53, ERP_HOST, 53),
            rule(RuleTransport::Udp, 53, FIN_HOST, 53),
        ];

        assert_eq!(
            matching_rule(&rules, Some(Transport::Tcp), 443).map(ToString::to_string),
            Some("TCP 443 -> 172.31.4.176:8443".to_string())
        );
        assert_eq!(matching_rule(&rules, Some(Transport::Udp), 443), None);
        assert_eq!(
            matching_rule(&rules, Some(Transport::Udp), 53),
            None,
            "two rules open UDP 53"
        );
        assert_eq!(
            matching_rule(&rules, Some(Transport::Tcp), 53).map(ToString::to_string),
            Some("TCP+UDP 53 -> 172.31.4.176:53".to_string())
        );
    }

    /// A gateway's address may be the internal service's own address (TT-2529 lets Portal assign
    /// one): forwarding and the reply still work, with only the port translated.
    #[test]
    fn a_gateway_whose_address_is_the_internal_host_is_relayed_both_ways() {
        let mut table = FlowTable::new();
        let to = dialled(Transport::Tcp, ERP_HOST, 443);
        admit_with_rules(
            &mut table,
            40100,
            Some(to),
            vec![rule(RuleTransport::Tcp, 443, ERP_HOST, 8443)],
        );

        let Forwarding::Forward {
            address: ERP_HOST,
            destination_port: Some(8443),
            source_port: Some(allocated),
        } = forward_packet(&mut table, 40100, to)
        else {
            panic!("expected a forward to the same address on the internal port");
        };
        assert_eq!(
            table.route_reply(Some(Transport::Tcp), Some(ERP_HOST), Some(8443), allocated),
            Ok(ReplyRoute::Restore {
                node_id: "n-1".to_string(),
                source: ERP_HOST,
                source_port: Some(443),
                destination_port: Some(40100),
            })
        );
    }
}
