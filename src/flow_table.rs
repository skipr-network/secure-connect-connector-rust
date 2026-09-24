//! Tracks currently-admitted flows so the real packet-forwarding loops
//! (`main`) can gate on them (TT-1732 review, Tasneem, finding #1 - "the
//! sharpest gap"): access decisions from `access.rs`/`flow_control.rs` were
//! never consulted by the actual forwarding loops, which routed purely by
//! learned IP with no entitlement check at all - a refused, or never
//! checked, device's traffic could still be forwarded once its IP was
//! observed once on the wire.
//!
//! A flow is identified by `(node_id, port)` per spec §B.8
//! ("Many-users-to-one-Connector is distinguished by translated source
//! port"). Release only ever carries `flow_id` (the agreed
//! `FlowReleaseRequest` schema has no `node_id` field), so entries are also
//! looked up by `flow_id` for removal - a linear scan, not a second index,
//! since the number of concurrently admitted flows on one Connector is
//! bounded by real concurrent user sessions, not internet-scale traffic.
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
/// catch up with the packet that lost the race. 300ms is generous headroom above that measured
/// window without holding a doomed packet meaningfully longer than today's instant drop.
const PENDING_PACKET_TTL: Duration = Duration::from_millis(300);

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
    /// (Gatekeeper's invented per-gateway address) - learned from the first forwarded packet, not
    /// known at admission time (Gatekeeper's admission request carries no such field). Needed to
    /// rewrite a *reply* packet's source back to what the client actually dialed before sending it
    /// back through the tunnel (TT-2046 review finding #1): a real kernel DNAT gets this reversal
    /// for free via conntrack; this rewrite happens in userspace with no conntrack entry to
    /// reverse it automatically, so the Connector has to remember it explicitly. `None` until the
    /// first forwarded packet for this flow has been seen.
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
}

/// How many distinct control-channel connections' worth of routing state to remember at once
/// (see `control_channel_ports`'s doc) - generously above any realistic number of concurrent
/// admission/release calls in flight on one Connector at a time.
const MAX_TRACKED_CONTROL_CHANNEL_PORTS: usize = 256;

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
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

    pub fn release(&mut self, flow_id: &str) {
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
        for flow in self.flows.values_mut() {
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
        let matching: Vec<&PolicyBundleEndpoint> = flow
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.port == packet_destination_port)
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
        self.pending_packets
            .insert((node_id.to_string(), port), (packet, now));
        self.pending_packets
            .retain(|_, (_, buffered_at)| now.duration_since(*buffered_at) <= PENDING_PACKET_TTL);
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
        let (packet, buffered_at) = self.pending_packets.remove(&(node_id.to_string(), port))?;
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
}
