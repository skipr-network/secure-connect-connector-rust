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

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::dto::PolicyBundleEndpoint;

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
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
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
}
