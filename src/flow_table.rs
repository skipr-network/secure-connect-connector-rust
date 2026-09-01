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

#[derive(Debug, Clone, PartialEq)]
struct AdmittedFlow {
    gateway_id: String,
    flow_id: String,
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

    pub fn admit(&mut self, node_id: String, port: u16, gateway_id: String, flow_id: String) {
        self.nodes_by_port
            .entry(port)
            .or_default()
            .insert(node_id.clone());
        self.flows.insert(
            (node_id, port),
            AdmittedFlow {
                gateway_id,
                flow_id,
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
    /// treat that as "refuse", never as "admit anyway".
    pub fn gateway_for(&self, node_id: &str, port: u16) -> Option<&str> {
        self.flows
            .get(&(node_id.to_string(), port))
            .map(|flow| flow.gateway_id.as_str())
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
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
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
        );
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
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
        );
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
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
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
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
        );
        table.admit(
            "n-1".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
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
        );
        table.admit(
            "n-2".to_string(),
            40002,
            "gw-1".to_string(),
            "flow-2".to_string(),
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
        );
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
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
        );

        table.release("flow-1");
        table.admit(
            "n-2".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
        );

        assert_eq!(table.node_for_port(40001), Some("n-2"));
    }

    #[test]
    fn re_admitting_the_same_node_and_port_replaces_the_previous_flow() {
        let mut table = FlowTable::new();
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
        );

        // The port is reused for a new flow (e.g. after the first was
        // released and Gatekeeper reassigned the same translated port).
        table.admit(
            "n-1".to_string(),
            40001,
            "gw-2".to_string(),
            "flow-2".to_string(),
        );

        assert_eq!(table.gateway_for("n-1", 40001), Some("gw-2"));
    }
}
