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

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
struct AdmittedFlow {
    gateway_id: String,
    flow_id: String,
}

#[derive(Default)]
pub struct FlowTable {
    flows: HashMap<(String, u16), AdmittedFlow>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn admit(&mut self, node_id: String, port: u16, gateway_id: String, flow_id: String) {
        self.flows.insert(
            (node_id, port),
            AdmittedFlow {
                gateway_id,
                flow_id,
            },
        );
    }

    pub fn release(&mut self, flow_id: &str) {
        self.flows.retain(|_, flow| flow.flow_id != flow_id);
    }

    /// The gateway this (node_id, port) pair is currently admitted for, or
    /// `None` if there's no matching admitted flow at all - callers must
    /// treat that as "refuse", never as "admit anyway".
    pub fn gateway_for(&self, node_id: &str, port: u16) -> Option<&str> {
        self.flows
            .get(&(node_id.to_string(), port))
            .map(|flow| flow.gateway_id.as_str())
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
