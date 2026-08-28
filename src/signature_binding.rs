//! Guards flow-admission signatures against cross-gateway replay (TT-1732
//! review, Tasneem: "admission signatures aren't bound to flow_id/gateway_id
//! /node_id/port, and there's no nonce/freshness check; a captured signature
//! is replayable across flows and gateways").
//!
//! **Why this can't bind to flow_id/node_id/port**: those fields aren't
//! signed by the user's client at all - `signed_data` is material the
//! client signs once "when establishing its Gatekeeper session" (spec
//! §B.8), a different, not-yet-built component this Connector<->Gatekeeper
//! contract doesn't control the content of. The Connector can't require a
//! specific format for bytes it doesn't define. What it *can* do without
//! renegotiating that external contract: track which gateway_id a given
//! (user_public_key, signature) pair was first used for, and refuse it for
//! any other gateway_id - a session-bound signature legitimately admitting
//! several flows to the *same* gateway within one session stays allowed
//! (the spec's own model), but a captured signature can no longer be
//! replayed to reach a gateway it was never presented for.
//!
//! Bounded by a TTL so this in-memory table doesn't grow unboundedly over
//! the Connector's long-running lifetime - old bindings age out and (if
//! genuinely reused after that) are treated as first-use again, same as any
//! session-based nonce scheme's practical trade-off between memory and an
//! unbounded window.

use std::collections::HashMap;
use std::time::{Duration, Instant};

const BINDING_TTL: Duration = Duration::from_secs(600);

pub struct SignatureBindingGuard {
    bindings: HashMap<(String, String), (String, Instant)>,
}

impl SignatureBindingGuard {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    /// Returns `true` if this (user_public_key, signature) pair is being
    /// presented for the first time, or has only ever been presented for
    /// this same `gateway_id` - `false` if it's already bound to a
    /// *different* `gateway_id` (a cross-gateway replay attempt).
    pub fn check_and_bind(
        &mut self,
        user_public_key: &str,
        signature: &str,
        gateway_id: &str,
    ) -> bool {
        self.prune_expired();

        let key = (user_public_key.to_string(), signature.to_string());
        match self.bindings.get(&key) {
            Some((bound_gateway, _)) if bound_gateway == gateway_id => true,
            Some(_) => false,
            None => {
                self.bindings
                    .insert(key, (gateway_id.to_string(), Instant::now()));
                true
            }
        }
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.bindings
            .retain(|_, (_, first_seen)| now.duration_since(*first_seen) < BINDING_TTL);
    }
}

impl Default for SignatureBindingGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_seen_for_the_first_time_is_allowed() {
        let mut guard = SignatureBindingGuard::new();

        assert!(guard.check_and_bind("user-key", "sig-1", "gw-1"));
    }

    #[test]
    fn the_same_signature_reused_for_the_same_gateway_is_allowed() {
        let mut guard = SignatureBindingGuard::new();
        guard.check_and_bind("user-key", "sig-1", "gw-1");

        assert!(guard.check_and_bind("user-key", "sig-1", "gw-1"));
    }

    #[test]
    fn the_same_signature_replayed_for_a_different_gateway_is_refused() {
        let mut guard = SignatureBindingGuard::new();
        guard.check_and_bind("user-key", "sig-1", "gw-1");

        assert!(!guard.check_and_bind("user-key", "sig-1", "gw-2"));
    }

    #[test]
    fn different_signatures_from_the_same_user_are_tracked_independently() {
        let mut guard = SignatureBindingGuard::new();
        guard.check_and_bind("user-key", "sig-1", "gw-1");

        assert!(guard.check_and_bind("user-key", "sig-2", "gw-2"));
    }

    #[test]
    fn the_same_signature_string_from_different_users_is_tracked_independently() {
        // Different users could coincidentally craft the same signature
        // string only with astronomically low probability, but the key must
        // still include user_public_key for correctness, not just signature.
        let mut guard = SignatureBindingGuard::new();
        guard.check_and_bind("user-key-a", "sig-1", "gw-1");

        assert!(guard.check_and_bind("user-key-b", "sig-1", "gw-2"));
    }
}
