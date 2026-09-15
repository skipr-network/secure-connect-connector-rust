//! Resolves a gateway's configured endpoint host to a real `Ipv4Addr` when it's a DNS hostname
//! rather than a literal IP (TT-2066: Portal's own validation always allowed a hostname there -
//! "real internal networks commonly name hosts without a domain suffix" - but TT-2046 only ever
//! matched a literal IPv4, silently dropping every packet for a hostname-configured gateway with
//! nothing visible to the admin).
//!
//! A hostname is never resolved synchronously in the per-packet forwarding hot path
//! (`flow_table::forward_target`, called under `flow_table`'s own lock on every decrypted
//! packet) - that would mean a DNS round-trip per packet, and a slow/hanging resolver stalling
//! every admitted flow's traffic. Instead, `refresh` re-resolves every currently-configured
//! hostname once per heartbeat cycle (`main::run_heartbeat`, right after a new policy package is
//! applied - it already carries the full, current set of every gateway's endpoints); `resolve`
//! is a plain, synchronous cache read.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

/// Bounds a single hostname's lookup so a hanging/unreachable DNS server can never stall the
/// whole `refresh` call - `refresh` runs synchronously inside `main::run_heartbeat`, so an
/// un-timed lookup would otherwise block that entire heartbeat cycle (policy application, node
/// dialing, entitlement-revocation reconciliation) indefinitely, for every gateway this Connector
/// serves, not just the one with the bad DNS. Generous relative to real DNS latency, short
/// relative to the heartbeat interval (60s default).
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct DnsCache {
    resolved: Mutex<HashMap<String, Ipv4Addr>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hot-path lookup - a literal IPv4 resolves to itself with no lock taken at all (the common
    /// case, "matches every real example seen so far" per TT-2046); a hostname returns whatever
    /// this cache last successfully resolved it to, or `None` if it's never resolved successfully
    /// (not yet refreshed, or DNS has been consistently failing) - callers must treat that the
    /// same as any other "can't forward this" case, never as "forward unchanged".
    pub fn resolve(&self, host: &str) -> Option<Ipv4Addr> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(ip);
        }
        self.resolved
            .lock()
            .expect("dns cache lock poisoned")
            .get(host)
            .copied()
    }

    /// Re-resolves every currently-configured hostname via the real OS resolver. Literal IPs in
    /// `hosts` are ignored - `resolve` already handles those with no cache entry needed.
    pub async fn refresh(&self, hosts: impl IntoIterator<Item = String>) {
        self.refresh_with(hosts, real_lookup).await;
    }

    /// The actual reconciliation logic, generic over the lookup function so tests (including
    /// other modules', e.g. `flow_table`'s) can inject a canned/failing resolver instead of
    /// hitting the real OS resolver (slow and non-hermetic in CI). Production always calls this
    /// via `refresh`, with `real_lookup`.
    pub(crate) async fn refresh_with<F, Fut>(
        &self,
        hosts: impl IntoIterator<Item = String>,
        lookup: F,
    ) where
        F: Fn(String) -> Fut,
        Fut: Future<Output = std::io::Result<Vec<Ipv4Addr>>>,
    {
        let wanted: HashSet<String> = hosts
            .into_iter()
            .filter(|host| host.parse::<Ipv4Addr>().is_err())
            .collect();

        for host in &wanted {
            let Ok(lookup_result) =
                tokio::time::timeout(LOOKUP_TIMEOUT, lookup(host.clone())).await
            else {
                tracing::warn!(
                    host,
                    timeout = ?LOOKUP_TIMEOUT,
                    "DNS resolution timed out - keeping any previously cached value"
                );
                continue;
            };
            match lookup_result {
                Ok(addrs) => match addrs.into_iter().next() {
                    Some(ip) => {
                        self.resolved
                            .lock()
                            .expect("dns cache lock poisoned")
                            .insert(host.clone(), ip);
                        tracing::info!(host, %ip, "resolved endpoint hostname");
                    }
                    None => {
                        // Resolved to something, but no A record - e.g. AAAA-only (v1 scope,
                        // TT-2046, is IPv4 only). Keep whatever was previously cached rather than
                        // evicting it below by leaving `host` out of the insert.
                        tracing::warn!(
                            host,
                            "DNS resolution returned no IPv4 address - keeping any previously cached value"
                        );
                    }
                },
                Err(error) => {
                    // Fails soft, not hard: a transient DNS hiccup must not take a
                    // previously-working, already-cached gateway from "forwarding traffic" to
                    // "every packet dropped" - the stale address is still more useful than none.
                    tracing::warn!(host, %error, "DNS resolution failed - keeping any previously cached value");
                }
            }
        }

        // Prune hostnames no longer configured by any current gateway (edited or removed in
        // Portal) - without this the cache would grow unboundedly over a long-running daemon's
        // life. Never prunes a literal IP - those were never inserted here in the first place.
        self.resolved
            .lock()
            .expect("dns cache lock poisoned")
            .retain(|host, _| wanted.contains(host));
    }
}

async fn real_lookup(host: String) -> std::io::Result<Vec<Ipv4Addr>> {
    // Port 0: lookup_host needs a `ToSocketAddrs`-shaped input, but nothing here ever dials the
    // port it returns - only the resolved address is used.
    let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
    Ok(addrs
        .filter_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn resolve_returns_a_literal_ip_directly_with_no_cache_entry_needed() {
        let cache = DnsCache::new();

        assert_eq!(cache.resolve("10.0.0.5"), Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn resolve_is_none_for_a_hostname_never_refreshed() {
        let cache = DnsCache::new();

        assert_eq!(cache.resolve("crm.internal.example.com"), None);
    }

    #[tokio::test]
    async fn refresh_caches_a_resolved_hostname_so_resolve_finds_it_afterward() {
        let cache = DnsCache::new();

        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[tokio::test]
    async fn refresh_ignores_literal_ips_in_the_host_list() {
        let cache = DnsCache::new();
        let lookups = AtomicUsize::new(0);

        cache
            .refresh_with(["10.0.0.5".to_string()], |_host| {
                lookups.fetch_add(1, Ordering::SeqCst);
                async { Ok(vec![]) }
            })
            .await;

        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refresh_keeps_the_previously_cached_value_when_a_later_lookup_fails() {
        let cache = DnsCache::new();
        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Err(std::io::Error::other("temporary DNS failure"))
            })
            .await;

        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_times_out_a_hanging_lookup_and_keeps_the_previously_cached_value() {
        // A lookup that never resolves must not stall refresh (and, in production, the whole
        // heartbeat cycle) forever - time is paused/auto-advanced here so this test doesn't
        // actually wait out the real timeout.
        let cache = DnsCache::new();
        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| {
                std::future::pending::<std::io::Result<Vec<Ipv4Addr>>>()
            })
            .await;

        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[tokio::test]
    async fn refresh_keeps_the_previously_cached_value_when_a_later_lookup_returns_no_addresses() {
        let cache = DnsCache::new();
        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![])
            })
            .await;

        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[tokio::test]
    async fn refresh_prunes_a_hostname_no_longer_in_the_wanted_set() {
        let cache = DnsCache::new();
        cache
            .refresh_with(["stale.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 9)])
            })
            .await;
        assert_eq!(
            cache.resolve("stale.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 9))
        );

        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        assert_eq!(cache.resolve("stale.internal.example.com"), None);
        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[tokio::test]
    async fn refresh_picks_the_first_returned_ipv4_address_when_a_host_has_several() {
        let cache = DnsCache::new();

        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 6)])
            })
            .await;

        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }
}
