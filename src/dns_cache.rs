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
//!
//! Supporting a hostname at all means enforcement now depends on whatever DNS server this
//! Connector's box is configured to use - DNS spoofing/poisoning there could redirect a gateway's
//! traffic to an attacker-chosen internal address. That's an accepted consequence of what TT-2066
//! asks for (and of Portal already allowing a hostname in the first place), not something this
//! module can itself defend against - written down here, and on TT-2066, rather than left
//! implicit (PR #10 review).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

/// Bounds how long `refresh` *waits* on a single hostname's lookup before moving on - not how
/// long the underlying OS resolver call itself runs. `tokio::time::timeout` drops the awaited
/// future, but `tokio::net::lookup_host` runs `getaddrinfo` on tokio's blocking thread pool, and
/// dropping the future cannot cancel that already-dispatched blocking call - the pool thread
/// stays occupied until the OS resolver gives up on its own (which has its own ceiling, so
/// threads don't accumulate without bound, but it isn't *this* 5s) (PR #10 review). What this
/// value actually guarantees: `refresh` - and so the heartbeat cycle that calls it - never waits
/// more than this long on any one hostname before moving on to the next.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// After this many consecutive failed refresh cycles for the same hostname, its cached address is
/// evicted rather than kept forever (PR #10 review: fail-soft on a *transient* hiccup is right,
/// but as originally written a cached address survived indefinitely as long as the hostname
/// stayed configured - a host decommissioned in DNS, persistent NXDOMAIN, kept receiving forwarded
/// traffic forever at an address that may since have been reassigned to something else on the
/// internal network). At the default 60s heartbeat interval this is ~10 minutes of persistent
/// failure before giving up - long enough to absorb a real outage, short enough to eventually stop
/// trusting a stale mapping.
const MAX_CONSECUTIVE_FAILURES: u32 = 10;

struct CacheEntry {
    address: Ipv4Addr,
    consecutive_failures: u32,
}

type BoxedLookupFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<Ipv4Addr>>> + Send>>;
type BoxedLookupFn = Box<dyn Fn(String) -> BoxedLookupFuture + Send + Sync>;

pub struct DnsCache {
    resolved: Mutex<HashMap<String, CacheEntry>>,
    // Chosen once at construction, not per `refresh` call (PR #10 review): lets a test build a
    // DnsCache with a canned/failing resolver and pass that *same instance* into run_heartbeat,
    // so the actual production call site (which bundles feed this) has real, deterministic test
    // coverage without ever touching the real OS resolver - `refresh_with` (generic per-call) is
    // still what direct DnsCache tests use for the reconciliation logic itself.
    lookup: BoxedLookupFn,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::with_lookup(real_lookup)
    }

    pub(crate) fn with_lookup<F, Fut>(lookup: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::io::Result<Vec<Ipv4Addr>>> + Send + 'static,
    {
        Self {
            resolved: Mutex::new(HashMap::new()),
            lookup: Box::new(move |host| Box::pin(lookup(host))),
        }
    }

    /// Hot-path lookup - a literal IPv4 resolves to itself with no lock taken at all (the common
    /// case, "matches every real example seen so far" per TT-2046); a hostname returns whatever
    /// this cache last successfully resolved it to, or `None` if it's never resolved successfully
    /// (not yet refreshed, DNS has been consistently failing, or it's been evicted after too many
    /// consecutive failures) - callers must treat that the same as any other "can't forward this"
    /// case, never as "forward unchanged".
    pub fn resolve(&self, host: &str) -> Option<Ipv4Addr> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(ip);
        }
        self.resolved
            .lock()
            .expect("dns cache lock poisoned")
            .get(host)
            .map(|entry| entry.address)
    }

    /// Re-resolves every currently-configured hostname, via the real OS resolver in production or
    /// whatever `with_lookup` was constructed with in a test. Literal IPs in `hosts` are ignored -
    /// `resolve` already handles those with no cache entry needed.
    pub async fn refresh(&self, hosts: impl IntoIterator<Item = String>) {
        self.refresh_with(hosts, |host| (self.lookup)(host)).await;
    }

    /// The actual reconciliation logic, generic over the lookup function so tests (including
    /// other modules', e.g. `flow_table`'s) can inject a canned/failing resolver instead of
    /// hitting the real OS resolver (slow and non-hermetic in CI). Production always calls this
    /// via `refresh`, with `real_lookup`.
    ///
    /// Every hostname's lookup runs concurrently (PR #10 review: a serial loop meant N
    /// unresolvable hostnames could consume N * `LOOKUP_TIMEOUT` of one heartbeat cycle - e.g. 12
    /// bad hostnames alone burning the entire default 60s interval) - `join_all` drives them all
    /// within this same task, not `tokio::spawn`, so the lookup function only needs to be
    /// `Fn(String) -> Fut` for the duration of this call, not `Send + 'static`.
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

        let outcomes = futures_util::future::join_all(wanted.iter().map(|host| {
            let lookup = &lookup;
            async move {
                let outcome = match tokio::time::timeout(LOOKUP_TIMEOUT, lookup(host.clone())).await
                {
                    Ok(Ok(addrs)) => match addrs.into_iter().next() {
                        Some(ip) => LookupOutcome::Resolved(ip),
                        // Resolved to something, but no A record - e.g. AAAA-only (v1 scope,
                        // TT-2046, is IPv4 only).
                        None => LookupOutcome::Failed(
                            "DNS resolution returned no IPv4 address".to_string(),
                        ),
                    },
                    Ok(Err(error)) => LookupOutcome::Failed(error.to_string()),
                    Err(_elapsed) => LookupOutcome::Failed(format!(
                        "DNS resolution timed out after {LOOKUP_TIMEOUT:?}"
                    )),
                };
                (host.clone(), outcome)
            }
        }))
        .await;

        let mut resolved = self.resolved.lock().expect("dns cache lock poisoned");
        for (host, outcome) in outcomes {
            match outcome {
                LookupOutcome::Resolved(ip) => {
                    match resolved.get_mut(&host) {
                        Some(entry) if entry.address == ip => {
                            // Unchanged from last successful refresh - logging this at info every
                            // heartbeat, forever, would be pure noise (PR #10 review). debug! is
                            // still there for anyone actively tracing DNS behavior.
                            tracing::debug!(host, %ip, "endpoint hostname still resolves to the same address");
                            entry.consecutive_failures = 0;
                        }
                        Some(entry) => {
                            tracing::info!(host, old = %entry.address, new = %ip, "endpoint hostname resolved to a new address");
                            entry.address = ip;
                            entry.consecutive_failures = 0;
                        }
                        None => {
                            tracing::info!(host, %ip, "resolved endpoint hostname");
                            resolved.insert(
                                host.clone(),
                                CacheEntry {
                                    address: ip,
                                    consecutive_failures: 0,
                                },
                            );
                        }
                    }
                }
                LookupOutcome::Failed(reason) => {
                    // Fails soft on a transient hiccup: a previously-working, already-cached
                    // gateway must not go from "forwarding traffic" to "every packet dropped" on
                    // one bad refresh - the stale address is still more useful than none, up to
                    // MAX_CONSECUTIVE_FAILURES, past which it's evicted instead of trusted forever.
                    if let Some(entry) = resolved.get_mut(&host) {
                        entry.consecutive_failures += 1;
                        if entry.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                            tracing::warn!(
                                host,
                                reason,
                                consecutive_failures = entry.consecutive_failures,
                                "DNS resolution failed too many times in a row - evicting the cached address, no longer forwardable"
                            );
                            resolved.remove(&host);
                        } else {
                            tracing::warn!(
                                host,
                                reason,
                                consecutive_failures = entry.consecutive_failures,
                                "DNS resolution failed - keeping the previously cached value"
                            );
                        }
                    } else {
                        tracing::warn!(
                            host,
                            reason,
                            "DNS resolution failed - this hostname has never resolved successfully"
                        );
                    }
                }
            }
        }

        // Prune hostnames no longer configured by any current gateway (edited or removed in
        // Portal) - without this the cache would grow unboundedly over a long-running daemon's
        // life. Never prunes a literal IP - those were never inserted here in the first place.
        resolved.retain(|host, _| wanted.contains(host));
    }
}

enum LookupOutcome {
    Resolved(Ipv4Addr),
    Failed(String),
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
        let lookups = std::sync::Arc::new(AtomicUsize::new(0));
        let lookups_in_closure = lookups.clone();

        cache
            .refresh_with(["10.0.0.5".to_string()], move |_host| {
                lookups_in_closure.fetch_add(1, Ordering::SeqCst);
                async { Ok(vec![]) }
            })
            .await;

        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refresh_resolves_several_hostnames_concurrently_not_serially() {
        // PR #10 review: a serial loop meant N unresolvable hostnames could consume N *
        // LOOKUP_TIMEOUT of one heartbeat cycle. Proof of concurrency: every lookup here blocks
        // until every lookup has started (a barrier), which can only complete if they're all
        // in flight together - a serial implementation would deadlock this test outright.
        let cache = DnsCache::new();
        let hosts = [
            "a.internal.example.com".to_string(),
            "b.internal.example.com".to_string(),
            "c.internal.example.com".to_string(),
        ];
        let started = std::sync::Arc::new(tokio::sync::Barrier::new(hosts.len()));

        cache
            .refresh_with(hosts, move |host| {
                let started = started.clone();
                async move {
                    started.wait().await;
                    Ok(vec![match host.as_str() {
                        "a.internal.example.com" => Ipv4Addr::new(10, 0, 0, 1),
                        "b.internal.example.com" => Ipv4Addr::new(10, 0, 0, 2),
                        _ => Ipv4Addr::new(10, 0, 0, 3),
                    }])
                }
            })
            .await;

        assert_eq!(
            cache.resolve("a.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            cache.resolve("b.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(
            cache.resolve("c.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 3))
        );
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
    async fn refresh_evicts_a_hostname_after_too_many_consecutive_failures() {
        let cache = DnsCache::new();
        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cache
                .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                    Err(std::io::Error::other("persistent NXDOMAIN"))
                })
                .await;
        }

        assert_eq!(cache.resolve("crm.internal.example.com"), None);
    }

    #[tokio::test]
    async fn refresh_does_not_evict_before_the_failure_threshold_is_reached() {
        let cache = DnsCache::new();
        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        for _ in 0..(MAX_CONSECUTIVE_FAILURES - 1) {
            cache
                .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                    Err(std::io::Error::other("temporary DNS failure"))
                })
                .await;
        }

        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[tokio::test]
    async fn refresh_resets_the_failure_count_on_a_successful_lookup() {
        let cache = DnsCache::new();
        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 5)])
            })
            .await;

        for _ in 0..(MAX_CONSECUTIVE_FAILURES - 1) {
            cache
                .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                    Err(std::io::Error::other("temporary DNS failure"))
                })
                .await;
        }
        // One success resets the streak - the failures above must not carry over.
        cache
            .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                Ok(vec![Ipv4Addr::new(10, 0, 0, 6)])
            })
            .await;
        for _ in 0..(MAX_CONSECUTIVE_FAILURES - 1) {
            cache
                .refresh_with(["crm.internal.example.com".to_string()], |_host| async {
                    Err(std::io::Error::other("temporary DNS failure"))
                })
                .await;
        }

        assert_eq!(
            cache.resolve("crm.internal.example.com"),
            Some(Ipv4Addr::new(10, 0, 0, 6))
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
