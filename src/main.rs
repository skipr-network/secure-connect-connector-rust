mod access;
mod audit;
mod ca_trust;
mod config;
mod crypto;
mod dns_cache;
mod dto;
mod flow_control;
mod flow_table;
mod heartbeat;
mod identity;
mod policy;
mod registry_client;
mod tun_device;
mod tunnel;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use audit::{AuditEvent, AuditLog};
use boringtun::noise::Tunn;
use config::Config;
use dto::{HeartbeatNode, PolicyBundle};
use flow_control::ControlPlaneState;
use flow_table::{FlowTable, ForwardOutcome};
use heartbeat::HeartbeatClient;
use policy::PolicyStore;
use registry_client::RegistryClient;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tunnel::{TunnelEvent, TunnelManager};

/// Explicit CLI modes - checked before tracing init or `Config::from_env` (TT-1886). Matches argv
/// exactly rather than just scanning for `--generate-identity` anywhere in it: a typo'd flag or
/// `--help` used to silently fall through to the normal startup path and hit the exact
/// `CONNECTOR_ID` dead-end this mode exists to remove (PR #5 review, Tasneem). `args_os` avoids a
/// panic on non-UTF-8 argv that `std::env::args` would produce (same review, nit).
enum CliMode {
    Normal,
    GenerateIdentity,
    Help,
}

const USAGE: &str = "Usage: secure_connect_connector [--generate-identity | --help]\n\n\
With no arguments, runs the Connector daemon (reads its config from the environment).\n\
  --generate-identity  Generate (or load) this Connector's identity keypair, print its\n\
                       public key, and exit. No other config or network calls required.\n\
  --help, -h           Show this message and exit.";

fn parse_cli_mode(args: std::env::ArgsOs) -> Result<CliMode, String> {
    // `.to_str()` (not `.to_string_lossy()`/`args()`) so a non-UTF-8 argument is gracefully
    // reported as unrecognized instead of panicking or silently mangling it into a match.
    let rest: Vec<std::ffi::OsString> = args.skip(1).collect();
    match rest.as_slice() {
        [] => Ok(CliMode::Normal),
        [only] => match only.to_str() {
            Some("--generate-identity") => Ok(CliMode::GenerateIdentity),
            Some("--help") | Some("-h") => Ok(CliMode::Help),
            _ => Err(format!("unrecognized argument: {only:?}\n\n{USAGE}")),
        },
        [first, ..] => Err(format!(
            "too many arguments (starting at {first:?}): only one flag is accepted\n\n{USAGE}"
        )),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_cli_mode(std::env::args_os()) {
        Ok(CliMode::GenerateIdentity) => return generate_identity(),
        Ok(CliMode::Help) => {
            println!("{USAGE}");
            return Ok(());
        }
        Ok(CliMode::Normal) => {}
        Err(message) => anyhow::bail!(message),
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    // Checked before the call, not derived from its result: load_or_generate's return shape is
    // the same either way, and the distinction matters here specifically - the daemon generating
    // a fresh identity at normal startup (as opposed to via --generate-identity) almost certainly
    // means the key Portal registered isn't the one about to be used. The Connector will still
    // heartbeat, just with a public key Portal doesn't recognize, and the gateway silently never
    // activates - a $HOME (or any path) mismatch between whoever ran --generate-identity and
    // whatever starts this daemon is exactly what makes this survivable to reach production
    // (PR #278 review, Tasneem).
    let identity_key_existed_already = config.identity_key_path.exists();
    let connector_identity = identity::load_or_generate(&config.identity_key_path)?;
    if identity_key_existed_already {
        info!(
            connector_id = %config.connector_id,
            public_key = %connector_identity.public_key_base64,
            "Connector identity ready"
        );
    } else {
        warn!(
            connector_id = %config.connector_id,
            public_key = %connector_identity.public_key_base64,
            path = %config.identity_key_path.display(),
            "Connector identity ready, but no key file existed at this path - generated a brand \
             new identity. If this Connector was already registered with Portal under a \
             different key, it will heartbeat but the gateway will never activate. Run \
             --generate-identity once and confirm CONNECTOR_IDENTITY_KEY_PATH matches exactly \
             what starts this daemon."
        );
    }

    // TT-2027 review finding #2: the native-roots half of this trust model was silent - only
    // logged if CONNECTOR_CA_BUNDLE_PATH was also set. This makes the zero-config OS-trust-store
    // path visible too, purely for that log line (see ca_trust's own doc).
    ca_trust::log_native_root_certificate_count();

    // TT-2027: CONNECTOR_CA_BUNDLE_PATH, when set, adds one or more extra trusted root CAs on
    // top of the default trust (Mozilla's bundled roots plus, via rustls-tls-native-roots, the
    // box's own OS trust store) - never a replacement for it, and never `danger_accept_invalid_certs`.
    let mut http_builder = reqwest::Client::builder();
    if let Some(ca_bundle_path) = &config.ca_bundle_path {
        for certificate in ca_trust::load_extra_root_certificates(ca_bundle_path)? {
            http_builder = http_builder.add_root_certificate(certificate);
        }
    }
    // reqwest::Certificate::from_pem_bundle doesn't validate DER structure under the rustls
    // backend - it just carries the bytes through - so a structurally-broken certificate in
    // CONNECTOR_CA_BUNDLE_PATH passes load_extra_root_certificates above with Ok, and only fails
    // here, once the TLS backend actually tries to load it as a trust anchor (PR #11 review
    // finding #1). Naming the path in this error, when one was configured, is the difference
    // between an admin immediately knowing which file to check and a bare "failed to build the
    // HTTP client" that gives no hint the CA bundle is even involved.
    let http = http_builder
        .build()
        .with_context(|| match &config.ca_bundle_path {
            Some(path) => format!(
                "failed to build the HTTP client - check that every certificate in \
             CONNECTOR_CA_BUNDLE_PATH ({}) is structurally valid DER, not just well-formed PEM",
                path.display()
            ),
            None => "failed to build the HTTP client".to_string(),
        })?;
    let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
    let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
    let policy_store = Arc::new(PolicyStore::new());
    let audit_log = Arc::new(AuditLog::new(&config.audit_log_path));
    // Moves connector_identity.secret - nothing else needs the identity after
    // the "ready" log line above.
    let tunnel_manager = Arc::new(Mutex::new(TunnelManager::new(connector_identity.secret)));

    // Ephemeral local port: the Connector dials out to nodes, not the other
    // way around (a standard road-warrior WireGuard pattern - no inbound
    // port needed on the customer's side for this leg, per the spec).
    let wg_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("failed to bind the WireGuard UDP socket")?,
    );

    // Shared with the flow-admission control plane below: only a (node_id, port) pair recorded
    // here by an actual "admit" decision may have its packets forwarded (TT-1732 review, Tasneem
    // finding #1). Created before the startup heartbeat loop below (not after, like the TUN
    // device) since run_heartbeat's node-dialing needs it too, to evict a departed node's flows
    // (TT-1732 review, Tasneem, TT-1847 finding #1).
    let flow_table = Arc::new(std::sync::Mutex::new(FlowTable::new()));
    // Refreshed once per heartbeat cycle in `run_heartbeat`, read synchronously on every
    // decrypted packet in `run_wireguard_receive_loop` (TT-2066) - see `dns_cache`'s module doc.
    let dns_cache = Arc::new(dns_cache::DnsCache::new());

    // TT-1838: the TUN device's own address is connector_virtual_ip - Portal's registered,
    // per-Connector control-channel address - not a locally guessed default anymore, so it can
    // only be known once the first heartbeat succeeds. Retries at the configured heartbeat
    // cadence (the same cadence steady-state heartbeats already use) rather than a separate,
    // invented backoff. The heartbeat's other effects (policy application, node dialing) also
    // run here on the very first successful attempt - nothing is fetched twice.
    let connector_virtual_ip = loop {
        match run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await
        {
            Ok(Some(ip)) => break ip,
            Ok(None) => {
                warn!(
                    "heartbeat succeeded but Portal has not assigned a connector_virtual_ip yet - cannot create the TUN device until it does, retrying"
                );
            }
            Err(error) => {
                error!(%error, "initial heartbeat failed - cannot create the TUN device until one succeeds, retrying");
            }
        }
        tokio::time::sleep(config.heartbeat_interval).await;
    };

    // Real packet forwarding (TT-1827): needs CAP_NET_ADMIN + /dev/net/tun,
    // proven for real via two Docker containers exchanging genuine ICMP
    // traffic through actual WireGuard encryption before this was wired in
    // (see tunnel.rs's module doc comment).
    let (tun_reader, tun_writer) =
        tun_device::create(connector_virtual_ip, config.tun_netmask, 1400)
            .context("failed to create the Connector's TUN device")?;
    info!(tun_addr = %connector_virtual_ip, tun_netmask = %config.tun_netmask, "TUN device ready");

    // Admission-rescue channel (2026-09-22 session notes): lets the control-plane admission
    // handler hand a packet it reclaimed via FlowTable::take_pending_packet back to the one task
    // allowed to write to tun_writer, instead of dropping it or needing its own TUN write access.
    let (recovered_packet_tx, recovered_packet_rx) =
        tokio::sync::mpsc::unbounded_channel::<(String, Vec<u8>)>();

    tokio::spawn(run_wireguard_receive_loop(
        wg_socket.clone(),
        tunnel_manager.clone(),
        tun_writer,
        flow_table.clone(),
        std::net::IpAddr::V4(connector_virtual_ip),
        dns_cache.clone(),
        recovered_packet_rx,
    ));
    tokio::spawn(run_tun_send_loop(
        tun_reader,
        wg_socket.clone(),
        tunnel_manager.clone(),
        flow_table.clone(),
    ));
    tokio::spawn(run_timer_loop(wg_socket.clone(), tunnel_manager.clone()));

    // TT-1838: bind to connector_virtual_ip itself, not a wildcard/loopback address - this is
    // what actually restricts these endpoints to genuine Gatekeeper peers (see flow_control.rs's
    // module doc). Only the port stays configurable.
    let control_plane_bind_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(connector_virtual_ip),
        config.control_plane_port,
    );
    let control_plane_listener = tokio::net::TcpListener::bind(control_plane_bind_addr)
        .await
        .with_context(|| format!("failed to bind the flow-admission control-plane listener on {control_plane_bind_addr}"))?;
    info!(
        addr = %control_plane_bind_addr,
        "flow-admission control plane listening"
    );
    let control_plane_router = flow_control::router(ControlPlaneState {
        policy_store: policy_store.clone(),
        audit_log: audit_log.clone(),
        flow_table: flow_table.clone(),
        recovered_packet_tx,
    });
    tokio::spawn(async move {
        if let Err(error) = axum::serve(control_plane_listener, control_plane_router).await {
            error!(%error, "flow-admission control plane server stopped");
        }
    });

    let mut interval = tokio::time::interval(config.heartbeat_interval);
    // The startup loop above already ran one successful heartbeat to learn
    // connector_virtual_ip - without this, interval's own first tick fires
    // immediately, re-running a heartbeat right away instead of waiting a
    // full interval like every subsequent one does.
    interval.reset();
    // Default MissedTickBehavior::Burst fires every missed tick back-to-back the moment a slow
    // heartbeat falls behind (PR #10 review) - e.g. several unresolvable endpoint hostnames each
    // burning their full DNS lookup timeout. Delay only ever schedules the next tick relative to
    // when the current one actually finished, so a slow cycle just pushes later ones back instead
    // of compounding into a burst of immediately-repeated heartbeats.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        match run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await
        {
            // A steady-state heartbeat reporting a different connector_virtual_ip than the one
            // the TUN device and control-plane listener were already created with (TT-1838) -
            // rebinding either live isn't supported, so this can only be surfaced, not applied.
            Ok(Some(latest)) if latest != connector_virtual_ip => {
                error!(
                    started_with = %connector_virtual_ip,
                    now_reported = %latest,
                    "Portal reported a different connector_virtual_ip than the one this process is bound to - restart the Connector to pick it up"
                );
            }
            Ok(_) => {}
            Err(error) => {
                error!(%error, "heartbeat cycle failed");
            }
        }
    }
}

/// TT-1886: generates (or loads, if one already exists) the Connector's identity keypair and
/// prints just the public key, then returns - touches `identity.rs` only, no config beyond
/// `CONNECTOR_IDENTITY_KEY_PATH` and no network calls. The public key is printed alone on its own
/// line on stdout (no label) so it stays scriptable for the eventual install flow (TT-1875), same
/// convention as `wg genkey`. The resolved key path goes to stderr instead (PR #5 review,
/// Tasneem) - useful diagnostic (e.g. confirms whether the default, root-owned
/// `/var/skipr/connector/.keys/identity.key` was actually writable) without breaking stdout's
/// scriptability.
fn generate_identity() -> anyhow::Result<()> {
    let path = config::identity_key_path_from_env();
    let identity = identity::load_or_generate(&path)?;
    eprintln!("identity key path: {}", path.display());
    println!("{}", identity.public_key_base64);
    Ok(())
}

/// Returns the Connector's own control-channel address if this heartbeat carried one - `main`
/// uses the very first successful heartbeat's value to create the TUN device (TT-1838), since
/// nothing local can guess it anymore (Portal is the sole source of truth). `None` means Portal
/// hasn't assigned one yet (or an older Agent didn't relay it) - not an error in itself, but
/// `main`'s startup loop treats it as "not ready" and keeps retrying.
// Each param is a genuinely distinct dependency this function needs (not an arbitrary pile) -
// bundling them into a struct would just move the same count into a constructor call at every
// site instead of removing it.
#[allow(clippy::too_many_arguments)]
async fn run_heartbeat(
    config: &Config,
    registry_client: &RegistryClient,
    heartbeat_client: &HeartbeatClient,
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    tunnel_manager: &Mutex<TunnelManager>,
    wg_socket: &UdpSocket,
    flow_table: &std::sync::Mutex<FlowTable>,
    dns_cache: &dns_cache::DnsCache,
) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
    // Snapshotted before `policy_store.apply(response)` replaces it and before `response` is moved
    // (TT-1640): the entitlement lists this Connector had *before* this heartbeat, diffed after a
    // successful apply against what it has *now* - see `reconcile_dropped_entitlements`. `None` on
    // the very first heartbeat (nothing was ever admitted before any policy existed, so nothing to
    // diff against). Taken before the heartbeat request goes out (not after, like it used to be)
    // since TT-2069 also needs this same snapshot to report the *previous* cycle's unresolved
    // hosts on the way out - `policy_store` isn't touched by anything in between, so the moment
    // doesn't matter for `old_bundles`' own original purpose.
    let old_bundles = policy_store.current().map(|state| state.policy_bundles);
    // TT-2069: report on this heartbeat whatever `old_bundles`' endpoint hosts dns_cache still
    // can't resolve, as of the *previous* cycle's refresh - this cycle's own refresh (below)
    // hasn't run yet, and can't have: the fresh set of hosts to refresh against only exists once
    // this heartbeat's response has already arrived. `None` (not `Some(vec![])`) on the first
    // heartbeat of any process lifetime - there is no previous cycle to report on, which is a
    // genuinely different fact than "checked, nothing unresolved" (review finding #1: collapsing
    // the two used to make Portal read every restart as "all clear" and wipe real marks).
    let unresolved_endpoint_hosts = old_bundles
        .as_deref()
        .map(|bundles| unresolved_hosts_in(bundles, dns_cache));

    let agent_public_key = registry_client
        .get_agent_permitted_key(&config.agent_ip_address)
        .await?;
    let response = heartbeat_client
        .fetch_and_verify(
            &config.connector_id,
            &agent_public_key,
            &dto::ConnectorHeartbeatRequest {
                unresolved_endpoint_hosts,
            },
        )
        .await?;

    let gateways = response.policy_bundles.len();
    let nodes = response.node_list.len();
    let node_list = response.node_list.clone();
    let new_bundles = response.policy_bundles.clone();
    let nodes_without_key = node_list
        .iter()
        .filter(|node| node.wireguard_public_key.is_none())
        .count();
    let connector_virtual_ip = match &response.connector_virtual_ip {
        Some(raw) => match raw.parse::<std::net::Ipv4Addr>() {
            Ok(parsed) => Some(parsed),
            Err(error) => {
                error!(%error, value = %raw, "connector_virtual_ip in the heartbeat response is not a valid IPv4 address");
                None
            }
        },
        None => None,
    };

    // Applying can still reject the package (e.g. an already-expired one) even
    // though the signature verified - don't touch existing local state on that.
    let apply_result = policy_store.apply(response);

    // Audited either way (TT-1820), and best-effort: a failure to *write* the
    // audit entry must not itself change or hide the underlying apply outcome.
    let audit_event = match &apply_result {
        Ok(()) => AuditEvent::PolicyApplied {
            connector_id: config.connector_id.clone(),
            gateway_count: gateways,
            node_count: nodes,
        },
        Err(error) => AuditEvent::PolicyRejected {
            reason: error.to_string(),
        },
    };
    if let Err(audit_error) = audit_log.record(audit_event).await {
        error!(error = %audit_error, "failed to write policy audit entry");
    }

    apply_result?;

    info!(gateways, nodes, "Applied verified heartbeat package");
    if nodes_without_key > 0 {
        warn!(
            nodes_without_key,
            "some nodes have no reported WireGuard public key yet - cannot be dialed until Orchestrator reports one"
        );
    }

    dial_new_nodes(tunnel_manager, wg_socket, &node_list, flow_table).await;
    if let Some(old_bundles) = old_bundles {
        reconcile_dropped_entitlements(flow_table, &old_bundles, &new_bundles);
    }
    reconcile_endpoint_changes(flow_table, &new_bundles);

    // TT-2066: re-resolve every currently-configured endpoint hostname off this same heartbeat
    // cycle - new_bundles is the full, current set of every attached gateway's endpoints, so this
    // also naturally drops a hostname's cache entry once it's no longer configured anywhere (see
    // dns_cache::refresh's pruning). Never blocks/slows packet forwarding itself - that only ever
    // reads the cache this populates, in flow_table::forward_target.
    dns_cache
        .refresh(collect_endpoint_hosts(&new_bundles))
        .await;

    Ok(connector_virtual_ip)
}

/// Every currently-configured endpoint host across every attached gateway - the input to
/// `dns_cache.refresh`. Factored out of `run_heartbeat` as its own pure function specifically so
/// this exact piece of wiring has a direct test (PR #10 review: every `run_heartbeat` test only
/// threads a fresh `DnsCache` through and asserts nothing about it - swapping `new_bundles` for
/// `old_bundles` at the call site, or reading a gateway's own `hostname` field instead of
/// `endpoints[].host`, would still pass the entire suite without this).
fn collect_endpoint_hosts(bundles: &[PolicyBundle]) -> Vec<String> {
    bundles
        .iter()
        .flat_map(|bundle| bundle.endpoints.iter())
        .map(|endpoint| endpoint.host.clone())
        .collect()
}

/// Which of `bundles`' endpoint hosts `dns_cache` currently has no resolved address for - the
/// input to `ConnectorHeartbeatRequest::unresolved_endpoint_hosts` (TT-2069). A literal IPv4 host
/// can never appear here: `DnsCache::resolve` always resolves one immediately, with no lookup at
/// all. Deduplicated and sorted *before* the cache lookups (review finding #5) - the same
/// unresolved host commonly appears on more than one gateway's endpoint list, and there is no
/// reason to take `dns_cache`'s lock more than once per distinct host.
fn unresolved_hosts_in(bundles: &[PolicyBundle], dns_cache: &dns_cache::DnsCache) -> Vec<String> {
    let mut hosts = collect_endpoint_hosts(bundles);
    hosts.sort();
    hosts.dedup();
    hosts.retain(|host| dns_cache.resolve(host).is_none());
    hosts
}

/// Tears down every already-admitted flow whose device dropped out of its gateway's entitlement
/// list in this heartbeat (TT-1640, "Revoke User Active Session From Gateway Through Connector",
/// spec §B.9.3: "each heartbeat's entitlement-list refresh tears down any open flow whose key has
/// dropped out"). Before this, dropping a user from `entitlement_list` (an admin revoking gateway
/// access, or an end-user being blocked) only blocked *new* admissions on the *next* heartbeat - an
/// already-admitted flow just kept forwarding traffic indefinitely, since nothing ever re-checked it
/// against a freshly-applied policy (`decide_access_at` is only consulted on `admit_flow`).
///
/// Diffs old vs. new per gateway: a device present in the old bundle's `entitlement_list` but not in
/// the new one - including when the whole gateway bundle disappeared entirely (gateway disabled,
/// Connector no longer attached to it, ...) - had its access revoked, so any admitted flow it still
/// holds on that gateway is evicted. A device that's still entitled, or a gateway that's unchanged,
/// is left completely alone. Idempotent and order-independent - evicting a device with no admitted
/// flow is a no-op (`FlowTable::evict_gateway_device`).
fn reconcile_dropped_entitlements(
    flow_table: &std::sync::Mutex<FlowTable>,
    old_bundles: &[PolicyBundle],
    new_bundles: &[PolicyBundle],
) {
    let mut table = flow_table.lock().expect("flow table lock poisoned");
    for old_bundle in old_bundles {
        let still_entitled: std::collections::HashSet<&str> = new_bundles
            .iter()
            .find(|bundle| bundle.gateway_id == old_bundle.gateway_id)
            .map(|bundle| {
                bundle
                    .entitlement_list
                    .iter()
                    .filter_map(|e| e.device_public_key.as_deref())
                    .collect()
            })
            .unwrap_or_default();
        for entitlement in &old_bundle.entitlement_list {
            // No device ever means no admitted flow to evict either - `access::decide_access_at`
            // can never have matched a real connecting device against a `None` entitlement.
            let Some(device_public_key) = entitlement.device_public_key.as_deref() else {
                continue;
            };
            if still_entitled.contains(device_public_key) {
                continue;
            }
            let evicted = table.evict_gateway_device(&old_bundle.gateway_id, device_public_key);
            if evicted > 0 {
                info!(
                    gateway_id = %old_bundle.gateway_id,
                    device_public_key,
                    evicted,
                    "entitlement dropped: tore down admitted flow(s) for this gateway"
                );
            }
        }
    }
}

/// Refreshes already-admitted flows' remembered endpoint config to this heartbeat's freshly-applied
/// bundles (TT-2046 review finding #4): unlike entitlements, endpoints were only ever snapshotted
/// once at admission and never revisited, so an admin repointing or removing a gateway's endpoint
/// kept every flow admitted before the change forwarding to the old address until the flow ended on
/// its own. Runs every heartbeat, independent of `old_bundles` (there's no diffing to do - this
/// just always brings `flow_table` up to date with the latest configured endpoints, a no-op for any
/// gateway with nothing currently admitted). See `FlowTable::update_endpoints`.
fn reconcile_endpoint_changes(
    flow_table: &std::sync::Mutex<FlowTable>,
    new_bundles: &[PolicyBundle],
) {
    let mut table = flow_table.lock().expect("flow table lock poisoned");
    for bundle in new_bundles {
        table.update_endpoints(&bundle.gateway_id, &bundle.endpoints);
    }
}

/// Syncs the tunnel set to this heartbeat's node list, then kicks off a
/// handshake for any node that doesn't have an established session yet.
/// Established tunnels are left alone entirely - re-dialing them would
/// discard a working session for no reason. Also evicts `flow_table`'s
/// entries for any node this sync dropped (TT-1847 finding #1).
///
/// Collects the handshake packets to send *while* holding the
/// `tunnel_manager` lock (mutating each tunnel's state needs `&mut`), then
/// releases the lock before actually sending anything - the lock must never
/// be held across a network `.await`, or it serializes this heartbeat
/// dial-out against unrelated live traffic forwarding sharing the same
/// `TunnelManager` (TT-1732 review, Tasneem).
async fn dial_new_nodes(
    tunnel_manager: &Mutex<TunnelManager>,
    wg_socket: &UdpSocket,
    nodes: &[HeartbeatNode],
    flow_table: &std::sync::Mutex<FlowTable>,
) {
    let mut handshakes_to_send = Vec::new();
    let dropped = {
        let mut manager = tunnel_manager.lock().await;
        let dropped = manager.sync_nodes(nodes);

        for node in nodes {
            let Some(tunnel) = manager.tunnel_for(&node.node_id) else {
                continue;
            };
            if tunnel.is_established() {
                continue;
            }
            if let TunnelEvent::SendToNode(packet) = tunnel.initiate_handshake() {
                handshakes_to_send.push((packet, tunnel.addr, node.node_id.clone()));
            }
        }
        dropped
    };

    // A node this Connector no longer has a tunnel for can't have its flows released cleanly by
    // Gatekeeper either - evict them here instead of leaving permanent ghost entries (TT-1732
    // review, Tasneem, TT-1847 finding #1).
    if !dropped.is_empty() {
        let mut table = flow_table.lock().expect("flow table lock poisoned");
        for node_id in &dropped {
            info!(%node_id, "node no longer present in heartbeat's node list - evicting its admitted flows");
            table.evict_node(node_id);
        }
    }

    for (packet, addr, node_id) in handshakes_to_send {
        if let Err(error) = wg_socket.send_to(&packet, addr).await {
            error!(%error, %node_id, %addr, "failed to send WireGuard handshake initiation");
        }
    }
}

/// Decides what to do with one decrypted packet, and does the address rewrite in place if
/// forwarding it - the entire admission/endpoint gate for `run_wireguard_receive_loop`,
/// factored out as a synchronous, sans-I/O function (no socket, no TUN device) specifically so
/// the forward/drop/rewrite decision itself is directly unit-testable (TT-2046 review) rather
/// than only reachable by running the whole daemon against a real socket. Two distinct cases
/// (TT-1838), gated differently:
/// - Addressed to `connector_virtual_ip` itself: Gatekeeper's flow-admission/release control
///   channel, always forwarded unchanged - the flow_table gate below exists to authorize
///   *forwarded* traffic; it has no entry for this because this packet *is* the thing that
///   would create one. Reachability through the tunnel is itself the trust boundary here
///   (Konyk, TT-1732 thread) - a real one, since this address is no longer reachable by
///   anything other than the genuine peer whose wg0 allowed-ips include it.
/// - Addressed anywhere else: forwarded traffic for admitted user flows, gated on `flow_table`
///   (TT-1827, TT-1732 review: decrypting successfully proves the packet came from a genuine
///   node tunnel, but says nothing about whether Gatekeeper's flow-admission relay ever
///   admitted this specific device/gateway; before that fix, ANY decrypted traffic was
///   forwarded regardless) - and, since TT-2046, rewritten to the entitled gateway's real
///   configured internal endpoint. The address this packet carries on arrival is never that
///   real endpoint: it's Gatekeeper's invented, unroutable per-gateway virtual address
///   (DNS-resolution only - see `flow_table::forward_target`'s doc comment), so forwarding it
///   unchanged could never have reached anywhere real even before TT-2046's admission check
///   existed. `forward_target` resolves the real address by matching the packet's destination
///   *port* (never translated by Gatekeeper, so it's the client's real intent) against the
///   entitled gateway's configured endpoints; `tunnel::rewrite_destination_ipv4` does the
///   actual byte-level rewrite, including the checksum fixups a raw address change requires.
///
/// Returns `true` (packet mutated in place if a rewrite was needed, ready to write to TUN
/// as-is) or `false` (packet must not be forwarded - left completely untouched: every check here
/// and in `tunnel::rewrite_destination_ipv4` runs before either one writes a single byte, so
/// there's no partial-rewrite state to worry about).
fn prepare_decrypted_packet_for_forwarding(
    packet: &mut [u8],
    node_id: &str,
    connector_virtual_ip: std::net::IpAddr,
    flow_table: &mut FlowTable,
    dns_cache: &dns_cache::DnsCache,
) -> bool {
    if Tunn::dst_address(packet) == Some(connector_virtual_ip) {
        // TT-2102: record who this direct control-plane connection belongs to, so its own reply
        // (the admission/release decision itself) has somewhere to route back to - previously
        // nothing was recorded here at all, so Gatekeeper's own admission call could never
        // complete, regardless of whether the client flow it was deciding about was admitted.
        if let Some(source_port) = tunnel::parse_source_port(packet) {
            flow_table.record_control_channel_port(node_id, source_port);
        }
        return true;
    }

    let (Some(source_port), Some(dst_port)) = (
        tunnel::parse_source_port(packet),
        tunnel::parse_destination_port(packet),
    ) else {
        warn!(
            %node_id,
            "decrypted packet has no parseable source and/or destination port - dropping"
        );
        return false;
    };

    let real_dst = match flow_table.forward_target(node_id, source_port, dst_port, dns_cache) {
        ForwardOutcome::Forward(real_dst) => real_dst,
        // Four genuinely different situations (TT-2046 review finding #5), each its own message:
        // an unadmitted flow is a security event, an admitted-but-unconfigured port is
        // misconfiguration or probing, an ambiguous match is a Portal config mistake, and a host
        // that hasn't resolved to an address yet (TT-2066) silently black-holes every packet for
        // that gateway until it does - none of these should be indistinguishable to whoever's
        // reading the log on-call.
        ForwardOutcome::NotAdmitted => {
            // Not necessarily gone for good (2026-09-22 session notes): Gatekeeper forwards a new
            // flow's raw packets independently of, and often slightly before, the admission relay
            // that decides whether it's allowed - buffer this one briefly in case that decision is
            // already in flight (see PENDING_PACKET_TTL's doc) instead of losing it outright.
            // run_wireguard_receive_loop's admission-recovery arm is what reclaims it, not here.
            flow_table.buffer_pending_packet(node_id, source_port, packet.to_vec(), Instant::now());
            warn!(%node_id, source_port, dst_port, "decrypted packet has no admitted flow for this node/port yet - buffering briefly in case admission is already in flight");
            return false;
        }
        ForwardOutcome::PortNotConfigured => {
            warn!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted, but its gateway has no endpoint configured on this port - dropping");
            return false;
        }
        ForwardOutcome::AmbiguousEndpoint => {
            warn!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted, but more than one configured endpoint shares this port - refusing to guess, dropping");
            return false;
        }
        ForwardOutcome::HostUnresolved => {
            warn!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted and the port matches, but its configured endpoint host hasn't resolved to an address yet - dropping");
            return false;
        }
    };

    // Recorded from the packet's own pre-rewrite destination - the fake/virtual address the
    // client actually dialed - so the reverse path can restore it on a reply's source before
    // sending it back out (TT-2046 review finding #1). Must happen before the rewrite below,
    // which overwrites this same field.
    if let Some(std::net::IpAddr::V4(virtual_address)) = Tunn::dst_address(packet) {
        flow_table.record_virtual_address(node_id, source_port, virtual_address);
    }

    if tunnel::rewrite_destination_ipv4(packet, real_dst) {
        return true;
    }

    // Distinguish the known v1 scope boundary (IPv6 - `rewrite_destination_ipv4` always
    // rejects it) from a genuinely unexpected rewrite failure, so this doesn't read as a bug
    // to chase during on-call debugging of a dual-stack customer network.
    if packet.first().is_some_and(|&byte| byte >> 4 == 6) {
        warn!(
            %node_id, %real_dst,
            "decrypted packet is IPv6 - endpoint rewriting only supports IPv4 in this version, dropping"
        );
    } else {
        warn!(%node_id, %real_dst, "failed to rewrite decrypted packet's destination - dropping");
    }
    false
}

/// Drives every node tunnel's WireGuard session from the network side: receives a datagram,
/// matches it to the node it came from, feeds it to that tunnel, and either sends back
/// whatever the tunnel produces in response (e.g. the initiator's post-handshake keepalive)
/// or, for real decrypted payload data, hands it to `prepare_decrypted_packet_for_forwarding`
/// and writes it to the TUN device if that says to.
///
/// Also owns the other end of `recovered_packet_rx` (paired with the `Sender` half in
/// `ControlPlaneState`) - the only task allowed to write to `tun_writer` (see `tun_device`'s
/// module doc: "only one task ever writes"), so a packet the admission handler rescues from
/// `FlowTable::take_pending_packet` has to be handed back here rather than written directly from
/// that handler's own task. Re-run through the exact same `prepare_decrypted_packet_for_forwarding`
/// gate as a freshly-arrived packet - by the time this arrives the flow really is admitted, so
/// this resolves to `Forward` and gets the same address rewrite a first-try success would have
/// gotten, not a special-cased raw write.
///
/// Runs for the lifetime of the process; a single receive error is logged
/// and the loop continues - one bad datagram must not take down every
/// node's tunnel.
async fn run_wireguard_receive_loop(
    wg_socket: Arc<UdpSocket>,
    tunnel_manager: Arc<Mutex<TunnelManager>>,
    mut tun_writer: tun_device::TunWriter,
    flow_table: Arc<std::sync::Mutex<FlowTable>>,
    connector_virtual_ip: std::net::IpAddr,
    dns_cache: Arc<dns_cache::DnsCache>,
    mut recovered_packet_rx: tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>,
) {
    let mut buf = [0u8; 2048];
    loop {
        tokio::select! {
            recovered = recovered_packet_rx.recv() => {
                let Some((node_id, mut packet)) = recovered else {
                    // Sender half (ControlPlaneState) dropped - the control-plane server task
                    // exited, which is itself a fatal condition logged elsewhere; nothing useful
                    // to do here except stop selecting on a channel that will never produce again.
                    error!("recovered-packet channel closed - admission-rescued packets will no longer be delivered");
                    continue;
                };
                let should_forward = {
                    let mut table = flow_table.lock().expect("flow table lock poisoned");
                    prepare_decrypted_packet_for_forwarding(
                        &mut packet,
                        &node_id,
                        connector_virtual_ip,
                        &mut table,
                        &dns_cache,
                    )
                };
                if !should_forward {
                    // A genuinely rare race within the race: admitted a moment ago, already
                    // released/refused/reconfigured by the time this was reclaimed. Not worth its
                    // own warning - prepare_decrypted_packet_for_forwarding already logged why.
                    continue;
                }
                if let Err(error) = tun_writer.write_packet(&packet).await {
                    error!(%error, node_id = %node_id, "failed to write admission-rescued packet to TUN device");
                }
            }
            received = wg_socket.recv_from(&mut buf) => {
                let (len, src) = match received {
                    Ok(result) => result,
                    Err(error) => {
                        error!(%error, "failed to receive on the WireGuard UDP socket");
                        continue;
                    }
                };

                let mut manager = tunnel_manager.lock().await;
                let Some(tunnel) = manager.tunnel_for_addr(src) else {
                    warn!(%src, "received a WireGuard datagram from an unrecognized peer address");
                    continue;
                };
                let node_id = tunnel.node_id.clone();
                let event = tunnel.receive(&buf[..len]);
                drop(manager);

                match event {
                    TunnelEvent::SendToNode(packet) => {
                        if let Err(error) = wg_socket.send_to(&packet, src).await {
                            error!(%error, %src, "failed to send WireGuard response packet");
                        }
                    }
                    TunnelEvent::DecryptedData(mut packet) => {
                        // Block-scoped (not a manual `drop`) so the std::sync::MutexGuard - not
                        // Send - provably can't be held across the `.await` below, which
                        // tokio::spawn's Send bound on the whole future requires.
                        let should_forward = {
                            let mut table = flow_table.lock().expect("flow table lock poisoned");
                            prepare_decrypted_packet_for_forwarding(
                                &mut packet,
                                &node_id,
                                connector_virtual_ip,
                                &mut table,
                                &dns_cache,
                            )
                        };
                        if !should_forward {
                            continue;
                        }
                        if let Err(error) = tun_writer.write_packet(&packet).await {
                            error!(%error, node_id = %node_id, "failed to write decrypted packet to TUN device");
                        }
                    }
                    TunnelEvent::ProtocolError(protocol_error) => {
                        warn!(error = %protocol_error, %src, "WireGuard protocol error");
                    }
                    TunnelEvent::Nothing => {}
                }
            }
        }
    }
}

/// Decides whether one outbound packet read from the TUN device (e.g. a reply from the internal
/// endpoint) should be forwarded, and restores its source address in place if so - factored out of
/// `run_tun_send_loop` for the same reason as `prepare_decrypted_packet_for_forwarding`: a
/// synchronous, sans-I/O function so this decision is directly unit-testable, rather than only
/// reachable by running the whole daemon against a real TUN device (TT-2046 review finding #1 -
/// this exact reverse-path rewrite was missing entirely before this fix).
///
/// `destination_port` is the reply's own destination port - the same translated port the original
/// request's flow was admitted on (TT-1847) - already parsed by the caller, since it's also
/// needed there for logging regardless of the outcome here.
///
/// Returns the node_id to route this packet to if it should be forwarded (packet mutated in place
/// with its restored source address), or `None` if it must be dropped - left completely untouched,
/// for the same reason as `prepare_decrypted_packet_for_forwarding`: every check runs before
/// `tunnel::rewrite_source_ipv4` writes anything, so there's no partial-rewrite state to worry
/// about.
fn prepare_reply_packet_for_forwarding(
    packet: &mut [u8],
    destination_port: u16,
    flow_table: &FlowTable,
) -> Option<String> {
    // TT-2102: a reply to this Connector's own control-plane API (Gatekeeper's admission/release
    // decision) needs no address rewrite at all - it was forwarded to the local server unchanged
    // on the way in (see prepare_decrypted_packet_for_forwarding's connector_virtual_ip branch),
    // so its reply already carries the right addresses on the way out too. Checked first, and
    // returns immediately: node_for_port below has no entry for this port at all (control-channel
    // connections are never admitted flows), so falling through would only ever drop it.
    if let Some(node_id) = flow_table.node_for_control_channel_port(destination_port) {
        return Some(node_id.to_string());
    }

    let node_id = match flow_table.node_for_port(destination_port) {
        Some(node_id) => node_id.to_string(),
        None => {
            warn!(
                destination_port,
                "no unambiguous admitted node for outbound packet's port - dropping"
            );
            return None;
        }
    };
    // Restores the source address a reply packet must carry to reach the client at all - the real
    // internal endpoint's own address (what this packet arrived from) is never what the client
    // dialed, so sending it back unchanged means the client's own network stack discards a
    // response from an address it never contacted (TT-2046 review finding #1: real kernel DNAT
    // reverses this automatically via conntrack; this userspace rewrite has no conntrack entry to
    // reverse it with, so it has to be done explicitly, symmetrically to the forward-direction
    // rewrite in `prepare_decrypted_packet_for_forwarding`).
    let Some(virtual_address) = flow_table.virtual_address_for(&node_id, destination_port) else {
        warn!(
            %node_id, destination_port,
            "no virtual address recorded for this flow yet - the client would never accept this reply anyway, dropping"
        );
        return None;
    };
    if !tunnel::rewrite_source_ipv4(packet, virtual_address) {
        warn!(
            %node_id, destination_port, %virtual_address,
            "failed to rewrite outbound packet's source address back to the virtual address - dropping"
        );
        return None;
    }
    Some(node_id)
}

/// Reads outbound IP packets the OS routed to the TUN device (e.g. return
/// traffic from an internal endpoint) and encrypts+sends each one to the
/// right node's tunnel (TT-1847). The destination *address* on this leg is
/// a masqueraded wg0 address identical across the whole fleet (`flow_table`'s
/// module doc) and carries no node identity - the destination *port* is the
/// only reliable signal left, resolved back to a node through `flow_table`'s
/// own admission state (told explicitly by Gatekeeper, never inferred from
/// traffic). A port with no unambiguous admitted node - never admitted, or
/// currently admitted on two different nodes at once - is dropped: there's
/// genuinely nowhere defensible to send it, not a bug to work around.
async fn run_tun_send_loop(
    mut tun_reader: tun_device::TunReader,
    wg_socket: Arc<UdpSocket>,
    tunnel_manager: Arc<Mutex<TunnelManager>>,
    flow_table: Arc<std::sync::Mutex<FlowTable>>,
) {
    let mut buf = [0u8; 2048];
    loop {
        let len = match tun_reader.read_packet(&mut buf).await {
            Ok(len) => len,
            Err(error) => {
                error!(%error, "failed to read from TUN device");
                continue;
            }
        };
        let Some(destination_port) = tunnel::parse_destination_port(&buf[..len]) else {
            continue;
        };

        // tunnel_manager is locked FIRST, and flow_table is looked up while still holding it, so
        // the admission check and the tunnel lookup are atomic with respect to each other - no
        // window where a concurrent release or node departure could invalidate node_id between
        // resolving it and using it (TT-1732 review, Tasneem, TT-1847 finding #2). flow_table's
        // std::sync::Mutex is only ever held for the synchronous lookup below, never across an
        // `.await`.
        let mut manager = tunnel_manager.lock().await;
        let node_id = {
            let table = flow_table.lock().expect("flow table lock poisoned");
            match prepare_reply_packet_for_forwarding(&mut buf[..len], destination_port, &table) {
                Some(node_id) => node_id,
                None => continue,
            }
        };
        let Some(tunnel) = manager.tunnel_for(&node_id) else {
            warn!(%node_id, destination_port, "admitted node has no active tunnel - dropping");
            continue;
        };
        let event = tunnel.encapsulate(&buf[..len]);
        let addr = tunnel.addr;
        // Released before the send below - must never be held across a
        // network `.await` (TT-1732 review, Tasneem).
        drop(manager);

        if let TunnelEvent::SendToNode(packet) = event
            && let Err(error) = wg_socket.send_to(&packet, addr).await
        {
            error!(%error, %addr, %node_id, destination_port, "failed to send encrypted outbound packet");
        }
    }
}

/// Periodically drives every tunnel's WireGuard timers - required for
/// sessions to stay alive at all; boringtun does nothing on its own to
/// rekey or detect expiry unless this is called regularly (TT-1732 review,
/// Tasneem: `Tunn::update_timers` was never called anywhere before this
/// fix, so a session would silently go stale after a few minutes and never
/// be re-dialed). Interval matches boringtun's own documented usage
/// convention of roughly once per second.
async fn run_timer_loop(wg_socket: Arc<UdpSocket>, tunnel_manager: Arc<Mutex<TunnelManager>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let packets = {
            let mut manager = tunnel_manager.lock().await;
            manager.drive_all_timers()
        };
        for (packet, addr) in packets {
            if let Err(error) = wg_socket.send_to(&packet, addr).await {
                error!(%error, %addr, "failed to send WireGuard timer-driven packet");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dto::Entitlement;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(registry_base_url: String, agent_base_url: String) -> Config {
        Config {
            connector_id: "c-1".to_string(),
            agent_base_url,
            agent_ip_address: "10.0.0.5".to_string(),
            registry_base_url,
            identity_key_path: "/tmp/unused-in-this-test".into(),
            audit_log_path: "/tmp/unused-in-this-test-audit.log".into(),
            control_plane_port: 0,
            tun_netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            heartbeat_interval: Duration::from_secs(60),
            ca_bundle_path: None,
        }
    }

    async fn wg_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    fn read_audit_lines(dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.path().join("audit.log"))
            .map(|contents| {
                contents
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Minimal IPv4/UDP packet - no payload, checksums left at 0 (UDP's "none computed", left
    /// alone by `rewrite_destination_ipv4` too), since `prepare_decrypted_packet_for_forwarding`
    /// never validates a checksum, only `tunnel::rewrite_destination_ipv4` does (covered by its
    /// own tests in `tunnel.rs`).
    fn udp_packet(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    #[test]
    fn prepare_decrypted_packet_forwards_a_control_channel_packet_unchanged() {
        let connector_virtual_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1));
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            std::net::Ipv4Addr::new(10, 98, 0, 1),
            51234,
            8443,
        );
        let original = packet.clone();
        let mut flow_table = FlowTable::new();
        let dns_cache = dns_cache::DnsCache::new();

        assert!(prepare_decrypted_packet_for_forwarding(
            &mut packet,
            "n-1",
            connector_virtual_ip,
            &mut flow_table,
            &dns_cache
        ));
        assert_eq!(
            packet, original,
            "control-channel packet must be forwarded byte-for-byte unchanged"
        );
        assert_eq!(
            flow_table.node_for_control_channel_port(51234),
            Some("n-1"),
            "TT-2102: the sending node must be recorded against its source port, so the reply has somewhere to route back to"
        );
    }

    #[test]
    fn prepare_decrypted_packet_drops_a_packet_for_an_unadmitted_flow() {
        let connector_virtual_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1));
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            std::net::Ipv4Addr::new(10, 99, 0, 1), // Gatekeeper's fake virtual address - never admitted under it
            51234,
            443,
        );
        let mut flow_table = FlowTable::new();
        let dns_cache = dns_cache::DnsCache::new();

        assert!(!prepare_decrypted_packet_for_forwarding(
            &mut packet,
            "n-1",
            connector_virtual_ip,
            &mut flow_table,
            &dns_cache
        ));
    }

    #[test]
    fn prepare_decrypted_packet_drops_an_admitted_flows_packet_to_an_unconfigured_port() {
        let connector_virtual_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1));
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            std::net::Ipv4Addr::new(10, 99, 0, 1),
            51234,
            8080, // not one of the gateway's configured endpoints below
        );
        let mut flow_table = FlowTable::new();
        flow_table.admit(
            "n-1".to_string(),
            51234,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: "10.0.0.5".to_string(),
                port: 443,
            }],
        );
        let dns_cache = dns_cache::DnsCache::new();

        assert!(!prepare_decrypted_packet_for_forwarding(
            &mut packet,
            "n-1",
            connector_virtual_ip,
            &mut flow_table,
            &dns_cache
        ));
    }

    #[test]
    fn prepare_decrypted_packet_rewrites_and_forwards_an_admitted_flows_packet() {
        // The integration case this whole function exists to cover (TT-2046 review): an
        // admitted flow's packet must actually come out rewritten to the gateway's real
        // configured endpoint, not just "allowed" in the abstract.
        let connector_virtual_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1));
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            std::net::Ipv4Addr::new(10, 99, 0, 1), // Gatekeeper's fake virtual address on arrival
            51234,
            443,
        );
        let mut flow_table = FlowTable::new();
        flow_table.admit(
            "n-1".to_string(),
            51234,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: "10.0.0.5".to_string(),
                port: 443,
            }],
        );
        let dns_cache = dns_cache::DnsCache::new();

        assert!(prepare_decrypted_packet_for_forwarding(
            &mut packet,
            "n-1",
            connector_virtual_ip,
            &mut flow_table,
            &dns_cache
        ));
        assert_eq!(
            &packet[16..20],
            &[10, 0, 0, 5],
            "must be rewritten to the real configured endpoint, not left on the fake virtual address"
        );
        // TT-2046 review finding #1: the packet's pre-rewrite (fake) destination must be recorded
        // so the reverse path can restore it on a reply - without this, no real request/response
        // can ever complete (the client discards a reply from an address it never contacted).
        assert_eq!(
            flow_table.virtual_address_for("n-1", 51234),
            Some(std::net::Ipv4Addr::new(10, 99, 0, 1))
        );
    }

    #[test]
    fn prepare_decrypted_packet_drops_an_ipv6_packet_even_when_a_matching_flow_would_admit_it() {
        // v1 scope (TT-2046): rewrite_destination_ipv4 always rejects IPv6, so an admitted
        // flow's IPv6 traffic must still be dropped, not forwarded unrewritten.
        let connector_virtual_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1));
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60; // IPv6
        packet[6] = 17; // next header: UDP
        packet[7] = 64; // hop limit
        packet[40..42].copy_from_slice(&51234u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());
        let mut flow_table = FlowTable::new();
        flow_table.admit(
            "n-1".to_string(),
            51234,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: "10.0.0.5".to_string(),
                port: 443,
            }],
        );
        let dns_cache = dns_cache::DnsCache::new();

        assert!(!prepare_decrypted_packet_for_forwarding(
            &mut packet,
            "n-1",
            connector_virtual_ip,
            &mut flow_table,
            &dns_cache
        ));
    }

    #[test]
    fn prepare_reply_packet_drops_when_no_admitted_node_for_the_port() {
        let flow_table = FlowTable::new();
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            443,
            51234,
        );

        assert_eq!(
            prepare_reply_packet_for_forwarding(&mut packet, 51234, &flow_table),
            None
        );
    }

    #[test]
    fn prepare_reply_packet_routes_a_control_channel_reply_unchanged_with_no_admitted_flow_at_all()
    {
        // TT-2102: a reply to this Connector's own control-plane API (Gatekeeper's admission
        // decision) must route back to the node without needing - or touching - any admitted
        // flow state at all. flow_table here has nothing admitted on this port whatsoever, which
        // is exactly the real situation: a control-channel connection's own port was never, and
        // will never be, an admitted flow.
        let mut flow_table = FlowTable::new();
        flow_table.record_control_channel_port("n-1", 51234);
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 98, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            8443,
            51234,
        );
        let original = packet.clone();

        let node_id = prepare_reply_packet_for_forwarding(&mut packet, 51234, &flow_table);

        assert_eq!(node_id, Some("n-1".to_string()));
        assert_eq!(
            packet, original,
            "a control-channel reply needs no address rewrite - it already carries the right addresses"
        );
    }

    #[test]
    fn prepare_reply_packet_prefers_the_control_channel_mapping_over_an_admitted_flow_on_the_same_port()
     {
        // Genuinely unlikely (an admitted flow's translated port colliding with a live
        // control-channel connection's own ephemeral port), but the control-channel check runs
        // first unconditionally, so confirm it actually takes precedence rather than relying on
        // the two never coinciding in practice.
        let mut flow_table = FlowTable::new();
        flow_table.admit(
            "n-2".to_string(),
            51234,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        flow_table.record_virtual_address("n-2", 51234, std::net::Ipv4Addr::new(10, 99, 0, 1));
        flow_table.record_control_channel_port("n-1", 51234);
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 98, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            8443,
            51234,
        );
        let original = packet.clone();

        let node_id = prepare_reply_packet_for_forwarding(&mut packet, 51234, &flow_table);

        assert_eq!(node_id, Some("n-1".to_string()));
        assert_eq!(packet, original);
    }

    #[test]
    fn prepare_reply_packet_drops_when_no_virtual_address_has_been_recorded_yet() {
        // TT-2046 review finding #1: a reply for a flow whose forward direction never ran (or
        // raced ahead of it) has nothing to restore its source to - the client would reject it
        // anyway (it never dialed the real internal address), so there's nowhere defensible to
        // send it, same reasoning as node_for_port's own ambiguity refusal.
        let mut flow_table = FlowTable::new();
        flow_table.admit(
            "n-1".to_string(),
            51234,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            443,
            51234,
        );

        assert_eq!(
            prepare_reply_packet_for_forwarding(&mut packet, 51234, &flow_table),
            None
        );
    }

    #[test]
    fn prepare_reply_packet_restores_the_recorded_virtual_address_as_the_source_and_returns_the_node_id()
     {
        let mut flow_table = FlowTable::new();
        flow_table.admit(
            "n-1".to_string(),
            51234,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![],
        );
        flow_table.record_virtual_address("n-1", 51234, std::net::Ipv4Addr::new(10, 99, 0, 1));
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            443,
            51234,
        );

        let node_id = prepare_reply_packet_for_forwarding(&mut packet, 51234, &flow_table);

        assert_eq!(node_id, Some("n-1".to_string()));
        assert_eq!(
            &packet[12..16],
            &[10, 99, 0, 1],
            "reply's source must be restored to the virtual address the client dialed"
        );
    }

    #[test]
    fn a_forwarded_packets_virtual_address_is_exactly_what_its_reply_gets_restored_to() {
        // The actual round-trip this whole fix is about (TT-2046 review finding #1): whatever
        // virtual address a request arrived addressed to is exactly what its reply must be
        // restored to carry as its source - proven end to end through both real functions
        // together, not just each one in isolation. Without this, the client's own network stack
        // discards the reply as coming from an address it never contacted, and no real
        // request/response can ever complete.
        let connector_virtual_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1));
        let mut request = udp_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            std::net::Ipv4Addr::new(10, 99, 0, 1), // the virtual address the client actually dialed
            51234,
            443,
        );
        let mut flow_table = FlowTable::new();
        flow_table.admit(
            "n-1".to_string(),
            51234,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-1".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: "10.0.0.5".to_string(),
                port: 443,
            }],
        );
        let dns_cache = dns_cache::DnsCache::new();
        assert!(prepare_decrypted_packet_for_forwarding(
            &mut request,
            "n-1",
            connector_virtual_ip,
            &mut flow_table,
            &dns_cache
        ));

        let mut reply = udp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 5), // the real internal endpoint's own address
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            443,
            51234,
        );
        let node_id = prepare_reply_packet_for_forwarding(&mut reply, 51234, &flow_table);

        assert_eq!(node_id, Some("n-1".to_string()));
        assert_eq!(
            &reply[12..16],
            &[10, 99, 0, 1],
            "reply's source must be the exact virtual address the client dialed, not the real internal endpoint's own address"
        );
    }

    #[tokio::test]
    async fn run_heartbeat_succeeds_against_a_correctly_signed_response() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        // No connector_virtual_ip in this response body - Ok(None), not an error.
        assert_eq!(result.unwrap(), None);
        assert_eq!(policy_store.current().unwrap().connector_id, "c-1");
        let entries = read_audit_lines(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["event"], "policy_applied");
        assert_eq!(entries[0]["gateway_count"], 0);
    }

    /// TT-1838: `main` uses this returned value to create the TUN device - must be the real
    /// parsed address, not just "heartbeat succeeded".
    #[tokio::test]
    async fn run_heartbeat_returns_the_parsed_connector_virtual_ip_when_present() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","connector_virtual_ip":"10.98.0.7","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert_eq!(result.unwrap(), Some(std::net::Ipv4Addr::new(10, 98, 0, 7)));
    }

    #[tokio::test]
    async fn run_heartbeat_surfaces_a_registry_lookup_failure() {
        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&registry_server)
            .await;

        let config = config(registry_server.uri(), "http://127.0.0.1:1".to_string());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
        // Failed before ever reaching policy application - nothing to audit yet.
        assert!(read_audit_lines(&dir).is_empty());
    }

    #[tokio::test]
    async fn run_heartbeat_surfaces_a_signature_verification_failure() {
        let agent_identity = crypto::generate_keypair();
        let impostor_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let wrong_signature =
            crypto::sign_to_base64(&impostor_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", wrong_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
        // Signature verification failed before policy application - nothing to audit yet.
        assert!(read_audit_lines(&dir).is_empty());
    }

    #[tokio::test]
    async fn run_heartbeat_rejects_an_already_expired_package_and_does_not_apply_it() {
        let agent_identity = crypto::generate_keypair();
        // 2020 is always in the past relative to any real run of this test.
        let body = r#"{"connector_id":"c-1","generated_at":"2020-01-01T09:55:00Z","expires_at":"2020-01-01T10:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert!(result.is_err());
        assert!(policy_store.current().is_none());
        let entries = read_audit_lines(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["event"], "policy_rejected");
    }

    #[tokio::test]
    async fn run_heartbeat_succeeds_and_warns_when_some_nodes_have_no_wireguard_key_yet() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[{"node_id":"n-1","ip_address":"10.0.0.10","wireguard_public_key":null}]}"#;
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        // Nodes-without-key is only a warning, not a failure - the cycle still
        // succeeds (there's simply nothing to dial yet for that node).
        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(policy_store.current().unwrap().node_list.len(), 1);
        // No key reported for this node yet, so nothing to dial.
        assert_eq!(tunnel_manager.lock().await.node_count(), 0);
    }

    #[tokio::test]
    async fn run_heartbeat_dials_a_node_that_has_a_reported_wireguard_key() {
        let agent_identity = crypto::generate_keypair();
        let node_identity = boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng);
        let node_public_key_base64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .encode(boringtun::x25519::PublicKey::from(&node_identity).as_bytes())
        };

        // The "node" in this test is a real bound UDP socket, standing in for
        // what a Gatekeeper-side WireGuard interface would receive. Bound to
        // the real WireGuard port, since that's where TunnelManager actually
        // sends - an ephemeral port here would never receive anything.
        let node_socket = UdpSocket::bind(format!("127.0.0.1:{}", tunnel::WIREGUARD_PORT))
            .await
            .unwrap();
        let node_addr = node_socket.local_addr().unwrap();
        let body = format!(
            r#"{{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[{{"node_id":"n-1","ip_address":"{}","wireguard_public_key":"{}"}}]}}"#,
            node_addr.ip(),
            node_public_key_base64
        );
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(tunnel_manager.lock().await.node_count(), 1);

        // A real handshake-initiation packet should have actually arrived at
        // the node's socket.
        let mut buf = [0u8; 2048];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(1), node_socket.recv_from(&mut buf))
                .await
                .expect("handshake initiation packet never arrived")
                .unwrap();
        assert!(len > 0);
        assert_eq!(from, wg_socket.local_addr().unwrap());
    }

    #[test]
    fn collect_endpoint_hosts_returns_every_endpoint_across_every_bundle() {
        let bundles = vec![
            PolicyBundle {
                gateway_id: "gw-1".to_string(),
                location: "Amsterdam".to_string(),
                hostname: "crm.internal.example.com".to_string(),
                access_mode: "SELECTED_USERS".to_string(),
                endpoints: vec![
                    dto::PolicyBundleEndpoint {
                        host: "10.0.0.5".to_string(),
                        port: 443,
                    },
                    dto::PolicyBundleEndpoint {
                        host: "erp.internal.example.com".to_string(),
                        port: 8443,
                    },
                ],
                entitlement_list: vec![],
            },
            PolicyBundle {
                gateway_id: "gw-2".to_string(),
                location: "Amsterdam".to_string(),
                hostname: "erp.internal.example.com".to_string(),
                access_mode: "SELECTED_USERS".to_string(),
                endpoints: vec![dto::PolicyBundleEndpoint {
                    host: "files.internal.example.com".to_string(),
                    port: 445,
                }],
                entitlement_list: vec![],
            },
        ];

        let hosts = collect_endpoint_hosts(&bundles);

        assert_eq!(
            hosts,
            vec![
                "10.0.0.5".to_string(),
                "erp.internal.example.com".to_string(),
                "files.internal.example.com".to_string(),
            ]
        );
    }

    fn bundle_with_endpoints(gateway_id: &str, hosts: &[&str]) -> PolicyBundle {
        PolicyBundle {
            gateway_id: gateway_id.to_string(),
            location: "Amsterdam".to_string(),
            hostname: "crm.internal.example.com".to_string(),
            access_mode: "SELECTED_USERS".to_string(),
            endpoints: hosts
                .iter()
                .map(|host| dto::PolicyBundleEndpoint {
                    host: host.to_string(),
                    port: 443,
                })
                .collect(),
            entitlement_list: vec![],
        }
    }

    #[test]
    fn unresolved_endpoint_hosts_excludes_a_literal_ip() {
        let bundles = vec![bundle_with_endpoints("gw-1", &["10.0.0.5"])];
        let dns_cache = dns_cache::DnsCache::new();

        assert_eq!(
            unresolved_hosts_in(&bundles, &dns_cache),
            Vec::<String>::new()
        );
    }

    #[test]
    fn unresolved_endpoint_hosts_includes_a_hostname_that_has_never_resolved() {
        let bundles = vec![bundle_with_endpoints("gw-1", &["erp.internal.example.com"])];
        let dns_cache = dns_cache::DnsCache::new();

        assert_eq!(
            unresolved_hosts_in(&bundles, &dns_cache),
            vec!["erp.internal.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn unresolved_endpoint_hosts_excludes_a_hostname_the_cache_has_already_resolved() {
        let bundles = vec![bundle_with_endpoints("gw-1", &["erp.internal.example.com"])];
        let dns_cache = dns_cache::DnsCache::with_lookup(|_host| async {
            Ok(vec!["10.0.0.5".parse().unwrap()])
        });
        dns_cache.refresh(collect_endpoint_hosts(&bundles)).await;

        assert_eq!(
            unresolved_hosts_in(&bundles, &dns_cache),
            Vec::<String>::new()
        );
    }

    #[test]
    fn unresolved_endpoint_hosts_deduplicates_and_sorts() {
        // The same unresolved hostname commonly appears on more than one gateway's endpoint list -
        // an admin-facing report must never repeat it.
        let bundles = vec![
            bundle_with_endpoints(
                "gw-1",
                &["b.internal.example.com", "a.internal.example.com"],
            ),
            bundle_with_endpoints("gw-2", &["a.internal.example.com"]),
        ];
        let dns_cache = dns_cache::DnsCache::new();

        assert_eq!(
            unresolved_hosts_in(&bundles, &dns_cache),
            vec![
                "a.internal.example.com".to_string(),
                "b.internal.example.com".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn run_heartbeat_refreshes_the_dns_cache_from_this_heartbeats_bundles_not_the_previous_ones()
     {
        // PR #10 review: the sharpest version of the wiring gap - an already-admitted gateway's
        // endpoint from a *previous* heartbeat (old_bundles) must never leak into what this
        // heartbeat resolves. DnsCache::with_lookup records every host it's actually asked to
        // resolve, so this proves the real production call site (not a hand-called refresh_with)
        // reads new_bundles, not old_bundles or something else entirely (a gateway's own
        // `hostname` field, say) - without ever touching the real OS resolver (PR #10 review: a
        // hostname fixture here must not risk a real, slow DNS lookup in CI).
        let agent_identity = crypto::generate_keypair();
        let old_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[{"host":"old.internal.example.com","port":443}],"entitlement_list":[]}],"node_list":[]}"#;
        let old_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, old_body.as_bytes());
        let new_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:01:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n2","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[{"host":"new.internal.example.com","port":443}],"entitlement_list":[]}],"node_list":[]}"#;
        let new_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, new_body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;
        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(old_body, "application/json")
                    .insert_header("X-Signature", old_signature.as_str()),
            )
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(new_body, "application/json")
                    .insert_header("X-Signature", new_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let requested_hosts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let requested_hosts_in_lookup = requested_hosts.clone();
        let dns_cache = dns_cache::DnsCache::with_lookup(move |host: String| {
            requested_hosts_in_lookup.lock().unwrap().push(host);
            async { Ok(vec![std::net::Ipv4Addr::new(10, 0, 0, 7)]) }
        });

        // First heartbeat: applies old_bundles as the *current* policy_store state, so the second
        // call below has real old_bundles/new_bundles to diff between - not None vs. something.
        run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await
        .unwrap();
        requested_hosts.lock().unwrap().clear();

        run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await
        .unwrap();

        // Only this heartbeat's own endpoint host - old.internal.example.com must never appear,
        // proving the call site reads new_bundles and not old_bundles.
        assert_eq!(
            *requested_hosts.lock().unwrap(),
            vec!["new.internal.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn run_heartbeat_reports_the_previous_cycles_unresolved_hosts_on_the_next_request() {
        // TT-2069, end to end: the first heartbeat applies a gateway whose endpoint hostname the
        // (faked) DNS lookup always fails for - the second heartbeat's own *outgoing request*
        // must then carry that host in unresolved_endpoint_hosts, proving the real
        // run_heartbeat/HeartbeatClient wiring, not just each piece tested in isolation.
        let agent_identity = crypto::generate_keypair();
        let first_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[{"host":"erp.internal.example.com","port":443}],"entitlement_list":[]}],"node_list":[]}"#;
        let first_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, first_body.as_bytes());
        let second_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:01:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n2","policy_bundles":[],"node_list":[]}"#;
        let second_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, second_body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;
        let agent_server = MockServer::start().await;
        // First request: an empty ConnectorHeartbeatRequest is all there is to report yet (no
        // prior cycle exists).
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .and(body_json(dto::ConnectorHeartbeatRequest::default()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(first_body, "application/json")
                    .insert_header("X-Signature", first_signature.as_str()),
            )
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        // Second request: must now report the hostname the fake resolver below always fails.
        // Only matched if the outgoing body is exactly this - an unmatched request gets wiremock's
        // default 404, which fetch_and_verify would surface as an error, failing this test.
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .and(body_json(&dto::ConnectorHeartbeatRequest {
                unresolved_endpoint_hosts: Some(vec!["erp.internal.example.com".to_string()]),
            }))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(second_body, "application/json")
                    .insert_header("X-Signature", second_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        // Always "fails" (no address returned) - see dns_cache::LookupOutcome, an empty Vec
        // means "no A record", the same as any other resolution failure.
        let dns_cache = dns_cache::DnsCache::with_lookup(|_host| async { Ok(vec![]) });

        run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await
        .unwrap();

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert!(
            result.is_ok(),
            "second heartbeat's request must have matched the body_json mock above, or this is \
             an unmatched-request error instead: {result:?}"
        );
    }

    fn bundle(gateway_id: &str, entitled_device_keys: &[&str]) -> PolicyBundle {
        PolicyBundle {
            gateway_id: gateway_id.to_string(),
            location: "Amsterdam".to_string(),
            hostname: "crm.internal.example.com".to_string(),
            access_mode: "SELECTED_USERS".to_string(),
            endpoints: vec![],
            entitlement_list: entitled_device_keys
                .iter()
                .map(|key| Entitlement {
                    user_id: "u-1".to_string(),
                    device_public_key: Some(key.to_string()),
                })
                .collect(),
        }
    }

    #[test]
    fn reconcile_dropped_entitlements_evicts_a_device_no_longer_entitled_to_its_gateway() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &[])];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none()
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_leaves_a_still_entitled_device_alone() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &["dev-A"])];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert_eq!(
            flow_table.lock().unwrap().gateway_for("n-1", 40001),
            Some("gw-1")
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_leaves_the_same_devices_other_gateway_flow_alone() {
        // The AC this whole feature exists for: revoking one gateway's access must never touch the
        // user's wider SecureConnect session, including their other Private Gateway access.
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40002,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"]), bundle("gw-2", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &[]), bundle("gw-2", &["dev-A"])];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none()
        );
        assert_eq!(
            flow_table.lock().unwrap().gateway_for("n-1", 40002),
            Some("gw-2")
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_evicts_every_flow_when_the_whole_gateway_bundle_disappears() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles: Vec<PolicyBundle> = vec![];

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles);

        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none()
        );
    }

    #[test]
    fn reconcile_dropped_entitlements_with_no_prior_bundles_is_a_no_op() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        reconcile_dropped_entitlements(&flow_table, &[], &[bundle("gw-1", &["dev-A"])]);
    }

    fn bundle_with_endpoint(gateway_id: &str, host: &str, port: u16) -> PolicyBundle {
        PolicyBundle {
            endpoints: vec![dto::PolicyBundleEndpoint {
                host: host.to_string(),
                port,
            }],
            ..bundle(gateway_id, &[])
        }
    }

    #[test]
    fn reconcile_endpoint_changes_updates_an_already_admitted_flows_forwarding_target() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: "10.0.0.1".to_string(),
                port: 443,
            }],
        );
        let new_bundles = vec![bundle_with_endpoint("gw-1", "10.0.0.2", 443)];

        reconcile_endpoint_changes(&flow_table, &new_bundles);
        let dns_cache = dns_cache::DnsCache::new();

        assert_eq!(
            flow_table
                .lock()
                .unwrap()
                .forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::Forward("10.0.0.2".parse().unwrap())
        );
    }

    #[test]
    fn reconcile_endpoint_changes_leaves_a_different_gateways_flow_alone() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: "10.0.0.1".to_string(),
                port: 443,
            }],
        );
        let new_bundles = vec![bundle_with_endpoint("gw-2", "10.0.0.2", 443)];

        reconcile_endpoint_changes(&flow_table, &new_bundles);
        let dns_cache = dns_cache::DnsCache::new();

        assert_eq!(
            flow_table
                .lock()
                .unwrap()
                .forward_target("n-1", 40001, 443, &dns_cache),
            ForwardOutcome::Forward("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn reconcile_endpoint_changes_with_no_bundles_is_a_no_op() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        reconcile_endpoint_changes(&flow_table, &[]);
    }

    /// End-to-end through two real `run_heartbeat` calls: entitlement present on the first, dropped
    /// on the second - proving the diff actually runs off `PolicyStore`'s real before/after state,
    /// not just the pure reconciliation function above.
    #[tokio::test]
    async fn a_second_heartbeat_evicts_a_flow_whose_device_dropped_out_of_entitlement_list() {
        let agent_identity = crypto::generate_keypair();
        let first_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]},{"gateway_id":"gw-2","location":"Amsterdam","hostname":"erp.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
        let second_body = r#"{"connector_id":"c-1","generated_at":"2026-08-27T10:01:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n2","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[]},{"gateway_id":"gw-2","location":"Amsterdam","hostname":"erp.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
        let first_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, first_body.as_bytes());
        let second_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, second_body.as_bytes());

        let registry_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agents/10.0.0.5/permitted-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_address": "10.0.0.5",
                "permitted_key": agent_identity.public_key_hex
            })))
            .mount(&registry_server)
            .await;

        let agent_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(first_body, "application/json")
                    .insert_header("X-Signature", first_signature.as_str()),
            )
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/c-1/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(second_body, "application/json")
                    .insert_header("X-Signature", second_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri(), agent_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http, config.agent_base_url.clone());
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await
        .unwrap();
        // Simulates Gatekeeper admitting the flows during the window this Connector was entitled -
        // this must not be evicted by the *first* heartbeat's own apply (nothing to diff against yet).
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40002,
            "gw-2".to_string(),
            "flow-2".to_string(),
            "dev-A".to_string(),
            vec![],
        );

        let result = run_heartbeat(
            &config,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
        )
        .await;

        assert!(result.is_ok());
        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none(),
            "the flow on the gateway whose entitlement was dropped must be torn down"
        );
        assert_eq!(
            flow_table.lock().unwrap().gateway_for("n-1", 40002),
            Some("gw-2"),
            "the same device's flow on a gateway it's still entitled to must survive"
        );
    }
}
