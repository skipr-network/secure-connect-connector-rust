mod access;
mod admission_poller;
mod agent_directory;
mod audit;
mod ca_trust;
mod config;
mod connection_events;
mod crypto;
mod dns_cache;
mod dto;
mod flow_control;
mod flow_table;
mod gateway_end;
mod heartbeat;
mod identity;
mod live_sessions;
mod policy;
mod registry_client;
mod request_proof;
mod state_file;
mod tun_device;
mod tunnel;

use std::sync::Arc;
use std::time::{Duration, Instant};

use admission_poller::AdmissionPollers;
use agent_directory::AgentDirectory;
use anyhow::Context;
use audit::{AuditEvent, AuditLog};
use boringtun::noise::Tunn;
use config::Config;
use dto::{HeartbeatNode, PolicyBundle};
use flow_control::ControlPlaneState;
use flow_table::{Dialled, FlowTable, ForwardOutcome, Forwarding, ReplyMiss, ReplyRoute};
use heartbeat::{AgentRejected, HeartbeatClient};
use policy::PolicyStore;
use registry_client::RegistryClient;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use tunnel::{TunnelEvent, TunnelManager};

/// Explicit CLI modes - checked before tracing init or `Config::from_env` (TT-1886). Matches argv
/// exactly rather than just scanning for `--generate-identity` anywhere in it: a typo'd flag or
/// `--help` used to silently fall through to the normal startup path and hit the exact
/// `CONNECTOR_ID` dead-end this mode exists to remove (PR #5 review, Tasneem). `args_os` avoids a
/// panic on non-UTF-8 argv that `std::env::args` would produce (same review, nit).
enum CliMode {
    Normal,
    GenerateIdentity,
    Deregister,
    Help,
}

const USAGE: &str = "Usage: secure_connect_connector [--generate-identity | --deregister | --help]\n\n\
With no arguments, runs the Connector daemon (reads its config from the environment).\n\
  --generate-identity  Generate (or load) this Connector's identity keypair, print its\n\
                       public key, and exit. No other config or network calls required.\n\
  --deregister         Deregister this Connector during its guided decommissioning, after an\n\
                       admin confirmed it in the Portal. Reads the daemon's environment and its\n\
                       existing identity key; exits 0 when confirmed, 2 when it is not registered,\n\
                       3 when it is not being decommissioned, 1 on any other error.\n\
  --help, -h           Show this message and exit.";

/// `--deregister` exit codes, read by `install-systemd.sh --decommission` (TT-2126, spec §B.19 point 5).
const EXIT_DEREGISTERED: i32 = 0;
const EXIT_FAILED: i32 = 1;
const EXIT_NOT_REGISTERED: i32 = 2;
const EXIT_NOT_DECOMMISSIONING: i32 = 3;

fn parse_cli_mode(args: std::env::ArgsOs) -> Result<CliMode, String> {
    // `.to_str()` (not `.to_string_lossy()`/`args()`) so a non-UTF-8 argument is gracefully
    // reported as unrecognized instead of panicking or silently mangling it into a match.
    let rest: Vec<std::ffi::OsString> = args.skip(1).collect();
    match rest.as_slice() {
        [] => Ok(CliMode::Normal),
        [only] => match only.to_str() {
            Some("--generate-identity") => Ok(CliMode::GenerateIdentity),
            Some("--deregister") => Ok(CliMode::Deregister),
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
        Ok(CliMode::Deregister) => std::process::exit(deregister().await),
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
            public_key = %connector_identity.public_key_base64,
            "Connector identity ready"
        );
    } else {
        warn!(
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

    let http = build_http_client(&config)?;
    let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
    // TT-3717 (spec §B.4 point 4): proves each heartbeat with its own copy of the identity secret
    // (moved into the tunnel below), keeping each Agent's key-agreement key next to the identity key.
    let agent_directory = AgentDirectory::new(http.clone(), config.agents_json_url.clone())
        .with_request_prover(request_proof::RequestProver::new(
            connector_identity.secret.clone(),
            request_proof::kept_agent_keys_path(&config.identity_key_path),
        ));
    let heartbeat_client = HeartbeatClient::new(http);
    // Kept past the move of connector_identity.secret below: every heartbeat identifies this
    // Connector by it (TT-2210).
    let connector_public_key = connector_identity.public_key_base64.clone();
    let policy_store = Arc::new(PolicyStore::with_live_session_settings(
        config.live_sessions,
    ));
    let audit_log = Arc::new(AuditLog::new(&config.audit_log_path));
    // TT-2464: kept next to the audit log, so undelivered gateway-end reports survive a restart.
    let gateway_end_queue = gateway_end::GatewayEndQueue::load(
        config
            .audit_log_path
            .with_file_name("pending-gateway-end-reports.json"),
    )
    .await;
    // TT-2250 (spec §B.22 point 5): one state file next to the audit log. Connections a previous
    // run left open end now, as `connector_restart`, and its open denial windows close.
    let connection_events = Arc::new(
        connection_events::ConnectionEvents::load(
            config
                .audit_log_path
                .with_file_name("connection-events.json"),
        )
        .await,
    );
    // TT-2250 review: callers change the state in memory only; this task writes it to the file,
    // and a graceful stop flushes what it has not written yet.
    tokio::spawn({
        let connection_events = connection_events.clone();
        async move { connection_events.run_writer().await }
    });
    tokio::spawn({
        let connection_events = connection_events.clone();
        async move {
            shutdown_signal().await;
            info!("stopping - saving the connection-event state");
            // Bounded, so a hanging disk cannot hold the stop until systemd's own timeout.
            if tokio::time::timeout(std::time::Duration::from_secs(5), connection_events.flush())
                .await
                .is_err()
            {
                warn!("stopping without saving the connection-event state: the save took too long");
            }
            std::process::exit(0);
        }
    });
    record_connection_ends(
        &connection_events.restart(chrono::Utc::now().timestamp_millis()),
        &audit_log,
    )
    .await;
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

    // Shared with the flow-admission poller below: only a (node_id, port) pair recorded here by
    // an actual "admit" decision may have its packets forwarded (TT-1732 review, Tasneem finding
    // #1). Created before the startup heartbeat loop below (not after, like the TUN device) since
    // run_heartbeat's node-dialing needs it too, to evict a departed node's flows (TT-1732 review,
    // Tasneem, TT-1847 finding #1).
    let flow_table = Arc::new(std::sync::Mutex::new(FlowTable::new()));
    // Refreshed once per heartbeat cycle in `run_heartbeat`, read synchronously on every
    // decrypted packet in `run_wireguard_receive_loop` (TT-2066) - see `dns_cache`'s module doc.
    let dns_cache = Arc::new(dns_cache::DnsCache::new());

    // TT-2144: created here, before the startup heartbeat loop - unlike the TUN device below, this
    // channel doesn't depend on connector_virtual_ip at all, only on policy_store/audit_log/
    // flow_table (already built above), so admission_pollers can be live from the very first
    // successful heartbeat instead of lagging behind by up to a full heartbeat_interval.
    let (recovered_packet_tx, recovered_packet_rx) =
        tokio::sync::mpsc::unbounded_channel::<(String, Vec<u8>)>();
    let mut admission_pollers = AdmissionPollers::new(
        config.gatekeeper_http_port,
        config.gatekeeper_wg0_address,
        ControlPlaneState {
            policy_store: policy_store.clone(),
            audit_log: audit_log.clone(),
            flow_table: flow_table.clone(),
            recovered_packet_tx,
            connection_events: Some(connection_events.clone()),
        },
    );

    // TT-1838: the TUN device's own address is connector_virtual_ip - Portal's registered,
    // per-Connector control-channel address - not a locally guessed default anymore, so it can
    // only be known once the first heartbeat succeeds. Retries at the configured heartbeat
    // cadence (the same cadence steady-state heartbeats already use) rather than a separate,
    // invented backoff. The heartbeat's other effects (policy application, node dialing, and now
    // syncing admission pollers) also run here on the very first successful attempt - nothing is
    // fetched twice.
    let connector_virtual_ip = loop {
        match run_heartbeat(
            &connector_public_key,
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &gateway_end_queue,
            Some(ConnectionEventsTurn {
                events: &connection_events,
                carry: true,
            }),
        )
        .await
        {
            Ok(Some(ip)) => break ip,
            Ok(None) => {
                warn!(
                    "heartbeat succeeded but Portal has not assigned a connector_virtual_ip yet - cannot create the TUN device until it does, retrying"
                );
            }
            Err(error) => log_heartbeat_failure(
                &error,
                &connector_public_key,
                "initial heartbeat failed - cannot create the TUN device until one succeeds, retrying",
            ),
        }
        tokio::time::sleep(config.heartbeat_interval).await;
    };

    // Real packet forwarding (TT-1827): needs CAP_NET_ADMIN + /dev/net/tun,
    // proven for real via two Docker containers exchanging genuine ICMP
    // traffic through actual WireGuard encryption before this was wired in
    // (see tunnel.rs's module doc comment).
    let (tun_reader, tun_writer) = tun_device::create(
        connector_virtual_ip,
        config.tun_netmask,
        1400,
        config.gatekeeper_wg0_address,
    )
    .context("failed to create the Connector's TUN device")?;
    info!(tun_addr = %connector_virtual_ip, tun_netmask = %config.tun_netmask, "TUN device ready");

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

    // TT-2144: no inbound listener for flow-admission/release at all anymore - `admission_pollers`
    // (constructed above, synced on every `run_heartbeat` call including the startup one) already
    // has one poll task running per node in the current node_list by this point.

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
    // TT-3770 (spec §B.9 point 1): an admission with an entitled key and an unknown session digest
    // asks for one heartbeat off schedule. One runs at a time (this loop runs one heartbeat at a
    // time), at most one starts per minimum interval, and after a failure the gap doubles, up to
    // the regular interval.
    let mut off_schedule = live_sessions::OffSchedule::new(
        config.live_sessions.off_schedule_min_interval,
        config.heartbeat_interval,
    );
    loop {
        // Biased to the regular tick: when both are due, one heartbeat answers both.
        let off_schedule_run = tokio::select! {
            biased;
            _ = interval.tick() => false,
            _ = off_schedule.ready(policy_store.live_sessions()) => true,
        };
        let result = run_heartbeat(
            &connector_public_key,
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &gateway_end_queue,
            // TT-2250 (spec §B.22 point 5): an off-schedule heartbeat carries no connection events,
            // so it stays quick; it still ends the connections it observes.
            Some(ConnectionEventsTurn {
                events: &connection_events,
                carry: !off_schedule_run,
            }),
        )
        .await;
        // A successful heartbeat of either kind ends any backoff; a failed off-schedule one extends it.
        if result.is_ok() || off_schedule_run {
            off_schedule.ran(result.is_ok());
        }
        match result {
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
                log_heartbeat_failure(&error, &connector_public_key, "heartbeat cycle failed")
            }
        }
    }
}

/// Resolves on SIGTERM (systemd's stop) or Ctrl-C. Without a handler either would end the process
/// before the connection-event writer saved its last changes (TT-2250 review).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(error) => {
                warn!(%error, "cannot listen for SIGTERM - only Ctrl-C saves the connection-event state before stopping");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// "Not registered" is the expected state between install and the admin pasting this Connector's
/// public key into Portal (TT-2210, spec §B.4 point 1) - said plainly, with the key to paste, rather
/// than logged as a failure. Anything else is a real failure.
fn log_heartbeat_failure(error: &anyhow::Error, connector_public_key: &str, message: &str) {
    if error
        .downcast_ref::<AgentRejected>()
        .is_some_and(AgentRejected::is_not_registered)
    {
        info!(
            public_key = %connector_public_key,
            "not registered - if this is a new install, paste this public key into Portal's Deploy Connector screen and the Connector activates on its next heartbeat; if it was active before, its registration was removed in Portal"
        );
    } else {
        error!(error = %format!("{error:#}"), "{message}");
    }
}

/// The HTTP client the daemon and `--deregister` share: the default trust plus any `CONNECTOR_CA_BUNDLE_PATH` roots,
/// and a bounded connect.
fn build_http_client(config: &Config) -> anyhow::Result<reqwest::Client> {
    // TT-2027: CONNECTOR_CA_BUNDLE_PATH, when set, adds one or more extra trusted root CAs on
    // top of the default trust (Mozilla's bundled roots plus, via rustls-tls-native-roots, the
    // box's own OS trust store) - never a replacement for it, and never `danger_accept_invalid_certs`.
    //
    // connect_timeout (TT-2210): a rotated-away Agent's address often just drops packets, and with
    // no bound a single connect attempt there would stall the whole heartbeat cycle - and the
    // failover to the next operational Agent with it. Each call adds its own overall timeout.
    let mut http_builder = reqwest::Client::builder().connect_timeout(Duration::from_secs(5));
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
    http_builder
        .build()
        .with_context(|| match &config.ca_bundle_path {
            Some(path) => format!(
                "failed to build the HTTP client - check that every certificate in \
             CONNECTOR_CA_BUNDLE_PATH ({}) is structurally valid DER, not just well-formed PEM",
                path.display()
            ),
            None => "failed to build the HTTP client".to_string(),
        })
}

/// `--deregister` (TT-2126, spec §B.19 points 4-5): deregisters this Connector through the first answering Agent and
/// returns the exit code `install-systemd.sh --decommission` acts on. Never generates an identity.
async fn deregister() -> i32 {
    let outcome = async {
        let config = Config::from_env()?;
        let identity = identity::load_existing(&config.identity_key_path)?;
        let http = build_http_client(&config)?;
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        // TT-3717: proven like the heartbeat, with the daemon's kept Agent keys - read only, as this
        // runs as root while the daemon still runs (install-systemd.sh --decommission).
        let agent_directory = AgentDirectory::new(http.clone(), config.agents_json_url.clone())
            .with_request_prover(request_proof::RequestProver::read_only(
                identity.secret.clone(),
                request_proof::kept_agent_keys_path(&config.identity_key_path),
            ));
        let heartbeat_client = HeartbeatClient::new(http);
        agent_directory
            .deregister(
                &registry_client,
                &heartbeat_client,
                &dto::ConnectorDeregisterRequest {
                    connector_public_key: identity.public_key_base64.clone(),
                },
            )
            .await
    }
    .await;
    match outcome {
        Ok(confirmed) => {
            println!("Connector {} deregistered.", confirmed.connector_id);
            EXIT_DEREGISTERED
        }
        Err(error) => match error.downcast_ref::<heartbeat::AgentRejected>() {
            Some(rejected) if rejected.is_not_registered() => {
                eprintln!("This Connector is not registered - nothing to deregister.");
                EXIT_NOT_REGISTERED
            }
            Some(rejected) if rejected.is_not_decommissioning() => {
                eprintln!(
                    "This Connector is not being decommissioned. Confirm Decommission Connector in the Portal first, then run this again."
                );
                EXIT_NOT_DECOMMISSIONING
            }
            _ => {
                eprintln!("Deregistration failed: {error:#}");
                EXIT_FAILED
            }
        },
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

/// TT-2250: what one heartbeat does with the connection events - `carry` false on an off-schedule
/// heartbeat, which sends none but still ends the connections it observes (spec §B.22 point 5).
struct ConnectionEventsTurn<'a> {
    events: &'a connection_events::ConnectionEvents,
    carry: bool,
}

/// TT-2250 (spec §B.22 point 2): what this heartbeat observed ending `connection`, the first that
/// applies in this order: its gateway left the bundles, its device left the gateway's list, its
/// session's digest left the accepted snapshot, its node left the node list. With the number of flows
/// a removal closed.
fn observe_connection_end(
    connection: &connection_events::OpenConnection,
    new_bundles: &[PolicyBundle],
    removal_flows: &std::collections::HashMap<(String, String), usize>,
    accepted_snapshot: Option<&live_sessions::LiveSessions>,
    dropped_nodes: &std::collections::HashSet<&str>,
) -> Option<(connection_events::Observation, usize)> {
    use connection_events::Observation;
    let flows = || {
        removal_flows
            .get(&(
                connection.gateway_id.clone(),
                connection.device_public_key.clone(),
            ))
            .copied()
            .unwrap_or(0)
    };
    let Some(bundle) = new_bundles
        .iter()
        .find(|bundle| bundle.gateway_id == connection.gateway_id)
    else {
        return Some((Observation::GatewayRemoved, flows()));
    };
    let entitled = bundle
        .entitlement_list
        .iter()
        .any(|e| e.device_public_key.as_deref() == Some(connection.device_public_key.as_str()));
    if !entitled {
        return Some((Observation::EntitlementRemoved, flows()));
    }
    if let Some(sessions) = accepted_snapshot
        && !sessions.is_live(
            &connection.device_public_key,
            connection.session_digest.as_deref(),
        )
    {
        return Some((Observation::SessionEnded, 0));
    }
    if dropped_nodes.contains(connection.node_id.as_str()) {
        return Some((Observation::NodeRemoved, 0));
    }
    None
}

/// TT-2250 (spec §B.10, §B.22 point 4): one `connection_ended` entry per connection that ended.
async fn record_connection_ends(
    ended: &[connection_events::EndedConnection],
    audit_log: &AuditLog,
) {
    for connection in ended {
        let event = AuditEvent::ConnectionEnded {
            connection_id: connection.connection_id.clone(),
            gateway_id: connection.gateway_id.clone(),
            device_public_key: connection.device_public_key.clone(),
            observation: connection.observation.as_str().to_string(),
            report_id: connection.report_id.clone(),
        };
        if let Err(error) = audit_log.record(event).await {
            error!(%error, "failed to write connection-ended audit entry");
        }
    }
}

/// TT-2250 (spec §B.22 point 4): with connection events, the `FlowsEnded` entry of an entitlement
/// refresh carries the `report_id` of the connection's removal end instead of a gateway-end report's.
/// A device with no open connection keeps the refresh's own id, as no event is sent for it.
async fn record_flows_ended(
    removals: &[gateway_end::GatewayEndReport],
    ended: &[connection_events::EndedConnection],
    new_bundles: &[PolicyBundle],
    events: &connection_events::ConnectionEvents,
    audit_log: &AuditLog,
) {
    for removal in removals {
        let matched = ended
            .iter()
            .filter(|c| c.observation.is_removal())
            .find(|c| {
                c.gateway_id == removal.gateway_id
                    && c.device_public_key == removal.device_public_key
            })
            .and_then(|c| c.report_id.clone());
        // No open connection took this removal (its flow was admitted while the connection was
        // still being opened): the notice still needs an end, so a notice-only one is queued.
        let report_id = match matched {
            Some(report_id) => report_id,
            None => {
                events.notice_only_end(
                    &removal.gateway_id,
                    &removal.device_public_key,
                    &removal.user_id,
                    // The whole gateway left the bundles (deleted, disabled, moved, blocked):
                    // the Portal decides from that whether a notice is due (§B.22 point 7).
                    if new_bundles
                        .iter()
                        .any(|b| b.gateway_id == removal.gateway_id)
                    {
                        connection_events::Observation::EntitlementRemoved
                    } else {
                        connection_events::Observation::GatewayRemoved
                    },
                    removal.flows_ended,
                    removal.ended_at,
                )
            }
        };
        let event = AuditEvent::FlowsEnded {
            gateway_id: removal.gateway_id.clone(),
            user_id: removal.user_id.clone(),
            device_public_key: removal.device_public_key.clone(),
            flows_ended: removal.flows_ended,
            report_id,
        };
        if let Err(error) = audit_log.record(event).await {
            error!(%error, "failed to write flows-ended audit entry");
        }
    }
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
    connector_public_key: &str,
    agent_directory: &AgentDirectory,
    registry_client: &RegistryClient,
    heartbeat_client: &HeartbeatClient,
    policy_store: &PolicyStore,
    audit_log: &AuditLog,
    tunnel_manager: &Mutex<TunnelManager>,
    wg_socket: &UdpSocket,
    flow_table: &std::sync::Mutex<FlowTable>,
    dns_cache: &dns_cache::DnsCache,
    admission_pollers: &mut AdmissionPollers,
    gateway_end_queue: &gateway_end::GatewayEndQueue,
    connection_events: Option<ConnectionEventsTurn<'_>>,
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
    // TT-2464: every gateway-end report not yet delivered, including ones from before a restart.
    let ended_flows = gateway_end_queue
        .pending(chrono::Utc::now().timestamp_millis())
        .await;
    let sent_report_ids: Vec<String> = ended_flows
        .iter()
        .map(|report| report.report_id.clone())
        .collect();
    // TT-2250 (spec §B.22 point 5): after an upgrade, gateway-end reports still queued go first, and
    // this heartbeat carries no connection events until that old queue is empty.
    let mut connection_batch = match &connection_events {
        Some(turn) if turn.carry && ended_flows.is_empty() => {
            Some(turn.events.batch(chrono::Utc::now().timestamp_millis()))
        }
        _ => None,
    };
    let mut request = dto::ConnectorHeartbeatRequest {
        connector_public_key: connector_public_key.to_string(),
        unresolved_endpoint_hosts,
        ended_flows,
        connection_events: Vec::new(),
        connection_events_lost: connection_batch
            .as_ref()
            .and_then(|batch| batch.lost.clone()),
    };
    // TT-2250 review (spec §B.22 point 5): only the events that fit the Agent's body limit go;
    // the rest stay queued for the next heartbeat, and only those sent get results applied.
    if let Some(batch) = connection_batch.as_mut() {
        let fitting = connection_events_within_body_limit(
            &request,
            &batch.events,
            dto::HEARTBEAT_BODY_BUDGET_BYTES,
        );
        if fitting < batch.events.len() {
            warn!(
                sent = fitting,
                held = batch.events.len() - fitting,
                "connection events over the heartbeat body limit - the rest go on the next heartbeat"
            );
            batch.events.truncate(fitting);
        }
        request.connection_events = batch.events.clone();
    }

    // TT-3770: this heartbeat's reply answers every off-schedule request made before it is sent, and
    // its snapshot counts for every admission that arrived before then.
    policy_store.live_sessions().clear_refresh_request();
    let requested_at = std::time::Instant::now();
    let response = agent_directory
        .heartbeat(registry_client, heartbeat_client, &request)
        .await?;

    // A verified response means Agent relayed the request to Portal, which processed it: the
    // reports it carried are delivered, whatever happens to this package below. Portal accepts a
    // report_id once, so a resend after a failed write here is harmless.
    if let Err(error) = gateway_end_queue.acknowledge(&sent_report_ids).await {
        warn!(%error, "failed to save the gateway-end report queue after delivery");
    }
    // TT-2250 (spec §B.22 point 6): only the Portal's result removes a connection event; a reply
    // without results keeps every one, as `retry`.
    if let (Some(turn), Some(batch)) = (&connection_events, &connection_batch) {
        let results = response
            .connection_event_results
            .clone()
            .unwrap_or_default();
        let applied = turn.events.apply_results(batch, &results);
        for report_id in applied.rejected {
            warn!(%report_id, "Portal rejected a connection event - not sending it again");
            if let Err(error) = audit_log
                .record(AuditEvent::ConnectionEventRejected { report_id })
                .await
            {
                error!(%error, "failed to write connection-event-rejected audit entry");
            }
        }
    }

    let connector_id = response.connector_id.clone();

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
    let apply_result = policy_store.apply_requested_at(response, requested_at);

    // Audited either way (TT-1820), and best-effort: a failure to *write* the
    // audit entry must not itself change or hide the underlying apply outcome.
    let audit_event = match &apply_result {
        Ok(_) => AuditEvent::PolicyApplied {
            connector_id: connector_id.clone(),
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

    let snapshot_update = apply_result?;
    record_snapshot_update(&snapshot_update, audit_log).await;

    // TT-2520: only once the package is in force - a rejected one wrote `PolicyRejected` above and
    // put nothing in force, so it writes neither of these.
    for event in bundle_audit_events(old_bundles.as_deref(), &new_bundles) {
        if let Err(audit_error) = audit_log.record(event).await {
            error!(error = %audit_error, "failed to write policy bundle audit entry");
        }
    }

    info!(gateways, nodes, "Applied verified heartbeat package");
    if nodes_without_key > 0 {
        warn!(
            nodes_without_key,
            "some nodes have no reported WireGuard public key yet - cannot be dialed until Orchestrator reports one"
        );
    }

    let dropped_nodes = dial_new_nodes(tunnel_manager, wg_socket, &node_list, flow_table).await;
    for (node_id, flows_ended) in dropped_nodes.iter().filter(|(_, ended)| *ended > 0) {
        if let Err(error) = audit_log
            .record(AuditEvent::FlowsEndedByNodeRemoval {
                node_id: node_id.clone(),
                flows_ended: *flows_ended,
            })
            .await
        {
            error!(%error, "failed to write node-removal flows-ended audit entry");
        }
    }
    // TT-2144: independent of WireGuard tunnel state - see admission_poller's module doc for why.
    admission_pollers.sync(&connector_id, &node_list);
    let mut removal_flows: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    let mut removal_reports: Vec<gateway_end::GatewayEndReport> = Vec::new();
    if let Some(old_bundles) = old_bundles {
        let reports = reconcile_dropped_entitlements(
            flow_table,
            &old_bundles,
            &new_bundles,
            chrono::Utc::now().timestamp_millis(),
        );
        if connection_events.is_some() {
            // TT-2250 (spec §B.22 point 5): the removal ends of the connection events are these
            // reports now; they are queued below, as connections end.
            for report in &reports {
                removal_flows.insert(
                    (report.gateway_id.clone(), report.device_public_key.clone()),
                    report.flows_ended,
                );
            }
            removal_reports = reports;
        } else {
            queue_gateway_end_reports(reports, audit_log, gateway_end_queue).await;
        }
        for event in reconcile_gateway_address_changes(flow_table, &old_bundles, &new_bundles) {
            if let Err(error) = audit_log.record(event).await {
                error!(%error, "failed to write address-change flows-ended audit entry");
            }
        }
    }
    // TT-3770 (spec §B.9 point 1): after the entitlement check above, so a revoked entitlement still
    // ends its flows with a gateway-end report; then the flows whose session the fresh snapshot no
    // longer holds end, with a local audit entry of their own and no report.
    if matches!(
        snapshot_update,
        live_sessions::SnapshotUpdate::Accepted { .. }
    ) {
        for event in reconcile_lease_ends(flow_table, policy_store.live_sessions()) {
            if let Err(error) = audit_log.record(event).await {
                error!(%error, "failed to write lease-end flows-ended audit entry");
            }
        }
    }
    for event in reconcile_endpoint_changes(flow_table, &new_bundles) {
        if let Err(error) = audit_log.record(event).await {
            error!(%error, "failed to write rule-change flows-ended audit entry");
        }
    }
    if let Some(turn) = &connection_events {
        let snapshot_accepted = matches!(
            snapshot_update,
            live_sessions::SnapshotUpdate::Accepted { .. }
        );
        let dropped: std::collections::HashSet<&str> = dropped_nodes
            .iter()
            .map(|(node_id, _)| node_id.as_str())
            .collect();
        let ended =
            turn.events
                .end_connections(chrono::Utc::now().timestamp_millis(), |connection| {
                    observe_connection_end(
                        connection,
                        &new_bundles,
                        &removal_flows,
                        snapshot_accepted.then_some(policy_store.live_sessions()),
                        &dropped,
                    )
                });
        record_flows_ended(
            &removal_reports,
            &ended,
            &new_bundles,
            turn.events,
            audit_log,
        )
        .await;
        record_connection_ends(&ended, audit_log).await;
        let dropped_events = turn.events.take_unlogged_drops();
        if dropped_events > 0 {
            warn!(
                dropped_events,
                "connection events dropped unsent - counted as lost"
            );
            if let Err(error) = audit_log
                .record(AuditEvent::ConnectionEventsDropped {
                    count: dropped_events,
                })
                .await
            {
                error!(%error, "failed to write connection-events-dropped audit entry");
            }
        }
    }

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
        .flat_map(|bundle| bundle.rules())
        .map(|rule| rule.internal_host)
        .collect()
}

/// Which of `bundles`' endpoint hosts `dns_cache` currently has no resolved address for - the
/// input to `ConnectorHeartbeatRequest::unresolved_endpoint_hosts` (TT-2069). A literal IPv4 host
/// can never appear here: `DnsCache::resolve` always resolves one immediately, with no lookup at
/// all. Deduplicated and sorted *before* the cache lookups (review finding #5) - the same
/// unresolved host commonly appears on more than one gateway's endpoint list, and there is no
/// reason to take `dns_cache`'s lock more than once per distinct host.
///
/// Capped at the first `MAX_UNRESOLVED_ENDPOINT_HOSTS` in that sorted order, as the Agent caps it
/// (TT-2250 review, spec §B.22 point 5): the heartbeat's size budget counts on it.
fn unresolved_hosts_in(bundles: &[PolicyBundle], dns_cache: &dns_cache::DnsCache) -> Vec<String> {
    let mut hosts = collect_endpoint_hosts(bundles);
    // As the Agent cleans the list before its cap: no blank names, none over 255 characters.
    hosts.retain(|host| {
        !host.trim().is_empty() && host.len() <= dto::MAX_UNRESOLVED_ENDPOINT_HOST_LENGTH
    });
    hosts.sort();
    hosts.dedup();
    hosts.retain(|host| dns_cache.resolve(host).is_none());
    hosts.truncate(dto::MAX_UNRESOLVED_ENDPOINT_HOSTS);
    hosts
}

/// TT-2250 review (spec §B.22 point 5): how many of `events`, from the front, fit `request` within
/// `budget` bytes once serialised - the whole request, unresolved hosts and lost report included.
/// Without this, 200 events and a long host list could exceed the Agent's body limit, which refuses
/// the whole heartbeat, its policy and snapshot refresh included, and the same batch would be sent
/// again on every heartbeat. A prefix keeps the batch's order rules: every end stays right after
/// its establishment and every follow-up after its first denial.
fn connection_events_within_body_limit(
    request: &dto::ConnectorHeartbeatRequest,
    events: &[connection_events::ConnectionEvent],
    budget: usize,
) -> usize {
    debug_assert!(request.connection_events.is_empty());
    let Ok(base) = serde_json::to_vec(request) else {
        return 0;
    };
    // `,"connection_events":[]` around the events, and a comma between two.
    let mut size = base.len() + r#","connection_events":[]"#.len();
    let mut fitting = 0;
    for (index, event) in events.iter().enumerate() {
        let Ok(bytes) = serde_json::to_vec(event) else {
            break;
        };
        size += bytes.len() + usize::from(index > 0);
        if size > budget {
            break;
        }
        fitting += 1;
    }
    fitting
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
///
/// Returns one gateway-end report per gateway and device whose admitted flow(s) it actually tore
/// down (TT-2464, spec §B.18) - none for a device that had no admitted flow, since the event must
/// never be emitted merely because an entitlement changed.
fn reconcile_dropped_entitlements(
    flow_table: &std::sync::Mutex<FlowTable>,
    old_bundles: &[PolicyBundle],
    new_bundles: &[PolicyBundle],
    now_ms: i64,
) -> Vec<gateway_end::GatewayEndReport> {
    let mut reports = Vec::new();
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
                reports.push(gateway_end::GatewayEndReport {
                    report_id: gateway_end::new_report_id(),
                    gateway_id: old_bundle.gateway_id.clone(),
                    user_id: entitlement.user_id.clone(),
                    device_public_key: device_public_key.to_string(),
                    ended_at: now_ms,
                    flows_ended: evicted,
                });
            }
        }
    }
    reports
}

/// Audits and queues the reports `reconcile_dropped_entitlements` produced (spec §B.10, §B.18).
/// Both are best-effort: neither failure may undo the flow teardown that already happened. A
/// queue-file write failure still leaves the reports queued in memory for the next heartbeat.
async fn queue_gateway_end_reports(
    reports: Vec<gateway_end::GatewayEndReport>,
    audit_log: &AuditLog,
    gateway_end_queue: &gateway_end::GatewayEndQueue,
) {
    for report in &reports {
        let event = AuditEvent::FlowsEnded {
            gateway_id: report.gateway_id.clone(),
            user_id: report.user_id.clone(),
            device_public_key: report.device_public_key.clone(),
            flows_ended: report.flows_ended,
            report_id: report.report_id.clone(),
        };
        if let Err(error) = audit_log.record(event).await {
            error!(%error, "failed to write flows-ended audit entry");
        }
    }
    if let Err(error) = gateway_end_queue.enqueue(reports).await {
        error!(%error, "failed to save the gateway-end report queue - reports stay queued in memory only");
    }
}

/// The per-gateway entries spec §B.10 requires for a just-applied heartbeat package (TT-2520):
/// `PolicyBundleApplied` for each gateway whose effective configuration is new or changed since
/// `old_bundles` (every gateway before the first package), and `EntitlementListReceived` for every
/// gateway on every heartbeat.
fn bundle_audit_events(
    old_bundles: Option<&[PolicyBundle]>,
    new_bundles: &[PolicyBundle],
) -> Vec<AuditEvent> {
    // The rules, not the transitional endpoints: they are what the Connector forwards by (TT-2514).
    let configuration = |bundle: &PolicyBundle| {
        (
            bundle.location.clone(),
            bundle.hostname.clone(),
            bundle.rules(),
            bundle.gateway_address,
        )
    };
    let mut events = Vec::new();
    for bundle in new_bundles {
        let unchanged = old_bundles
            .and_then(|old| old.iter().find(|o| o.gateway_id == bundle.gateway_id))
            .is_some_and(|old| configuration(old) == configuration(bundle));
        if !unchanged {
            events.push(AuditEvent::PolicyBundleApplied {
                gateway_id: bundle.gateway_id.clone(),
                location: bundle.location.clone(),
                hostname: bundle.hostname.clone(),
                port_rules: bundle.rules(),
                gateway_address: bundle.gateway_address,
            });
        }
        events.push(AuditEvent::EntitlementListReceived {
            gateway_id: bundle.gateway_id.clone(),
            entitlement_count: bundle.entitlement_list.len(),
            entitlement_list_sha256: entitlement_list_sha256(&bundle.entitlement_list),
        });
    }
    events
}

/// SHA-256 (hex) of an entitlement list, independent of the order Portal happened to list it in:
/// the same set of (user, device) pairs always hashes the same. Each pair is JSON-encoded, so no
/// choice of user id or key can make two different lists encode identically.
fn entitlement_list_sha256(entitlements: &[dto::Entitlement]) -> String {
    let mut pairs: Vec<(&str, Option<&str>)> = entitlements
        .iter()
        .map(|e| (e.user_id.as_str(), e.device_public_key.as_deref()))
        .collect();
    pairs.sort_unstable();
    let encoded = serde_json::to_vec(&pairs).expect("string pairs always serialize");
    hex::encode(ring::digest::digest(&ring::digest::SHA256, &encoded))
}

/// Refreshes already-admitted flows' remembered port rules (endpoints before TT-2514) to this
/// heartbeat's freshly-applied bundles (TT-2046 review finding #4): unlike entitlements, they were only ever snapshotted
/// once at admission and never revisited, so an admin repointing or removing a gateway's endpoint
/// kept every flow admitted before the change forwarding to the old address until the flow ended on
/// its own. Runs every heartbeat, independent of `old_bundles` (there's no diffing to do - this
/// just always brings `flow_table` up to date with the latest configured rules, a no-op for any
/// gateway with nothing currently admitted). See `FlowTable::update_rules`.
///
/// TT-3449: returns one audit entry per gateway whose refreshed rules ended open flows (spec §B.10);
/// no gateway-end report is queued for them (§B.18).
/// TT-3770 (spec §B.9 point 1, §B.10): ends every open flow whose session the just-accepted
/// live-session snapshot no longer holds - a reconnect, a disconnect or a lease end - and returns one
/// `FlowsEndedByLeaseEnd` entry per gateway and device. A flow admitted without a session digest (before
/// the first snapshot, or from signed data without a token) ends here too.
fn reconcile_lease_ends(
    flow_table: &std::sync::Mutex<FlowTable>,
    sessions: &live_sessions::LiveSessions,
) -> Vec<AuditEvent> {
    let ended = flow_table
        .lock()
        .expect("flow table lock poisoned")
        .end_flows_without_live_session(|key, digest| sessions.is_live(key, digest));
    let mut by_gateway_device: std::collections::BTreeMap<(String, String), Vec<audit::EndedFlow>> =
        std::collections::BTreeMap::new();
    for flow in ended {
        by_gateway_device
            .entry((flow.gateway_id, flow.device_public_key.clone()))
            .or_default()
            .push(audit::EndedFlow {
                flow_id: flow.flow_id,
                device_public_key: flow.device_public_key,
            });
    }
    by_gateway_device
        .into_iter()
        .map(|((gateway_id, device_public_key), flows)| {
            info!(
                %gateway_id,
                flows_ended = flows.len(),
                "session no longer live: ended its open flow(s)"
            );
            AuditEvent::FlowsEndedByLeaseEnd {
                gateway_id,
                device_public_key,
                flows_ended: flows.len(),
                flows,
            }
        })
        .collect()
}

/// TT-3770 (spec §B.9 point 1): a refused or missing snapshot is logged and written to the local
/// audit log - the Connector's own record (§B.10) - since the last accepted snapshot stays in use.
async fn record_snapshot_update(update: &live_sessions::SnapshotUpdate, audit_log: &AuditLog) {
    let event = match update {
        live_sessions::SnapshotUpdate::Refused { entries, limit } => {
            warn!(
                entries,
                limit,
                "live-session snapshot is over its size limit - refused it whole and kept the last one"
            );
            AuditEvent::LiveSessionSnapshotRefused {
                entries: *entries,
                limit: *limit,
            }
        }
        live_sessions::SnapshotUpdate::Missing => {
            warn!("heartbeat carried no live-session snapshot - kept the last one");
            AuditEvent::LiveSessionSnapshotMissing
        }
        _ => return,
    };
    if let Err(error) = audit_log.record(event).await {
        error!(%error, "failed to write live-session snapshot audit entry");
    }
}

fn reconcile_endpoint_changes(
    flow_table: &std::sync::Mutex<FlowTable>,
    new_bundles: &[PolicyBundle],
) -> Vec<AuditEvent> {
    let mut table = flow_table.lock().expect("flow table lock poisoned");
    table.retain_gateway_rules(|gateway_id| {
        new_bundles
            .iter()
            .any(|bundle| bundle.gateway_id == gateway_id)
    });
    let mut events = Vec::new();
    for bundle in new_bundles {
        let ended = table.update_rules(&bundle.gateway_id, &bundle.rules());
        if ended.is_empty() {
            continue;
        }
        info!(
            gateway_id = %bundle.gateway_id,
            flows_ended = ended.len(),
            "port rule removed: ended the open flow(s) it served"
        );
        events.push(AuditEvent::FlowsEndedByRuleChange {
            gateway_id: bundle.gateway_id.clone(),
            flows_ended: ended.len(),
            flows: ended
                .into_iter()
                .map(|flow| audit::EndedFlow {
                    flow_id: flow.flow_id,
                    device_public_key: flow.device_public_key,
                })
                .collect(),
        });
    }
    events
}

/// Ends the open flows to a gateway's old address when this heartbeat changed it (TT-3699, spec
/// §B.20.3): the spec decides that changing the address is a configuration change and that open
/// flows to the old address end at the Connector's next heartbeat. On the first Portal address this
/// includes, once, the flows of a node that refused it and keeps the gateway on its pool address.
/// Diffs old vs. new per gateway, like `reconcile_dropped_entitlements`; a gateway new on this
/// heartbeat has no flow to end, and an unchanged address ends nothing. See
/// `FlowTable::end_flows_to_old_address` for which flows end. Admissions that arrive after the
/// change are not re-checked against the address.
///
/// Returns one audit entry per gateway whose change ended open flows (spec §B.10); no gateway-end
/// report is queued for them (§B.18): changing the address is a configuration change, not a
/// withdrawal of the user's access.
fn reconcile_gateway_address_changes(
    flow_table: &std::sync::Mutex<FlowTable>,
    old_bundles: &[PolicyBundle],
    new_bundles: &[PolicyBundle],
) -> Vec<AuditEvent> {
    let mut table = flow_table.lock().expect("flow table lock poisoned");
    let mut events = Vec::new();
    for bundle in new_bundles {
        let Some(old_bundle) = old_bundles
            .iter()
            .find(|old| old.gateway_id == bundle.gateway_id)
        else {
            continue;
        };
        let ended = table.end_flows_to_old_address(
            &bundle.gateway_id,
            old_bundle.gateway_address,
            bundle.gateway_address,
        );
        if ended.is_empty() {
            continue;
        }
        info!(
            gateway_id = %bundle.gateway_id,
            old_gateway_address = ?old_bundle.gateway_address,
            gateway_address = ?bundle.gateway_address,
            flows_ended = ended.len(),
            "gateway address changed: ended the open flow(s) to the old address"
        );
        events.push(AuditEvent::FlowsEndedByAddressChange {
            gateway_id: bundle.gateway_id.clone(),
            old_gateway_address: old_bundle.gateway_address,
            gateway_address: bundle.gateway_address,
            flows_ended: ended.len(),
            flows: ended
                .into_iter()
                .map(|flow| audit::EndedFlow {
                    flow_id: flow.flow_id,
                    device_public_key: flow.device_public_key,
                })
                .collect(),
        });
    }
    events
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
) -> Vec<(String, usize)> {
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
    // TT-2250: returned with the number of flows each eviction ended, for the local audit log and
    // the connection events (spec §B.22 point 4).
    let mut evicted = Vec::new();
    if !dropped.is_empty() {
        let mut table = flow_table.lock().expect("flow table lock poisoned");
        for node_id in &dropped {
            info!(%node_id, "node no longer present in heartbeat's node list - evicting its admitted flows");
            let ended = table.evict_node(node_id);
            evicted.push((node_id.clone(), ended));
        }
    }

    for (packet, addr, node_id) in handshakes_to_send {
        if let Err(error) = wg_socket.send_to(&packet, addr).await {
            error!(%error, %node_id, %addr, "failed to send WireGuard handshake initiation");
        }
    }
    evicted
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
///   (DNS-resolution only - see `FlowTable::forward`'s doc comment), so forwarding it
///   unchanged could never have reached anywhere real even before TT-2046's admission check
///   existed. `FlowTable::forward` resolves the real address and port by matching the packet's
///   transport and destination *port* (never translated by Gatekeeper, so it's the client's real
///   intent) against the entitled gateway's port rules (TT-2514); `tunnel::rewrite_destination_ipv4`
///   and `tunnel::rewrite_destination_port` do the actual byte-level rewrite, including the checksum
///   fixups.
///
/// Returns `true` (packet mutated in place if a rewrite was needed, ready to write to TUN
/// as-is) or `false` (packet must not be forwarded - left completely untouched: every check here
/// and in `tunnel::rewrite_destination_ipv4` runs before either one writes a single byte, so
/// there's no partial-rewrite state to worry about).
/// Logs why an admitted flow's packet can't be forwarded - shared by the dialled (TT-2639) and the
/// node/port paths of `prepare_decrypted_packet_for_forwarding`.
fn warn_unforwardable(outcome: ForwardOutcome, node_id: &str, source_port: u16, dst_port: u16) {
    match outcome {
        ForwardOutcome::PortNotConfigured => {
            // Debug, not warn: the flow's admission already warned once, in the log and the local audit
            // log - that no single rule serves it, or, for a flow from a node without the dialled
            // identity, that only rules with equal ports serve it. It lasts until Gatekeeper releases
            // it (spec §B.9 point 4).
            debug!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted, but its gateway has no port rule for this transport and port - dropping");
        }
        ForwardOutcome::AmbiguousEndpoint => {
            warn!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted, but more than one port rule matches this transport and port - refusing to guess, dropping");
        }
        ForwardOutcome::HostUnresolved => {
            warn!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted and a port rule matches, but its internal host hasn't resolved to an address yet - dropping");
        }
        ForwardOutcome::PortTranslationNeedsUpdatedNode => {
            warn!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted, but its port rule translates the port and the flow came from a node that predates the dialled identity, whose replies could not get the port back - dropping until the node is updated (TT-2514)");
        }
        ForwardOutcome::NoFreeSourcePort => {
            error!(%node_id, source_port, dst_port, "decrypted packet's flow is admitted, but every source port toward its internal host:port is in use - dropping until one is freed (TT-2639)");
        }
        ForwardOutcome::NotAdmitted | ForwardOutcome::Forward(_) => {
            warn!(%node_id, source_port, dst_port, ?outcome, "decrypted packet can't be forwarded - dropping");
        }
    }
}

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
        //
        // TT-2297: except a reply on one of this Connector's OWN outbound connections (its
        // destination port is one the admission poller registered). Its source port is
        // Gatekeeper's fixed HTTP port, the same on every node, so recording it would claim that
        // port for this node and misroute every other node's polls.
        if let Some(source_port) = tunnel::parse_source_port(packet) {
            let is_reply_to_own_connection =
                tunnel::parse_destination_port(packet).is_some_and(|port| {
                    flow_table
                        .node_for_outbound_control_channel_source_port(port)
                        .is_some()
                });
            if !is_reply_to_own_connection {
                flow_table.record_control_channel_port(node_id, source_port);
            }
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

    // TT-2639 (spec §B.8): a flow is identified by what the user dialled too, read from the packet
    // itself - so a packet addressed to one gateway can never match a flow admitted for another.
    let dialled = match (
        tunnel::parse_ipv4_transport(packet),
        tunnel::parse_destination_ipv4(packet),
    ) {
        (Some(transport), Some(gateway_address)) => Some(Dialled {
            transport,
            gateway_address,
            destination_port: dst_port,
        }),
        _ => None,
    };
    let (real_dst, internal_port, allocated_port) = match flow_table.forward(
        node_id,
        source_port,
        dialled,
        dst_port,
        dns_cache,
    ) {
        Forwarding::Forward {
            address,
            destination_port: internal_port,
            source_port: allocated_port,
        } => (address, internal_port, allocated_port),
        Forwarding::NotAdmitted
            if flow_table.is_rule_ended(node_id, source_port, dialled, Instant::now()) =>
        {
            // TT-3449: its rule was removed and the flow ended; the user's side keeps sending until it
            // gives up. Dropped quietly - no admission is coming, so nothing to buffer or warn about.
            debug!(%node_id, source_port, dst_port, "dropped a packet of a flow its removed port rule ended");
            return false;
        }
        Forwarding::NotAdmitted => {
            // Not necessarily gone for good (2026-09-22 session notes): Gatekeeper forwards a
            // new flow's raw packets independently of, and often slightly before, the
            // admission relay that decides whether it's allowed - buffer this one briefly in
            // case that decision is already in flight (see PENDING_PACKET_TTL's doc) instead of
            // losing it outright. run_wireguard_receive_loop's admission-recovery arm is what
            // reclaims it, not here. TT-2639: held under its dialled identity when readable, so
            // only exactly that flow's admission reclaims it - including a packet the
            // transition rule kept off a flow admitted before its node was updated.
            flow_table.buffer_pending(
                node_id,
                source_port,
                dialled,
                packet.to_vec(),
                Instant::now(),
            );
            warn!(%node_id, source_port, dst_port, "decrypted packet has no admitted flow for this node, port and gateway yet - buffering briefly in case admission is already in flight");
            return false;
        }
        // Genuinely different situations (TT-2046 review finding #5), each its own message.
        Forwarding::Refused(outcome) => {
            warn_unforwardable(outcome, node_id, source_port, dst_port);
            return false;
        }
    };

    // A flow with its dialled identity also gets its allocated source port, which keeps it apart
    // from every other flow on the internal network and is how its replies find it again (TT-2639),
    // and the rule's internal port when it differs from the dialled one (TT-2514) - its replies get
    // the dialled port back in `route_reply`.
    if tunnel::rewrite_destination_ipv4(packet, real_dst)
        && internal_port.is_none_or(|port| tunnel::rewrite_destination_port(packet, port))
        && allocated_port.is_none_or(|port| tunnel::rewrite_source_port(packet, port))
    {
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
        warn!(%node_id, %real_dst, ?internal_port, ?allocated_port, "failed to rewrite decrypted packet's destination - dropping");
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
/// `FlowTable::take_pending` has to be handed back here rather than written directly from
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
    // The lookups and their order - a reply on a flow with its dialled identity (TT-2639), this
    // Connector's own outbound control-channel connection (TT-2144, TT-2297), Gatekeeper's inbound
    // one (TT-2102), then a flow without an identity (TT-1847) - live in `FlowTable::route_reply`.
    let route = flow_table.route_reply(
        tunnel::parse_ipv4_transport(packet),
        tunnel::parse_source_ipv4(packet),
        tunnel::parse_source_port(packet),
        destination_port,
    );
    match route {
        Ok(ReplyRoute::Unchanged { node_id }) => Some(node_id),
        // Restores what the client dialled as the reply's source - the real internal endpoint's own
        // address is never what the client contacted, so its network stack would discard the reply
        // (TT-2046 review finding #1: kernel DNAT reverses this via conntrack; this userspace rewrite
        // has no conntrack entry, so it is done explicitly) - and, for a flow with its dialled
        // identity, the dialled port and the translated port the node knows the flow by (TT-2639).
        Ok(ReplyRoute::Restore {
            node_id,
            source,
            source_port,
            destination_port: restored_destination_port,
        }) => {
            if tunnel::rewrite_source_ipv4(packet, source)
                && source_port.is_none_or(|port| tunnel::rewrite_source_port(packet, port))
                && restored_destination_port
                    .is_none_or(|port| tunnel::rewrite_destination_port(packet, port))
            {
                Some(node_id)
            } else {
                warn!(
                    %node_id, destination_port, %source,
                    "failed to restore a reply's source and ports to what the client dialled - dropping"
                );
                None
            }
        }
        Err(ReplyMiss::NoFlow) => {
            warn!(
                destination_port,
                "no unambiguous admitted node for outbound packet's port - dropping"
            );
            None
        }
        Err(ReplyMiss::NoAddressYet { node_id }) => {
            warn!(
                %node_id, destination_port,
                "no virtual address recorded for this flow yet - the client would never accept this reply anyway, dropping"
            );
            None
        }
    }
}

/// Reads outbound IP packets the OS routed to the TUN device (e.g. return
/// traffic from an internal endpoint) and encrypts+sends each one to the
/// right node's tunnel (TT-1847). The destination *address* on this leg is
/// a masqueraded wg0 address identical across the whole fleet (`flow_table`'s
/// module doc) and carries no node identity. A reply on a flow admitted with its
/// dialled identity is matched by its allocated port and its source (TT-2639);
/// otherwise the destination *port* is resolved back to a node through
/// `flow_table`'s own admission state (told explicitly by Gatekeeper, never
/// inferred from traffic). A reply with no unambiguous flow - never admitted, or
/// a port admitted on two different nodes at once from older nodes - is dropped:
/// there's genuinely nowhere defensible to send it.
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

    fn config(registry_base_url: String) -> Config {
        Config {
            agents_json_url: "unused - see test_agent_directory".to_string(),
            registry_base_url,
            identity_key_path: "/tmp/unused-in-this-test".into(),
            audit_log_path: "/tmp/unused-in-this-test-audit.log".into(),
            gatekeeper_http_port: 0,
            gatekeeper_wg0_address: std::net::Ipv4Addr::new(10, 66, 66, 1),
            tun_netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            heartbeat_interval: Duration::from_secs(60),
            ca_bundle_path: None,
            live_sessions: live_sessions::LiveSessionSettings::default(),
        }
    }

    /// An `agents.json` listing the one Agent every heartbeat test's Registry mock knows
    /// (`10.0.0.5`), served at `agent_base_url`. The returned server must be kept alive for as long
    /// as the directory is used.
    async fn test_agent_directory(agent_base_url: String) -> (AgentDirectory, MockServer) {
        let agents_json = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agents.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "agents": [{ "ip_address": "10.0.0.5", "status": "operational" }]
            })))
            .mount(&agents_json)
            .await;
        let directory = AgentDirectory::with_base_url_for(
            reqwest::Client::new(),
            format!("{}/agents.json", agents_json.uri()),
            Box::new(move |_| agent_base_url.clone()),
        );
        (directory, agents_json)
    }

    async fn wg_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    /// `run_heartbeat`'s own tests don't exercise the admission-poller lifecycle itself (that's
    /// `admission_poller`'s own test module) - this just satisfies the parameter; `sync`'s spawned
    /// pollers are never asked to make a real call in any of these tests (no node in any response
    /// body here has a resolvable ip_address that would make a real poll attempt worth asserting
    /// on).
    fn admission_pollers() -> AdmissionPollers {
        AdmissionPollers::new(
            0,
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            ControlPlaneState {
                policy_store: Arc::new(PolicyStore::new()),
                // AuditLog::new only stores the path lazily - never opened unless something
                // actually calls .record() through this AdmissionPollers, which none of these
                // tests do, so a fixed path under the OS temp dir is fine here.
                audit_log: Arc::new(AuditLog::new(
                    std::env::temp_dir().join("connector-rust-test-unused-audit.log"),
                )),
                flow_table: Arc::new(std::sync::Mutex::new(FlowTable::new())),
                recovered_packet_tx: tokio::sync::mpsc::unbounded_channel().0,
                connection_events: None,
            },
        )
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

    // --- TT-2639: the TT-2651 reproduction, through the real forward and reply paths ---

    const ERP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 99, 0, 3);
    const FIN: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 99, 0, 2);
    const ERP_HOST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(172, 31, 4, 176);
    const FIN_HOST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(172, 31, 11, 207);
    const NODE_WG: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 66, 66, 1);

    fn admit_dialled_udp(
        flow_table: &mut FlowTable,
        node_id: &str,
        gateway_address: std::net::Ipv4Addr,
        gateway_id: &str,
        host: std::net::Ipv4Addr,
    ) {
        flow_table.admit_dialled(
            node_id.to_string(),
            40100,
            Dialled {
                transport: flow_table::Transport::Udp,
                gateway_address,
                destination_port: 80,
            },
            gateway_id.to_string(),
            format!("flow-{gateway_id}-{node_id}"),
            "dev-1".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: host.to_string(),
                port: 80,
            }],
        );
    }

    fn forward_from(
        flow_table: &mut FlowTable,
        node_id: &str,
        gateway_address: std::net::Ipv4Addr,
    ) -> Option<Vec<u8>> {
        let mut packet = udp_packet(NODE_WG, gateway_address, 40100, 80);
        prepare_decrypted_packet_for_forwarding(
            &mut packet,
            node_id,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1)),
            flow_table,
            &dns_cache::DnsCache::new(),
        )
        .then_some(packet)
    }

    // --- TT-2514 AC 11: the TT-2639 scenarios with port rewrite, through the real forward and
    // reply paths. Every flow below shares the translated source port 40100. ---

    /// Minimal IPv4/TCP packet (no options, no payload), the TCP counterpart of `udp_packet`.
    fn tcp_packet(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[32] = 0x50; // data offset: 5 words
        packet
    }

    fn rewrite_packet(
        transport: flow_table::Transport,
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        match transport {
            flow_table::Transport::Tcp => tcp_packet(src, dst, src_port, dst_port),
            flow_table::Transport::Udp => udp_packet(src, dst, src_port, dst_port),
        }
    }

    /// Admits a flow on translated port 40100 for what the user dialled, served by `rules`.
    fn admit_ruled(
        flow_table: &mut FlowTable,
        node_id: &str,
        dialled: Dialled,
        gateway_id: &str,
        rules: Vec<dto::PortRule>,
    ) {
        flow_table.admit_flow(
            node_id.to_string(),
            40100,
            Some(dialled),
            gateway_id.to_string(),
            format!(
                "flow-{gateway_id}-{node_id}-{:?}-{}",
                dialled.transport, dialled.destination_port
            ),
            format!("dev-{node_id}"),
            rules,
        );
    }

    fn port_rule(
        transport: dto::RuleTransport,
        external_port: u16,
        host: std::net::Ipv4Addr,
        internal_port: u16,
    ) -> dto::PortRule {
        dto::PortRule {
            transport,
            external_port,
            internal_host: host.to_string(),
            internal_port,
        }
    }

    /// What the internal network received for one of the user's packets.
    struct Forwarded {
        transport: flow_table::Transport,
        connector: std::net::Ipv4Addr,
        host: std::net::Ipv4Addr,
        internal_port: u16,
        source_port: u16,
    }

    /// Sends the user's packet for `dialled` from `node_id` (translated port 40100) through the
    /// forward path.
    fn forward_dialled(flow_table: &mut FlowTable, node_id: &str, dialled: Dialled) -> Forwarded {
        let mut packet = rewrite_packet(
            dialled.transport,
            NODE_WG,
            dialled.gateway_address,
            40100,
            dialled.destination_port,
        );
        assert!(
            prepare_decrypted_packet_for_forwarding(
                &mut packet,
                node_id,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1)),
                flow_table,
                &dns_cache::DnsCache::new(),
            ),
            "{dialled:?} from {node_id} is forwarded"
        );
        Forwarded {
            transport: dialled.transport,
            connector: tunnel::parse_source_ipv4(&packet).expect("source"),
            host: tunnel::parse_destination_ipv4(&packet).expect("destination"),
            internal_port: tunnel::parse_destination_port(&packet).expect("destination port"),
            source_port: tunnel::parse_source_port(&packet).expect("source port"),
        }
    }

    /// Sends the internal service's reply to a forwarded packet through the reply path. Returns the
    /// node it is routed to and the source address, source port and destination port the user sees.
    fn reply_to(
        flow_table: &FlowTable,
        forwarded: &Forwarded,
    ) -> (String, std::net::Ipv4Addr, u16, u16) {
        let mut reply = rewrite_packet(
            forwarded.transport,
            forwarded.host,
            forwarded.connector,
            forwarded.internal_port,
            forwarded.source_port,
        );
        let routed_to =
            prepare_reply_packet_for_forwarding(&mut reply, forwarded.source_port, flow_table)
                .expect("the reply is routed");
        (
            routed_to,
            tunnel::parse_source_ipv4(&reply).expect("reply source"),
            tunnel::parse_source_port(&reply).expect("reply source port"),
            tunnel::parse_destination_port(&reply).expect("reply destination port"),
        )
    }

    fn dialled_tcp(gateway_address: std::net::Ipv4Addr, destination_port: u16) -> Dialled {
        Dialled {
            transport: flow_table::Transport::Tcp,
            gateway_address,
            destination_port,
        }
    }

    /// AC 11 main case: two gateways on one Connector, each with TCP 443 rewritten to a different
    /// internal port, used at once by two devices through one node from the same source port.
    #[test]
    fn two_gateways_rewriting_tcp_443_keep_two_devices_on_one_node_and_port_apart() {
        let mut flow_table = FlowTable::new();
        let erp = dialled_tcp(ERP, 443);
        let fin = dialled_tcp(FIN, 443);
        admit_ruled(
            &mut flow_table,
            "n-1",
            erp,
            "gw-erp",
            vec![port_rule(dto::RuleTransport::Tcp, 443, ERP_HOST, 8443)],
        );
        admit_ruled(
            &mut flow_table,
            "n-1",
            fin,
            "gw-fin",
            vec![port_rule(dto::RuleTransport::Tcp, 443, FIN_HOST, 9443)],
        );

        // Both flows are open before either reply comes back.
        let to_erp = forward_dialled(&mut flow_table, "n-1", erp);
        let to_fin = forward_dialled(&mut flow_table, "n-1", fin);

        assert_eq!((to_erp.host, to_erp.internal_port), (ERP_HOST, 8443));
        assert_eq!((to_fin.host, to_fin.internal_port), (FIN_HOST, 9443));
        assert_eq!(
            reply_to(&flow_table, &to_erp),
            ("n-1".to_string(), ERP, 443, 40100)
        );
        assert_eq!(
            reply_to(&flow_table, &to_fin),
            ("n-1".to_string(), FIN, 443, 40100)
        );
    }

    /// AC 11, two nodes: the same rewritten port reached at once from two nodes with the same source
    /// port goes to its gateway's service, and each reply goes back to its own node.
    #[test]
    fn rewritten_flows_from_two_nodes_on_one_port_reply_to_their_own_node() {
        let mut flow_table = FlowTable::new();
        let erp = dialled_tcp(ERP, 443);
        let fin = dialled_tcp(FIN, 443);
        let erp_rules = vec![port_rule(dto::RuleTransport::Tcp, 443, ERP_HOST, 8443)];
        admit_ruled(&mut flow_table, "n-1", erp, "gw-erp", erp_rules.clone());
        admit_ruled(&mut flow_table, "n-2", erp, "gw-erp", erp_rules);
        admit_ruled(
            &mut flow_table,
            "n-2",
            fin,
            "gw-fin",
            vec![port_rule(dto::RuleTransport::Tcp, 443, FIN_HOST, 9443)],
        );

        // All three flows are open before any reply comes back.
        let n1_erp = forward_dialled(&mut flow_table, "n-1", erp);
        let n2_erp = forward_dialled(&mut flow_table, "n-2", erp);
        let n2_fin = forward_dialled(&mut flow_table, "n-2", fin);

        assert_eq!((n1_erp.host, n1_erp.internal_port), (ERP_HOST, 8443));
        assert_eq!((n2_erp.host, n2_erp.internal_port), (ERP_HOST, 8443));
        assert_eq!((n2_fin.host, n2_fin.internal_port), (FIN_HOST, 9443));
        assert_ne!(
            n1_erp.source_port, n2_erp.source_port,
            "the two nodes' flows to one service get their own source port"
        );
        assert_eq!(
            reply_to(&flow_table, &n1_erp),
            ("n-1".to_string(), ERP, 443, 40100)
        );
        assert_eq!(
            reply_to(&flow_table, &n2_erp),
            ("n-2".to_string(), ERP, 443, 40100)
        );
        assert_eq!(
            reply_to(&flow_table, &n2_fin),
            ("n-2".to_string(), FIN, 443, 40100)
        );
    }

    /// AC 11, TCP and UDP on one port: one gateway opens 5353 on both transports, rewritten to the
    /// same internal address and port. The two flows come from different nodes on the same source
    /// port and are given the same allocated port, so only the transport tells their replies apart:
    /// a reply matched to the other transport's flow would go to the wrong node.
    #[test]
    fn tcp_and_udp_rules_on_one_port_keep_their_flows_apart() {
        let mut flow_table = FlowTable::new();
        let tcp = dialled_tcp(ERP, 5353);
        let udp = Dialled {
            transport: flow_table::Transport::Udp,
            gateway_address: ERP,
            destination_port: 5353,
        };
        let rules = vec![
            port_rule(dto::RuleTransport::Tcp, 5353, ERP_HOST, 53),
            port_rule(dto::RuleTransport::Udp, 5353, ERP_HOST, 53),
        ];
        admit_ruled(&mut flow_table, "n-1", tcp, "gw-erp", rules.clone());
        admit_ruled(&mut flow_table, "n-2", udp, "gw-erp", rules);

        let over_tcp = forward_dialled(&mut flow_table, "n-1", tcp);
        let over_udp = forward_dialled(&mut flow_table, "n-2", udp);

        assert_eq!((over_tcp.host, over_tcp.internal_port), (ERP_HOST, 53));
        assert_eq!((over_udp.host, over_udp.internal_port), (ERP_HOST, 53));
        assert_eq!(
            over_tcp.source_port, over_udp.source_port,
            "ports are allocated per transport, so both flows get the same one"
        );
        assert_eq!(
            reply_to(&flow_table, &over_tcp),
            ("n-1".to_string(), ERP, 5353, 40100)
        );
        assert_eq!(
            reply_to(&flow_table, &over_udp),
            ("n-2".to_string(), ERP, 5353, 40100)
        );
        assert_eq!(flow_table.flow_count(), 2, "two flows, not one merged");
    }

    /// AC 11, two ports of one gateway: TCP 443 and TCP 2222 of one gateway, rewritten to different
    /// internal services, used at once from the same node and source port.
    #[test]
    fn two_rewritten_ports_of_one_gateway_reach_their_own_service() {
        let mut flow_table = FlowTable::new();
        let https = dialled_tcp(ERP, 443);
        let ssh = dialled_tcp(ERP, 2222);
        let rules = vec![
            port_rule(dto::RuleTransport::Tcp, 443, ERP_HOST, 8443),
            port_rule(dto::RuleTransport::Tcp, 2222, FIN_HOST, 22),
        ];
        admit_ruled(&mut flow_table, "n-1", https, "gw-erp", rules.clone());
        admit_ruled(&mut flow_table, "n-1", ssh, "gw-erp", rules);

        let to_https = forward_dialled(&mut flow_table, "n-1", https);
        let to_ssh = forward_dialled(&mut flow_table, "n-1", ssh);

        assert_eq!((to_https.host, to_https.internal_port), (ERP_HOST, 8443));
        assert_eq!((to_ssh.host, to_ssh.internal_port), (FIN_HOST, 22));
        assert_eq!(
            reply_to(&flow_table, &to_https),
            ("n-1".to_string(), ERP, 443, 40100)
        );
        assert_eq!(
            reply_to(&flow_table, &to_ssh),
            ("n-1".to_string(), ERP, 2222, 40100)
        );
        assert_eq!(flow_table.flow_count(), 2, "two flows, not one merged");
    }

    #[test]
    fn packets_sharing_a_translated_port_reach_their_own_gateways_service() {
        let mut flow_table = FlowTable::new();
        admit_dialled_udp(&mut flow_table, "n-1", ERP, "gw-erp", ERP_HOST);
        admit_dialled_udp(&mut flow_table, "n-1", FIN, "gw-fin", FIN_HOST);

        let to_erp = forward_from(&mut flow_table, "n-1", ERP).expect("forwarded");
        let to_fin = forward_from(&mut flow_table, "n-1", FIN).expect("forwarded");

        assert_eq!(&to_erp[16..20], &ERP_HOST.octets());
        assert_eq!(&to_fin[16..20], &FIN_HOST.octets());
        // The allocated source port, not the translated one, toward the internal network.
        assert_ne!(tunnel::parse_source_port(&to_erp), Some(40100));
        assert_ne!(tunnel::parse_source_port(&to_fin), Some(40100));
    }

    #[test]
    fn a_packet_for_a_gateway_without_a_flow_is_held_under_its_dialled_identity_not_forwarded() {
        let mut flow_table = FlowTable::new();
        admit_dialled_udp(&mut flow_table, "n-1", ERP, "gw-erp", ERP_HOST);

        assert!(forward_from(&mut flow_table, "n-1", FIN).is_none());

        let fin = Dialled {
            transport: flow_table::Transport::Udp,
            gateway_address: FIN,
            destination_port: 80,
        };
        assert!(
            flow_table
                .take_pending_dialled_packet("n-1", 40100, fin, Instant::now())
                .is_some()
        );
    }

    #[test]
    fn a_reply_goes_back_to_its_own_node_with_what_the_client_dialled_restored() {
        let mut flow_table = FlowTable::new();
        admit_dialled_udp(&mut flow_table, "n-1", ERP, "gw-erp", ERP_HOST);
        admit_dialled_udp(&mut flow_table, "n-2", ERP, "gw-erp", ERP_HOST);
        let sent_1 = forward_from(&mut flow_table, "n-1", ERP).expect("forwarded");
        let sent_2 = forward_from(&mut flow_table, "n-2", ERP).expect("forwarded");
        let port_1 = tunnel::parse_source_port(&sent_1).unwrap();
        let port_2 = tunnel::parse_source_port(&sent_2).unwrap();
        let mut reply_1 = udp_packet(ERP_HOST, NODE_WG, 80, port_1);
        let mut reply_2 = udp_packet(ERP_HOST, NODE_WG, 80, port_2);

        assert_eq!(
            prepare_reply_packet_for_forwarding(&mut reply_1, port_1, &flow_table).as_deref(),
            Some("n-1")
        );
        assert_eq!(
            prepare_reply_packet_for_forwarding(&mut reply_2, port_2, &flow_table).as_deref(),
            Some("n-2")
        );
        assert_eq!(
            &reply_1[12..16],
            &ERP.octets(),
            "the gateway address the client dialled"
        );
        assert_eq!(tunnel::parse_source_port(&reply_1), Some(80));
        assert_eq!(
            tunnel::parse_destination_port(&reply_1),
            Some(40100),
            "the translated port"
        );
    }

    /// TT-2514 through the real forward and reply paths: a TCP 443 rule to an internal :8443 reaches
    /// the internal port, and the reply goes back from the port the user dialled.
    #[test]
    fn a_translated_port_rule_rewrites_the_port_both_ways() {
        let mut flow_table = FlowTable::new();
        flow_table.admit_flow(
            "n-1".to_string(),
            40100,
            Some(Dialled {
                transport: flow_table::Transport::Udp,
                gateway_address: ERP,
                destination_port: 443,
            }),
            "gw-erp".to_string(),
            "flow-erp".to_string(),
            "dev-1".to_string(),
            vec![dto::PortRule {
                transport: dto::RuleTransport::TcpUdp,
                external_port: 443,
                internal_host: ERP_HOST.to_string(),
                internal_port: 8443,
            }],
        );
        let mut packet = udp_packet(NODE_WG, ERP, 40100, 443);

        assert!(prepare_decrypted_packet_for_forwarding(
            &mut packet,
            "n-1",
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98, 0, 1)),
            &mut flow_table,
            &dns_cache::DnsCache::new(),
        ));
        assert_eq!(tunnel::parse_destination_ipv4(&packet), Some(ERP_HOST));
        assert_eq!(tunnel::parse_destination_port(&packet), Some(8443));
        let allocated = tunnel::parse_source_port(&packet).unwrap();

        let mut reply = udp_packet(ERP_HOST, NODE_WG, 8443, allocated);
        assert_eq!(
            prepare_reply_packet_for_forwarding(&mut reply, allocated, &flow_table).as_deref(),
            Some("n-1")
        );
        assert_eq!(&reply[12..16], &ERP.octets());
        assert_eq!(
            tunnel::parse_source_port(&reply),
            Some(443),
            "the port the user dialled"
        );
        assert_eq!(tunnel::parse_destination_port(&reply), Some(40100));
    }

    #[test]
    fn a_reply_from_another_service_on_the_allocated_port_is_not_routed() {
        let mut flow_table = FlowTable::new();
        admit_dialled_udp(&mut flow_table, "n-1", ERP, "gw-erp", ERP_HOST);
        let sent = forward_from(&mut flow_table, "n-1", ERP).expect("forwarded");
        let port = tunnel::parse_source_port(&sent).unwrap();
        let mut reply = udp_packet(FIN_HOST, NODE_WG, 80, port);

        assert_eq!(
            prepare_reply_packet_for_forwarding(&mut reply, port, &flow_table),
            None
        );
    }

    // --- TT-2639 review: flows admitted before their node was updated ---

    fn admit_legacy_erp(flow_table: &mut FlowTable) {
        flow_table.admit(
            "n-1".to_string(),
            40100,
            "gw-erp".to_string(),
            "flow-legacy-erp".to_string(),
            "dev-1".to_string(),
            vec![dto::PolicyBundleEndpoint {
                host: ERP_HOST.to_string(),
                port: 80,
            }],
        );
    }

    /// n-1 has since been updated: it sent an admission with its dialled identity.
    fn mark_n1_updated(flow_table: &mut FlowTable) {
        admit_dialled_udp(
            flow_table,
            "n-1",
            std::net::Ipv4Addr::new(10, 99, 0, 9),
            "gw-other",
            ERP_HOST,
        );
    }

    #[test]
    fn another_gateways_packet_does_not_use_a_flow_admitted_before_the_node_was_updated() {
        let mut flow_table = FlowTable::new();
        admit_legacy_erp(&mut flow_table);
        flow_table.record_virtual_address("n-1", 40100, ERP);
        mark_n1_updated(&mut flow_table);

        assert!(
            forward_from(&mut flow_table, "n-1", FIN).is_none(),
            "Finance's packet must not reach ERP"
        );
        assert!(
            forward_from(&mut flow_table, "n-1", ERP).is_some(),
            "ERP's own packets still do"
        );
    }

    #[test]
    fn with_no_address_recorded_yet_an_updated_nodes_packet_is_refused_not_forwarded() {
        let mut flow_table = FlowTable::new();
        admit_legacy_erp(&mut flow_table);
        mark_n1_updated(&mut flow_table);

        assert!(forward_from(&mut flow_table, "n-1", FIN).is_none());
        assert_eq!(
            flow_table.virtual_address_for("n-1", 40100),
            None,
            "Finance's address must not be recorded on ERP's flow"
        );
        let fin = Dialled {
            transport: flow_table::Transport::Udp,
            gateway_address: FIN,
            destination_port: 80,
        };
        assert!(
            flow_table
                .take_pending_dialled_packet("n-1", 40100, fin, Instant::now())
                .is_some(),
            "held for Finance's own admission"
        );
    }

    #[test]
    fn a_node_not_yet_updated_still_forwards_a_legacy_flows_first_packet() {
        let mut flow_table = FlowTable::new();
        admit_legacy_erp(&mut flow_table);

        assert!(forward_from(&mut flow_table, "n-1", ERP).is_some());
        assert_eq!(flow_table.virtual_address_for("n-1", 40100), Some(ERP));
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

    /// TT-2144 regression test: proves the actual production bug (admission_poller's own outbound
    /// connection to Gatekeeper never routed to the right node, since destination_port - the
    /// packet's own destination port - is the SAME fixed value (Gatekeeper's HTTP port) for every
    /// node, and carries no information about which one a brand new outbound connection is even
    /// for) is fixed: this Connector's own outbound packet, on a connection whose *source* port
    /// was registered via `record_outbound_control_channel_port`, must resolve to that node
    /// through this new source-port-keyed lookup - the destination-port-keyed
    /// `node_for_control_channel_port` (checked first, and correctly returns None here) can never
    /// match it, by construction, since nothing was ever recorded under the destination port.
    #[test]
    fn prepare_reply_packet_routes_a_locally_initiated_outbound_connections_packet_via_its_own_source_port()
     {
        let mut flow_table = FlowTable::new();
        flow_table.record_outbound_control_channel_port("n-1", 54321);
        // Gatekeeper's fixed HTTP port - identical regardless of which node this packet is
        // actually for, which is exactly the fact that makes the destination-port lookup useless
        // here and the source-port one necessary.
        let gatekeeper_http_port = 4000;
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 98, 0, 5), // this Connector's own connector_virtual_ip
            std::net::Ipv4Addr::new(10, 66, 66, 1), // Gatekeeper's fixed tunnel address
            54321,                                 // this connection's own registered local port
            gatekeeper_http_port,
        );
        let original = packet.clone();

        let node_id =
            prepare_reply_packet_for_forwarding(&mut packet, gatekeeper_http_port, &flow_table);

        assert_eq!(node_id, Some("n-1".to_string()));
        assert_eq!(
            packet, original,
            "this Connector's own outbound packet already carries its real address - no rewrite needed"
        );
    }

    /// The two directions must never be conflated even when the raw port number happens to
    /// coincide - see `FlowTable`'s own test of the same property. TT-2297: the outbound
    /// (source-port-keyed) mapping takes precedence. It names exactly one connection this Connector
    /// opened itself; the inbound key is only the peer's port, which for every Gatekeeper reply is
    /// the same fixed HTTP port on every node.
    #[test]
    fn prepare_reply_packet_prefers_the_outbound_control_channel_mapping_over_an_inbound_one_at_the_same_port_number()
     {
        let mut flow_table = FlowTable::new();
        flow_table.record_control_channel_port("n-1", 51234);
        flow_table.record_outbound_control_channel_port("n-2", 51234);
        // Source AND destination both 51234, so BOTH the inbound (destination-port-keyed) and
        // outbound (source-port-keyed) lookups below have a real, distinct candidate to match -
        // without this, one of the two branches could never have matched this packet at all
        // regardless of lookup order, and this test would prove nothing about precedence.
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 98, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            51234,
            51234,
        );

        let node_id = prepare_reply_packet_for_forwarding(&mut packet, 51234, &flow_table);

        assert_eq!(
            node_id,
            Some("n-2".to_string()),
            "the outbound (source-port) mapping, checked first, must take precedence"
        );
    }

    /// TT-2297: the live failure. Two nodes each hold a poll open to the same Gatekeeper port, and
    /// an entry for that port from an earlier reply points at the first node. The second node's
    /// poll must still go through the second node's tunnel.
    #[test]
    fn a_polls_packets_follow_its_own_node_not_the_node_that_answered_last() {
        let mut flow_table = FlowTable::new();
        flow_table.record_outbound_control_channel_port("n-1", 50001);
        flow_table.record_outbound_control_channel_port("n-2", 50002);
        flow_table.record_control_channel_port("n-1", 4000);
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 98, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            50002,
            4000,
        );

        let node_id = prepare_reply_packet_for_forwarding(&mut packet, 4000, &flow_table);

        assert_eq!(node_id, Some("n-2".to_string()));
    }

    /// TT-2297: after the first node leaves the node_list (a rotation), the second node's polls
    /// still reach it.
    #[test]
    fn a_polls_packets_still_reach_their_node_after_another_node_is_evicted() {
        let mut flow_table = FlowTable::new();
        flow_table.record_outbound_control_channel_port("n-1", 50001);
        flow_table.record_outbound_control_channel_port("n-2", 50002);
        flow_table.record_control_channel_port("n-1", 4000);
        flow_table.evict_node("n-1");
        let mut packet = udp_packet(
            std::net::Ipv4Addr::new(10, 98, 0, 5),
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            50002,
            4000,
        );

        assert_eq!(
            prepare_reply_packet_for_forwarding(&mut packet, 4000, &flow_table),
            Some("n-2".to_string())
        );
    }

    /// TT-2297: Gatekeeper's reply to one of this Connector's own polls must not be recorded as an
    /// inbound control-channel connection - its source port is Gatekeeper's fixed HTTP port, the
    /// same on every node.
    #[test]
    fn a_reply_to_the_connectors_own_poll_is_not_recorded_as_an_inbound_control_channel_port() {
        let mut flow_table = FlowTable::new();
        flow_table.record_outbound_control_channel_port("n-2", 50002);
        let connector_virtual_ip = std::net::Ipv4Addr::new(10, 98, 0, 5);
        let mut reply = udp_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            connector_virtual_ip,
            4000,
            50002,
        );

        let forwarded = prepare_decrypted_packet_for_forwarding(
            &mut reply,
            "n-2",
            std::net::IpAddr::V4(connector_virtual_ip),
            &mut flow_table,
            &dns_cache::DnsCache::new(),
        );

        assert!(forwarded, "the reply itself is still delivered");
        assert!(flow_table.node_for_control_channel_port(4000).is_none());
    }

    /// A genuinely inbound connection (Gatekeeper dialing this Connector) is still recorded, as
    /// before (TT-2102).
    #[test]
    fn an_inbound_control_channel_connection_is_still_recorded() {
        let mut flow_table = FlowTable::new();
        let connector_virtual_ip = std::net::Ipv4Addr::new(10, 98, 0, 5);
        let mut request = udp_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 1),
            connector_virtual_ip,
            51234,
            8443,
        );

        prepare_decrypted_packet_for_forwarding(
            &mut request,
            "n-1",
            std::net::IpAddr::V4(connector_virtual_ip),
            &mut flow_table,
            &dns_cache::DnsCache::new(),
        );

        assert_eq!(flow_table.node_for_control_channel_port(51234), Some("n-1"));
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
        let body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
        )
        .await;

        // No connector_virtual_ip in this response body - Ok(None), not an error.
        assert_eq!(result.unwrap(), None);
        assert_eq!(policy_store.current().unwrap().connector_id, "c-1");
        // TT-2210 follow-up: the pollers poll under the heartbeat's connector_id, which Agent
        // provisioned on Gatekeeper - never the public key ("pk-1") this Connector heartbeats with.
        assert_eq!(admission_pollers.connector_id(), Some("c-1"));
        let entries = read_audit_lines(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["event"], "policy_applied");
        assert_eq!(entries[0]["gateway_count"], 0);
    }

    #[tokio::test]
    async fn run_heartbeat_records_each_gateways_configuration_and_entitlement_list() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED","endpoints":[{"host":"10.0.0.5","port":443}],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
        )
        .await;

        // TT-2520 (spec §B.10): the summary, then the gateway's configuration and entitlement list.
        result.unwrap();
        let entries = read_audit_lines(&dir);
        let events: Vec<&str> = entries
            .iter()
            .map(|e| e["event"].as_str().unwrap())
            .collect();
        assert_eq!(
            events,
            [
                "policy_applied",
                "policy_bundle_applied",
                "entitlement_list_received"
            ]
        );
        assert_eq!(entries[1]["gateway_id"], "gw-1");
        assert_eq!(entries[1]["location"], "Amsterdam");
        assert_eq!(entries[1]["hostname"], "crm.internal.example.com");
        // A bundle without port rules: its endpoint as the TCP + UDP rule it is served by (TT-2514).
        assert_eq!(
            entries[1]["port_rules"],
            serde_json::json!([{"transport": "TCP_UDP", "external_port": 443, "internal_host": "10.0.0.5", "internal_port": 443}])
        );
        assert_eq!(entries[2]["gateway_id"], "gw-1");
        assert_eq!(entries[2]["entitlement_count"], 1);
        assert_eq!(
            entries[2]["entitlement_list_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }

    /// TT-1838: `main` uses this returned value to create the TUN device - must be the real
    /// parsed address, not just "heartbeat succeeded".
    #[tokio::test]
    async fn run_heartbeat_returns_the_parsed_connector_virtual_ip_when_present() {
        let agent_identity = crypto::generate_keypair();
        let body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","connector_virtual_ip":"10.98.0.7","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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

        let config = config(registry_server.uri());
        let agent_base_url = "http://127.0.0.1:1".to_string();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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
        let body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", wrong_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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
        // TT-2520: with a gateway in it, so this also shows a rejected package writes no
        // policy_bundle_applied or entitlement_list_received entry.
        let body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2020-01-01T09:55:00Z","expires_at":"2020-01-01T10:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED","endpoints":[{"host":"10.0.0.5","port":443}],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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
        let body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[{"node_id":"n-1","ip_address":"10.0.0.10","wireguard_public_key":null}]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
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
        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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
            r#"{{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[],"node_list":[{{"node_id":"n-1","ip_address":"{}","wireguard_public_key":"{}"}}]}}"#,
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(body, "application/json")
                    .insert_header("X-Signature", signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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
                port_rules: None,
                gateway_address: None,
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
                port_rules: None,
                gateway_address: None,
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

    /// TT-2514: with port rules, the hosts the DNS cache refreshes and the heartbeat reports as
    /// unresolved are the rules' internal hosts, not the transitional endpoints'.
    #[test]
    fn collect_endpoint_hosts_reads_the_port_rules_when_a_bundle_has_them() {
        let mut bundle = bundle_with_endpoints("gw-1", &["10.0.0.5"]);
        bundle.port_rules = Some(vec![
            dto::PortRule {
                transport: dto::RuleTransport::Tcp,
                external_port: 443,
                internal_host: "erp.internal.example.com".to_string(),
                internal_port: 8443,
            },
            dto::PortRule {
                transport: dto::RuleTransport::Udp,
                external_port: 514,
                internal_host: "syslog.internal.example.com".to_string(),
                internal_port: 514,
            },
        ]);

        assert_eq!(
            collect_endpoint_hosts(&[bundle]),
            vec![
                "erp.internal.example.com".to_string(),
                "syslog.internal.example.com".to_string(),
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
            port_rules: None,
            gateway_address: None,
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
        let old_body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[{"host":"old.internal.example.com","port":443}],"entitlement_list":[]}],"node_list":[]}"#;
        let old_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, old_body.as_bytes());
        let new_body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:01:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n2","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[{"host":"new.internal.example.com","port":443}],"entitlement_list":[]}],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(old_body, "application/json")
                    .insert_header("X-Signature", old_signature.as_str()),
            )
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(new_body, "application/json")
                    .insert_header("X-Signature", new_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
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
        let mut admission_pollers = admission_pollers();
        run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
        )
        .await
        .unwrap();
        requested_hosts.lock().unwrap().clear();

        run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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

    fn signed_heartbeat(
        agent_identity: &crypto::KeyPair,
        nonce: &str,
        bundles_json: &str,
    ) -> ResponseTemplate {
        let body = format!(
            r#"{{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"{nonce}","policy_bundles":{bundles_json},"node_list":[]}}"#
        );
        let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());
        ResponseTemplate::new(200)
            .set_body_raw(body, "application/json")
            .insert_header("X-Signature", signature.as_str())
    }

    /// TT-2464, end to end through run_heartbeat: a revoke that ends an admitted flow queues and
    /// audits a report, the next heartbeat's request carries it, and once that heartbeat succeeds
    /// the queue is empty.
    #[tokio::test]
    async fn run_heartbeat_reports_an_ended_flow_on_the_next_heartbeat_then_acknowledges_it() {
        let agent_identity = crypto::generate_keypair();
        let entitled = r#"[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-7","device_public_key":"dev-A"}]}]"#;
        let revoked = r#"[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[]}]"#;

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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(signed_heartbeat(&agent_identity, "n1", entitled))
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(signed_heartbeat(&agent_identity, "n2", revoked))
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(signed_heartbeat(&agent_identity, "n3", revoked))
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_server.uri()).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let queue_path = dir.path().join("pending-gateway-end-reports.json");
        let gateway_end_queue = gateway_end::GatewayEndQueue::load(&queue_path).await;
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();
        let mut admission_pollers = admission_pollers();

        macro_rules! heartbeat {
            () => {
                run_heartbeat(
                    "pk-1",
                    &agent_directory,
                    &registry_client,
                    &heartbeat_client,
                    &policy_store,
                    &audit_log,
                    &tunnel_manager,
                    &wg_socket,
                    &flow_table,
                    &dns_cache,
                    &mut admission_pollers,
                    &gateway_end_queue,
                    None,
                )
                .await
                .unwrap()
            };
        }

        heartbeat!();
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );

        heartbeat!(); // the revoke: tears the flow down and queues a report
        let queued = gateway_end_queue
            .pending(chrono::Utc::now().timestamp_millis())
            .await;
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].gateway_id, "gw-1");
        assert_eq!(queued[0].user_id, "u-7");
        assert_eq!(queued[0].device_public_key, "dev-A");
        assert!(
            queue_path.exists(),
            "the report must be on disk before it is delivered"
        );
        let audit = read_audit_lines(&dir);
        let ended: Vec<_> = audit
            .iter()
            .filter(|e| e["event"] == "flows_ended")
            .collect();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0]["report_id"], queued[0].report_id.as_str());
        assert_eq!(ended[0]["user_id"], "u-7");

        heartbeat!(); // carries the report, then acknowledges it
        let requests = agent_server.received_requests().await.unwrap();
        let third: serde_json::Value = serde_json::from_slice(&requests[2].body).unwrap();
        assert_eq!(
            third["ended_flows"],
            serde_json::to_value(&queued).unwrap(),
            "the third heartbeat must carry exactly the queued report"
        );
        let second: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert!(
            second.get("ended_flows").is_none(),
            "nothing was pending before the revoke"
        );
        assert!(
            gateway_end_queue
                .pending(chrono::Utc::now().timestamp_millis())
                .await
                .is_empty()
        );
        let reloaded = gateway_end::GatewayEndQueue::load(&queue_path).await;
        assert!(
            reloaded
                .pending(chrono::Utc::now().timestamp_millis())
                .await
                .is_empty()
        );
    }

    /// TT-2250: a heartbeat reply that accepts every connection event the request carried.
    fn accepting_heartbeat(
        agent_identity: &crypto::KeyPair,
        bundles_json: &'static str,
    ) -> impl Fn(&wiremock::Request) -> ResponseTemplate + use<> {
        let signing_key = agent_identity.signing_key.clone();
        move |request: &wiremock::Request| {
            let sent: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let results: serde_json::Map<String, serde_json::Value> = sent["connection_events"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| {
                    (
                        e["report_id"].as_str().unwrap().to_string(),
                        "accepted".into(),
                    )
                })
                .collect();
            let body = format!(
                r#"{{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"{}","policy_bundles":{bundles_json},"node_list":[],"connection_event_results":{}}}"#,
                gateway_end::new_report_id(),
                serde_json::Value::Object(results)
            );
            let signature = crypto::sign_to_base64(&signing_key, body.as_bytes());
            ResponseTemplate::new(200)
                .set_body_raw(body, "application/json")
                .insert_header("X-Signature", signature.as_str())
        }
    }

    /// TT-2250 (spec §B.22), end to end through run_heartbeat: an admitted connection is sent as
    /// `established`; a revoke ends it with a removal end (flows_ended 1) instead of a gateway-end
    /// report, the `FlowsEnded` entry names that end, and once accepted nothing is left queued. An
    /// off-schedule heartbeat sends no connection events.
    #[tokio::test]
    async fn run_heartbeat_sends_connection_events_and_a_revoke_ends_the_connection() {
        let agent_identity = crypto::generate_keypair();
        let entitled = r#"[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-7","device_public_key":"dev-A"}]}]"#;
        let revoked = r#"[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[]}]"#;

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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(accepting_heartbeat(&agent_identity, entitled))
            .up_to_n_times(2)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(accepting_heartbeat(&agent_identity, revoked))
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_server.uri()).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let gateway_end_queue =
            gateway_end::GatewayEndQueue::load(dir.path().join("pending-gateway-end-reports.json"))
                .await;
        let events =
            connection_events::ConnectionEvents::load(dir.path().join("connection-events.json"))
                .await;
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();
        let mut admission_pollers = admission_pollers();

        macro_rules! heartbeat {
            ($carry:expr) => {
                run_heartbeat(
                    "pk-1",
                    &agent_directory,
                    &registry_client,
                    &heartbeat_client,
                    &policy_store,
                    &audit_log,
                    &tunnel_manager,
                    &wg_socket,
                    &flow_table,
                    &dns_cache,
                    &mut admission_pollers,
                    &gateway_end_queue,
                    Some(ConnectionEventsTurn {
                        events: &events,
                        carry: $carry,
                    }),
                )
                .await
                .unwrap()
            };
        }

        heartbeat!(true);
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        events.flow_admitted(
            "gw-1",
            "dev-A",
            None,
            "u-7",
            "n-1",
            chrono::Utc::now().timestamp_millis(),
        );

        heartbeat!(false); // off schedule: carries nothing
        heartbeat!(true); // carries the establishment (accepted), and the revoke ends the connection
        assert!(
            gateway_end_queue
                .pending(chrono::Utc::now().timestamp_millis())
                .await
                .is_empty(),
            "a Connector with connection events queues no gateway-end report"
        );
        heartbeat!(true); // carries the removal end (accepted)

        let requests = agent_server.received_requests().await.unwrap();
        let bodies: Vec<serde_json::Value> = requests
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect();
        assert!(
            bodies[1].get("connection_events").is_none(),
            "off schedule sends none"
        );
        assert_eq!(bodies[2]["connection_events"][0]["kind"], "established");
        let end = &bodies[3]["connection_events"][0];
        assert_eq!(end["kind"], "ended");
        assert_eq!(end["observation"], "entitlement_removed");
        assert_eq!(end["flows_ended"], 1);
        assert!(bodies.iter().all(|b| b.get("ended_flows").is_none()));

        let audit = read_audit_lines(&dir);
        let flows_ended: Vec<_> = audit
            .iter()
            .filter(|e| e["event"] == "flows_ended")
            .collect();
        assert_eq!(flows_ended.len(), 1);
        assert_eq!(flows_ended[0]["report_id"], end["report_id"]);
        assert!(audit.iter().any(|e| e["event"] == "connection_ended"));

        assert!(
            events.batch(i64::MAX / 2).events.is_empty(),
            "every event was accepted"
        );
    }

    /// TT-2250 (spec §B.22 point 5): after an upgrade, gateway-end reports still queued go first and
    /// the heartbeat carries no connection events until that queue is empty.
    #[tokio::test]
    async fn run_heartbeat_drains_old_gateway_end_reports_before_connection_events() {
        let agent_identity = crypto::generate_keypair();
        let entitled = r#"[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-7","device_public_key":"dev-A"}]}]"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(accepting_heartbeat(&agent_identity, entitled))
            .mount(&agent_server)
            .await;
        let config = config(registry_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_server.uri()).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let gateway_end_queue =
            gateway_end::GatewayEndQueue::load(dir.path().join("pending-gateway-end-reports.json"))
                .await;
        gateway_end_queue
            .enqueue(vec![gateway_end::GatewayEndReport {
                report_id: gateway_end::new_report_id(),
                gateway_id: "gw-1".to_string(),
                user_id: "u-7".to_string(),
                device_public_key: "dev-B".to_string(),
                ended_at: chrono::Utc::now().timestamp_millis(),
                flows_ended: 1,
            }])
            .await
            .unwrap();
        let events =
            connection_events::ConnectionEvents::load(dir.path().join("connection-events.json"))
                .await;
        events.flow_admitted(
            "gw-1",
            "dev-A",
            None,
            "u-7",
            "n-1",
            chrono::Utc::now().timestamp_millis(),
        );
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();
        let mut admission_pollers = admission_pollers();
        for _ in 0..2 {
            run_heartbeat(
                "pk-1",
                &agent_directory,
                &registry_client,
                &heartbeat_client,
                &policy_store,
                &audit_log,
                &tunnel_manager,
                &wg_socket,
                &flow_table,
                &dns_cache,
                &mut admission_pollers,
                &gateway_end_queue,
                Some(ConnectionEventsTurn {
                    events: &events,
                    carry: true,
                }),
            )
            .await
            .unwrap();
        }
        let requests = agent_server.received_requests().await.unwrap();
        let first: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(first["ended_flows"].as_array().unwrap().len(), 1);
        assert!(first.get("connection_events").is_none());
        assert!(second.get("ended_flows").is_none());
        assert_eq!(second["connection_events"][0]["kind"], "established");
    }

    /// A heartbeat that fails must not drop the reports it was carrying - they go out again on
    /// the next attempt.
    #[tokio::test]
    async fn run_heartbeat_keeps_the_reports_when_the_heartbeat_fails() {
        let agent_identity = crypto::generate_keypair();
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_server.uri()).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let gateway_end_queue =
            gateway_end::GatewayEndQueue::load(dir.path().join("queue.json")).await;
        let report = gateway_end::GatewayEndReport {
            report_id: gateway_end::new_report_id(),
            gateway_id: "gw-1".to_string(),
            user_id: "u-7".to_string(),
            device_public_key: "dev-A".to_string(),
            ended_at: chrono::Utc::now().timestamp_millis(),
            flows_ended: 1,
        };
        gateway_end_queue
            .enqueue(vec![report.clone()])
            .await
            .unwrap();
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();
        let mut admission_pollers = admission_pollers();

        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &gateway_end_queue,
            None,
        )
        .await;

        assert!(result.is_err());
        let requests = agent_server.received_requests().await.unwrap();
        let sent: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            sent["ended_flows"][0]["report_id"],
            report.report_id.as_str()
        );
        assert_eq!(
            gateway_end_queue
                .pending(chrono::Utc::now().timestamp_millis())
                .await,
            vec![report]
        );
    }

    #[tokio::test]
    async fn run_heartbeat_reports_the_previous_cycles_unresolved_hosts_on_the_next_request() {
        // TT-2069, end to end: the first heartbeat applies a gateway whose endpoint hostname the
        // (faked) DNS lookup always fails for - the second heartbeat's own *outgoing request*
        // must then carry that host in unresolved_endpoint_hosts, proving the real
        // run_heartbeat/HeartbeatClient wiring, not just each piece tested in isolation.
        let agent_identity = crypto::generate_keypair();
        let first_body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.example.com","access_mode":"SELECTED_USERS","endpoints":[{"host":"erp.internal.example.com","port":443}],"entitlement_list":[]}],"node_list":[]}"#;
        let first_signature =
            crypto::sign_to_base64(&agent_identity.signing_key, first_body.as_bytes());
        let second_body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:01:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n2","policy_bundles":[],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .and(body_json(dto::ConnectorHeartbeatRequest {
                connector_public_key: "pk-1".to_string(),
                unresolved_endpoint_hosts: None,
                ended_flows: vec![],
                connection_events: Vec::new(),
                connection_events_lost: None,
            }))
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
            .and(path("/api/connectors/heartbeat"))
            .and(body_json(&dto::ConnectorHeartbeatRequest {
                connector_public_key: "pk-1".to_string(),
                unresolved_endpoint_hosts: Some(vec!["erp.internal.example.com".to_string()]),
                ended_flows: vec![],
                connection_events: Vec::new(),
                connection_events_lost: None,
            }))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(second_body, "application/json")
                    .insert_header("X-Signature", second_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
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

        let mut admission_pollers = admission_pollers();
        run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
        )
        .await
        .unwrap();

        let result = run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
        )
        .await;

        assert!(
            result.is_ok(),
            "second heartbeat's request must have matched the body_json mock above, or this is \
             an unmatched-request error instead: {result:?}"
        );
    }

    /// A queue for tests that don't inspect it: backed by a unique file under the OS temp dir,
    /// which is only ever written if the test produces a gateway-end report.
    fn test_gateway_end_queue() -> gateway_end::GatewayEndQueue {
        gateway_end::GatewayEndQueue::new(
            std::env::temp_dir().join(format!("gateway-end-{}.json", gateway_end::new_report_id())),
        )
    }

    fn bundle(gateway_id: &str, entitled_device_keys: &[&str]) -> PolicyBundle {
        PolicyBundle {
            gateway_id: gateway_id.to_string(),
            location: "Amsterdam".to_string(),
            hostname: "crm.internal.example.com".to_string(),
            access_mode: "SELECTED_USERS".to_string(),
            endpoints: vec![],
            port_rules: None,
            gateway_address: None,
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

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles, 0);

        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none()
        );
    }

    /// TT-2464: the report names the gateway, the user from the entitlement row, the device and
    /// how many flows ended - exactly what Portal needs to accept it (spec §B.18 point 3).
    #[test]
    fn reconcile_dropped_entitlements_reports_the_ended_flows_of_a_dropped_device() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        for (port, flow_id) in [(40001, "flow-1"), (40002, "flow-2")] {
            flow_table.lock().unwrap().admit(
                "n-1".to_string(),
                port,
                "gw-1".to_string(),
                flow_id.to_string(),
                "dev-A".to_string(),
                vec![],
            );
        }
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &[])];

        let reports =
            reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles, 1_234);

        assert_eq!(
            reports.len(),
            1,
            "one report per gateway and device, not per flow"
        );
        let report = &reports[0];
        assert_eq!(report.gateway_id, "gw-1");
        assert_eq!(report.user_id, "u-1");
        assert_eq!(report.device_public_key, "dev-A");
        assert_eq!(report.flows_ended, 2);
        assert_eq!(report.ended_at, 1_234);
        assert_eq!(report.report_id.len(), 36);
    }

    /// TT-1734: no event merely because an entitlement changed - the device had no active flow.
    #[test]
    fn reconcile_dropped_entitlements_reports_nothing_for_a_dropped_device_with_no_flow() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let old_bundles = vec![bundle("gw-1", &["dev-A"])];
        let new_bundles = vec![bundle("gw-1", &[])];

        let reports = reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles, 0);

        assert!(reports.is_empty());
    }

    #[test]
    fn reconcile_dropped_entitlements_reports_nothing_for_a_still_entitled_device() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit(
            "n-1".to_string(),
            40001,
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            vec![],
        );
        let bundles = vec![bundle("gw-1", &["dev-A"])];

        let reports = reconcile_dropped_entitlements(&flow_table, &bundles, &bundles, 0);

        assert!(reports.is_empty());
    }

    /// A deleted or disabled gateway drops its whole bundle - its active flows still end and must
    /// still be reported (TT-501 "Remove a Private Gateway").
    #[test]
    fn reconcile_dropped_entitlements_reports_flows_ended_by_a_vanished_gateway_bundle() {
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

        let reports = reconcile_dropped_entitlements(&flow_table, &old_bundles, &[], 0);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].gateway_id, "gw-1");
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

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles, 0);

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

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles, 0);

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

        reconcile_dropped_entitlements(&flow_table, &old_bundles, &new_bundles, 0);

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

        reconcile_dropped_entitlements(&flow_table, &[], &[bundle("gw-1", &["dev-A"])], 0);
    }

    fn events_named<'a>(events: &'a [AuditEvent], name: &str) -> Vec<&'a AuditEvent> {
        events
            .iter()
            .filter(|event| serde_json::to_value(event).unwrap()["event"] == name)
            .collect()
    }

    #[test]
    fn the_first_package_records_every_gateways_configuration_and_entitlement_list() {
        // TT-2520 (spec §B.10).
        let events = bundle_audit_events(
            None,
            &[
                bundle_with_endpoint("gw-1", "172.22.247.15", 8443),
                bundle("gw-2", &["dev-A", "dev-B"]),
            ],
        );

        let applied = events_named(&events, "policy_bundle_applied");
        assert_eq!(applied.len(), 2);
        assert_eq!(
            applied[0],
            &AuditEvent::PolicyBundleApplied {
                gateway_id: "gw-1".to_string(),
                location: bundle("gw-1", &[]).location,
                hostname: bundle("gw-1", &[]).hostname,
                port_rules: vec![dto::PortRule {
                    transport: dto::RuleTransport::TcpUdp,
                    external_port: 8443,
                    internal_host: "172.22.247.15".to_string(),
                    internal_port: 8443,
                }],
                gateway_address: None,
            }
        );
        let received = events_named(&events, "entitlement_list_received");
        assert_eq!(received.len(), 2);
        assert!(matches!(
            received[1],
            AuditEvent::EntitlementListReceived { gateway_id, entitlement_count: 2, .. } if gateway_id == "gw-2"
        ));
    }

    #[test]
    fn an_unchanged_configuration_is_not_recorded_again_but_its_entitlement_list_always_is() {
        let old = [bundle_with_endpoint("gw-1", "10.0.0.5", 443)];
        let same_config_new_list = PolicyBundle {
            entitlement_list: bundle("gw-1", &["dev-C"]).entitlement_list,
            ..bundle_with_endpoint("gw-1", "10.0.0.5", 443)
        };

        let events = bundle_audit_events(Some(&old), &[same_config_new_list]);

        assert!(events_named(&events, "policy_bundle_applied").is_empty());
        assert_eq!(events_named(&events, "entitlement_list_received").len(), 1);
    }

    #[test]
    fn a_changed_endpoint_hostname_or_location_is_recorded_as_a_new_configuration() {
        let old = [bundle_with_endpoint("gw-1", "10.0.0.5", 443)];
        let changed = [
            bundle_with_endpoint("gw-1", "10.0.0.6", 443),
            bundle_with_endpoint("gw-1", "10.0.0.5", 8443),
            PolicyBundle {
                hostname: "erp.internal.example.com".to_string(),
                ..bundle_with_endpoint("gw-1", "10.0.0.5", 443)
            },
            PolicyBundle {
                location: "Istanbul".to_string(),
                ..bundle_with_endpoint("gw-1", "10.0.0.5", 443)
            },
        ];

        for bundle in changed {
            let events = bundle_audit_events(Some(&old), &[bundle]);
            assert_eq!(events_named(&events, "policy_bundle_applied").len(), 1);
        }
    }

    #[test]
    fn a_gateway_new_since_the_last_package_is_recorded() {
        let old = [bundle_with_endpoint("gw-1", "10.0.0.5", 443)];
        let events = bundle_audit_events(
            Some(&old),
            &[
                bundle_with_endpoint("gw-1", "10.0.0.5", 443),
                bundle_with_endpoint("gw-2", "10.0.0.7", 22),
            ],
        );

        let applied = events_named(&events, "policy_bundle_applied");
        assert_eq!(applied.len(), 1);
        assert!(matches!(
            applied[0],
            AuditEvent::PolicyBundleApplied { gateway_id, .. } if gateway_id == "gw-2"
        ));
    }

    /// TT-2514: with port rules, the entry records them, and only a change to the rules - not to the
    /// transitional endpoints, which the Connector doesn't forward by - is a new configuration.
    #[test]
    fn with_port_rules_the_entry_records_the_rules_and_a_rule_change_is_a_new_configuration() {
        let rule = |internal_port: u16| dto::PortRule {
            transport: dto::RuleTransport::Tcp,
            external_port: 443,
            internal_host: "10.0.0.5".to_string(),
            internal_port,
        };
        let with_rules = |internal_port: u16, endpoint_host: &str| PolicyBundle {
            port_rules: Some(vec![rule(internal_port)]),
            ..bundle_with_endpoint("gw-1", endpoint_host, 443)
        };
        let old = [with_rules(8443, "10.0.0.5")];

        let applied = bundle_audit_events(None, &old);
        assert!(matches!(
            events_named(&applied, "policy_bundle_applied")[0],
            AuditEvent::PolicyBundleApplied { port_rules, .. } if port_rules == &vec![rule(8443)]
        ));
        assert_eq!(
            serde_json::to_value(events_named(&applied, "policy_bundle_applied")[0]).unwrap()["port_rules"],
            serde_json::json!([{"transport": "TCP", "external_port": 443, "internal_host": "10.0.0.5", "internal_port": 8443}])
        );
        assert_eq!(
            events_named(
                &bundle_audit_events(Some(&old), &[with_rules(9443, "10.0.0.5")]),
                "policy_bundle_applied"
            )
            .len(),
            1,
            "a changed rule"
        );
        assert!(
            events_named(
                &bundle_audit_events(Some(&old), &[with_rules(8443, "10.0.0.9")]),
                "policy_bundle_applied"
            )
            .is_empty(),
            "only the transitional endpoints changed"
        );
    }

    #[test]
    fn the_entitlement_list_hash_depends_on_the_entries_not_their_order() {
        let entitlement = |user: &str, key: Option<&str>| dto::Entitlement {
            user_id: user.to_string(),
            device_public_key: key.map(str::to_string),
        };
        let list = [entitlement("u-1", Some("k-1")), entitlement("u-2", None)];
        let reordered = [entitlement("u-2", None), entitlement("u-1", Some("k-1"))];
        let other_key = [entitlement("u-1", Some("k-9")), entitlement("u-2", None)];
        let fewer = [entitlement("u-1", Some("k-1"))];

        let hash = entitlement_list_sha256(&list);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, entitlement_list_sha256(&reordered));
        assert_ne!(hash, entitlement_list_sha256(&other_key));
        assert_ne!(hash, entitlement_list_sha256(&fewer));
        assert_ne!(
            entitlement_list_sha256(&[]),
            entitlement_list_sha256(&fewer)
        );
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

    /// TT-3449: a heartbeat whose rules no longer serve an open flow ends it and returns the local
    /// audit entry naming it; it is a configuration change, so it is not a gateway-end report.
    #[test]
    fn reconcile_endpoint_changes_ends_a_flow_whose_rule_was_removed_and_audits_it() {
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
        let dns_cache = dns_cache::DnsCache::new();
        flow_table
            .lock()
            .unwrap()
            .forward("n-1", 40001, None, 443, &dns_cache);

        let events = reconcile_endpoint_changes(
            &flow_table,
            &[bundle_with_endpoint("gw-1", "10.0.0.1", 8443)],
        );

        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            AuditEvent::FlowsEndedByRuleChange { gateway_id, flows_ended: 1, flows }
                if gateway_id == "gw-1"
                    && flows == &vec![audit::EndedFlow {
                        flow_id: "flow-1".to_string(),
                        device_public_key: "dev-A".to_string(),
                    }]
        ));
        assert!(
            flow_table
                .lock()
                .unwrap()
                .gateway_for("n-1", 40001)
                .is_none(),
            "the flow is gone"
        );
    }

    /// TT-3557: a flow no rule served - admitted for a port the gateway does not open - is not
    /// reported as ended by a rule change when the heartbeat's rules did not change.
    #[test]
    fn reconcile_endpoint_changes_does_not_report_a_flow_no_rule_served() {
        let rules = vec![dto::PortRule {
            transport: dto::RuleTransport::Tcp,
            external_port: 443,
            internal_host: "10.0.0.1".to_string(),
            internal_port: 80,
        }];
        let bundle = PolicyBundle {
            port_rules: Some(rules.clone()),
            ..bundle("gw-1", &[])
        };
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        flow_table.lock().unwrap().admit_flow(
            "n-1".to_string(),
            40001,
            Some(flow_table::Dialled {
                transport: flow_table::Transport::Tcp,
                gateway_address: std::net::Ipv4Addr::new(10, 99, 0, 1),
                destination_port: 8080,
            }),
            "gw-1".to_string(),
            "flow-1".to_string(),
            "dev-A".to_string(),
            rules,
        );

        let events = reconcile_endpoint_changes(&flow_table, &[bundle]);

        assert!(events.is_empty(), "nothing to report: {events:?}");
    }

    #[test]
    fn reconcile_endpoint_changes_with_no_bundles_is_a_no_op() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());

        reconcile_endpoint_changes(&flow_table, &[]);
    }

    // --- TT-3699: a changed gateway address ends the open flows to the old one (spec §B.20.3) ---

    fn bundle_with_address(gateway_id: &str, address: Option<[u8; 4]>) -> PolicyBundle {
        PolicyBundle {
            gateway_address: address.map(std::net::Ipv4Addr::from),
            ..bundle_with_endpoint(gateway_id, "10.0.0.1", 443)
        }
    }

    fn admit_to(
        flow_table: &std::sync::Mutex<FlowTable>,
        gateway_id: &str,
        port: u16,
        to: [u8; 4],
    ) {
        flow_table.lock().unwrap().admit_flow(
            "n-1".to_string(),
            port,
            Some(flow_table::Dialled {
                transport: flow_table::Transport::Tcp,
                gateway_address: std::net::Ipv4Addr::from(to),
                destination_port: 443,
            }),
            gateway_id.to_string(),
            format!("flow-{port}"),
            "dev-A".to_string(),
            bundle_with_endpoint(gateway_id, "10.0.0.1", 443).rules(),
        );
    }

    #[test]
    fn reconcile_gateway_address_changes_ends_the_flows_to_the_old_address_and_audits_them() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        admit_to(&flow_table, "gw-1", 40001, [100, 64, 5, 10]);
        admit_to(&flow_table, "gw-2", 40002, [100, 64, 5, 20]);
        let old = [
            bundle_with_address("gw-1", Some([100, 64, 5, 10])),
            bundle_with_address("gw-2", Some([100, 64, 5, 20])),
        ];
        let new = [
            bundle_with_address("gw-1", Some([100, 64, 5, 11])),
            bundle_with_address("gw-2", Some([100, 64, 5, 20])),
        ];

        let events = reconcile_gateway_address_changes(&flow_table, &old, &new);

        assert_eq!(
            events,
            vec![AuditEvent::FlowsEndedByAddressChange {
                gateway_id: "gw-1".to_string(),
                old_gateway_address: Some(std::net::Ipv4Addr::new(100, 64, 5, 10)),
                gateway_address: Some(std::net::Ipv4Addr::new(100, 64, 5, 11)),
                flows_ended: 1,
                flows: vec![audit::EndedFlow {
                    flow_id: "flow-40001".to_string(),
                    device_public_key: "dev-A".to_string(),
                }],
            }]
        );
        assert_eq!(
            flow_table.lock().unwrap().flow_count(),
            1,
            "the other gateway's flow stays"
        );
    }

    #[test]
    fn reconcile_gateway_address_changes_ends_nothing_for_an_unchanged_or_new_gateway() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        admit_to(&flow_table, "gw-1", 40001, [100, 64, 5, 10]);
        admit_to(&flow_table, "gw-2", 40002, [10, 99, 0, 2]);
        admit_to(&flow_table, "gw-3", 40003, [10, 99, 0, 3]);
        let old = [
            bundle_with_address("gw-1", Some([100, 64, 5, 10])),
            bundle_with_address("gw-2", None),
        ];
        let new = [
            bundle_with_address("gw-1", Some([100, 64, 5, 10])),
            bundle_with_address("gw-2", None),
            bundle_with_address("gw-3", Some([100, 64, 5, 30])),
        ];

        let events = reconcile_gateway_address_changes(&flow_table, &old, &new);

        assert!(events.is_empty(), "nothing to end: {events:?}");
        assert_eq!(flow_table.lock().unwrap().flow_count(), 3);
    }

    /// The Portal no longer holds an address: the flows to the old one end, the flows already on a
    /// pool address stay.
    #[test]
    fn reconcile_gateway_address_changes_ends_the_flows_to_a_removed_address() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        admit_to(&flow_table, "gw-1", 40001, [100, 64, 5, 10]);
        admit_to(&flow_table, "gw-1", 40002, [10, 99, 0, 1]);

        let events = reconcile_gateway_address_changes(
            &flow_table,
            &[bundle_with_address("gw-1", Some([100, 64, 5, 10]))],
            &[bundle_with_address("gw-1", None)],
        );

        assert!(matches!(
            &events[..],
            [AuditEvent::FlowsEndedByAddressChange {
                old_gateway_address: Some(_),
                gateway_address: None,
                flows_ended: 1,
                flows,
                ..
            }] if flows[0].flow_id == "flow-40001"
        ));
        assert_eq!(flow_table.lock().unwrap().flow_count(), 1);
    }

    /// TT-2529: the address is part of the gateway's configuration (spec §B.10), recorded only when
    /// the Portal holds one - an entry without it reads as before.
    #[test]
    fn a_gateway_address_change_is_a_new_configuration_and_is_recorded() {
        let old = [bundle_with_address("gw-1", None)];
        let new = [bundle_with_address("gw-1", Some([100, 64, 5, 10]))];

        let unchanged = bundle_audit_events(Some(&old), &old);
        let changed = bundle_audit_events(Some(&old), &new);

        assert!(events_named(&unchanged, "policy_bundle_applied").is_empty());
        let applied = events_named(&changed, "policy_bundle_applied");
        assert_eq!(applied.len(), 1);
        assert_eq!(
            serde_json::to_value(applied[0]).unwrap()["gateway_address"],
            "100.64.5.10"
        );
        let without = bundle_audit_events(None, &old);
        assert!(
            serde_json::to_value(events_named(&without, "policy_bundle_applied")[0])
                .unwrap()
                .get("gateway_address")
                .is_none()
        );
    }

    /// End-to-end through two real `run_heartbeat` calls: entitlement present on the first, dropped
    /// on the second - proving the diff actually runs off `PolicyStore`'s real before/after state,
    /// not just the pure reconciliation function above.
    #[tokio::test]
    async fn a_second_heartbeat_evicts_a_flow_whose_device_dropped_out_of_entitlement_list() {
        let agent_identity = crypto::generate_keypair();
        let first_body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]},{"gateway_id":"gw-2","location":"Amsterdam","hostname":"erp.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
        let second_body = r#"{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:01:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n2","policy_bundles":[{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[]},{"gateway_id":"gw-2","location":"Amsterdam","hostname":"erp.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{"user_id":"u-1","device_public_key":"dev-A"}]}],"node_list":[]}"#;
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
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(first_body, "application/json")
                    .insert_header("X-Signature", first_signature.as_str()),
            )
            .up_to_n_times(1)
            .mount(&agent_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(second_body, "application/json")
                    .insert_header("X-Signature", second_signature.as_str()),
            )
            .mount(&agent_server)
            .await;

        let config = config(registry_server.uri());
        let agent_base_url = agent_server.uri();
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_base_url).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();

        let mut admission_pollers = admission_pollers();
        run_heartbeat(
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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
            "pk-1",
            &agent_directory,
            &registry_client,
            &heartbeat_client,
            &policy_store,
            &audit_log,
            &tunnel_manager,
            &wg_socket,
            &flow_table,
            &dns_cache,
            &mut admission_pollers,
            &test_gateway_end_queue(),
            None,
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

    /// TT-3770 (spec §B.9 point 1) end to end through real `run_heartbeat` calls: once a fresh
    /// live-session snapshot no longer holds a flow's session, that flow ends with a local audit entry
    /// of its own and no gateway-end report; a flow whose session is still live stays.
    #[tokio::test]
    async fn a_heartbeat_ends_only_the_flows_whose_session_dropped_out_of_the_snapshot() {
        let agent_identity = crypto::generate_keypair();
        let live_a = live_sessions::token_digest("token-a");
        let live_b = live_sessions::token_digest("token-b");
        let body = |nonce: &str, digests: &[&str]| {
            let digests = digests
                .iter()
                .map(|digest| format!(r#""{digest}""#))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                r#"{{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"{nonce}","policy_bundles":[{{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[],"entitlement_list":[{{"user_id":"u-1","device_public_key":"dev-A"}}]}}],"node_list":[],"zero_trust_enabled":true,"live_sessions":{{"dev-A":[{digests}]}}}}"#
            )
        };
        let first_body = body("n1", &[&live_a, &live_b]);
        let second_body = body("n2", &[&live_b]);

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
        for (body, times) in [(&first_body, Some(1)), (&second_body, None)] {
            let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());
            let mock = Mock::given(method("POST"))
                .and(path("/api/connectors/heartbeat"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(body.clone(), "application/json")
                        .insert_header("X-Signature", signature.as_str()),
                );
            match times {
                Some(times) => mock.up_to_n_times(times).mount(&agent_server).await,
                None => mock.mount(&agent_server).await,
            }
        }

        let config = config(registry_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_server.uri()).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();
        let gateway_end_queue = test_gateway_end_queue();
        let mut admission_pollers = admission_pollers();

        for round in 0..2 {
            run_heartbeat(
                "pk-1",
                &agent_directory,
                &registry_client,
                &heartbeat_client,
                &policy_store,
                &audit_log,
                &tunnel_manager,
                &wg_socket,
                &flow_table,
                &dns_cache,
                &mut admission_pollers,
                &gateway_end_queue,
                None,
            )
            .await
            .unwrap();
            if round == 0 {
                let mut table = flow_table.lock().unwrap();
                for (port, flow_id, digest) in
                    [(40001, "flow-a", &live_a), (40002, "flow-b", &live_b)]
                {
                    table.admit_session_flow(
                        "n-1".to_string(),
                        port,
                        None,
                        "gw-1".to_string(),
                        flow_id.to_string(),
                        "dev-A".to_string(),
                        vec![],
                        Some(digest.clone()),
                    );
                }
            }
        }

        {
            let table = flow_table.lock().unwrap();
            assert!(
                table.gateway_for("n-1", 40001).is_none(),
                "the flow whose session dropped out of the snapshot must end"
            );
            assert_eq!(table.gateway_for("n-1", 40002), Some("gw-1"));
        }
        assert!(
            gateway_end_queue
                .pending(chrono::Utc::now().timestamp_millis())
                .await
                .is_empty(),
            "a session ending is not a revoked entitlement - no gateway-end report"
        );
        let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let lease_end: Vec<serde_json::Value> = audit
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|entry| entry["event"] == "flows_ended_by_lease_end")
            .collect();
        assert_eq!(lease_end.len(), 1);
        assert_eq!(lease_end[0]["gateway_id"], "gw-1");
        assert_eq!(lease_end[0]["device_public_key"], "dev-A");
        assert_eq!(lease_end[0]["flows_ended"], 1);
        assert_eq!(lease_end[0]["flows"][0]["flow_id"], "flow-a");
        assert!(!audit.contains(r#""event":"flows_ended""#));
    }

    /// TT-3770 (spec §B.9 point 1, Rollout): a flow admitted without a session digest - before the
    /// first snapshot - ends on the first snapshot that enforces the binding; one whose session is in
    /// it stays. No snapshot in force ends nothing.
    #[test]
    fn the_first_snapshot_ends_the_flows_admitted_without_a_session() {
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let sessions = live_sessions::LiveSessions::new(Default::default());
        for (port, flow_id, digest) in [(40001, "f-old", None), (40002, "f-live", Some("d1"))] {
            flow_table.lock().unwrap().admit_session_flow(
                "n-1".to_string(),
                port,
                None,
                "gw-1".to_string(),
                flow_id.to_string(),
                "dev-A".to_string(),
                vec![],
                digest.map(ToString::to_string),
            );
        }
        assert!(reconcile_lease_ends(&flow_table, &sessions).is_empty());

        sessions.update(
            Some(true),
            Some(std::collections::HashMap::from([(
                "dev-A".to_string(),
                vec!["d1".to_string()],
            )])),
            std::time::Instant::now(),
        );
        let events = reconcile_lease_ends(&flow_table, &sessions);

        assert_eq!(
            events,
            vec![AuditEvent::FlowsEndedByLeaseEnd {
                gateway_id: "gw-1".to_string(),
                device_public_key: "dev-A".to_string(),
                flows_ended: 1,
                flows: vec![audit::EndedFlow {
                    flow_id: "f-old".to_string(),
                    device_public_key: "dev-A".to_string(),
                }],
            }]
        );
        assert_eq!(
            flow_table.lock().unwrap().gateway_for("n-1", 40002),
            Some("gw-1")
        );
    }

    /// TT-3770: a snapshot over the size limit is refused whole and recorded; the last one stays in use.
    #[tokio::test]
    async fn a_refused_snapshot_is_recorded_and_the_last_one_kept() {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        record_snapshot_update(
            &live_sessions::SnapshotUpdate::Refused {
                entries: 20_001,
                limit: 20_000,
            },
            &audit_log,
        )
        .await;
        record_snapshot_update(&live_sessions::SnapshotUpdate::Missing, &audit_log).await;
        record_snapshot_update(
            &live_sessions::SnapshotUpdate::Accepted { entries: 1 },
            &audit_log,
        )
        .await;
        let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let events: Vec<serde_json::Value> = audit
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event"], "live_session_snapshot_refused");
        assert_eq!(events[0]["entries"], 20_001);
        assert_eq!(events[0]["limit"], 20_000);
        assert_eq!(events[1]["event"], "live_session_snapshot_missing");
    }

    /// TT-3699 end to end through real `run_heartbeat` calls (TT-2529 "Nodes use the Portal's
    /// Gateway IP", including a change of address): the first Portal address ends the flows to the
    /// pool address, an unchanged address ends nothing, a changed one ends the flows to the old
    /// address - only that gateway's, with no gateway-end report, and recorded in the local audit log.
    #[tokio::test]
    async fn heartbeats_that_change_a_gateways_address_end_only_the_flows_to_the_old_one() {
        let agent_identity = crypto::generate_keypair();
        let body = |nonce: &str, gw_1_address: Option<&str>| {
            let address = gw_1_address
                .map(|address| format!(r#""gateway_address":"{address}","#))
                .unwrap_or_default();
            format!(
                r#"{{"connector_id":"c-1","connector_public_key":"pk-1","generated_at":"2026-08-27T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"{nonce}","policy_bundles":[{{"gateway_id":"gw-1","location":"Amsterdam","hostname":"crm.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[{{"host":"10.0.0.1","port":443}}],{address}"entitlement_list":[{{"user_id":"u-1","device_public_key":"dev-A"}}]}},{{"gateway_id":"gw-2","location":"Amsterdam","hostname":"erp.internal.example.com","access_mode":"SELECTED_USERS","endpoints":[{{"host":"10.0.0.1","port":443}}],"entitlement_list":[{{"user_id":"u-1","device_public_key":"dev-A"}}]}}],"node_list":[]}}"#
            )
        };
        let bodies = [
            body("n1", None),
            body("n2", Some("100.64.5.10")),
            body("n3", Some("100.64.5.10")),
            body("n4", Some("100.64.5.11")),
        ];

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
        for body in &bodies {
            let signature = crypto::sign_to_base64(&agent_identity.signing_key, body.as_bytes());
            Mock::given(method("POST"))
                .and(path("/api/connectors/heartbeat"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(body.clone(), "application/json")
                        .insert_header("X-Signature", signature.as_str()),
                )
                .up_to_n_times(1)
                .mount(&agent_server)
                .await;
        }

        let config = config(registry_server.uri());
        let http = reqwest::Client::new();
        let registry_client = RegistryClient::new(http.clone(), config.registry_base_url.clone());
        let heartbeat_client = HeartbeatClient::new(http);
        let (agent_directory, _agents_json) = test_agent_directory(agent_server.uri()).await;
        let policy_store = PolicyStore::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_log = AuditLog::new(dir.path().join("audit.log"));
        let tunnel_manager = Mutex::new(TunnelManager::new(
            boringtun::x25519::StaticSecret::random_from_rng(rand_core::OsRng),
        ));
        let wg_socket = wg_socket().await;
        let flow_table = std::sync::Mutex::new(FlowTable::new());
        let dns_cache = dns_cache::DnsCache::new();
        let gateway_end_queue = test_gateway_end_queue();
        let mut admission_pollers = admission_pollers();
        let mut heartbeat = async || {
            run_heartbeat(
                "pk-1",
                &agent_directory,
                &registry_client,
                &heartbeat_client,
                &policy_store,
                &audit_log,
                &tunnel_manager,
                &wg_socket,
                &flow_table,
                &dns_cache,
                &mut admission_pollers,
                &gateway_end_queue,
                None,
            )
            .await
            .unwrap();
        };
        let dialled = |to: [u8; 4]| flow_table::Dialled {
            transport: flow_table::Transport::Tcp,
            gateway_address: std::net::Ipv4Addr::from(to),
            destination_port: 443,
        };
        let forwards = |port: u16, to: [u8; 4]| {
            matches!(
                flow_table
                    .lock()
                    .unwrap()
                    .forward("n-1", port, Some(dialled(to)), 443, &dns_cache),
                flow_table::Forwarding::Forward { .. }
            )
        };

        // 1. No Portal address yet: the nodes serve both gateways on their pool addresses.
        heartbeat().await;
        admit_to(&flow_table, "gw-1", 40001, [10, 99, 0, 1]);
        admit_to(&flow_table, "gw-2", 40002, [10, 99, 0, 2]);
        assert!(forwards(40001, [10, 99, 0, 1]) && forwards(40002, [10, 99, 0, 2]));

        // 2. The Portal's first address for gw-1 (the rollout): its flow to the pool address ends.
        heartbeat().await;
        assert!(
            !forwards(40001, [10, 99, 0, 1]),
            "the flow to the pool address ended"
        );
        assert!(
            forwards(40002, [10, 99, 0, 2]),
            "the other gateway's flow stays"
        );
        admit_to(&flow_table, "gw-1", 40003, [100, 64, 5, 10]);
        assert!(
            forwards(40003, [100, 64, 5, 10]),
            "served on the Portal address"
        );

        // 3. The same address again: nothing ends.
        heartbeat().await;
        assert!(forwards(40003, [100, 64, 5, 10]) && forwards(40002, [10, 99, 0, 2]));

        // 4. The address changes: the flow to the old one ends.
        heartbeat().await;
        assert!(
            !forwards(40003, [100, 64, 5, 10]),
            "the flow to the old address ended"
        );
        assert!(forwards(40002, [10, 99, 0, 2]));
        assert_eq!(flow_table.lock().unwrap().flow_count(), 1);

        // A configuration change, not a withdrawal of access: no gateway-end report (spec §B.18).
        assert!(
            gateway_end_queue
                .pending(chrono::Utc::now().timestamp_millis())
                .await
                .is_empty()
        );
        let entries = read_audit_lines(&dir);
        assert!(entries.iter().all(|e| e["event"] != "flows_ended"));
        let ended: Vec<&serde_json::Value> = entries
            .iter()
            .filter(|e| e["event"] == "flows_ended_by_address_change")
            .collect();
        assert_eq!(ended.len(), 2);
        assert_eq!(ended[0]["gateway_id"], "gw-1");
        assert_eq!(ended[0]["old_gateway_address"], serde_json::Value::Null);
        assert_eq!(ended[0]["gateway_address"], "100.64.5.10");
        assert_eq!(ended[0]["flows"][0]["flow_id"], "flow-40001");
        assert_eq!(ended[1]["old_gateway_address"], "100.64.5.10");
        assert_eq!(ended[1]["gateway_address"], "100.64.5.11");
        assert_eq!(ended[1]["flows"][0]["flow_id"], "flow-40003");
        let gw_1_applied: Vec<&serde_json::Value> = entries
            .iter()
            .filter(|e| e["event"] == "policy_bundle_applied" && e["gateway_id"] == "gw-1")
            .collect();
        assert_eq!(gw_1_applied.len(), 3, "heartbeats 1, 2 and 4 changed it");
        assert!(gw_1_applied[0].get("gateway_address").is_none());
        assert_eq!(gw_1_applied[2]["gateway_address"], "100.64.5.11");
    }

    /// TT-2250 review (spec §B.22 point 5): the list is capped at the Agent's 500 names, the first
    /// in sorted order after deduplication.
    #[test]
    fn unresolved_endpoint_hosts_are_capped_at_the_agents_limit_in_sorted_order() {
        let hosts: Vec<String> = (0..dto::MAX_UNRESOLVED_ENDPOINT_HOSTS + 100)
            .rev()
            .map(|i| format!("host-{i:04}.internal.example.com"))
            .collect();
        let host_refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let bundles = vec![
            bundle_with_endpoints("gw-1", &host_refs),
            bundle_with_endpoints("gw-2", &host_refs),
        ];
        let unresolved = unresolved_hosts_in(&bundles, &dns_cache::DnsCache::new());
        assert_eq!(unresolved.len(), dto::MAX_UNRESOLVED_ENDPOINT_HOSTS);
        assert_eq!(unresolved[0], "host-0000.internal.example.com");
        assert_eq!(
            unresolved.last().unwrap(),
            &format!(
                "host-{:04}.internal.example.com",
                dto::MAX_UNRESOLVED_ENDPOINT_HOSTS - 1
            )
        );
        assert!(unresolved.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn blank_and_overlong_host_names_are_dropped_before_the_cap_as_the_agent_does() {
        let too_long = format!("{}.example.com", "a".repeat(250));
        let bundles = vec![bundle_with_endpoints(
            "gw-1",
            &["  ", too_long.as_str(), "erp.internal.example.com"],
        )];
        assert_eq!(
            unresolved_hosts_in(&bundles, &dns_cache::DnsCache::new()),
            vec!["erp.internal.example.com".to_string()]
        );
    }

    fn heartbeat_request_with_hosts(count: usize) -> dto::ConnectorHeartbeatRequest {
        dto::ConnectorHeartbeatRequest {
            connector_public_key: "pk-1".to_string(),
            // The longest names the Agent accepts (255 characters).
            unresolved_endpoint_hosts: Some(
                (0..count)
                    .map(|i| format!("{i:05}{}", "h".repeat(250)))
                    .collect(),
            ),
            ended_flows: Vec::new(),
            connection_events: Vec::new(),
            connection_events_lost: Some(connection_events::LostReport {
                report_id: gateway_end::new_report_id(),
                count: 7,
                first_at: 1,
                last_at: 2,
            }),
        }
    }

    fn queued_establishments(
        count: usize,
        key_len: usize,
    ) -> Vec<connection_events::ConnectionEvent> {
        let mut state = connection_events::State::default();
        for i in 0..count {
            state.flow_admitted(
                "0b0c6f1e-5d1a-4c55-9a39-6f3b2a7d9e10",
                &format!("{i:05}{}", "k".repeat(key_len)),
                Some(&live_sessions::token_digest("token")),
                "6c1b8f7e-2a3d-4e5f-8a9b-0c1d2e3f4a5b",
                "node-1",
                1_700_000_000_000,
            );
        }
        state.batch(1_700_000_000_001).events
    }

    /// TT-2250 review (spec §B.22 point 5): with the longest host list, 200 ordinary connection
    /// events fit the Agent's body limit, as the spec sizes it.
    #[test]
    fn a_full_batch_fits_beside_the_longest_unresolved_host_list() {
        let mut request = heartbeat_request_with_hosts(dto::MAX_UNRESOLVED_ENDPOINT_HOSTS);
        let events = queued_establishments(connection_events::MAX_PER_HEARTBEAT, 44);
        assert_eq!(events.len(), connection_events::MAX_PER_HEARTBEAT);
        let fitting = connection_events_within_body_limit(
            &request,
            &events,
            dto::HEARTBEAT_BODY_BUDGET_BYTES,
        );
        assert_eq!(fitting, events.len());
        request.connection_events = events;
        assert!(serde_json::to_vec(&request).unwrap().len() <= dto::HEARTBEAT_BODY_BUDGET_BYTES);
    }

    /// TT-2250 review: events that would take the request over the limit stay queued; the request
    /// sent, lost report included, stays under it.
    #[test]
    fn connection_events_over_the_body_limit_are_held_for_the_next_heartbeat() {
        let mut request = heartbeat_request_with_hosts(dto::MAX_UNRESOLVED_ENDPOINT_HOSTS);
        // Unusually long keys: 200 of these would not fit.
        let events = queued_establishments(connection_events::MAX_PER_HEARTBEAT, 1_000);
        let fitting = connection_events_within_body_limit(
            &request,
            &events,
            dto::HEARTBEAT_BODY_BUDGET_BYTES,
        );
        assert!(fitting > 0 && fitting < events.len(), "{fitting}");
        request.connection_events = events[..fitting].to_vec();
        let size = serde_json::to_vec(&request).unwrap().len();
        assert!(size <= dto::HEARTBEAT_BODY_BUDGET_BYTES, "{size}");
        request.connection_events = events[..=fitting].to_vec();
        assert!(
            serde_json::to_vec(&request).unwrap().len() > dto::HEARTBEAT_BODY_BUDGET_BYTES,
            "the count is exact: one more does not fit"
        );
    }

    fn open_connection(node_id: &str, digest: Option<&str>) -> connection_events::OpenConnection {
        let mut state = connection_events::State::default();
        state.flow_admitted("gw-1", "dev-A", digest, "u-1", node_id, 1);
        state.open_connections()[0].clone()
    }

    fn snapshot(digests: &[&str]) -> live_sessions::LiveSessions {
        let sessions = live_sessions::LiveSessions::new(Default::default());
        sessions.update(
            Some(true),
            Some(std::collections::HashMap::from([(
                "dev-A".to_string(),
                digests.iter().map(ToString::to_string).collect(),
            )])),
            std::time::Instant::now(),
        );
        sessions
    }

    /// TT-2250 review (spec §B.22 point 2): `session_ended` when the accepted snapshot no longer
    /// holds the connection's session; nothing while it does, or when no snapshot was accepted.
    #[test]
    fn a_connection_whose_session_left_the_snapshot_ends_as_session_ended() {
        use connection_events::Observation;
        let connection = open_connection("n-1", Some("d1"));
        let bundles = vec![bundle("gw-1", &["dev-A"])];
        let no_removals = std::collections::HashMap::new();
        let no_drops = std::collections::HashSet::new();
        let live = snapshot(&["d1"]);
        let gone = snapshot(&["d2"]);
        assert_eq!(
            observe_connection_end(&connection, &bundles, &no_removals, Some(&live), &no_drops),
            None
        );
        assert_eq!(
            observe_connection_end(&connection, &bundles, &no_removals, None, &no_drops),
            None,
            "no snapshot accepted this heartbeat"
        );
        assert_eq!(
            observe_connection_end(&connection, &bundles, &no_removals, Some(&gone), &no_drops),
            Some((Observation::SessionEnded, 0))
        );
    }

    /// TT-2250 review (spec §B.22 point 2): `node_removed` when the node of the connection's last
    /// admitted flow left the node list; another node leaving ends nothing.
    #[test]
    fn a_connection_whose_node_left_the_node_list_ends_as_node_removed() {
        use connection_events::Observation;
        let connection = open_connection("n-1", Some("d1"));
        let bundles = vec![bundle("gw-1", &["dev-A"])];
        let no_removals = std::collections::HashMap::new();
        let live = snapshot(&["d1"]);
        assert_eq!(
            observe_connection_end(
                &connection,
                &bundles,
                &no_removals,
                Some(&live),
                &std::collections::HashSet::from(["n-2"])
            ),
            None
        );
        assert_eq!(
            observe_connection_end(
                &connection,
                &bundles,
                &no_removals,
                Some(&live),
                &std::collections::HashSet::from(["n-1"])
            ),
            Some((Observation::NodeRemoved, 0))
        );
    }

    /// TT-2250 review (spec §B.22 point 2): when one heartbeat gives a connection several
    /// observations, the first of gateway_removed > entitlement_removed > session_ended >
    /// node_removed counts; a removal carries the flows the refresh ended.
    #[test]
    fn the_first_observation_in_the_specs_order_counts() {
        use connection_events::Observation;
        let connection = open_connection("n-1", Some("d1"));
        let removals =
            std::collections::HashMap::from([(("gw-1".to_string(), "dev-A".to_string()), 3)]);
        let gone = snapshot(&["d2"]);
        let node_gone = std::collections::HashSet::from(["n-1"]);
        let observe = |bundles: &[PolicyBundle]| {
            observe_connection_end(&connection, bundles, &removals, Some(&gone), &node_gone)
        };
        assert_eq!(
            observe(&[bundle("gw-2", &["dev-A"])]),
            Some((Observation::GatewayRemoved, 3)),
            "all four apply"
        );
        assert_eq!(
            observe(&[bundle("gw-1", &["dev-B"])]),
            Some((Observation::EntitlementRemoved, 3)),
            "all but the gateway removal apply"
        );
        assert_eq!(
            observe(&[bundle("gw-1", &["dev-A"])]),
            Some((Observation::SessionEnded, 0)),
            "session and node apply"
        );
    }
}
