//! Environment-driven config. The Connector runs on the enterprise's own network,
//! installed by their admin - config comes from env vars set at install time, not
//! a config server (no such thing exists here; per the confirmed TT-501 flow, the
//! admin registers the Connector's public key manually in Portal, not the other
//! way around).

use anyhow::{Context, Result};
use std::env;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

pub struct Config {
    /// The environment's `agents.json` list (TT-2210) - the Connector heartbeats through whichever
    /// `operational` Agent it lists, re-resolving when that one stops answering, instead of being
    /// pinned to one Agent address that silently breaks when that instance rotates (spec §B.4: "any
    /// closest, publicly available instance"). There is no connector_id here either: the Connector
    /// identifies itself by its own public key, the only identity it has before an admin registers
    /// it, so nothing has to be configured on this host after that registration.
    pub agents_json_url: String,
    pub registry_base_url: String,
    pub identity_key_path: PathBuf,
    pub audit_log_path: PathBuf,
    /// Konyk's answer (TT-1732 comment thread): 60s default, must stay configurable
    /// and below Agent's 5-minute signature validity window.
    pub heartbeat_interval: Duration,
    /// The HTTP port each paired Node's Gatekeeper listens on, for the flow-admission/release
    /// control channel (TT-2144) - the Connector polls out to `http://{gatekeeper_wg0_address}:
    /// {this port}/api/connector/{connector_id}/poll`, *within* the Connector<->Node tunnel (spec
    /// §B.8; see `gatekeeper_wg0_address`'s own doc for that address, and `admission_poller`'s
    /// module doc for how a plain TCP connection to it ends up carried through the tunnel with no
    /// new userspace TCP stack needed). No inbound listener of its own anymore (replaces the old
    /// `control_plane_port`, which was the port *this* process used to listen on before the
    /// channel flipped direction).
    pub gatekeeper_http_port: u16,
    /// Gatekeeper's own fixed address on the `wg0` interface this Connector is a peer on (TT-2144
    /// review, PR #21: previously a hardcoded constant in `tun_device.rs`, `10.66.66.1` - a real
    /// orchestrator-side provisioning convention, but one a node provisioned with a different wg0
    /// address would silently violate, sending every flow admission/release into a permanent
    /// fail-closed with no config knob to recover without a rebuild). Defaults to that same
    /// `10.66.66.1` (unchanged behavior for the fleet's actual convention), overridable via
    /// `CONNECTOR_GATEKEEPER_WG0_ADDRESS` for a deployment that genuinely differs. `tun_device`'s
    /// own kernel return-route is derived from this same value (its /24), not a second, separately
    /// hardcoded subnet - one address to get right, not two.
    pub gatekeeper_wg0_address: Ipv4Addr,
    /// Netmask for the Connector's TUN interface - the address itself is no longer a local
    /// config concern (TT-1838): it's `connector_virtual_ip`, learned from the first successful
    /// heartbeat (Portal's own registered, per-Connector address), not guessed here.
    pub tun_netmask: Ipv4Addr,
    /// Optional PEM bundle of extra root CA certificates to trust for the Agent/Registry HTTP
    /// clients (TT-2027) - on top of, not instead of, the default trust (Mozilla's bundled roots
    /// and, since this same fix, the box's own OS trust store). Lets an Enterprise Admin running
    /// Agent behind a private/internal CA point the Connector at it explicitly; unset by default,
    /// which leaves TLS validation exactly as it was before this option existed. See
    /// `ca_trust::load_extra_root_certificates` for how this is used and why an unreadable/invalid
    /// path fails startup rather than silently falling back to the default roots.
    pub ca_bundle_path: Option<PathBuf>,
}

/// Konyk's answer (TT-1732 comment thread): default 60s, must stay below
/// Agent's 5-minute (300s) signature validity window.
const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: u64 = 60;
const AGENT_SIGNATURE_VALIDITY_SECONDS: u64 = 300;

/// Shared with the standalone `--generate-identity` mode (TT-1886), which prints the Connector's
/// public key without the rest of `Config::from_env`'s required env vars.
pub fn identity_key_path_from_env() -> PathBuf {
    PathBuf::from(
        env::var("CONNECTOR_IDENTITY_KEY_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/var/skipr/connector/.keys/identity.key".to_string()),
    )
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            agents_json_url: require_env("AGENTS_JSON_URL")?,
            registry_base_url: require_env("REGISTRY_BASE_URL")?,
            identity_key_path: identity_key_path_from_env(),
            audit_log_path: PathBuf::from(
                env::var("CONNECTOR_AUDIT_LOG_PATH")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "/var/skipr/connector/audit/audit.log".to_string()),
            ),
            // 4000 matches secure-connect-backend-gatekeeper's own default `server.port`
            // (application-prod.yml) - overridable in case a deployment ever changes it.
            gatekeeper_http_port: env::var("CONNECTOR_GATEKEEPER_HTTP_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(4000),
            gatekeeper_wg0_address: env::var("CONNECTOR_GATEKEEPER_WG0_ADDRESS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(Ipv4Addr::new(10, 66, 66, 1)),
            tun_netmask: env::var("CONNECTOR_TUN_NETMASK")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
            heartbeat_interval: parse_heartbeat_interval(),
            // PR #11 review: trims before use, not just before the blank-check - a value with
            // stray leading/trailing whitespace (systemd EnvironmentFile doesn't strip it,
            // per install-systemd.sh's own CONNECTOR_IDENTITY_KEY_PATH lesson) previously passed
            // the blank-check but still built a PathBuf containing the whitespace, which would
            // never resolve to the real file.
            ca_bundle_path: env::var("CONNECTOR_CA_BUNDLE_PATH")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
        })
    }
}

fn require_env(name: &str) -> Result<String> {
    // A systemd EnvironmentFile line like `VAR=` sets VAR to the empty string, not unset - an
    // admin who left a required placeholder blank must still fail here, not start with an empty
    // value.
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("required environment variable {name} is not set"))
}

/// A zero interval reaches `tokio::time::interval` in `main`, which panics on
/// a zero period - reject it (and any unparseable/non-positive value) the
/// same way `tun_addr` falls back to a safe default rather than letting a bad
/// env var take the whole process down. Also warns (doesn't reject - this
/// isn't a correctness invariant the same way zero is) when the configured
/// interval is at or above Agent's signature validity window, since a
/// heartbeat that rare would race package expiry (TT-1732 review, Tasneem).
fn parse_heartbeat_interval() -> Duration {
    let raw = env::var("HEARTBEAT_INTERVAL_SECONDS").ok();
    let seconds = raw
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|&seconds| seconds > 0)
        .unwrap_or_else(|| {
            if let Some(value) = raw.as_deref() {
                tracing::warn!(
                    value,
                    default = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
                    "HEARTBEAT_INTERVAL_SECONDS must be a positive integer - falling back to the default"
                );
            }
            DEFAULT_HEARTBEAT_INTERVAL_SECONDS
        });

    if seconds >= AGENT_SIGNATURE_VALIDITY_SECONDS {
        tracing::warn!(
            heartbeat_interval_seconds = seconds,
            agent_signature_validity_seconds = AGENT_SIGNATURE_VALIDITY_SECONDS,
            "heartbeat interval is at or above Agent's signature validity window - heartbeats may race package expiry"
        );
    }

    Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_all() {
        for key in [
            "AGENTS_JSON_URL",
            "REGISTRY_BASE_URL",
            "CONNECTOR_IDENTITY_KEY_PATH",
            "CONNECTOR_AUDIT_LOG_PATH",
            "CONNECTOR_GATEKEEPER_HTTP_PORT",
            "CONNECTOR_GATEKEEPER_WG0_ADDRESS",
            "CONNECTOR_TUN_NETMASK",
            "HEARTBEAT_INTERVAL_SECONDS",
            "CONNECTOR_CA_BUNDLE_PATH",
        ] {
            unsafe { env::remove_var(key) };
        }
    }

    #[test]
    fn errors_when_a_required_variable_is_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();

        assert!(Config::from_env().is_err());
    }

    /// TT-2210: the only per-environment values a Connector needs are the two its install command
    /// writes - nothing issued at registration (no connector_id) and no pinned Agent address.
    #[test]
    fn starts_with_only_the_agents_json_url_and_registry_url_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(
            config.agents_json_url,
            "https://agents.example.com/agents.json"
        );
        assert_eq!(config.registry_base_url, "https://registry.example.com");
        clear_all();
    }

    #[test]
    fn errors_when_the_agents_json_url_is_missing_or_blank() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }
        assert!(Config::from_env().is_err());

        unsafe {
            env::set_var("AGENTS_JSON_URL", "  ");
        }
        assert!(Config::from_env().is_err());
        clear_all();
    }

    #[test]
    fn defaults_the_heartbeat_interval_to_sixty_seconds() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
        clear_all();
    }

    #[test]
    fn defaults_the_audit_log_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(
            config.audit_log_path,
            PathBuf::from("/var/skipr/connector/audit/audit.log")
        );
        clear_all();
    }

    #[test]
    fn defaults_the_ca_bundle_path_to_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.ca_bundle_path, None);
        clear_all();
    }

    #[test]
    fn reads_a_configured_ca_bundle_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var(
                "CONNECTOR_CA_BUNDLE_PATH",
                "/etc/skipr/connector/ca-bundle.pem",
            );
        }

        let config = Config::from_env().unwrap();

        assert_eq!(
            config.ca_bundle_path,
            Some(PathBuf::from("/etc/skipr/connector/ca-bundle.pem"))
        );
        clear_all();
    }

    /// PR #11 review: the value must be trimmed before it becomes the path, not just before the
    /// blank-check - a value that's only whitespace after trimming must still resolve to `None`
    /// (already covered by `defaults_the_ca_bundle_path_to_unset`'s sibling), but a value with real
    /// content plus stray surrounding whitespace must resolve to the trimmed path, not one that
    /// still has the whitespace baked in (which would never exist on disk).
    #[test]
    fn trims_surrounding_whitespace_from_a_configured_ca_bundle_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var(
                "CONNECTOR_CA_BUNDLE_PATH",
                "  /etc/skipr/connector/ca-bundle.pem  ",
            );
        }

        let config = Config::from_env().unwrap();

        assert_eq!(
            config.ca_bundle_path,
            Some(PathBuf::from("/etc/skipr/connector/ca-bundle.pem"))
        );
        clear_all();
    }

    #[test]
    fn reads_a_configured_audit_log_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_AUDIT_LOG_PATH", "/tmp/custom-audit.log");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(
            config.audit_log_path,
            PathBuf::from("/tmp/custom-audit.log")
        );
        clear_all();
    }

    #[test]
    fn defaults_the_gatekeeper_http_port() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.gatekeeper_http_port, 4000);
        clear_all();
    }

    #[test]
    fn reads_a_configured_gatekeeper_http_port() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_GATEKEEPER_HTTP_PORT", "9000");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.gatekeeper_http_port, 9000);
        clear_all();
    }

    #[test]
    fn defaults_the_gatekeeper_wg0_address() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.gatekeeper_wg0_address, Ipv4Addr::new(10, 66, 66, 1));
        clear_all();
    }

    #[test]
    fn reads_a_configured_gatekeeper_wg0_address() {
        // TT-2144 review: a node provisioned with a non-default wg0 address must be recoverable
        // via config, not force a rebuild or a permanent fail-closed on every flow.
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_GATEKEEPER_WG0_ADDRESS", "10.66.66.9");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.gatekeeper_wg0_address, Ipv4Addr::new(10, 66, 66, 9));
        clear_all();
    }

    #[test]
    fn defaults_the_tun_netmask() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.tun_netmask, Ipv4Addr::new(255, 255, 255, 0));
        clear_all();
    }

    #[test]
    fn reads_a_configured_tun_netmask() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_TUN_NETMASK", "255.255.0.0");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.tun_netmask, Ipv4Addr::new(255, 255, 0, 0));
        clear_all();
    }

    #[test]
    fn reads_a_configured_heartbeat_interval() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("HEARTBEAT_INTERVAL_SECONDS", "90");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.heartbeat_interval, Duration::from_secs(90));
        clear_all();
    }

    #[test]
    fn falls_back_to_the_default_heartbeat_interval_when_the_env_value_is_zero() {
        // Zero would otherwise reach tokio::time::interval in main, which panics on a zero period.
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("HEARTBEAT_INTERVAL_SECONDS", "0");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
        clear_all();
    }

    #[test]
    fn falls_back_to_the_default_heartbeat_interval_when_the_env_value_is_unparseable() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("HEARTBEAT_INTERVAL_SECONDS", "not-a-number");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
        clear_all();
    }

    #[test]
    fn accepts_a_heartbeat_interval_at_or_above_the_agent_signature_window_but_still_applies_it() {
        // Warned about (see parse_heartbeat_interval's doc comment), not rejected - the operator's
        // explicit choice is still honored.
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("AGENTS_JSON_URL", "https://agents.example.com/agents.json");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("HEARTBEAT_INTERVAL_SECONDS", "600");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.heartbeat_interval, Duration::from_secs(600));
        clear_all();
    }
}
