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
    /// The connector_id the Enterprise Admin assigned when registering this
    /// Connector's public key in Portal.
    pub connector_id: String,
    pub agent_base_url: String,
    pub agent_ip_address: String,
    pub registry_base_url: String,
    pub identity_key_path: PathBuf,
    pub audit_log_path: PathBuf,
    /// Konyk's answer (TT-1732 comment thread): 60s default, must stay configurable
    /// and below Agent's 5-minute signature validity window.
    pub heartbeat_interval: Duration,
    /// Port the flow-admission/release HTTP server (TT-1821) listens on. The
    /// host half is not configurable (TT-1838): `main` always binds to
    /// `connector_virtual_ip`, the Connector's own TUN address, which only
    /// receives traffic that arrived through an established WireGuard
    /// session - so only the port is left as a knob.
    pub control_plane_port: u16,
    /// Netmask for the Connector's TUN interface - the address itself is no longer a local
    /// config concern (TT-1838): it's `connector_virtual_ip`, learned from the first successful
    /// heartbeat (Portal's own registered, per-Connector address), not guessed here.
    pub tun_netmask: Ipv4Addr,
}

/// Konyk's answer (TT-1732 comment thread): default 60s, must stay below
/// Agent's 5-minute (300s) signature validity window.
const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: u64 = 60;
const AGENT_SIGNATURE_VALIDITY_SECONDS: u64 = 300;

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            connector_id: require_env("CONNECTOR_ID")?,
            agent_base_url: require_env("AGENT_BASE_URL")?,
            agent_ip_address: require_env("AGENT_IP_ADDRESS")?,
            registry_base_url: require_env("REGISTRY_BASE_URL")?,
            identity_key_path: PathBuf::from(
                env::var("CONNECTOR_IDENTITY_KEY_PATH")
                    .unwrap_or_else(|_| "/var/skipr/connector/.keys/identity.key".to_string()),
            ),
            audit_log_path: PathBuf::from(
                env::var("CONNECTOR_AUDIT_LOG_PATH")
                    .unwrap_or_else(|_| "/var/skipr/connector/audit/audit.log".to_string()),
            ),
            control_plane_port: env::var("CONNECTOR_CONTROL_PLANE_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(8443),
            tun_netmask: env::var("CONNECTOR_TUN_NETMASK")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
            heartbeat_interval: parse_heartbeat_interval(),
        })
    }
}

fn require_env(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("required environment variable {name} is not set"))
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
            "CONNECTOR_ID",
            "AGENT_BASE_URL",
            "AGENT_IP_ADDRESS",
            "REGISTRY_BASE_URL",
            "CONNECTOR_IDENTITY_KEY_PATH",
            "CONNECTOR_AUDIT_LOG_PATH",
            "CONNECTOR_CONTROL_PLANE_PORT",
            "CONNECTOR_TUN_NETMASK",
            "HEARTBEAT_INTERVAL_SECONDS",
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

    #[test]
    fn defaults_the_heartbeat_interval_to_sixty_seconds() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
    fn reads_a_configured_audit_log_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
    fn defaults_the_control_plane_port() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.control_plane_port, 8443);
        clear_all();
    }

    #[test]
    fn reads_a_configured_control_plane_port() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_CONTROL_PLANE_PORT", "9000");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.control_plane_port, 9000);
        clear_all();
    }

    #[test]
    fn defaults_the_tun_netmask() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
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
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("HEARTBEAT_INTERVAL_SECONDS", "600");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.heartbeat_interval, Duration::from_secs(600));
        clear_all();
    }
}
