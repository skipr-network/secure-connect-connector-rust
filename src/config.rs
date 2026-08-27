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
    /// Where the flow-admission/release HTTP server (TT-1821) listens. Not
    /// specified anywhere in the spec or the agreed contract - Konyk's own
    /// comment says these calls should arrive "inside the already established
    /// Connector <-> Node private tunnel network", but nothing in this repo
    /// yet binds to a real WireGuard-tunnel-internal interface (TT-1823 only
    /// establishes the session, not a routable virtual address). A plain
    /// configurable bind address is the honest stand-in until that exists.
    pub control_plane_listen_addr: String,
    /// The Connector's own address on its TUN interface (TT-1827) - real
    /// packet forwarding needs *some* local address for the OS to route
    /// through, but nothing in the spec or the agreed contract defines a
    /// Connector<->Node virtual addressing scheme. `10.99.0.1/24` is a
    /// private (RFC 1918), otherwise-unused-in-this-codebase default,
    /// documented as an assumption the same way `WIREGUARD_PORT` is -
    /// override via env if it ever collides with something real.
    pub tun_addr: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,
}

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
            control_plane_listen_addr: env::var("CONNECTOR_CONTROL_PLANE_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8443".to_string()),
            tun_addr: env::var("CONNECTOR_TUN_ADDR")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(Ipv4Addr::new(10, 99, 0, 1)),
            tun_netmask: env::var("CONNECTOR_TUN_NETMASK")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
            heartbeat_interval: Duration::from_secs(
                env::var("HEARTBEAT_INTERVAL_SECONDS")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(60),
            ),
        })
    }
}

fn require_env(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("required environment variable {name} is not set"))
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
            "CONNECTOR_CONTROL_PLANE_LISTEN_ADDR",
            "CONNECTOR_TUN_ADDR",
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
    fn defaults_the_control_plane_listen_addr() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.control_plane_listen_addr, "0.0.0.0:8443");
        clear_all();
    }

    #[test]
    fn reads_a_configured_control_plane_listen_addr() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_CONTROL_PLANE_LISTEN_ADDR", "127.0.0.1:9000");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.control_plane_listen_addr, "127.0.0.1:9000");
        clear_all();
    }

    #[test]
    fn defaults_the_tun_addr_and_netmask() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.tun_addr, Ipv4Addr::new(10, 99, 0, 1));
        assert_eq!(config.tun_netmask, Ipv4Addr::new(255, 255, 255, 0));
        clear_all();
    }

    #[test]
    fn reads_a_configured_tun_addr_and_netmask() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_TUN_ADDR", "10.5.0.1");
            env::set_var("CONNECTOR_TUN_NETMASK", "255.255.0.0");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.tun_addr, Ipv4Addr::new(10, 5, 0, 1));
        assert_eq!(config.tun_netmask, Ipv4Addr::new(255, 255, 0, 0));
        clear_all();
    }

    #[test]
    fn falls_back_to_the_default_tun_addr_when_the_env_value_is_unparseable() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("CONNECTOR_ID", "c-1");
            env::set_var("AGENT_BASE_URL", "https://agent.example.com");
            env::set_var("AGENT_IP_ADDRESS", "10.0.0.5");
            env::set_var("REGISTRY_BASE_URL", "https://registry.example.com");
            env::set_var("CONNECTOR_TUN_ADDR", "not-an-ip");
        }

        let config = Config::from_env().unwrap();

        assert_eq!(config.tun_addr, Ipv4Addr::new(10, 99, 0, 1));
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
}
