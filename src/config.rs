//! Environment-driven config. The Connector runs on the enterprise's own network,
//! installed by their admin - config comes from env vars set at install time, not
//! a config server (no such thing exists here; per the confirmed TT-501 flow, the
//! admin registers the Connector's public key manually in Portal, not the other
//! way around).

use anyhow::{Context, Result};
use std::env;
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
    /// Konyk's answer (TT-1732 comment thread): 60s default, must stay configurable
    /// and below Agent's 5-minute signature validity window.
    pub heartbeat_interval: Duration,
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
