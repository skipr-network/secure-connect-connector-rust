//! TT-3717 (spec §B.4 point 4): proves to the Agent that a heartbeat or deregistration comes from
//! the holder of this Connector's private key.
//!
//! The Connector's identity is its X25519 WireGuard key, which cannot sign, so the proof is a MAC
//! keyed by an X25519 key agreement with the key-agreement key the Agent publishes in the Registry
//! (`x25519_public_key`, separate from its Ed25519 `permitted_key`):
//!
//! - `shared = X25519(connector_private, agent_x25519_public)`; a malformed Agent key and an
//!   all-zero `shared` are refused;
//! - `mac_key = HKDF-SHA256(salt = empty, ikm = shared, info = LABEL || connector_public_key_raw,
//!   length = 32)` - the raw shared secret is never used as a key;
//! - `proof = base64(HMAC-SHA256(mac_key, canonical))`, where `canonical` is the label, the method,
//!   the route path, the public key and the timestamp exactly as sent in the headers, each followed
//!   by `\n`, then the raw request body bytes exactly as sent.
//!
//! The Agent's key is kept per Agent in a file next to the identity key, so a key that goes missing
//! from the Registry (a Registry rollback, a registration still retrying, a cleared entry) does not
//! lock out a Connector that has already proven itself. With no usable key for an Agent at all, no
//! proof is sent to it - the Agent decides whether to serve that during its migration window.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::{hkdf, hmac};
use tracing::warn;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PROOF_LABEL: &str = "skipr-connector-proof-v1";
pub const PROOF_VERSION: &str = "1";

pub const PROOF_VERSION_HEADER: &str = "X-Connector-Proof-Version";
pub const PUBLIC_KEY_HEADER: &str = "X-Connector-Public-Key";
pub const TIMESTAMP_HEADER: &str = "X-Connector-Timestamp";
pub const PROOF_HEADER: &str = "X-Connector-Proof";

/// Next to the identity key file (spec §B.4 point 4: "in a file next to its identity key").
const KEPT_AGENT_KEYS_FILE_NAME: &str = "agent-x25519-keys";

/// Where the Agents' key-agreement keys are kept for the identity key at `identity_key_path`.
pub fn kept_agent_keys_path(identity_key_path: &Path) -> PathBuf {
    identity_key_path.with_file_name(KEPT_AGENT_KEYS_FILE_NAME)
}

/// The MAC key this Connector shares with one Agent instance, ready to prove requests to it.
#[derive(Clone)]
pub struct AgentProofKey {
    mac_key: hmac::Key,
    connector_public_key_base64: String,
}

impl AgentProofKey {
    /// Derives the MAC key from this Connector's secret and the Agent's published key (64
    /// lower-case hex characters). Refuses a malformed key and a key whose agreement is all zero
    /// (a low-order point), which would make the MAC key public.
    fn derive(
        connector_secret: &StaticSecret,
        connector_public_key: &PublicKey,
        agent_x25519_public_key_hex: &str,
    ) -> Result<Self> {
        let agent_public_key = PublicKey::from(decode_agent_key(agent_x25519_public_key_hex)?);
        let shared = connector_secret.diffie_hellman(&agent_public_key);
        if !shared.was_contributory() {
            bail!("the Agent's x25519_public_key gives an all-zero shared secret");
        }
        let info: [&[u8]; 2] = [PROOF_LABEL.as_bytes(), connector_public_key.as_bytes()];
        let mac_key: hmac::Key = hkdf::Salt::new(hkdf::HKDF_SHA256, &[])
            .extract(shared.as_bytes())
            .expand(&info, hmac::HMAC_SHA256)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?
            .into();
        Ok(Self {
            mac_key,
            connector_public_key_base64: BASE64.encode(connector_public_key.as_bytes()),
        })
    }

    /// The four proof headers for one request. `path` is the Connector route without scheme, host
    /// or query string; `body` must be the exact bytes sent; `timestamp_ms` must be new on every
    /// attempt (the Agent refuses a replayed MAC).
    pub fn headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp_ms: i64,
    ) -> [(&'static str, String); 4] {
        let timestamp = timestamp_ms.to_string();
        let mut canonical = format!(
            "{PROOF_LABEL}\n{}\n{path}\n{}\n{timestamp}\n",
            method.to_ascii_uppercase(),
            self.connector_public_key_base64
        )
        .into_bytes();
        canonical.extend_from_slice(body);
        let proof = BASE64.encode(hmac::sign(&self.mac_key, &canonical).as_ref());
        [
            (PROOF_VERSION_HEADER, PROOF_VERSION.to_string()),
            (PUBLIC_KEY_HEADER, self.connector_public_key_base64.clone()),
            (TIMESTAMP_HEADER, timestamp),
            (PROOF_HEADER, proof),
        ]
    }
}

/// The Agent key format the Registry publishes: exactly 64 lower-case hex characters.
fn decode_agent_key(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("the Agent's x25519_public_key is not 64 lower-case hex characters");
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).context("x25519_public_key is not valid hex")?;
    Ok(bytes)
}

/// Builds the proof key for each Agent from this Connector's identity secret, and keeps the last
/// key fetched per Agent.
pub struct RequestProver {
    secret: StaticSecret,
    public_key: PublicKey,
    kept: KeptAgentKeys,
    /// (Agent, key) pairs already warned about as unusable - a bad key is reported once per
    /// process, not on every heartbeat.
    warned: Mutex<HashSet<(String, String)>>,
}

impl RequestProver {
    /// For the daemon: keys fetched from the Registry are kept in the file for later runs.
    pub fn new(secret: StaticSecret, kept_agent_keys_path: PathBuf) -> Self {
        Self::with_kept_keys(secret, KeptAgentKeys::load(kept_agent_keys_path, true))
    }

    /// For `--deregister`: reads the kept keys but never writes the file. It runs as root next to
    /// the still-running daemon (install-systemd.sh `--decommission`), so a write could leave a
    /// root-owned file the daemon can no longer replace, or race the daemon's own write.
    pub fn read_only(secret: StaticSecret, kept_agent_keys_path: PathBuf) -> Self {
        Self::with_kept_keys(secret, KeptAgentKeys::load(kept_agent_keys_path, false))
    }

    fn with_kept_keys(secret: StaticSecret, kept: KeptAgentKeys) -> Self {
        let public_key = PublicKey::from(&secret);
        Self {
            secret,
            public_key,
            kept,
            warned: Mutex::new(HashSet::new()),
        }
    }

    /// True the first time this (Agent, key) pair is reported in this process.
    fn first_warning(&self, agent_ip: &str, key: &str) -> bool {
        self.warned
            .lock()
            .unwrap()
            .insert((agent_ip.to_string(), key.to_string()))
    }

    /// The proof key for the Agent at `agent_ip`, from the key the Registry `published` for it -
    /// kept for later when it is usable - or else from the key kept from an earlier fetch. `None`
    /// means no proof is sent to this Agent.
    pub fn key_for_agent(&self, agent_ip: &str, published: Option<&str>) -> Option<AgentProofKey> {
        if let Some(published) = published.filter(|key| !key.trim().is_empty()) {
            match self.derive(published) {
                Ok(key) => {
                    self.kept.keep(agent_ip, published);
                    return Some(key);
                }
                // A published key nobody can use is no better than none: fall back to the kept
                // one, as for a key missing from the Registry.
                Err(error) => {
                    if self.first_warning(agent_ip, published) {
                        warn!(agent = %agent_ip, error = %format!("{error:#}"), "the Agent's published key-agreement key is unusable - not using it for the request proof");
                    }
                }
            }
        }
        let kept = self.kept.get(agent_ip)?;
        match self.derive(&kept) {
            Ok(key) => Some(key),
            Err(error) => {
                if self.first_warning(agent_ip, &kept) {
                    warn!(agent = %agent_ip, error = %format!("{error:#}"), "the kept key-agreement key for this Agent is unusable - sending no request proof to it");
                }
                None
            }
        }
    }

    fn derive(&self, agent_key_hex: &str) -> Result<AgentProofKey> {
        AgentProofKey::derive(&self.secret, &self.public_key, agent_key_hex)
    }
}

/// One line per Agent, `<agent ip> <x25519_public_key>`, written only when a key changes.
struct KeptAgentKeys {
    path: PathBuf,
    keys: Mutex<BTreeMap<String, String>>,
    /// `false` keeps changes in memory only (see [`RequestProver::read_only`]).
    writable: bool,
}

impl KeptAgentKeys {
    /// A missing or unreadable file is an empty one: the keys are fetched again from the Registry.
    fn load(path: PathBuf, writable: bool) -> Self {
        let keys = match fs::read_to_string(&path) {
            Ok(contents) => contents
                .lines()
                .filter_map(|line| {
                    let (ip, key) = line.trim().split_once(' ')?;
                    Some((ip.to_string(), key.trim().to_string()))
                })
                .collect(),
            // First start: nothing kept yet.
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => {
                warn!(path = %path.display(), %error, "could not read the kept Agent key-agreement keys - using only what the Registry returns");
                BTreeMap::new()
            }
        };
        Self {
            path,
            keys: Mutex::new(keys),
            writable,
        }
    }

    fn get(&self, agent_ip: &str) -> Option<String> {
        self.keys.lock().unwrap().get(agent_ip).cloned()
    }

    fn keep(&self, agent_ip: &str, key: &str) {
        let mut keys = self.keys.lock().unwrap();
        if keys.get(agent_ip).map(String::as_str) == Some(key) {
            return;
        }
        keys.insert(agent_ip.to_string(), key.to_string());
        if !self.writable {
            return;
        }
        let contents: String = keys
            .iter()
            .map(|(ip, key)| format!("{ip} {key}\n"))
            .collect();
        // Still used from memory for this run if it cannot be written.
        if let Err(error) = write_private(&self.path, &contents) {
            warn!(path = %self.path.display(), error = %format!("{error:#}"), "could not keep the Agents' key-agreement keys on disk");
        }
    }
}

/// Writes a temporary file readable by the owner only and renames it over `path`, so a crash
/// mid-write never leaves a half-written file. The temporary name carries the process id, so two
/// processes never write the same temporary file, and it is created with mode 0600 from the start.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    // A leftover from a crashed process that had the same id would make `create_new` fail.
    let _ = fs::remove_file(&tmp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&tmp)
        .and_then(|mut file| file.write_all(contents.as_bytes()));
    if let Err(error) = written {
        let _ = fs::remove_file(&tmp);
        return Err(error).with_context(|| format!("failed to write {}", tmp.display()));
    }
    fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Recomputes a proof from first principles (X25519 + HKDF-SHA256 + HMAC-SHA256), as the
    /// Agent does, from the Agent's private key and what was received - independent of
    /// [`AgentProofKey`], so a test can check what was actually sent.
    pub(crate) fn expected_proof(
        agent_secret: &StaticSecret,
        connector_public_key_base64: &str,
        method: &str,
        path: &str,
        timestamp: &str,
        body: &[u8],
    ) -> String {
        let connector_public: [u8; 32] = BASE64
            .decode(connector_public_key_base64)
            .unwrap()
            .try_into()
            .unwrap();
        let shared = agent_secret.diffie_hellman(&PublicKey::from(connector_public));
        let mut info = PROOF_LABEL.as_bytes().to_vec();
        info.extend_from_slice(&connector_public);
        let mut mac_key = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, &[])
            .extract(shared.as_bytes())
            .expand(&[&info], hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut mac_key)
            .unwrap();
        let mut canonical = format!(
            "{PROOF_LABEL}\n{method}\n{path}\n{connector_public_key_base64}\n{timestamp}\n"
        )
        .into_bytes();
        canonical.extend_from_slice(body);
        BASE64.encode(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &mac_key), &canonical).as_ref())
    }

    fn bytes(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }

    // RFC 7748 §6.1: Alice is the Connector, Bob the Agent.
    const CONNECTOR_PRIVATE: &str =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const AGENT_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const AGENT_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    fn prover(dir: &Path) -> RequestProver {
        RequestProver::new(
            StaticSecret::from(bytes(CONNECTOR_PRIVATE)),
            dir.join(KEPT_AGENT_KEYS_FILE_NAME),
        )
    }

    fn agent_public_hex() -> String {
        hex::encode(PublicKey::from(&StaticSecret::from(bytes(AGENT_PRIVATE))).as_bytes())
    }

    /// Fixed vector computed outside this codebase (Python `cryptography`: X25519, HKDF, HMAC),
    /// so a change to the canonical form or the derivation on either side shows up here.
    #[test]
    fn matches_the_fixed_test_vector() {
        assert_eq!(agent_public_hex(), AGENT_PUBLIC, "RFC 7748 §6.1 public key");
        let dir = tempdir().unwrap();
        let key = prover(dir.path())
            .key_for_agent("10.0.0.2", Some(AGENT_PUBLIC))
            .unwrap();

        let headers = key.headers(
            "POST",
            "/api/connectors/heartbeat",
            br#"{"connector_public_key":"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="}"#,
            1_763_300_000_000,
        );

        assert_eq!(
            headers,
            [
                (PROOF_VERSION_HEADER, "1".to_string()),
                (
                    PUBLIC_KEY_HEADER,
                    "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=".to_string()
                ),
                (TIMESTAMP_HEADER, "1763300000000".to_string()),
                (
                    PROOF_HEADER,
                    "0ugQOtUi2QstGTuLVPy6a8c9c4rILHxjNrejByXL0rY=".to_string()
                ),
            ]
        );
    }

    #[test]
    fn the_agent_can_verify_the_proof_with_its_own_private_key() {
        let dir = tempdir().unwrap();
        let agent_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let agent_public = hex::encode(PublicKey::from(&agent_secret).as_bytes());
        let key = prover(dir.path())
            .key_for_agent("10.0.0.2", Some(&agent_public))
            .unwrap();

        let [_, (_, public_key), (_, timestamp), (_, proof)] =
            key.headers("POST", "/api/connectors/deregister", b"{}", 42);

        assert_eq!(
            proof,
            expected_proof(
                &agent_secret,
                &public_key,
                "POST",
                "/api/connectors/deregister",
                &timestamp,
                b"{}"
            )
        );
    }

    #[test]
    fn refuses_malformed_agent_keys() {
        let dir = tempdir().unwrap();
        let prover = prover(dir.path());
        for bad in [
            "",
            "abc",
            &agent_public_hex().to_uppercase(),
            &format!("{}0", agent_public_hex()),
            &"g".repeat(64),
        ] {
            assert!(
                prover.key_for_agent("10.0.0.2", Some(bad)).is_none(),
                "{bad}"
            );
        }
    }

    /// The all-zero point (and every other low-order point) makes the shared secret all zero -
    /// a MAC key anyone could compute.
    #[test]
    fn refuses_an_agent_key_with_an_all_zero_shared_secret() {
        let dir = tempdir().unwrap();
        assert!(
            prover(dir.path())
                .key_for_agent("10.0.0.2", Some(&"0".repeat(64)))
                .is_none()
        );
    }

    /// A non-zero low-order point: its agreement with any secret is all zero.
    #[test]
    fn refuses_a_non_zero_low_order_agent_key() {
        let dir = tempdir().unwrap();
        assert!(
            prover(dir.path())
                .key_for_agent(
                    "10.0.0.2",
                    Some("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
                )
                .is_none()
        );
    }

    /// `--deregister` runs as root next to the daemon: it uses the kept keys but never writes.
    #[test]
    fn a_read_only_prover_uses_the_kept_keys_but_never_writes_the_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(KEPT_AGENT_KEYS_FILE_NAME);
        let secret = || StaticSecret::from(bytes(CONNECTOR_PRIVATE));
        let read_only = RequestProver::read_only(secret(), path.clone());
        assert!(
            read_only
                .key_for_agent("10.0.0.2", Some(AGENT_PUBLIC))
                .is_some()
        );
        assert!(!path.exists());

        prover(dir.path()).key_for_agent("10.0.0.2", Some(AGENT_PUBLIC));
        let kept = fs::read_to_string(&path).unwrap();
        let read_only = RequestProver::read_only(secret(), path.clone());
        assert!(read_only.key_for_agent("10.0.0.2", None).is_some());
        // A different published key is used, but not written.
        let other = hex::encode(
            PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng)).as_bytes(),
        );
        assert!(read_only.key_for_agent("10.0.0.2", Some(&other)).is_some());
        assert_eq!(fs::read_to_string(&path).unwrap(), kept);
    }

    #[test]
    fn keeps_the_last_fetched_key_per_agent_in_a_private_file_and_uses_it_when_none_is_published() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(KEPT_AGENT_KEYS_FILE_NAME);
        let agent_public = agent_public_hex();
        let published = prover(dir.path())
            .key_for_agent("10.0.0.2", Some(&agent_public))
            .unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("10.0.0.2 {agent_public}\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // No temporary file left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);

        // A restart: a new prover reads the file.
        let restarted = prover(dir.path());
        let kept = restarted.key_for_agent("10.0.0.2", None).unwrap();
        assert_eq!(
            kept.headers("POST", "/p", b"x", 1),
            published.headers("POST", "/p", b"x", 1)
        );
        // An unusable published key also falls back to the kept one.
        assert!(restarted.key_for_agent("10.0.0.2", Some("zz")).is_some());
        // Kept per Agent: another Agent has none.
        assert!(restarted.key_for_agent("10.0.0.3", None).is_none());
    }
}
