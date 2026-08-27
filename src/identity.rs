//! This Connector instance's own Ed25519 signing identity (TT-1732 acceptance
//! criterion: "loads or creates its Connector identity"). Mirrors the Java fleet's
//! `AgentIdentityKeyProvider` exactly: on first start, generate a key pair and
//! persist it to a 2-line hex file (private key seed, public key) outside anything
//! a redeploy overwrites, so identity survives upgrades. A genuinely new/replacement
//! host has an empty key file path, so it generates a fresh identity - matching the
//! fact that it really is a different install.
//!
//! Unlike Agent, the Connector does not self-register its public key anywhere: per
//! the TT-501 admin flow, the Enterprise Admin manually copies the printed public
//! key into Portal's "Deploy Connector" screen - there is no API call for this.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::Path;

use crate::crypto;

pub struct ConnectorIdentity {
    /// Not read from `main` yet - needed once the Connector signs outbound
    /// provisioning requests to Gatekeeper (a later TT-1732 slice).
    #[allow(dead_code)]
    pub signing_key: SigningKey,
    pub public_key_hex: String,
}

/// Loads the identity from `path` if it already exists, otherwise generates a new
/// Ed25519 key pair and persists it there before returning.
pub fn load_or_generate(path: &Path) -> Result<ConnectorIdentity> {
    if path.exists() {
        load(path)
    } else {
        generate_and_persist(path)
    }
}

fn load(path: &Path) -> Result<ConnectorIdentity> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read identity key file at {}", path.display()))?;
    let mut lines = contents.lines();
    let private_key_hex = lines
        .next()
        .with_context(|| format!("identity key file at {} is empty", path.display()))?
        .trim();
    let public_key_hex = lines
        .next()
        .with_context(|| {
            format!(
                "identity key file at {} is missing the public key line",
                path.display()
            )
        })?
        .trim()
        .to_string();

    let signing_key = crypto::decode_private_key_hex(private_key_hex).with_context(|| {
        format!(
            "identity key file at {} has an invalid private key",
            path.display()
        )
    })?;

    Ok(ConnectorIdentity {
        signing_key,
        public_key_hex,
    })
}

fn generate_and_persist(path: &Path) -> Result<ConnectorIdentity> {
    let keypair = crypto::generate_keypair();
    let private_key_hex = crypto::encode_private_key_hex(&keypair.signing_key);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create identity key directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(
        path,
        format!("{private_key_hex}\n{}\n", keypair.public_key_hex),
    )
    .with_context(|| format!("failed to persist identity key file at {}", path.display()))?;
    restrict_permissions(path)?;

    Ok(ConnectorIdentity {
        signing_key: keypair.signing_key,
        public_key_hex: keypair.public_key_hex,
    })
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
        format!(
            "failed to restrict permissions on identity key file at {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_and_persists_a_new_identity_when_the_file_does_not_exist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let identity = load_or_generate(&path).unwrap();

        assert!(path.exists());
        assert_eq!(identity.public_key_hex.len(), 64);
    }

    #[test]
    fn loads_the_same_identity_on_a_second_call() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let first = load_or_generate(&path).unwrap();
        let second = load_or_generate(&path).unwrap();

        assert_eq!(first.public_key_hex, second.public_key_hex);
        assert_eq!(first.signing_key.to_bytes(), second.signing_key.to_bytes());
    }

    #[test]
    fn a_different_key_file_path_produces_a_different_identity() {
        let dir = tempdir().unwrap();
        let first = load_or_generate(&dir.path().join("a.key")).unwrap();
        let second = load_or_generate(&dir.path().join("b.key")).unwrap();

        assert_ne!(first.public_key_hex, second.public_key_hex);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_key_file_is_owner_only_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        load_or_generate(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rejects_a_malformed_key_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        fs::write(&path, "not-a-valid-hex-seed\n").unwrap();

        assert!(load_or_generate(&path).is_err());
    }
}
