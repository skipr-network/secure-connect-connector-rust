//! This Connector instance's own X25519 identity (TT-1732 acceptance criterion:
//! "loads or creates its Connector identity"). On first start, generate a key
//! pair and persist it to a 2-line base64 file (private key, public key)
//! outside anything a redeploy overwrites, so identity survives upgrades. A
//! genuinely new/replacement host has an empty key file path, so it generates
//! a fresh identity - matching the fact that it really is a different install.
//!
//! X25519, not Ed25519 - and base64, not the hex used everywhere else in this
//! codebase for Ed25519 material. This is a deliberate correction: the spec
//! describes one Connector keypair serving two jobs - registration identity
//! *and* WireGuard peer identity (§B.5) - and WireGuard peers must be X25519,
//! a hard protocol requirement, not a style choice. There's exactly one
//! `connector_public_key` field anywhere in the agreed provisioning contract
//! (TT-1732 comment thread) that ever reaches a node's Gatekeeper - whatever
//! the Enterprise Admin pastes into Portal at setup is the only key that ever
//! gets there, so it has to already be a valid WireGuard key, not a different
//! type that would need converting. Base64 matches native `wg genkey`/`wg
//! pubkey` output, what Gatekeeper's wg-CLI template scripts actually expect -
//! no Java-interop concern applies here, unlike the Ed25519 material in
//! `crypto.rs` (which stays as-is: verifying Agent's and users' signatures is
//! a separate, still-Ed25519 concern).
//!
//! Unlike Agent, the Connector does not self-register its public key anywhere:
//! per the TT-501 admin flow, the Enterprise Admin manually copies the printed
//! public key into Portal's "Deploy Connector" screen - there is no API call
//! for this.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand_core::OsRng;
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct ConnectorIdentity {
    /// Moved into `TunnelManager::new` in `main` - the Connector's own
    /// static secret for every node's WireGuard session.
    pub secret: StaticSecret,
    pub public_key_base64: String,
}

/// Loads the identity from `path` if it already exists, otherwise generates a new
/// X25519 key pair and persists it there before returning.
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
    let private_key_base64 = lines
        .next()
        .with_context(|| format!("identity key file at {} is empty", path.display()))?
        .trim();
    let public_key_base64 = lines
        .next()
        .with_context(|| {
            format!(
                "identity key file at {} is missing the public key line",
                path.display()
            )
        })?
        .trim()
        .to_string();

    let secret = decode_secret_base64(private_key_base64).with_context(|| {
        format!(
            "identity key file at {} has an invalid private key",
            path.display()
        )
    })?;

    // The two lines are meant to be a matched pair - if the file was ever
    // partially written, manually edited, or corrupted, using the stored
    // public key as-is without checking it against the secret would mean
    // this Connector announces (and Portal registers) a public key that
    // doesn't correspond to what it actually uses for the WireGuard
    // handshake - a Connector that can never establish a tunnel, without any
    // error until nodes silently refuse a handshake from an unrecognized
    // peer (TT-1732 review, Tasneem).
    let derived_public_key_base64 = encode_public_base64(&PublicKey::from(&secret));
    if derived_public_key_base64 != public_key_base64 {
        anyhow::bail!(
            "identity key file at {} is corrupt: the stored public key does not match the one derived from the stored private key",
            path.display()
        );
    }

    Ok(ConnectorIdentity {
        secret,
        public_key_base64,
    })
}

fn generate_and_persist(path: &Path) -> Result<ConnectorIdentity> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public_key_base64 = encode_public_base64(&PublicKey::from(&secret));
    let private_key_base64 = encode_secret_base64(&secret);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create identity key directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(path, format!("{private_key_base64}\n{public_key_base64}\n"))
        .with_context(|| format!("failed to persist identity key file at {}", path.display()))?;
    restrict_permissions(path)?;

    Ok(ConnectorIdentity {
        secret,
        public_key_base64,
    })
}

fn encode_secret_base64(secret: &StaticSecret) -> String {
    BASE64.encode(secret.to_bytes())
}

fn encode_public_base64(public: &PublicKey) -> String {
    BASE64.encode(public.as_bytes())
}

fn decode_secret_base64(value: &str) -> Result<StaticSecret> {
    let bytes = BASE64
        .decode(value)
        .context("X25519 private key is not valid base64")?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("X25519 private key must be exactly 32 bytes"))?;
    Ok(StaticSecret::from(array))
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
        // 32 raw bytes, base64-encoded with padding.
        assert_eq!(identity.public_key_base64.len(), 44);
    }

    #[test]
    fn loads_the_same_identity_on_a_second_call() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let first = load_or_generate(&path).unwrap();
        let second = load_or_generate(&path).unwrap();

        assert_eq!(first.public_key_base64, second.public_key_base64);
        assert_eq!(first.secret.to_bytes(), second.secret.to_bytes());
    }

    #[test]
    fn a_different_key_file_path_produces_a_different_identity() {
        let dir = tempdir().unwrap();
        let first = load_or_generate(&dir.path().join("a.key")).unwrap();
        let second = load_or_generate(&dir.path().join("b.key")).unwrap();

        assert_ne!(first.public_key_base64, second.public_key_base64);
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
    fn rejects_a_key_file_missing_the_public_key_line() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        fs::write(&path, "not-a-valid-base64-seed\n").unwrap();

        assert!(load_or_generate(&path).is_err());
    }

    #[test]
    fn rejects_a_key_file_whose_public_key_does_not_match_its_private_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        // A genuinely valid private key, paired with a genuinely valid but
        // *different* public key - the file is well-formed, just corrupt.
        let real_secret = StaticSecret::random_from_rng(OsRng);
        let mismatched_secret = StaticSecret::random_from_rng(OsRng);
        let mismatched_public_base64 = encode_public_base64(&PublicKey::from(&mismatched_secret));
        fs::write(
            &path,
            format!(
                "{}\n{}\n",
                encode_secret_base64(&real_secret),
                mismatched_public_base64
            ),
        )
        .unwrap();

        assert!(load_or_generate(&path).is_err());
    }

    #[test]
    fn rejects_a_key_file_with_a_well_formed_but_invalid_private_key() {
        // Two lines present (so this exercises the *different* failure path than
        // the missing-second-line case above): valid base64, but the wrong
        // decoded length for an X25519 key.
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        fs::write(&path, "YWJjZA==\nsomepublickey\n").unwrap();

        assert!(load_or_generate(&path).is_err());
    }

    #[test]
    fn errors_when_the_key_directory_cannot_be_created() {
        // The parent path component is itself a plain file, so create_dir_all
        // must fail rather than silently succeeding.
        let dir = tempdir().unwrap();
        let blocking_file = dir.path().join("not-a-directory");
        fs::write(&blocking_file, "").unwrap();
        let path = blocking_file.join("identity.key");

        assert!(load_or_generate(&path).is_err());
    }
}
