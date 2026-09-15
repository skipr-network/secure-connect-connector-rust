//! Loads an optional extra root CA bundle (TT-2027) so the Connector can trust a private/internal
//! CA for its Agent/Registry TLS connections - a real, ordinary on-prem requirement (an Enterprise
//! Admin running Agent behind their own internal CA), not something the default trust covers.
//!
//! This is additive, never a replacement: Mozilla's bundled roots (`rustls-tls`) stay enabled
//! exactly as before, and `rustls-tls-native-roots` (enabled alongside it, Cargo.toml) also makes
//! the box's own OS trust store work with zero configuration at all - the standard on-prem path
//! for an admin who's already installed their CA there, per the standard procedure. This module's
//! `CONNECTOR_CA_BUNDLE_PATH` is the explicit, secondary option for when that isn't enough (e.g.
//! the box's own OS trust store isn't the one an admin controls).
//!
//! Pinning, not blanket trust: only ever `reqwest::ClientBuilder::add_root_certificate`, which
//! keeps full hostname verification in place - `danger_accept_invalid_certs` must never be used
//! here or anywhere else in this codebase, that would defeat the entire point of pinning a
//! specific root over trusting anything presented.
//!
//! Fails at startup (returns `Err`, surfaced via `main`'s `?`) rather than silently falling back
//! to the default roots on an unreadable file or invalid PEM - falling back silently would be the
//! worst outcome here: the box looks configured (the env var is set) while nothing extra is
//! actually trusted, and the admin has no signal anything's wrong until a real connection fails
//! for what looks like an unrelated reason.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// Reads and parses `path` as a PEM bundle (one or more certificates), logs each one's subject
/// and expiry once, and returns them ready to hand to
/// `reqwest::ClientBuilder::add_root_certificate` - one call per certificate, since that method
/// takes a single `Certificate` at a time.
pub fn load_extra_root_certificates(path: &Path) -> Result<Vec<reqwest::Certificate>> {
    let pem_bytes = std::fs::read(path).with_context(|| {
        format!(
            "failed to read CONNECTOR_CA_BUNDLE_PATH at {}",
            path.display()
        )
    })?;

    let certificates = reqwest::Certificate::from_pem_bundle(&pem_bytes).with_context(|| {
        format!(
            "CONNECTOR_CA_BUNDLE_PATH at {} is not a valid PEM certificate bundle",
            path.display()
        )
    })?;
    if certificates.is_empty() {
        bail!(
            "CONNECTOR_CA_BUNDLE_PATH at {} contains no certificates",
            path.display()
        );
    }

    // Parsed a second time, independently, purely for the subject/expiry logged below -
    // reqwest::Certificate deliberately doesn't expose parsed metadata, it just carries the raw
    // bytes through to the TLS backend. Best-effort: x509-parser does full RFC 5280 semantic
    // parsing, stricter than the DER-level parse reqwest just used to successfully load these as
    // trust anchors above, so a certificate that's already proven usable for TLS must never be
    // rejected at startup only because this purely cosmetic logging step couldn't describe it -
    // that would invert the whole point of failing at startup (catch an untrusted certificate,
    // not add a second, unrelated way to fail on a valid one).
    for pem in x509_parser::pem::Pem::iter_from_buffer(&pem_bytes) {
        let pem = match pem {
            Ok(pem) => pem,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "trusting an extra root CA for Agent/Registry TLS (CONNECTOR_CA_BUNDLE_PATH), but could not re-read a certificate to log its subject/expiry"
                );
                continue;
            }
        };
        match x509_parser::parse_x509_certificate(&pem.contents) {
            Ok((_, parsed)) => {
                tracing::info!(
                    path = %path.display(),
                    subject = %parsed.subject(),
                    not_after = %parsed.validity().not_after,
                    "trusting an extra root CA for Agent/Registry TLS (CONNECTOR_CA_BUNDLE_PATH)"
                );
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "trusting an extra root CA for Agent/Registry TLS (CONNECTOR_CA_BUNDLE_PATH), but could not parse its subject/expiry to log them"
                );
            }
        }
    }

    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real, self-signed root CA certificate - generated once with
    /// `openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out ca.pem -days 3650 -subj
    /// "/CN=Test Internal CA"` and committed here as a fixture, not regenerated per test run
    /// (a fixed, known subject/expiry to assert against).
    const VALID_CA_PEM: &str = include_str!("../tests/fixtures/test-ca.pem");

    #[test]
    fn loads_a_single_certificate_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, VALID_CA_PEM).unwrap();

        let certificates = load_extra_root_certificates(&path).unwrap();

        assert_eq!(certificates.len(), 1);
    }

    #[test]
    fn loads_every_certificate_in_a_multi_certificate_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca-bundle.pem");
        std::fs::write(&path, format!("{VALID_CA_PEM}\n{VALID_CA_PEM}")).unwrap();

        let certificates = load_extra_root_certificates(&path).unwrap();

        assert_eq!(certificates.len(), 2);
    }

    #[test]
    fn fails_startup_rather_than_falling_back_when_the_file_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.pem");

        assert!(load_extra_root_certificates(&path).is_err());
    }

    #[test]
    fn fails_startup_rather_than_falling_back_on_invalid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.pem");
        std::fs::write(&path, "this is not a certificate").unwrap();

        assert!(load_extra_root_certificates(&path).is_err());
    }

    #[test]
    fn fails_startup_rather_than_falling_back_on_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, "").unwrap();

        assert!(load_extra_root_certificates(&path).is_err());
    }
}
