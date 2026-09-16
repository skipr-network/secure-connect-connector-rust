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
                warn_if_expiring_soon(path, &parsed);
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

/// How far ahead of an anchor's expiry to start warning (PR #11 review finding #5, Oleksandr
/// Konyk): "an expired pinned root CA takes every Connector down at once, and that should be
/// visible in advance rather than discovered the hard way." Logging `not_after` at `info` on
/// every startup satisfies that only in principle - nobody reads info logs in advance, they read
/// them after the outage - so this needs to actually escalate to `warn` once expiry is close
/// enough to be someone's problem soon, not just be present in the log line.
const EXPIRY_WARNING_THRESHOLD_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Whether `not_after` is already past, or within `EXPIRY_WARNING_THRESHOLD_SECONDS` of, `now` -
/// the decision `warn_if_expiring_soon` acts on, factored out as its own pure function so it's
/// directly unit-testable without capturing log output.
fn is_expiring_soon(
    not_after: x509_parser::time::ASN1Time,
    now: x509_parser::time::ASN1Time,
) -> bool {
    not_after.timestamp() - now.timestamp() <= EXPIRY_WARNING_THRESHOLD_SECONDS
}

/// Escalates to a `warn!` if `certificate` is already expired or expires within
/// `EXPIRY_WARNING_THRESHOLD_SECONDS` - in addition to, not instead of, the `info!` logged above,
/// which every anchor gets regardless of how close it is to expiry.
fn warn_if_expiring_soon(path: &Path, certificate: &x509_parser::certificate::X509Certificate) {
    let not_after = certificate.validity().not_after;
    let now = x509_parser::time::ASN1Time::now();
    if !is_expiring_soon(not_after, now) {
        return;
    }
    let seconds_until_expiry = not_after.timestamp() - now.timestamp();
    if seconds_until_expiry <= 0 {
        tracing::warn!(
            path = %path.display(),
            subject = %certificate.subject(),
            %not_after,
            "trusted root CA (CONNECTOR_CA_BUNDLE_PATH) has already expired - Agent/Registry TLS \
             connections relying on it will start failing, if they haven't already"
        );
    } else {
        tracing::warn!(
            path = %path.display(),
            subject = %certificate.subject(),
            %not_after,
            days_remaining = seconds_until_expiry / (24 * 60 * 60),
            "trusted root CA (CONNECTOR_CA_BUNDLE_PATH) expires soon - Agent/Registry TLS will \
             start failing once it does"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real, self-signed root CA certificate - `basicConstraints=critical,CA:TRUE` and
    /// `keyUsage=critical,keyCertSign,cRLSign`, not just an end-entity cert with a CA-sounding
    /// subject (PR #11 review finding #3 - the original fixture had neither extension, so it
    /// wasn't actually a CA despite its doc comment and subject claiming otherwise). Generated
    /// once and committed here, not regenerated per test run (a fixed, known subject/expiry to
    /// assert against):
    /// ```sh
    /// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca-key.pem
    /// openssl req -x509 -new -key ca-key.pem -out test-ca.pem -days 3650 \
    ///   -subj "/CN=Test Internal CA" \
    ///   -addext "basicConstraints=critical,CA:TRUE" \
    ///   -addext "keyUsage=critical,keyCertSign,cRLSign"
    /// ```
    const VALID_CA_PEM: &str = include_str!("../tests/fixtures/test-ca.pem");

    /// A leaf certificate for `127.0.0.1` (SAN, not just CN), signed by `VALID_CA_PEM`'s CA - used
    /// with `LEAF_VALID_KEY_PEM` to prove a client trusting only this CA actually completes a real
    /// TLS handshake against a server presenting this cert (PR #11 review finding #4). Generated
    /// with the CA fixture above as `-CA`/`-CAkey`:
    /// ```sh
    /// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf-valid-key.pem
    /// openssl req -new -key leaf-valid-key.pem -out leaf-valid.csr -subj "/CN=127.0.0.1"
    /// openssl x509 -req -in leaf-valid.csr -CA test-ca.pem -CAkey ca-key.pem -CAcreateserial \
    ///   -out test-leaf-valid.pem -days 3650 -extfile <(printf \
    ///   "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n\
    ///    keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
    /// ```
    const LEAF_VALID_PEM: &str = include_str!("../tests/fixtures/test-leaf-valid.pem");
    const LEAF_VALID_KEY_PEM: &str = include_str!("../tests/fixtures/test-leaf-valid-key.pem");

    /// A leaf certificate signed by the *same* trusted CA as `LEAF_VALID_PEM`, but for
    /// `wrong-host.example.internal` instead of `127.0.0.1` - used to prove the other half of PR
    /// #11 review finding #4: that trusting a CA via `add_root_certificate` does not also disable
    /// hostname verification. A server presenting this cert while answering on `127.0.0.1` must
    /// still be rejected, even though the CA itself is fully trusted. Generated the same way as
    /// `LEAF_VALID_PEM` above, with `subjectAltName=DNS:wrong-host.example.internal` instead.
    const LEAF_WRONG_HOST_PEM: &str = include_str!("../tests/fixtures/test-leaf-wrong-host.pem");
    const LEAF_WRONG_HOST_KEY_PEM: &str =
        include_str!("../tests/fixtures/test-leaf-wrong-host-key.pem");

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

    fn asn1_time_in(seconds_from_now: i64) -> x509_parser::time::ASN1Time {
        x509_parser::time::ASN1Time::from_timestamp(
            x509_parser::time::ASN1Time::now().timestamp() + seconds_from_now,
        )
        .unwrap()
    }

    #[test]
    fn is_expiring_soon_is_false_for_a_certificate_valid_for_a_year() {
        let now = asn1_time_in(0);
        assert!(!is_expiring_soon(asn1_time_in(365 * 24 * 60 * 60), now));
    }

    #[test]
    fn is_expiring_soon_is_true_for_a_certificate_that_already_expired() {
        let now = asn1_time_in(0);
        assert!(is_expiring_soon(asn1_time_in(-1), now));
    }

    #[test]
    fn is_expiring_soon_is_true_just_inside_the_threshold() {
        let now = asn1_time_in(0);
        assert!(is_expiring_soon(
            asn1_time_in(EXPIRY_WARNING_THRESHOLD_SECONDS - 1),
            now
        ));
    }

    #[test]
    fn is_expiring_soon_is_false_just_outside_the_threshold() {
        let now = asn1_time_in(0);
        assert!(!is_expiring_soon(
            asn1_time_in(EXPIRY_WARNING_THRESHOLD_SECONDS + 1),
            now
        ));
    }

    /// Parses a PEM block (cert or PKCS8 private key - the parse itself doesn't care which) into
    /// raw DER bytes via `x509_parser::pem`, already a dependency, rather than pulling in
    /// `rustls-pemfile` as a new one purely for test code.
    fn pem_to_der(pem: &str) -> Vec<u8> {
        x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes())
            .next()
            .expect("no PEM block found")
            .expect("malformed PEM block")
            .contents
    }

    /// Spins up a real TLS listener on `127.0.0.1` presenting `(leaf_pem, leaf_key_pem)`, and
    /// returns its address plus the accept-loop's `JoinHandle` (aborted by the caller once the
    /// test is done with it). Every connection gets the same trivial `200 OK` response - these
    /// tests only care whether the TLS handshake itself succeeds or fails, never about anything
    /// at the HTTP layer above it.
    async fn spawn_test_tls_server(
        leaf_pem: &str,
        leaf_key_pem: &str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        // rustls only auto-selects a process-wide CryptoProvider when exactly one of its
        // backends is compiled in - both `ring` and `aws-lc-rs` end up in the dependency tree
        // here (reqwest and this test's own tokio-rustls dev-dependency don't necessarily agree
        // on one), so it has to be picked explicitly. Ignoring the error: a previous test in the
        // same process may have already installed one, which is fine - only one is ever needed.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        let certs: Vec<CertificateDer<'static>> =
            x509_parser::pem::Pem::iter_from_buffer(leaf_pem.as_bytes())
                .map(|pem| CertificateDer::from(pem.expect("malformed PEM block").contents))
                .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_to_der(leaf_key_pem)));

        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("failed to build a rustls ServerConfig from the test fixtures");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind the test TLS listener");
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // A failed handshake here (the wrong-host-cert test) is the point of the
                    // test, not a bug in the server - nothing to log or act on beyond dropping
                    // the connection.
                    let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls_stream.read(&mut buf).await;
                    let _ = tls_stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await;
                });
            }
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn connecting_with_the_trusted_ca_completes_a_real_tls_handshake_against_a_server_using_it()
     {
        // The other half of the trust model this module exists for (PR #11 review finding #4):
        // not just "does the client accept this CA" in the abstract, but "does a real client
        // actually complete a real TLS handshake against a real server presenting a certificate
        // that chains to it" - proven end to end, not asserted in a doc comment.
        let (addr, server) = spawn_test_tls_server(LEAF_VALID_PEM, LEAF_VALID_KEY_PEM).await;

        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, VALID_CA_PEM).unwrap();
        let mut builder = reqwest::Client::builder();
        for certificate in load_extra_root_certificates(&ca_path).unwrap() {
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build().unwrap();

        let response = client
            .get(format!("https://{addr}/"))
            .send()
            .await
            .expect("handshake against a server using a trusted CA must succeed");
        assert!(response.status().is_success());

        server.abort();
    }

    #[tokio::test]
    async fn hostname_verification_still_rejects_a_wrong_host_cert_even_from_a_trusted_ca() {
        // TT-2027 ticket point 3 - "add_root_certificate keeps real hostname verification in
        // place - that's the entire point" - proven, not just asserted: the server's certificate
        // is signed by the exact same CA the client trusts, but for a hostname that doesn't match
        // where the client is actually connecting. Trusting the CA must never be enough on its
        // own; the leaf's own identity still has to match.
        let (addr, server) =
            spawn_test_tls_server(LEAF_WRONG_HOST_PEM, LEAF_WRONG_HOST_KEY_PEM).await;

        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, VALID_CA_PEM).unwrap();
        let mut builder = reqwest::Client::builder();
        for certificate in load_extra_root_certificates(&ca_path).unwrap() {
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build().unwrap();

        let result = client.get(format!("https://{addr}/")).send().await;
        assert!(
            result.is_err(),
            "a certificate for the wrong host must be rejected even when its CA is trusted, \
             but the connection succeeded"
        );

        server.abort();
    }
}
