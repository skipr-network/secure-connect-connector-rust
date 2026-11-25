//! Raw-key-material Ed25519 helpers, hex-encoded exactly like the Java fleet's
//! `Ed25519Support` (skipr-agent's key format): a 32-byte private key seed and a
//! standard RFC 8032 32-byte public key, both as 64 lowercase hex characters. No
//! manual byte-order conversion is needed on this side - the Java implementation's
//! `EdECPoint` little-endian-Y encoding *is* the RFC 8032 wire format that
//! `ed25519-dalek` already uses natively for `VerifyingKey`/`SigningKey` bytes.
//!
//! `verify_base64` also verifies a second, unrelated signer (TT-2107): the mobile
//! app's own device session signature, which - unlike Agent's Ed25519-based
//! `X-Signature` scheme this module was originally built for - turns out to be
//! ECDSA P-256 (`SHA256withECDSA`, Android/Java's own default "EC" keypair and
//! signature algorithm), sent as a 65-byte SEC1-uncompressed public key
//! (`0x04 || X || Y`, 130 hex chars) and a DER-encoded signature. Nobody had
//! reconciled the two schemes before TT-1734's live E2E testing exercised this
//! path for the first time - see `ClientSessionSignatureRegistry`'s own doc
//! comment in the Gatekeeper repo ("a different, not-yet-built component this
//! contract doesn't control the content of"). Dispatched by public key byte
//! length (32 = Ed25519, 65 = ECDSA P-256) so both existing call sites
//! (`heartbeat.rs`'s Agent verification, `flow_control.rs`'s device
//! verification) keep working unchanged.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

/// Not constructed by production code - the Connector's own identity is
/// X25519 now (`identity.rs`, TT-1822), not Ed25519. This and
/// `generate_keypair` remain genuinely useful: every test that needs to
/// simulate an Agent's or a device's Ed25519 identity (both still real
/// Ed25519 signers this Connector verifies against) uses them.
#[allow(dead_code)]
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub public_key_hex: String,
}

#[allow(dead_code)]
pub fn generate_keypair() -> KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    KeyPair {
        signing_key,
        public_key_hex,
    }
}

/// Only exercised by this module's own round-trip test now - no production
/// caller needs to re-encode a private key it just generated (see
/// `generate_keypair`'s doc comment).
#[allow(dead_code)]
pub fn encode_private_key_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.to_bytes())
}

/// Only exercised by this module's own tests now - see `generate_keypair`'s
/// doc comment for why nothing in production decodes a private key anymore.
#[allow(dead_code)]
pub fn decode_private_key_hex(hex_str: &str) -> Result<SigningKey> {
    let bytes = hex::decode(hex_str).context("private key is not valid hex")?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("Ed25519 private key seed must be exactly 32 bytes (64 hex chars)")
    })?;
    Ok(SigningKey::from_bytes(&array))
}

/// No longer called from production code - `verify_base64` (TT-2107) now decodes
/// and dispatches on the raw key bytes itself, since it has to handle ECDSA's
/// 65-byte keys too, not just this function's fixed 32-byte Ed25519 assumption.
/// Kept for the same reason as `decode_private_key_hex`: still genuinely useful
/// wherever a test needs to parse a known-Ed25519 public key on its own.
#[allow(dead_code)]
pub fn decode_public_key_hex(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str).context("public key is not valid hex")?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("Ed25519 public key must be exactly 32 bytes (64 hex chars)")
    })?;
    VerifyingKey::from_bytes(&array).context("invalid Ed25519 public key point")
}

/// Not called from `main` yet - signing outbound requests (e.g. Connector peer
/// provisioning to Gatekeeper, TT-1733) is a later TT-1732 slice. Kept alongside
/// `verify_base64` as the natural signing counterpart, same pairing as the Java
/// fleet's `Ed25519Support.sign`/`.verify`.
#[allow(dead_code)]
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verifies a base64-encoded signature against the raw message bytes, using the
/// signer's hex-encoded public key - either Ed25519 (as carried in Agent's
/// `X-Signature` response header, mirroring `Ed25519Support.verify`) or ECDSA P-256
/// (the mobile app's device session signature, TT-2107), dispatched by the decoded
/// public key's byte length since the two schemes' keys can never collide in size
/// (32 bytes vs 65). Any decode/parse failure is treated as "not verified" rather
/// than propagated, since an attacker-controlled signature must never crash the
/// caller.
pub fn verify_base64(public_key_hex: &str, message: &[u8], signature_base64: &str) -> bool {
    let Ok(public_key_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(signature_bytes) = BASE64.decode(signature_base64) else {
        return false;
    };
    match public_key_bytes.len() {
        32 => verify_ed25519(&public_key_bytes, message, &signature_bytes),
        65 => verify_ecdsa_p256(&public_key_bytes, message, &signature_bytes),
        _ => false,
    }
}

fn verify_ed25519(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let Ok(public_key_array) = <[u8; 32]>::try_from(public_key_bytes) else {
        return false;
    };
    let Ok(public_key) = VerifyingKey::from_bytes(&public_key_array) else {
        return false;
    };
    let Ok(signature_array) = <[u8; 64]>::try_from(signature_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_array);
    public_key.verify(message, &signature).is_ok()
}

/// `public_key_bytes` (the raw 65-byte SEC1-uncompressed point, `0x04 || X || Y`)
/// is what `ring` calls an "unparsed" public key for this algorithm - it needs no
/// further parsing itself. `signature_bytes` is the DER encoding the algorithm's
/// own name already promises ("ASN1"), verified as-is with no re-encoding needed
/// on either side.
fn verify_ecdsa_p256(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_bytes)
        .verify(message, signature_bytes)
        .is_ok()
}

#[allow(dead_code)]
pub fn sign_to_base64(signing_key: &SigningKey, message: &[u8]) -> String {
    BASE64.encode(sign(signing_key, message).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let keypair = generate_keypair();
        let message = b"hello connector";
        let signature = sign_to_base64(&keypair.signing_key, message);

        assert!(verify_base64(&keypair.public_key_hex, message, &signature));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let keypair = generate_keypair();
        let signature = sign_to_base64(&keypair.signing_key, b"original");

        assert!(!verify_base64(
            &keypair.public_key_hex,
            b"tampered",
            &signature
        ));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let keypair_a = generate_keypair();
        let keypair_b = generate_keypair();
        let message = b"hello connector";
        let signature = sign_to_base64(&keypair_a.signing_key, message);

        assert!(!verify_base64(
            &keypair_b.public_key_hex,
            message,
            &signature
        ));
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let keypair = generate_keypair();
        assert!(!verify_base64(
            &keypair.public_key_hex,
            b"msg",
            "not-valid-base64!!"
        ));
    }

    #[test]
    fn verify_rejects_a_signature_of_the_wrong_length() {
        // Valid base64, but not 64 decoded bytes - a different failure mode than
        // "not base64 at all".
        let keypair = generate_keypair();
        let short_signature = BASE64.encode(b"too short");
        assert!(!verify_base64(
            &keypair.public_key_hex,
            b"msg",
            &short_signature
        ));
    }

    #[test]
    fn verify_rejects_malformed_public_key() {
        assert!(!verify_base64("not-hex", b"msg", "AAAA"));
    }

    #[test]
    fn private_key_hex_round_trips_through_decode() {
        let keypair = generate_keypair();
        let hex_seed = encode_private_key_hex(&keypair.signing_key);
        let decoded = decode_private_key_hex(&hex_seed).unwrap();

        assert_eq!(decoded.to_bytes(), keypair.signing_key.to_bytes());
    }

    #[test]
    fn decode_private_key_rejects_wrong_length() {
        assert!(decode_private_key_hex("abcd").is_err());
    }

    #[test]
    fn decode_public_key_rejects_wrong_length() {
        assert!(decode_public_key_hex("abcd").is_err());
    }

    /// Fixed values captured from a real, live run of the Java fleet's
    /// `Ed25519Support.sign`/`.encodePublicKeyHex` (see the TT-1732 bootstrap
    /// session notes for how they were generated) - confirms this module's hex
    /// encoding and signature format are actually interoperable with the Java
    /// side, not just reasoned to be from reading the RFC 8032 spec. Verified
    /// bidirectionally at the time: Java also independently verified a
    /// Rust-produced signature.
    #[test]
    fn verifies_a_real_java_ed25519support_signature() {
        let public_key_hex = "0c02ed1b75a9232e073957cfa2f15d03338e3e1e0e71a621ae54c23cea566495";
        let signature_base64 = "oTDDSU38U7ymg22nbQACz31MDo/dlaXpVHs2M71uiZE9b1LLZ5zoumMvDQzhD5tkh8/DuZRatTAuwWlaTlTuBg==";
        let message = b"cross-language interop check";

        assert!(verify_base64(public_key_hex, message, signature_base64));
    }

    /// Fixed values captured from a real run of Python's `cryptography` library
    /// (`ec.generate_private_key(ec.SECP256R1())` + `.sign(message,
    /// ec.ECDSA(hashes.SHA256()))`) - the same SEC1-uncompressed-key /
    /// DER-signature shape Android/Java's default "EC" keypair and
    /// `SHA256withECDSA` produce (TT-2107). Confirms `verify_base64` is
    /// genuinely interoperable with a real external ECDSA P-256 implementation,
    /// not just reasoned to be from the byte layout alone.
    #[test]
    fn verifies_a_real_ecdsa_p256_signature() {
        let public_key_hex = "0468108ea52b4e9e2df35999b34a44ee41a5a0d9acdfc8ab64c791464a424ed6ec9e81e5d7fd9cea30377d693a921de69cef09c996a081b28540a22529da0d6230";
        let signature_base64 = "MEUCIQDESgMpvWtTW5LmigBReAvvB1d4rxlxoEgd7x7ydm846wIgTAGjfjjdDrUZu1rCEdqJDkkwDro+vbFH9ipTJcU5j8E=";
        let message = b"cross-language ECDSA interop check";

        assert!(verify_base64(public_key_hex, message, signature_base64));
    }

    #[test]
    fn ecdsa_p256_rejects_a_tampered_message() {
        let public_key_hex = "0468108ea52b4e9e2df35999b34a44ee41a5a0d9acdfc8ab64c791464a424ed6ec9e81e5d7fd9cea30377d693a921de69cef09c996a081b28540a22529da0d6230";
        let signature_base64 = "MEUCIQDESgMpvWtTW5LmigBReAvvB1d4rxlxoEgd7x7ydm846wIgTAGjfjjdDrUZu1rCEdqJDkkwDro+vbFH9ipTJcU5j8E=";

        assert!(!verify_base64(
            public_key_hex,
            b"tampered",
            signature_base64
        ));
    }

    #[test]
    fn ecdsa_p256_rejects_a_signature_from_a_different_key() {
        // A genuinely different, valid SEC1 point (also from Python's
        // `cryptography` library) - not the key that actually produced this
        // signature - must fail verification, not panic.
        let other_public_key_hex = "04b69c4f998d949c060154b932acd848e9aabd706660aa8457c88d4a78ac635ff5027f56ccdd7bc13d567af97884f4ebf794afcfd8ad230cddc1788a758f80769e";
        let signature_base64 = "MEUCIQDESgMpvWtTW5LmigBReAvvB1d4rxlxoEgd7x7ydm846wIgTAGjfjjdDrUZu1rCEdqJDkkwDro+vbFH9ipTJcU5j8E=";
        let message = b"cross-language ECDSA interop check";

        assert!(!verify_base64(
            other_public_key_hex,
            message,
            signature_base64
        ));
    }

    #[test]
    fn ecdsa_p256_rejects_a_malformed_der_signature() {
        let public_key_hex = "0468108ea52b4e9e2df35999b34a44ee41a5a0d9acdfc8ab64c791464a424ed6ec9e81e5d7fd9cea30377d693a921de69cef09c996a081b28540a22529da0d6230";
        let not_der = BASE64.encode(b"not a der signature");

        assert!(!verify_base64(public_key_hex, b"msg", &not_der));
    }

    #[test]
    fn a_65_byte_public_key_never_falls_through_to_ed25519_decoding() {
        // Regression guard for the dispatch itself: a key of exactly the ECDSA
        // length must never be handed to the Ed25519 path (which would either
        // reject it as unrelated garbage or, worse, silently succeed on
        // unrelated bytes) - it must go through verify_ecdsa_p256 exclusively.
        let ecdsa_public_key_hex = "0468108ea52b4e9e2df35999b34a44ee41a5a0d9acdfc8ab64c791464a424ed6ec9e81e5d7fd9cea30377d693a921de69cef09c996a081b28540a22529da0d6230";
        let ed25519_signature = {
            let keypair = generate_keypair();
            sign_to_base64(&keypair.signing_key, b"msg")
        };

        assert!(!verify_base64(
            ecdsa_public_key_hex,
            b"msg",
            &ed25519_signature
        ));
    }

    #[test]
    fn verify_rejects_a_public_key_of_an_unrecognized_length() {
        // Neither 32 (Ed25519) nor 65 (ECDSA P-256) bytes - e.g. a compressed
        // EC point (33 bytes) - must fail closed, not guess a scheme.
        let compressed_point_hex = "02".to_string() + &"ab".repeat(32);
        assert!(!verify_base64(&compressed_point_hex, b"msg", "AAAA"));
    }
}
