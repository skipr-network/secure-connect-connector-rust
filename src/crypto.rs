//! Raw-key-material Ed25519 helpers, hex-encoded exactly like the Java fleet's
//! `Ed25519Support` (skipr-agent's key format): a 32-byte private key seed and a
//! standard RFC 8032 32-byte public key, both as 64 lowercase hex characters. No
//! manual byte-order conversion is needed on this side - the Java implementation's
//! `EdECPoint` little-endian-Y encoding *is* the RFC 8032 wire format that
//! `ed25519-dalek` already uses natively for `VerifyingKey`/`SigningKey` bytes.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

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

/// Verifies a base64-encoded Ed25519 signature (as carried in Agent's `X-Signature`
/// response header) against the raw message bytes, using the signer's hex-encoded
/// public key. Mirrors `Ed25519Support.verify` - any decode/parse failure is treated
/// as "not verified" rather than propagated, since an attacker-controlled signature
/// header must never crash the caller.
pub fn verify_base64(public_key_hex: &str, message: &[u8], signature_base64: &str) -> bool {
    let Ok(public_key) = decode_public_key_hex(public_key_hex) else {
        return false;
    };
    let Ok(signature_bytes) = BASE64.decode(signature_base64) else {
        return false;
    };
    let Ok(signature_array) = <[u8; 64]>::try_from(signature_bytes.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_array);
    public_key.verify(message, &signature).is_ok()
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
}
