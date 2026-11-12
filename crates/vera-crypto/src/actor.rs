//! Delegation actors: the `did:key` identities that issue tokens.
//!
//! An actor signs with the JWT algorithm of its key type: ES256K for
//! secp256k1, EdDSA for Ed25519 and ES256 for P-256. ECDSA signatures cover
//! the SHA-256 digest of the signing input; Ed25519 signs the input itself.

use crate::{actor_key::ActorKey, jwt::JwtError};

/// The `did:key` under which an Ed25519 public key acts.
pub fn ed25519_did(public_key: &[u8; 32]) -> Result<String, JwtError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|error| JwtError::InvalidIssuer(format!("invalid Ed25519 key: {error}")))?;
    checked(&ActorKey::Ed25519(key))
}

/// The `did:key` under which a P-256 public key acts.
///
/// Accepts a compressed or uncompressed SEC1 point; the DID always names the
/// compressed one.
pub fn p256_did(public_key: &[u8]) -> Result<String, JwtError> {
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|error| JwtError::InvalidIssuer(format!("invalid P-256 key: {error}")))?;
    checked(&ActorKey::P256(key))
}

fn checked(key: &ActorKey) -> Result<String, JwtError> {
    let did = key.canonical_did();
    ActorKey::from_did(&did).map(|_| did)
}

/// The JWT `alg` an actor's tokens must name.
pub fn algorithm(actor: &str) -> Result<&'static str, JwtError> {
    ActorKey::from_did(actor).map(|key| key.algorithm())
}

/// The single signature encoding accepted from `actor`, from a raw signature.
///
/// ECDSA input is the 64-byte `r || s`; a high `s` is replaced by its low
/// equivalent. Ed25519 input is returned unchanged.
pub fn canonical_signature(actor: &str, signature: &[u8]) -> Result<Vec<u8>, JwtError> {
    ActorKey::from_did(actor)?.canonical_signature(signature)
}

/// The single signature encoding accepted from `actor`, from ASN.1 DER.
///
/// Platform key stores return ECDSA signatures in this form. Ed25519 has no
/// DER signature form and is rejected.
pub fn canonical_der_signature(actor: &str, signature: &[u8]) -> Result<Vec<u8>, JwtError> {
    ActorKey::from_did(actor)?.canonical_der_signature(signature)
}

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
