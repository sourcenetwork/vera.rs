//! Operator keys as an approval policy lists them.
//!
//! A secp256k1 operator is 66 lowercase hexadecimal characters of its
//! compressed key. An Ed25519 or P-256 operator is its `did:key`. A key has
//! exactly one entry form, so it cannot be listed twice. Any P-256 operator
//! may approve with a passkey assertion instead of a raw signature.

use vera_crypto::actor::{self, ActorKeyType};
use vera_crypto::webauthn::{self, Assertion};

/// The `did:key` of the key a policy entry names, or why the entry is invalid.
pub(super) fn did(entry: &str) -> Result<String, String> {
    if entry.starts_with("did:key:") {
        return match actor::key_type(entry).map_err(|error| error.to_string())? {
            ActorKeyType::Secp256k1 => {
                Err("secp256k1 operator keys must use hexadecimal encoding".into())
            }
            ActorKeyType::Ed25519 | ActorKeyType::P256 => Ok(entry.to_owned()),
        };
    }
    if entry.len() != 66 {
        return Err("operator keys must contain 33 bytes or be a did:key".into());
    }
    let bytes = hex::decode(entry).map_err(|error| error.to_string())?;
    if hex::encode(&bytes) != *entry {
        return Err("operator keys must use lowercase hexadecimal".into());
    }
    vera_crypto::secp256k1::decode_pubkey(&bytes).map_err(|error| error.to_string())?;
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(&bytes).map_err(|error| error.to_string())
}

/// Verify one approval signature by the key a policy entry names.
///
/// Without an assertion the key signs the digest itself. With one, the key
/// is P-256 and signs the assertion that carries the digest as its challenge.
pub(super) fn verify(
    entry: &str,
    digest: &[u8; 32],
    signature: &[u8],
    assertion: Option<&Assertion<'_>>,
) -> Result<(), String> {
    let did = did(entry)?;
    match assertion {
        None => actor::verify_digest(&did, digest, signature).map_err(|error| error.to_string()),
        Some(assertion) => {
            webauthn::verify(&did, digest, assertion, signature).map_err(|error| error.to_string())
        }
    }
}
