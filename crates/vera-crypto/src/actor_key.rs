//! Public keys that may issue delegation tokens, identified by `did:key`.
//!
//! Token records and revocation are keyed by the token's hash, and policy
//! ownership is compared as a DID string. Ed25519 and P-256 keys therefore
//! have exactly one accepted DID spelling and one accepted signature encoding.

use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::{Digest as _, Sha256};

use crate::jwt::JwtError;

const SECP256K1_MULTICODEC: u64 = 0xe7;
const ED25519_MULTICODEC: u64 = 0xed;
const P256_MULTICODEC: u64 = 0x1200;

/// A delegation issuer's verification key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActorKey {
    Secp256k1(k256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl ActorKey {
    /// Decode the key a `did:key` names.
    ///
    /// secp256k1 keeps its historical spellings: compressed or uncompressed
    /// points, base58btc or base64url. The other types accept only the
    /// base58btc spelling of the canonical key bytes.
    pub(crate) fn from_did(did: &str) -> Result<Self, JwtError> {
        let multibase = did
            .strip_prefix("did:key:")
            .ok_or_else(|| JwtError::InvalidIssuer("not a did:key: string".into()))?;
        let decoded = crate::did_key::decode(multibase)
            .map_err(|e| JwtError::InvalidIssuer(format!("multibase decode: {e}")))?;
        let (codec, key) = unsigned_varint::decode::u64(&decoded)
            .map_err(|e| JwtError::InvalidIssuer(format!("multicodec: {e}")))?;
        let actor = match codec {
            SECP256K1_MULTICODEC => {
                if key.len() != 33 && key.len() != 65 {
                    return Err(JwtError::InvalidIssuer(format!(
                        "expected 33 or 65 byte pubkey, got {}",
                        key.len()
                    )));
                }
                return k256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .map(Self::Secp256k1)
                    .map_err(|e| JwtError::InvalidIssuer(format!("invalid secp256k1 key: {e}")));
            }
            ED25519_MULTICODEC => {
                let bytes: &[u8; 32] = key.try_into().map_err(|_| {
                    JwtError::InvalidIssuer(format!("expected 32 byte pubkey, got {}", key.len()))
                })?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                    .map_err(|e| JwtError::InvalidIssuer(format!("invalid Ed25519 key: {e}")))?;
                if key.is_weak() {
                    return Err(JwtError::InvalidIssuer("small-order Ed25519 key".into()));
                }
                Self::Ed25519(key)
            }
            P256_MULTICODEC => {
                if key.len() != 33 {
                    return Err(JwtError::InvalidIssuer(format!(
                        "expected 33 byte compressed pubkey, got {}",
                        key.len()
                    )));
                }
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .map(Self::P256)
                    .map_err(|e| JwtError::InvalidIssuer(format!("invalid P-256 key: {e}")))?
            }
            _ => return Err(JwtError::InvalidIssuer("unsupported did:key type".into())),
        };
        if actor.canonical_did() != did {
            return Err(JwtError::InvalidIssuer("noncanonical did:key".into()));
        }
        Ok(actor)
    }

    /// The JWT `alg` this key signs with.
    pub(crate) const fn algorithm(&self) -> &'static str {
        match self {
            Self::Secp256k1(_) => "ES256K",
            Self::Ed25519(_) => "EdDSA",
            Self::P256(_) => "ES256",
        }
    }

    /// The single DID under which this key is recorded.
    pub(crate) fn canonical_did(&self) -> String {
        let (codec, key) = match self {
            Self::Secp256k1(key) => (
                SECP256K1_MULTICODEC,
                key.to_encoded_point(true).as_bytes().to_vec(),
            ),
            Self::Ed25519(key) => (ED25519_MULTICODEC, key.to_bytes().to_vec()),
            Self::P256(key) => (
                P256_MULTICODEC,
                key.to_encoded_point(true).as_bytes().to_vec(),
            ),
        };
        let mut buffer = [0u8; 10];
        let mut bytes = unsigned_varint::encode::u64(codec, &mut buffer).to_vec();
        bytes.extend_from_slice(&key);
        format!("did:key:{}", crate::did_key::encode(&bytes))
    }

    /// Verify a raw 64-byte signature over a JWT signing input.
    ///
    /// ECDSA signatures are `r || s` over SHA-256 and must be low-S; a high-S
    /// copy would be a second valid token with a different hash. Ed25519 is
    /// verified strictly for the same reason.
    pub(crate) fn verify(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        let verified = match self {
            Self::Secp256k1(key) => {
                let signature = k256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JwtError::InvalidSignature)?;
                if signature.normalize_s().is_some() {
                    return Err(JwtError::InvalidSignature);
                }
                key.verify_prehash(&Sha256::digest(signing_input), &signature)
                    .is_ok()
            }
            Self::P256(key) => {
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JwtError::InvalidSignature)?;
                if signature.normalize_s().is_some() {
                    return Err(JwtError::InvalidSignature);
                }
                key.verify_prehash(&Sha256::digest(signing_input), &signature)
                    .is_ok()
            }
            Self::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| JwtError::InvalidSignature)?;
                key.verify_strict(signing_input, &signature).is_ok()
            }
        };
        verified.then_some(()).ok_or(JwtError::InvalidSignature)
    }

    /// The one accepted encoding of a raw fixed-width signature.
    ///
    /// ECDSA signers may return either `s`; the verifier accepts the low one.
    pub(crate) fn canonical_signature(&self, signature: &[u8]) -> Result<Vec<u8>, JwtError> {
        let canonical = match self {
            Self::Secp256k1(_) => k256::ecdsa::Signature::from_slice(signature)
                .ok()
                .map(|signature| signature.normalize_s().unwrap_or(signature).to_vec()),
            Self::P256(_) => p256::ecdsa::Signature::from_slice(signature)
                .ok()
                .map(|signature| signature.normalize_s().unwrap_or(signature).to_vec()),
            Self::Ed25519(_) => ed25519_dalek::Signature::from_slice(signature)
                .ok()
                .map(|_| signature.to_vec()),
        };
        canonical.ok_or(JwtError::InvalidSignature)
    }

    /// The accepted encoding of an ASN.1 DER ECDSA signature.
    pub(crate) fn canonical_der_signature(&self, signature: &[u8]) -> Result<Vec<u8>, JwtError> {
        let canonical = match self {
            Self::Secp256k1(_) => k256::ecdsa::Signature::from_der(signature)
                .ok()
                .map(|signature| signature.normalize_s().unwrap_or(signature).to_vec()),
            Self::P256(_) => p256::ecdsa::Signature::from_der(signature)
                .ok()
                .map(|signature| signature.normalize_s().unwrap_or(signature).to_vec()),
            Self::Ed25519(_) => None,
        };
        canonical.ok_or(JwtError::InvalidSignature)
    }
}

#[cfg(test)]
#[path = "actor_key_tests.rs"]
mod tests;
