//! secp256k1 keys: validation, digest signatures and `did:key:` derivation.

use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{Signature as K256Sig, VerifyingKey};

/// Decode and validate a compressed secp256k1 public key.
pub fn decode_pubkey(public_key: &[u8]) -> Result<VerifyingKey, Secp256k1Error> {
    if public_key.len() != 33 {
        return Err(Secp256k1Error::InvalidPubkeyLength(public_key.len()));
    }
    // The SEC1 compact form is also 33 bytes and would be a second spelling of one key.
    if !matches!(public_key[0], 0x02 | 0x03) {
        return Err(Secp256k1Error::Recovery("not a compressed point".into()));
    }
    VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|error| Secp256k1Error::Recovery(error.to_string()))
}

/// Verify a canonical compact ECDSA signature over an already computed digest.
pub fn verify_digest(
    public_key: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), Secp256k1Error> {
    let key = decode_pubkey(public_key)?;
    let signature = K256Sig::from_slice(signature)
        .map_err(|error| Secp256k1Error::Recovery(error.to_string()))?;
    if signature.normalize_s().is_some() {
        return Err(Secp256k1Error::Recovery("noncanonical signature".into()));
    }
    key.verify_prehash(digest, &signature)
        .map_err(|error| Secp256k1Error::Recovery(error.to_string()))
}

/// secp256k1 multicodec prefix (`secp256k1-pub`, 0xe7).
const SECP256K1_PUB_MULTICODEC: u64 = 0xe7;

/// Errors from secp256k1 operations.
#[derive(Debug, thiserror::Error)]
pub enum Secp256k1Error {
    /// Compressed public key must be exactly 33 bytes.
    #[error("invalid compressed pubkey length: expected 33 bytes, got {0}")]
    InvalidPubkeyLength(usize),
    /// The key or signature is not valid.
    #[error("invalid secp256k1 key or signature: {0}")]
    Recovery(String),
}

/// Derive a `did:key:` identifier from a compressed secp256k1 public key (33 bytes).
///
/// Encoding: `did:key:` + multibase(Base58Btc, varint(0xe7) || compressed_pubkey).
pub fn did_from_secp256k1_pubkey(compressed_pubkey: &[u8]) -> Result<String, Secp256k1Error> {
    if compressed_pubkey.len() != 33 {
        return Err(Secp256k1Error::InvalidPubkeyLength(compressed_pubkey.len()));
    }

    Ok(crate::did_key::did(
        SECP256K1_PUB_MULTICODEC,
        compressed_pubkey,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn test_keypair() -> (SigningKey, Vec<u8>) {
        let secret = [42u8; 32];
        let signing_key = SigningKey::from_bytes((&secret).into()).unwrap();
        let compressed = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (signing_key, compressed)
    }

    #[test]
    fn compact_digest_signatures_require_canonical_key_and_low_s() {
        use k256::ecdsa::signature::hazmat::PrehashSigner as _;
        let key = k256::ecdsa::SigningKey::from_bytes(&[1; 32].into()).unwrap();
        let public = key.verifying_key().to_sec1_bytes();
        let digest = [7; 32];
        let signature: K256Sig = key.sign_prehash(&digest).unwrap();
        assert!(verify_digest(&public, &digest, &signature.to_bytes()).is_ok());
        assert!(verify_digest(&public, &[8; 32], &signature.to_bytes()).is_err());
        assert!(verify_digest(&public, &digest, &[0; 64]).is_err());
        assert!(verify_digest(&public, &digest, &[0; 63]).is_err());
        let (r, s) = signature.split_scalars();
        let high_s = K256Sig::from_scalars(r.to_bytes(), (-s).to_bytes()).unwrap();
        assert!(verify_digest(&public, &digest, &high_s.to_bytes()).is_err());
        assert!(decode_pubkey(key.verifying_key().to_encoded_point(false).as_bytes()).is_err());
        assert!(decode_pubkey(&[0; 33]).is_err());
    }

    #[test]
    fn did_from_secp256k1_pubkey_valid_format() {
        let (_sk, pubkey) = test_keypair();
        let did = did_from_secp256k1_pubkey(&pubkey).unwrap();

        assert!(
            did.starts_with("did:key:zQ3s"),
            "secp256k1 did:key should start with zQ3s, got: {did}"
        );

        let multibase_part = &did["did:key:".len()..];
        let decoded = crate::did_key::decode(multibase_part).unwrap();

        let mut varint_buf = [0u8; 10];
        let expected_prefix =
            unsigned_varint::encode::u64(SECP256K1_PUB_MULTICODEC, &mut varint_buf);
        assert_eq!(&decoded[..expected_prefix.len()], expected_prefix);
        assert_eq!(&decoded[expected_prefix.len()..], pubkey.as_slice());
    }

    #[test]
    fn did_is_deterministic() {
        let (_sk, pubkey) = test_keypair();
        let did1 = did_from_secp256k1_pubkey(&pubkey).unwrap();
        let did2 = did_from_secp256k1_pubkey(&pubkey).unwrap();
        assert_eq!(did1, did2);
    }

    #[test]
    fn did_rejects_wrong_length_pubkey() {
        assert!(did_from_secp256k1_pubkey(&[0u8; 32]).is_err());
        assert!(did_from_secp256k1_pubkey(&[0u8; 65]).is_err());
        assert!(did_from_secp256k1_pubkey(&[]).is_err());
    }
}
