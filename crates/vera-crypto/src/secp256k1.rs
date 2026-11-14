//! secp256k1 public key recovery and `did:key:` derivation.
//!
//! Parallel to [`bls`](super::bls) — provides DID derivation for EVM transaction signers
//! by recovering the secp256k1 public key from ECDSA signatures.

use alloy_primitives::{B256, Signature as AlloySig};
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};

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
    /// ECDSA public key recovery failed.
    #[error("pubkey recovery failed: {0}")]
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

/// Recover the compressed secp256k1 public key (33 bytes) from an ECDSA signature.
pub fn recover_pubkey(signature: &AlloySig, sighash: &B256) -> Result<Vec<u8>, Secp256k1Error> {
    let r_bytes: [u8; 32] = signature.r().to_be_bytes();
    let s_bytes: [u8; 32] = signature.s().to_be_bytes();

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    let k256_sig = K256Sig::from_bytes((&sig_bytes).into())
        .map_err(|e| Secp256k1Error::Recovery(e.to_string()))?;

    let recovery_id = RecoveryId::new(signature.v(), false);

    let verifying_key =
        VerifyingKey::recover_from_prehash(sighash.as_ref(), &k256_sig, recovery_id)
            .map_err(|e| Secp256k1Error::Recovery(e.to_string()))?;

    Ok(verifying_key.to_encoded_point(true).as_bytes().to_vec())
}

/// Recover a `did:key:` identifier from an ECDSA signature and signing hash.
///
/// Combines [`recover_pubkey`] and [`did_from_secp256k1_pubkey`].
pub fn recover_did(signature: &AlloySig, sighash: &B256) -> Result<String, Secp256k1Error> {
    let pubkey = recover_pubkey(signature, sighash)?;
    did_from_secp256k1_pubkey(&pubkey)
}

/// Derive an Ethereum address from a secp256k1 `did:key:` string.
///
/// Decodes the compressed public key, decompresses it, and computes
/// `keccak256(uncompressed_pubkey[1..])` → last 20 bytes.
pub fn evm_address_from_did(did: &str) -> Result<alloy_primitives::Address, Secp256k1Error> {
    let multibase_part = did
        .strip_prefix("did:key:")
        .ok_or_else(|| Secp256k1Error::Recovery("not a did:key: string".into()))?;

    let decoded = crate::did_key::decode(multibase_part)
        .map_err(|e| Secp256k1Error::Recovery(format!("multibase decode: {e}")))?;

    let mut varint_buf = [0u8; 10];
    let prefix = unsigned_varint::encode::u64(SECP256K1_PUB_MULTICODEC, &mut varint_buf);
    if !decoded.starts_with(prefix) {
        return Err(Secp256k1Error::Recovery("not a secp256k1 did:key".into()));
    }
    let compressed = &decoded[prefix.len()..];
    let vk = decode_pubkey(compressed)?;
    let uncompressed = vk.to_encoded_point(false);
    let raw = &uncompressed.as_bytes()[1..]; // strip 0x04 prefix

    let hash = alloy_primitives::keccak256(raw);
    Ok(alloy_primitives::Address::from_slice(&hash[12..]))
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

    #[test]
    fn recover_did_roundtrip() {
        let (signing_key, pubkey) = test_keypair();
        let expected_did = did_from_secp256k1_pubkey(&pubkey).unwrap();

        let msg_hash = B256::from([0xAB; 32]);
        let (sig, recovery_id): (K256Sig, RecoveryId) = signing_key
            .sign_prehash_recoverable(msg_hash.as_ref())
            .unwrap();

        let sig_bytes = sig.to_bytes();
        let r = alloy_primitives::U256::from_be_slice(&sig_bytes[..32]);
        let s = alloy_primitives::U256::from_be_slice(&sig_bytes[32..]);
        let alloy_sig = AlloySig::new(r, s, recovery_id.is_y_odd());

        let recovered_did = recover_did(&alloy_sig, &msg_hash).unwrap();
        assert_eq!(recovered_did, expected_did);
    }

    #[test]
    fn evm_address_from_did_roundtrip() {
        let (_sk, pubkey) = test_keypair();
        let did = did_from_secp256k1_pubkey(&pubkey).unwrap();
        let addr = evm_address_from_did(&did).unwrap();
        assert_ne!(addr, alloy_primitives::Address::ZERO);

        // Verify against manual computation
        let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        let uncompressed = vk.to_encoded_point(false);
        let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
        let expected = alloy_primitives::Address::from_slice(&hash[12..]);
        assert_eq!(addr, expected);
    }

    #[test]
    fn evm_address_from_did_rejects_non_did() {
        assert!(evm_address_from_did("not-a-did").is_err());
        assert!(evm_address_from_did("did:key:z6MkTest").is_err());
    }

    /// Full signing roundtrip: private key → EVM address → sign → recover DID → DID → address.
    ///
    /// This is the exact path the runtime takes when an EVM tx hits a precompile:
    /// 1. User signs tx with their secp256k1 key
    /// 2. `recover_did()` extracts `did:key:` from the signature
    /// 3. `evm_address_from_did()` converts back to EVM address
    /// 4. That address must match `ecrecover`'s output
    #[test]
    fn full_sign_recover_did_to_address_roundtrip() {
        let (signing_key, _pubkey) = test_keypair();

        // Derive the canonical EVM address directly from the signing key
        let vk = signing_key.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
        let expected_address = alloy_primitives::Address::from_slice(&hash[12..]);

        // Sign a message (simulates tx signing)
        let msg_hash = B256::from([0xDE; 32]);
        let (sig, recovery_id): (K256Sig, RecoveryId) = signing_key
            .sign_prehash_recoverable(msg_hash.as_ref())
            .unwrap();

        let sig_bytes = sig.to_bytes();
        let r = alloy_primitives::U256::from_be_slice(&sig_bytes[..32]);
        let s = alloy_primitives::U256::from_be_slice(&sig_bytes[32..]);
        let alloy_sig = AlloySig::new(r, s, recovery_id.is_y_odd());

        // Runtime path: recover DID from signature, then derive EVM address
        let recovered_did = recover_did(&alloy_sig, &msg_hash).unwrap();
        let recovered_address = evm_address_from_did(&recovered_did).unwrap();

        assert_eq!(
            recovered_address, expected_address,
            "sign → recover_did → evm_address_from_did must match the signer's EVM address"
        );
    }

    /// Pinned test vector: Hardhat account 0 private key must produce the known address.
    #[test]
    fn hardhat_account_0_address_from_did() {
        let secret =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let signing_key = SigningKey::from_bytes((&secret[..]).into()).unwrap();
        let compressed = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let did = did_from_secp256k1_pubkey(&compressed).unwrap();
        let addr = evm_address_from_did(&did).unwrap();

        let expected: alloy_primitives::Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        assert_eq!(
            addr, expected,
            "Hardhat account 0 DID must resolve to 0xf39F...2266"
        );
    }

    /// Multiple Hardhat accounts all roundtrip correctly through DID encoding.
    #[test]
    fn hardhat_accounts_did_roundtrip() {
        let keys_and_addresses: &[(&str, &str)] = &[
            (
                "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            ),
            (
                "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            ),
            (
                "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
                "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            ),
        ];

        for (hex_key, expected_addr) in keys_and_addresses {
            let secret = hex::decode(hex_key).unwrap();
            let sk = SigningKey::from_bytes((&secret[..]).into()).unwrap();
            let compressed = sk
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec();

            let did = did_from_secp256k1_pubkey(&compressed).unwrap();
            let addr = evm_address_from_did(&did).unwrap();
            let expected: alloy_primitives::Address = expected_addr.parse().unwrap();

            assert_eq!(addr, expected, "key {hex_key} DID roundtrip failed");
        }
    }
}
