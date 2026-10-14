//! BLS12-381 signing, verification, and `did:key:` derivation.
//!
//! Matches orbis-rs conventions: G1 pubkeys (48 bytes), G2 signatures (96 bytes),
//! IETF-standard hash-to-curve DST.

use ark_bls12_381::{G1Affine, G2Affine, G2Projective, g2::Config as G2Config};
use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
};
use ark_ff::{Zero, field_hashers::DefaultFieldHasher};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

/// IETF-standard BLS signature DST (matches orbis-rs `sign.rs:27`).
const BLS_SIG_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// BLS multicodec prefix for `bls12_381-g1-pub`.
const BLS_G1_MULTICODEC: u64 = 0xea;

/// Errors from BLS operations.
#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    /// Hash-to-curve failed.
    #[error("hash-to-curve failed")]
    HashToCurve,
    /// Point serialization failed.
    #[error("serialization failed")]
    Serialize,
    /// Point deserialization failed.
    #[error("deserialization failed")]
    Deserialize,
    /// Signature verification failed (pairing mismatch).
    #[error("invalid signature")]
    InvalidSignature,
    /// Secret key is zero (degenerate — produces forgeable identity signatures).
    #[error("invalid secret key")]
    InvalidSecretKey,
    /// Public key is the identity point (degenerate — passes no signature checks).
    #[error("invalid public key")]
    InvalidPublicKey,
}

/// Hash a message to a G2 point using the IETF hash-to-curve suite.
///
/// Ported from orbis-rs `sign.rs:201-223`.
pub fn hash_to_g2(msg: &[u8]) -> Result<G2Affine, BlsError> {
    type G2Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256>, WBMap<G2Config>>;
    let hasher = G2Hasher::new(BLS_SIG_DOMAIN).map_err(|_| BlsError::HashToCurve)?;
    let point: G2Affine = hasher.hash(msg).map_err(|_| BlsError::HashToCurve)?;
    if point.is_zero() {
        return Err(BlsError::HashToCurve);
    }
    Ok(point)
}

/// Sign a message with a BLS secret key, producing a compressed G2 signature (96 bytes).
pub fn sign(secret_key: &ark_bls12_381::Fr, msg: &[u8]) -> Result<Vec<u8>, BlsError> {
    if secret_key.is_zero() {
        return Err(BlsError::InvalidSecretKey);
    }
    let h_msg = hash_to_g2(msg)?;
    let sig: G2Affine = (G2Projective::from(h_msg) * secret_key).into_affine();
    let mut bytes = Vec::with_capacity(96);
    sig.serialize_compressed(&mut bytes)
        .map_err(|_| BlsError::Serialize)?;
    Ok(bytes)
}

/// Verify a BLS signature against a G1 public key and message.
///
/// Rejects identity points for both the public key and signature to prevent
/// trivial forgery. Uses blst with signature subgroup and public-key validation.
pub fn verify(pubkey: &G1Affine, msg: &[u8], sig_bytes: &[u8]) -> Result<(), BlsError> {
    if pubkey.is_zero() {
        return Err(BlsError::InvalidSignature);
    }

    let mut encoded_key = [0u8; 48];
    pubkey
        .serialize_compressed(encoded_key.as_mut_slice())
        .map_err(|_| BlsError::Serialize)?;
    verify_compressed(&encoded_key, msg, sig_bytes).map(|_| ())
}

/// Verify a compressed G1 key/G2 signature and return the authenticated signer's DID.
/// Both points are validated before deriving the DID from the canonical key encoding.
pub fn verify_and_identify(
    pubkey: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<String, BlsError> {
    let key = verify_compressed(pubkey, msg, signature)?;
    Ok(did_from_encoded_key(&key.to_bytes()))
}

fn verify_compressed(
    pubkey: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<blst::min_pk::PublicKey, BlsError> {
    if pubkey.len() != 48 || sig_bytes.len() != 96 {
        return Err(BlsError::Deserialize);
    }
    let key = blst::min_pk::PublicKey::from_bytes(pubkey).map_err(|_| BlsError::Deserialize)?;
    let signature =
        blst::min_pk::Signature::from_bytes(sig_bytes).map_err(|_| BlsError::Deserialize)?;
    if signature.verify(true, msg, BLS_SIG_DOMAIN, &[], &key, true)
        != blst::BLST_ERROR::BLST_SUCCESS
    {
        return Err(BlsError::InvalidSignature);
    }
    Ok(key)
}

/// Deserialize a compressed BLS G1 public key (48 bytes).
///
/// Rejects the identity point (point at infinity).
pub fn deserialize_pubkey(bytes: &[u8]) -> Result<G1Affine, BlsError> {
    let pk = G1Affine::deserialize_compressed(bytes).map_err(|_| BlsError::Deserialize)?;
    if pk.is_zero() {
        return Err(BlsError::InvalidPublicKey);
    }
    Ok(pk)
}

/// Derive a `did:key:` identifier from a BLS G1 public key.
///
/// Encoding: `did:key:` + multibase(Base58Btc, varint(0xea) || compressed_pubkey).
pub fn did_from_bls_pubkey(pubkey: &G1Affine) -> Result<String, BlsError> {
    if pubkey.is_zero() {
        return Err(BlsError::InvalidPublicKey);
    }
    let mut pubkey_bytes = [0u8; 48];
    pubkey
        .serialize_compressed(pubkey_bytes.as_mut_slice())
        .map_err(|_| BlsError::Serialize)?;
    Ok(did_from_encoded_key(&pubkey_bytes))
}

/// Validate a compressed G1 public key and derive its canonical DID.
/// Rejects infinity and non-subgroup points; does not verify a request signature.
pub fn did_from_compressed_pubkey(bytes: &[u8]) -> Result<String, BlsError> {
    if bytes.len() != 48 {
        return Err(BlsError::Deserialize);
    }
    let key = blst::min_pk::PublicKey::from_bytes(bytes).map_err(|_| BlsError::Deserialize)?;
    key.validate().map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(did_from_encoded_key(&key.to_bytes()))
}

fn did_from_encoded_key(pubkey: &[u8; 48]) -> String {
    let mut varint_buf = [0u8; 10];
    let varint = unsigned_varint::encode::u64(BLS_G1_MULTICODEC, &mut varint_buf);
    let mut codec_bytes = Vec::with_capacity(varint.len() + pubkey.len());
    codec_bytes.extend_from_slice(varint);
    codec_bytes.extend_from_slice(pubkey);
    let encoded = multibase::encode(multibase::Base::Base58Btc, &codec_bytes);
    format!("did:key:{encoded}")
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;

    use super::*;

    fn generate_keypair() -> (Fr, G1Affine) {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();
        (sk, pk)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, pk) = generate_keypair();
        let msg = b"test message";
        let sig = sign(&sk, msg).expect("sign");
        verify(&pk, msg, &sig).expect("verify");
    }

    #[test]
    fn verify_rejects_non_subgroup_public_key_and_trailing_signature_bytes() {
        let (sk, pk) = generate_keypair();
        let mut signature = sign(&sk, b"message").unwrap();
        let torsion =
            G1Affine::new_unchecked(ark_bls12_381::Fq::from(0), ark_bls12_381::Fq::from(2));
        assert!(torsion.is_on_curve());
        assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
        assert!(verify(&torsion, b"message", &signature).is_err());
        signature.push(0);
        assert!(verify(&pk, b"message", &signature).is_err());
    }

    #[test]
    fn compressed_verification_preserves_identity_and_rejects_invalid_inputs() {
        let (sk, pk) = generate_keypair();
        let mut encoded = Vec::new();
        pk.serialize_compressed(&mut encoded).unwrap();
        let signature = sign(&sk, b"message").unwrap();
        assert_eq!(
            verify_and_identify(&encoded, b"message", &signature).unwrap(),
            did_from_bls_pubkey(&pk).unwrap()
        );
        assert!(verify_and_identify(&encoded, b"other", &signature).is_err());
        assert!(verify_and_identify(&encoded[..47], b"message", &signature).is_err());
        let torsion =
            G1Affine::new_unchecked(ark_bls12_381::Fq::from(0), ark_bls12_381::Fq::from(2));
        for invalid in [G1Affine::zero(), torsion] {
            let mut encoded = Vec::new();
            invalid.serialize_compressed(&mut encoded).unwrap();
            assert!(verify_and_identify(&encoded, b"message", &signature).is_err());
        }
        let mut identity_signature = Vec::new();
        G2Affine::zero()
            .serialize_compressed(&mut identity_signature)
            .unwrap();
        assert!(verify_and_identify(&encoded, b"message", &identity_signature).is_err());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (sk, pk) = generate_keypair();
        let sig = sign(&sk, b"correct message").expect("sign");
        let result = verify(&pk, b"wrong message", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (sk, _pk) = generate_keypair();
        let msg = b"test message";
        let sig = sign(&sk, msg).expect("sign");

        let mut rng = test_rng();
        // Use a different seed to get a different key.
        let _ = Fr::rand(&mut rng);
        let sk2 = Fr::rand(&mut rng);
        let pk2 = (G1Projective::from(G1Affine::generator()) * sk2).into_affine();

        let result = verify(&pk2, msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn did_derivation_valid_format() {
        let (_sk, pk) = generate_keypair();
        let did = did_from_bls_pubkey(&pk).expect("did");
        assert!(
            did.starts_with("did:key:z"),
            "DID should start with did:key:z, got: {did}"
        );

        let multibase_part = &did["did:key:".len()..];
        let (_base, decoded) = multibase::decode(multibase_part).expect("multibase decode");

        let mut varint_buf = [0u8; 10];
        let expected_prefix = unsigned_varint::encode::u64(BLS_G1_MULTICODEC, &mut varint_buf);
        assert_eq!(&decoded[..expected_prefix.len()], expected_prefix);

        let recovered_pk =
            G1Affine::deserialize_compressed(&decoded[expected_prefix.len()..]).expect("deser pk");
        assert_eq!(recovered_pk, pk);
    }

    #[test]
    fn did_is_deterministic() {
        let (_sk, pk) = generate_keypair();
        let did1 = did_from_bls_pubkey(&pk).expect("did1");
        let did2 = did_from_bls_pubkey(&pk).expect("did2");
        assert_eq!(did1, did2);
    }

    #[test]
    fn compressed_did_derivation_matches_validated_arkworks_keys() {
        for scalar in 1..=32_u64 {
            let key = (G1Projective::from(G1Affine::generator()) * Fr::from(scalar)).into_affine();
            let mut encoded = Vec::new();
            key.serialize_compressed(&mut encoded).unwrap();
            let decoded = deserialize_pubkey(&encoded).unwrap();
            assert_eq!(
                did_from_compressed_pubkey(&encoded).unwrap(),
                did_from_bls_pubkey(&decoded).unwrap()
            );
        }
    }

    #[test]
    fn compressed_did_rejects_invalid_encoding_identity_and_torsion() {
        let torsion =
            G1Affine::new_unchecked(ark_bls12_381::Fq::from(0), ark_bls12_381::Fq::from(2));
        assert!(torsion.is_on_curve());
        assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
        for key in [G1Affine::zero(), torsion] {
            let mut encoded = Vec::new();
            key.serialize_compressed(&mut encoded).unwrap();
            assert!(did_from_compressed_pubkey(&encoded).is_err());
        }
        let mut valid = Vec::new();
        G1Affine::generator()
            .serialize_compressed(&mut valid)
            .unwrap();
        assert!(did_from_compressed_pubkey(&[]).is_err());
        assert!(did_from_compressed_pubkey(&valid[..47]).is_err());
        valid.push(0);
        assert!(did_from_compressed_pubkey(&valid).is_err());
        assert!(did_from_compressed_pubkey(&[0xff; 48]).is_err());
        let mut uncompressed = Vec::new();
        G1Affine::generator()
            .serialize_uncompressed(&mut uncompressed)
            .unwrap();
        assert!(did_from_compressed_pubkey(&uncompressed).is_err());
    }

    #[test]
    fn sign_rejects_zero_secret_key() {
        let result = sign(&Fr::from(0u64), b"test message");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_pubkey_rejects_identity() {
        let mut bytes = Vec::new();
        G1Affine::zero()
            .serialize_compressed(&mut bytes)
            .expect("serialize identity");
        assert!(deserialize_pubkey(&bytes).is_err());
    }

    #[test]
    fn did_rejects_identity_pubkey() {
        let identity = G1Affine::zero();
        assert!(did_from_bls_pubkey(&identity).is_err());
    }

    #[test]
    fn verify_rejects_identity_pubkey() {
        let (sk, _pk) = generate_keypair();
        let msg = b"test message";
        let sig = sign(&sk, msg).expect("sign");
        let identity = G1Affine::zero();
        assert!(verify(&identity, msg, &sig).is_err());
    }

    #[test]
    fn verify_rejects_identity_signature() {
        let (_sk, pk) = generate_keypair();
        let msg = b"test message";
        let mut sig_bytes = Vec::new();
        G2Affine::zero()
            .serialize_compressed(&mut sig_bytes)
            .expect("serialize identity");
        assert!(verify(&pk, msg, &sig_bytes).is_err());
    }

    #[test]
    fn pubkey_serialization_roundtrip() {
        let (_sk, pk) = generate_keypair();
        let mut bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut bytes).expect("serialize");
        assert_eq!(bytes.len(), 48);
        let recovered = deserialize_pubkey(&bytes).expect("deserialize");
        assert_eq!(recovered, pk);
    }
}
