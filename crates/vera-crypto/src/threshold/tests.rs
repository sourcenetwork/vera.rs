use super::*;
use alloy_primitives::U256;
use jubjub::{AffinePoint, ExtendedPoint, Fq};

fn jubjub_vector() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // Copied verbatim from Orbis f1c15b0, crypto/src/jubjub/test_vectors/frost.json.
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("orbis_jubjub_vector.json")).unwrap();
    let decode = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
    (decode("public_key"), decode("message"), decode("signature"))
}

#[test]
fn jubjub_signature_matches_independent_orbis_vector_and_binds_inputs() {
    let (key, message, signature) = jubjub_vector();
    verify(ThresholdScheme::JubjubFrost, &key, &message, &signature).unwrap();
    let other_key = (SubgroupPoint::generator() * Fr::from(8u64)).to_bytes();
    assert!(
        verify(
            ThresholdScheme::JubjubFrost,
            &other_key,
            &message,
            &signature
        )
        .is_err()
    );
    assert!(verify(ThresholdScheme::JubjubFrost, &key, b"other", &signature).is_err());
    let mut altered = signature;
    altered[32] ^= 1;
    assert!(verify(ThresholdScheme::JubjubFrost, &key, &message, &altered).is_err());
}

#[test]
fn jubjub_requires_exact_key_and_signature_lengths() {
    let (key, message, signature) = jubjub_vector();
    for len in [0, 31, 33, 48] {
        let mut malformed = key.clone();
        malformed.resize(len, 0);
        assert!(
            verify(
                ThresholdScheme::JubjubFrost,
                &malformed,
                &message,
                &signature
            )
            .is_err()
        );
    }
    for len in [0, 31, 32, 63, 65, 96] {
        let mut malformed = signature.clone();
        malformed.resize(len, 0);
        assert!(verify(ThresholdScheme::JubjubFrost, &key, &message, &malformed).is_err());
    }
}

#[test]
fn jubjub_rejects_noncanonical_scalar_instead_of_reducing_it() {
    let (key, message, mut signature) = jubjub_vector();
    // Adding the scalar field order preserves the equation if decoding reduces it.
    let modulus = U256::from_str_radix(
        "0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7",
        16,
    )
    .unwrap();
    let noncanonical = U256::from_le_slice(&signature[32..]) + modulus;
    signature[32..].copy_from_slice(&noncanonical.to_le_bytes::<32>());
    assert!(verify(ThresholdScheme::JubjubFrost, &key, &message, &signature).is_err());
    signature[32..].fill(255);
    assert!(verify(ThresholdScheme::JubjubFrost, &key, &message, &signature).is_err());
}

#[test]
fn jubjub_rejects_invalid_noncanonical_and_non_subgroup_points() {
    let (key, message, signature) = jubjub_vector();
    let order_two_bytes = (-Fq::one()).to_bytes();
    let order_two = AffinePoint::from_bytes(order_two_bytes).unwrap();
    assert!(bool::from(order_two.is_small_order()));
    assert!(!bool::from(order_two.is_torsion_free()));
    let mixed_order = ExtendedPoint::from(SubgroupPoint::generator()) + order_two;
    assert!(!bool::from(mixed_order.is_small_order()));
    assert!(!bool::from(mixed_order.is_torsion_free()));
    let mut signed_identity = SubgroupPoint::identity().to_bytes();
    signed_identity[31] |= 0x80;
    let mut signed_order_two = order_two_bytes;
    signed_order_two[31] |= 0x80;
    for invalid in [
        [255; 32],
        order_two_bytes,
        mixed_order.to_bytes(),
        signed_identity,
        signed_order_two,
    ] {
        // Assert rejection at decoding, not merely a later signature mismatch.
        assert!(decode_jubjub_point(&invalid).is_err());
        assert!(verify(ThresholdScheme::JubjubFrost, &invalid, &message, &signature).is_err());
        let mut malformed = signature.clone();
        malformed[..32].copy_from_slice(&invalid);
        assert!(verify(ThresholdScheme::JubjubFrost, &key, &message, &malformed).is_err());
    }
}

#[test]
fn jubjub_rejects_identity_key_forgery() {
    let z = Fr::from(13u64);
    let r = SubgroupPoint::generator() * z;
    let signature = [r.to_bytes(), z.to_bytes()].concat();
    assert!(
        verify(
            ThresholdScheme::JubjubFrost,
            &SubgroupPoint::identity().to_bytes(),
            b"any message",
            &signature,
        )
        .is_err()
    );
}

#[test]
fn jubjub_scheme_uses_the_orbis_wire_name() {
    assert_eq!(
        serde_json::to_string(&ThresholdScheme::JubjubFrost).unwrap(),
        "\"jubjub_frost\""
    );
    assert_eq!(
        serde_json::from_str::<ThresholdScheme>("\"jubjub_frost\"").unwrap(),
        ThresholdScheme::JubjubFrost
    );
    assert!(serde_json::from_str::<ThresholdScheme>("\"decaf377_frost\"").is_err());
}

#[test]
fn augmented_bls_rejects_basic_signatures_and_public_key_substitution() {
    let key = blst::min_pk::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let public = key.sk_to_pk().to_bytes();
    let message = b"ring authorization";
    let augmented = key
        .sign(
            message,
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
            &public,
        )
        .to_bytes();
    verify(ThresholdScheme::Bls12381AugV1, &public, message, &augmented).unwrap();
    let basic = key
        .sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_", &[])
        .to_bytes();
    assert!(verify(ThresholdScheme::Bls12381AugV1, &public, message, &basic).is_err());
    let unaugmented = key
        .sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_", &[])
        .to_bytes();
    assert!(
        verify(
            ThresholdScheme::Bls12381AugV1,
            &public,
            message,
            &unaugmented
        )
        .is_err()
    );
    assert!(
        verify(
            ThresholdScheme::Bls12381AugV1,
            &public,
            b"other",
            &augmented
        )
        .is_err()
    );
    let other = blst::min_pk::SecretKey::key_gen(&[43; 32], &[])
        .unwrap()
        .sk_to_pk()
        .to_bytes();
    assert!(verify(ThresholdScheme::Bls12381AugV1, &other, message, &augmented).is_err());
    assert!(
        verify(
            ThresholdScheme::Bls12381AugV1,
            &public,
            message,
            &augmented[..95]
        )
        .is_err()
    );
    let mut identity = [0; 48];
    identity[0] = 0xc0;
    assert!(
        verify(
            ThresholdScheme::Bls12381AugV1,
            &identity,
            message,
            &augmented
        )
        .is_err()
    );
    assert!(verify(ThresholdScheme::JubjubFrost, &public, message, &augmented).is_err());
    assert!(serde_json::from_str::<ThresholdScheme>("\"bls12_381_g1_pk_g2_sig_nul\"").is_err());
    assert_eq!(
        serde_json::to_string(&ThresholdScheme::Bls12381AugV1).unwrap(),
        "\"bls12_381_g1_pk_g2_sig_aug_v1\""
    );
}

#[test]
fn augmented_bls_matches_orbis_and_rejects_scaled_signature() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("orbis_aug_vector.json")).unwrap();
    let decode = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
    verify(
        ThresholdScheme::Bls12381AugV1,
        &decode("public_key"),
        &decode("message"),
        &decode("signature"),
    )
    .unwrap();
    assert!(
        verify(
            ThresholdScheme::Bls12381AugV1,
            &decode("scaled_public_key"),
            &decode("message"),
            &decode("scaled_signature")
        )
        .is_err()
    );
}
