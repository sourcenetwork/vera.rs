use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use sha2::{Digest as _, Sha256};

use super::*;

const INPUT: &[u8] = b"header.payload";

#[test]
fn derived_dids_name_the_key_and_its_algorithm() {
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let did = ed25519_did(&ed25519.verifying_key().to_bytes()).unwrap();
    assert!(did.starts_with("did:key:z6Mk"));
    assert_eq!(algorithm(&did).unwrap(), "EdDSA");

    let p256 = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let key = p256.verifying_key();
    let did = p256_did(key.to_encoded_point(true).as_bytes()).unwrap();
    assert!(did.starts_with("did:key:zDn"));
    assert_eq!(
        did,
        p256_did(key.to_encoded_point(false).as_bytes()).unwrap()
    );
    assert_eq!(algorithm(&did).unwrap(), "ES256");

    let secp256k1 = k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let did = crate::secp256k1::did_from_secp256k1_pubkey(
        secp256k1.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    assert_eq!(algorithm(&did).unwrap(), "ES256K");
}

#[test]
fn invalid_keys_have_no_did() {
    assert!(ed25519_did(&[0; 32]).is_err());
    for invalid in [&[8; 33][..], &[0], &[]] {
        assert!(p256_did(invalid).is_err());
    }
    assert!(algorithm("did:key:z6Mk").is_err());
}

#[test]
fn either_ecdsa_s_and_der_reduce_to_the_accepted_signature() {
    let signer = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let did = p256_did(signer.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
    let key = ActorKey::from_did(&did).unwrap();
    let signature: p256::ecdsa::Signature = signer.sign_prehash(&Sha256::digest(INPUT)).unwrap();
    let low = signature.normalize_s().unwrap_or(signature);
    let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
    assert!(key.verify(INPUT, &high.to_vec()).is_err());
    for accepted in [
        canonical_signature(&did, &low.to_vec()).unwrap(),
        canonical_signature(&did, &high.to_vec()).unwrap(),
        canonical_der_signature(&did, low.to_der().as_bytes()).unwrap(),
        canonical_der_signature(&did, high.to_der().as_bytes()).unwrap(),
    ] {
        assert_eq!(accepted, low.to_vec());
        key.verify(INPUT, &accepted).unwrap();
    }
    assert!(canonical_signature(&did, &low.to_vec()[..63]).is_err());
    assert!(canonical_der_signature(&did, &low.to_vec()).is_err());
}

#[test]
fn ed25519_signatures_are_raw_only() {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let did = ed25519_did(&signer.verifying_key().to_bytes()).unwrap();
    let signature = signer.sign(INPUT).to_bytes();
    assert_eq!(canonical_signature(&did, &signature).unwrap(), signature);
    assert!(canonical_signature(&did, &signature[..63]).is_err());
    assert!(canonical_der_signature(&did, &signature).is_err());
}

#[test]
fn each_key_type_verifies_a_digest_signature_in_one_encoding() {
    let digest: [u8; 32] = Sha256::digest(INPUT).into();

    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let did = ed25519_did(&ed25519.verifying_key().to_bytes()).unwrap();
    assert_eq!(key_type(&did).unwrap(), ActorKeyType::Ed25519);
    let signature = ed25519.sign(&digest).to_bytes();
    verify_digest(&did, &digest, &signature).unwrap();
    assert!(verify_digest(&did, &[0; 32], &signature).is_err());
    assert!(verify_digest(&did, &digest, &ed25519.sign(INPUT).to_bytes()).is_err());

    let p256 = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let did = p256_did(p256.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
    assert_eq!(key_type(&did).unwrap(), ActorKeyType::P256);
    let signature: p256::ecdsa::Signature = p256.sign_prehash(&digest).unwrap();
    let low = signature.normalize_s().unwrap_or(signature);
    let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
    verify_digest(&did, &digest, &low.to_vec()).unwrap();
    assert!(verify_digest(&did, &digest, &high.to_vec()).is_err());
    assert!(verify_digest(&did, &[0; 32], &low.to_vec()).is_err());

    let secp256k1 = k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let public = secp256k1.verifying_key().to_encoded_point(true);
    let did = crate::secp256k1::did_from_secp256k1_pubkey(public.as_bytes()).unwrap();
    assert_eq!(key_type(&did).unwrap(), ActorKeyType::Secp256k1);
    let signature: k256::ecdsa::Signature = secp256k1.sign_prehash(&digest).unwrap();
    let low = signature.normalize_s().unwrap_or(signature);
    verify_digest(&did, &digest, &low.to_vec()).unwrap();
    crate::secp256k1::verify_digest(public.as_bytes(), &digest, &low.to_vec()).unwrap();
    assert!(verify_digest(&did, &digest, &low.to_vec()[..63]).is_err());
}

fn secp256k1_spellings(key: &k256::ecdsa::SigningKey) -> [String; 4] {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = |compressed| {
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(key.verifying_key().to_encoded_point(compressed).as_bytes());
        bytes
    };
    [
        format!("did:key:{}", crate::did_key::encode(&bytes(true))),
        format!("did:key:{}", crate::did_key::encode(&bytes(false))),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(true))),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(false))),
    ]
}

#[test]
fn every_secp256k1_spelling_is_recorded_as_the_compressed_base58_did() {
    let key = k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let spellings = secp256k1_spellings(&key);
    let canonical = crate::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    assert_eq!(spellings[0], canonical);
    assert!(canonical.starts_with("did:key:zQ3s"));
    for spelling in &spellings {
        assert_eq!(key_type(spelling).unwrap(), ActorKeyType::Secp256k1);
        assert_eq!(canonical_did(spelling), canonical);
        assert_eq!(
            crate::jwt::canonical_actor(spelling).unwrap(),
            canonical,
            "both canonical functions share one definition"
        );
        assert_eq!(canonical_did(&canonical_did(spelling)), canonical);
        assert!(crate::jwt::matches_issuer(spelling, &canonical));
    }
    assert!(matches!(
        canonical_did(&canonical),
        std::borrow::Cow::Borrowed(_)
    ));

    let other = k256::ecdsa::SigningKey::from_slice(&[43; 32]).unwrap();
    for spelling in secp256k1_spellings(&other) {
        assert_ne!(canonical_did(&spelling), canonical);
        assert!(!crate::jwt::matches_issuer(&spelling, &canonical));
    }
}

#[test]
fn identifiers_with_one_spelling_are_recorded_as_written() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let ed25519_key = ed25519.verifying_key().to_bytes();
    let p256 = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let p256_key = p256.verifying_key();
    let bls = crate::bls::did_from_bls_pubkey(&ark_ec::AffineRepr::generator());

    let mut ed25519_base64 = vec![0xed, 0x01];
    ed25519_base64.extend_from_slice(&ed25519_key);
    let mut p256_uncompressed = vec![0x80, 0x24];
    p256_uncompressed.extend_from_slice(p256_key.to_encoded_point(false).as_bytes());
    let mut off_curve = vec![0xe7, 0x01, 0x04];
    off_curve.extend_from_slice(&[0x11; 64]);

    for unchanged in [
        ed25519_did(&ed25519_key).unwrap(),
        p256_did(p256_key.to_encoded_point(true).as_bytes()).unwrap(),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(&ed25519_base64)),
        format!("did:key:{}", crate::did_key::encode(&p256_uncompressed)),
        format!("did:key:{}", crate::did_key::encode(&off_curve)),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(&off_curve)),
        bls.unwrap(),
        format!("did:opk:{}", "ab".repeat(32)),
        "*".to_owned(),
        "did:key:alice".to_owned(),
        "did:key:user".to_owned(),
        "did:key:z0".to_owned(),
        "did:key:".to_owned(),
        "0xABCD".to_owned(),
        String::new(),
    ] {
        assert!(
            matches!(canonical_did(&unchanged), std::borrow::Cow::Borrowed(_)),
            "rewrote {unchanged:?}"
        );
    }
}
