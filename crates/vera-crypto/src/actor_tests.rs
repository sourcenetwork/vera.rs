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
