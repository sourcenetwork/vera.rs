use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Signer as _;
use vera_crypto::{
    actor::{ed25519_did, p256_did},
    jwt::verify_bearer_token,
    operation::{OperationClaim, OperationId},
};

use super::*;

fn ed25519() -> (ed25519_dalek::SigningKey, String) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let did = ed25519_did(&key.verifying_key().to_bytes()).unwrap();
    (key, did)
}

fn p256() -> (p256::ecdsa::SigningKey, String) {
    let key = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let did = p256_did(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
    (key, did)
}

fn delegation(issuer: &str) -> UnsignedToken {
    UnsignedToken::delegation(
        issuer,
        "did:key:worker",
        9001,
        50,
        100,
        DelegationScope::CreatePolicy,
    )
    .unwrap()
}

#[test]
fn an_ed25519_key_signs_the_input_itself() {
    let (key, did) = ed25519();
    let unsigned = delegation(&did);
    let signature = key.sign(unsigned.signing_input()).to_bytes();
    let claims = verify_bearer_token(&unsigned.finish(&signature).unwrap()).unwrap();
    assert_eq!(claims.iss, did);
    assert_eq!(claims.scope, DelegationScope::CreatePolicy);
    claims.authorize("did:key:worker", 9001, 50).unwrap();
}

#[test]
fn a_p256_key_signs_the_digest_in_raw_or_der_form() {
    let (key, did) = p256();
    let signature: p256::ecdsa::Signature = key.sign(delegation(&did).signing_input());
    let low = signature.normalize_s().unwrap_or(signature);
    let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
    let raw = delegation(&did).finish(&low.to_vec()).unwrap();
    assert_eq!(verify_bearer_token(&raw).unwrap().iss, did);
    assert_eq!(delegation(&did).finish(&high.to_vec()).unwrap(), raw);
    for der in [low.to_der(), high.to_der()] {
        assert_eq!(delegation(&did).finish_der(der.as_bytes()).unwrap(), raw);
    }
}

#[test]
fn a_signature_from_another_key_or_token_is_refused() {
    let (key, did) = ed25519();
    let other = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
    let unsigned = delegation(&did);
    let foreign = other.sign(unsigned.signing_input()).to_bytes();
    assert!(unsigned.clone().finish(&foreign).is_err());
    let stale = key.sign(b"another token").to_bytes();
    assert!(unsigned.clone().finish(&stale).is_err());
    assert!(unsigned.clone().finish(&foreign[..63]).is_err());
    assert!(unsigned.finish_der(&foreign).is_err());
}

#[test]
fn an_issuer_must_be_a_supported_canonical_key() {
    for issuer in ["did:key:z6Mk", "did:opk:abc", ""] {
        assert!(
            UnsignedToken::delegation(issuer, "w", 9001, 50, 100, DelegationScope::CreatePolicy)
                .is_err()
        );
    }
    let (_, did) = ed25519();
    for expires_at in [0, 50] {
        assert!(
            UnsignedToken::delegation(&did, "w", 9001, 50, expires_at, DelegationScope::EditPolicy)
                .is_err()
        );
    }
}

#[test]
fn operation_tokens_keep_their_binding_checks_for_every_key_type() {
    let (key, did) = p256();
    let mut id = [1; 32];
    id[..8].copy_from_slice(&100u64.to_be_bytes());
    let claims = JwtClaims {
        iss: did.clone(),
        sub: "did:key:worker".into(),
        exp: 100,
        aud: "vera:9001".into(),
        scope: DelegationScope::CreatePolicy,
        iat: 50,
        nbf: 50,
        relay: None,
        request: Some(OperationClaim {
            id: OperationId(id),
            digest: [3; 32],
            genesis_id: [4; 32],
        }),
    };
    let unsigned = UnsignedToken::operation(&claims).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(unsigned.signing_input());
    let verified = verify_bearer_token(&unsigned.finish(&signature.to_vec()).unwrap()).unwrap();
    assert_eq!(verified.iss, did);
    assert_eq!(verified.request.unwrap().digest, [3; 32]);
    for case in 0..5 {
        let mut invalid = claims.clone();
        match case {
            0 => invalid.request = None,
            1 => invalid.exp = 101,
            2 => invalid.request.as_mut().unwrap().genesis_id = [0; 32],
            3 => invalid.request.as_mut().unwrap().id.0[8..].fill(0),
            _ => invalid.nbf -= 1,
        }
        assert!(UnsignedToken::operation(&invalid).is_err());
    }
}
