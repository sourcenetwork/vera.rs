use sha2::{Digest as _, Sha256};

use super::*;
use crate::webauthn::{
    WebauthnError, join_token_signature,
    testing::{Authenticator, Signed},
};

fn claims(issuer: &str) -> String {
    serde_json::json!({"iss": issuer, "sub": "worker", "aud": "vera:9001", "scope": "acp:policy", "iat": 10, "nbf": 5, "exp": 100}).to_string()
}

fn input(header: &str, payload: &str) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

fn header(alg: &str, typ: &str) -> String {
    format!(r#"{{"alg":"{alg}","typ":"{typ}"}}"#)
}

fn challenge_of(input: &str) -> [u8; 32] {
    Sha256::digest(input.as_bytes()).into()
}

fn token(input: &str, signed: &Signed) -> String {
    let segment = join_token_signature(&signed.assertion(), &signed.signature);
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(segment))
}

/// A passkey delegation by `authenticator`, asserted as a platform does.
fn passkey_token(authenticator: &Authenticator) -> String {
    let input = input(
        &header("ES256", WEBAUTHN_TOKEN_TYPE),
        &claims(&authenticator.did()),
    );
    token(&input, &authenticator.assert(&challenge_of(&input)))
}

#[test]
fn a_passkey_delegation_verifies() {
    let authenticator = Authenticator::new([3; 32]);
    let claims = verify_bearer_token(&passkey_token(&authenticator)).unwrap();
    assert_eq!(claims.iss, authenticator.did());
    assert_eq!(claims.scope, DelegationScope::PolicyCommands);
}

#[test]
fn the_challenge_is_the_digest_of_this_tokens_signing_input() {
    let authenticator = Authenticator::new([3; 32]);
    let input = input(
        &header("ES256", WEBAUTHN_TOKEN_TYPE),
        &claims(&authenticator.did()),
    );
    let other = input.replacen('.', ".e", 1);
    let wrong = token(&input, &authenticator.assert(&challenge_of(&other)));
    assert!(matches!(
        verify_bearer_token(&wrong),
        Err(JwtError::Assertion(WebauthnError::Challenge))
    ));
    // The same assertion moved to another payload by the same issuer.
    let token = passkey_token(&authenticator);
    let signature = token.rsplit_once('.').unwrap().1;
    let moved = format!(
        "{}.{signature}",
        self::input(
            &header("ES256", WEBAUTHN_TOKEN_TYPE),
            &claims(&authenticator.did()).replace("worker", "attacker")
        )
    );
    assert!(matches!(
        verify_bearer_token(&moved),
        Err(JwtError::Assertion(WebauthnError::Challenge))
    ));
}

#[test]
fn only_a_p256_issuer_signs_under_the_passkey_type() {
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let ed25519 = crate::actor::ed25519_did(&ed25519.verifying_key().to_bytes()).unwrap();
    let secp256k1 = crate::secp256k1::did_from_secp256k1_pubkey(
        &k256::ecdsa::SigningKey::from_slice(&[1; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes(),
    )
    .unwrap();
    let authenticator = Authenticator::new([3; 32]);
    for (issuer, alg) in [
        (&ed25519, "EdDSA"),
        (&ed25519, "ES256"),
        (&secp256k1, "ES256K"),
        (&secp256k1, "ES256"),
    ] {
        let input = input(&header(alg, WEBAUTHN_TOKEN_TYPE), &claims(issuer));
        let token = token(&input, &authenticator.assert(&challenge_of(&input)));
        assert!(
            matches!(
                verify_bearer_token(&token),
                Err(JwtError::UnsupportedAlgorithm(_))
            ),
            "{issuer} {alg}"
        );
    }
}

#[test]
fn a_relay_claim_is_not_accepted_under_the_passkey_type() {
    let authenticator = Authenticator::new([3; 32]);
    let mut claims: serde_json::Value =
        serde_json::from_str(&claims(&authenticator.did())).unwrap();
    claims["relay"] = serde_json::json!({"actor": "did:opk:x", "genesis_id": vec![1; 32], "grant_sequence": 0, "operation": vec![2; 32]});
    let input = input(&header("ES256", WEBAUTHN_TOKEN_TYPE), &claims.to_string());
    let token = token(&input, &authenticator.assert(&challenge_of(&input)));
    assert!(matches!(
        verify_bearer_token(&token),
        Err(JwtError::InvalidClaims(_))
    ));
}

#[test]
fn the_two_signature_forms_do_not_cross() {
    let authenticator = Authenticator::new([3; 32]);
    let passkey = passkey_token(&authenticator);
    let (_, segment) = passkey.rsplit_once('.').unwrap();
    let raw_input = input(
        &header("ES256", DELEGATION_TOKEN_TYPE),
        &claims(&authenticator.did()),
    );
    assert!(matches!(
        verify_bearer_token(&format!("{raw_input}.{segment}")),
        Err(JwtError::InvalidSignature)
    ));
    let signed = authenticator.assert(&challenge_of(&raw_input));
    assert!(matches!(
        verify_bearer_token(&format!(
            "{raw_input}.{}",
            URL_SAFE_NO_PAD.encode(signed.signature)
        )),
        Err(JwtError::InvalidSignature)
    ));
}

#[test]
fn the_signature_segment_is_strict() {
    let authenticator = Authenticator::new([3; 32]);
    let input = input(
        &header("ES256", WEBAUTHN_TOKEN_TYPE),
        &claims(&authenticator.did()),
    );
    let signed = authenticator.assert(&challenge_of(&input));
    let segment = join_token_signature(&signed.assertion(), &signed.signature);
    let valid = format!("{input}.{}", URL_SAFE_NO_PAD.encode(&segment));
    verify_bearer_token(&valid).unwrap();
    assert!(matches!(
        verify_bearer_token(&format!("{valid}=")),
        Err(JwtError::MalformedToken(_))
    ));
    let der = [
        signed.authenticator_data.as_slice(),
        &signed.der,
        &signed.client_data_json,
    ]
    .concat();
    assert!(verify_bearer_token(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(der))).is_err());
    let signature = p256::ecdsa::Signature::from_slice(&signed.signature).unwrap();
    let high = p256::ecdsa::Signature::from_scalars(signature.r(), -*signature.s()).unwrap();
    let high = [
        signed.authenticator_data.as_slice(),
        &high.to_bytes(),
        &signed.client_data_json,
    ]
    .concat();
    assert!(matches!(
        verify_bearer_token(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(high))),
        Err(JwtError::Assertion(WebauthnError::Signature))
    ));
    for short in [0, 37, 101] {
        assert!(matches!(
            verify_bearer_token(&format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(&segment[..short])
            )),
            Err(JwtError::Assertion(WebauthnError::TokenSignatureLength))
        ));
    }
    let long = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        crate::webauthn::challenge(&challenge_of(&input)),
        "o".repeat(1000)
    );
    let long = authenticator.sign(&signed.authenticator_data, long.as_bytes());
    assert!(long.client_data_json.len() > 1024);
    assert!(matches!(
        verify_bearer_token(&token(&input, &long)),
        Err(JwtError::Assertion(WebauthnError::TokenSignatureLength))
    ));
}

#[test]
fn user_verification_is_required_in_tokens() {
    let mut authenticator = Authenticator::new([3; 32]);
    authenticator.flags = 0x01;
    assert!(matches!(
        verify_bearer_token(&passkey_token(&authenticator)),
        Err(JwtError::Assertion(WebauthnError::UserNotVerified))
    ));
}
