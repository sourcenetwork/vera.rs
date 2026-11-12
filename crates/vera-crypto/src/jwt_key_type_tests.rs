//! Delegation tokens across the three issuer key types.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;
use k256::ecdsa::signature::hazmat::PrehashSigner as _;
use sha2::{Digest as _, Sha256};

use super::*;

enum Issuer {
    Secp256k1(k256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Issuer {
    fn all() -> [Self; 3] {
        [
            Self::Secp256k1(k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap()),
            Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[42; 32])),
            Self::P256(p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap()),
        ]
    }

    fn key(&self) -> ActorKey {
        match self {
            Self::Secp256k1(key) => ActorKey::Secp256k1(*key.verifying_key()),
            Self::Ed25519(key) => ActorKey::Ed25519(key.verifying_key()),
            Self::P256(key) => ActorKey::P256(*key.verifying_key()),
        }
    }

    fn did(&self) -> String {
        self.key().canonical_did()
    }

    /// The single signature encoding a verifier accepts for `input`.
    fn sign(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Secp256k1(key) => {
                let signature: k256::ecdsa::Signature =
                    key.sign_prehash(&Sha256::digest(input)).unwrap();
                signature.normalize_s().unwrap_or(signature).to_vec()
            }
            Self::Ed25519(key) => key.sign(input).to_bytes().to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature =
                    key.sign_prehash(&Sha256::digest(input)).unwrap();
                signature.normalize_s().unwrap_or(signature).to_vec()
            }
        }
    }
}

fn claims(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": issuer, "sub": "worker", "aud": "vera:9001", "scope": "acp:policy",
        "iat": 1, "nbf": 1, "exp": 9_999_999_999u64,
    })
}

fn token(alg: &str, typ: &str, claims: &serde_json::Value, signer: &Issuer) -> String {
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{alg}","typ":"{typ}"}}"#));
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(signer.sign(input.as_bytes()));
    format!("{input}.{signature}")
}

const DELEGATION: &str = "vera-delegation-v1+jwt";

#[test]
fn each_key_type_issues_a_delegation_under_its_own_algorithm() {
    for issuer in Issuer::all() {
        let did = issuer.did();
        let alg = issuer.key().algorithm();
        let verified =
            verify_bearer_token(&token(alg, DELEGATION, &claims(&did), &issuer)).unwrap();
        assert_eq!(verified.iss, did);
        assert_eq!(verified.actor(), did);
        assert_eq!(canonical_actor(&did).unwrap(), did);
        verified.authorize("worker", 9001, 5).unwrap();
    }
}

#[test]
fn an_algorithm_that_is_not_the_issuer_key_type_is_rejected() {
    for issuer in Issuer::all() {
        let own = issuer.key().algorithm();
        for alg in ["ES256K", "EdDSA", "ES256"] {
            if alg == own {
                continue;
            }
            let result =
                verify_bearer_token(&token(alg, DELEGATION, &claims(&issuer.did()), &issuer));
            assert!(
                matches!(result, Err(JwtError::UnsupportedAlgorithm(_))),
                "{own} key accepted under {alg}"
            );
        }
    }
}

#[test]
fn a_token_signed_by_another_key_is_rejected() {
    let issuers = Issuer::all();
    for (index, issuer) in issuers.iter().enumerate() {
        let other = &issuers[(index + 1) % issuers.len()];
        let forged = token(
            issuer.key().algorithm(),
            DELEGATION,
            &claims(&issuer.did()),
            other,
        );
        assert!(matches!(
            verify_bearer_token(&forged),
            Err(JwtError::InvalidSignature)
        ));
    }
}

#[test]
fn a_high_s_p256_signature_is_not_a_second_valid_token() {
    let issuer = Issuer::P256(p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap());
    let valid = token("ES256", DELEGATION, &claims(&issuer.did()), &issuer);
    verify_bearer_token(&valid).unwrap();

    let (input, signature) = valid.rsplit_once('.').unwrap();
    let low =
        p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
    let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
    assert!(high.normalize_s().is_some());
    let malleated = format!("{input}.{}", URL_SAFE_NO_PAD.encode(high.to_bytes()));
    assert_ne!(malleated, valid);
    assert!(matches!(
        verify_bearer_token(&malleated),
        Err(JwtError::InvalidSignature)
    ));
}

#[test]
fn relay_tokens_and_relay_identities_stay_secp256k1() {
    for issuer in Issuer::all() {
        let did = issuer.did();
        let mut relay = claims(&did);
        relay["relay"] = serde_json::json!({
            "actor": format!("did:opk:{}", "ab".repeat(32)),
            "genesis_id": vec![7u8; 32],
            "grant_sequence": 1,
            "operation": vec![9u8; 32],
        });
        let result = verify_bearer_token(&token(
            issuer.key().algorithm(),
            "vera-relay-v1+jwt",
            &relay,
            &issuer,
        ));
        let secp256k1 = matches!(issuer, Issuer::Secp256k1(_));
        assert_eq!(result.is_ok(), secp256k1, "{did}");
        assert_eq!(canonical_issuer(&did).is_ok(), secp256k1, "{did}");
    }
}

#[test]
fn revocation_matches_only_the_same_key() {
    let issuers = Issuer::all();
    for (index, issuer) in issuers.iter().enumerate() {
        assert!(matches_issuer(&issuer.did(), &issuer.did()));
        let other = &issuers[(index + 1) % issuers.len()];
        assert!(!matches_issuer(&issuer.did(), &other.did()));
    }
}
