use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Signer as _;
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};

use super::*;
use crate::{types::Timestamp, vera::keys};

const TOKEN: &str = "issued-bearer-token";

enum Actor {
    Secp256k1(k256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Actor {
    fn all() -> [Self; 3] {
        [
            Self::Secp256k1(k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap()),
            Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[42; 32])),
            Self::P256(p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap()),
        ]
    }

    fn other() -> Self {
        Self::Secp256k1(k256::ecdsa::SigningKey::from_slice(&[43; 32]).unwrap())
    }

    fn did(&self) -> String {
        match self {
            Self::Secp256k1(key) => {
                return vera_crypto::secp256k1::did_from_secp256k1_pubkey(
                    key.verifying_key().to_sec1_bytes().as_ref(),
                )
                .unwrap();
            }
            Self::Ed25519(key) => vera_crypto::actor::ed25519_did(&key.verifying_key().to_bytes()),
            Self::P256(key) => {
                vera_crypto::actor::p256_did(key.verifying_key().to_encoded_point(true).as_bytes())
            }
        }
        .unwrap()
    }

    fn sign(&self, claims: &JwtClaims) -> String {
        let alg = match self {
            Self::Secp256k1(_) => "ES256K",
            Self::Ed25519(_) => "EdDSA",
            Self::P256(_) => "ES256",
        };
        let header = format!(r#"{{"alg":"{alg}","typ":"vera-delegation-v1+jwt"}}"#);
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        let signature = match self {
            Self::Secp256k1(key) => {
                let signature: k256::ecdsa::Signature = key.sign(input.as_bytes());
                signature.normalize_s().unwrap_or(signature).to_vec()
            }
            Self::Ed25519(key) => key.sign(input.as_bytes()).to_bytes().to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
                signature.normalize_s().unwrap_or(signature).to_vec()
            }
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn claims(&self, worker: &TxExecCtx, entropy: u8, token_hash: &str) -> JwtClaims {
        let revocation = DelegatedOperation::RevokeToken(token_hash);
        JwtClaims {
            iss: self.did(),
            sub: worker.signer.clone(),
            exp: 200,
            aud: "vera:9001".into(),
            scope: revocation.scope(),
            iat: 90,
            nbf: 90,
            relay: None,
            request: Some(OperationClaim {
                id: id(entropy),
                digest: revocation.digest().unwrap(),
                genesis_id: [7; 32],
            }),
        }
    }

    fn operation(&self, worker: &TxExecCtx, entropy: u8, token_hash: &str) -> String {
        self.sign(&self.claims(worker, entropy, token_hash))
    }
}

fn id(entropy: u8) -> OperationId {
    OperationId::new(200, [entropy; 24])
}

fn worker(seed: u8) -> TxExecCtx {
    TxExecCtx {
        signer: Actor::Secp256k1(k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()).did(),
        tx_hash: vec![seed; 32],
        sequence: 0,
    }
}

const fn context(now: u64) -> BlockExecCtx {
    BlockExecCtx {
        genesis_id: [7; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: now,
            block_height: now,
        },
    }
}

/// A module holding one valid token `actor` issued to an account that is not the worker.
fn issued_by(actor: &Actor) -> (VeraModule, AcpModule, String) {
    let mut vera = VeraModule::new();
    vera.store_or_update_jws_token(
        &context(95),
        TOKEN,
        &actor.did().parse().unwrap(),
        "did:key:z6MkAccount",
        Timestamp::default(),
        Timestamp {
            seconds: 1_000,
            block_height: 0,
        },
    )
    .unwrap();
    (vera, AcpModule::new(), keys::hash_jws_token(TOKEN))
}

fn snapshot(vera: &VeraModule, acp: &AcpModule) -> (Vec<u8>, Vec<u8>) {
    (vera.store().serialize(), acp.store().serialize())
}

#[test]
fn an_issuer_of_each_key_type_revokes_through_a_worker() {
    for actor in Actor::all() {
        let (mut vera, mut acp, hash) = issued_by(&actor);
        let worker = worker(7);
        let record = vera
            .invalidate_jws_by_issuer(
                &mut acp,
                &context(100),
                &worker,
                &actor.operation(&worker, 1, &hash),
                &hash,
            )
            .unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert_eq!(record.invalidated_by, actor.did());
        assert_eq!(record.issuer_did, actor.did());
        assert_eq!(vera.get_jws_token(&hash).unwrap().unwrap(), record);
        let outcome = acp.operation(&actor.did(), id(1)).unwrap().unwrap();
        assert_eq!(outcome.worker, worker.signer);
        assert_eq!(outcome.actor, actor.did());
    }
}

#[test]
fn a_replayed_identity_returns_the_original_record_without_applying_again() {
    let actor = Actor::Secp256k1(k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap());
    let (mut vera, mut acp, hash) = issued_by(&actor);
    let (first, second) = (worker(7), worker(8));
    let original = vera
        .invalidate_jws_by_issuer(
            &mut acp,
            &context(100),
            &first,
            &actor.operation(&first, 1, &hash),
            &hash,
        )
        .unwrap();
    let retry = actor.operation(&second, 1, &hash);
    vera.invalidate_jws_by_issuer(&mut acp, &context(110), &second, &retry, &hash)
        .unwrap();
    let before = snapshot(&vera, &acp);
    let replayed = vera
        .invalidate_jws_by_issuer(&mut acp, &context(120), &second, &retry, &hash)
        .unwrap();
    assert_eq!(replayed, original);
    assert_eq!(snapshot(&vera, &acp), before);
    let stored = vera.get_jws_token(&hash).unwrap().unwrap();
    assert_eq!(stored.invalidated_at, original.invalidated_at);

    let other = keys::hash_jws_token("another-token");
    let reused = vera.invalidate_jws_by_issuer(
        &mut acp,
        &context(120),
        &second,
        &actor.operation(&second, 1, &other),
        &other,
    );
    assert!(matches!(reused, Err(VeraError::InvalidJws { .. })));
    assert_eq!(snapshot(&vera, &acp), before);

    let fresh = vera.invalidate_jws_by_issuer(
        &mut acp,
        &context(120),
        &second,
        &actor.operation(&second, 2, &hash),
        &hash,
    );
    assert!(matches!(
        fresh,
        Err(VeraError::TokenAlreadyInvalidated { .. })
    ));
    assert_eq!(snapshot(&vera, &acp), before);
}

#[test]
fn another_actors_signature_is_refused() {
    let [actor, ..] = Actor::all();
    let (mut vera, mut acp, hash) = issued_by(&actor);
    let worker = worker(7);
    let before = snapshot(&vera, &acp);
    let result = vera.invalidate_jws_by_issuer(
        &mut acp,
        &context(100),
        &worker,
        &Actor::other().operation(&worker, 1, &hash),
        &hash,
    );
    assert!(matches!(result, Err(VeraError::Unauthorized { .. })));
    assert_eq!(snapshot(&vera, &acp), before);

    let mut forged = actor.operation(&worker, 1, &hash);
    let last = forged.pop().unwrap();
    forged.push(if last == 'A' { 'B' } else { 'A' });
    let result = vera.invalidate_jws_by_issuer(&mut acp, &context(100), &worker, &forged, &hash);
    assert!(matches!(result, Err(VeraError::InvalidJws { .. })));
    assert_eq!(snapshot(&vera, &acp), before);
}

#[test]
fn an_operation_bound_elsewhere_is_refused() {
    let [actor, ..] = Actor::all();
    let (mut vera, mut acp, hash) = issued_by(&actor);
    let worker = worker(7);
    let before = snapshot(&vera, &acp);
    let mut cases = Vec::new();
    for case in 0..5 {
        let mut claims = actor.claims(&worker, 1, &hash);
        match case {
            0 => claims.aud = "vera:9002".into(),
            1 => claims.request.as_mut().unwrap().genesis_id = [8; 32],
            2 => claims.request.as_mut().unwrap().digest = [0; 32],
            3 => claims.scope = DelegationScope::PolicyCommands,
            _ => claims.request = None,
        }
        cases.push(actor.sign(&claims));
    }
    for operation in &cases {
        let result =
            vera.invalidate_jws_by_issuer(&mut acp, &context(100), &worker, operation, &hash);
        assert!(
            matches!(result, Err(VeraError::InvalidJws { .. })),
            "{result:?}"
        );
    }
    let operation = actor.operation(&worker, 1, &hash);
    let result =
        vera.invalidate_jws_by_issuer(&mut acp, &context(100), &self::worker(8), &operation, &hash);
    assert!(matches!(result, Err(VeraError::InvalidJws { .. })));
    assert_eq!(snapshot(&vera, &acp), before);
}

#[test]
fn a_missing_token_is_not_found() {
    let [actor, ..] = Actor::all();
    let (mut vera, mut acp, _) = issued_by(&actor);
    let worker = worker(7);
    let missing = keys::hash_jws_token("never-used");
    let result = vera.invalidate_jws_by_issuer(
        &mut acp,
        &context(100),
        &worker,
        &actor.operation(&worker, 1, &missing),
        &missing,
    );
    assert!(matches!(result, Err(VeraError::TokenNotFound { .. })));
}
