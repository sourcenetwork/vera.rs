//! Delegated operations issued by Ed25519 and P-256 actors.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Signer as _;
use vera_crypto::{jwt::JwtClaims, operation::OperationClaim};
use vera_identity::Did;

use super::{FORMAT, POLICY, context, id, submission};
use crate::{
    acp::{AcpModule, delegated_operation::DelegatedOperation},
    types::TxExecCtx,
    vera::VeraModule,
};

enum Actor {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Actor {
    fn all() -> [Self; 2] {
        [
            Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[42; 32])),
            Self::P256(p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap()),
        ]
    }

    fn did(&self) -> String {
        match self {
            Self::Ed25519(key) => vera_crypto::actor::ed25519_did(&key.verifying_key().to_bytes()),
            Self::P256(key) => {
                vera_crypto::actor::p256_did(key.verifying_key().to_encoded_point(true).as_bytes())
            }
        }
        .unwrap()
    }

    fn sign(&self, claims: &JwtClaims) -> String {
        let alg = match self {
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
            Self::Ed25519(key) => key.sign(input.as_bytes()).to_bytes().to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
                signature.normalize_s().unwrap_or(signature).to_vec()
            }
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn token(&self, worker: &TxExecCtx, entropy: u8, operation: &DelegatedOperation<'_>) -> String {
        self.sign(&JwtClaims {
            iss: self.did(),
            sub: worker.signer.clone(),
            exp: 200,
            aud: "vera:9001".into(),
            scope: operation.scope(),
            iat: 90,
            nbf: 90,
            relay: None,
            request: Some(OperationClaim {
                id: id(entropy, 200),
                digest: operation.digest().unwrap(),
                genesis_id: [7; 32],
            }),
        })
    }
}

#[test]
fn ed25519_and_p256_actors_own_what_their_workers_create() {
    let create = DelegatedOperation::CreatePolicy(POLICY, &FORMAT);
    for actor in Actor::all() {
        let mut acp = AcpModule::new();
        let mut vera = VeraModule::new();
        let (first, second) = (submission(7), submission(8));
        let created = acp
            .bearer_create_policy(
                &mut vera,
                &context(100),
                &first,
                &actor.token(&first, 1, &create),
                POLICY,
                FORMAT,
            )
            .unwrap();
        assert_eq!(created.metadata.owner_did, actor.did());
        assert_eq!(created.metadata.tx_signer, first.signer);

        let outcome = acp.operation(&actor.did(), id(1, 200)).unwrap().unwrap();
        assert_eq!(outcome.actor, actor.did());
        assert_eq!(outcome.worker, first.signer);

        let before = acp.store().serialize();
        let repeated = acp
            .bearer_create_policy(
                &mut vera,
                &context(101),
                &second,
                &actor.token(&second, 1, &create),
                POLICY,
                FORMAT,
            )
            .unwrap();
        assert_eq!(repeated.policy.id, created.policy.id);
        assert_eq!(acp.store().serialize(), before);
    }
}

#[test]
fn actors_of_different_key_types_keep_separate_operation_outcomes() {
    let [ed25519, p256] = Actor::all();
    let create = DelegatedOperation::CreatePolicy(POLICY, &FORMAT);
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let worker = submission(7);
    let mut policies = Vec::new();
    for actor in [&ed25519, &p256] {
        let created = acp
            .bearer_create_policy(
                &mut vera,
                &context(100),
                &worker,
                &actor.token(&worker, 1, &create),
                POLICY,
                FORMAT,
            )
            .unwrap();
        policies.push((created.policy.id, created.metadata.owner_did));
    }
    assert_ne!(policies[0], policies[1]);
    assert_ne!(
        super::operation_key(&ed25519.did(), id(1, 200)).unwrap(),
        super::operation_key(&p256.did(), id(1, 200)).unwrap()
    );
}

#[test]
fn a_worker_revokes_a_delegation_from_an_ed25519_or_p256_actor() {
    let create = DelegatedOperation::CreatePolicy(POLICY, &FORMAT);
    for actor in Actor::all() {
        let mut acp = AcpModule::new();
        let mut vera = VeraModule::new();
        let worker = submission(7);
        let token = actor.token(&worker, 1, &create);
        let record = vera
            .revoke_delegation(&context(100), &Did::new(&worker.signer).unwrap(), &token)
            .unwrap();
        assert_eq!(record.issuer_did, actor.did());
        assert!(
            acp.bearer_create_policy(&mut vera, &context(100), &worker, &token, POLICY, FORMAT)
                .is_err()
        );
    }
}
