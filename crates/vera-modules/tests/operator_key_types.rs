//! Operator policies that mix secp256k1, Ed25519 and P-256 keys.

use ed25519_dalek::Signer as _;
use k256::ecdsa::signature::hazmat::PrehashSigner as _;
use vera_modules::{
    acp::{AcpModule, types::AcpParams},
    types::Duration,
    vera::{VeraModule, administration::*},
};

const GENESIS: [u8; 32] = [7; 32];

enum Operator {
    Secp256k1(k256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Operator {
    fn entry(&self) -> String {
        match self {
            Self::Secp256k1(key) => hex::encode(key.verifying_key().to_sec1_bytes()),
            Self::Ed25519(key) => {
                vera_crypto::actor::ed25519_did(&key.verifying_key().to_bytes()).unwrap()
            }
            Self::P256(key) => {
                vera_crypto::actor::p256_did(key.verifying_key().to_encoded_point(true).as_bytes())
                    .unwrap()
            }
        }
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        match self {
            Self::Secp256k1(key) => {
                let signature: k256::ecdsa::Signature = key.sign_prehash(digest).unwrap();
                signature.normalize_s().unwrap_or(signature).to_vec()
            }
            Self::Ed25519(key) => key.sign(digest).to_bytes().to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign_prehash(digest).unwrap();
                signature.normalize_s().unwrap_or(signature).to_vec()
            }
        }
    }
}

/// An account key and two device keys, any two of which approve a change.
fn operators() -> (OperatorPolicy, Vec<Operator>) {
    let mut operators = vec![
        Operator::Secp256k1(k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap()),
        Operator::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[2; 32])),
        Operator::P256(p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap()),
    ];
    operators.sort_by_key(Operator::entry);
    let policy = OperatorPolicy {
        threshold: 2,
        keys: operators.iter().map(Operator::entry).collect(),
    };
    (policy, operators)
}

const fn request(sequence: u64) -> AdministrativeRequest {
    AdministrativeRequest {
        genesis_id: GENESIS,
        sequence,
        expires_at: 100,
        command: AdministrativeCommand::SetAcpParameters(AcpParams {
            policy_command_max_expiration_delta: 90,
            registrations_commitment_validity: Duration::Blocks(12),
        }),
    }
}

fn approve(
    request: AdministrativeRequest,
    operators: &[Operator],
    signers: &[usize],
) -> SignedAdministrativeRequest {
    let digest = request.signing_digest().unwrap();
    let approvals = signers
        .iter()
        .map(|&index| OperatorApproval {
            signer: index as u16,
            signature: hex::encode(operators[index].sign(&digest)),
        })
        .collect();
    SignedAdministrativeRequest { request, approvals }
}

fn deployment(policy: OperatorPolicy) -> (VeraModule, AcpModule) {
    let mut vera = VeraModule::new();
    vera.initialize_administration(policy).unwrap();
    (vera, AcpModule::new())
}

#[test]
fn any_two_operators_of_any_key_type_approve_a_change() {
    let (policy, operators) = operators();
    for (sequence, signers) in [[0, 1], [0, 2], [1, 2]].into_iter().enumerate() {
        let (mut vera, mut acp) = deployment(policy.clone());
        let signed = approve(request(0), &operators, &signers);
        vera.apply_administrative_request(&mut acp, GENESIS, 50, &signed)
            .unwrap_or_else(|error| panic!("signers {signers:?} ({sequence}): {error}"));
        assert_eq!(vera.administration().unwrap().unwrap().sequence, 1);
    }
}

#[test]
fn one_operator_alone_approves_nothing() {
    let (policy, operators) = operators();
    for signer in 0..operators.len() {
        let (mut vera, mut acp) = deployment(policy.clone());
        let before = (vera.store().serialize(), acp.store().serialize());
        let signed = approve(request(0), &operators, &[signer]);
        assert!(
            vera.apply_administrative_request(&mut acp, GENESIS, 50, &signed)
                .is_err()
        );
        assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    }
}

#[test]
fn a_signature_by_another_key_or_in_another_encoding_is_rejected() {
    let (policy, operators) = operators();
    let digest = request(0).signing_digest().unwrap();
    for (index, operator) in operators.iter().enumerate() {
        let approval = |signature: Vec<u8>| OperatorApproval {
            signer: index as u16,
            signature: hex::encode(signature),
        };
        policy
            .verify_approval(&digest, &approval(operator.sign(&digest)))
            .unwrap();
        let other = &operators[(index + 1) % operators.len()];
        assert!(
            policy
                .verify_approval(&digest, &approval(other.sign(&digest)))
                .is_err()
        );
        assert!(
            policy
                .verify_approval(&[9; 32], &approval(operator.sign(&digest)))
                .is_err()
        );
        if let Operator::P256(key) = operator {
            let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
            let low = signature.normalize_s().unwrap_or(signature);
            let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
            assert!(
                policy
                    .verify_approval(&digest, &approval(high.to_vec()))
                    .is_err()
            );
        }
    }
}

#[test]
fn a_key_has_exactly_one_entry_form() {
    let (policy, operators) = operators();
    policy.validate().unwrap();
    let secp256k1 = operators
        .iter()
        .find_map(|operator| match operator {
            Operator::Secp256k1(key) => Some(key.verifying_key().to_sec1_bytes()),
            _ => None,
        })
        .unwrap();
    let as_did = vera_crypto::secp256k1::did_from_secp256k1_pubkey(&secp256k1).unwrap();
    for invalid in [
        as_did.as_str(),
        "did:key:z6Mk",
        "did:key:zNotAKey",
        "did:opk:0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        let mut keys = policy.keys.clone();
        keys.push(invalid.to_owned());
        keys.sort();
        let policy = OperatorPolicy { threshold: 2, keys };
        assert!(policy.validate().is_err(), "accepted {invalid}");
    }
    let mut duplicated = policy.clone();
    duplicated.keys.push(policy.keys[2].clone());
    assert!(duplicated.validate().is_err());
    let mut unsorted = policy;
    unsorted.keys.swap(1, 2);
    assert!(unsorted.validate().is_err());
}

#[test]
fn a_secp256k1_key_cannot_be_listed_again_in_compact_form() {
    let compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    // SEC1 compact form of the same even-y point; one holder would otherwise give both approvals.
    let compact = format!("05{}", &compressed[2..]);
    let policy = OperatorPolicy {
        threshold: 2,
        keys: vec![compressed.to_owned(), compact],
    };
    assert!(policy.validate().is_err());
}

#[test]
fn rotation_installs_and_then_requires_the_new_key_types() {
    let secp256k1: Vec<_> = (1..=2u8)
        .map(|byte| Operator::Secp256k1(k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap()))
        .collect();
    let mut old = secp256k1;
    old.sort_by_key(Operator::entry);
    let (mut vera, mut acp) = deployment(OperatorPolicy {
        threshold: 2,
        keys: old.iter().map(Operator::entry).collect(),
    });
    let (policy, new) = operators();
    let rotate = AdministrativeRequest {
        command: AdministrativeCommand::RotateOperators(policy.clone()),
        ..request(0)
    };
    vera.apply_administrative_request(&mut acp, GENESIS, 50, &approve(rotate, &old, &[0, 1]))
        .unwrap();
    assert_eq!(vera.administration().unwrap().unwrap().policy, policy);
    assert!(
        vera.apply_administrative_request(
            &mut acp,
            GENESIS,
            50,
            &approve(request(1), &old, &[0, 1])
        )
        .is_err()
    );
    vera.apply_administrative_request(&mut acp, GENESIS, 50, &approve(request(1), &new, &[1, 2]))
        .unwrap();
}
