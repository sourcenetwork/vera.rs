//! Quorum authorization, replay and rotation invariants.

use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use vera_modules::{
    acp::{AcpModule, types::AcpParams},
    kv_store::InMemoryKvStore,
    types::Duration,
    vera::{VeraModule, administration::*},
};

const GENESIS: [u8; 32] = [7; 32];

fn operators() -> (OperatorPolicy, Vec<SigningKey>) {
    let mut keys: Vec<_> = (1..=3)
        .map(|byte| SigningKey::from_bytes(&[byte; 32].into()).unwrap())
        .collect();
    keys.sort_by_key(|key| key.verifying_key().to_sec1_bytes().to_vec());
    let policy = OperatorPolicy {
        threshold: 2,
        keys: keys
            .iter()
            .map(|key| hex::encode(key.verifying_key().to_sec1_bytes()))
            .collect(),
    };
    (policy, keys)
}

const fn request(sequence: u64) -> AdministrativeRequest {
    AdministrativeRequest {
        genesis_id: GENESIS,
        sequence,
        expires_at: 100,
        command: AdministrativeCommand::SetAcpParameters(AcpParams {
            registrations_commitment_validity: Duration::Blocks(12),
        }),
    }
}

fn approve(request: AdministrativeRequest, keys: &[SigningKey]) -> SignedAdministrativeRequest {
    let digest = request.signing_digest().unwrap();
    let approvals = keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(index, key)| {
            let signature: Signature = key.sign_prehash(&digest).unwrap();
            OperatorApproval {
                signer: index as u16,
                signature: hex::encode(signature.to_bytes()),
            }
        })
        .collect();
    SignedAdministrativeRequest { request, approvals }
}

#[test]
fn quorum_changes_parameters_once_and_survives_serialization() {
    let (policy, keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    let signed = approve(request(0), &keys);
    assert!(
        vera.apply_administrative_request(&mut acp, GENESIS, 100, &signed)
            .is_err()
    );
    vera.initialize_administration(policy.clone()).unwrap();
    assert!(vera.initialize_administration(policy).is_err());
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &signed)
        .unwrap();
    assert_eq!(
        acp.query_params()
            .unwrap()
            .registrations_commitment_validity,
        Duration::Blocks(12)
    );
    assert_eq!(vera.administration().unwrap().unwrap().sequence, 1);
    let bytes = vera.store().serialize();
    let mut reopened = VeraModule::from_store(InMemoryKvStore::deserialize(&bytes).unwrap());
    assert!(
        reopened
            .apply_administrative_request(&mut acp, GENESIS, 100, &signed)
            .is_err()
    );
    assert_eq!(reopened.store().serialize(), bytes);
}

#[test]
fn outcome_budget_requires_operator_approval_and_survives_reopen() {
    let (policy, keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    vera.initialize_administration(policy).unwrap();
    let mut change = request(0);
    change.command = AdministrativeCommand::SetOperationBudget(128 << 20);
    let approved = approve(change, &keys);
    let mut unauthorized = approved.clone();
    unauthorized.approvals.pop();
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        vera.apply_administrative_request(&mut acp, GENESIS, 100, &unauthorized)
            .is_err()
    );
    assert_eq!(before, (vera.store().serialize(), acp.store().serialize()));
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &approved)
        .unwrap();
    assert_eq!(acp.operation_budget().unwrap(), 128 << 20);
    let mut acp =
        AcpModule::from_store(InMemoryKvStore::deserialize(&acp.store().serialize()).unwrap());
    assert_eq!(acp.operation_budget().unwrap(), 128 << 20);
    let before = (vera.store().serialize(), acp.store().serialize());
    let mut invalid = request(1);
    invalid.command = AdministrativeCommand::SetOperationBudget(0);
    assert!(
        vera.apply_administrative_request(&mut acp, GENESIS, 100, &approve(invalid, &keys))
            .is_err()
    );
    assert_eq!(before, (vera.store().serialize(), acp.store().serialize()));
}

#[test]
fn rejected_approvals_leave_both_stores_unchanged() {
    let (policy, keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    vera.initialize_administration(policy).unwrap();
    let signed = approve(request(0), &keys);
    let mut cases = Vec::new();
    let mut invalid = signed.clone();
    invalid.approvals.pop();
    cases.push(invalid);
    let mut invalid = signed.clone();
    invalid.approvals[1] = invalid.approvals[0].clone();
    cases.push(invalid);
    let mut invalid = signed.clone();
    invalid.approvals[1].signer = 9;
    cases.push(invalid);
    let mut invalid = signed.clone();
    invalid.approvals[1].signature = invalid.approvals[0].signature.clone();
    cases.push(invalid);
    let mut invalid = signed.clone();
    invalid.approvals[0].signature = invalid.approvals[0].signature.to_uppercase();
    cases.push(invalid);
    let mut invalid = signed.clone();
    invalid.request.expires_at += 1;
    cases.push(invalid);
    let mut invalid = signed;
    invalid.request.command = AdministrativeCommand::SetAcpParameters(AcpParams::default());
    cases.push(invalid);
    let mut invalid = request(0);
    invalid.genesis_id = [8; 32];
    cases.push(approve(invalid, &keys));
    cases.push(approve(request(1), &keys));
    let mut invalid = request(0);
    invalid.expires_at = 99;
    cases.push(approve(invalid, &keys));
    let before = (vera.store().serialize(), acp.store().serialize());
    for invalid in cases {
        assert!(
            vera.apply_administrative_request(&mut acp, GENESIS, 100, &invalid)
                .is_err()
        );
        assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    }
}

#[test]
fn rotation_requires_existing_quorum_and_revokes_old_keys() {
    let (policy, old_keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    vera.initialize_administration(policy).unwrap();
    let next = SigningKey::from_bytes(&[9; 32].into()).unwrap();
    let mut rotation = request(0);
    rotation.command = AdministrativeCommand::RotateOperators(OperatorPolicy {
        threshold: 1,
        keys: vec![hex::encode(next.verifying_key().to_sec1_bytes())],
    });
    let unauthorized = approve(rotation.clone(), std::slice::from_ref(&next));
    assert!(
        vera.apply_administrative_request(&mut acp, GENESIS, 100, &unauthorized)
            .is_err()
    );
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &approve(rotation, &old_keys))
        .unwrap();
    let old_approval = approve(request(1), &old_keys[..1]);
    assert!(
        vera.apply_administrative_request(&mut acp, GENESIS, 100, &old_approval)
            .is_err()
    );
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &approve(request(1), &[next]))
        .unwrap();
    assert_eq!(vera.administration().unwrap().unwrap().sequence, 2);
}

#[test]
fn invalid_rotation_does_not_consume_sequence() {
    let (mut policy, keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    vera.initialize_administration(policy.clone()).unwrap();
    policy.keys[1] = policy.keys[0].clone();
    let mut invalid = request(0);
    invalid.command = AdministrativeCommand::RotateOperators(policy);
    let before = vera.store().serialize();
    assert!(
        vera.apply_administrative_request(&mut acp, GENESIS, 100, &approve(invalid, &keys))
            .is_err()
    );
    assert_eq!(vera.store().serialize(), before);
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &approve(request(0), &keys))
        .unwrap();
}

#[test]
fn invalid_operator_policies_cannot_initialize_authority() {
    let (policy, _) = operators();
    let mut invalid = Vec::new();
    let mut candidate = policy.clone();
    candidate.threshold = 0;
    invalid.push(candidate);
    let mut candidate = policy.clone();
    candidate.threshold = 4;
    invalid.push(candidate);
    let mut candidate = policy.clone();
    candidate.keys[1] = candidate.keys[0].clone();
    invalid.push(candidate);
    let mut candidate = policy.clone();
    candidate.keys.reverse();
    invalid.push(candidate);
    let mut candidate = policy.clone();
    candidate.keys[0] = candidate.keys[0].to_uppercase();
    invalid.push(candidate);
    let mut candidate = policy.clone();
    candidate.keys[0] = "00".repeat(33);
    invalid.push(candidate);
    let mut candidate = policy;
    candidate.keys[0].pop();
    invalid.push(candidate);
    let mut keys: Vec<_> = (1..=129)
        .map(|byte| {
            hex::encode(
                SigningKey::from_bytes(&[byte; 32].into())
                    .unwrap()
                    .verifying_key()
                    .to_sec1_bytes(),
            )
        })
        .collect();
    keys.sort();
    invalid.push(OperatorPolicy { threshold: 1, keys });
    for policy in invalid {
        let mut vera = VeraModule::new();
        assert!(vera.initialize_administration(policy).is_err());
        assert!(vera.store().is_empty());
    }
}

#[test]
fn exhausted_sequence_cannot_change_parameters() {
    let (policy, keys) = operators();
    let state = AdministrationState {
        policy,
        sequence: u64::MAX,
        membership_policy: None,
    };
    let store =
        InMemoryKvStore::from_pairs(vec![(b"admin/v1".to_vec(), borsh::to_vec(&state).unwrap())]);
    let mut vera = VeraModule::from_store(store);
    let mut acp = AcpModule::new();
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        vera.apply_administrative_request(
            &mut acp,
            GENESIS,
            100,
            &approve(request(u64::MAX), &keys)
        )
        .is_err()
    );
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
}
