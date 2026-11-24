//! Membership commands through native requests: commitment, rollback,
//! faults of stored state, epoch rosters and consensus-key address updates.

use super::{
    native_call::{execute_native, member_did, member_request, try_execute_native},
    *,
};
use alloy_sol_types::SolCall;
use ed25519_dalek::Signer as _;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use vera_executor::{ModuleState, VeraExecutor, dispatch::VALIDATOR_REGISTRY_ADDRESS};
use vera_modules::{
    acp::types::{Object, PolicyCmd, PolicyMarshalingType},
    kv_store::ModuleKvStore as _,
    validator_registry::{abi::IValidatorRegistry, address_update_digest},
    vera::{VeraModule, administration::*},
};

const GENESIS: [u8; 32] = [7; 32];

fn consensus(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

const fn member(seed: u8) -> Address {
    Address::repeat_byte(seed)
}

/// An executor whose membership policy lets the member key manage the registry.
fn authorized() -> VeraExecutor {
    let did = member_did();
    let mut modules = ModuleState::default();
    let policy = modules.acp.create_policy(&did,
        "name: membership\nresources:\n  - name: registry\n    relations:\n      - name: admin\n    permissions:\n      - name: manage\n        expr: admin\n",
        PolicyMarshalingType::ShortYaml, Default::default(),
    ).unwrap().policy.id;
    for command in [
        PolicyCmd::RegisterObject(Object {
            resource: "registry".into(),
            id: "registry".into(),
        }),
        PolicyCmd::SetRelationship(vera_acp::Relationship::new(
            "registry",
            "registry",
            "admin",
            vera_acp::Subject::entity(did.clone()),
        )),
    ] {
        modules
            .acp
            .direct_policy_cmd(&did, &policy, command)
            .unwrap();
    }
    let operator = SigningKey::from_bytes(&[9; 32].into()).unwrap();
    modules
        .vera
        .initialize_administration(OperatorPolicy {
            threshold: 1,
            keys: vec![hex::encode(operator.verifying_key().to_sec1_bytes())],
        })
        .unwrap();
    let request = AdministrativeRequest {
        genesis_id: GENESIS,
        sequence: 0,
        expires_at: 100,
        command: AdministrativeCommand::InitializeMembershipPolicy(
            hex::decode(&policy).unwrap().try_into().unwrap(),
        ),
    };
    let signature: Signature = operator
        .sign_prehash(&request.signing_digest().unwrap())
        .unwrap();
    modules
        .vera
        .apply_administrative_request(
            &mut modules.acp,
            GENESIS,
            100,
            &SignedAdministrativeRequest {
                request,
                approvals: vec![OperatorApproval {
                    signer: 0,
                    signature: hex::encode(signature.to_bytes()),
                }],
            },
        )
        .unwrap();
    let executor = VeraExecutor::new(9001).with_genesis_id(GENESIS);
    executor.set_base_modules(modules);
    executor
}

fn add(seed: u8) -> Vec<u8> {
    IValidatorRegistry::addValidatorCall {
        validator: member(seed),
        consensusPubkey: consensus(seed).verifying_key().to_bytes().into(),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode()
}

fn status(seed: u8, active: bool) -> Vec<u8> {
    IValidatorRegistry::setValidatorStatusCall {
        validator: member(seed),
        active,
    }
    .abi_encode()
}

fn run(executor: &VeraExecutor, calldata: Vec<u8>) -> bool {
    let (outcome, _) = execute_native(VALIDATOR_REGISTRY_ADDRESS, calldata, executor.clone());
    outcome.receipts[0].success()
}

fn members(executor: &VeraExecutor) -> Vec<Address> {
    executor
        .modules()
        .read()
        .unwrap()
        .vera
        .registry_members()
        .unwrap()
        .into_iter()
        .map(|(address, _)| address)
        .collect()
}

#[test]
fn the_last_active_member_cannot_be_removed_or_deactivated() {
    let executor = authorized();
    assert!(run(&executor, add(0x11)));
    let remove = IValidatorRegistry::removeValidatorCall {
        validator: member(0x11),
    }
    .abi_encode();
    assert!(!run(&executor, remove));
    assert!(!run(&executor, status(0x11, false)));
    assert_eq!(members(&executor), [member(0x11)]);
}

#[test]
fn membership_changes_stay_on_their_branch_until_published() {
    let executor = authorized();
    let parent = executor.snapshot();
    let context = BlockContext::new(1, 0, 30_000_000);
    let requests = [
        member_request(VALIDATOR_REGISTRY_ADDRESS, 0, add(0x11)),
        member_request(VALIDATOR_REGISTRY_ADDRESS, 1, add(0x22)),
        member_request(VALIDATOR_REGISTRY_ADDRESS, 2, add(0x11)),
    ];
    let (outcome, branch) = executor
        .execute_with_modules(&context, &requests, parent.clone())
        .unwrap();
    assert_eq!(
        outcome
            .receipts
            .iter()
            .map(|receipt| receipt.success())
            .collect::<Vec<_>>(),
        [true, true, false]
    );
    assert!(members(&executor).is_empty());
    let (replayed, verified) = executor
        .execute_with_modules(&context.with_verification(), &requests, parent)
        .unwrap();
    assert_eq!(replayed.receipts.len(), 3);
    assert!(
        verified
            .changes_from(&branch)
            .iter()
            .all(|changes| changes.is_empty())
    );
    executor.publish_snapshot(branch);
    assert_eq!(members(&executor), [member(0x11), member(0x22)]);
}

#[test]
fn a_signer_without_the_manage_permission_changes_nothing() {
    let executor = VeraExecutor::new(9001).with_genesis_id(GENESIS);
    assert!(!run(&executor, add(0x11)));
    assert!(members(&executor).is_empty());
}

#[rstest]
#[case(false)]
#[case(true)]
fn a_member_record_that_does_not_read_back_fails_the_block(#[case] verification: bool) {
    let executor = authorized();
    assert!(run(&executor, add(0x11)));
    let mut modules = executor.modules().read().unwrap().clone();
    let mut store = modules.vera.store().clone();
    let (key, _) = store
        .prefix_scan(b"registry/member/")
        .into_iter()
        .next()
        .unwrap();
    store.put(&key, vec![0xff]);
    modules.vera = VeraModule::from_store(store);
    executor.set_base_modules(modules);

    let mut context = BlockContext::new(2, 0, 30_000_000);
    context.is_verification = verification;
    for calldata in [
        add(0x22),
        IValidatorRegistry::getValidatorsCall {}.abi_encode(),
    ] {
        let request = member_request(VALIDATOR_REGISTRY_ADDRESS, 1, calldata);
        assert!(matches!(
            executor.execute_with_modules(&context, &[request], executor.snapshot()),
            Err(vera_executor::ExecutionError::TxExecution(_))
        ));
    }

    let boundary = executor.with_membership_epochs(
        std::num::NonZeroU64::new(10).unwrap(),
        std::num::NonZeroU64::new(2).unwrap(),
    );
    assert!(matches!(
        boundary.execute_with_modules(
            &BlockContext::new(9, 0, 30_000_000).with_verification(),
            &[],
            boundary.snapshot()
        ),
        Err(vera_executor::ExecutionError::TxExecution(_))
    ));
}

#[test]
fn an_epoch_boundary_records_the_active_members_of_its_own_branch() {
    use std::num::NonZeroU64;
    let executor = authorized()
        .with_membership_epochs(NonZeroU64::new(10).unwrap(), NonZeroU64::new(1).unwrap());
    for seed in [0x11, 0x22, 0x33] {
        assert!(run(&executor, add(seed)));
    }
    assert!(run(&executor, status(0x22, false)));

    let boundary = BlockContext::new(9, 0, 30_000_000);
    let late = member_request(VALIDATOR_REGISTRY_ADDRESS, 4, status(0x33, false));
    let (_, with_change) = executor
        .execute_with_modules(&boundary, &[late], executor.snapshot())
        .unwrap();
    let (_, without) = executor
        .execute_with_modules(&boundary, &[], executor.snapshot())
        .unwrap();
    let roster = |snapshot: &vera_executor::ModuleSnapshot, epoch| {
        let parent = vera_executor::ModuleSnapshot::clone(snapshot);
        executor.publish_snapshot(parent);
        executor
            .modules()
            .read()
            .unwrap()
            .vera
            .consensus_roster(epoch)
            .map(<[u8]>::to_vec)
    };
    let keys = |seeds: &[u8]| {
        let mut keys: Vec<_> = seeds
            .iter()
            .map(|seed| consensus(*seed).verifying_key().to_bytes())
            .collect();
        keys.sort_unstable();
        keys.concat()
    };
    assert_eq!(roster(&with_change, 3), Some(keys(&[0x11])));
    assert_eq!(roster(&without, 3), Some(keys(&[0x11, 0x33])));
    assert_eq!(roster(&without, 2), None);
}

#[test]
fn an_epochs_capacity_bounds_additions_and_reactivation() {
    use std::num::NonZeroU64;
    // Ten views of two-view terms give five leader terms: at most five active members.
    let executor = authorized()
        .with_membership_epochs(NonZeroU64::new(10).unwrap(), NonZeroU64::new(2).unwrap());
    let capacity = executor.config().max_active_members() as u8;
    for seed in 1..=capacity {
        assert!(run(&executor, add(seed)), "member {seed}");
    }
    assert!(!run(&executor, add(0x77)));
    assert!(run(&executor, status(1, false)));
    assert!(run(&executor, add(0x77)));
    assert!(!run(&executor, status(1, true)));
    assert_eq!(members(&executor).len(), usize::from(capacity) + 1);
}

fn update(signer: u8, validator: u8, sequence: u64, to: &str) -> Vec<u8> {
    let digest = address_update_digest(&GENESIS, member(validator), sequence, to);
    IValidatorRegistry::updateP2PAddressCall {
        validator: member(validator),
        p2pAddr: to.into(),
        sequence,
        signature: consensus(signer).sign(&digest).to_bytes().to_vec().into(),
    }
    .abi_encode()
}

#[test]
fn a_validator_moves_itself_with_its_consensus_key_through_any_signer() {
    let executor = authorized();
    assert!(run(&executor, add(0x11)));
    assert!(run(&executor, add(0x22)));
    let address = |executor: &VeraExecutor| {
        let modules = executor.modules().read().unwrap();
        let record = modules.vera.registry_member(member(0x11)).unwrap().unwrap();
        (record.p2p_address, record.address_sequence)
    };

    // Another member's key, and a party holding no member key at all.
    assert!(!run(&executor, update(0x22, 0x11, 0, "127.0.0.1:4000")));
    assert!(!run(&executor, update(0x55, 0x11, 0, "127.0.0.1:4000")));
    assert_eq!(address(&executor), ("127.0.0.1:3000".to_owned(), 0));

    let accepted = update(0x11, 0x11, 0, "127.0.0.1:4000");
    let (outcome, _) = execute_native(
        VALIDATOR_REGISTRY_ADDRESS,
        accepted.clone(),
        executor.clone(),
    );
    assert!(outcome.receipts[0].success());
    assert_eq!(outcome.receipts[0].logs.len(), 1);
    assert_eq!(address(&executor), ("127.0.0.1:4000".to_owned(), 1));

    // The same signature does not apply twice, and the next sequence does.
    assert!(!run(&executor, accepted));
    assert!(run(&executor, update(0x11, 0x11, 1, "127.0.0.1:5000")));
    assert_eq!(address(&executor), ("127.0.0.1:5000".to_owned(), 2));

    // A deployment with another genesis record refuses the signature.
    let elsewhere = VeraExecutor::new(9001).with_genesis_id([8; 32]);
    elsewhere.set_base_modules(executor.modules().read().unwrap().clone());
    assert!(!run(&elsewhere, update(0x11, 0x11, 2, "127.0.0.1:6000")));
}

#[test]
fn a_request_that_fails_leaves_the_registry_as_it_was() {
    let executor = authorized();
    assert!(run(&executor, add(0x11)));
    let before = executor.modules().read().unwrap().serialize_stores()[2].clone();
    let result =
        try_execute_native(VALIDATOR_REGISTRY_ADDRESS, vec![1, 2, 3, 4], executor).unwrap();
    assert!(!result.0.receipts[0].success());
    assert_eq!(result.1.serialize_stores()[2], before);
}
