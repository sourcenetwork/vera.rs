use super::{rollback::execute_with_executor, *};
use alloy_primitives::{TxKind, keccak256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use vera_executor::{ModuleState, VeraExecutor, precompiles::VALIDATOR_REGISTRY_ADDRESS};
use vera_modules::{
    acp::types::{Object, PolicyCmd, PolicyMarshalingType},
    validator_registry::abi::IValidatorRegistry,
};

fn authorized_state() -> (MockStateDb, VeraExecutor) {
    let signer: PrivateKeySigner = "42".repeat(32).parse().unwrap();
    let did = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        &signer.credential().verifying_key().to_sec1_bytes(),
    )
    .unwrap()
    .parse::<identity::Did>()
    .unwrap();
    authorized_actor(did)
}

fn authorized_actor(did: identity::Did) -> (MockStateDb, VeraExecutor) {
    let mut modules = ModuleState::default();
    let policy = modules.acp.create_policy(&did,
        "name: membership\nresources:\n  - name: registry\n    relations:\n      - name: admin\n    permissions:\n      - name: manage\n        expr: admin\n",
        PolicyMarshalingType::ShortYaml,
    ).unwrap().policy.id;
    modules
        .acp
        .direct_policy_cmd(
            &did,
            &policy,
            PolicyCmd::RegisterObject(Object {
                resource: "registry".into(),
                id: "registry".into(),
            }),
        )
        .unwrap();
    modules
        .acp
        .direct_policy_cmd(
            &did,
            &policy,
            PolicyCmd::SetRelationship(acp::Relationship::new(
                "registry",
                "registry",
                "admin",
                acp::Subject::entity(did.clone()),
            )),
        )
        .unwrap();
    let state = MockStateDb::new();
    state.insert_account(
        VALIDATOR_REGISTRY_ADDRESS,
        MockAccount {
            storage: HashMap::from([(
                U256::ZERO,
                U256::from_be_slice(&hex::decode(policy).unwrap()),
            )]),
            ..Default::default()
        },
    );
    let executor = VeraExecutor::new(9001);
    executor.set_base_modules(modules);
    (state, executor)
}

fn member_slot(address: Address) -> U256 {
    let mut data = [0; 64];
    data[12..32].copy_from_slice(address.as_slice());
    data[63] = 3;
    U256::from_be_bytes(keccak256(data).0)
}

fn native_member_call(sequence: u64, calldata: Vec<u8>) -> (Bytes, identity::Did) {
    use ark_ec::{AffineRepr as _, CurveGroup as _};
    use ark_serialize::CanonicalSerialize as _;
    let key = ark_bls12_381::Fr::from(7u64);
    let public = (ark_bls12_381::G1Affine::generator() * key).into_affine();
    let mut encoded = Vec::new();
    public.serialize_compressed(&mut encoded).unwrap();
    let mut request = vera_domain::NativeTx {
        chain_id: 9001,
        nonce: sequence,
        bls_pubkey: alloy_primitives::FixedBytes::from_slice(&encoded),
        target: VALIDATOR_REGISTRY_ADDRESS,
        calldata: calldata.into(),
        signature: Default::default(),
    };
    request.signature = alloy_primitives::FixedBytes::from_slice(
        &vera_crypto::bls::sign(&key, &request.signing_data()).unwrap(),
    );
    (
        request.encode_wire().into(),
        vera_crypto::bls::did_from_bls_pubkey(&public)
            .unwrap()
            .parse()
            .unwrap(),
    )
}

fn native_registration() -> Vec<u8> {
    IValidatorRegistry::addValidatorCall {
        evmAddr: Address::repeat_byte(0x11),
        consensusPubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap(),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode()
}

fn backup_member_call(sequence: u64) -> Bytes {
    let mut command =
        IValidatorRegistry::addValidatorCall::abi_decode(&native_registration()).unwrap();
    command.evmAddr = Address::repeat_byte(0x33);
    command.consensusPubkey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        .parse()
        .unwrap();
    native_member_call(sequence, command.abi_encode()).0
}

#[test]
fn native_membership_cannot_remove_or_deactivate_the_last_active_member() {
    let (registration, actor) = native_member_call(0, native_registration());
    let commands = [
        IValidatorRegistry::removeValidatorCall {
            evmAddr: Address::repeat_byte(0x11),
        }
        .abi_encode(),
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: Address::repeat_byte(0x11),
            active: false,
        }
        .abi_encode(),
        IValidatorRegistry::setValidatorStatusByIndexCall {
            index: U256::ZERO,
            active: false,
        }
        .abi_encode(),
    ];
    let mut requests = vec![registration];
    requests.extend(
        commands
            .into_iter()
            .enumerate()
            .map(|(index, command)| native_member_call(index as u64 + 1, command).0),
    );
    let (state, executor) = authorized_actor(actor);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, _) = executor
        .execute_with_modules(&state, &context, &requests, executor.snapshot().unwrap())
        .unwrap();
    assert_eq!(
        outcome
            .receipts
            .iter()
            .map(|r| r.success())
            .collect::<Vec<_>>(),
        [true, false, false, false]
    );
    let storage = &outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage;
    assert_eq!(storage[&U256::from(1)], U256::from(1));
    assert_eq!(
        storage[&member_slot(Address::repeat_byte(0x11))].to_be_bytes::<32>()[20],
        1
    );
}

#[test]
fn native_membership_changes_share_proposal_storage_and_preserve_parent() {
    let (registration, actor) = native_member_call(0, native_registration());
    let (duplicate, _) = native_member_call(2, native_registration());
    let (deactivate, _) = native_member_call(
        3,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: Address::repeat_byte(0x11),
            active: false,
        }
        .abi_encode(),
    );
    let (state, executor) = authorized_actor(actor);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let parent = executor.snapshot().unwrap();
    let (outcome, _) = executor
        .execute_with_modules(
            &state,
            &context,
            &[
                registration.clone(),
                backup_member_call(1),
                duplicate,
                deactivate,
            ],
            parent.clone(),
        )
        .unwrap();
    assert_eq!(
        outcome
            .receipts
            .iter()
            .map(|r| r.success())
            .collect::<Vec<_>>(),
        [true, true, false, true]
    );
    let slots = &outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage;
    assert_eq!(slots[&U256::from(1)], U256::from(2));
    assert_eq!(
        slots[&member_slot(Address::repeat_byte(0x11))].to_be_bytes::<32>()[20],
        0
    );
    assert_eq!(
        state.accounts.read().unwrap()[&VALIDATOR_REGISTRY_ADDRESS]
            .storage
            .len(),
        1
    );
    let (sibling, _) = executor
        .execute_with_modules(&state, &context, &[registration], parent)
        .unwrap();
    assert!(sibling.receipts[0].success());
    assert_eq!(
        sibling.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage
            [&member_slot(Address::repeat_byte(0x11))]
            .to_be_bytes::<32>()[20],
        1
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn native_membership_storage_failure_aborts_the_proposal(#[case] building: bool) {
    let (registration, actor) = native_member_call(0, native_registration());
    let (mut state, executor) = authorized_actor(actor);
    state.unreadable_storage = Some((
        VALIDATOR_REGISTRY_ADDRESS,
        member_slot(Address::repeat_byte(0x11)).wrapping_add(U256::from(2)),
    ));
    let mut context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    context.is_verification = !building;
    let error = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration],
            executor.snapshot().unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        vera_executor::ExecutionError::TxExecution(_)
    ));
    assert_eq!(
        state.accounts.read().unwrap()[&VALIDATOR_REGISTRY_ADDRESS]
            .storage
            .len(),
        1
    );
}

#[test]
fn native_membership_requires_the_configured_actor_permission() {
    let (registration, _) = native_member_call(0, native_registration());
    let (state, executor) = authorized_state();
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, _) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration],
            executor.snapshot().unwrap(),
        )
        .unwrap();
    assert!(!outcome.receipts[0].success());
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.is_empty())
    );
}

#[rstest]
#[case(U256::from(vera_domain::MAX_DKG_PARTICIPANTS.get()), false)]
#[case(U256::from(vera_domain::MAX_DKG_PARTICIPANTS.get() + 1), true)]
#[case(U256::from_limbs([0, 1, 0, 0]), true)]
#[case(U256::MAX, true)]
fn native_membership_bounds_the_full_stored_count(#[case] count: U256, #[case] corrupt: bool) {
    let (request, actor) = native_member_call(0, native_registration());
    let (state, executor) = authorized_actor(actor);
    state
        .accounts
        .write()
        .unwrap()
        .get_mut(&VALIDATOR_REGISTRY_ADDRESS)
        .unwrap()
        .storage
        .insert(U256::from(1), count);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let result =
        executor.execute_with_modules(&state, &context, &[request], executor.snapshot().unwrap());
    if corrupt {
        assert!(matches!(
            result,
            Err(vera_executor::ExecutionError::TxExecution(_))
        ));
    } else {
        let (outcome, _) = result.unwrap();
        assert!(!outcome.receipts[0].success());
        assert!(
            outcome
                .changes
                .accounts
                .get(&VALIDATOR_REGISTRY_ADDRESS)
                .is_none_or(|a| a.storage.is_empty())
        );
    }
}

#[test]
fn native_membership_rejects_reusing_an_inactive_consensus_identity() {
    let (registration, actor) = native_member_call(0, native_registration());
    let (inactive, _) = native_member_call(
        2,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: Address::repeat_byte(0x11),
            active: false,
        }
        .abi_encode(),
    );
    let mut duplicate =
        IValidatorRegistry::addValidatorCall::abi_decode(&native_registration()).unwrap();
    duplicate.evmAddr = Address::repeat_byte(0x22);
    let (duplicate, _) = native_member_call(3, duplicate.abi_encode());
    let (state, executor) = authorized_actor(actor);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, _) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration, backup_member_call(1), inactive, duplicate],
            executor.snapshot().unwrap(),
        )
        .unwrap();
    assert_eq!(
        outcome
            .receipts
            .iter()
            .map(|r| r.success())
            .collect::<Vec<_>>(),
        [true, true, true, false]
    );
    assert_eq!(
        outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage[&U256::from(1)],
        U256::from(2)
    );
}

#[rstest]
#[case(2, U256::from_limbs([0, 1, 0, 0]))]
#[case(3, U256::from(33))]
#[case(3, U256::from_limbs([10, 1, 0, 0]))]
fn native_membership_rejects_truncated_record_fields(#[case] offset: u64, #[case] value: U256) {
    let (registration, actor) = native_member_call(0, native_registration());
    let (state, executor) = authorized_actor(actor);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, parent) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration],
            executor.snapshot().unwrap(),
        )
        .unwrap();
    let mut accounts = state.accounts.write().unwrap();
    let storage = &mut accounts
        .get_mut(&VALIDATOR_REGISTRY_ADDRESS)
        .unwrap()
        .storage;
    storage.extend(
        outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS]
            .storage
            .clone(),
    );
    storage.insert(
        member_slot(Address::repeat_byte(0x11)).wrapping_add(U256::from(offset)),
        value,
    );
    drop(accounts);
    let (request, _) = native_member_call(
        1,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: Address::repeat_byte(0x11),
            active: true,
        }
        .abi_encode(),
    );
    assert!(matches!(
        executor.execute_with_modules(&state, &context, &[request], parent),
        Err(vera_executor::ExecutionError::TxExecution(_))
    ));
}

#[rstest]
#[case(None)]
#[case(Some(false))]
#[case(Some(true))]
fn registry_write_storage_failure_cannot_commit_partial_member(#[case] during_write: Option<bool>) {
    let (mut state, executor) = authorized_state();
    let member = Address::repeat_byte(0x11);
    let slot = if during_write == Some(true) {
        member_slot(member).wrapping_add(U256::from(2))
    } else {
        U256::from(1)
    };
    state.unreadable_storage = during_write.map(|_| (VALIDATOR_REGISTRY_ADDRESS, slot));
    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: member,
        consensusPubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap(),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode();
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    if during_write.is_none() {
        assert_eq!(outcome.receipts.len(), 1);
        assert!(outcome.receipts[0].success());
        assert_eq!(
            outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage[&U256::from(1)],
            U256::from(1)
        );
        return;
    }
    assert!(
        outcome.receipts.iter().all(|receipt| !receipt.success()),
        "failed storage access returned success"
    );
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.is_empty()),
        "failed operation retained registry writes"
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn registry_queries_do_not_treat_storage_failure_as_absence(#[case] single_member: bool) {
    let (mut state, executor) = authorized_state();
    let member = Address::repeat_byte(0x11);
    let (slot, calldata) = if single_member {
        (
            member_slot(member),
            IValidatorRegistry::getValidatorCall { evmAddr: member }.abi_encode(),
        )
    } else {
        (
            U256::from(1),
            IValidatorRegistry::getValidatorsCall {}.abi_encode(),
        )
    };
    state.unreadable_storage = Some((VALIDATOR_REGISTRY_ADDRESS, slot));
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    assert!(outcome.receipts.iter().all(|receipt| !receipt.success()));
}

#[test]
fn registry_rejects_malformed_consensus_key() {
    let (state, executor) = authorized_state();
    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: Address::repeat_byte(0x11),
        consensusPubkey: B256::repeat_byte(0xDD),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode();
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    assert_eq!(outcome.receipts.len(), 1);
    assert!(!outcome.receipts[0].success());
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.is_empty())
    );
}

#[rstest]
#[case(U256::ZERO, true)]
#[case(U256::from(1), false)]
#[case(U256::from_limbs([0, 1, 0, 0]), false)]
#[case(U256::MAX, false)]
fn registry_status_checks_the_full_member_index(#[case] index: U256, #[case] success: bool) {
    let (state, executor) = authorized_state();
    let member = Address::repeat_byte(0x11);
    let registration = IValidatorRegistry::addValidatorCall {
        evmAddr: member,
        consensusPubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap(),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode();
    let (registered, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        registration.into(),
        executor.clone(),
    );
    assert_eq!(registered.receipts.len(), 1);
    assert!(registered.receipts[0].success());
    state
        .accounts
        .write()
        .unwrap()
        .get_mut(&VALIDATOR_REGISTRY_ADDRESS)
        .unwrap()
        .storage
        .extend(
            registered.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS]
                .storage
                .clone(),
        );
    let calldata = IValidatorRegistry::setValidatorStatusByIndexCall {
        index,
        active: true,
    }
    .abi_encode();
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    assert_eq!(outcome.receipts.len(), 1);
    assert_eq!(outcome.receipts[0].success(), success);
    let changes = outcome.changes.accounts.get(&VALIDATOR_REGISTRY_ADDRESS);
    if success {
        let packed = changes.unwrap().storage[&member_slot(member)].to_be_bytes::<32>();
        assert_eq!(packed[20], 1);
    } else {
        assert!(changes.is_none_or(|account| account.storage.is_empty()));
    }
}

#[test]
fn epoch_rosters_capture_the_boundary_branch_and_survive_later_changes() {
    use std::num::NonZeroU64;
    let (registration, actor) = native_member_call(0, native_registration());
    let (state, executor) = authorized_actor(actor);
    let executor = executor.with_membership_epochs(NonZeroU64::new(10).unwrap(), NonZeroU64::MIN);
    let parent = executor.snapshot().unwrap();
    let mut context = BlockContext::new(
        Header {
            number: 8,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (_, before) = executor
        .execute_with_modules(
            &state,
            &context,
            std::slice::from_ref(&registration),
            parent.clone(),
        )
        .unwrap();
    assert!(before.changes_from(&parent)[2].is_empty());
    context.header.number = 9;
    let (outcome, selected) = executor
        .execute_with_modules(
            &state,
            &context,
            std::slice::from_ref(&registration),
            parent.clone(),
        )
        .unwrap();
    let changes = selected.changes_from(&parent);
    let roster = changes[2]
        .iter()
        .find(|(key, _)| key.starts_with(b"consensus_roster/"))
        .unwrap();
    assert_eq!(&roster.0[17..], &3u64.to_be_bytes());
    assert_eq!(roster.1.as_ref().unwrap().len(), 32);
    assert!(
        executor
            .modules()
            .read()
            .unwrap()
            .vera
            .consensus_roster(3)
            .is_none()
    );
    let (_, sibling) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration, backup_member_call(1)],
            parent.clone(),
        )
        .unwrap();
    assert_ne!(selected.state_root(9), sibling.state_root(9));
    let mut verification = context.clone();
    verification.is_verification = true;
    let (registration, _) = native_member_call(0, native_registration());
    let (_, verified) = executor
        .execute_with_modules(&state, &verification, &[registration], parent)
        .unwrap();
    assert_eq!(selected.state_root(9), verified.state_root(9));
    futures::executor::block_on(state.commit(outcome.changes)).unwrap();
    context.header.number = 19;
    let (_, later) = executor
        .execute_with_modules(&state, &context, &[backup_member_call(1)], selected.clone())
        .unwrap();
    let delta = later.changes_from(&selected);
    let roster_changes: Vec<_> = delta[2]
        .iter()
        .filter(|(key, _)| key.starts_with(b"consensus_roster/"))
        .collect();
    assert_eq!(roster_changes.len(), 1);
    assert_eq!(&roster_changes[0].0[17..], &4u64.to_be_bytes());
    assert_eq!(roster_changes[0].1.as_ref().unwrap().len(), 64);
}

#[rstest]
#[case(true, 4, 1, true)]
#[case(false, 4, 1, true)]
#[case(true, 20, 1, false)]
#[case(false, 20, 1, false)]
#[case(true, 20, 16, true)]
#[case(false, 20, 16, true)]
#[case(true, 192, 16, false)]
fn membership_epoch_capacity_rejects_addition_and_both_reactivation_paths(
    #[case] native: bool,
    #[case] epoch_length: u64,
    #[case] term_length: u64,
    #[case] limited: bool,
) {
    let (state, executor) = if native {
        authorized_actor(native_member_call(0, native_registration()).1)
    } else {
        authorized_state()
    };
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let mut backup =
        IValidatorRegistry::addValidatorCall::abi_decode(&native_registration()).unwrap();
    backup.evmAddr = Address::repeat_byte(0x33);
    backup.consensusPubkey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        .parse()
        .unwrap();
    let mut third = backup.clone();
    third.evmAddr = Address::repeat_byte(0x44);
    third.consensusPubkey = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        .parse()
        .unwrap();
    let status = |address, active| {
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: address,
            active,
        }
        .abi_encode()
    };
    let commands = [
        (native_registration(), true),
        (backup.abi_encode(), true),
        (status(backup.evmAddr, false), true),
        (third.abi_encode(), !limited),
        (status(backup.evmAddr, true), !limited),
        (
            IValidatorRegistry::setValidatorStatusByIndexCall {
                index: U256::from(1),
                active: true,
            }
            .abi_encode(),
            !limited,
        ),
        (status(Address::repeat_byte(0x11), true), true),
        (
            IValidatorRegistry::removeValidatorCall {
                evmAddr: backup.evmAddr,
            }
            .abi_encode(),
            true,
        ),
        (status(Address::repeat_byte(0x11), false), !limited),
    ];
    for (sequence, (calldata, expected)) in commands.into_iter().enumerate() {
        let executor = if sequence < 3 {
            executor.clone()
        } else {
            executor.clone().with_membership_epochs(
                std::num::NonZeroU64::new(epoch_length).unwrap(),
                std::num::NonZeroU64::new(term_length).unwrap(),
            )
        };
        let before = state.accounts.read().unwrap()[&VALIDATOR_REGISTRY_ADDRESS]
            .storage
            .clone();
        let outcome = if native {
            let request = native_member_call(sequence as u64, calldata).0;
            let (outcome, modules) = executor
                .execute_with_modules(&state, &context, &[request], executor.snapshot().unwrap())
                .unwrap();
            executor.commit_snapshot(1, modules).unwrap();
            outcome
        } else {
            execute_with_executor(
                &state,
                TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
                calldata.into(),
                executor,
            )
            .0
        };
        assert_eq!(
            outcome.receipts[0].success(),
            expected,
            "command {sequence}"
        );
        let mut accounts = state.accounts.write().unwrap();
        let storage = &mut accounts
            .get_mut(&VALIDATOR_REGISTRY_ADDRESS)
            .unwrap()
            .storage;
        if let Some(changes) = outcome.changes.accounts.get(&VALIDATOR_REGISTRY_ADDRESS) {
            storage.extend(changes.storage.clone());
        }
        if !expected {
            assert_eq!(*storage, before, "rejected command changed membership");
        }
    }
    assert_eq!(
        state.accounts.read().unwrap()[&VALIDATOR_REGISTRY_ADDRESS].storage[&U256::from(1)],
        U256::from(if limited { 1 } else { 2 })
    );
}
