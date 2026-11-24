use super::*;
use alloy_primitives::FixedBytes;
use alloy_sol_types::{SolCall, SolEvent as _};
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use commonware_codec::Encode as _;
use vera_domain::{Block, ExecutionReceipt, RefusalKind, RefusingModule, testing::TestDeployment};
use vera_executor::dispatch::ANCHOR_ADDRESS;
use vera_executor::{ModuleSnapshot, ModuleState};
use vera_modules::vera::administration::{
    AdministrativeCommand, AdministrativeRequest, OperatorApproval, OperatorPolicy,
    SignedAdministrativeRequest,
};
use vera_modules::vera::anchors::{
    AnchorSubmitterGrant, DeploymentRegistration, abi::IAnchor, deployment_id,
};

const GENESIS: [u8; 32] = [7; 32];
/// Submissions the granted signer may make in one day.
const QUOTA: u32 = 12;

/// The public key of the native signer with secret `secret`.
fn public(secret: u64) -> Vec<u8> {
    let key = ark_bls12_381::Fr::from(secret);
    let public = (ark_bls12_381::G1Affine::generator() * key).into_affine();
    let mut encoded = Vec::new();
    public.serialize_compressed(&mut encoded).unwrap();
    encoded
}

fn native(nonce: u64, calldata: Vec<u8>) -> Bytes {
    native_from(13, nonce, calldata)
}

fn native_from(secret: u64, nonce: u64, calldata: Vec<u8>) -> Bytes {
    let key = ark_bls12_381::Fr::from(secret);
    let encoded = public(secret);
    let mut request = vera_domain::NativeTx {
        chain_id: 9001,
        nonce,
        bls_pubkey: FixedBytes::from_slice(&encoded),
        target: ANCHOR_ADDRESS,
        calldata: calldata.into(),
        signature: Default::default(),
    };
    request.signature =
        FixedBytes::from_slice(&vera_crypto::bls::sign(&key, &request.signing_data()).unwrap());
    request.encode_wire().into()
}

/// Module state in which the operator registered `deployments` and granted
/// the signer with secret 13 the right to submit for each.
fn registered(deployments: &[&TestDeployment]) -> ModuleState {
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
    let operator = SigningKey::from_bytes(&[1; 32].into()).unwrap();
    let policy = OperatorPolicy {
        threshold: 1,
        keys: vec![hex::encode(operator.verifying_key().to_sec1_bytes())],
    };
    let mut modules = ModuleState::default();
    modules
        .vera
        .initialize_administration(policy.clone())
        .unwrap();
    let submitter = vera_crypto::bls::did_from_compressed_pubkey(&public(13)).unwrap();
    let commands = deployments.iter().flat_map(|deployment| {
        let key = deployment.key().encode();
        [
            AdministrativeCommand::RegisterDeployment(DeploymentRegistration {
                consensus_key: hex::encode(&key),
                genesis_id: [9; 32],
                operators: policy.clone(),
            }),
            AdministrativeCommand::SetAnchorSubmitter(AnchorSubmitterGrant {
                deployment: deployment_id(&key).0,
                submitter: submitter.clone(),
                quota: QUOTA,
            }),
        ]
    });
    for (sequence, command) in commands.enumerate() {
        let request = AdministrativeRequest {
            genesis_id: GENESIS,
            sequence: sequence as u64,
            expires_at: 100,
            command,
        };
        let signature: Signature = operator
            .sign_prehash(&request.signing_digest().unwrap())
            .unwrap();
        let signed = SignedAdministrativeRequest {
            request,
            approvals: vec![OperatorApproval {
                signer: 0,
                signature: hex::encode(signature.to_bytes()),
            }],
        };
        modules
            .vera
            .apply_administrative_request(&mut modules.acp, GENESIS, 100, &signed)
            .unwrap();
    }
    modules
}

fn artifacts(deployment: &TestDeployment, block: &Block) -> IAnchor::anchorRevisionCall {
    let artifacts = deployment.finalize(block);
    IAnchor::anchorRevisionCall {
        deployment: deployment_id(&deployment.key().encode()),
        block: artifacts.block.into(),
        descendants: Vec::new(),
        finalization: artifacts.finalization.into(),
        epochMaterial: artifacts.epoch_material.into(),
        ancestryProof: Bytes::new(),
    }
}

/// The proof that `chain[ancestor]` is an ancestor of `chain[height]`.
fn proof(chain: &[Block], ancestor: usize, height: usize) -> Bytes {
    let ids: Vec<_> = chain[ancestor..height].iter().map(Block::id).collect();
    chain[ancestor]
        .ancestry
        .prove(ancestor as u64, &ids, ancestor as u64)
        .unwrap()
        .encode()
        .into()
}

/// An anchor of `chain[height]` proving that `chain[from]` is an ancestor of it.
fn anchor_call(
    deployment: &TestDeployment,
    chain: &[Block],
    from: usize,
    height: usize,
) -> Vec<u8> {
    let mut call = artifacts(deployment, &chain[height]);
    if from < height {
        call.ancestryProof = proof(chain, from, height);
    }
    call.abi_encode()
}

/// A report of `chain[height]`, whose ancestor at `anchored` is `chain[anchored]`.
fn fork_call(
    deployment: &TestDeployment,
    chain: &[Block],
    anchored: usize,
    height: usize,
) -> Vec<u8> {
    let call = artifacts(deployment, &chain[height]);
    IAnchor::reportForkCall {
        deployment: call.deployment,
        block: call.block,
        descendants: call.descendants,
        finalization: call.finalization,
        epochMaterial: call.epochMaterial,
        ancestor: chain[anchored].id().0,
        ancestryProof: if anchored < height {
            proof(chain, anchored, height)
        } else {
            Bytes::new()
        },
    }
    .abi_encode()
}

fn execute(deployments: &[&TestDeployment], calls: Vec<Vec<u8>>) -> Vec<ExecutionReceipt> {
    let txs: Vec<Bytes> = calls
        .into_iter()
        .enumerate()
        .map(|(nonce, call)| native(nonce as u64, call))
        .collect();
    execute_requests(deployments, &txs).0
}

/// Execute signed requests in one block and return the receipts and the module state after it.
fn execute_requests(
    deployments: &[&TestDeployment],
    txs: &[Bytes],
) -> (Vec<ExecutionReceipt>, ModuleSnapshot) {
    let executor = VeraExecutor::new(9001);
    executor.set_base_modules(registered(deployments));
    let context = BlockContext::new(1, 100, 30_000_000);
    let (outcome, modules) = executor
        .execute_with_modules(&context, txs, executor.snapshot())
        .unwrap();
    (outcome.receipts, modules)
}

fn refusals(receipts: &[ExecutionReceipt]) -> Vec<RefusalKind> {
    receipts
        .iter()
        .map(|receipt| {
            let refusal = receipt.refusal.as_ref().expect("refused");
            assert_eq!(refusal.module, RefusingModule::Anchor);
            assert_eq!(
                receipt.gas_used, 250_000,
                "a refused anchor is charged in full"
            );
            refusal.kind
        })
        .collect()
}

#[test]
fn a_native_anchor_is_recorded_and_another_deployment_or_a_regression_is_refused() {
    let deployment = TestDeployment::new(21);
    let chain = deployment.chain(40, 1);
    let other_history = deployment.chain(40, 2);
    let foreign = {
        let other = TestDeployment::new(22);
        let mut call = artifacts(&other, &other.chain(40, 1)[40]);
        call.deployment = deployment_id(&deployment.key().encode());
        call.abi_encode()
    };
    let receipts = execute(
        &[&deployment],
        vec![
            anchor_call(&deployment, &chain, 20, 20),
            anchor_call(&deployment, &other_history, 20, 20),
            foreign,
            anchor_call(&deployment, &chain, 10, 10),
        ],
    );

    assert!(receipts[0].success(), "{:?}", receipts[0].refusal);
    let log = &receipts[0].logs()[0];
    assert_eq!(log.address, ANCHOR_ADDRESS);
    let event = IAnchor::RevisionAnchored::decode_log_data(&log.data).unwrap();
    assert_eq!(
        event.deployment.0,
        deployment_id(&deployment.key().encode()).0
    );
    assert_eq!((event.sequence, event.height), (1, 20));
    assert_eq!(
        refusals(&receipts[1..]),
        [
            RefusalKind::NotNewer,
            RefusalKind::InvalidProof,
            RefusalKind::NotNewer
        ]
    );
}

#[test]
fn an_anchor_extends_the_latest_one_and_another_history_is_refused_and_recorded_as_a_fork() {
    let deployment = TestDeployment::new(23);
    let chain = deployment.chain(40, 1);
    // A second device finalized another history from the same genesis block.
    let fork = deployment.chain(40, 2);
    let mut unproven = artifacts(&deployment, &chain[30]);
    unproven.ancestryProof = proof(&chain, 10, 30);
    let receipts = execute(
        &[&deployment],
        vec![
            anchor_call(&deployment, &chain, 20, 20),
            // The fork above the anchor, with the proof of its own ancestor at the anchored height.
            anchor_call(&deployment, &fork, 20, 30),
            // The honest block without a proof, and with a proof of another ancestor.
            artifacts(&deployment, &chain[30]).abi_encode(),
            unproven.abi_encode(),
            anchor_call(&deployment, &chain, 20, 30),
            // The fork is evidence once it is reported with what it does descend from.
            fork_call(&deployment, &fork, 30, 30),
            fork_call(&deployment, &fork, 30, 35),
            fork_call(&deployment, &fork, 30, 35),
            // Blocks of the anchored history are no fork.
            fork_call(&deployment, &chain, 30, 30),
            fork_call(&deployment, &chain, 30, 35),
            anchor_call(&deployment, &chain, 30, 40),
        ],
    );

    assert!(receipts[0].success(), "{:?}", receipts[0].refusal);
    assert_eq!(refusals(&receipts[1..4]), [RefusalKind::NotDescendant; 3]);
    for (index, sequence, height) in [(4, 2, 30), (10, 3, 40)] {
        assert!(receipts[index].success(), "{:?}", receipts[index].refusal);
        let event =
            IAnchor::RevisionAnchored::decode_log_data(&receipts[index].logs()[0].data).unwrap();
        assert_eq!((event.sequence, event.height), (sequence, height));
        assert_eq!(event.blockHash.0, chain[height as usize].id().0.0);
    }
    for (index, height) in [(5, 30), (6, 35)] {
        assert!(receipts[index].success(), "{:?}", receipts[index].refusal);
        let event =
            IAnchor::ForkReported::decode_log_data(&receipts[index].logs()[0].data).unwrap();
        assert_eq!(
            event.deployment.0,
            deployment_id(&deployment.key().encode()).0
        );
        assert_eq!((event.sequence, event.height), (2, height));
        assert_eq!(event.anchoredBlock.0, chain[30].id().0.0);
        assert_eq!(event.blockHash.0, fork[height as usize].id().0.0);
    }
    assert_eq!(
        refusals(&receipts[7..10]),
        [
            RefusalKind::AlreadyExists,
            RefusalKind::InvalidProof,
            RefusalKind::InvalidProof
        ]
    );
}

#[test]
fn only_a_granted_signer_anchors_a_registered_deployment_within_its_quota() {
    let deployment = TestDeployment::new(24);
    let unregistered = TestDeployment::new(25);
    let chain = deployment.chain(u64::from(QUOTA), 1);
    let mut txs = vec![
        // A signer without a grant, and a deployment nobody registered.
        native_from(14, 0, anchor_call(&deployment, &chain, 1, 1)),
        native(
            0,
            anchor_call(&unregistered, &unregistered.chain(1, 1), 1, 1),
        ),
        native(1, anchor_call(&deployment, &chain, 1, 1)),
        // A refused submission counts against the quota like a recorded one.
        native(2, artifacts(&deployment, &chain[2]).abi_encode()),
    ];
    // The quota's remaining submissions, and one more.
    for height in 2..=QUOTA as usize {
        let nonce = txs.len() as u64 - 1;
        txs.push(native(
            nonce,
            anchor_call(&deployment, &chain, height - 1, height),
        ));
    }
    let (receipts, modules) = execute_requests(&[&deployment], &txs);

    assert_eq!(
        refusals(&receipts[..2]),
        [RefusalKind::Unauthorized, RefusalKind::NotFound]
    );
    assert!(receipts[2].success(), "{:?}", receipts[2].refusal);
    assert_eq!(refusals(&receipts[3..4]), [RefusalKind::NotDescendant]);
    let (accepted, last) = receipts[4..].split_at(receipts.len() - 5);
    assert_eq!(accepted.len(), QUOTA as usize - 2);
    for receipt in accepted {
        assert!(receipt.success(), "{:?}", receipt.refusal);
    }
    assert_eq!(refusals(last), [RefusalKind::WorkLimitExceeded]);

    let submitter = vera_crypto::bls::did_from_compressed_pubkey(&public(13)).unwrap();
    let id = deployment_id(&deployment.key().encode());
    let snapshot = modules.changes_from(&VeraExecutor::new(9001).snapshot());
    let record = snapshot[2]
        .iter()
        .find_map(|(key, value)| {
            (key == &vera_modules::vera::anchors::submitter_key(&id, &submitter))
                .then(|| value.clone().expect("the grant is kept"))
        })
        .expect("the grant changed");
    let record =
        vera_modules::vera::anchors::SubmitterRecord::decode(&id, &submitter, &record).unwrap();
    assert_eq!((record.quota, record.used), (QUOTA, QUOTA));
}

/// A term change of the deployment registered with genesis block `[9; 32]`,
/// approved by the operator with secret `[secret; 32]`.
fn term_call(
    deployment: &TestDeployment,
    genesis: u8,
    secret: u8,
    term: u64,
    cut: &Block,
) -> Vec<u8> {
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
    use vera_domain::{TermApproval, TermCertificate, TermChange, TermCut};
    let change = TermChange {
        genesis_id: B256::repeat_byte(genesis),
        term,
        holder: B256::repeat_byte(0xd0),
        cut: TermCut {
            height: cut.height,
            block: cut.id().0,
        },
    };
    let operator = SigningKey::from_bytes(&[secret; 32].into()).unwrap();
    let signature: Signature = operator.sign_prehash(&change.signing_digest()).unwrap();
    let certificate = TermCertificate {
        change,
        approvals: vec![TermApproval {
            signer: 0,
            signature: FixedBytes::from_slice(&signature.to_bytes()),
        }],
    };
    IAnchor::changeTermCall {
        deployment: deployment_id(&deployment.key().encode()),
        certificate: serde_json::to_vec(&certificate).unwrap().into(),
    }
    .abi_encode()
}

#[test]
fn a_term_is_anchored_only_under_its_certificate_and_continues_from_its_cut() {
    let deployment = TestDeployment::new(26);
    let replaced = deployment.chain(20, 1);
    // The device that took over built term 1 on the block at height 10.
    let mut taken = replaced[..=10].to_vec();
    for _ in 0..5 {
        let next = deployment.child(&taken[taken.len() - 1], 1, B256::repeat_byte(2));
        taken.push(next);
    }
    let receipts = execute(
        &[&deployment],
        vec![
            anchor_call(&deployment, &replaced, 5, 5),
            // A block of term 1 that does descend from the anchor, before any certificate.
            anchor_call(&deployment, &taken, 5, 12),
            // A certificate by another key, and one for another deployment's genesis block.
            term_call(&deployment, 9, 2, 1, &replaced[10]),
            term_call(&deployment, 8, 1, 1, &replaced[10]),
            anchor_call(&deployment, &replaced, 5, 15),
            term_call(&deployment, 9, 1, 1, &replaced[10]),
            // The replaced device's blocks above the cut are void.
            anchor_call(&deployment, &replaced, 15, 18),
            fork_call(&deployment, &replaced, 10, 15),
            // The term's first anchor proves the cut, not an earlier anchor.
            anchor_call(&deployment, &taken, 5, 12),
            anchor_call(&deployment, &taken, 10, 12),
            term_call(&deployment, 9, 1, 1, &replaced[10]),
            anchor_call(&deployment, &taken, 12, 15),
        ],
    );

    assert!(receipts[0].success(), "{:?}", receipts[0].refusal);
    assert_eq!(
        refusals(&receipts[1..4]),
        [
            RefusalKind::Unauthorized,
            RefusalKind::InvalidProof,
            RefusalKind::InvalidProof
        ]
    );
    assert!(receipts[4].success(), "{:?}", receipts[4].refusal);
    assert!(receipts[5].success(), "{:?}", receipts[5].refusal);
    let event = IAnchor::TermChanged::decode_log_data(&receipts[5].logs()[0].data).unwrap();
    assert_eq!((event.term, event.cutHeight, event.sequence), (1, 10, 2));
    assert_eq!(event.cutBlock.0, replaced[10].id().0.0);
    assert_eq!(
        refusals(&receipts[6..9]),
        [
            RefusalKind::NotNewer,
            RefusalKind::InvalidProof,
            RefusalKind::NotDescendant
        ]
    );
    for (index, sequence, height) in [(9, 3, 12), (11, 4, 15)] {
        assert!(receipts[index].success(), "{:?}", receipts[index].refusal);
        let event =
            IAnchor::RevisionAnchored::decode_log_data(&receipts[index].logs()[0].data).unwrap();
        assert_eq!((event.sequence, event.height), (sequence, height));
        assert_eq!(event.blockHash.0, taken[height as usize].id().0.0);
    }
    assert_eq!(refusals(&receipts[10..11]), [RefusalKind::NotNewer]);
}
