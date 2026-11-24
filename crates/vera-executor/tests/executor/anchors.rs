use super::*;
use alloy_primitives::FixedBytes;
use alloy_sol_types::{SolCall, SolEvent as _};
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use commonware_codec::Encode as _;
use vera_domain::{Block, ExecutionReceipt, RefusalKind, RefusingModule, testing::TestDeployment};
use vera_executor::dispatch::ANCHOR_ADDRESS;
use vera_modules::vera::anchors::{abi::IAnchor, deployment_id};

fn native(nonce: u64, calldata: Vec<u8>) -> Bytes {
    let key = ark_bls12_381::Fr::from(13u64);
    let public = (ark_bls12_381::G1Affine::generator() * key).into_affine();
    let mut encoded = Vec::new();
    public.serialize_compressed(&mut encoded).unwrap();
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

fn artifacts(deployment: &TestDeployment, block: &Block) -> IAnchor::anchorRevisionCall {
    let artifacts = deployment.finalize(block);
    IAnchor::anchorRevisionCall {
        consensusKey: deployment.key().encode().to_vec().into(),
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
        consensusKey: call.consensusKey,
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

fn execute(calls: Vec<Vec<u8>>) -> Vec<ExecutionReceipt> {
    let executor = VeraExecutor::new(9001);
    let context = BlockContext::new(1, 100, 30_000_000);
    let txs: Vec<Bytes> = calls
        .into_iter()
        .enumerate()
        .map(|(nonce, call)| native(nonce as u64, call))
        .collect();
    let (outcome, _) = executor
        .execute_with_modules(&context, &txs, executor.snapshot())
        .unwrap();
    outcome.receipts
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
        call.consensusKey = deployment.key().encode().to_vec().into();
        call.abi_encode()
    };
    let receipts = execute(vec![
        anchor_call(&deployment, &chain, 20, 20),
        anchor_call(&deployment, &other_history, 20, 20),
        foreign,
        anchor_call(&deployment, &chain, 10, 10),
    ]);

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
    let receipts = execute(vec![
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
    ]);

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
