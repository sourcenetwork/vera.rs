use super::*;
use alloy_primitives::FixedBytes;
use alloy_sol_types::{SolCall, SolEvent as _};
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use commonware_codec::Encode as _;
use vera_domain::{ExecutionReceipt, RefusalKind, RefusingModule, testing::TestDeployment};
use vera_executor::precompiles::ANCHOR_ADDRESS;
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

fn anchor_call(deployment: &TestDeployment, height: u64, root: u8) -> Vec<u8> {
    let block = deployment.block(height, B256::repeat_byte(7), 0, B256::repeat_byte(root));
    let artifacts = deployment.finalize(&block);
    IAnchor::anchorRevisionCall {
        consensusKey: deployment.key().encode().to_vec().into(),
        block: artifacts.block.into(),
        descendants: Vec::new(),
        finalization: artifacts.finalization.into(),
        epochMaterial: artifacts.epoch_material.into(),
    }
    .abi_encode()
}

fn execute(calls: Vec<Vec<u8>>) -> Vec<ExecutionReceipt> {
    let executor = VeraExecutor::new(9001);
    let context = BlockContext::new(
        Header {
            number: 1,
            timestamp: 100,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let txs: Vec<Bytes> = calls
        .into_iter()
        .enumerate()
        .map(|(nonce, call)| native(nonce as u64, call))
        .collect();
    let (outcome, _) = executor
        .execute_with_modules(&MockStateDb::new(), &context, &txs, executor.snapshot())
        .unwrap();
    outcome.receipts
}

#[test]
fn a_native_anchor_is_recorded_and_a_fork_another_deployment_or_a_regression_is_refused() {
    let deployment = TestDeployment::new(21);
    let foreign = {
        let other = TestDeployment::new(22);
        let block = other.block(40, B256::repeat_byte(7), 0, B256::repeat_byte(1));
        let artifacts = other.finalize(&block);
        IAnchor::anchorRevisionCall {
            consensusKey: deployment.key().encode().to_vec().into(),
            block: artifacts.block.into(),
            descendants: Vec::new(),
            finalization: artifacts.finalization.into(),
            epochMaterial: artifacts.epoch_material.into(),
        }
        .abi_encode()
    };
    let receipts = execute(vec![
        anchor_call(&deployment, 20, 1),
        anchor_call(&deployment, 20, 2),
        foreign,
        anchor_call(&deployment, 10, 1),
    ]);

    assert!(receipts[0].success(), "{:?}", receipts[0].refusal);
    let log = &receipts[0].logs()[0];
    assert_eq!(log.address, ANCHOR_ADDRESS);
    let event = IAnchor::RevisionAnchored::decode_log_data(&log.data).unwrap();
    assert_eq!(event.deployment.0, deployment_id(&deployment.key()).0);
    assert_eq!((event.sequence, event.height), (1, 20));

    let refusals: Vec<_> = receipts[1..]
        .iter()
        .map(|receipt| {
            let refusal = receipt.refusal.as_ref().expect("refused");
            assert_eq!(refusal.module, RefusingModule::Anchor);
            refusal.kind
        })
        .collect();
    assert_eq!(
        refusals,
        [
            RefusalKind::NotNewer,
            RefusalKind::InvalidProof,
            RefusalKind::NotNewer
        ]
    );
}
