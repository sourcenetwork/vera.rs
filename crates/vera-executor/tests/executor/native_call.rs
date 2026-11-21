//! One native request from a fixed member key, executed as its own block.

use super::*;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use vera_executor::{ExecutionError, ExecutionOutcome, ModuleState, VeraExecutor};

fn member_key() -> (ark_bls12_381::Fr, ark_bls12_381::G1Affine) {
    let key = ark_bls12_381::Fr::from(7u64);
    (
        key,
        (ark_bls12_381::G1Affine::generator() * key).into_affine(),
    )
}

/// The DID the fixed member key signs as.
pub(super) fn member_did() -> vera_identity::Did {
    vera_crypto::bls::did_from_bls_pubkey(&member_key().1)
        .unwrap()
        .parse()
        .unwrap()
}

/// A request to `target` signed by the member key under `sequence`.
pub(super) fn member_request(target: Address, sequence: u64, calldata: Vec<u8>) -> Bytes {
    let (key, public) = member_key();
    let mut encoded = Vec::new();
    public.serialize_compressed(&mut encoded).unwrap();
    let mut request = vera_domain::NativeTx {
        chain_id: 9001,
        nonce: sequence,
        bls_pubkey: alloy_primitives::FixedBytes::from_slice(&encoded),
        target,
        calldata: calldata.into(),
        signature: Default::default(),
    };
    request.signature = alloy_primitives::FixedBytes::from_slice(
        &vera_crypto::bls::sign(&key, &request.signing_data()).unwrap(),
    );
    request.encode_wire().into()
}

/// Execute the member's next request and publish its module values.
pub(super) fn execute_native(
    state: &MockStateDb,
    target: Address,
    calldata: Vec<u8>,
    executor: VeraExecutor,
) -> (ExecutionOutcome, ModuleState) {
    try_execute_native(state, target, calldata, executor).unwrap()
}

pub(super) fn try_execute_native(
    state: &MockStateDb,
    target: Address,
    calldata: Vec<u8>,
    executor: VeraExecutor,
) -> Result<(ExecutionOutcome, ModuleState), ExecutionError> {
    let sequence = executor
        .modules()
        .read()
        .unwrap()
        .nonces
        .get_nonce(member_did().as_ref())
        .unwrap();
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
    );
    let request = member_request(target, sequence, calldata);
    let (outcome, modules) =
        executor.execute_with_modules(state, &context, &[request], executor.snapshot())?;
    executor.publish_snapshot(modules);
    let modules = executor.modules().read().unwrap().clone();
    Ok((outcome, modules))
}
