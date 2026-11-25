//! The checks every native request passes before it reaches a module.

use alloy_primitives::Address;
use vera_crypto::bls;
use vera_domain::NativeTx;

use crate::ExecutionError;
use crate::dispatch::{
    ACP_ADDRESS, ANCHOR_ADDRESS, BULLETIN_ADDRESS, VALIDATOR_REGISTRY_ADDRESS, VERA_ADDRESS,
};

const NATIVE_TARGETS: [Address; 5] = [
    ACP_ADDRESS,
    BULLETIN_ADDRESS,
    VERA_ADDRESS,
    VALIDATOR_REGISTRY_ADDRESS,
    ANCHOR_ADDRESS,
];

/// Whether a native request may be addressed to `target`.
pub(crate) fn is_native_target(target: &Address) -> bool {
    NATIVE_TARGETS.contains(target)
}

pub(crate) struct AuthenticatedNativeTx {
    pub(crate) native_tx: NativeTx,
    pub(crate) signer_did: String,
}

/// Decode a native request and check its deployment and target module.
pub(crate) fn decode_native_tx(chain_id: u64, tx_bytes: &[u8]) -> Result<NativeTx, ExecutionError> {
    let native_tx = NativeTx::decode_wire(tx_bytes)
        .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;
    if native_tx.chain_id != chain_id {
        return Err(ExecutionError::ChainIdMismatch {
            expected: chain_id,
            got: native_tx.chain_id,
        });
    }
    if !is_native_target(&native_tx.target) {
        return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
    }
    Ok(native_tx)
}

/// Decode a native request, then verify its signature and derive its signer.
pub(crate) fn authenticate_native_tx(
    chain_id: u64,
    tx_bytes: &[u8],
) -> Result<AuthenticatedNativeTx, ExecutionError> {
    let native_tx = decode_native_tx(chain_id, tx_bytes)?;
    let signer_did = bls::verify_and_identify(
        native_tx.bls_pubkey.as_slice(),
        &native_tx.signing_data(),
        native_tx.signature.as_slice(),
    )
    .map_err(|e| ExecutionError::BlsVerification(format!("signature: {e}")))?;
    Ok(AuthenticatedNativeTx {
        native_tx,
        signer_did,
    })
}
