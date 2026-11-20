//! Anchor precompile dispatch: ABI decode of anchor submissions.

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use vera_domain::{FinalizedArtifacts, RefusalKind};
use vera_modules::types::BlockExecCtx;
use vera_modules::vera::VeraModule;
use vera_modules::vera::anchors::{
    AnchorError, AnchorSubmission, MAX_ANCHOR_ARTIFACT_BYTES, abi::IAnchor,
};

use super::refusal::Refuse;
use super::{
    ANCHOR_ADDRESS, DispatchReturn, decode_error, err_dispatch, event_log, internal_fault,
    ok_dispatch, oog_dispatch, refusal::refused, unknown_selector,
};

/// Charge of an anchor: decoding the artifacts and one aggregate pairing check.
const ANCHOR_GAS: u64 = 250_000;

impl Refuse for AnchorError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::TooLarge => RefusalKind::ArgumentOutOfBounds,
            Self::InvalidConsensusKey => RefusalKind::UndecodableInput,
            Self::Finality(_) => RefusalKind::InvalidProof,
            Self::NotNewer { .. } | Self::LowerTerm { .. } => RefusalKind::NotNewer,
            Self::MalformedRecord => RefusalKind::StateError,
        }
    }
}

/// Dispatch an ABI-encoded call to the anchor methods of the identity module.
/// Anchors need no signer: their authority is the anchored deployment's certificate.
pub(super) fn dispatch(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    if input.len() < 4 {
        return Ok(super::short_input());
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");
    if selector != IAnchor::anchorRevisionCall::SELECTOR {
        return Err(unknown_selector("anchor", selector));
    }
    if gas_limit < ANCHOR_GAS {
        return Ok(oog_dispatch());
    }
    if input.len() > 2 * MAX_ANCHOR_ARTIFACT_BYTES {
        return Err(refused(
            RefusalKind::ArgumentOutOfBounds,
            AnchorError::TooLarge,
        ));
    }
    let call = IAnchor::anchorRevisionCall::abi_decode(input).map_err(decode_error)?;
    let submission = AnchorSubmission {
        consensus_key: call.consensusKey.to_vec(),
        artifacts: FinalizedArtifacts {
            block: call.block.to_vec(),
            descendants: call.descendants.iter().map(|d| d.to_vec()).collect(),
            finalization: call.finalization.to_vec(),
            epoch_material: call.epochMaterial.to_vec(),
        },
    };
    match module.anchor_revision(block_ctx, &submission) {
        Ok(anchored) => {
            let record = &anchored.record;
            let logs = if anchored.recorded {
                vec![event_log(
                    ANCHOR_ADDRESS,
                    &IAnchor::RevisionAnchored {
                        deployment: FixedBytes(record.deployment.0),
                        sequence: record.sequence,
                        height: record.height,
                        blockHash: FixedBytes(record.block_hash.0),
                    },
                )]
            } else {
                vec![]
            };
            Ok(ok_dispatch(
                ANCHOR_GAS,
                IAnchor::anchorRevisionCall::abi_encode_returns(&record.encode().into()),
                logs,
            ))
        }
        Err(AnchorError::MalformedRecord) => Err(internal_fault(AnchorError::MalformedRecord)),
        Err(error) => Ok(err_dispatch(error)),
    }
}
