//! Anchor precompile dispatch: ABI decode, and finality and ancestry
//! verification of anchor submissions, recorded by the identity module.

mod submission;
#[cfg(test)]
mod tests;

use alloy_primitives::{B256, FixedBytes};
use alloy_sol_types::SolCall;
use vera_domain::{FinalizedArtifacts, RefusalKind};
use vera_modules::types::BlockExecCtx;
use vera_modules::vera::VeraModule;
use vera_modules::vera::anchors::{
    AnchorError, MAX_ANCHOR_ARTIFACT_BYTES, abi::IAnchor, deployment_id,
};

use submission::{AnchorRefusal, AnchorSubmission};

use super::refusal::Refuse;
use super::{
    ANCHOR_ADDRESS, DispatchResult, DispatchReturn, decode_error, err_dispatch, event_log,
    internal_fault, ok_dispatch, oog_dispatch, refusal::refused, unknown_selector,
};

/// Charge of an anchor or a fork report, accepted or refused: decoding the
/// artifacts, one aggregate pairing check and the ancestry proof.
pub(crate) const ANCHOR_GAS: u64 = 250_000;

impl Refuse for AnchorError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::TooLarge => RefusalKind::ArgumentOutOfBounds,
            Self::InvalidConsensusKey => RefusalKind::UndecodableInput,
            Self::NotNewer { .. } | Self::LowerTerm { .. } => RefusalKind::NotNewer,
            Self::NotDescendant { .. } => RefusalKind::NotDescendant,
            Self::NoAnchor => RefusalKind::NotFound,
            Self::NotAFork { .. } => RefusalKind::InvalidProof,
            Self::ForkRecorded => RefusalKind::AlreadyExists,
            Self::MalformedRecord => RefusalKind::StateError,
        }
    }
}

impl Refuse for AnchorRefusal {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::Anchor(error) => error.refusal_kind(),
            Self::Finality(_) => RefusalKind::InvalidProof,
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
    if selector != IAnchor::anchorRevisionCall::SELECTOR
        && selector != IAnchor::reportForkCall::SELECTOR
    {
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
    let outcome = if selector == IAnchor::anchorRevisionCall::SELECTOR {
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
        anchor(module, block_ctx, &submission, &call.ancestryProof)
    } else {
        let call = IAnchor::reportForkCall::abi_decode(input).map_err(decode_error)?;
        let submission = AnchorSubmission {
            consensus_key: call.consensusKey.to_vec(),
            artifacts: FinalizedArtifacts {
                block: call.block.to_vec(),
                descendants: call.descendants.iter().map(|d| d.to_vec()).collect(),
                finalization: call.finalization.to_vec(),
                epoch_material: call.epochMaterial.to_vec(),
            },
        };
        report_fork(
            module,
            block_ctx,
            &submission,
            B256::from(call.ancestor.0),
            &call.ancestryProof,
        )
    };
    match outcome {
        Ok(dispatched) => Ok(dispatched),
        Err(AnchorRefusal::Anchor(AnchorError::MalformedRecord)) => {
            Err(internal_fault(AnchorError::MalformedRecord))
        }
        Err(error) => {
            // Every validator decoded and verified the submission before refusing it.
            let mut refused = err_dispatch(error);
            refused.output.gas_used = ANCHOR_GAS;
            Ok(refused)
        }
    }
}

fn anchor(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    submission: &AnchorSubmission,
    proof: &[u8],
) -> Result<DispatchResult, AnchorRefusal> {
    let verified = submission.verify()?;
    let latest = module.latest_anchor(&deployment_id(&verified.consensus_key))?;
    let (height, ancestor) =
        latest.map_or((0, B256::ZERO), |latest| (latest.height, latest.block_hash));
    let revision = verified.revision(height, ancestor, proof);
    let anchored = module.record_anchor(block_ctx, &verified.consensus_key, &revision)?;
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

fn report_fork(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    submission: &AnchorSubmission,
    ancestor: B256,
    proof: &[u8],
) -> Result<DispatchResult, AnchorRefusal> {
    let verified = submission.verify()?;
    let latest = module
        .latest_anchor(&deployment_id(&verified.consensus_key))?
        .ok_or(AnchorError::NoAnchor)?;
    let revision = verified.revision(latest.height, ancestor, proof);
    let record = module.record_fork(block_ctx, &verified.consensus_key, &revision)?;
    let log = event_log(
        ANCHOR_ADDRESS,
        &IAnchor::ForkReported {
            deployment: FixedBytes(record.deployment.0),
            sequence: record.sequence,
            anchoredBlock: FixedBytes(record.anchored_block.0),
            height: record.height,
            blockHash: FixedBytes(record.block_hash.0),
        },
    );
    Ok(ok_dispatch(
        ANCHOR_GAS,
        IAnchor::reportForkCall::abi_encode_returns(&record.encode().into()),
        vec![log],
    ))
}
