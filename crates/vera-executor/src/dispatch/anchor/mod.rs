//! Anchor precompile dispatch: ABI decode, and finality, ancestry and term
//! certificate verification of anchor submissions, recorded by the identity module.

mod submission;
#[cfg(test)]
mod tests;

use alloy_primitives::{B256, FixedBytes};
use alloy_sol_types::SolCall;
use vera_domain::{FinalizedArtifacts, RefusalKind, TermCertificate};
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::vera::VeraModule;
use vera_modules::vera::anchors::{
    AnchorError, DeploymentRecord, MAX_ANCHOR_ARTIFACT_BYTES, VerifiedTerm, abi::IAnchor,
};
use vera_permission::verify_term_certificate;

use submission::{AnchorRefusal, AnchorSubmission, VerifiedSubmission};

use super::refusal::Refuse;
use super::{
    ANCHOR_ADDRESS, DispatchResult, DispatchReturn, decode_error, err_dispatch, event_log,
    internal_fault, ok_dispatch, oog_dispatch, refusal::refused, unknown_selector,
};

/// Charge of an anchor, a fork report or a term change, accepted or refused:
/// decoding the artifacts, one aggregate pairing check and the ancestry
/// proof, or the approvals of a certificate.
pub(crate) const ANCHOR_GAS: u64 = 250_000;

impl Refuse for AnchorError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::TooLarge => RefusalKind::ArgumentOutOfBounds,
            Self::InvalidConsensusKey => RefusalKind::UndecodableInput,
            Self::NotNewer { .. } | Self::LowerTerm { .. } | Self::TermNotNewer { .. } => {
                RefusalKind::NotNewer
            }
            Self::TermNotCertified { .. } => RefusalKind::Unauthorized,
            Self::NotDescendant { .. } => RefusalKind::NotDescendant,
            Self::NoAnchor | Self::NotRegistered => RefusalKind::NotFound,
            Self::NotGranted => RefusalKind::Unauthorized,
            Self::QuotaExceeded { .. } => RefusalKind::WorkLimitExceeded,
            Self::InvalidRegistration | Self::InvalidGrant => RefusalKind::InvalidArgument,
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
            Self::Finality(_) | Self::Term(_) => RefusalKind::InvalidProof,
            Self::Certificate => RefusalKind::UndecodableInput,
        }
    }
}

/// The deployment an anchor call names: the first argument of every method.
pub(crate) fn named_deployment(input: &[u8]) -> Option<B256> {
    let known = input.get(..4).is_some_and(is_method);
    input.get(4..36).filter(|_| known).map(B256::from_slice)
}

fn is_method(selector: &[u8]) -> bool {
    selector == IAnchor::anchorRevisionCall::SELECTOR
        || selector == IAnchor::reportForkCall::SELECTOR
        || selector == IAnchor::changeTermCall::SELECTOR
}

/// Count a refused submission against its signer's grant. The refusal rolled
/// the module back, so the count the call made is gone with it.
pub(crate) fn charge_refused(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
) {
    if let Some(deployment) = named_deployment(input) {
        // A signer without a grant or beyond its quota has nothing left to count.
        let _ = module.charge_anchor_submission(block_ctx, &deployment, &tx_ctx.signer);
    }
}

/// Dispatch an ABI-encoded call to the anchor methods of the identity module.
/// The signer needs a grant for the deployment it names; what is recorded
/// rests on the deployment's certificate.
pub(super) fn dispatch(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    if input.len() < 4 {
        return Ok(super::short_input());
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");
    if !is_method(&selector) {
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
    let outcome = if selector == IAnchor::changeTermCall::SELECTOR {
        let call = IAnchor::changeTermCall::abi_decode(input).map_err(decode_error)?;
        change_term(
            module,
            block_ctx,
            tx_ctx,
            &B256::from(call.deployment.0),
            &call.certificate,
        )
    } else if selector == IAnchor::anchorRevisionCall::SELECTOR {
        let call = IAnchor::anchorRevisionCall::abi_decode(input).map_err(decode_error)?;
        let submission = AnchorSubmission {
            deployment: B256::from(call.deployment.0),
            artifacts: FinalizedArtifacts {
                block: call.block.to_vec(),
                descendants: call.descendants.iter().map(|d| d.to_vec()).collect(),
                finalization: call.finalization.to_vec(),
                epoch_material: call.epochMaterial.to_vec(),
            },
        };
        anchor(module, block_ctx, tx_ctx, &submission, &call.ancestryProof)
    } else {
        let call = IAnchor::reportForkCall::abi_decode(input).map_err(decode_error)?;
        let submission = AnchorSubmission {
            deployment: B256::from(call.deployment.0),
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
            tx_ctx,
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
            // A refusal costs the full price whichever check raised it. One
            // raised in `authorize` (an unregistered deployment, no grant, a
            // used quota) comes before the artifacts are verified, but the
            // request still took its place in the block, and a flat price
            // keeps a signer from probing for the cheaper refusals.
            let mut refused = err_dispatch(error);
            refused.output.gas_used = ANCHOR_GAS;
            Ok(refused)
        }
    }
}

/// Check that the deployment is registered and count the submission against
/// the signer's grant.
fn authorize(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    deployment: &B256,
) -> Result<DeploymentRecord, AnchorRefusal> {
    let registered = module.registered_deployment(deployment)?;
    module.charge_anchor_submission(block_ctx, deployment, &tx_ctx.signer)?;
    Ok(registered)
}

/// [`authorize`] the submission, then verify the revision under the registered key.
fn admit(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    submission: &AnchorSubmission,
) -> Result<(DeploymentRecord, VerifiedSubmission), AnchorRefusal> {
    let registered = authorize(module, block_ctx, tx_ctx, &submission.deployment)?;
    let verified = submission.verify(&registered.consensus_key)?;
    Ok((registered, verified))
}

/// Largest term certificate a term change carries, in bytes.
const MAX_TERM_CERTIFICATE_BYTES: usize = 32 << 10;

fn change_term(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    deployment: &B256,
    certificate: &[u8],
) -> Result<DispatchResult, AnchorRefusal> {
    let registered = authorize(module, block_ctx, tx_ctx, deployment)?;
    if certificate.len() > MAX_TERM_CERTIFICATE_BYTES {
        return Err(AnchorError::TooLarge.into());
    }
    let certificate: TermCertificate =
        serde_json::from_slice(certificate).map_err(|_| AnchorRefusal::Certificate)?;
    verify_term_certificate(&certificate, &registered.genesis_id, &registered.operators)?;
    let change = certificate.change;
    let record = module.record_term(
        block_ctx,
        deployment,
        &VerifiedTerm {
            term: change.term,
            holder: change.holder,
            cut_height: change.cut.height,
            cut_block: change.cut.block,
        },
    )?;
    let log = event_log(
        ANCHOR_ADDRESS,
        &IAnchor::TermChanged {
            deployment: FixedBytes(record.deployment.0),
            term: record.term,
            cutHeight: record.cut_height,
            cutBlock: FixedBytes(record.cut_block.0),
            sequence: record.sequence,
        },
    );
    Ok(ok_dispatch(
        ANCHOR_GAS,
        IAnchor::changeTermCall::abi_encode_returns(&record.encode().into()),
        vec![log],
    ))
}

fn anchor(
    module: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    submission: &AnchorSubmission,
    proof: &[u8],
) -> Result<DispatchResult, AnchorRefusal> {
    let (registered, verified) = admit(module, block_ctx, tx_ctx, submission)?;
    let (height, ancestor) = module
        .lineage(&registered)?
        .tip()
        .unwrap_or((0, B256::ZERO));
    let revision = verified.revision(height, ancestor, proof);
    let anchored = module.record_anchor(block_ctx, &submission.deployment, &revision)?;
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
    tx_ctx: &TxExecCtx,
    submission: &AnchorSubmission,
    ancestor: B256,
    proof: &[u8],
) -> Result<DispatchResult, AnchorRefusal> {
    let (registered, verified) = admit(module, block_ctx, tx_ctx, submission)?;
    let (height, _) = module
        .lineage(&registered)?
        .tip()
        .ok_or(AnchorError::NoAnchor)?;
    let revision = verified.revision(height, ancestor, proof);
    let record = module.record_fork(block_ctx, &submission.deployment, &revision)?;
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
