//! Unsigned dry run of a native module call as a named acting DID.

use alloy_primitives::{Address, Bytes, Log};
use thiserror::Error;
use vera_domain::Refusal;
use vera_identity::Did;
use vera_modules::ModuleState;
use vera_modules::types::TxExecCtx;
use vera_traits::StateDbRead;

use super::SimulationContext;
use crate::ExecutionError;
use crate::executor::native_authentication::is_native_target;
use crate::executor::native_dispatch::{NATIVE_TX_GAS_LIMIT, NativeCall, dispatch_native_call};
use crate::executor::native_outcome::native_outcome;

/// Longest acting DID a simulation accepts.
pub const MAX_SIMULATED_SIGNER_BYTES: usize = 256;

/// A module call to dry-run, within the bounds of a native submission.
/// Nothing authenticates the signer: the result says what that DID could do,
/// and authorizes nothing.
#[derive(Debug)]
pub struct NativeSimulateRequest {
    signer: String,
    target: Address,
    calldata: Bytes,
}

impl NativeSimulateRequest {
    /// A call to the module at `target`, acting as `signer`.
    ///
    /// The signer is recorded in the spelling the executor derives for its key.
    pub fn new(
        signer: &str,
        target: Address,
        calldata: Bytes,
    ) -> Result<Self, NativeSimulateError> {
        if signer.len() > MAX_SIMULATED_SIGNER_BYTES {
            return Err(NativeSimulateError::InvalidSigner(format!(
                "longer than {MAX_SIMULATED_SIGNER_BYTES} bytes"
            )));
        }
        Did::new(signer).map_err(|error| NativeSimulateError::InvalidSigner(error.to_string()))?;
        if !is_native_target(&target) {
            return Err(NativeSimulateError::UnknownTarget(target));
        }
        if calldata.len() > vera_domain::MAX_TX_BYTES {
            return Err(NativeSimulateError::CalldataTooLarge {
                got: calldata.len(),
                limit: vera_domain::MAX_TX_BYTES,
            });
        }
        Ok(Self {
            signer: vera_crypto::actor::canonical_did(signer).into_owned(),
            target,
            calldata,
        })
    }
}

/// What the module call would do if a request carrying it were executed now.
#[derive(Debug)]
pub struct NativeSimulateResult {
    /// Whether the call ran to completion.
    pub success: bool,
    /// Why the call was refused, as a receipt would record it; `None` on success.
    pub refusal: Option<Refusal>,
    /// Gas a receipt would record.
    pub gas_used: u64,
    /// Return data of a successful call.
    pub output: Bytes,
    /// Events a successful call would emit.
    pub logs: Vec<Log>,
}

/// A simulation request outside what a native submission may carry.
#[derive(Debug, Error)]
pub enum NativeSimulateError {
    /// The acting DID is not a supported identity.
    #[error("invalid signer: {0}")]
    InvalidSigner(String),
    /// The target is not a module address.
    #[error("unknown native target: {0}")]
    UnknownTarget(Address),
    /// The calldata is larger than a native request may carry.
    #[error("calldata is {got} bytes; at most {limit} are accepted")]
    CalldataTooLarge {
        /// Size of the calldata sent.
        got: usize,
        /// Largest accepted size.
        limit: usize,
    },
}

/// Dry-run a native module call against copies of the module values.
///
/// The call runs as it would in a block at the context's height and time,
/// under the signer's next sequence and a zero submission identifier, without
/// a signature or a sequence check. Its effects are discarded.
pub fn simulate_native_call<S: StateDbRead>(
    state: &S,
    context: &SimulationContext,
    request: &NativeSimulateRequest,
    modules: &ModuleState,
) -> Result<NativeSimulateResult, ExecutionError> {
    let tx_ctx = TxExecCtx {
        sequence: modules.nonces.get_nonce(&request.signer)?,
        tx_hash: vec![0; 32],
        signer: request.signer.clone(),
    };
    let (mut acp, mut bulletin, mut vera) = (
        modules.acp.clone(),
        modules.bulletin.clone(),
        modules.vera.clone(),
    );
    let dispatch = dispatch_native_call(
        &NativeCall {
            target: request.target,
            calldata: &request.calldata,
            max_active_members: context.max_active_members,
            gas_limit: NATIVE_TX_GAS_LIMIT,
        },
        &context.block(),
        &tx_ctx,
        &mut acp,
        &mut bulletin,
        &mut vera,
        &mut context.journal(state),
    );

    let outcome = native_outcome(request.target, dispatch)?;
    Ok(NativeSimulateResult {
        success: outcome.refusal.is_none(),
        refusal: outcome.refusal,
        gas_used: outcome.gas_used,
        output: outcome.output,
        logs: outcome.logs,
    })
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
