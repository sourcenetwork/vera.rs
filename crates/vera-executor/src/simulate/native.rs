//! Unsigned dry run of a native module call as a named acting DID.

use alloy_primitives::{Address, Bytes, Log};
use revm::precompile::PrecompileStatus;
use thiserror::Error;
use vera_identity::Did;
use vera_modules::ModuleState;
use vera_modules::types::TxExecCtx;
use vera_traits::StateDbRead;

use super::SimulationContext;
use crate::ExecutionError;
use crate::executor::native_authentication::is_native_target;
use crate::executor::native_dispatch::{NATIVE_TX_GAS_LIMIT, NativeCall, dispatch_native_call};
use crate::precompiles::{internal_fault_reason, is_out_of_gas, recoverable_message};

/// Longest acting DID a simulation accepts.
pub const MAX_SIMULATED_SIGNER_BYTES: usize = 256;

const OUT_OF_GAS: &str = "out of gas";

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
    /// Why the call was refused; `None` on success.
    pub reason: Option<String>,
    /// Gas a receipt would record: the whole allowance for a refused call.
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
        },
        &context.block(),
        &tx_ctx,
        &mut acp,
        &mut bulletin,
        &mut vera,
        &mut context.evm(state),
    );

    let refused = |reason: String| NativeSimulateResult {
        success: false,
        reason: Some(reason),
        gas_used: NATIVE_TX_GAS_LIMIT,
        output: Bytes::new(),
        logs: Vec::new(),
    };
    match dispatch {
        Ok(Ok(result)) => match result.precompile.status {
            PrecompileStatus::Success => Ok(NativeSimulateResult {
                success: true,
                reason: None,
                gas_used: result.precompile.gas_used,
                output: result.precompile.bytes,
                logs: result.logs,
            }),
            PrecompileStatus::Revert => Ok(refused(
                String::from_utf8_lossy(&result.precompile.bytes).into_owned(),
            )),
            PrecompileStatus::Halt(_) => Ok(refused(OUT_OF_GAS.into())),
        },
        Ok(Err(error)) if is_out_of_gas(&error) => Ok(refused(OUT_OF_GAS.into())),
        Ok(Err(error)) => internal_fault_reason(&error).map_or_else(
            || Ok(refused(recoverable_message(&error))),
            |fault| Err(ExecutionError::TxExecution(fault)),
        ),
        Err(_) => Ok(refused("module execution failed".into())),
    }
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
