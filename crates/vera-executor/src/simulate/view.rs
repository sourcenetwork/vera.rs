//! Signerless, read-only module call against copies of the module values.

use alloy_primitives::{Address, Bytes};
use thiserror::Error;
use vera_domain::Refusal;
use vera_modules::ModuleState;
use vera_modules::types::TxExecCtx;
use vera_traits::StateDbRead;

use super::SimulationContext;
use crate::ExecutionError;
use crate::executor::native_authentication::is_native_target;
use crate::executor::native_dispatch::{NativeCall, dispatch_native_call};
use crate::executor::native_outcome::native_outcome;

/// A module call to evaluate without a signer, within the bounds of a native
/// submission.
#[derive(Debug)]
pub struct ViewCall {
    target: Address,
    calldata: Bytes,
}

impl ViewCall {
    /// A call to the module at `target`.
    pub fn new(target: Address, calldata: Bytes) -> Result<Self, ViewCallError> {
        if !is_native_target(&target) {
            return Err(ViewCallError::UnknownTarget(target));
        }
        if calldata.len() > vera_domain::MAX_TX_BYTES {
            return Err(ViewCallError::CalldataTooLarge {
                got: calldata.len(),
                limit: vera_domain::MAX_TX_BYTES,
            });
        }
        Ok(Self { target, calldata })
    }
}

/// What a module answered a signerless call with.
#[derive(Debug)]
pub struct ViewCallResult {
    /// Return data of a call that ran to completion.
    pub output: Bytes,
    /// Why the call was refused; `None` when it ran to completion.
    pub refusal: Option<Refusal>,
}

/// A view call outside what a native submission may carry.
#[derive(Debug, Error)]
pub enum ViewCallError {
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

/// Evaluate a module call that carries no signer.
///
/// The call observes the context's height and time and may use the context's
/// view allowance. A method that needs a signer refuses it as
/// unauthenticated. Every effect is discarded, and no gas is charged.
pub fn view_call<S: StateDbRead>(
    state: &S,
    context: &SimulationContext,
    call: &ViewCall,
    modules: &ModuleState,
) -> Result<ViewCallResult, ExecutionError> {
    let tx_ctx = TxExecCtx {
        sequence: 0,
        tx_hash: vec![0; 32],
        signer: String::new(),
    };
    let (mut acp, mut bulletin, mut vera) = (
        modules.acp.clone(),
        modules.bulletin.clone(),
        modules.vera.clone(),
    );
    let dispatch = dispatch_native_call(
        &NativeCall {
            target: call.target,
            calldata: &call.calldata,
            max_active_members: context.max_active_members,
            gas_limit: context.view_gas_limit,
        },
        &context.block(),
        &tx_ctx,
        &mut acp,
        &mut bulletin,
        &mut vera,
        &mut context.journal(state),
    );

    let outcome = native_outcome(call.target, dispatch)?;
    Ok(ViewCallResult {
        output: outcome.output,
        refusal: outcome.refusal,
    })
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
