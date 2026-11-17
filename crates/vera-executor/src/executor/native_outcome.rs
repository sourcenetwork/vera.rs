//! What a native module call's receipt records: its charge, effects and refusal.

use alloy_primitives::{Address, Bytes, Log};
use revm::precompile::PrecompileStatus;
use vera_domain::{Refusal, RefusalKind, RefusingModule};

use super::native_dispatch::NATIVE_TX_GAS_LIMIT;
use crate::ExecutionError;
use crate::precompiles::{
    ACP_ADDRESS, BULLETIN_ADDRESS, DispatchReturn, VALIDATOR_REGISTRY_ADDRESS, VERA_ADDRESS,
    internal_fault_reason, is_out_of_gas, recoverable_message, refusal::kind_of,
};

/// Least gas a refused native request is charged: the base charge of a module
/// write. Refusals of fixed-charge methods report no work of their own.
pub(crate) const NATIVE_REFUSAL_GAS: u64 = 5_000;

const OUT_OF_GAS: &str = "out of gas";
const MODULE_FAILED: &str = "module execution failed";

/// The outcome of one native module call, as its receipt records it.
#[derive(Debug)]
pub(crate) struct NativeOutcome {
    /// Gas the receipt charges.
    pub(crate) gas_used: u64,
    /// Return data of a successful call.
    pub(crate) output: Bytes,
    /// Events of a successful call.
    pub(crate) logs: Vec<Log>,
    /// Why the call was refused; `None` on success.
    pub(crate) refusal: Option<Refusal>,
}

/// Classify a dispatched native call. A fault of the node is an error, which
/// fails the block; every other failure is a refusal of the request.
///
/// A refusal is charged what the call reported using, and at least
/// [`NATIVE_REFUSAL_GAS`]. An exhausted allowance and a module failure, which
/// report no usage, are charged the whole allowance.
pub(crate) fn native_outcome(
    target: Address,
    dispatch: std::thread::Result<DispatchReturn>,
) -> Result<NativeOutcome, ExecutionError> {
    let module = refusing_module(target);
    let refused = |kind: RefusalKind, message: String, reported: u64| {
        let gas_used = if kind.charges_full_allowance() {
            NATIVE_TX_GAS_LIMIT
        } else {
            reported.clamp(NATIVE_REFUSAL_GAS, NATIVE_TX_GAS_LIMIT)
        };
        NativeOutcome {
            gas_used,
            output: Bytes::new(),
            logs: Vec::new(),
            refusal: Some(Refusal::new(module, kind, message)),
        }
    };
    Ok(match dispatch {
        Ok(Ok(result)) => match result.precompile.status {
            PrecompileStatus::Success => NativeOutcome {
                gas_used: result.precompile.gas_used,
                output: result.precompile.bytes,
                logs: result.logs,
                refusal: None,
            },
            PrecompileStatus::Revert => refused(
                result.refusal.unwrap_or(RefusalKind::InvalidArgument),
                String::from_utf8_lossy(&result.precompile.bytes).into_owned(),
                result.precompile.gas_used,
            ),
            PrecompileStatus::Halt(_) => refused(RefusalKind::OutOfGas, OUT_OF_GAS.into(), 0),
        },
        Ok(Err(error)) if is_out_of_gas(&error) => {
            refused(RefusalKind::OutOfGas, OUT_OF_GAS.into(), 0)
        }
        Ok(Err(error)) => {
            if let Some(fault) = internal_fault_reason(&error) {
                return Err(ExecutionError::TxExecution(fault));
            }
            refused(kind_of(&error), recoverable_message(&error), 0)
        }
        Err(_) => {
            tracing::warn!("native module call panicked");
            refused(RefusalKind::ModuleFailed, MODULE_FAILED.into(), 0)
        }
    })
}

fn refusing_module(target: Address) -> RefusingModule {
    match target {
        ACP_ADDRESS => RefusingModule::Acp,
        BULLETIN_ADDRESS => RefusingModule::Bulletin,
        VERA_ADDRESS => RefusingModule::Vera,
        VALIDATOR_REGISTRY_ADDRESS => RefusingModule::ValidatorRegistry,
        _ => unreachable!("native targets are module addresses"),
    }
}
