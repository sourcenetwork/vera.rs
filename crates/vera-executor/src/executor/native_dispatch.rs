//! One native module call, run against module values.

use std::panic::{AssertUnwindSafe, catch_unwind};

use alloy_primitives::Address;
use vera_modules::acp::AcpModule;
use vera_modules::bulletin::BulletinModule;
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::validator_registry::MembershipLimits;
use vera_modules::vera::VeraModule;

use crate::dispatch::{DispatchReturn, dispatch_to_module, storage_bounds_dispatch};

/// Gas budget for native BLS transactions dispatched to modules.
pub(crate) const NATIVE_TX_GAS_LIMIT: u64 = 1_000_000;

/// The module call a native request carries. The target is one of the
/// module addresses, which the caller has checked.
pub(crate) struct NativeCall<'a> {
    pub(crate) target: Address,
    pub(crate) calldata: &'a [u8],
    pub(crate) limits: MembershipLimits,
    /// Gas the call may use.
    pub(crate) gas_limit: u64,
}

/// Whether a module call ran to completion: not a refusal, an exhausted allowance, an error or a panic.
pub(crate) fn succeeded(dispatch: &std::thread::Result<DispatchReturn>) -> bool {
    matches!(dispatch, Ok(Ok(result)) if result.output.status.is_success())
}

/// Run the call, keeping its module effects only if it succeeds.
pub(crate) fn dispatch_native_call(
    call: &NativeCall<'_>,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    acp: &mut AcpModule,
    bulletin: &mut BulletinModule,
    vera: &mut VeraModule,
) -> std::thread::Result<DispatchReturn> {
    let before = (acp.clone(), bulletin.clone(), vera.clone());
    let mut dispatch_result = catch_unwind(AssertUnwindSafe(|| {
        dispatch_to_module(
            acp,
            bulletin,
            vera,
            call.target,
            call.calldata,
            block_ctx,
            tx_ctx,
            call.limits,
            call.gas_limit,
        )
        .expect("target validated above")
    }));

    if succeeded(&dispatch_result)
        && !(acp.store().changes_fit_native_bounds(before.0.store())
            && bulletin.store().changes_fit_native_bounds(before.1.store())
            && vera.store().changes_fit_native_bounds(before.2.store()))
    {
        // The call ran to completion, so it is charged what it used.
        let used = match &dispatch_result {
            Ok(Ok(result)) => result.output.gas_used,
            _ => unreachable!("checked that the call succeeded"),
        };
        dispatch_result = Ok(Ok(storage_bounds_dispatch(used)));
    }

    // An exhausted allowance is a failure like a refusal: it commits nothing.
    if !succeeded(&dispatch_result) {
        (*acp, *bulletin, *vera) = before;
    }
    dispatch_result
}
