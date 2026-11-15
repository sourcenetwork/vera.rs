//! One native module call, run against module values and the EVM journal.

use std::panic::{AssertUnwindSafe, catch_unwind};

use alloy_primitives::Address;
use revm::context_interface::{ContextTr, JournalTr};
use vera_modules::acp::AcpModule;
use vera_modules::bulletin::BulletinModule;
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::vera::VeraModule;

use crate::precompiles::{
    DispatchReturn, VALIDATOR_REGISTRY_ADDRESS, dispatch_to_module, err_dispatch, internal_fault,
    validator_registry,
};

/// Gas budget for native BLS transactions dispatched to modules.
pub(crate) const NATIVE_TX_GAS_LIMIT: u64 = 1_000_000;

/// The module call a native request carries. The target is one of the
/// module addresses, which the caller has checked.
pub(crate) struct NativeCall<'a> {
    pub(crate) target: Address,
    pub(crate) calldata: &'a [u8],
    pub(crate) max_active_members: u32,
}

/// Whether a module call ran to completion: not a revert, a halt, an error or a panic.
pub(crate) fn succeeded(dispatch: &std::thread::Result<DispatchReturn>) -> bool {
    matches!(dispatch, Ok(Ok(result)) if result.precompile.status.is_success())
}

/// Run the call, keeping its module and journal effects only if it succeeds.
pub(crate) fn dispatch_native_call<CTX: ContextTr>(
    call: &NativeCall<'_>,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    acp: &mut AcpModule,
    bulletin: &mut BulletinModule,
    vera: &mut VeraModule,
    journal: &mut CTX,
) -> std::thread::Result<DispatchReturn> {
    let before = (acp.clone(), bulletin.clone(), vera.clone());
    let checkpoint = journal.journal_mut().checkpoint();
    let mut dispatch_result = catch_unwind(AssertUnwindSafe(|| {
        if call.target == VALIDATOR_REGISTRY_ADDRESS {
            journal
                .journal_mut()
                .load_account(VALIDATOR_REGISTRY_ADDRESS)
                .map_err(|error| {
                    internal_fault(format!("membership account read failed: {error:?}"))
                })?;
            journal
                .journal_mut()
                .touch_account(VALIDATOR_REGISTRY_ADDRESS);
            return validator_registry::dispatch_with_journal(
                journal,
                acp,
                vera,
                call.max_active_members,
                tx_ctx,
                call.calldata,
                NATIVE_TX_GAS_LIMIT,
            );
        }
        dispatch_to_module(
            acp,
            bulletin,
            vera,
            call.target,
            call.calldata,
            block_ctx,
            tx_ctx,
            NATIVE_TX_GAS_LIMIT,
        )
        .expect("target validated above")
    }));

    if succeeded(&dispatch_result)
        && !(acp.store().changes_fit_native_bounds(before.0.store())
            && bulletin.store().changes_fit_native_bounds(before.1.store())
            && vera.store().changes_fit_native_bounds(before.2.store()))
    {
        let mut rejected = err_dispatch("module record exceeds native storage bounds");
        rejected.precompile.gas_used = NATIVE_TX_GAS_LIMIT;
        dispatch_result = Ok(Ok(rejected));
    }

    // A halt is a failure like a revert: an exhausted allowance commits nothing.
    if succeeded(&dispatch_result) {
        journal.journal_mut().checkpoint_commit();
    } else {
        (*acp, *bulletin, *vera) = before;
        journal.journal_mut().checkpoint_revert(checkpoint);
    }
    dispatch_result
}
