//! Delegated command lists: one authorization over ordered commands.

use super::*;
use crate::dispatch::ModuleError;
use vera_modules::acp::CommandBudget;

/// Decode `bearerPolicyCmds` and apply its commands in order, all or none. Each
/// command after the first pays the write base a separate call would pay.
pub(super) fn dispatch(
    module: &mut AcpModule,
    vera: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    budget: &CommandBudget,
) -> DispatchReturn {
    let call = IAcp::bearerPolicyCmdsCall::abi_decode(input).map_err(decode_error)?;
    let commands: Vec<(String, PolicyCmd)> =
        serde_json::from_slice(&call.commands).map_err(|e| {
            crate::dispatch::refusal::refused(
                vera_domain::RefusalKind::UndecodableInput,
                format!("command list JSON decode: {e}"),
            )
        })?;
    let further = u64::try_from(commands.len().saturating_sub(1)).unwrap_or(u64::MAX);
    if budget.reserve(further.saturating_mul(WRITE_GAS)).is_err() {
        return Err(ModuleError::OutOfGas);
    }
    match module.bearer_policy_cmds_with_budget(
        vera,
        block_ctx,
        tx_ctx,
        &call.bearerToken,
        &commands,
        budget,
    ) {
        Ok(results) => Ok(ok_dispatch(
            0,
            IAcp::bearerPolicyCmdsCall::abi_encode_returns(&json_bytes(&results)),
            vec![],
        )),
        Err(error) => Ok(err_dispatch(error)),
    }
}
