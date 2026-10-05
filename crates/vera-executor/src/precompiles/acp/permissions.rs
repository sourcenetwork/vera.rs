//! Native permission checks share an execution allowance across reads and evaluation.

use super::*;
use vera_modules::acp::PermissionBudget;

pub(super) fn dispatch(
    module: &mut AcpModule,
    vera: &mut VeraModule,
    block: &BlockExecCtx,
    tx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    let selector: [u8; 4] = input[..4].try_into().expect("dispatch checked selector");
    let base = if selector == IAcp::verifyAccessRequestCall::SELECTOR {
        READ_GAS
    } else {
        WRITE_GAS
    };
    let budget = PermissionBudget::new(
        gas_limit
            .checked_sub(base)
            .ok_or(PrecompileError::OutOfGas)?,
    );
    match selector {
        IAcp::bearerCheckAccessCall::SELECTOR => {
            let call = IAcp::bearerCheckAccessCall::abi_decode(input).map_err(decode_error)?;
            let request: AccessRequest =
                serde_json::from_slice(&call.request).map_err(|error| {
                    PrecompileError::Other(format!("access request JSON decode: {error}").into())
                })?;
            output(
                module.bearer_check_access_with_budget(
                    vera,
                    block,
                    tx,
                    &call.bearerToken,
                    &policy_id_to_string(&call.policyId),
                    &request,
                    &budget,
                ),
                &budget,
                base,
                |decision| IAcp::bearerCheckAccessCall::abi_encode_returns(&json_bytes(&decision)),
            )
        }
        IAcp::checkAccessCall::SELECTOR => {
            let call = IAcp::checkAccessCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx.signer)?;
            let request = AccessRequest {
                actor: Actor(did_from_actor(&call.actor)?),
                operations: build_operations(&call.resources, &call.objectIds, &call.permissions)?,
            };
            output(
                module.check_access_with_budget(
                    &creator,
                    &policy_id_to_string(&call.policyId),
                    &request,
                    block,
                    tx,
                    &budget,
                ),
                &budget,
                base,
                |decision| IAcp::checkAccessCall::abi_encode_returns(&json_bytes(&decision)),
            )
        }
        IAcp::verifyAccessRequestCall::SELECTOR => {
            let call = IAcp::verifyAccessRequestCall::abi_decode(input).map_err(decode_error)?;
            let request = AccessRequest {
                actor: Actor(did_from_actor(&call.actor)?),
                operations: build_operations(&call.resources, &call.objectIds, &call.permissions)?,
            };
            output(
                module.query_verify_access_request_with_budget(
                    &policy_id_to_string(&call.policyId),
                    &request,
                    &budget,
                ),
                &budget,
                base,
                |allowed| IAcp::verifyAccessRequestCall::abi_encode_returns(&allowed),
            )
        }
        _ => unreachable!("permission selector was checked"),
    }
}

fn output<T>(
    result: Result<T, impl core::fmt::Display>,
    budget: &PermissionBudget,
    base: u64,
    encode: impl FnOnce(T) -> Vec<u8>,
) -> DispatchReturn {
    if budget.is_exhausted() {
        return Err(PrecompileError::OutOfGas);
    }
    let gas = base
        .checked_add(budget.consumed())
        .ok_or(PrecompileError::OutOfGas)?;
    match result {
        Ok(value) => Ok(ok_dispatch(gas, encode(value), vec![])),
        Err(error) => {
            let mut result = err_dispatch(error);
            result.precompile.gas_used = gas;
            Ok(result)
        }
    }
}
