//! Policy validation reserves input work before decoding and compilation.

use super::*;
use alloy_sol_types::{SolType, sol_data::Uint};
use vera_modules::acp::PolicyCreateBudget;

pub(super) fn dispatch(module: &AcpModule, input: &[u8], gas_limit: u64) -> DispatchReturn {
    let budget = PolicyCreateBudget::new(
        gas_limit
            .checked_sub(READ_GAS)
            .ok_or(PrecompileError::OutOfGas)?,
    );
    budget
        .input(input.len())
        .map_err(|_| PrecompileError::OutOfGas)?;
    let body = &input[4..];
    body.get(..64)
        .ok_or_else(|| PrecompileError::Other("invalid policy validation ABI".into()))?;
    let policy = leaf::bytes(body, 0)?;
    budget
        .input(policy.len())
        .map_err(|_| PrecompileError::OutOfGas)?;
    let marshal_type = Uint::<8>::abi_decode(&body[32..64]).map_err(decode_error)?;
    let policy = std::str::from_utf8(policy)
        .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;
    let result = module.query_validate_policy(policy, marshal_type_from_u8(marshal_type));
    let gas = READ_GAS
        .checked_add(budget.consumed())
        .ok_or(PrecompileError::OutOfGas)?;
    let (valid, reason, _) = match result {
        Ok(result) => result,
        Err(error) => {
            let mut result = err_dispatch(error);
            result.precompile.gas_used = gas;
            return Ok(result);
        }
    };
    let output =
        IAcp::validatePolicyCall::abi_encode_returns(&IAcp::validatePolicyReturn { valid, reason });
    Ok(ok_dispatch(gas, output, vec![]))
}
