//! Policy validation reserves input work before decoding and compilation.

use super::oog_dispatch;
use super::*;
use alloy_sol_types::{SolType, sol_data::Uint};
use vera_modules::acp::PolicyCreateBudget;

pub(super) fn dispatch(module: &AcpModule, input: &[u8], gas_limit: u64) -> DispatchReturn {
    let Some(allowance) = gas_limit.checked_sub(READ_GAS) else {
        return Ok(oog_dispatch());
    };
    let budget = PolicyCreateBudget::new(allowance);
    if budget.input(input.len()).is_err() {
        return Ok(oog_dispatch());
    }
    let body = &input[4..];
    body.get(..64)
        .ok_or_else(|| PrecompileError::Fatal("invalid policy validation ABI".to_string()))?;
    let policy = leaf::bytes(body, 0)?;
    if budget.input(policy.len()).is_err() {
        return Ok(oog_dispatch());
    }
    let marshal_type = Uint::<8>::abi_decode(&body[32..64]).map_err(decode_error)?;
    let policy = std::str::from_utf8(policy)
        .map_err(|_| PrecompileError::Fatal("invalid UTF-8 in policy".to_string()))?;
    let result = module.query_validate_policy(policy, marshal_type_from_u8(marshal_type));
    let Some(gas) = READ_GAS.checked_add(budget.consumed()) else {
        return Ok(oog_dispatch());
    };
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
