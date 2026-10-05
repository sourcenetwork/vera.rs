//! Policy creation reserves input and storage work across all creation selectors.

use super::*;
use vera_modules::acp::{
    PolicyCreateBudget,
    types::{PolicyCreation, PolicyRecord},
};

pub(super) const fn handles(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        IAcp::createPolicyCall::SELECTOR
            | IAcp::createPolicyWithOptionsCall::SELECTOR
            | IAcp::bearerCreatePolicyCall::SELECTOR
    )
}

pub(super) fn dispatch(
    module: &mut AcpModule,
    vera: &mut VeraModule,
    block: &BlockExecCtx,
    tx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    let budget = PolicyCreateBudget::new(
        gas_limit
            .checked_sub(WRITE_GAS)
            .ok_or(PrecompileError::OutOfGas)?,
    );
    // Reserve the whole leaf before any owned ABI or JSON decoding, including
    // options whitespace and fields ultimately rejected by semantic validation.
    budget
        .input(input.len())
        .map_err(|_| PrecompileError::OutOfGas)?;
    let selector: [u8; 4] = input[..4].try_into().expect("dispatch checked selector");
    let result = create(module, vera, block, tx, selector, input, &budget);
    if budget.is_exhausted() {
        return Err(PrecompileError::OutOfGas);
    }
    let gas = WRITE_GAS
        .checked_add(budget.consumed())
        .ok_or(PrecompileError::OutOfGas)?;
    let record = match result {
        Ok(record) => record,
        Err(error) => {
            let mut result = err_dispatch(error);
            result.precompile.gas_used = gas;
            return Ok(result);
        }
    };
    let output = json_bytes(&record);
    let (bytes, log) = match selector {
        IAcp::bearerCreatePolicyCall::SELECTOR => (
            IAcp::bearerCreatePolicyCall::abi_encode_returns(&output),
            event_log(
                ACP_ADDRESS,
                &IAcp::DelegatedPolicyCreated {
                    policyId: record.policy.id.parse().map_err(|_| {
                        PrecompileError::Other("invalid created policy identifier".into())
                    })?,
                    creator: record.metadata.owner_did,
                },
            ),
        ),
        _ => (
            if selector == IAcp::createPolicyCall::SELECTOR {
                IAcp::createPolicyCall::abi_encode_returns(&output)
            } else {
                IAcp::createPolicyWithOptionsCall::abi_encode_returns(&output)
            },
            event_log(
                ACP_ADDRESS,
                &IAcp::PolicyCreated {
                    policyId: alloy_primitives::keccak256(record.policy.id.as_bytes()),
                    creator: tx.signer.clone(),
                },
            ),
        ),
    };
    Ok(ok_dispatch(gas, bytes, vec![log]))
}

#[allow(clippy::too_many_arguments)]
fn create(
    module: &mut AcpModule,
    vera: &mut VeraModule,
    block: &BlockExecCtx,
    tx: &TxExecCtx,
    selector: [u8; 4],
    input: &[u8],
    budget: &PolicyCreateBudget,
) -> Result<PolicyRecord, String> {
    match selector {
        IAcp::bearerCreatePolicyCall::SELECTOR => {
            let call = IAcp::bearerCreatePolicyCall::abi_decode(input)
                .map_err(|error| decode_error(error).to_string())?;
            let policy = std::str::from_utf8(&call.policy)
                .map_err(|_| "invalid UTF-8 in policy".to_string())?;
            module
                .bearer_create_policy_with_budget(
                    vera,
                    block,
                    tx,
                    &call.bearerToken,
                    policy,
                    marshal_type_from_u8(call.marshalType),
                    budget,
                )
                .map_err(|error| error.to_string())
        }
        IAcp::createPolicyCall::SELECTOR => {
            let call = IAcp::createPolicyCall::abi_decode(input)
                .map_err(|error| decode_error(error).to_string())?;
            let request = PolicyCreation {
                policy: String::from_utf8(call.policy.to_vec())
                    .map_err(|_| "invalid UTF-8 in policy".to_string())?,
                marshal_type: marshal_type_from_u8(call.marshalType),
                required_specification: None,
                metadata: Default::default(),
            };
            let actor = did_from_signer(&tx.signer).map_err(|error| error.to_string())?;
            module
                .execute_create_policy_with_budget(&actor, &request, block, tx, budget)
                .map_err(|error| error.to_string())
        }
        IAcp::createPolicyWithOptionsCall::SELECTOR => {
            let call = IAcp::createPolicyWithOptionsCall::abi_decode(input)
                .map_err(|error| decode_error(error).to_string())?;
            let request = serde_json::from_slice(&call.request)
                .map_err(|error| format!("invalid policy request: {error}"))?;
            let actor = did_from_signer(&tx.signer).map_err(|error| error.to_string())?;
            module
                .execute_create_policy_with_budget(&actor, &request, block, tx, budget)
                .map_err(|error| error.to_string())
        }
        _ => unreachable!("creation selector was checked"),
    }
}
