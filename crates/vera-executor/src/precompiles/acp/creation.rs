//! Policy creation reserves input and storage work across all creation selectors.

use super::oog_dispatch;
use super::*;
use crate::precompiles::refusal::{Refuse, Stated, kind_of};
use vera_domain::RefusalKind;
use vera_modules::acp::{
    PolicyCreateBudget,
    types::{PolicyCreation, PolicyNonce, PolicyRecord},
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
    let Some(allowance) = gas_limit.checked_sub(WRITE_GAS) else {
        return Ok(oog_dispatch());
    };
    let budget = PolicyCreateBudget::new(allowance);
    // Reserve the whole leaf before any owned ABI or JSON decoding, including
    // options whitespace and fields ultimately rejected by semantic validation.
    if budget.input(input.len()).is_err() {
        return Ok(oog_dispatch());
    }
    let selector: [u8; 4] = input[..4].try_into().expect("dispatch checked selector");
    let result = create(module, vera, block, tx, selector, input, &budget);
    if let Err(CreationError::Fault(fault)) = result {
        return Err(fault);
    }
    if budget.is_exhausted() {
        return Ok(oog_dispatch());
    }
    let Some(gas) = WRITE_GAS.checked_add(budget.consumed()) else {
        return Ok(oog_dispatch());
    };
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
                        crate::precompiles::internal_fault("invalid created policy identifier")
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

/// Why a creation produced no record.
#[derive(Debug, thiserror::Error)]
enum CreationError {
    /// The caller's request is refused and reverts.
    #[error("{1}")]
    Refused(RefusalKind, String),
    /// The node's own fault, which fails the block.
    #[error("{0}")]
    Fault(PrecompileError),
}

impl Refuse for CreationError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::Refused(kind, _) => *kind,
            Self::Fault(_) => RefusalKind::StateError,
        }
    }
}

fn refused(error: impl Refuse) -> CreationError {
    CreationError::Refused(error.refusal_kind(), error.to_string())
}

/// A refusal raised as an error, reported as revm displays it.
fn refused_by(error: &PrecompileError) -> CreationError {
    CreationError::Refused(
        kind_of(error),
        format!("fatal: {}", recoverable_message(error)),
    )
}

fn creator(tx: &TxExecCtx) -> Result<Did, CreationError> {
    did_from_signer(&tx.signer).map_err(|error| {
        if internal_fault_reason(&error).is_some() {
            CreationError::Fault(error)
        } else {
            refused_by(&error)
        }
    })
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
) -> Result<PolicyRecord, CreationError> {
    match selector {
        IAcp::bearerCreatePolicyCall::SELECTOR => {
            let call = IAcp::bearerCreatePolicyCall::abi_decode(input)
                .map_err(|error| refused_by(&decode_error(error)))?;
            let policy = std::str::from_utf8(&call.policy).map_err(|_| {
                refused(Stated(
                    RefusalKind::UndecodableInput,
                    "invalid UTF-8 in policy",
                ))
            })?;
            module
                .bearer_create_policy_with_budget(
                    vera,
                    block,
                    tx,
                    &call.bearerToken,
                    policy,
                    marshal_type_from_u8(call.marshalType),
                    PolicyNonce(call.nonce.0),
                    budget,
                )
                .map_err(refused)
        }
        IAcp::createPolicyCall::SELECTOR => {
            let call = IAcp::createPolicyCall::abi_decode(input)
                .map_err(|error| refused_by(&decode_error(error)))?;
            let request = PolicyCreation {
                policy: String::from_utf8(call.policy.to_vec()).map_err(|_| {
                    refused(Stated(
                        RefusalKind::UndecodableInput,
                        "invalid UTF-8 in policy",
                    ))
                })?,
                marshal_type: marshal_type_from_u8(call.marshalType),
                nonce: PolicyNonce(call.nonce.0),
                required_specification: None,
                metadata: Default::default(),
            };
            let actor = creator(tx)?;
            module
                .execute_create_policy_with_budget(&actor, &request, block, tx, budget)
                .map_err(refused)
        }
        IAcp::createPolicyWithOptionsCall::SELECTOR => {
            let call = IAcp::createPolicyWithOptionsCall::abi_decode(input)
                .map_err(|error| refused_by(&decode_error(error)))?;
            let request = serde_json::from_slice(&call.request).map_err(|error| {
                refused(Stated(
                    RefusalKind::UndecodableInput,
                    format!("invalid policy request: {error}"),
                ))
            })?;
            let actor = creator(tx)?;
            module
                .execute_create_policy_with_budget(&actor, &request, block, tx, budget)
                .map_err(refused)
        }
        _ => unreachable!("creation selector was checked"),
    }
}
