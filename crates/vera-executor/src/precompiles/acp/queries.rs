//! Collection queries retain read charges even when filtering returns no records.

use super::*;

pub(super) const fn handles(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        IAcp::getPolicyIdsCall::SELECTOR
            | IAcp::getPolicyCall::SELECTOR
            | IAcp::getPoliciesCall::SELECTOR
            | IAcp::getPoliciesPageCall::SELECTOR
            | IAcp::getRelationshipsPageCall::SELECTOR
            | IAcp::getPolicyCatalogueCall::SELECTOR
            | IAcp::filterRelationshipsCall::SELECTOR
            | IAcp::hasRelationshipCall::SELECTOR
    )
}

pub(super) fn dispatch(module: &AcpModule, input: &[u8], gas_limit: u64) -> DispatchReturn {
    let allowance = gas_limit
        .checked_sub(READ_GAS)
        .ok_or(PrecompileError::OutOfGas)?;
    let budget = QueryBudget::new(allowance);
    let selector: [u8; 4] = input[..4].try_into().expect("selector checked by parent");
    match selector {
        IAcp::getPolicyIdsCall::SELECTOR => {
            IAcp::getPolicyIdsCall::abi_decode(input).map_err(decode_error)?;
            output(
                module.query_policy_ids_with_budget(&budget),
                &budget,
                |ids| IAcp::getPolicyIdsCall::abi_encode_returns(&ids),
            )
        }
        IAcp::getPolicyCall::SELECTOR => {
            let call = IAcp::getPolicyCall::abi_decode(input).map_err(decode_error)?;
            output(
                module.query_policy_with_budget(&policy_id_to_string(&call.policyId), &budget),
                &budget,
                |record| IAcp::getPolicyCall::abi_encode_returns(&json_bytes(&record)),
            )
        }
        IAcp::getPoliciesCall::SELECTOR => {
            IAcp::getPoliciesCall::abi_decode(input).map_err(decode_error)?;
            output(
                module.query_policies_with_budget(&budget),
                &budget,
                |records| IAcp::getPoliciesCall::abi_encode_returns(&json_bytes(&records)),
            )
        }
        IAcp::getPoliciesPageCall::SELECTOR => {
            let call = IAcp::getPoliciesPageCall::abi_decode(input).map_err(decode_error)?;
            output(
                module.query_policies_page_with_budget(
                    (!call.cursor.is_empty()).then_some(call.cursor.as_ref()),
                    &budget,
                ),
                &budget,
                |page| IAcp::getPoliciesPageCall::abi_encode_returns(&json_bytes(&page)),
            )
        }
        IAcp::getRelationshipsPageCall::SELECTOR => {
            let call = IAcp::getRelationshipsPageCall::abi_decode(input).map_err(decode_error)?;
            let request = serde_json::from_slice(&call.request).map_err(|error| {
                PrecompileError::Other(format!("invalid relationship query: {error}").into())
            })?;
            output(
                module.query_relationships_page_with_budget(
                    &policy_id_to_string(&call.policyId),
                    &request,
                    &budget,
                ),
                &budget,
                |page| IAcp::getRelationshipsPageCall::abi_encode_returns(&json_bytes(&page)),
            )
        }
        IAcp::getPolicyCatalogueCall::SELECTOR => {
            let call = IAcp::getPolicyCatalogueCall::abi_decode(input).map_err(decode_error)?;
            output(
                module.query_policy_catalogue_with_budget(
                    &policy_id_to_string(&call.policyId),
                    &budget,
                ),
                &budget,
                |catalogue| {
                    IAcp::getPolicyCatalogueCall::abi_encode_returns(&json_bytes(&catalogue))
                },
            )
        }
        IAcp::filterRelationshipsCall::SELECTOR => {
            let call = IAcp::filterRelationshipsCall::abi_decode(input).map_err(decode_error)?;
            let selector = build_relationship_selector(
                &call.resource,
                &call.objectId,
                &call.relation,
                &call.actor,
            )?;
            output(
                module.query_filter_relationships_with_budget(
                    &policy_id_to_string(&call.policyId),
                    &selector,
                    &budget,
                ),
                &budget,
                |records| IAcp::filterRelationshipsCall::abi_encode_returns(&json_bytes(&records)),
            )
        }
        IAcp::hasRelationshipCall::SELECTOR => {
            let call = IAcp::hasRelationshipCall::abi_decode(input).map_err(decode_error)?;
            let actor = did_from_actor(&call.actor)?;
            let selector = RelationshipSelector {
                object_selector: Some(vera_modules::acp::types::ObjectSelector::Exact(Object {
                    resource: call.resource,
                    id: call.objectId,
                })),
                relation_selector: Some(vera_modules::acp::types::RelationSelector::Exact(
                    call.relation,
                )),
                subject_selector: Some(vera_modules::acp::types::SubjectSelector::Exact(
                    acp::Subject::entity(actor),
                )),
            };
            output(
                module.query_filter_relationships_with_budget(
                    &policy_id_to_string(&call.policyId),
                    &selector,
                    &budget,
                ),
                &budget,
                |records| IAcp::hasRelationshipCall::abi_encode_returns(&!records.is_empty()),
            )
        }
        _ => Err(PrecompileError::Other("unknown ACP query selector".into())),
    }
}

fn output<T>(
    result: Result<T, impl core::fmt::Display>,
    budget: &QueryBudget,
    encode: impl FnOnce(T) -> Vec<u8>,
) -> DispatchReturn {
    if budget.is_exhausted() {
        return Err(PrecompileError::OutOfGas);
    }
    let gas_used = READ_GAS
        .checked_add(budget.consumed())
        .ok_or(PrecompileError::OutOfGas)?;
    match result {
        Ok(value) => Ok(ok_dispatch(gas_used, encode(value), vec![])),
        Err(error) => {
            let mut result = err_dispatch(error);
            result.precompile.gas_used = gas_used;
            Ok(result)
        }
    }
}
