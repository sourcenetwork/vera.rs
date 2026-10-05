use super::*;
use vera_modules::acp::types::SuppliedMetadata;

pub(super) const fn handles(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        IAcp::deletePolicyCall::SELECTOR
            | IAcp::editPolicyMetadataCall::SELECTOR
            | IAcp::getObjectRegistrationCall::SELECTOR
            | IAcp::evaluateTheoremCall::SELECTOR
    )
}

pub(super) fn dispatch(
    module: &mut AcpModule,
    block: &BlockExecCtx,
    tx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    let selector: [u8; 4] = input[..4].try_into().expect("selector checked by parent");
    let write = matches!(
        selector,
        IAcp::deletePolicyCall::SELECTOR | IAcp::editPolicyMetadataCall::SELECTOR
    );
    let gas = if write { WRITE_GAS } else { READ_GAS };
    if gas_limit < gas {
        return Err(PrecompileError::OutOfGas);
    }
    match selector {
        IAcp::deletePolicyCall::SELECTOR => {
            let call = IAcp::deletePolicyCall::abi_decode(input).map_err(decode_error)?;
            let actor = did_from_signer(&tx.signer)?;
            match module.delete_policy(&actor, &policy_id_to_string(&call.policyId)) {
                Ok(found) => Ok(ok_dispatch(
                    gas,
                    IAcp::deletePolicyCall::abi_encode_returns(&found),
                    if found {
                        vec![event_log(
                            ACP_ADDRESS,
                            &IAcp::PolicyDeleted {
                                policyId: call.policyId,
                            },
                        )]
                    } else {
                        vec![]
                    },
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IAcp::editPolicyMetadataCall::SELECTOR => {
            let call = IAcp::editPolicyMetadataCall::abi_decode(input).map_err(decode_error)?;
            let metadata: SuppliedMetadata =
                serde_json::from_slice(&call.metadata).map_err(|error| {
                    PrecompileError::Other(format!("invalid policy metadata: {error}").into())
                })?;
            let actor = did_from_signer(&tx.signer)?;
            match module.edit_policy_metadata(
                &actor,
                &policy_id_to_string(&call.policyId),
                metadata,
                &block.timestamp,
            ) {
                Ok(record) => Ok(ok_dispatch(
                    gas,
                    IAcp::editPolicyMetadataCall::abi_encode_returns(&json_bytes(&record)),
                    vec![event_log(
                        ACP_ADDRESS,
                        &IAcp::PolicyMetadataEdited {
                            policyId: call.policyId,
                        },
                    )],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IAcp::evaluateTheoremCall::SELECTOR => {
            let call = IAcp::evaluateTheoremCall::abi_decode(input).map_err(decode_error)?;
            match module.evaluate_theorem(&policy_id_to_string(&call.policyId), &call.source) {
                Ok(value) => Ok(ok_dispatch(
                    gas,
                    IAcp::evaluateTheoremCall::abi_encode_returns(&json_bytes(&value)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IAcp::getObjectRegistrationCall::SELECTOR => {
            let call = IAcp::getObjectRegistrationCall::abi_decode(input).map_err(decode_error)?;
            match module.query_object_registration(
                &policy_id_to_string(&call.policyId),
                &Object {
                    resource: call.resource,
                    id: call.objectId,
                },
            ) {
                Ok(value) => Ok(ok_dispatch(
                    gas,
                    IAcp::getObjectRegistrationCall::abi_encode_returns(&json_bytes(&value)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }

        _ => Err(PrecompileError::Other(
            "unknown ACP lifecycle selector".into(),
        )),
    }
}
