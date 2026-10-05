use super::*;
use vera_modules::acp::types::SuppliedMetadata;

pub(super) const fn handles(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        IAcp::executePolicyCommandCall::SELECTOR
            | IAcp::createPolicyWithOptionsCall::SELECTOR
            | IAcp::transferObjectCall::SELECTOR
            | IAcp::deletePolicyCall::SELECTOR
            | IAcp::editPolicyMetadataCall::SELECTOR
            | IAcp::checkManagementAuthorityCall::SELECTOR
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
        IAcp::executePolicyCommandCall::SELECTOR
            | IAcp::createPolicyWithOptionsCall::SELECTOR
            | IAcp::transferObjectCall::SELECTOR
            | IAcp::deletePolicyCall::SELECTOR
            | IAcp::editPolicyMetadataCall::SELECTOR
    );
    let gas = if write { WRITE_GAS } else { READ_GAS };
    if gas_limit < gas {
        return Err(PrecompileError::OutOfGas);
    }
    match selector {
        IAcp::executePolicyCommandCall::SELECTOR => {
            let call = IAcp::executePolicyCommandCall::abi_decode(input).map_err(decode_error)?;
            let request = serde_json::from_slice(&call.request).map_err(|error| {
                PrecompileError::Other(format!("invalid policy command: {error}").into())
            })?;
            let actor = did_from_signer(&tx.signer)?;
            match module.execute_policy_cmd_with_metadata(
                &actor,
                &policy_id_to_string(&call.policyId),
                request,
                block,
                tx,
            ) {
                Ok(result) => Ok(ok_dispatch(
                    gas,
                    IAcp::executePolicyCommandCall::abi_encode_returns(&json_bytes(&result)),
                    vec![event_log(
                        ACP_ADDRESS,
                        &IAcp::PolicyCommandExecuted {
                            policyId: call.policyId,
                            actor: tx.signer.clone(),
                        },
                    )],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }

        IAcp::createPolicyWithOptionsCall::SELECTOR => {
            let call =
                IAcp::createPolicyWithOptionsCall::abi_decode(input).map_err(decode_error)?;
            let request = serde_json::from_slice(&call.request).map_err(|error| {
                PrecompileError::Other(format!("invalid policy request: {error}").into())
            })?;
            let actor = did_from_signer(&tx.signer)?;
            match module.execute_create_policy(&actor, &request, block, tx) {
                Ok(record) => Ok(ok_dispatch(
                    gas,
                    IAcp::createPolicyWithOptionsCall::abi_encode_returns(&json_bytes(&record)),
                    vec![event_log(
                        ACP_ADDRESS,
                        &IAcp::PolicyCreated {
                            policyId: alloy_primitives::keccak256(record.policy.id.as_bytes()),
                            creator: tx.signer.clone(),
                        },
                    )],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IAcp::transferObjectCall::SELECTOR => {
            let call = IAcp::transferObjectCall::abi_decode(input).map_err(decode_error)?;
            let actor = did_from_signer(&tx.signer)?;
            let new_owner = did_from_actor(&call.newOwner)?;
            let policy = policy_id_to_string(&call.policyId);
            let command = PolicyCmd::TransferObject {
                object: Object {
                    resource: call.resource.clone(),
                    id: call.objectId.clone(),
                },
                new_owner: Actor(new_owner),
            };
            match module.execute_policy_cmd(&actor, &policy, command, block, tx) {
                Ok(record) => Ok(ok_dispatch(
                    gas,
                    IAcp::transferObjectCall::abi_encode_returns(&json_bytes(&record)),
                    vec![event_log(
                        ACP_ADDRESS,
                        &IAcp::ObjectTransferred {
                            policyId: call.policyId,
                            resource: call.resource,
                            objectId: call.objectId,
                            newOwner: call.newOwner,
                        },
                    )],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
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
        IAcp::checkManagementAuthorityCall::SELECTOR => {
            let call =
                IAcp::checkManagementAuthorityCall::abi_decode(input).map_err(decode_error)?;
            let actor = did_from_actor(&call.actor)?;
            match module.check_management_authority(
                &actor,
                &policy_id_to_string(&call.policyId),
                &Object {
                    resource: call.resource,
                    id: call.objectId,
                },
                &call.relation,
            ) {
                Ok(value) => Ok(ok_dispatch(
                    gas,
                    IAcp::checkManagementAuthorityCall::abi_encode_returns(&value),
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
