//! Policy command input and management authorization accounting.

use super::*;
use vera_modules::acp::CommandBudget;

pub(super) const fn handles(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        IAcp::setRelationshipCall::SELECTOR
            | IAcp::deleteRelationshipCall::SELECTOR
            | IAcp::setRelationshipSubjectCall::SELECTOR
            | IAcp::deleteRelationshipSubjectCall::SELECTOR
            | IAcp::registerObjectCall::SELECTOR
            | IAcp::archiveObjectCall::SELECTOR
            | IAcp::unarchiveObjectCall::SELECTOR
            | IAcp::commitRegistrationsCall::SELECTOR
            | IAcp::revealRegistrationCall::SELECTOR
            | IAcp::flagHijackAttemptCall::SELECTOR
            | IAcp::bearerPolicyCmdCall::SELECTOR
            | IAcp::executePolicyCommandCall::SELECTOR
            | IAcp::transferObjectCall::SELECTOR
            | IAcp::checkManagementAuthorityCall::SELECTOR
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
    let selector: [u8; 4] = input[..4].try_into().expect("dispatch checked selector");
    let base = if selector == IAcp::checkManagementAuthorityCall::SELECTOR {
        READ_GAS
    } else {
        WRITE_GAS
    };
    let budget = CommandBudget::new(
        gas_limit
            .checked_sub(base)
            .ok_or(PrecompileError::OutOfGas)?,
    );
    budget
        .input(input.len())
        .map_err(|_| PrecompileError::OutOfGas)?;
    // A leaf can alias its dynamic tails. Reserve each owned occurrence before
    // Alloy decoding, in addition to processing the raw calldata and JSON bytes.
    let prepared = reserve_fields(selector, input, &budget);
    let snapshot = (module.clone(), vera.clone());
    let result = prepared.and_then(|()| run(module, vera, block, tx, selector, input, &budget));
    if budget.is_exhausted() {
        (*module, *vera) = snapshot;
        return Err(PrecompileError::OutOfGas);
    }
    let gas = base
        .checked_add(budget.consumed())
        .ok_or(PrecompileError::OutOfGas)?;
    match result {
        Ok(mut result) => {
            if result.precompile.reverted {
                (*module, *vera) = snapshot;
            }
            result.precompile.gas_used = gas;
            Ok(result)
        }
        Err(PrecompileError::OutOfGas) => {
            (*module, *vera) = snapshot;
            Err(PrecompileError::OutOfGas)
        }
        Err(error) => {
            (*module, *vera) = snapshot;
            let mut result = err_dispatch(error);
            result.precompile.gas_used = gas;
            Ok(result)
        }
    }
}

fn reserve_fields(
    selector: [u8; 4],
    input: &[u8],
    budget: &CommandBudget,
) -> Result<(), PrecompileError> {
    let fields: &[usize] = match selector {
        IAcp::setRelationshipCall::SELECTOR
        | IAcp::deleteRelationshipCall::SELECTOR
        | IAcp::checkManagementAuthorityCall::SELECTOR => &[1, 2, 3, 4],
        IAcp::setRelationshipSubjectCall::SELECTOR
        | IAcp::deleteRelationshipSubjectCall::SELECTOR => &[1, 2, 3, 5, 6, 7],
        IAcp::registerObjectCall::SELECTOR
        | IAcp::archiveObjectCall::SELECTOR
        | IAcp::unarchiveObjectCall::SELECTOR => &[1, 2],
        IAcp::transferObjectCall::SELECTOR => &[1, 2, 3],
        IAcp::revealRegistrationCall::SELECTOR
        | IAcp::executePolicyCommandCall::SELECTOR
        | IAcp::commitRegistrationsCall::SELECTOR => &[1],
        IAcp::bearerPolicyCmdCall::SELECTOR => &[0, 2],
        _ => &[],
    };
    for field in fields {
        let value = leaf::bytes(&input[4..], field * 32)?;
        budget
            .input(value.len())
            .map_err(|_| PrecompileError::OutOfGas)?;
        let is_string = match selector {
            IAcp::revealRegistrationCall::SELECTOR
            | IAcp::executePolicyCommandCall::SELECTOR
            | IAcp::commitRegistrationsCall::SELECTOR => false,
            IAcp::bearerPolicyCmdCall::SELECTOR => *field == 0,
            _ => true,
        };
        if is_string {
            // Alloy detokenizes strings lossily; reserve replacement expansion too.
            let extra = value
                .utf8_chunks()
                .map(|chunk| {
                    if chunk.invalid().is_empty() {
                        0
                    } else {
                        3 - chunk.invalid().len()
                    }
                })
                .sum();
            budget.input(extra).map_err(|_| PrecompileError::OutOfGas)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run(
    module: &mut AcpModule,
    vera: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    selector: [u8; 4],
    input: &[u8],
    budget: &CommandBudget,
) -> DispatchReturn {
    match selector {
        IAcp::setRelationshipCall::SELECTOR => {
            let call = IAcp::setRelationshipCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let cmd = PolicyCmd::SetRelationship(acp::Relationship::new(
                &call.resource,
                &call.objectId,
                &call.relation,
                acp::Subject::entity(actor_did),
            ));

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let (record_existed, record) = match result {
                vera_modules::acp::types::PolicyCmdResult::SetRelationship {
                    record_existed,
                    record,
                } => (record_existed, record),
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let event = IAcp::RelationshipSet {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                resource: call.resource.clone(),
                objectId: call.objectId.clone(),
                relation: call.relation.clone(),
                actor: call.actor,
            };
            let ret = IAcp::setRelationshipCall::abi_encode_returns(&IAcp::setRelationshipReturn {
                recordExisted: record_existed,
                record: json_bytes(&record),
            });
            Ok(ok_dispatch(0, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::deleteRelationshipCall::SELECTOR => {
            let call = IAcp::deleteRelationshipCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let cmd = PolicyCmd::DeleteRelationship(acp::Relationship::new(
                &call.resource,
                &call.objectId,
                &call.relation,
                acp::Subject::entity(actor_did),
            ));

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let record_found = match result {
                vera_modules::acp::types::PolicyCmdResult::DeleteRelationship { record_found } => {
                    record_found
                }
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let event = IAcp::RelationshipDeleted {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                resource: call.resource.clone(),
                objectId: call.objectId.clone(),
                relation: call.relation.clone(),
                actor: call.actor,
            };
            let ret = IAcp::deleteRelationshipCall::abi_encode_returns(&record_found);
            Ok(ok_dispatch(0, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::setRelationshipSubjectCall::SELECTOR => {
            let call = IAcp::setRelationshipSubjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let subject = decode_subject(
                call.subjectKind,
                &call.subjectResource,
                &call.subjectObjectId,
                &call.subjectRelation,
            )?;
            let cmd = PolicyCmd::SetRelationship(acp::Relationship::new(
                &call.resource,
                &call.objectId,
                &call.relation,
                subject,
            ));

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let (record_existed, record) = match result {
                vera_modules::acp::types::PolicyCmdResult::SetRelationship {
                    record_existed,
                    record,
                } => (record_existed, record),
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let event = IAcp::RelationshipSubjectSet {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                resource: call.resource,
                objectId: call.objectId,
                relation: call.relation,
                subjectKind: call.subjectKind,
                subjectResource: call.subjectResource,
                subjectObjectId: call.subjectObjectId,
                subjectRelation: call.subjectRelation,
            };
            let ret = IAcp::setRelationshipSubjectCall::abi_encode_returns(
                &IAcp::setRelationshipSubjectReturn {
                    recordExisted: record_existed,
                    record: json_bytes(&record),
                },
            );
            Ok(ok_dispatch(0, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::deleteRelationshipSubjectCall::SELECTOR => {
            let call =
                IAcp::deleteRelationshipSubjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let subject = decode_subject(
                call.subjectKind,
                &call.subjectResource,
                &call.subjectObjectId,
                &call.subjectRelation,
            )?;
            let cmd = PolicyCmd::DeleteRelationship(acp::Relationship::new(
                &call.resource,
                &call.objectId,
                &call.relation,
                subject,
            ));

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let record_found = match result {
                vera_modules::acp::types::PolicyCmdResult::DeleteRelationship { record_found } => {
                    record_found
                }
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let event = IAcp::RelationshipSubjectDeleted {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                resource: call.resource,
                objectId: call.objectId,
                relation: call.relation,
                subjectKind: call.subjectKind,
                subjectResource: call.subjectResource,
                subjectObjectId: call.subjectObjectId,
                subjectRelation: call.subjectRelation,
            };
            let ret = IAcp::deleteRelationshipSubjectCall::abi_encode_returns(&record_found);
            Ok(ok_dispatch(0, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::registerObjectCall::SELECTOR => {
            let call = IAcp::registerObjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let resource = call.resource.clone();
            let object_id = call.objectId.clone();
            let cmd = PolicyCmd::RegisterObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let record = match result {
                vera_modules::acp::types::PolicyCmdResult::RegisterObject { record } => record,
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let event = IAcp::ObjectRegistered {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                resource,
                objectId: object_id,
                owner: tx_ctx.signer.clone(),
            };
            let ret = IAcp::registerObjectCall::abi_encode_returns(&json_bytes(&record));
            Ok(ok_dispatch(0, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::archiveObjectCall::SELECTOR => {
            let call = IAcp::archiveObjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let resource = call.resource.clone();
            let object_id = call.objectId.clone();
            let cmd = PolicyCmd::ArchiveObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let (found, relationships_removed) = match result {
                vera_modules::acp::types::PolicyCmdResult::ArchiveObject {
                    found,
                    relationships_removed,
                } => (found, relationships_removed),
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let event = IAcp::ObjectUnregistered {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                resource,
                objectId: object_id,
            };
            let ret = IAcp::archiveObjectCall::abi_encode_returns(&IAcp::archiveObjectReturn {
                found,
                relationshipsRemoved: relationships_removed,
            });
            Ok(ok_dispatch(0, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::unarchiveObjectCall::SELECTOR => {
            let call = IAcp::unarchiveObjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::UnarchiveObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let (record, relationship_modified) = match result {
                vera_modules::acp::types::PolicyCmdResult::UnarchiveObject {
                    record,
                    relationship_modified,
                } => (record, relationship_modified),
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::unarchiveObjectCall::abi_encode_returns(&IAcp::unarchiveObjectReturn {
                record: json_bytes(&record),
                relationshipModified: relationship_modified,
            });
            Ok(ok_dispatch(0, ret, vec![]))
        }

        IAcp::commitRegistrationsCall::SELECTOR => {
            let call = IAcp::commitRegistrationsCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::CommitRegistrations {
                commitment: call.commitment.to_vec(),
            };

            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let commitment_id = match result {
                vera_modules::acp::types::PolicyCmdResult::CommitRegistrations {
                    registrations_commitment,
                } => registrations_commitment.id,
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::commitRegistrationsCall::abi_encode_returns(&commitment_id);
            let event = IAcp::RegistrationsCommitted {
                commitmentId: commitment_id,
                policyId: call.policyId,
                commitment: alloy_primitives::B256::from_slice(&call.commitment),
            };
            Ok(ok_dispatch(0, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::revealRegistrationCall::SELECTOR => {
            let call = IAcp::revealRegistrationCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let proof: vera_modules::acp::types::RegistrationProof =
                serde_json::from_slice(&call.proof).map_err(|e| {
                    PrecompileError::Other(format!("proof JSON decode: {e}").into())
                })?;
            let cmd = PolicyCmd::RevealRegistration {
                registrations_commitment_id: call.commitmentId,
                proof,
            };

            let policy_id = match module
                .query_registrations_commitment_with_budget(call.commitmentId, budget)
            {
                Ok(commitment) => commitment.policy_id,
                Err(error) => return Ok(err_dispatch(error)),
            };
            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let encoded = serde_json::to_vec(&result).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::revealRegistrationCall::abi_encode_returns(&ret_bytes);
            Ok(ok_dispatch(0, ret, vec![]))
        }

        IAcp::flagHijackAttemptCall::SELECTOR => {
            let call = IAcp::flagHijackAttemptCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let cmd = PolicyCmd::FlagHijackAttempt {
                event_id: call.eventId,
            };

            let policy_id = match module.get_amendment_event_by_id_with_budget(call.eventId, budget)
            {
                Ok(Some(event)) => event.policy_id,
                Ok(None) => {
                    return Ok(err_dispatch(vera_modules::acp::error::AcpError::State(
                        format!("amendment event {} not found", call.eventId),
                    )));
                }
                Err(e) => return Ok(err_dispatch(e)),
            };
            let result = match module.execute_policy_cmd_with_budget(
                &creator, &policy_id, cmd, block_ctx, tx_ctx, budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let event = match result {
                vera_modules::acp::types::PolicyCmdResult::FlagHijackAttempt { event } => event,
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::flagHijackAttemptCall::abi_encode_returns(&json_bytes(&event));
            Ok(ok_dispatch(0, ret, vec![]))
        }

        IAcp::bearerPolicyCmdCall::SELECTOR => {
            let call = IAcp::bearerPolicyCmdCall::abi_decode(input).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd: PolicyCmd = serde_json::from_slice(&call.cmd)
                .map_err(|e| PrecompileError::Other(format!("cmd JSON decode: {e}").into()))?;

            let result = match module.bearer_policy_cmd_with_budget(
                vera,
                block_ctx,
                tx_ctx,
                &call.bearerToken,
                &policy_id,
                cmd,
                budget,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IAcp::bearerPolicyCmdCall::abi_encode_returns(&json_bytes(&result));
            Ok(ok_dispatch(0, ret, vec![]))
        }

        IAcp::executePolicyCommandCall::SELECTOR => {
            let call = IAcp::executePolicyCommandCall::abi_decode(input).map_err(decode_error)?;
            let request = serde_json::from_slice(&call.request).map_err(|error| {
                PrecompileError::Other(format!("invalid policy command: {error}").into())
            })?;
            let actor = did_from_signer(&tx_ctx.signer)?;
            match module.execute_policy_cmd_with_metadata_and_budget(
                &actor,
                &policy_id_to_string(&call.policyId),
                request,
                block_ctx,
                tx_ctx,
                budget,
            ) {
                Ok(result) => Ok(ok_dispatch(
                    0,
                    IAcp::executePolicyCommandCall::abi_encode_returns(&json_bytes(&result)),
                    vec![event_log(
                        ACP_ADDRESS,
                        &IAcp::PolicyCommandExecuted {
                            policyId: call.policyId,
                            actor: tx_ctx.signer.clone(),
                        },
                    )],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }

        IAcp::transferObjectCall::SELECTOR => {
            let call = IAcp::transferObjectCall::abi_decode(input).map_err(decode_error)?;
            let actor = did_from_signer(&tx_ctx.signer)?;
            let new_owner = did_from_actor(&call.newOwner)?;
            let policy = policy_id_to_string(&call.policyId);
            let command = PolicyCmd::TransferObject {
                object: Object {
                    resource: call.resource.clone(),
                    id: call.objectId.clone(),
                },
                new_owner: Actor(new_owner),
            };
            match module
                .execute_policy_cmd_with_budget(&actor, &policy, command, block_ctx, tx_ctx, budget)
            {
                Ok(record) => Ok(ok_dispatch(
                    0,
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
        IAcp::checkManagementAuthorityCall::SELECTOR => {
            let call =
                IAcp::checkManagementAuthorityCall::abi_decode(input).map_err(decode_error)?;
            let actor = did_from_actor(&call.actor)?;
            match module.check_management_authority_with_budget(
                &actor,
                &policy_id_to_string(&call.policyId),
                &Object {
                    resource: call.resource,
                    id: call.objectId,
                },
                &call.relation,
                budget,
            ) {
                Ok(value) => Ok(ok_dispatch(
                    0,
                    IAcp::checkManagementAuthorityCall::abi_encode_returns(&value),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        _ => unreachable!("command selector checked by dispatcher"),
    }
}
