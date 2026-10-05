//! ACP precompile dispatch — ABI decode/encode for all IAcp selectors.

mod batch;
mod batch_results;
#[cfg(test)]
mod batch_tests;
mod creation;
#[cfg(test)]
mod creation_tests;
#[cfg(test)]
mod edit_budget_tests;
mod leaf;
#[cfg(test)]
mod leaf_tests;
mod lifecycle;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod permission_budget_tests;
mod permissions;
mod queries;
#[cfg(test)]
mod query_budget_tests;

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall;
use identity::Did;
use revm::precompile::{PrecompileError, PrecompileOutput};
use vera_modules::acp::abi::IAcp;
use vera_modules::acp::types::{
    AccessRequest, AcpParams, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType,
    RelationshipSelector,
};
use vera_modules::acp::{AcpModule, PolicyEditBudget, QueryBudget};
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::vera::VeraModule;

use super::{
    ACP_ADDRESS, DispatchResult, DispatchReturn, decode_error, did_from_signer, err_dispatch,
    event_log, json_bytes, ok_dispatch,
};

/// Base gas cost for reads and each batch wrapper.
const READ_GAS: u64 = 1000;
/// Base gas cost for writes.
const WRITE_GAS: u64 = 5000;

// Keep work charges on ordinary reverts; snapshots restore state, never spent gas.
fn edit_gas(budget: &PolicyEditBudget) -> Result<u64, PrecompileError> {
    if budget.is_exhausted() {
        return Err(PrecompileError::OutOfGas);
    }
    WRITE_GAS
        .checked_add(budget.consumed())
        .ok_or(PrecompileError::OutOfGas)
}

fn edit_error(error: impl core::fmt::Display, budget: &PolicyEditBudget) -> DispatchReturn {
    let gas_used = edit_gas(budget)?;
    let mut result = err_dispatch(error);
    result.precompile.gas_used = gas_used;
    Ok(result)
}

fn did_from_actor(actor: &str) -> Result<Did, PrecompileError> {
    Did::new(actor).map_err(|e| PrecompileError::Other(format!("actor DID: {e}").into()))
}

/// Decode a structured subject — a `subjectKind` discriminant plus the discrete
/// `subjectResource` / `subjectObjectId` / `subjectRelation` fields — into a
/// [`acp::Subject`]. Subjects are never parsed from a single string: object IDs
/// are path-like and may be quoted, so a string grammar would be fragile on this
/// security boundary.
///
/// | kind | fields | subject |
/// |------|--------|---------|
/// | 0 Entity | `object_id` = DID | `Entity` |
/// | 1 Wildcard | — | `Wildcard` |
/// | 2 Object (edge) | `resource`, `object_id` | `EntitySet{…, relation: ""}` |
/// | 3 Userset | `resource`, `object_id`, `relation` | `EntitySet{…, relation}` |
fn decode_subject(
    kind: u8,
    resource: &str,
    object_id: &str,
    relation: &str,
) -> Result<acp::Subject, PrecompileError> {
    match kind {
        // Entity — DID in object_id; no cross-object fields.
        0 => {
            if object_id.is_empty() {
                return Err(subject_field_error(
                    "entity requires a DID in subjectObjectId",
                ));
            }
            if !resource.is_empty() || !relation.is_empty() {
                return Err(subject_field_error(
                    "entity takes no subjectResource/subjectRelation",
                ));
            }
            Ok(acp::Subject::entity(did_from_actor(object_id)?))
        }
        // Wildcard — all-actors; no fields.
        1 => {
            if !resource.is_empty() || !object_id.is_empty() || !relation.is_empty() {
                return Err(subject_field_error("wildcard takes no subject fields"));
            }
            Ok(acp::Subject::wildcard())
        }
        // Object edge — resource:object_id, empty relation.
        2 => {
            if resource.is_empty() || object_id.is_empty() {
                return Err(subject_field_error(
                    "object requires subjectResource and subjectObjectId",
                ));
            }
            if !relation.is_empty() {
                return Err(subject_field_error("object takes no subjectRelation"));
            }
            Ok(acp::Subject::entity_set(resource, object_id, ""))
        }
        // Userset — resource:object_id#relation.
        3 => {
            if resource.is_empty() || object_id.is_empty() || relation.is_empty() {
                return Err(subject_field_error(
                    "userset requires subjectResource, subjectObjectId and subjectRelation",
                ));
            }
            Ok(acp::Subject::entity_set(resource, object_id, relation))
        }
        // 4 is reserved for TypedWildcard (not yet supported).
        other => Err(subject_field_error(&format!(
            "unsupported subjectKind {other}"
        ))),
    }
}

fn subject_field_error(msg: &str) -> PrecompileError {
    PrecompileError::Other(format!("subject: {msg}").into())
}

fn policy_id_to_string(b: &B256) -> String {
    hex::encode(b.as_slice())
}

const fn marshal_type_from_u8(v: u8) -> PolicyMarshalingType {
    match v {
        1 => PolicyMarshalingType::ShortYaml,
        2 => PolicyMarshalingType::ShortJson,
        _ => PolicyMarshalingType::Unknown,
    }
}

fn build_operations(
    resources: &[String],
    object_ids: &[String],
    permissions: &[String],
) -> Result<Vec<Operation>, PrecompileError> {
    if resources.len() != object_ids.len() || resources.len() != permissions.len() {
        return Err(PrecompileError::Other("array length mismatch".into()));
    }
    Ok(resources
        .iter()
        .zip(object_ids)
        .zip(permissions)
        .map(|((r, o), p)| Operation {
            object: Object {
                resource: r.clone(),
                id: o.clone(),
            },
            permission: p.clone(),
        })
        .collect())
}

fn batch_revert(
    index: usize,
    gas_used: u64,
    bytes: &Bytes,
    budget: &mut batch_results::Budget,
) -> DispatchReturn {
    let call_number = index + 1;
    let prefix = format!("batch call {call_number} reverted");
    budget.revert(&prefix, bytes)?;
    let message = if bytes.is_empty() {
        format!("batch call {call_number} reverted")
    } else {
        format!(
            "batch call {call_number} reverted: {}",
            String::from_utf8_lossy(bytes.as_ref())
        )
    };

    Ok(DispatchResult {
        precompile: PrecompileOutput {
            gas_used,
            gas_refunded: 0,
            bytes: message.into_bytes().into(),
            reverted: true,
        },
        logs: vec![],
    })
}

fn batch_error(index: usize, err: PrecompileError) -> PrecompileError {
    match err {
        PrecompileError::Other(message) => {
            PrecompileError::Other(format!("batch call {}: {message}", index + 1).into())
        }
        other => other,
    }
}

/// Dispatch an ABI-encoded call after bounding batch and leaf array allocations.
pub(super) fn dispatch(
    module: &mut AcpModule,
    vera: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    let preflight_gas = leaf::required_gas(input).or_else(|| {
        input
            .starts_with(&IAcp::batchCallsCall::SELECTOR)
            .then_some(READ_GAS)
    });
    if let Some(minimum) = preflight_gas {
        if gas_limit < minimum {
            return Err(PrecompileError::OutOfGas);
        }
        batch::validate(input)?;
    }
    dispatch_validated(
        module,
        vera,
        block_ctx,
        tx_ctx,
        input,
        gas_limit,
        &mut batch_results::Budget::new(),
    )
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn dispatch_validated(
    module: &mut AcpModule,
    vera: &mut VeraModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
    result_budget: &mut batch_results::Budget,
) -> DispatchReturn {
    if input.len() < 4 {
        return Err(PrecompileError::Other(
            "input too short for selector".into(),
        ));
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");

    if creation::handles(selector) {
        return creation::dispatch(module, vera, block_ctx, tx_ctx, input, gas_limit);
    }
    if queries::handles(selector) {
        return queries::dispatch(module, input, gas_limit);
    }
    if lifecycle::handles(selector) {
        return lifecycle::dispatch(module, block_ctx, tx_ctx, input, gas_limit);
    }
    match selector {
        // ── Write methods ────────────────────────────────────────────
        IAcp::batchCallsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::batchCallsCall::abi_decode(input).map_err(decode_error)?;
            result_budget.begin_batch(call.calls.len())?;
            let snapshot = (module.clone(), vera.clone());
            let mut results = Vec::with_capacity(call.calls.len());
            let mut logs = Vec::new();
            let mut gas_used = READ_GAS;

            for (index, inner_call) in call.calls.iter().enumerate() {
                let remaining_gas = gas_limit.saturating_sub(gas_used);
                let inner = match dispatch_validated(
                    module,
                    vera,
                    block_ctx,
                    tx_ctx,
                    inner_call.as_ref(),
                    remaining_gas,
                    result_budget,
                ) {
                    Ok(inner) => inner,
                    Err(err) => {
                        (*module, *vera) = snapshot;
                        return Err(batch_error(index, err));
                    }
                };

                let inner_gas = match gas_used.checked_add(inner.precompile.gas_used) {
                    Some(total) => total,
                    None => {
                        (*module, *vera) = snapshot;
                        return Err(PrecompileError::OutOfGas);
                    }
                };

                if inner.precompile.reverted {
                    (*module, *vera) = snapshot;
                    return batch_revert(index, inner_gas, &inner.precompile.bytes, result_budget);
                }

                // Nested logs were already charged where they originated and are only moved here.
                let new_logs = if inner_call.starts_with(&IAcp::batchCallsCall::SELECTOR) {
                    &[][..]
                } else {
                    inner.logs.as_slice()
                };
                if let Err(error) = result_budget.retain(&inner.precompile.bytes, new_logs) {
                    (*module, *vera) = snapshot;
                    return Err(batch_error(index, error));
                }
                gas_used = inner_gas;
                results.push(inner.precompile.bytes);
                logs.extend(inner.logs);
            }

            let ret = IAcp::batchCallsCall::abi_encode_returns(&results);
            Ok(ok_dispatch(gas_used, ret, logs))
        }

        IAcp::bearerEditPolicyCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let budget = PolicyEditBudget::new(gas_limit - WRITE_GAS);
            let call = IAcp::bearerEditPolicyCall::abi_decode(input).map_err(decode_error)?;
            let policy = std::str::from_utf8(&call.policy)
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;
            let policy_id = policy_id_to_string(&call.policyId);
            let (removed, record) = match module.bearer_edit_policy_with_budget(
                vera,
                block_ctx,
                tx_ctx,
                &call.bearerToken,
                &policy_id,
                policy,
                marshal_type_from_u8(call.marshalType),
                &budget,
            ) {
                Ok(result) => result,
                Err(error) => return edit_error(error, &budget),
            };
            let event = IAcp::PolicyEdited {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                creator: record.metadata.owner_did.clone(),
                relationshipsRemoved: alloy_primitives::U256::from(removed),
            };
            Ok(ok_dispatch(
                edit_gas(&budget)?,
                IAcp::bearerEditPolicyCall::abi_encode_returns(&IAcp::bearerEditPolicyReturn {
                    relationshipsRemoved: removed,
                    record: json_bytes(&record),
                }),
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::editPolicyCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let budget = PolicyEditBudget::new(gas_limit - WRITE_GAS);
            let call = IAcp::editPolicyCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let policy_str = std::str::from_utf8(&call.policy)
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;
            let marshal_type = marshal_type_from_u8(call.marshalType);

            let (relationships_removed, record) = match module.edit_policy_at_with_budget(
                &creator,
                &policy_id,
                policy_str,
                marshal_type,
                &block_ctx.timestamp,
                &budget,
            ) {
                Ok(r) => r,
                Err(e) => return edit_error(e, &budget),
            };

            let event = IAcp::PolicyEdited {
                policyId: alloy_primitives::keccak256(policy_id.as_bytes()),
                creator: tx_ctx.signer.clone(),
                relationshipsRemoved: alloy_primitives::U256::from(relationships_removed),
            };
            let ret = IAcp::editPolicyCall::abi_encode_returns(&IAcp::editPolicyReturn {
                relationshipsRemoved: relationships_removed,
                record: json_bytes(&record),
            });
            Ok(ok_dispatch(
                edit_gas(&budget)?,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::setRelationshipCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
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

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::deleteRelationshipCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
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

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::setRelationshipSubjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
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

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::deleteRelationshipSubjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
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

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::registerObjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::registerObjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let resource = call.resource.clone();
            let object_id = call.objectId.clone();
            let cmd = PolicyCmd::RegisterObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::archiveObjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::archiveObjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let resource = call.resource.clone();
            let object_id = call.objectId.clone();
            let cmd = PolicyCmd::ArchiveObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::unarchiveObjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::unarchiveObjectCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::UnarchiveObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(WRITE_GAS, ret, vec![]))
        }

        IAcp::commitRegistrationsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::commitRegistrationsCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::CommitRegistrations {
                commitment: call.commitment.to_vec(),
            };

            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
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
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::revealRegistrationCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
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

            let policy_id = match module.query_registrations_commitment(call.commitmentId) {
                Ok(commitment) => commitment.policy_id,
                Err(error) => return Ok(err_dispatch(error)),
            };
            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
                    Ok(r) => r,
                    Err(e) => return Ok(err_dispatch(e)),
                };

            let encoded = serde_json::to_vec(&result).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::revealRegistrationCall::abi_encode_returns(&ret_bytes);
            Ok(ok_dispatch(WRITE_GAS, ret, vec![]))
        }

        IAcp::flagHijackAttemptCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::flagHijackAttemptCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let cmd = PolicyCmd::FlagHijackAttempt {
                event_id: call.eventId,
            };

            let policy_id = match module.get_amendment_event_by_id(call.eventId) {
                Ok(Some(event)) => event.policy_id,
                Ok(None) => {
                    return Ok(err_dispatch(vera_modules::acp::error::AcpError::State(
                        format!("amendment event {} not found", call.eventId),
                    )));
                }
                Err(e) => return Ok(err_dispatch(e)),
            };
            let result =
                match module.execute_policy_cmd(&creator, &policy_id, cmd, block_ctx, tx_ctx) {
                    Ok(r) => r,
                    Err(e) => return Ok(err_dispatch(e)),
                };

            let event = match result {
                vera_modules::acp::types::PolicyCmdResult::FlagHijackAttempt { event } => event,
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::flagHijackAttemptCall::abi_encode_returns(&json_bytes(&event));
            Ok(ok_dispatch(WRITE_GAS, ret, vec![]))
        }

        IAcp::bearerCheckAccessCall::SELECTOR
        | IAcp::checkAccessCall::SELECTOR
        | IAcp::verifyAccessRequestCall::SELECTOR => {
            permissions::dispatch(module, vera, block_ctx, tx_ctx, input, gas_limit)
        }

        IAcp::bearerPolicyCmdCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::bearerPolicyCmdCall::abi_decode(input).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd: PolicyCmd = serde_json::from_slice(&call.cmd)
                .map_err(|e| PrecompileError::Other(format!("cmd JSON decode: {e}").into()))?;

            let result = match module.bearer_policy_cmd(
                vera,
                block_ctx,
                tx_ctx,
                &call.bearerToken,
                &policy_id,
                cmd,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IAcp::bearerPolicyCmdCall::abi_encode_returns(&json_bytes(&result));
            Ok(ok_dispatch(WRITE_GAS, ret, vec![]))
        }

        IAcp::updateParamsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::updateParamsCall::abi_decode(input).map_err(decode_error)?;
            let authority = did_from_signer(&tx_ctx.signer)?;
            let params: AcpParams = serde_json::from_slice(&call.params)
                .map_err(|e| PrecompileError::Other(format!("params JSON decode: {e}").into()))?;

            match module.update_params(&authority, params) {
                Ok(()) => {}
                Err(e) => return Ok(err_dispatch(e)),
            }

            Ok(ok_dispatch(WRITE_GAS, Vec::new(), vec![]))
        }

        // ── Read methods ─────────────────────────────────────────────
        IAcp::getObjectOwnerCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getObjectOwnerCall::abi_decode(input).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let object = Object {
                resource: call.resource,
                id: call.objectId,
            };

            let (registered, record) = match module.query_object_owner(&policy_id, &object) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IAcp::getObjectOwnerCall::abi_encode_returns(&IAcp::getObjectOwnerReturn {
                registered,
                record: json_bytes(&record),
            });
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IAcp::validatePolicyCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::validatePolicyCall::abi_decode(input).map_err(decode_error)?;
            let policy_str = String::from_utf8(call.policy.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;
            let marshal_type = marshal_type_from_u8(call.marshalType);

            let (valid, reason, _policy) =
                match module.query_validate_policy(&policy_str, marshal_type) {
                    Ok(r) => r,
                    Err(e) => return Ok(err_dispatch(e)),
                };

            let ret = IAcp::validatePolicyCall::abi_encode_returns(&IAcp::validatePolicyReturn {
                valid,
                reason,
            });
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IAcp::getAccessDecisionCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getAccessDecisionCall::abi_decode(input).map_err(decode_error)?;

            let decision = match module.query_access_decision(&call.decisionId) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IAcp::getAccessDecisionCall::abi_encode_returns(&json_bytes(&decision));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IAcp::getRegistrationsCommitmentCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::getRegistrationsCommitmentCall::abi_decode(input).map_err(decode_error)?;

            let commitment = match module.query_registrations_commitment(call.commitmentId) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret =
                IAcp::getRegistrationsCommitmentCall::abi_encode_returns(&json_bytes(&commitment));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IAcp::getRegistrationsCommitmentByValueCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getRegistrationsCommitmentByValueCall::abi_decode(input)
                .map_err(decode_error)?;

            let commitments =
                match module.query_registrations_commitment_by_commitment(&call.commitment) {
                    Ok(r) => r,
                    Err(e) => return Ok(err_dispatch(e)),
                };

            let ret = IAcp::getRegistrationsCommitmentByValueCall::abi_encode_returns(&json_bytes(
                &commitments,
            ));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IAcp::getHijackAttemptsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getHijackAttemptsCall::abi_decode(input).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);

            let events = match module.query_hijack_attempts_by_policy(&policy_id) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IAcp::getHijackAttemptsCall::abi_encode_returns(&json_bytes(&events));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IAcp::generateCommitmentCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::generateCommitmentCall::abi_decode(input).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;

            if call.resources.len() != call.objectIds.len() {
                return Err(PrecompileError::Other("array length mismatch".into()));
            }
            let objects: Vec<Object> = call
                .resources
                .iter()
                .zip(&call.objectIds)
                .map(|(r, o)| Object {
                    resource: r.clone(),
                    id: o.clone(),
                })
                .collect();

            let result =
                match module.query_generate_commitment(&policy_id, &objects, &Actor(actor_did)) {
                    Ok(r) => r,
                    Err(e) => return Ok(err_dispatch(e)),
                };

            let ret = IAcp::generateCommitmentCall::abi_encode_returns(&json_bytes(&result));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IAcp::getParamsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            // Zero-parameter function — no ABI decoding needed.
            let params = match module.query_params() {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IAcp::getParamsCall::abi_encode_returns(&json_bytes(&params));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        _ => Err(PrecompileError::Other(
            format!("unknown ACP selector: 0x{}", hex::encode(selector)).into(),
        )),
    }
}

fn build_relationship_selector(
    resource: &str,
    object_id: &str,
    relation: &str,
    actor: &str,
) -> Result<RelationshipSelector, PrecompileError> {
    use vera_modules::acp::types::{ObjectSelector, RelationSelector, SubjectSelector};

    let object_selector = if resource.is_empty() && object_id.is_empty() {
        None
    } else if resource.is_empty() {
        return Err(PrecompileError::Other(
            "object selector requires a resource".into(),
        ));
    } else if object_id.is_empty() {
        Some(ObjectSelector::ResourcePredicate(resource.to_owned()))
    } else {
        Some(ObjectSelector::Exact(Object {
            resource: resource.to_owned(),
            id: object_id.to_owned(),
        }))
    };

    let relation_selector = if relation.is_empty() {
        None
    } else {
        Some(RelationSelector::Exact(relation.to_owned()))
    };

    let subject_selector = if actor.is_empty() {
        None
    } else {
        let actor_did = did_from_actor(actor)?;
        Some(SubjectSelector::Exact(acp::Subject::entity(actor_did)))
    };

    Ok(RelationshipSelector {
        object_selector,
        relation_selector,
        subject_selector,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use vera_modules::types::Timestamp;

    const TEST_POLICY_YAML: &str = "\
name: test-policy
resources:
  - name: document
    relations:
      - name: owner
      - name: reader
    permissions:
      - name: read
        expr: owner + reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
";

    #[test]
    fn dispatch_create_policy_roundtrip() {
        let calldata = IAcp::createPolicyCall {
            policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
            marshalType: 1,
        }
        .abi_encode();

        let mut module = AcpModule::new();
        let block_ctx = BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 1000,
                block_height: 5,
            },
        };
        let tx_ctx = TxExecCtx {
            sequence: 0,
            tx_hash: vec![1; 32],
            signer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        };

        let result = dispatch(
            &mut module,
            &mut VeraModule::new(),
            &block_ctx,
            &tx_ctx,
            &calldata,
            1_000_000,
        );
        match &result {
            Ok(dr) => {
                assert!(
                    !dr.precompile.reverted,
                    "dispatch should not revert, output bytes: {}",
                    String::from_utf8_lossy(&dr.precompile.bytes)
                );
            }
            Err(e) => panic!("dispatch returned PrecompileError: {e:?}"),
        }
    }

    #[test]
    fn dispatch_batch_calls_apply_multiple_mutations() {
        let calldata = IAcp::batchCallsCall {
            calls: vec![
                IAcp::createPolicyCall {
                    policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
                    marshalType: 1,
                }
                .abi_encode()
                .into(),
                IAcp::createPolicyCall {
                    policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
                    marshalType: 1,
                }
                .abi_encode()
                .into(),
            ],
        }
        .abi_encode();

        let mut module = AcpModule::new();
        let block_ctx = BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 1000,
                block_height: 5,
            },
        };
        let tx_ctx = TxExecCtx {
            sequence: 0,
            tx_hash: vec![1; 32],
            signer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        };

        let result = dispatch(
            &mut module,
            &mut VeraModule::new(),
            &block_ctx,
            &tx_ctx,
            &calldata,
            1_000_000,
        )
        .unwrap();
        assert!(!result.precompile.reverted);
        assert_eq!(result.logs.len(), 2);
        assert_eq!(module.query_policy_ids().unwrap().len(), 2);
    }

    #[test]
    fn dispatch_batch_calls_rollback_on_failure() {
        let block_ctx = BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 1000,
                block_height: 5,
            },
        };
        let tx_ctx = TxExecCtx {
            sequence: 0,
            tx_hash: vec![1; 32],
            signer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        };
        let creator = did_from_signer(&tx_ctx.signer).unwrap();
        let mut module = AcpModule::new();
        let record = module
            .create_policy(&creator, TEST_POLICY_YAML, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = FixedBytes::from_slice(&hex::decode(&record.policy.id).unwrap());

        let calldata = IAcp::batchCallsCall {
            calls: vec![
                IAcp::registerObjectCall {
                    policyId: policy_id,
                    objectId: "doc-1".into(),
                    resource: "document".into(),
                }
                .abi_encode()
                .into(),
                IAcp::setRelationshipCall {
                    policyId: policy_id,
                    resource: "document".into(),
                    objectId: "doc-1".into(),
                    relation: "reader".into(),
                    actor: "not-a-did".into(),
                }
                .abi_encode()
                .into(),
            ],
        }
        .abi_encode();

        let err = dispatch(
            &mut module,
            &mut VeraModule::new(),
            &block_ctx,
            &tx_ctx,
            &calldata,
            1_000_000,
        )
        .unwrap_err();
        match err {
            PrecompileError::Other(message) => {
                assert!(message.contains("batch call 2"), "{message}");
            }
            other => panic!("expected wrapped batch error, got {other:?}"),
        }

        let (registered, _) = module
            .query_object_owner(
                &record.policy.id,
                &Object {
                    resource: "document".into(),
                    id: "doc-1".into(),
                },
            )
            .unwrap();
        assert!(
            !registered,
            "failed batch should not persist earlier writes"
        );
    }

    const ALICE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[test]
    fn decode_subject_entity() {
        let got = decode_subject(0, "", ALICE_DID, "").unwrap();
        assert_eq!(got, acp::Subject::entity(Did::new(ALICE_DID).unwrap()));
    }

    #[test]
    fn decode_subject_wildcard() {
        assert_eq!(
            decode_subject(1, "", "", "").unwrap(),
            acp::Subject::wildcard()
        );
    }

    #[test]
    fn decode_subject_object_edge_has_empty_relation() {
        let got = decode_subject(2, "collection", "col1", "").unwrap();
        assert_eq!(got, acp::Subject::entity_set("collection", "col1", ""));
    }

    #[test]
    fn decode_subject_userset() {
        let got = decode_subject(3, "collection", "col1", "reader").unwrap();
        assert_eq!(
            got,
            acp::Subject::entity_set("collection", "col1", "reader")
        );
    }

    #[test]
    fn decode_subject_rejects_malformed() {
        assert!(
            decode_subject(4, "", "", "").is_err(),
            "kind 4 (TypedWildcard) reserved"
        );
        assert!(decode_subject(7, "", "", "").is_err(), "unknown kind");
        assert!(decode_subject(0, "", "", "").is_err(), "entity needs a DID");
        assert!(
            decode_subject(0, "", "not-a-did", "").is_err(),
            "entity DID must be valid"
        );
        assert!(
            decode_subject(2, "", "col1", "").is_err(),
            "object needs resource"
        );
        assert!(
            decode_subject(2, "collection", "", "").is_err(),
            "object needs object_id"
        );
        assert!(
            decode_subject(3, "collection", "col1", "").is_err(),
            "userset needs relation"
        );
        // Cross-object fields on entity/wildcard are a client bug — reject.
        assert!(
            decode_subject(1, "collection", "", "").is_err(),
            "wildcard takes no fields"
        );
        assert!(
            decode_subject(0, "collection", ALICE_DID, "").is_err(),
            "entity takes no resource"
        );
    }

    const CROSS_POLICY_YAML: &str = "\
name: cross-policy
resources:
  - name: collection
    relations:
      - name: owner
      - name: reader
    permissions:
      - name: read
        expr: owner + reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
  - name: document
    relations:
      - name: owner
      - name: parent
    permissions:
      - name: read
        expr: owner + parent->reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
";

    fn policy_fixed(id: &str) -> FixedBytes<32> {
        let mut b = [0u8; 32];
        hex::decode_to_slice(id, &mut b).expect("policy id hex");
        FixedBytes::from(b)
    }

    #[test]
    fn dispatch_set_and_delete_relationship_subject_userset() {
        use vera_modules::acp::types::{ObjectSelector, RelationSelector};

        let mut module = AcpModule::new();
        let block_ctx = BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 1000,
                block_height: 5,
            },
        };
        let tx_ctx = TxExecCtx {
            sequence: 0,
            tx_hash: vec![1; 32],
            signer: ALICE_DID.to_string(),
        };
        let creator = Did::new(ALICE_DID).unwrap();

        let record = module
            .create_policy(&creator, CROSS_POLICY_YAML, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = record.policy.id;
        module
            .direct_policy_cmd(
                &creator,
                &policy_id,
                PolicyCmd::RegisterObject(Object {
                    resource: "document".into(),
                    id: "doc1".into(),
                }),
            )
            .unwrap();

        let pid = policy_fixed(&policy_id);

        let fields = || IAcp::setRelationshipSubjectCall {
            policyId: pid,
            resource: "document".into(),
            objectId: "doc1".into(),
            relation: "parent".into(),
            subjectKind: 3,
            subjectResource: "collection".into(),
            subjectObjectId: "col1".into(),
            subjectRelation: "reader".into(),
        };

        let set = fields().abi_encode();
        let dr = dispatch(
            &mut module,
            &mut VeraModule::new(),
            &block_ctx,
            &tx_ctx,
            &set,
            1_000_000,
        )
        .unwrap();
        assert!(
            !dr.precompile.reverted,
            "set subject should not revert: {}",
            String::from_utf8_lossy(&dr.precompile.bytes)
        );

        let selector = RelationshipSelector {
            object_selector: Some(ObjectSelector::Exact(Object {
                resource: "document".into(),
                id: "doc1".into(),
            })),
            relation_selector: Some(RelationSelector::Exact("parent".into())),
            subject_selector: None,
        };
        let rels = module
            .query_filter_relationships(&policy_id, &selector)
            .unwrap();
        assert_eq!(rels.len(), 1, "userset edge stored");
        assert_eq!(
            rels[0].relationship.subject,
            acp::Subject::entity_set("collection", "col1", "reader"),
            "subject decoded to the userset EntitySet"
        );

        let c = fields();
        let del = IAcp::deleteRelationshipSubjectCall {
            policyId: c.policyId,
            resource: c.resource,
            objectId: c.objectId,
            relation: c.relation,
            subjectKind: c.subjectKind,
            subjectResource: c.subjectResource,
            subjectObjectId: c.subjectObjectId,
            subjectRelation: c.subjectRelation,
        }
        .abi_encode();
        let dr = dispatch(
            &mut module,
            &mut VeraModule::new(),
            &block_ctx,
            &tx_ctx,
            &del,
            1_000_000,
        )
        .unwrap();
        assert!(!dr.precompile.reverted, "delete subject should not revert");
        let rels = module
            .query_filter_relationships(&policy_id, &selector)
            .unwrap();
        assert!(rels.is_empty(), "userset edge removed after delete");
    }
}
