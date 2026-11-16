//! ACP precompile dispatch — ABI decode/encode for all IAcp selectors.

mod batch;
mod batch_results;
#[cfg(test)]
mod batch_tests;
#[cfg(test)]
mod command_budget_tests;
mod command_list;
#[cfg(test)]
mod command_list_tests;
mod commands;
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
#[cfg(test)]
mod spelling_tests;
mod validation;
#[cfg(test)]
mod validation_tests;

use crate::dispatch::{ModuleError, ModuleOutput, ModuleStatus};
use acp::domain::{ActorSet, Object as AcpObject, Relationship, Subject};
use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall;
use vera_identity::Did;
use vera_modules::acp::abi::IAcp;
use vera_modules::acp::types::{
    AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType, RelationshipSelector,
};
use vera_modules::acp::{AcpModule, PolicyEditBudget, QueryBudget};
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::vera::VeraModule;

use super::{
    ACP_ADDRESS, DispatchResult, DispatchReturn, decode_error, did_from_signer, err_dispatch,
    event_log, json_bytes, ok_dispatch, oog_dispatch, refusal_dispatch,
};

/// Base gas cost for reads and each batch wrapper.
const READ_GAS: u64 = 1000;
/// Base gas cost for writes.
const WRITE_GAS: u64 = 5000;

// Keep work charges on ordinary reverts; snapshots restore state, never spent gas.
fn edit_gas(budget: &PolicyEditBudget) -> Result<u64, ModuleError> {
    if budget.is_exhausted() {
        return Err(ModuleError::OutOfGas);
    }
    WRITE_GAS
        .checked_add(budget.consumed())
        .ok_or(ModuleError::OutOfGas)
}

fn edit_error(error: impl super::refusal::Refuse, budget: &PolicyEditBudget) -> DispatchReturn {
    let Ok(gas_used) = edit_gas(budget) else {
        return Ok(oog_dispatch());
    };
    let mut result = err_dispatch(error);
    result.output.gas_used = gas_used;
    Ok(result)
}

fn did_from_actor(actor: &str) -> Result<Did, ModuleError> {
    Did::new(actor).map_err(|e| {
        crate::dispatch::refusal::refused(
            vera_domain::RefusalKind::UndecodableInput,
            format!("actor DID: {e}"),
        )
    })
}

/// Decode a structured subject — a `subjectKind` discriminant plus the discrete
/// `subjectResource` / `subjectObjectId` / `subjectRelation` fields — into a
/// [`Subject`]. Subjects are never parsed from a single string: object IDs
/// are path-like and may be quoted, so a string grammar would be fragile on this
/// security boundary.
///
/// | kind | fields | subject |
/// |------|--------|---------|
/// | 0 Actor | `object_id` = DID | `Actor` |
/// | 1 All actors | — | `AllActors` |
/// | 2 Object (edge) | `resource`, `object_id` | `Object` |
/// | 3 Actor set | `resource`, `object_id`, `relation` | `ActorSet` |
fn decode_subject(
    kind: u8,
    resource: &str,
    object_id: &str,
    relation: &str,
) -> Result<Subject, ModuleError> {
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
            actor_subject(&did_from_actor(object_id)?)
        }
        // Wildcard — all-actors; no fields.
        1 => {
            if !resource.is_empty() || !object_id.is_empty() || !relation.is_empty() {
                return Err(subject_field_error("wildcard takes no subject fields"));
            }
            Ok(Subject::AllActors)
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
            Ok(Subject::Object(AcpObject::new(resource, object_id)))
        }
        // Userset — resource:object_id#relation.
        3 => {
            if resource.is_empty() || object_id.is_empty() || relation.is_empty() {
                return Err(subject_field_error(
                    "userset requires subjectResource, subjectObjectId and subjectRelation",
                ));
            }
            Ok(Subject::ActorSet(ActorSet {
                object: AcpObject::new(resource, object_id),
                relation: relation.into(),
            }))
        }
        other => Err(subject_field_error(&format!(
            "unsupported subjectKind {other}"
        ))),
    }
}

/// `did` as a relationship subject.
fn actor_subject(did: &Did) -> Result<Subject, ModuleError> {
    vera_modules::acp::relationship_values::actor(did)
        .map(Subject::Actor)
        .map_err(|error| subject_field_error(&error.to_string()))
}

fn subject_field_error(msg: &str) -> ModuleError {
    ModuleError::invalid(format!("subject: {msg}"))
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
) -> Result<Vec<Operation>, ModuleError> {
    if resources.len() != object_ids.len() || resources.len() != permissions.len() {
        return Err(ModuleError::invalid("array length mismatch".to_string()));
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
    inner: &DispatchResult,
    budget: &mut batch_results::Budget,
) -> DispatchReturn {
    let bytes = &inner.output.bytes;
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
        output: ModuleOutput::revert(gas_used, message.into_bytes().into()),
        logs: vec![],
        refusal: Some(
            inner
                .refusal
                .unwrap_or(vera_domain::RefusalKind::InvalidArgument),
        ),
    })
}

fn batch_error(index: usize, err: ModuleError) -> ModuleError {
    // Both are recognised by their leading sentinel, which a prefix would hide.
    if matches!(err, ModuleError::OutOfGas) || matches!(err, ModuleError::Fault(_)) {
        return err;
    }
    super::refusal::with_context(err, &format!("batch call {}: ", index + 1))
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
            return Ok(oog_dispatch());
        }
        batch::validate(input)?;
    }
    let result = dispatch_validated(
        module,
        vera,
        block_ctx,
        tx_ctx,
        input,
        gas_limit,
        &mut batch_results::Budget::new(),
    );
    match result {
        Err(ModuleError::OutOfGas) => Ok(oog_dispatch()),
        other => other,
    }
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
        return Ok(super::short_input());
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");

    if creation::handles(selector) {
        return creation::dispatch(module, vera, block_ctx, tx_ctx, input, gas_limit);
    }
    if commands::handles(selector) {
        return commands::dispatch(module, vera, block_ctx, tx_ctx, input, gas_limit);
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
                return Ok(oog_dispatch());
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

                let inner_gas = match gas_used.checked_add(inner.output.gas_used) {
                    Some(total) => total,
                    None => {
                        (*module, *vera) = snapshot;
                        return Ok(oog_dispatch());
                    }
                };

                if matches!(inner.output.status, ModuleStatus::OutOfGas) {
                    (*module, *vera) = snapshot;
                    return Ok(oog_dispatch());
                }

                if inner.output.status.is_revert() {
                    (*module, *vera) = snapshot;
                    return batch_revert(index, inner_gas, &inner, result_budget);
                }

                // Nested logs were already charged where they originated and are only moved here.
                let new_logs = if inner_call.starts_with(&IAcp::batchCallsCall::SELECTOR) {
                    &[][..]
                } else {
                    inner.logs.as_slice()
                };
                if let Err(error) = result_budget.retain(&inner.output.bytes, new_logs) {
                    (*module, *vera) = snapshot;
                    return Err(batch_error(index, error));
                }
                gas_used = inner_gas;
                results.push(inner.output.bytes);
                logs.extend(inner.logs);
            }

            let ret = IAcp::batchCallsCall::abi_encode_returns(&results);
            Ok(ok_dispatch(gas_used, ret, logs))
        }

        IAcp::bearerEditPolicyCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Ok(oog_dispatch());
            }
            let budget = PolicyEditBudget::new(gas_limit - WRITE_GAS);
            let call = IAcp::bearerEditPolicyCall::abi_decode(input).map_err(decode_error)?;
            let policy = std::str::from_utf8(&call.policy).map_err(|_| {
                crate::dispatch::refusal::refused(
                    vera_domain::RefusalKind::UndecodableInput,
                    "invalid UTF-8 in policy",
                )
            })?;
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
            let Ok(gas) = edit_gas(&budget) else {
                return Ok(oog_dispatch());
            };
            Ok(ok_dispatch(
                gas,
                IAcp::bearerEditPolicyCall::abi_encode_returns(&IAcp::bearerEditPolicyReturn {
                    relationshipsRemoved: removed,
                    record: json_bytes(&record),
                }),
                vec![event_log(ACP_ADDRESS, &event)],
            ))
        }

        IAcp::editPolicyCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Ok(oog_dispatch());
            }
            let budget = PolicyEditBudget::new(gas_limit - WRITE_GAS);
            let call = IAcp::editPolicyCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let policy_str = std::str::from_utf8(&call.policy).map_err(|_| {
                crate::dispatch::refusal::refused(
                    vera_domain::RefusalKind::UndecodableInput,
                    "invalid UTF-8 in policy",
                )
            })?;
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
            let Ok(gas) = edit_gas(&budget) else {
                return Ok(oog_dispatch());
            };
            Ok(ok_dispatch(gas, ret, vec![event_log(ACP_ADDRESS, &event)]))
        }

        IAcp::bearerCheckAccessCall::SELECTOR
        | IAcp::checkAccessCall::SELECTOR
        | IAcp::verifyAccessRequestCall::SELECTOR => {
            permissions::dispatch(module, vera, block_ctx, tx_ctx, input, gas_limit)
        }

        // ── Read methods ─────────────────────────────────────────────
        IAcp::getObjectOwnerCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
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

        IAcp::validatePolicyCall::SELECTOR => validation::dispatch(module, input, gas_limit),

        IAcp::getAccessDecisionCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
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
                return Ok(oog_dispatch());
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
                return Ok(oog_dispatch());
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
                return Ok(oog_dispatch());
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
                return Ok(oog_dispatch());
            }
            let call = IAcp::generateCommitmentCall::abi_decode(input).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;

            if call.resources.len() != call.objectIds.len() {
                return Err(ModuleError::invalid("array length mismatch".to_string()));
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
                return Ok(oog_dispatch());
            }
            // Zero-parameter function — no ABI decoding needed.
            let params = match module.query_params() {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IAcp::getParamsCall::abi_encode_returns(&json_bytes(&params));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        _ => Err(super::unknown_selector("ACP", selector)),
    }
}

fn build_relationship_selector(
    resource: &str,
    object_id: &str,
    relation: &str,
    actor: &str,
) -> Result<RelationshipSelector, ModuleError> {
    use vera_modules::acp::types::{ObjectSelector, RelationSelector, SubjectSelector};

    let object_selector = if resource.is_empty() && object_id.is_empty() {
        None
    } else if resource.is_empty() {
        return Err(ModuleError::invalid(
            "object selector requires a resource".to_string(),
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
        Some(SubjectSelector::Exact(actor_subject(&actor_did)?))
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
      - name: reader
    permissions:
      - name: read
        expr: reader
      - name: update
      - name: delete
";

    #[test]
    fn dispatch_create_policy_roundtrip() {
        let calldata = IAcp::createPolicyCall {
            policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
            marshalType: 1,
            nonce: Default::default(),
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
                    !dr.output.status.is_revert(),
                    "dispatch should not revert, output bytes: {}",
                    String::from_utf8_lossy(&dr.output.bytes)
                );
            }
            Err(e) => panic!("dispatch returned ModuleError: {e:?}"),
        }
    }

    #[test]
    fn dispatch_batch_calls_apply_multiple_mutations() {
        let calldata = IAcp::batchCallsCall {
            calls: vec![
                IAcp::createPolicyCall {
                    policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
                    marshalType: 1,
                    nonce: Default::default(),
                }
                .abi_encode()
                .into(),
                IAcp::createPolicyCall {
                    policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
                    marshalType: 1,
                    nonce: FixedBytes::repeat_byte(1),
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
        assert!(!result.output.status.is_revert());
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
            .create_policy(
                &creator,
                TEST_POLICY_YAML,
                PolicyMarshalingType::ShortYaml,
                Default::default(),
            )
            .unwrap();
        let policy_id =
            FixedBytes::from_slice(&hex::decode(&record.policy.id.to_string()).unwrap());

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

        let before = module.store().serialize();
        let result = dispatch(
            &mut module,
            &mut VeraModule::new(),
            &block_ctx,
            &tx_ctx,
            &calldata,
            1_000_000,
        )
        .unwrap();
        assert!(result.output.status.is_revert());
        assert!(result.output.gas_used > READ_GAS + 2 * WRITE_GAS);
        let message = std::str::from_utf8(&result.output.bytes).unwrap();
        assert!(
            message.starts_with("batch call 2 reverted: actor DID:"),
            "{message}"
        );
        assert!(result.logs.is_empty());
        assert_eq!(module.store().serialize(), before);

        let (registered, _) = module
            .query_object_owner(
                &record.policy.id.to_string(),
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
        assert_eq!(
            got,
            vera_modules::acp::relationship_values::actor_subject(&Did::new(ALICE_DID).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn decode_subject_wildcard() {
        assert_eq!(decode_subject(1, "", "", "").unwrap(), Subject::AllActors);
    }

    #[test]
    fn decode_subject_object_edge_has_empty_relation() {
        let got = decode_subject(2, "collection", "col1", "").unwrap();
        assert_eq!(
            got,
            vera_modules::acp::relationship_values::object_subject("collection", "col1")
        );
    }

    #[test]
    fn decode_subject_userset() {
        let got = decode_subject(3, "collection", "col1", "reader").unwrap();
        assert_eq!(
            got,
            vera_modules::acp::relationship_values::actor_set("collection", "col1", "reader")
        );
    }

    #[test]
    fn decode_subject_rejects_malformed() {
        assert!(
            decode_subject(4, "", "", "").is_err(),
            "kind 4 is not a subject kind"
        );
        assert!(decode_subject(7, "", "", "").is_err(), "unknown kind");
        assert!(
            decode_subject(0, "", "", "").is_err(),
            "an actor needs a DID"
        );
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
      - name: reader
    permissions:
      - name: read
        expr: reader
      - name: update
      - name: delete
  - name: document
    relations:
      - name: parent
        types: [collection]
      - name: viewer
        types: [collection->reader]
    permissions:
      - name: read
        expr: parent->reader + viewer
      - name: update
      - name: delete
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
            .create_policy(
                &creator,
                CROSS_POLICY_YAML,
                PolicyMarshalingType::ShortYaml,
                Default::default(),
            )
            .unwrap();
        let policy_id = record.policy.id.to_string();
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
            relation: "viewer".into(),
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
            !dr.output.status.is_revert(),
            "set subject should not revert: {}",
            String::from_utf8_lossy(&dr.output.bytes)
        );

        let selector = RelationshipSelector {
            object_selector: Some(ObjectSelector::Exact(Object {
                resource: "document".into(),
                id: "doc1".into(),
            })),
            relation_selector: Some(RelationSelector::Exact("viewer".into())),
            subject_selector: None,
        };
        let rels = module
            .query_filter_relationships(&policy_id, &selector)
            .unwrap();
        assert_eq!(rels.len(), 1, "userset edge stored");
        assert_eq!(
            rels[0].relationship.subject,
            vera_modules::acp::relationship_values::actor_set("collection", "col1", "reader"),
            "subject decoded to the actor set"
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
        assert!(
            !dr.output.status.is_revert(),
            "delete subject should not revert"
        );
        let rels = module
            .query_filter_relationships(&policy_id, &selector)
            .unwrap();
        assert!(rels.is_empty(), "userset edge removed after delete");
    }
}
