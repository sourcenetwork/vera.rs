//! Replays fixtures produced by tools/acp-oracle against acp_core v0.8.2.
use acp::{Relationship, Subject};
use identity::Did;
use serde::{Deserialize, Serialize};
use vera_modules::{
    acp::{
        AcpModule,
        error::AcpError,
        types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
    },
    kv_store::InMemoryKvStore,
};

#[derive(Deserialize)]
struct Case {
    name: String,
    policy: String,
    steps: Vec<Step>,
    create_error: bool,
    results: Vec<Outcome>,
}
#[derive(Deserialize)]
struct Step {
    #[serde(default)]
    policy: String,
    #[serde(default)]
    blob: String,
    op: String,
    actor: String,
    resource: String,
    object: String,
    relation: String,
    subject: String,
    #[serde(default)]
    subject_resource: String,
    #[serde(default)]
    subject_object: String,
    #[serde(default)]
    subject_relation: String,
}
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Outcome {
    #[serde(default)]
    blob: String,
    #[serde(default)]
    count: Option<u64>,
    error: bool,
    #[serde(default)]
    value: Option<bool>,
    #[serde(default)]
    owner: String,
}

fn evaluate(module: &mut AcpModule, policy: &str, step: &Step) -> Result<Outcome, AcpError> {
    let actor = Did::new(step.actor.as_str()).unwrap();
    let object = Object {
        resource: step.resource.clone(),
        id: step.object.clone(),
    };
    let subject = if !step.subject_resource.is_empty() {
        Subject::entity_set(
            &step.subject_resource,
            &step.subject_object,
            &step.subject_relation,
        )
    } else if step.subject == "*" {
        Subject::Wildcard
    } else {
        Subject::Entity(Did::new(step.subject.as_str()).unwrap())
    };
    let rel = Relationship::new(&step.resource, &step.object, &step.relation, subject);
    let mut result = Outcome::default();
    match step.op.as_str() {
        "edit" => {
            result.count = Some(
                module
                    .edit_policy(
                        &actor,
                        policy,
                        &step.policy,
                        PolicyMarshalingType::ShortYaml,
                    )?
                    .0,
            )
        }
        "metadata" => {
            module.edit_policy_metadata(
                &actor,
                policy,
                vera_modules::acp::types::SuppliedMetadata {
                    blob: step.blob.as_bytes().to_vec(),
                    ..Default::default()
                },
                &vera_modules::types::Timestamp {
                    block_height: 1,
                    seconds: 1,
                },
            )?;
        }
        "policy" => {
            result.blob =
                String::from_utf8(module.query_policy(policy)?.supplied_metadata.blob).unwrap()
        }
        "theorem" => result.value = Some(module.evaluate_theorem(policy, &step.policy)?.ok),
        "check" => {
            result.value = Some(module.query_verify_access_request(
                policy,
                &AccessRequest {
                    actor: Actor(Did::new(step.subject.as_str()).unwrap()),
                    operations: vec![Operation {
                        object,
                        permission: step.relation.clone(),
                    }],
                },
            )?)
        }
        "manage" => {
            result.value = Some(module.check_management_authority(
                &Did::new(step.subject.as_str()).unwrap(),
                policy,
                &object,
                &step.relation,
            )?)
        }
        "owner" => {
            let record = module.query_object_registration(policy, &object)?;
            result.value = Some(record.is_some());
            result.owner = record.map_or_else(String::new, |record| record.metadata.owner_did);
        }
        op => {
            let cmd = match op {
                "register" => PolicyCmd::RegisterObject(object),
                "set" => PolicyCmd::SetRelationship(rel),
                "delete" => PolicyCmd::DeleteRelationship(rel),
                "transfer" => PolicyCmd::TransferObject {
                    object,
                    new_owner: Actor(Did::new(step.subject.as_str()).unwrap()),
                },
                "archive" => PolicyCmd::ArchiveObject(object),
                "unarchive" => PolicyCmd::UnarchiveObject(object),
                _ => panic!("unknown fixture operation {op}"),
            };
            module.execute_policy_cmd_with_metadata(
                &actor,
                policy,
                vera_modules::acp::types::PolicyCommandRequest {
                    command: cmd,
                    metadata: vera_modules::acp::types::SuppliedMetadata {
                        blob: step.blob.as_bytes().to_vec(),
                        ..Default::default()
                    },
                },
                &vera_modules::types::BlockExecCtx {
                    timestamp: vera_modules::types::Timestamp {
                        block_height: 1,
                        seconds: 1,
                    },
                    ..Default::default()
                },
                &vera_modules::types::TxExecCtx {
                    signer: actor.to_string(),
                    tx_hash: vec![1; 32],
                    sequence: 0,
                },
            )?;
        }
    }
    Ok(result)
}

#[test]
fn go_v082_operations_match_before_and_after_restore() {
    let cases: Vec<Case> = serde_json::from_str(include_str!("fixtures/acp_v1.json")).unwrap();
    let mut mismatches = Vec::new();
    for case in cases {
        let mut module = AcpModule::new();
        let record = module.create_policy(
            &Did::new("did:key:creator").unwrap(),
            &case.policy,
            PolicyMarshalingType::ShortYaml,
        );
        // Existing Rust syntax permits explicit owner declarations/references. Unknown
        // specifications are rejected instead of silently becoming unrestricted policies.
        let expected_error = match case.name.as_str() {
            "reserved-owner-relation" | "permission-owner-reference" | "owner-tuple-source" => {
                false
            }
            "unknown-specification" => true,
            _ => case.create_error,
        };
        if record.is_err() != expected_error {
            mismatches.push(format!(
                "{}: create error {:?}, expected {expected_error}",
                case.name,
                record.as_ref().err()
            ));
        }
        let Ok(record) = record else {
            continue;
        };
        assert_eq!(case.steps.len(), case.results.len());
        for (index, (step, expected)) in case.steps.iter().zip(&case.results).enumerate() {
            let before = module.store().serialize();
            let result = evaluate(&mut module, &record.policy.id, step);
            if result.is_err() {
                assert_eq!(
                    module.store().serialize(),
                    before,
                    "{} step {index} partially mutated state",
                    case.name
                );
            }
            let actual = result.unwrap_or_else(|_| Outcome {
                error: true,
                ..Default::default()
            });
            if &actual != expected {
                mismatches.push(format!(
                    "{} step {index} {}: {actual:?} != {expected:?}",
                    case.name, step.op
                ));
            }
            module = AcpModule::from_store(
                InMemoryKvStore::deserialize(&module.store().serialize()).unwrap(),
            );
            module.validate_restored_state().unwrap();
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
