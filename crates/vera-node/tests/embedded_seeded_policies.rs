//! Policies a solo deployment starts with, under the identifiers its host chose.

mod support;

use std::time::{Duration, Instant};

use serde_json::json;
use support::{block_on, config, finalize_a_write};
use vera_client::{BlsSigner, ModuleId, RECORD_PROOF_BYTES, RecordResponse};
use vera_modules::acp::{
    AcpModule, PlacedPolicy, keys,
    types::{PolicyMarshalingType, PolicyRecord},
};
use vera_node::{EmbedError, EmbeddedConfig, EmbeddedNode, SoloError};

const OWNER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const NOTES: &str = "name: notes\nresources:\n  - name: note\n";
const TASKS: &str = "name: tasks\nresources:\n  - name: task\n";

fn seeded(directory: &std::path::Path, definitions: &[&str]) -> EmbeddedConfig {
    let mut config = config(directory, 9_301);
    config.genesis.policies = definitions
        .iter()
        .map(|definition| PlacedPolicy {
            definition: (*definition).to_string(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            counter: 0,
            owner: OWNER.into(),
        })
        .collect();
    config
}

fn stored_policy(node: &EmbeddedNode, id: &str) -> Option<PolicyRecord> {
    let key = keys::policy_key(id);
    // An idle node certifies its first revision at the first heartbeat.
    let deadline = Instant::now() + Duration::from_secs(60);
    let response: RecordResponse = loop {
        match block_on(node.rpc().request(
            "vera_getCurrentRecordProof",
            vec![
                json!(ModuleId::Acp),
                json!(alloy_primitives::Bytes::copy_from_slice(&key)),
                json!(0),
            ],
        )) {
            Ok(response) => break response,
            Err(error) => assert!(Instant::now() < deadline, "record proof: {error}"),
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    response
        .verify(
            ModuleId::Acp,
            &key,
            0,
            node.consensus_key(),
            RECORD_PROOF_BYTES,
        )
        .unwrap();
    response
        .record
        .value
        .map(|value| serde_json::from_slice(&value).unwrap())
}

#[test]
fn a_deployment_starts_with_its_policies_under_the_chosen_identifiers() {
    let directory = tempfile::tempdir().unwrap();
    let yaml = PolicyMarshalingType::ShortYaml;
    let node = block_on(EmbeddedNode::start(seeded(
        directory.path(),
        &[NOTES, TASKS],
    )))
    .unwrap();
    for definition in [NOTES, TASKS] {
        let id = AcpModule::predict_policy_id(definition, &yaml, 0).unwrap();
        let record = stored_policy(&node, &id).expect("seeded policy");
        assert_eq!(record.policy.id, id);
        assert_eq!(record.raw_policy, definition);
        assert_eq!(record.metadata.owner_did, OWNER);
    }
    let unseeded = AcpModule::predict_policy_id(NOTES, &yaml, 1).unwrap();
    assert!(stored_policy(&node, &unseeded).is_none());
    finalize_a_write(&node, &BlsSigner::new(7u64.into(), 9_301).unwrap());
    block_on(node.stop()).unwrap();

    let reopened = block_on(EmbeddedNode::start(seeded(
        directory.path(),
        &[NOTES, TASKS],
    )))
    .unwrap();
    let id = AcpModule::predict_policy_id(TASKS, &yaml, 0).unwrap();
    assert!(stored_policy(&reopened, &id).is_some());
    block_on(reopened.stop()).unwrap();

    assert!(matches!(
        block_on(EmbeddedNode::start(seeded(directory.path(), &[NOTES]))),
        Err(EmbedError::Deployment(SoloError::Mismatch(
            "seeded policies"
        )))
    ));
}
