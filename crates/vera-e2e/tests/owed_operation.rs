//! A long-lived operation identity over an ordered list of policy commands.

use std::time::{SystemTime, UNIX_EPOCH};

use vera_client::Secp256k1SigningKey as SigningKey;
use vera_client::{
    BlsSigner, ClientError, PolicyOperation, VeraClient, administration::AdministrativeCommand,
    create_operation_token_with_lead,
};
use vera_crypto::operation::{DEFAULT_OPERATION_LEAD, OperationId};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::acp::types::{Object, PolicyCmd};

#[path = "support/administration.rs"]
mod administration_support;

const LEAD: u64 = 2 * 60 * 60;

fn register(policy: &str, name: &str) -> (String, PolicyCmd) {
    (
        policy.into(),
        PolicyCmd::RegisterObject(Object {
            resource: "file".into(),
            id: name.into(),
        }),
    )
}

#[tokio::test]
async fn an_owed_list_runs_under_the_raised_lead_once_and_only_as_signed() {
    let deployment = 9091;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(GenesisBuilder::devnet().operators(administration_support::operators()))
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let other = BlsSigner::new(8u64.into(), deployment).unwrap();
    let operator = BlsSigner::new(9u64.into(), deployment).unwrap();
    let created = client
        .native_create_policy(&worker, b"name: owed\nresources:\n  - name: file\n", 1, Default::default())
        .await
        .unwrap();
    let policy = client
        .read_policy_page(None, 1, created.block_number, &trusted)
        .await
        .unwrap()
        .records
        .remove(0)
        .policy
        .id;

    let key = SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
    let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_sec1_point(true).as_bytes(),
    )
    .unwrap();
    let approved = administration_support::approve(
        &client,
        AdministrativeCommand::SetPolicyOperationLead(LEAD),
        0,
    )
    .await;
    let genesis = approved.request.genesis_id;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let operation = PolicyOperation::list(vec![
        register(&policy, "first"),
        register(&policy, "second"),
    ])
    .unwrap();
    let identity = OperationId::new(now + LEAD - 60, [5; 24]);
    let sign = |submitter: &BlsSigner, operation: &PolicyOperation| {
        let claims = operation
            .claims(&actor, submitter.did(), deployment, genesis, identity, now)
            .unwrap();
        create_operation_token_with_lead(&key, &claims, LEAD).unwrap()
    };
    let token = sign(&worker, &operation);

    let refused = client
        .native_policy_operation(&worker, &token, &operation)
        .await;
    assert!(
        matches!(refused, Err(ClientError::Refused { .. })),
        "{refused:?}"
    );
    assert_eq!(
        client
            .read_policy_operation_lead(0, &trusted)
            .await
            .unwrap()
            .seconds,
        DEFAULT_OPERATION_LEAD
    );

    client
        .native_apply_administration(&operator, &approved)
        .await
        .unwrap();
    let raised = client
        .read_policy_operation_lead(0, &trusted)
        .await
        .unwrap();
    assert_eq!(raised.seconds, LEAD);

    let reordered = PolicyOperation::list(vec![
        register(&policy, "second"),
        register(&policy, "first"),
    ])
    .unwrap();
    let refused = client
        .native_policy_operation(&worker, &token, &reordered)
        .await;
    assert!(
        matches!(refused, Err(ClientError::Refused { .. })),
        "{refused:?}"
    );

    let applied = client
        .native_policy_operation(&worker, &token, &operation)
        .await
        .unwrap();
    let replayed = client
        .native_policy_operation(&other, &sign(&other, &operation), &operation)
        .await
        .unwrap();
    assert!(replayed.block_number >= applied.block_number);
    for name in ["first", "second"] {
        let object = Object {
            resource: "file".into(),
            id: name.into(),
        };
        let prefix = vera_client::object_owner_prefix(&policy, &object).unwrap();
        let owner = client
            .read_current_policy_prefix(
                &policy,
                &prefix,
                replayed.block_number,
                &trusted,
                vera_client::RECORD_PROOF_BYTES,
            )
            .await
            .unwrap()
            .verify_object_owner(&policy, &object, replayed.block_number, &trusted)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(owner.as_str(), actor);
    }
}
