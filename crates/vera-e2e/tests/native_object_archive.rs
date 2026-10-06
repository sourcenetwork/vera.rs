//! Certified object archive lifecycle on four pipelined native validators.

#[path = "native_object_archive/support.rs"]
mod support;

use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use std::time::{SystemTime, UNIX_EPOCH};
use vera_client::{
    ACP_ADDRESS, AccessRequest, Actor, BlsSigner, ModuleId, Object, Operation, PERMISSION_LIMITS,
    RECORD_PROOF_BYTES, VeraClient,
};
use vera_crypto::jwt::DelegationScope;
use vera_domain::ConsensusPublicKey;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::acp::{
    abi::IAcp,
    keys, object_state,
    types::{PolicyCmd, PolicyCmdResult, RelationshipRecord},
};

const DEPLOYMENT: u64 = 9109;
const POLICY: &str = "name: native-object-archive\nresources:\n  - name: file\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n";

#[tokio::test]
async fn pipelined_object_archive_preserves_exact_counts_and_regrants_after_restart() {
    let keys = KeySet::builder().seed(DEPLOYMENT).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let mut cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(DEPLOYMENT)
        .chain_id(DEPLOYMENT)
        .genesis(
            GenesisBuilder::devnet()
                .simplex(vera_domain::SimplexParameters::default())
                .blocks_per_epoch(192),
        )
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    support::publication(&cluster, 3).await;
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let worker = BlsSigner::new(7u64.into(), DEPLOYMENT).unwrap();
    let key = k256::ecdsa::SigningKey::from_bytes((&[43u8; 32]).into()).unwrap();
    let issued = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires = issued + vera_crypto::operation::MAX_OPERATION_TTL;
    let create_token = vera_client::create_scoped_bearer_token(
        &key,
        worker.did(),
        DEPLOYMENT,
        issued,
        expires,
        DelegationScope::CreatePolicy,
    )
    .unwrap();
    let actor = vera_crypto::jwt::verify_bearer_token(&create_token)
        .unwrap()
        .iss;
    let token = vera_client::create_scoped_bearer_token(
        &key,
        worker.did(),
        DEPLOYMENT,
        issued,
        expires,
        DelegationScope::PolicyCommands,
    )
    .unwrap();
    let created = support::submit(
        &cluster,
        &worker,
        &trusted,
        IAcp::bearerCreatePolicyCall {
            bearerToken: create_token,
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
        },
    )
    .await;
    let page = client
        .read_policy_page(None, 1, created.block_number, &trusted)
        .await
        .unwrap();
    assert!(page.continuation.is_none());
    assert_eq!(page.records.len(), 1);
    let policy = page.records[0].policy.id.clone();
    assert_eq!(page.records[0].metadata.owner_did, actor);
    let policy_id: B256 = policy.parse().unwrap();
    let genesis = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse::<B256>()
        .unwrap()
        .0;
    let controller = support::Controller {
        key,
        actor,
        token,
        issued,
        expires,
        genesis,
    };
    let reader = BlsSigner::new(8u64.into(), DEPLOYMENT)
        .unwrap()
        .did()
        .to_owned();
    let other_reader = BlsSigner::new(9u64.into(), DEPLOYMENT)
        .unwrap()
        .did()
        .to_owned();
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let incoming = acp::Relationship::new(
        "file",
        "child",
        "reader",
        acp::Subject::entity_set("file", "report", "reader"),
    );
    let reader_grant =
        acp::Relationship::with_entity("file", "report", "reader", reader.parse().unwrap());
    let commands = [
        PolicyCmd::RegisterObject(object.clone()),
        PolicyCmd::RegisterObject(Object {
            resource: "file".into(),
            id: "child".into(),
        }),
        PolicyCmd::SetRelationship(reader_grant.clone()),
        PolicyCmd::SetRelationship(acp::Relationship::with_entity(
            "file",
            "report",
            "reader",
            other_reader.parse().unwrap(),
        )),
        PolicyCmd::SetRelationship(incoming.clone()),
    ];
    let setup = support::submit(
        &cluster,
        &worker,
        &trusted,
        IAcp::batchCallsCall {
            calls: commands
                .iter()
                .map(|command| {
                    support::command(&controller.token, policy_id, command)
                        .abi_encode()
                        .into()
                })
                .collect(),
        },
    )
    .await;
    let initial = client
        .read_relationship_page(policy_id, None, 16, setup.block_number, &trusted)
        .await
        .unwrap();
    assert!(initial.continuation.is_none());
    let incoming = initial
        .records
        .iter()
        .find(|row| row.relationship == incoming)
        .unwrap()
        .clone();
    let old_rows: Vec<_> = initial
        .records
        .iter()
        .filter(|row| {
            row.relationship.object_id == "report" && row.relationship.relation == "reader"
        })
        .cloned()
        .collect();
    assert_eq!(old_rows.len(), 2);
    support::check_members(
        &cluster,
        &policy,
        &controller.actor,
        &reader,
        setup.block_number,
        &trusted,
        support::Expected {
            allowed: true,
            owned: true,
            incarnation: 0,
            rows: 5,
            incoming: &incoming,
        },
    )
    .await;

    let archived = controller
        .archive(&cluster, &worker, &trusted, &policy, 1, 3)
        .await;
    support::check_members(
        &cluster,
        &policy,
        &controller.actor,
        &reader,
        archived,
        &trusted,
        support::Expected {
            allowed: false,
            owned: false,
            incarnation: 1,
            rows: 3,
            incoming: &incoming,
        },
    )
    .await;
    let repeated = controller
        .archive(&cluster, &worker, &trusted, &policy, 2, 0)
        .await;
    support::check_members(
        &cluster,
        &policy,
        &controller.actor,
        &reader,
        repeated,
        &trusted,
        support::Expected {
            allowed: false,
            owned: false,
            incarnation: 1,
            rows: 3,
            incoming: &incoming,
        },
    )
    .await;
    let unarchived = support::submit(
        &cluster,
        &worker,
        &trusted,
        support::command(
            &controller.token,
            policy_id,
            &PolicyCmd::UnarchiveObject(object),
        ),
    )
    .await;
    support::check_members(
        &cluster,
        &policy,
        &controller.actor,
        &reader,
        unarchived.block_number,
        &trusted,
        support::Expected {
            allowed: false,
            owned: true,
            incarnation: 1,
            rows: 3,
            incoming: &incoming,
        },
    )
    .await;
    let regranted = support::submit(
        &cluster,
        &worker,
        &trusted,
        support::command(
            &controller.token,
            policy_id,
            &PolicyCmd::SetRelationship(reader_grant),
        ),
    )
    .await;
    // This live fixture proves cleanup completion, not overlap with the regrant.
    // The module regressions cover regrant while a larger old incarnation remains.
    let settled = regranted.block_number + 8;
    support::old_rows_absent(&cluster, &old_rows, settled, &trusted).await;
    support::check_members(
        &cluster,
        &policy,
        &controller.actor,
        &reader,
        settled,
        &trusted,
        support::Expected {
            allowed: true,
            owned: true,
            incarnation: 1,
            rows: 4,
            incoming: &incoming,
        },
    )
    .await;

    for index in 0..cluster.node_count() {
        cluster.restart_node(index).unwrap();
        cluster
            .wait_ready(vera_e2e::readiness_deadline())
            .await
            .unwrap();
        support::publication(&cluster, settled).await;
    }
    support::check_members(
        &cluster,
        &policy,
        &controller.actor,
        &reader,
        settled + 2,
        &trusted,
        support::Expected {
            allowed: true,
            owned: true,
            incarnation: 1,
            rows: 4,
            incoming: &incoming,
        },
    )
    .await;
    support::old_rows_absent(&cluster, &old_rows, settled + 2, &trusted).await;
}
