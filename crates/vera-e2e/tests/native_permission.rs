//! Native permission evidence across a running consensus group and later denial.

#[path = "native_permission/policy_edits.rs"]
mod policy_edits;

use std::time::Duration;

use alloy_sol_types::SolCall;
use vera_client::{
    ACP_ADDRESS, AccessRequest, Actor, BlsSigner, ClientError, ModuleId, Object, Operation,
    PERMISSION_LIMITS, PermissionProof, PermissionRead, RECORD_PROOF_BYTES, VeraClient,
    verify_permission_proof,
};
use vera_domain::{ConsensusPublicKey, LightBlock, verify_finalized_block};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};
use vera_modules::acp::abi::IAcp;

const READER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const POLICY: &str = "\
name: native-permissions
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
      - name: blocked
        types: [actor]
    permissions:
      - name: read
        expr: reader - blocked
";

async fn submit(client: &VeraClient, signer: &BlsSigner, call: impl SolCall) -> u64 {
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    let receipt = client
        .wait_for_receipt(id, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
        .await
        .unwrap();
    assert_eq!(receipt.status, 1);
    receipt.block_number
}

async fn current_evidence(
    client: &VeraClient,
    policy: &str,
    request: &AccessRequest,
    minimum: u64,
    trusted: &ConsensusPublicKey,
) -> (LightBlock, PermissionProof) {
    let response: vera_client::PermissionResponse = client
        .rpc_call_typed(
            "vera_getCurrentPermissionProof",
            serde_json::json!([policy, request, minimum]),
        )
        .await
        .unwrap();
    let block = verify_finalized_block(&response.revision, trusted).unwrap();
    assert!(block.native_targets.is_some());
    assert!(block.height >= minimum);
    (response.revision, response.proof)
}

fn evaluate(
    light: &LightBlock,
    policy: &str,
    request: &AccessRequest,
    proof: &PermissionProof,
    trusted: &ConsensusPublicKey,
) -> bool {
    let block = verify_finalized_block(light, trusted).unwrap();
    verify_permission_proof(
        block.module_state_root,
        block.height,
        policy,
        request,
        proof,
        PERMISSION_LIMITS,
    )
    .unwrap()
}

#[tokio::test]
async fn native_permission_reads_follow_finalized_grants_and_denials() {
    permission_lifecycle(false).await;
}

#[tokio::test]
async fn pipelined_permission_reads_follow_finalized_grants_and_deletion() {
    permission_lifecycle(true).await;
}

async fn permission_lifecycle(pipelined: bool) {
    let deployment = if pipelined { 9057 } else { 9047 };
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let genesis = if pipelined {
        GenesisBuilder::devnet().simplex(vera_domain::SimplexParameters::default())
    } else {
        GenesisBuilder::devnet()
    };
    let mut cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(genesis)
        .preset(ConsensusPreset::Fast)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let observed = cluster.observe(Duration::from_millis(100));
    observed
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let owner = BlsSigner::new(1u64.into(), deployment).unwrap();
    submit(
        &client,
        &owner,
        IAcp::createPolicyCall {
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
        },
    )
    .await;
    let policy = client.get_policy_ids().await.unwrap().remove(0);
    let granted = submit(
        &client,
        &owner,
        IAcp::batchCallsCall {
            calls: vec![
                IAcp::registerObjectCall {
                    policyId: policy.parse().unwrap(),
                    resource: "document".into(),
                    objectId: "report".into(),
                }
                .abi_encode()
                .into(),
                IAcp::setRelationshipCall {
                    policyId: policy.parse().unwrap(),
                    resource: "document".into(),
                    objectId: "report".into(),
                    relation: "reader".into(),
                    actor: READER.into(),
                }
                .abi_encode()
                .into(),
            ],
        },
    )
    .await;
    let object = Object {
        resource: "document".into(),
        id: "report".into(),
    };
    let owner_prefix = vera_client::object_owner_prefix(&policy, &object).unwrap();
    let ownership = client
        .read_current_policy_prefix(
            &policy,
            &owner_prefix,
            granted,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership
            .verify_object_owner(&policy, &object, granted, &trusted)
            .unwrap()
            .unwrap()
            .0
            .as_str(),
        owner.did()
    );
    assert!(
        ownership
            .verify_object_owner(&policy, &object, ownership.revision.height + 1, &trusted)
            .is_err()
    );
    let unrelated_trust = *KeySet::builder()
        .seed(deployment + 1)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    assert!(
        ownership
            .verify_object_owner(&policy, &object, granted, &unrelated_trust)
            .is_err()
    );
    let policy_key = vera_modules::acp::keys::policy_key(&policy);
    let policy_record = client
        .read_current_record(
            ModuleId::Acp,
            &policy_key,
            granted,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert!(policy_record.record.value.is_some());
    let missing = client
        .read_current_record(
            ModuleId::Acp,
            b"missing",
            granted,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert!(missing.record.value.is_none());
    let request = AccessRequest {
        actor: Actor(READER.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "document".into(),
                id: "report".into(),
            },
            permission: "read".into(),
        }],
    };
    let (allowed_revision, proof) =
        current_evidence(&client, &policy, &request, granted, &trusted).await;
    assert!(evaluate(
        &allowed_revision,
        &policy,
        &request,
        &proof,
        &trusted
    ));
    assert!(proof.roots.is_some());
    assert!(proof.reads.iter().all(|read| matches!(
        read,
        PermissionRead::CurrentPoint { .. } | PermissionRead::CurrentPrefix { .. }
    )));
    let denied = submit(
        &client,
        &owner,
        IAcp::setRelationshipCall {
            policyId: policy.parse().unwrap(),
            resource: "document".into(),
            objectId: "report".into(),
            relation: "blocked".into(),
            actor: READER.into(),
        },
    )
    .await;
    observed
        .wait_for_height(denied + 2, Duration::from_secs(30))
        .await
        .unwrap();
    assert!(matches!(
        client
            .verify_access_at(
                &policy,
                &request,
                &allowed_revision,
                &trusted,
                PERMISSION_LIMITS
            )
            .await,
        Err(ClientError::Rpc { code: -32002, .. })
    ));
    for index in 0..cluster.node_count() {
        let replica = VeraClient::new(cluster.node(index).rpc_url());
        let current = replica
            .read_current_record(
                ModuleId::Acp,
                &policy_key,
                denied,
                &trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .unwrap();
        assert_eq!(current.record.value, policy_record.record.value);
        let mut mixed = policy_record.clone();
        mixed.revision = current.revision;
        assert!(
            mixed
                .verify(
                    ModuleId::Acp,
                    &policy_key,
                    denied,
                    &trusted,
                    RECORD_PROOF_BYTES
                )
                .is_err()
        );
        let (denied_revision, denied_proof) =
            current_evidence(&replica, &policy, &request, denied, &trusted).await;
        assert!(
            !evaluate(&denied_revision, &policy, &request, &denied_proof, &trusted),
            "node {index} must deny the blocked reader"
        );
        let block = verify_finalized_block(&denied_revision, &trusted).unwrap();
        assert!(
            verify_permission_proof(
                block.module_state_root,
                denied,
                &policy,
                &request,
                &proof,
                PERMISSION_LIMITS,
            )
            .is_err(),
            "the old grant must not verify at the new root"
        );
        let mut owner_request = request.clone();
        owner_request.actor = Actor(owner.did().parse().unwrap());
        let (_, allowed) = replica
            .verify_current_access(&policy, &owner_request, denied, &trusted, PERMISSION_LIMITS)
            .await
            .unwrap();
        assert!(allowed);
    }
    let mut owner_request = request.clone();
    owner_request.actor = Actor(owner.did().parse().unwrap());
    let reads = async {
        let mut minimum = denied;
        for _ in 0..20 {
            let (revision, allowed) = client
                .verify_current_access(
                    &policy,
                    &owner_request,
                    minimum,
                    &trusted,
                    PERMISSION_LIMITS,
                )
                .await
                .unwrap();
            assert!(allowed);
            let record = client
                .read_current_record(
                    ModuleId::Acp,
                    &policy_key,
                    revision.height,
                    &trusted,
                    RECORD_PROOF_BYTES,
                )
                .await
                .unwrap();
            assert_eq!(record.record.value, policy_record.record.value);
            let owners = client
                .read_current_policy_prefix(
                    &policy,
                    &owner_prefix,
                    record.revision.height,
                    &trusted,
                    RECORD_PROOF_BYTES,
                )
                .await
                .unwrap();
            assert!(
                owners
                    .verify_object_owner(&policy, &object, record.revision.height, &trusted)
                    .unwrap()
                    .is_some()
            );
            minimum = owners.revision.height;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let writes = async {
        for index in 0..4 {
            submit(
                &client,
                &owner,
                IAcp::registerObjectCall {
                    policyId: policy.parse().unwrap(),
                    resource: "document".into(),
                    objectId: format!("concurrent-{index}"),
                },
            )
            .await;
        }
    };
    tokio::join!(reads, writes);
    if pipelined {
        policy_edits::exercise(&mut cluster, &policy, &owner, &request, &trusted).await;
    }
    let archived = submit(
        &client,
        &owner,
        IAcp::archiveObjectCall {
            policyId: policy.parse().unwrap(),
            resource: object.resource.clone(),
            objectId: object.id.clone(),
        },
    )
    .await;
    observed
        .wait_for_height(archived + 2, Duration::from_secs(30))
        .await
        .unwrap();
    for index in 0..cluster.node_count() {
        let replica = VeraClient::new(cluster.node(index).rpc_url());
        let current = replica
            .read_current_policy_prefix(
                &policy,
                &owner_prefix,
                archived,
                &trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .unwrap();
        assert!(
            current
                .verify_object_owner(&policy, &object, archived, &trusted)
                .unwrap()
                .is_none()
        );
        let mut mixed = ownership.clone();
        mixed.revision = current.revision.clone();
        assert!(
            mixed
                .verify_object_owner(&policy, &object, archived, &trusted)
                .is_err()
        );
        let other = Object {
            resource: object.resource.clone(),
            id: "never-registered".into(),
        };
        assert!(
            current
                .verify_object_owner(&policy, &other, archived, &trusted)
                .is_err()
        );
        let missing = replica
            .read_current_policy_prefix(
                &policy,
                &vera_client::object_owner_prefix(&policy, &other).unwrap(),
                archived,
                &trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .unwrap();
        assert!(
            missing
                .verify_object_owner(&policy, &other, archived, &trusted)
                .unwrap()
                .is_none()
        );
    }
    let deleted = submit(
        &client,
        &owner,
        IAcp::deletePolicyCall {
            policyId: policy.parse().unwrap(),
        },
    )
    .await;
    let live_object = Object {
        resource: "document".into(),
        id: "concurrent-0".into(),
    };
    let live_prefix = vera_client::object_owner_prefix(&policy, &live_object).unwrap();
    for index in 0..cluster.node_count() {
        let replica = VeraClient::new(cluster.node(index).rpc_url());
        let deleted_owner = replica
            .read_current_policy_prefix(
                &policy,
                &live_prefix,
                deleted,
                &trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .unwrap();
        assert!(deleted_owner.proof.policy.value.is_none());
        assert!(
            deleted_owner
                .verify_object_owner(&policy, &live_object, deleted, &trusted)
                .unwrap()
                .is_none()
        );
        let page = replica
            .read_relationship_page(policy.parse().unwrap(), None, 8, deleted, &trusted)
            .await
            .unwrap();
        assert!(page.records.is_empty());
        assert!(page.continuation.is_none());
    }
    assert!(
        ownership
            .verify_object_owner(&policy, &object, deleted, &trusted)
            .is_err()
    );
    cluster.restart_node(0).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let restarted = VeraClient::new(cluster.node(0).rpc_url());
    let current = restarted
        .read_current_policy_prefix(
            &policy,
            &owner_prefix,
            deleted,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert!(current.proof.policy.value.is_none());
    assert!(
        current
            .verify_object_owner(&policy, &object, deleted, &trusted)
            .unwrap()
            .is_none()
    );
}
