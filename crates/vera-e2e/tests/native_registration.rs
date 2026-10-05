//! Registration priority and ownership transfer through certified native execution.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::{SolCall as _, SolEvent as _};
use std::time::Duration;
use vera_client::{ACP_ADDRESS, Actor, BlsSigner, Object, RECORD_PROOF_BYTES, VeraClient};
use vera_domain::{ConsensusPublicKey, ExecutionReceipt, NativeTx};
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use vera_modules::acp::{abi::IAcp, types::RelationshipRecord};

async fn submit(
    client: &VeraClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: Vec<u8>,
) -> (u64, ExecutionReceipt) {
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, Bytes::from(call))
        .unwrap();
    let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), id);
    certified_receipt(client, id, trusted).await
}

async fn certified_receipt(
    client: &VeraClient,
    id: B256,
    trusted: &ConsensusPublicKey,
) -> (u64, ExecutionReceipt) {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(Some(response)) = client.read_receipt(id, trusted).await {
                return (
                    response.revision.height,
                    response.verify(id, trusted).unwrap().clone(),
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("certified registration receipt deadline")
}

#[tokio::test]
async fn native_registration_preserves_commitment_priority_and_owner_proofs() {
    registration_workflow(false).await;
}

#[tokio::test]
async fn native_registration_survives_journal_pruning() {
    registration_workflow(true).await;
}

async fn registration_workflow(pruning: bool) {
    let deployment = 9083;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let mut cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .jmt_seeder(move |dir, _| {
            if pruning {
                use std::io::Write as _;
                let mut config = std::fs::OpenOptions::new().append(true)
                    .open(dir.join("config.toml")).unwrap();
                writeln!(config, "\n[pruning]\nmaintenance_interval = 1\nretained_consensus_revisions = 18\nretained_state_revisions = 0").unwrap();
            }
        })
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let empty = client.read_policy_page(None, 1, 0, &trusted).await.unwrap();
    assert!(empty.records.is_empty());
    assert!(empty.continuation.is_none());
    let first = BlsSigner::new(7u64.into(), deployment).unwrap();
    let second = BlsSigner::new(8u64.into(), deployment).unwrap();
    let created = client.native_create_policy(&first, br#"{"name":"registrations","resources":[{"name":"file","permissions":[{"name":"read","expr":"owner"}]}]}"#, 2).await.unwrap();
    let page = client
        .read_policy_page(None, 1, created.block_number, &trusted)
        .await
        .unwrap();
    assert!(page.continuation.is_none());
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].metadata.owner_did, first.did());
    let policy = page.records[0].policy.id.clone();
    let policy_id: B256 = policy.parse().unwrap();
    let selected = client
        .read_policy(policy_id, page.revision, &trusted)
        .await
        .unwrap();
    assert!(selected.revision >= page.revision);
    assert_eq!(
        serde_json::to_value(selected.value.as_ref().unwrap()).unwrap(),
        serde_json::to_value(&page.records[0]).unwrap()
    );
    assert!(
        client
            .read_policy(B256::ZERO, selected.revision, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let empty_relationships = client
        .read_relationship_page(policy_id, None, 1, selected.revision, &trusted)
        .await
        .unwrap();
    assert!(empty_relationships.records.is_empty());
    assert!(empty_relationships.continuation.is_none());
    let extra = client
        .native_create_policy(
            &first,
            b"name: another
resources:
  - name: file
",
            1,
        )
        .await
        .unwrap();
    let first_page = client
        .read_policy_page(None, 1, extra.block_number, &trusted)
        .await
        .unwrap();
    assert_eq!(first_page.records.len(), 1);
    assert!(first_page.continuation.is_some());
    let last_page = client
        .read_policy_page(first_page.continuation, 1, first_page.revision, &trusted)
        .await
        .unwrap();
    assert_eq!(last_page.records.len(), 1);
    assert!(last_page.continuation.is_none());
    assert!(first_page.records[0].policy.id < last_page.records[0].policy.id);
    assert!(first_page.records[0].policy.id == policy || last_page.records[0].policy.id == policy);

    let generated = vera_client::registrations::generate_registration_commitment(
        policy_id,
        &[Object {
            resource: "file".into(),
            id: "report".into(),
        }],
        &Actor(second.did().parse().unwrap()),
    )
    .unwrap();
    let commitment = B256::from_slice(&generated.commitment);
    let committed = client
        .native_commit_registrations(&second, policy_id, commitment)
        .await
        .unwrap();
    let (early_height, early) =
        certified_receipt(&client, committed.transaction_hash, &trusted).await;
    assert!(early.success());
    let early = IAcp::RegistrationsCommitted::decode_log(&early.logs()[0]).unwrap();
    assert_eq!(early.data.policyId, policy_id);
    assert_eq!(early.data.commitment.as_slice(), generated.commitment);
    let registered = client
        .native_register_object(&first, policy_id, "report", "file")
        .await
        .unwrap();
    assert!(registered.block_number > early_height);
    let committed = client
        .native_commit_registrations(&second, policy_id, commitment)
        .await
        .unwrap();
    let (late_height, late) =
        certified_receipt(&client, committed.transaction_hash, &trusted).await;
    assert!(late.success());
    let late = IAcp::RegistrationsCommitted::decode_log(&late.logs()[0]).unwrap();
    let commitment = client
        .read_registration_commitment(policy_id, early.data.commitmentId, late_height, &trusted)
        .await
        .unwrap();
    assert!(commitment.revision >= late_height);
    let record = commitment.value.unwrap();
    assert_eq!(record.commitment, generated.commitment);
    assert_eq!(record.metadata.creation_ts.block_height, early_height);
    assert_eq!(record.metadata.owner_did, second.did());
    assert!(
        client
            .read_registration_commitment(
                B256::ZERO,
                early.data.commitmentId,
                late_height,
                &trusted,
            )
            .await
            .is_err()
    );
    assert!(
        client
            .read_registration_commitment(policy_id, u64::MAX, late_height, &trusted,)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let first_page = client
        .read_registration_commitment_ids(early.data.commitment, None, 1, late_height, &trusted)
        .await
        .unwrap();
    assert_eq!(first_page.ids, vec![early.data.commitmentId]);
    assert!(first_page.continuation.is_some());
    let second_page = client
        .read_registration_commitment_ids(
            early.data.commitment,
            first_page.continuation,
            1,
            first_page.revision,
            &trusted,
        )
        .await
        .unwrap();
    assert_eq!(second_page.ids, vec![late.data.commitmentId]);
    assert!(second_page.continuation.is_none());
    let missing = client
        .read_registration_commitment_ids(B256::ZERO, None, 1, late_height, &trusted)
        .await
        .unwrap();
    assert!(missing.ids.is_empty());
    assert!(missing.continuation.is_none());
    let reveal = |id| {
        IAcp::revealRegistrationCall {
            commitmentId: id,
            proof: serde_json::to_vec(&generated.proofs[0]).unwrap().into(),
        }
        .abi_encode()
    };
    let (_, rejected) = submit(&client, &second, &trusted, reveal(late.data.commitmentId)).await;
    assert!(!rejected.success());
    let revealed = client
        .native_reveal_registration(&second, early.data.commitmentId, &generated.proofs[0])
        .await
        .unwrap();
    let (amended_height, amended) =
        certified_receipt(&client, revealed.transaction_hash, &trusted).await;
    assert!(amended.success());
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let prefix = vera_client::object_owner_prefix(&policy, &object).unwrap();
    let ownership = client
        .read_current_policy_prefix(
            &policy,
            &prefix,
            amended_height,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership
            .verify_object_owner(&policy, &object, amended_height, &trusted)
            .unwrap(),
        Some(Actor(second.did().parse().unwrap()))
    );
    let records = ownership
        .verify(
            &policy,
            &prefix,
            amended_height,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .unwrap();
    let records = records.expect("the registration policy is live");
    assert_eq!(records.entries.len(), 1);
    let record: RelationshipRecord = serde_json::from_slice(&records.entries[0].value).unwrap();
    assert_eq!(record.metadata.creation_ts.block_height, early_height);
    let archive = || {
        IAcp::archiveObjectCall {
            policyId: policy_id,
            objectId: "report".into(),
            resource: "file".into(),
        }
        .abi_encode()
    };
    assert!(
        !submit(&client, &first, &trusted, archive())
            .await
            .1
            .success()
    );
    assert!(
        submit(&client, &second, &trusted, archive())
            .await
            .1
            .success()
    );
    if pruning {
        cluster
            .observe(Duration::from_millis(100))
            .wait_for_height(300, Duration::from_secs(180))
            .await
            .unwrap();
        for index in 0..cluster.node_count() {
            let node = cluster.node(index);
            let logs = std::fs::read_to_string(node.log_dir.join("stdout.log")).unwrap();
            assert!(
                logs.matches("pruned state journals").count() > 10,
                "expected repeated completed pruning on every replica"
            );
        }
    }
    cluster.restart_node(0).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let restored_policy = client
        .read_policy(policy_id, amended_height, &trusted)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(restored_policy.value).unwrap(),
        serde_json::to_value(selected.value).unwrap()
    );
    let added = client
        .native_register_object(&second, policy_id, "second", "file")
        .await
        .unwrap();
    let expected = vera_modules::acp::decision::DecisionRequest {
        deployment_id: deployment,
        policy_id: policy.clone(),
        creator: second.did().into(),
        creator_sequence: second.nonce(),
        request: vera_modules::acp::types::AccessRequest {
            actor: Actor(second.did().parse().unwrap()),
            operations: vec![vera_modules::acp::types::Operation {
                object: Object {
                    resource: "file".into(),
                    id: "second".into(),
                },
                permission: "read".into(),
            }],
        },
    };
    assert!(
        client
            .read_access_decision(&expected, added.block_number, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let evaluated = client
        .native_check_access(
            &second,
            policy_id,
            vec!["file".into()],
            vec!["second".into()],
            vec!["read".into()],
            second.did(),
        )
        .await
        .unwrap();
    let (decision_height, decision_receipt) =
        certified_receipt(&client, evaluated.transaction_hash, &trusted).await;
    assert!(decision_receipt.success());
    let decision = client
        .read_access_decision(&expected, decision_height, &trusted)
        .await
        .unwrap()
        .value
        .unwrap();
    assert_eq!(decision.issued_height, decision_height);
    assert_eq!(decision.creator_acc_sequence, expected.creator_sequence);
    assert_eq!(decision.actor, second.did());
    let mut unrelated = expected.clone();
    unrelated.request.operations[0].object.id = "report".into();
    assert!(
        client
            .read_access_decision(&unrelated, decision_height, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let first_relationships = client
        .read_relationship_page(policy_id, None, 1, added.block_number, &trusted)
        .await
        .unwrap();
    assert_eq!(first_relationships.records.len(), 1);
    assert!(first_relationships.continuation.is_some());
    let last_relationships = client
        .read_relationship_page(
            policy_id,
            first_relationships.continuation,
            1,
            first_relationships.revision,
            &trusted,
        )
        .await
        .unwrap();
    assert_eq!(last_relationships.records.len(), 1);
    assert!(last_relationships.continuation.is_none());
    let archived = &first_relationships.records[0];
    assert_eq!(archived.relationship.object_id, "report");
    assert!(archived.archived);
    assert_eq!(archived.metadata.owner_did, second.did());
    assert_eq!(archived.metadata.creation_ts.block_height, early_height);
    assert_eq!(
        last_relationships.records[0].relationship.object_id,
        "second"
    );
    assert!(!last_relationships.records[0].archived);
    let history = client
        .read_amendment_ids(policy_id, None, 1, amended_height, &trusted)
        .await
        .unwrap();
    assert_eq!(history.ids.len(), 1);
    assert!(history.continuation.is_none());
    let event_id = history.ids[0];
    let event = client
        .read_amendment(policy_id, event_id, history.revision, &trusted)
        .await
        .unwrap()
        .value
        .unwrap();
    assert_eq!(event.object, object);
    assert_eq!(event.new_owner.0.as_str(), second.did());
    assert_eq!(event.previous_owner.0.as_str(), first.did());
    assert_eq!(event.commitment_id, early.data.commitmentId);
    assert!(!event.hijack_flag);
    assert!(
        client
            .read_amendment(B256::ZERO, event_id, history.revision, &trusted)
            .await
            .is_err()
    );
    assert!(
        client
            .read_amendment(policy_id, u64::MAX, history.revision, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let (_, unauthorized) = submit(
        &client,
        &first,
        &trusted,
        IAcp::flagHijackAttemptCall { eventId: event_id }.abi_encode(),
    )
    .await;
    assert!(!unauthorized.success());
    let flagged = client
        .native_flag_hijack_attempt(&second, event_id)
        .await
        .unwrap();
    let (flagged_height, receipt) =
        certified_receipt(&client, flagged.transaction_hash, &trusted).await;
    assert!(receipt.success());
    let reported = client
        .read_amendment(policy_id, event_id, flagged_height, &trusted)
        .await
        .unwrap()
        .value
        .unwrap();
    assert!(reported.hijack_flag);
    assert_eq!(reported.metadata, event.metadata);
}
