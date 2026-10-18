use alloy_primitives::{B256, Bytes};
use vera_client::{ModuleId, RECORD_PROOF_BYTES, VeraClient};
use vera_domain::{ConsensusPublicKey, LightBlock, verify_light_block};
use vera_modules::acp::{keys, types::PolicyRecord};
use vera_permission::RecordResponse;

/// Inspect the authenticated bytes, not merely the transport's presence flag.
pub(super) fn assert_policy(
    response: &RecordResponse,
    policy: &str,
    minimum: u64,
    trusted: &ConsensusPublicKey,
) {
    let key = keys::policy_key(policy);
    response
        .verify(ModuleId::Acp, &key, minimum, trusted, RECORD_PROOF_BYTES)
        .expect("policy response should authenticate at its captured revision");
    let value = response.record.value.as_ref().expect("policy should exist");
    let record: PolicyRecord = serde_json::from_slice(value).expect("policy record encoding");
    assert_eq!(record.policy.id, policy);
    assert_eq!(record.policy.name, "test-policy");
    assert_eq!(record.raw_policy, super::TEST_POLICY_YAML);
    assert_eq!(record.policy.resources.len(), 1);
    assert_eq!(record.policy.resources[0].name, "document");
    record.relations.validate(&record.policy).unwrap();

    let (_, root) = verify_light_block(&response.revision, trusted).unwrap();
    response
        .record
        .verify(root, ModuleId::Acp, &key, RECORD_PROOF_BYTES)
        .unwrap();
    assert!(
        response
            .record
            .verify(B256::ZERO, ModuleId::Acp, &key, RECORD_PROOF_BYTES)
            .is_err()
    );
    assert!(
        response
            .record
            .verify(
                root,
                ModuleId::Acp,
                b"policy/objs/wrong",
                RECORD_PROOF_BYTES
            )
            .is_err()
    );
    let mut changed = response.record.clone();
    changed.value = Some(Bytes::from_static(b"forged policy"));
    assert!(
        changed
            .verify(root, ModuleId::Acp, &key, RECORD_PROOF_BYTES)
            .is_err()
    );
}

pub(super) async fn check_peer_and_absence(
    peer: &VeraClient,
    original: &RecordResponse,
    policy: &str,
    trusted: &ConsensusPublicKey,
) {
    // Finalization and RPC indexing are asynchronous on each validator. Wait for
    // this exact revision to be indexed, without retrying verification failures.
    tokio::time::timeout(vera_e2e::readiness_deadline(), async {
        loop {
            let block: Option<serde_json::Value> = peer
                .rpc_call_typed(
                    "eth_getBlockByNumber",
                    serde_json::json!([format!("0x{:x}", original.revision.height), false]),
                )
                .await
                .expect("peer block lookup should succeed");
            if block.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("peer should index the captured revision before the deadline");

    // Query the exact same canonical revision on another validator, not its newer head.
    let light: LightBlock = peer
        .rpc_call_typed(
            "vera_getLightBlock",
            serde_json::json!([original.revision.height]),
        )
        .await
        .unwrap();
    assert_eq!(light.height, original.revision.height);
    assert_eq!(light.block_hash, original.revision.block_hash);
    let roots = verify_light_block(&light, trusted).unwrap();
    assert_eq!(
        roots,
        verify_light_block(&original.revision, trusted).unwrap()
    );
    original
        .record
        .verify(
            roots.1,
            ModuleId::Acp,
            &keys::policy_key(policy),
            RECORD_PROOF_BYTES,
        )
        .unwrap();

    // Current-state evidence can capture a later revision; compare authenticated values,
    // not serialized proof paths or roots that legitimately change between revisions.
    let present = peer
        .read_current_record(
            ModuleId::Acp,
            &keys::policy_key(policy),
            original.revision.height,
            trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert_policy(&present, policy, original.revision.height, trusted);
    assert_eq!(present.record.value, original.record.value);

    let missing_policy = "ff".repeat(32);
    assert_ne!(missing_policy, policy);
    let missing_key = keys::policy_key(&missing_policy);
    let absent = peer
        .read_current_record(
            ModuleId::Acp,
            &missing_key,
            present.revision.height,
            trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    absent
        .verify(
            ModuleId::Acp,
            &missing_key,
            present.revision.height,
            trusted,
            RECORD_PROOF_BYTES,
        )
        .unwrap();
    assert!(
        absent.record.value.is_none(),
        "never-created policy must have certified absence"
    );
    let (_, root) = verify_light_block(&absent.revision, trusted).unwrap();
    assert!(
        absent
            .record
            .verify(
                root,
                ModuleId::Acp,
                &keys::policy_key(policy),
                RECORD_PROOF_BYTES
            )
            .is_err()
    );
    assert!(
        absent
            .record
            .verify(B256::ZERO, ModuleId::Acp, &missing_key, RECORD_PROOF_BYTES)
            .is_err()
    );
    let mut forged = absent.record;
    forged.value = present.record.value;
    assert!(
        forged
            .verify(root, ModuleId::Acp, &missing_key, RECORD_PROOF_BYTES)
            .is_err()
    );
}
