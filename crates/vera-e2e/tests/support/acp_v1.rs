use alloy_primitives::B256;
use vera_client::{BlsSigner, VeraClient};
use vera_modules::acp::types::{
    Object, PolicyCmd, PolicyCommandRequest, PolicyCreation, PolicyMarshalingType, SuppliedMetadata,
};

pub(super) async fn lifecycle(
    client: &VeraClient,
    owner: &BlsSigner,
    next: &BlsSigner,
) -> Vec<vera_client::TransactionReceipt> {
    let metadata = SuppliedMetadata {
        blob: b"documents".to_vec(),
        ..Default::default()
    };
    let mut receipts = vec![client.native_create_policy_with_options(owner, &PolicyCreation {
        policy: "name: acp-v1-e2e\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader\n".into(),
        marshal_type: PolicyMarshalingType::ShortYaml, required_specification: None, metadata: metadata.clone(),
    }).await.unwrap()];
    assert_eq!(receipts[0].status, 1);
    let record = client
        .get_policies()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.policy.name == "acp-v1-e2e")
        .unwrap();
    assert_eq!(
        record.metadata.creation_ts.block_height,
        receipts[0].block_number
    );
    assert_eq!(record.metadata.owner_did, owner.did());
    assert_eq!(record.supplied_metadata, metadata);
    let policy: B256 = record.policy.id.parse().unwrap();
    receipts.push(
        client
            .native_policy_command(
                owner,
                policy,
                &PolicyCommandRequest {
                    command: PolicyCmd::RegisterObject(Object {
                        resource: "file".into(),
                        id: "report".into(),
                    }),
                    metadata: metadata.clone(),
                },
            )
            .await
            .unwrap(),
    );
    receipts.push(
        client
            .native_set_relationship(owner, policy, "file", "report", "reader", next.did())
            .await
            .unwrap(),
    );
    let original = client
        .get_object_registration(policy, "file", "report")
        .await
        .unwrap()
        .unwrap();
    receipts.push(
        client
            .native_transfer_object(owner, policy, "file", "report", next.did())
            .await
            .unwrap(),
    );
    let transferred = client
        .get_object_registration(policy, "file", "report")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transferred.metadata.owner_did, next.did());
    assert_eq!(
        transferred.metadata.creation_ts,
        original.metadata.creation_ts
    );
    assert_eq!(transferred.supplied_metadata, metadata);
    assert!(
        !client
            .check_management_authority(policy, "file", "report", "reader", owner.did())
            .await
            .unwrap()
    );
    assert!(
        client
            .check_management_authority(policy, "file", "report", "reader", next.did())
            .await
            .unwrap()
    );
    let theorem = format!(
        "Authorizations {{ file:report#read@{} }} Delegations {{ !{} > file:report#reader }}",
        next.did(),
        owner.did()
    );
    let report = client
        .evaluate_policy_theorem(policy, &theorem)
        .await
        .unwrap();
    assert!(report.ok);
    assert_eq!(report.theorem_count, 2);
    receipts.push(
        client
            .native_archive_object(next, policy, "report", "file")
            .await
            .unwrap(),
    );
    assert!(
        client
            .get_object_registration(policy, "file", "report")
            .await
            .unwrap()
            .unwrap()
            .archived
    );
    receipts.push(
        client
            .native_policy_command(
                next,
                policy,
                &PolicyCommandRequest {
                    command: PolicyCmd::UnarchiveObject(Object {
                        resource: "file".into(),
                        id: "report".into(),
                    }),
                    metadata: Default::default(),
                },
            )
            .await
            .unwrap(),
    );
    assert!(
        !client
            .get_object_registration(policy, "file", "report")
            .await
            .unwrap()
            .unwrap()
            .archived
    );
    receipts.push(
        client
            .native_edit_policy_metadata(owner, policy, &SuppliedMetadata::default())
            .await
            .unwrap(),
    );
    assert_eq!(
        client.get_policy_catalogue(policy).await.unwrap().resources["file"]
            .object_ids
            .len(),
        1
    );
    receipts.push(client.native_delete_policy(owner, policy).await.unwrap());
    assert!(
        client
            .get_policies()
            .await
            .unwrap()
            .iter()
            .all(|record| record.policy.id != hex::encode(policy))
    );
    assert!(receipts.iter().all(|receipt| receipt.status == 1));
    receipts
}
