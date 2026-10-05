use super::*;
use crate::native::{policy_prefix_page_at, policy_prefix_proof_at, prefix_proof_at};
use vera_permission::{
    ModuleId, PAGE_PROOF_BYTES, PrefixPageRequest, RECORD_PROOF_BYTES, encoded_size,
};

#[test]
fn policy_evidence_revokes_retained_relationships_at_the_deletion_root() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let actor = "did:key:owner".parse().unwrap();
            let mut state = ModuleState::default();
            let policy = state
                .acp
                .create_policy(&actor, POLICY, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .policy
                .id;
            state
                .acp
                .direct_policy_cmd(
                    &actor,
                    &policy,
                    PolicyCmd::RegisterObject(Object {
                        resource: "document".into(),
                        id: "report".into(),
                    }),
                )
                .unwrap();
            let prefix = keys::relationship_policy_prefix(&policy);
            let request = PrefixPageRequest {
                module: ModuleId::Acp,
                prefix: prefix.clone().into(),
                start: prefix.clone().into(),
                limit: 2,
            };
            let root = apply(&set, state.diff_from(&ModuleState::default())).await;
            let (live_prefix, live_page) = {
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                let dbs: [&crate::native::NativeDb; 4] = [&a, &b, &h, &n];
                let proof = policy_prefix_proof_at(dbs, root, &policy, &prefix)
                    .await
                    .unwrap();
                assert_eq!(
                    proof
                        .verify(root, &policy, &prefix, RECORD_PROOF_BYTES)
                        .unwrap()
                        .unwrap()
                        .entries
                        .len(),
                    1
                );
                let page = policy_prefix_page_at(dbs, root, &policy, &request)
                    .await
                    .unwrap();
                assert_eq!(
                    page.verify(root, &policy, &request, PAGE_PROOF_BYTES)
                        .unwrap()
                        .unwrap()
                        .entries
                        .len(),
                    1
                );
                let old_prefix = format!("relationship/{policy}/");
                let old = prefix_proof_at(dbs, root, ModuleId::Acp, old_prefix.as_bytes())
                    .await
                    .unwrap();
                assert!(
                    old.verify(
                        root,
                        ModuleId::Acp,
                        old_prefix.as_bytes(),
                        RECORD_PROOF_BYTES
                    )
                    .unwrap()
                    .entries
                    .is_empty()
                );
                let maximum = encoded_size(&proof, RECORD_PROOF_BYTES).unwrap() - 1;
                assert!(encoded_size(&proof.policy, maximum).is_ok());
                assert!(encoded_size(&proof.prefix, maximum).is_ok());
                assert!(proof.verify(root, &policy, &prefix, maximum).is_err());
                let maximum = encoded_size(&page, PAGE_PROOF_BYTES).unwrap() - 1;
                assert!(encoded_size(&page.policy, maximum).is_ok());
                assert!(encoded_size(&page.page, maximum).is_ok());
                assert!(page.verify(root, &policy, &request, maximum).is_err());
                let other = "00".repeat(32);
                assert!(
                    proof
                        .verify(root, &other, &prefix, RECORD_PROOF_BYTES)
                        .is_err()
                );
                let mut outside = request.clone();
                outside.start = b"outside".as_slice().into();
                assert!(
                    policy_prefix_page_at(dbs, root, &policy, &outside)
                        .await
                        .is_err()
                );
                let mut wrong_module = request.clone();
                wrong_module.module = ModuleId::Bulletin;
                assert!(
                    policy_prefix_page_at(dbs, root, &policy, &wrong_module)
                        .await
                        .is_err()
                );
                (proof, page)
            };
            let before = state.clone();
            assert!(state.acp.delete_policy(&actor, &policy).unwrap());
            assert_eq!(state.acp.store().prefix_iter(&prefix).count(), 1);
            let deleted = apply(&set, state.diff_from(&before)).await;
            {
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                let dbs: [&crate::native::NativeDb; 4] = [&a, &b, &h, &n];
                let proof = policy_prefix_proof_at(dbs, deleted, &policy, &prefix)
                    .await
                    .unwrap();
                assert!(proof.policy.value.is_none());
                assert_eq!(
                    proof
                        .prefix
                        .verify(deleted, ModuleId::Acp, &prefix, RECORD_PROOF_BYTES)
                        .unwrap()
                        .entries
                        .len(),
                    1
                );
                assert!(
                    proof
                        .verify(deleted, &policy, &prefix, RECORD_PROOF_BYTES)
                        .unwrap()
                        .is_none()
                );
                let page = policy_prefix_page_at(dbs, deleted, &policy, &request)
                    .await
                    .unwrap();
                assert!(
                    page.verify(deleted, &policy, &request, PAGE_PROOF_BYTES)
                        .unwrap()
                        .is_none()
                );
                let mut corrupt = proof.clone();
                corrupt.prefix.proof = Bytes::from_static(b"invalid").into();
                assert!(
                    corrupt
                        .verify(deleted, &policy, &prefix, RECORD_PROOF_BYTES)
                        .is_err()
                );
                let mut corrupt = page.clone();
                corrupt.page.proof = Bytes::from_static(b"invalid").into();
                assert!(
                    corrupt
                        .verify(deleted, &policy, &request, PAGE_PROOF_BYTES)
                        .is_err()
                );
                let mut mixed = proof.clone();
                mixed.policy = live_prefix.policy;
                assert!(
                    mixed
                        .verify(deleted, &policy, &prefix, RECORD_PROOF_BYTES)
                        .is_err()
                );
                let mut mixed = page.clone();
                mixed.policy = live_page.policy;
                assert!(
                    mixed
                        .verify(deleted, &policy, &request, PAGE_PROOF_BYTES)
                        .is_err()
                );
            }
            let malformed = apply(
                &set,
                [
                    vec![(keys::policy_key(&policy), Some(b"malformed".to_vec()))],
                    vec![],
                    vec![],
                    vec![],
                ],
            )
            .await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            assert!(
                policy_prefix_proof_at([&a, &b, &h, &n], malformed, &policy, &prefix)
                    .await
                    .is_err()
            );
            assert!(
                policy_prefix_page_at([&a, &b, &h, &n], malformed, &policy, &request)
                    .await
                    .is_err()
            );
        },
    );
}

#[test]
fn policy_pages_filter_retired_generations_without_losing_the_physical_cursor() {
    const SCHEMA: &str = "\
name: generations
resources:
  - name: document
    relations:
      - name: reader
  - name: group
    relations:
      - name: member
";
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let actor = "did:key:owner".parse().unwrap();
            let mut state = ModuleState::default();
            let policy = state
                .acp
                .create_policy(&actor, SCHEMA, PolicyMarshalingType::ShortYaml)
                .unwrap();
            let id = &policy.policy.id;
            state
                .acp
                .direct_policy_cmd(
                    &actor,
                    id,
                    PolicyCmd::RegisterObject(Object {
                        resource: "document".into(),
                        id: "report".into(),
                    }),
                )
                .unwrap();
            let direct = Relationship::with_entity("document", "report", "reader", actor.clone());
            let userset = Relationship::new(
                "document",
                "report",
                "reader",
                Subject::entity_set("group", "staff", "member"),
            );
            for relationship in [&direct, &userset] {
                state
                    .acp
                    .direct_policy_cmd(&actor, id, PolicyCmd::SetRelationship(relationship.clone()))
                    .unwrap();
            }
            let prefix = keys::relationship_policy_prefix(id);
            let old_key = keys::relationship_generation_key(
                id,
                policy.relations.pair(&direct).unwrap(),
                &keys::relationship_storage_key(&direct),
            );
            let mut request = PrefixPageRequest {
                module: ModuleId::Acp,
                prefix: prefix.clone().into(),
                start: old_key.into(),
                limit: 1,
            };
            let original_root = apply(&set, state.diff_from(&ModuleState::default())).await;
            let original_policy = {
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                policy_prefix_page_at([&a, &b, &h, &n], original_root, id, &request)
                    .await
                    .unwrap()
                    .policy
            };
            let before = state.clone();
            let removed_schema = SCHEMA.replace("    relations:\n      - name: reader\n", "");
            assert_eq!(
                state
                    .acp
                    .edit_policy(&actor, id, &removed_schema, PolicyMarshalingType::ShortYaml)
                    .unwrap()
                    .0,
                2
            );
            let (_, recreated) = state
                .acp
                .edit_policy(&actor, id, SCHEMA, PolicyMarshalingType::ShortYaml)
                .unwrap();
            state
                .acp
                .direct_policy_cmd(&actor, id, PolicyCmd::SetRelationship(direct.clone()))
                .unwrap();
            let fresh_pair = recreated.relations.pair(&direct).unwrap();
            assert_ne!(fresh_pair, policy.relations.pair(&direct).unwrap());
            let root = apply(&set, state.diff_from(&before)).await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            let dbs: [&crate::native::NativeDb; 4] = [&a, &b, &h, &n];
            let raw = prefix_proof_at(dbs, root, ModuleId::Acp, &prefix)
                .await
                .unwrap();
            assert_eq!(
                raw.verify(root, ModuleId::Acp, &prefix, RECORD_PROOF_BYTES)
                    .unwrap()
                    .entries
                    .len(),
                4
            );
            assert!(
                policy_prefix_proof_at(dbs, root, id, &prefix)
                    .await
                    .is_err()
            );
            let first = policy_prefix_page_at(dbs, root, id, &request)
                .await
                .unwrap();
            let physical = first.page.verify(root, &request, PAGE_PROOF_BYTES).unwrap();
            assert_eq!(physical.entries.len(), 1);
            let current = first
                .verify(root, id, &request, PAGE_PROOF_BYTES)
                .unwrap()
                .unwrap();
            assert!(current.entries.is_empty());
            assert!(current.continuation.is_some());
            assert_eq!(current.continuation, physical.continuation);
            let complete = vera_permission::PolicyPrefixProof {
                policy: first.policy.clone(),
                prefix: raw,
            };
            assert!(
                complete
                    .verify(root, id, &prefix, RECORD_PROOF_BYTES)
                    .is_err()
            );
            let mut mixed = first.clone();
            mixed.policy = original_policy;
            assert!(mixed.verify(root, id, &request, PAGE_PROOF_BYTES).is_err());
            let mut continuation = current.continuation;
            let mut records = Vec::new();
            while let Some(start) = continuation {
                request.start = start;
                let page = policy_prefix_page_at(dbs, root, id, &request)
                    .await
                    .unwrap()
                    .verify(root, id, &request, PAGE_PROOF_BYTES)
                    .unwrap()
                    .unwrap();
                records.extend(page.entries);
                continuation = page.continuation;
            }
            assert_eq!(records.len(), 1);
            let record: vera_modules::acp::types::RelationshipRecord =
                serde_json::from_slice(&records[0].value).unwrap();
            assert_eq!(record.relationship, direct);
            assert_eq!(record.generations, fresh_pair);
        },
    );
}
