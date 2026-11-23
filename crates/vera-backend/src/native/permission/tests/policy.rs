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
                .create_policy(
                    &actor,
                    POLICY,
                    PolicyMarshalingType::ShortYaml,
                    Default::default(),
                )
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
                let mut mixed = page;
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
                .create_policy(
                    &actor,
                    SCHEMA,
                    PolicyMarshalingType::ShortYaml,
                    Default::default(),
                )
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
                &keys::relationship_storage_key(&direct, 0),
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
                objects: first.objects.clone(),
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

#[test]
fn complete_relation_evidence_survives_unrelated_growth_and_withdrawal() {
    use vera_modules::acp::types::{PolicyCmdResult, RelationshipRecord};

    const POLICY: &str = "name: fleet
resources:
  - name: host_specs
    relations:
      - name: assigned
        types: [actor]
  - name: host_observations
    relations:
      - name: reader
        types: [actor]
";
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path()));
    runtime.start(|context| async move {
        let set = init(&context).await;
        let issuer = "did:key:issuer".parse().unwrap();
        let host = Actor("did:key:host".parse().unwrap()).0;
        let mut state = ModuleState::default();
        let policy = state
            .acp
            .create_policy(
                &issuer,
                POLICY,
                PolicyMarshalingType::ShortYaml,
                Default::default(),
            )
            .unwrap();
        let id = &policy.policy.id;
        let assigned =
            Relationship::with_entity("host_specs", "revision-1", "assigned", host.clone());
        let generation = policy.relations.pair(&assigned).unwrap().target;
        let all = keys::relationship_policy_prefix(id);
        let scoped = keys::relationship_target_prefix(id, generation);

        let grant = |state: &mut ModuleState, row: &Relationship| {
            let object = Object {
                resource: row.resource.clone(),
                id: row.object_id.clone(),
            };
            state
                .acp
                .direct_policy_cmd(&issuer, id, PolicyCmd::RegisterObject(object))
                .unwrap();
            state
                .acp
                .direct_policy_cmd(&issuer, id, PolicyCmd::SetRelationship(row.clone()))
                .unwrap();
        };
        grant(&mut state, &assigned);
        let mut previous = ModuleState::default();
        let mut reports = 0;
        for (count, active) in [
            (0, true),
            (100, true),
            (253, true),
            (254, true),
            (10_000, true),
            (10_000, false),
        ] {
            for i in reports..count {
                let report = Relationship::with_entity(
                    "host_observations",
                    format!("report-{i:05}"),
                    "reader",
                    host.clone(),
                );
                grant(&mut state, &report);
            }
            reports = count;
            if !active {
                let result = state
                    .acp
                    .direct_policy_cmd(&issuer, id, PolicyCmd::DeleteRelationship(assigned.clone()))
                    .unwrap();
                assert!(matches!(
                    result,
                    PolicyCmdResult::DeleteRelationship { record_found: true }
                ));
            }
            let root = apply(&set, state.diff_from(&previous)).await;
            previous = state.clone();
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            let databases: [&NativeDb; 4] = [&a, &b, &h, &n];
            for (name, prefix) in [("policy", &all), ("assigned", &scoped)] {
                let result = policy_prefix_proof_at(databases, root, id, prefix).await;
                if name == "policy" && count >= 254 {
                    assert!(matches!(
                        result,
                        Err(BackendError::Permission(PermissionError::Limit))
                    ));
                    println!(
                        "reports={count} active={active} prefix={name} error=Permission(Limit)"
                    );
                    continue;
                }
                let proof = result.unwrap();
                let rows = proof
                    .verify(root, id, prefix, RECORD_PROOF_BYTES)
                    .unwrap()
                    .unwrap()
                    .entries;
                if name == "policy" {
                    assert_eq!(rows.len(), 2 * (count + 1));
                    assert_eq!(proof.objects.len(), count + 1);
                } else if active {
                    let verified = proof
                        .verify_relation(root, id, "host_specs", "assigned", RECORD_PROOF_BYTES)
                        .unwrap();
                    assert_eq!(verified.entries.len(), 1);
                    let subject = Actor(host.clone());
                    let issuing_actor = Actor(issuer.clone());
                    let selector = vera_permission::AssignmentSelector {
                        resource: "host_specs",
                        relation: "assigned",
                        subject: &subject,
                        issuer: &issuing_actor,
                    };
                    let assignments = proof
                        .verify_assignments(root, id, &selector, RECORD_PROOF_BYTES)
                        .unwrap();
                    assert_eq!(assignments.len(), 1);
                    assert_eq!(assignments[0].relationship, assigned);
                    let other = Actor("did:key:other".parse().unwrap());
                    let wrong_issuer = vera_permission::AssignmentSelector {
                        issuer: &other,
                        ..selector
                    };
                    assert!(
                        proof
                            .verify_assignments(root, id, &wrong_issuer, RECORD_PROOF_BYTES)
                            .unwrap()
                            .is_empty()
                    );
                    assert!(
                        proof
                            .verify_relation(
                                root,
                                id,
                                "host_observations",
                                "reader",
                                RECORD_PROOF_BYTES
                            )
                            .is_err()
                    );
                    let [entry] = rows.as_slice() else {
                        panic!("expected the original assignment")
                    };
                    let record: RelationshipRecord = serde_json::from_slice(&entry.value).unwrap();
                    assert!(!record.archived);
                    assert_eq!(record.relationship, assigned);
                    assert_eq!(proof.objects.len(), 1);
                } else {
                    assert!(rows.is_empty());
                    assert!(proof.objects.is_empty());
                    assert!(
                        proof
                            .verify_relation(root, id, "host_specs", "assigned", RECORD_PROOF_BYTES)
                            .unwrap()
                            .entries
                            .is_empty()
                    );
                    assert!(
                        proof
                            .verify_relation(
                                root,
                                id,
                                "host_observations",
                                "reader",
                                RECORD_PROOF_BYTES
                            )
                            .is_err()
                    );
                }
                println!(
                    "reports={count} active={active} prefix={name} rows={} witnesses={} bytes={}",
                    rows.len(),
                    proof.objects.len(),
                    encoded_size(&proof, RECORD_PROOF_BYTES).unwrap()
                );
            }
        }
        let before = state.clone();
        let removed = POLICY.replace(
            "    relations:\n      - name: assigned\n        types: [actor]\n",
            "",
        );
        state
            .acp
            .edit_policy(&issuer, id, &removed, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let (_, updated) = state
            .acp
            .edit_policy(&issuer, id, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let new_generation = updated.relations.pair(&assigned).unwrap().target;
        assert_ne!(generation, new_generation);
        let root = apply(&set, state.diff_from(&before)).await;
        let (a, b, h, n) = futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
        let databases: [&NativeDb; 4] = [&a, &b, &h, &n];
        let old = policy_prefix_proof_at(databases, root, id, &scoped)
            .await
            .unwrap();
        assert!(
            old.verify(root, id, &scoped, RECORD_PROOF_BYTES)
                .unwrap()
                .unwrap()
                .entries
                .is_empty()
        );
        assert!(
            old.verify_relation(root, id, "host_specs", "assigned", RECORD_PROOF_BYTES)
                .is_err()
        );
        let current = keys::relationship_target_prefix(id, new_generation);
        let fresh = policy_prefix_proof_at(databases, root, id, &current)
            .await
            .unwrap();
        assert!(
            fresh
                .verify_relation(root, id, "host_specs", "assigned", RECORD_PROOF_BYTES)
                .unwrap()
                .entries
                .is_empty()
        );
    });
}
