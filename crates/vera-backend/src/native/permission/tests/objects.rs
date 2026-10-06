use super::*;
use crate::native::{policy_prefix_page_at, policy_prefix_proof_at};
use vera_modules::acp::{object_state, types::RelationshipRecord};
use vera_permission::{
    ModuleId, PAGE_PROOF_BYTES, PolicyPrefixPageProof, PrefixPageRequest, RECORD_PROOF_BYTES,
    object_owner_prefix,
};

#[test]
fn object_retirement_is_proven_without_reviving_grants_or_losing_page_continuations() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let owner = "did:key:owner".parse().unwrap();
            let actor = Actor("did:key:reader".parse().unwrap());
            let mut state = ModuleState::default();
            let policy = state.acp.create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml).unwrap();
            let id = &policy.policy.id;
            let object = Object { resource: "document".into(), id: "report".into() };
            let relation = Relationship::with_entity("document", "report", "reader", actor.0.clone());
            for command in [PolicyCmd::RegisterObject(object.clone()), PolicyCmd::SetRelationship(relation.clone())] {
                state.acp.direct_policy_cmd(&owner, id, command).unwrap();
            }
            let old_key = keys::relationship_generation_key(id, policy.relations.pair(&relation).unwrap(), &keys::relationship_storage_key(&relation, 0));
            let state_key = object_state::key(id, "document", "report");
            let request = AccessRequest {
                actor,
                operations: vec![Operation { object: object.clone(), permission: "read".into() }],
            };
            let prefix = keys::relationship_policy_prefix(id);
            let page_request = PrefixPageRequest {
                module: ModuleId::Acp, prefix: prefix.clone().into(), start: old_key.into(), limit: 1,
            };
            let initial = apply(&set, state.diff_from(&ModuleState::default())).await;
            let allowed = permission_proof(&set, initial, state.acp.store().clone(), id, &request, PERMISSION_LIMITS).await.unwrap();
            assert!(verify_permission_proof(initial, 0, id, &request, &allowed, PERMISSION_LIMITS).unwrap());
            assert!(allowed.reads.iter().any(|read| matches!(read, PermissionRead::CurrentPoint { key, value: None, .. } if key.as_ref() == state_key)));
            let mut missing = allowed.clone();
            missing.reads.retain(|read| !matches!(read, PermissionRead::CurrentPoint { key, .. } if key.as_ref() == state_key));
            assert!(verify_permission_proof(initial, 0, id, &request, &missing, PERMISSION_LIMITS).is_err());
            let initial_page = {
                let (a, b, h, n) = futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                let dbs: [&crate::native::NativeDb; 4] = [&a, &b, &h, &n];
                let complete = policy_prefix_proof_at(dbs, initial, id, &prefix).await.unwrap();
                assert_eq!(complete.objects.len(), 1);
                assert!(complete.objects[0].value.is_none());
                assert_eq!(complete.verify(initial, id, &prefix, RECORD_PROOF_BYTES).unwrap().unwrap().entries.len(), 2);
                let page = policy_prefix_page_at(dbs, initial, id, &page_request).await.unwrap();
                assert_invalid_witnesses(&page, initial, id, &page_request);
                page
            };
            let before = state.clone();
            for command in [PolicyCmd::ArchiveObject(object.clone()), PolicyCmd::UnarchiveObject(object.clone())] {
                state.acp.direct_policy_cmd(&owner, id, command).unwrap();
            }
            let retired = apply(&set, state.diff_from(&before)).await;
            let denied = permission_proof(&set, retired, state.acp.store().clone(), id, &request, PERMISSION_LIMITS).await.unwrap();
            assert!(!verify_permission_proof(retired, 0, id, &request, &denied, PERMISSION_LIMITS).unwrap());
            assert!(verify_permission_proof(retired, 0, id, &request, &allowed, PERMISSION_LIMITS).is_err());
            let before = state.clone();
            state.acp.direct_policy_cmd(&owner, id, PolicyCmd::SetRelationship(relation)).unwrap();
            let current = apply(&set, state.diff_from(&before)).await;
            let fresh = permission_proof(&set, current, state.acp.store().clone(), id, &request, PERMISSION_LIMITS).await.unwrap();
            assert!(verify_permission_proof(current, 0, id, &request, &fresh, PERMISSION_LIMITS).unwrap());
            let (a, b, h, n) = futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            let dbs: [&crate::native::NativeDb; 4] = [&a, &b, &h, &n];
            assert!(policy_prefix_proof_at(dbs, current, id, &prefix).await.is_err());
            let page = policy_prefix_page_at(dbs, current, id, &page_request).await.unwrap();
            assert_eq!(page.objects.len(), 1);
            assert_eq!(object_state::decode(page.objects[0].value.as_deref().unwrap()).unwrap(), 1);
            let physical = page.page.verify(current, &page_request, PAGE_PROOF_BYTES).unwrap();
            assert_eq!(physical.entries.len(), 1);
            let filtered = page.verify(current, id, &page_request, PAGE_PROOF_BYTES).unwrap().unwrap();
            assert!(filtered.entries.is_empty());
            assert!(filtered.continuation.is_some());
            assert_eq!(filtered.continuation, physical.continuation);
            let mut stale = page.clone();
            stale.objects = initial_page.objects;
            assert!(stale.verify(current, id, &page_request, PAGE_PROOF_BYTES).is_err());
            assert_invalid_witnesses(&page, current, id, &page_request);
            let next_request = PrefixPageRequest { start: filtered.continuation.unwrap(), ..page_request };
            let next = policy_prefix_page_at(dbs, current, id, &next_request).await.unwrap().verify(current, id, &next_request, PAGE_PROOF_BYTES).unwrap().unwrap();
            assert_eq!(next.entries.len(), 1);
            let record: RelationshipRecord = serde_json::from_slice(&next.entries[0].value).unwrap();
            assert_eq!(record.incarnation, 1);
            let owner_prefix = object_owner_prefix(id, &object).unwrap();
            let ownership = policy_prefix_proof_at(dbs, current, id, &owner_prefix).await.unwrap();
            assert!(ownership.objects.is_empty());
            assert_eq!(ownership.verify(current, id, &owner_prefix, RECORD_PROOF_BYTES).unwrap().unwrap().entries.len(), 1);
        },
    );
}

fn assert_invalid_witnesses(
    proof: &PolicyPrefixPageProof,
    root: B256,
    policy: &str,
    request: &PrefixPageRequest,
) {
    let mut missing = proof.clone();
    missing.objects.clear();
    assert!(
        missing
            .verify(root, policy, request, PAGE_PROOF_BYTES)
            .is_err()
    );
    let mut duplicate = proof.clone();
    duplicate.objects.push(duplicate.objects[0].clone());
    assert!(
        duplicate
            .verify(root, policy, request, PAGE_PROOF_BYTES)
            .is_err()
    );
    let mut extra = proof.clone();
    extra.objects.push(extra.policy.clone());
    assert!(
        extra
            .verify(root, policy, request, PAGE_PROOF_BYTES)
            .is_err()
    );
    let mut forged = proof.clone();
    forged.objects[0].value = Some(42_u64.to_be_bytes().to_vec().into());
    assert!(
        forged
            .verify(root, policy, request, PAGE_PROOF_BYTES)
            .is_err()
    );
    let mut mixed = proof.clone();
    mixed.objects[0].roots[0] = B256::repeat_byte(7);
    assert!(
        mixed
            .verify(root, policy, request, PAGE_PROOF_BYTES)
            .is_err()
    );
    let mut encoded = serde_json::to_value(proof).unwrap();
    encoded.as_object_mut().unwrap().remove("objects");
    assert!(serde_json::from_value::<PolicyPrefixPageProof>(encoded).is_err());
    let size = encoded_size(proof, PAGE_PROOF_BYTES).unwrap();
    assert!(proof.verify(root, policy, request, size).is_ok());
    assert!(matches!(
        proof.verify(root, policy, request, size - 1),
        Err(PermissionError::Limit)
    ));
}
