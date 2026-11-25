use super::*;
use crate::native::policy_prefix_proof_at;
use vera_modules::acp::types::RelationshipRecord;
use vera_permission::{ObjectRegistration, current::PrefixEvidence, object_owner_prefix};

#[test]
fn owner_prefix_evidence_distinguishes_live_archived_and_absent_objects() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let owner = "did:key:owner".parse().unwrap();
            let mut state = ModuleState::default();
            let id = state
                .acp
                .create_policy(
                    &owner,
                    POLICY,
                    PolicyMarshalingType::ShortYaml,
                    Default::default(),
                )
                .unwrap()
                .policy
                .id;
            let object = |name: &str| Object {
                resource: "document".into(),
                id: name.into(),
            };
            let (archived, live, never) = (object("archived"), object("live"), object("never"));
            for command in [
                PolicyCmd::RegisterObject(archived.clone()),
                PolicyCmd::RegisterObject(live.clone()),
                PolicyCmd::ArchiveObject(archived.clone()),
            ] {
                state.acp.direct_policy_cmd(&owner, &id, command).unwrap();
            }
            assert!(
                state
                    .acp
                    .clone()
                    .direct_policy_cmd(&owner, &id, PolicyCmd::RegisterObject(archived.clone()))
                    .is_err()
            );
            let root = apply(&set, state.diff_from(&ModuleState::default())).await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            let dbs: [&crate::native::NativeDb; 4] = [&a, &b, &h, &n];
            let mut proofs = Vec::new();
            for object in [&archived, &live, &never] {
                let prefix = object_owner_prefix(&id, object).unwrap();
                proofs.push(
                    policy_prefix_proof_at(dbs, root, &id, &prefix)
                        .await
                        .unwrap(),
                );
            }
            let read = |proof: &vera_permission::PolicyPrefixProof, object: &Object| {
                proof.verify_object_registration(root, &id, object)
            };
            assert_eq!(
                read(&proofs[0], &archived).unwrap(),
                ObjectRegistration::Archived
            );
            assert_eq!(
                read(&proofs[1], &live).unwrap(),
                ObjectRegistration::Live(Actor(owner.clone()))
            );
            assert_eq!(
                read(&proofs[2], &never).unwrap(),
                ObjectRegistration::Absent
            );
            assert!(read(&proofs[2], &archived).is_err());
            assert!(read(&proofs[0], &never).is_err());
            assert!(
                proofs[0]
                    .verify_object_registration(B256::repeat_byte(1), &id, &archived)
                    .is_err()
            );

            let mut revived = proofs[0].clone();
            let mut evidence = PrefixEvidence::decode_cfg(
                commonware_codec::Copying(revived.prefix.proof.as_ref()),
                &PERMISSION_LIMITS.reads.records,
            )
            .unwrap();
            let mut record: RelationshipRecord =
                serde_json::from_slice(&evidence.entries[0].value).unwrap();
            record.archived = false;
            evidence.entries[0].value = serde_json::to_vec(&record).unwrap().into();
            revived.prefix.proof = evidence.encode().into();
            assert!(read(&revived, &archived).is_err());

            let mut hidden = proofs[0].clone();
            evidence.entries.clear();
            hidden.prefix.proof = evidence.encode().into();
            assert!(read(&hidden, &archived).is_err());
        },
    );
}
