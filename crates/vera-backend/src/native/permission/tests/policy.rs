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
