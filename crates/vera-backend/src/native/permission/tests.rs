use super::*;
use bytes::Bytes;
use commonware_codec::Decode as _;
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use vera_modules::{
    ModuleState,
    acp::{
        keys,
        types::{PolicyCmd, PolicyMarshalingType},
        zanzibar_store::evaluate_access_request,
    },
    module_state::ModuleChanges,
};
use vera_permission::current::{MAX_KEY_BYTES, MAX_VALUE_BYTES, exclusion, membership};
use vera_permission::{Actor, Object, Operation, PERMISSION_LIMITS, ReadCapture};
use zanzibar::{Relationship, Subject};

const POLICY: &str = "\
name: documents
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
      - name: blocked
    permissions:
      - name: read
        expr: reader - blocked
";

#[test]
fn native_proof_decoders_bound_keys_values_and_merkle_paths() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let mut empty = set
                .0
                .read()
                .await
                .exclusion_proof(&b"missing".to_vec())
                .await
                .unwrap();
            assert!(exclusion(&empty.encode()).is_ok());
            let Exclusion::Commit(_, metadata) = &mut empty else {
                panic!("empty database")
            };
            *metadata = Some(Bytes::from(vec![0; MAX_VALUE_BYTES + 1]));
            assert!(exclusion(&empty.encode()).is_err());
            apply(
                &set,
                [
                    vec![(b"p/a".to_vec(), Some(vec![1]))],
                    vec![],
                    vec![],
                    vec![],
                ],
            )
            .await;
            let db = set.0.read().await;
            let proof = db.key_value_proof(b"p/a".to_vec()).await.unwrap();
            let encoded = proof.encode();
            assert!(membership(&encoded).is_ok());
            assert!(membership(&encoded[..encoded.len() - 1]).is_err());
            let mut trailing = encoded.to_vec();
            trailing.push(0);
            assert!(membership(&trailing).is_err());
            let mut changed = proof.clone();
            changed.next_key = vec![0; MAX_KEY_BYTES + 1];
            assert!(membership(&changed.encode()).is_err());
            let mut changed = proof;
            changed.proof.range_proof.proof.digests = vec![
                commonware_cryptography::sha256::Digest::from([0; 32]);
                commonware_storage::merkle::MAX_PROOF_DIGESTS_PER_ELEMENT + 1
            ];
            assert!(membership(&changed.encode()).is_err());
            let mut absent = db.exclusion_proof(&b"missing".to_vec()).await.unwrap();
            let Exclusion::KeyValue(_, record) = &mut absent else {
                panic!("nonempty database")
            };
            record.value = Bytes::from(vec![0; MAX_VALUE_BYTES + 1]);
            assert!(exclusion(&absent.encode()).is_err());
            let mut remaining = PERMISSION_LIMITS.reads;
            let mut prefix =
                prefix_proof(&db, b"p/", &mut remaining, PERMISSION_LIMITS.proof_bytes)
                    .await
                    .unwrap();
            prefix.entries[0].value = Bytes::from(vec![0; MAX_VALUE_BYTES + 1]);
            assert!(PrefixEvidence::decode_cfg(prefix.encode(), &1).is_err());
        },
    );
}

async fn init(context: &crate::Ctx) -> NativeStateSet {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(64));
    NativeStateSet::init(
        context.child("proof"),
        super::super::state_config("proof", cache),
        None,
    )
    .await
}

async fn apply(set: &NativeStateSet, changes: ModuleChanges) -> B256 {
    set.apply(
        super::super::prepare(set.new_batches().await, changes)
            .await
            .unwrap(),
    )
    .await;
    combine_module_roots(&[
        set.0.read().await.root().0,
        set.1.read().await.root().0,
        set.2.read().await.root().0,
        set.3.read().await.root().0,
    ])
}

#[test]
fn permission_evidence_replays_deny_and_revocation_at_one_revision() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path()));
    runtime.start(|context| async move {
        let set = init(&context).await;
        let owner = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let actor = Actor(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
                .parse()
                .unwrap(),
        );
        let mut state = ModuleState::default();
        let policy = state
            .acp
            .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        state
            .acp
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "document".into(),
                    id: "report".into(),
                }),
            )
            .unwrap();
        let blocked = Relationship::new(
            "document",
            "report",
            "blocked",
            Subject::typed_wildcard("document"),
        );
        let reader = Relationship::with_entity("document", "report", "reader", actor.0.clone());
        for relationship in [reader.clone(), blocked.clone()] {
            state
                .acp
                .direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(relationship))
                .unwrap();
        }
        let request = AccessRequest {
            actor,
            operations: vec![Operation {
                object: Object {
                    resource: "document".into(),
                    id: "report".into(),
                },
                permission: "read".into(),
            }],
        };
        let root = apply(&set, state.diff_from(&ModuleState::default())).await;
        let proof = permission_proof(
            &set,
            root,
            state.acp.store().clone(),
            &policy,
            &request,
            PERMISSION_LIMITS,
        )
        .await
        .unwrap();
        let verify = |proof: &PermissionProof, root, limits| {
            verify_permission_proof(root, 7, &policy, &request, proof, limits)
        };
        assert!(!verify(&proof, root, PERMISSION_LIMITS).unwrap());
        assert!(
            !evaluate_access_request(
                ReadCapture::new(state.acp.store().clone(), PERMISSION_LIMITS.reads),
                &policy,
                &request
            )
            .unwrap()
        );
        for i in 0..proof.reads.len() {
            let mut changed = proof.clone();
            changed.reads.remove(i);
            assert!(verify(&changed, root, PERMISSION_LIMITS).is_err());
            let mut duplicate = proof.clone();
            duplicate.reads.push(proof.reads[i].clone());
            assert!(verify(&duplicate, root, PERMISSION_LIMITS).is_err());
        }
        let generations = state.acp.query_policy(&policy).unwrap().relations;
        let blocked_prefix = keys::relationship_generation_prefix(
            &policy,
            generations.pair(&blocked).unwrap(),
            &keys::relation_prefix("document", "report", "blocked", 0),
        );
        let mut omitted = proof.clone();
        let deny_read = omitted
            .reads
            .iter_mut()
            .find(|r| {
                matches!(
                    r,
                    PermissionRead::CurrentPrefix { prefix, .. }
                        if prefix.as_ref() == blocked_prefix
                )
            })
            .unwrap();
        let PermissionRead::CurrentPrefix { proof: encoded, .. } = deny_read else {
            panic!("missing deny proof")
        };
        let mut evidence = PrefixEvidence::decode_cfg(
            commonware_codec::Copying(encoded.as_ref()),
            &PERMISSION_LIMITS.reads.records,
        )
        .unwrap();
        assert_eq!(evidence.entries.len(), 1);
        evidence.entries.clear();
        *encoded = evidence.encode().into();
        assert!(verify(&omitted, root, PERMISSION_LIMITS).is_err());

        let mut wrong_value = proof.clone();
        let present = wrong_value
            .reads
            .iter_mut()
            .find(|r| matches!(r, PermissionRead::CurrentPoint { value: Some(_), .. }))
            .unwrap();
        let PermissionRead::CurrentPoint {
            value: Some(value), ..
        } = present
        else {
            unreachable!()
        };
        *value = vec![0].into();
        assert!(verify(&wrong_value, root, PERMISSION_LIMITS).is_err());
        let mut wrong_roots = proof.clone();
        wrong_roots.roots.as_mut().unwrap().swap(0, 1);
        assert!(verify(&wrong_roots, root, PERMISSION_LIMITS).is_err());
        wrong_roots.roots = None;
        assert!(verify(&wrong_roots, root, PERMISSION_LIMITS).is_err());

        let size = encoded_size(&proof, usize::MAX).unwrap();
        assert!(
            !verify(
                &proof,
                root,
                PermissionLimits {
                    proof_bytes: size,
                    ..PERMISSION_LIMITS
                }
            )
            .unwrap()
        );
        assert!(
            verify(
                &proof,
                root,
                PermissionLimits {
                    proof_bytes: size - 1,
                    ..PERMISSION_LIMITS
                }
            )
            .is_err()
        );
        for limits in [
            PermissionLimits {
                proof_bytes: size - 1,
                ..PERMISSION_LIMITS
            },
            PermissionLimits {
                reads: ReadLimits {
                    records: 0,
                    ..PERMISSION_LIMITS.reads
                },
                ..PERMISSION_LIMITS
            },
            PermissionLimits {
                reads: ReadLimits {
                    bytes: 1,
                    ..PERMISSION_LIMITS.reads
                },
                ..PERMISSION_LIMITS
            },
        ] {
            assert!(
                permission_proof(
                    &set,
                    root,
                    state.acp.store().clone(),
                    &policy,
                    &request,
                    limits
                )
                .await
                .is_err()
            );
        }
        assert!(
            permission_proof(
                &set,
                root,
                InMemoryKvStore::default(),
                &policy,
                &request,
                PERMISSION_LIMITS
            )
            .await
            .is_err()
        );
        let before = state.clone();
        state
            .acp
            .direct_policy_cmd(&owner, &policy, PolicyCmd::DeleteRelationship(blocked))
            .unwrap();
        let next_root = apply(&set, state.diff_from(&before)).await;
        assert!(verify(&proof, next_root, PERMISSION_LIMITS).is_err());
        assert!(
            permission_proof(
                &set,
                root,
                state.acp.store().clone(),
                &policy,
                &request,
                PERMISSION_LIMITS
            )
            .await
            .is_err()
        );
        let allowed = permission_proof(
            &set,
            next_root,
            before.acp.store().clone(),
            &policy,
            &request,
            PERMISSION_LIMITS,
        )
        .await
        .unwrap();
        assert!(verify(&allowed, next_root, PERMISSION_LIMITS).unwrap());
        assert!(verify(&allowed, root, PERMISSION_LIMITS).is_err());
        let before = state.clone();
        state
            .acp
            .direct_policy_cmd(&owner, &policy, PolicyCmd::DeleteRelationship(reader))
            .unwrap();
        let revoked_root = apply(&set, state.diff_from(&before)).await;
        let revoked = permission_proof(
            &set,
            revoked_root,
            state.acp.store().clone(),
            &policy,
            &request,
            PERMISSION_LIMITS,
        )
        .await
        .unwrap();
        assert!(!verify(&revoked, revoked_root, PERMISSION_LIMITS).unwrap());
        assert!(verify(&allowed, revoked_root, PERMISSION_LIMITS).is_err());
    });
}

#[test]
fn prefix_evidence_handles_boundaries_and_rejects_noncanonical_or_excessive_data() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            for keys in [
                vec![],
                vec![b"p".to_vec()],
                vec![b"p/a".to_vec(), b"p/b".to_vec(), b"q".to_vec()],
            ] {
                apply(
                    &set,
                    [
                        keys.into_iter().map(|key| (key, Some(vec![1]))).collect(),
                        vec![],
                        vec![],
                        vec![],
                    ],
                )
                .await;
                let db = set.0.read().await;
                for prefix in [
                    b"".as_slice(),
                    b"a",
                    b"p",
                    b"p/",
                    b"p/a",
                    b"p/aa",
                    b"q",
                    b"z",
                ] {
                    let mut remaining = PERMISSION_LIMITS.reads;
                    let evidence =
                        prefix_proof(&db, prefix, &mut remaining, PERMISSION_LIMITS.proof_bytes)
                            .await
                            .unwrap();
                    evidence.verify(prefix, &db.root()).unwrap();
                    let encoded = evidence.encode();
                    assert_eq!(encoded.len(), evidence.encode_size());
                    let decoded =
                        PrefixEvidence::decode_cfg(encoded.clone(), &evidence.entries.len())
                            .unwrap();
                    decoded.verify(prefix, &db.root()).unwrap();
                    assert!(
                        PrefixEvidence::decode_cfg(encoded.slice(..encoded.len() - 1), &4096)
                            .is_err()
                    );
                    let mut trailing = encoded.to_vec();
                    trailing.push(0);
                    assert!(
                        PrefixEvidence::decode_cfg(
                            commonware_codec::Copying(trailing.as_slice()),
                            &4096
                        )
                        .is_err()
                    );
                    if !evidence.entries.is_empty() {
                        assert!(
                            PrefixEvidence::decode_cfg(encoded, &(evidence.entries.len() - 1))
                                .is_err()
                        );
                        let mut omitted = evidence.clone();
                        omitted.entries.pop();
                        assert!(omitted.verify(prefix, &db.root()).is_err());
                        let mut changed = evidence.clone();
                        changed.entries[0].value = Bytes::from_static(b"wrong");
                        assert!(changed.verify(prefix, &db.root()).is_err());
                    }
                    assert!(prefix_proof(&db, prefix, &mut remaining, 0).await.is_err());
                }
            }
        },
    );
}

#[test]
fn native_records_bind_module_key_value_and_current_root() {
    use super::super::record_proof_at;
    use vera_permission::{ModuleId, RECORD_PROOF_BYTES};

    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let key = b"record";
            let modules = [
                ModuleId::Acp,
                ModuleId::Bulletin,
                ModuleId::Vera,
                ModuleId::NativeNonce,
            ];
            let root = apply(&set, std::array::from_fn(|_| vec![])).await;
            {
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                for module in modules {
                    let absent = record_proof_at([&a, &b, &h, &n], root, module, key)
                        .await
                        .unwrap();
                    assert!(absent.value.is_none());
                    absent
                        .verify(root, module, key, RECORD_PROOF_BYTES)
                        .unwrap();
                }
            }
            let root = apply(
                &set,
                std::array::from_fn(|i| vec![(key.to_vec(), Some(vec![i as u8]))]),
            )
            .await;
            let retained = {
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                let mut retained = Vec::new();
                for module in modules {
                    let record = record_proof_at([&a, &b, &h, &n], root, module, key)
                        .await
                        .unwrap();
                    assert_eq!(
                        record.value.as_ref().unwrap().as_ref(),
                        &[module.index() as u8]
                    );
                    record
                        .verify(root, module, key, RECORD_PROOF_BYTES)
                        .unwrap();
                    assert!(
                        record
                            .verify(root, module, b"other", RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    assert!(record.verify(root, module, key, 1).is_err());
                    let other = modules[(module.index() + 1) % 4];
                    assert!(record.verify(root, other, key, RECORD_PROOF_BYTES).is_err());
                    let mut changed = record.clone();
                    changed.module = other;
                    assert!(
                        changed
                            .verify(root, other, key, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let mut changed = record.clone();
                    changed.value = Some(vec![42].into());
                    assert!(
                        changed
                            .verify(root, module, key, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let mut changed = record.clone();
                    changed.value = None;
                    assert!(
                        changed
                            .verify(root, module, key, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let mut changed = record.clone();
                    changed.roots[0].0[0] ^= 1;
                    assert!(
                        changed
                            .verify(root, module, key, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let mut changed = record.clone();
                    let mut bytes = changed.proof.to_vec();
                    bytes.push(0);
                    changed.proof = bytes.into();
                    assert!(
                        changed
                            .verify(root, module, key, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    retained.push(record);
                }
                assert!(
                    record_proof_at(
                        [&a, &b, &h, &n],
                        root,
                        ModuleId::Acp,
                        &vec![0; MAX_KEY_BYTES + 1]
                    )
                    .await
                    .is_err()
                );
                retained
            };
            let next = apply(&set, std::array::from_fn(|_| vec![(key.to_vec(), None)])).await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            for record in retained {
                assert!(
                    record
                        .verify(next, record.module, key, RECORD_PROOF_BYTES)
                        .is_err()
                );
                assert!(
                    record_proof_at([&a, &b, &h, &n], root, record.module, key)
                        .await
                        .is_err()
                );
                let absent = record_proof_at([&a, &b, &h, &n], next, record.module, key)
                    .await
                    .unwrap();
                assert!(absent.value.is_none());
                absent
                    .verify(next, record.module, key, RECORD_PROOF_BYTES)
                    .unwrap();
            }
        },
    );
}

#[test]
fn native_prefixes_bind_complete_coverage_module_and_root() {
    use super::super::prefix_proof_at;
    use vera_permission::{ModuleId, RECORD_PROOF_BYTES};

    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let modules = [
                ModuleId::Acp,
                ModuleId::Bulletin,
                ModuleId::Vera,
                ModuleId::NativeNonce,
            ];
            let root = apply(&set, std::array::from_fn(|_| vec![])).await;
            {
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                for module in modules {
                    let proof = prefix_proof_at([&a, &b, &h, &n], root, module, b"p/")
                        .await
                        .unwrap();
                    assert!(
                        proof
                            .verify(root, module, b"p/", RECORD_PROOF_BYTES)
                            .unwrap()
                            .entries
                            .is_empty()
                    );
                }
            }
            let root = apply(
                &set,
                std::array::from_fn(|i| {
                    [b"p/".as_slice(), b"p/a", b"p/b", b"q/"]
                        .into_iter()
                        .map(|key| (key.to_vec(), Some(vec![i as u8])))
                        .collect()
                }),
            )
            .await;
            let retained = {
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                let mut retained = Vec::new();
                for module in modules {
                    let proof = prefix_proof_at([&a, &b, &h, &n], root, module, b"p/")
                        .await
                        .unwrap();
                    let evidence = proof
                        .verify(root, module, b"p/", RECORD_PROOF_BYTES)
                        .unwrap();
                    assert_eq!(evidence.entries.len(), 3);
                    assert!(
                        proof
                            .verify(root, module, b"q/", RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    assert!(proof.verify(root, module, b"p/", 1).is_err());
                    let other = modules[(module.index() + 1) % 4];
                    let mut altered = proof.clone();
                    altered.module = other;
                    assert!(
                        altered
                            .verify(root, other, b"p/", RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let mut altered = proof.clone();
                    altered.roots[0].0[0] ^= 1;
                    assert!(
                        altered
                            .verify(root, module, b"p/", RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    for change in 0..4 {
                        let mut evidence = evidence.clone();
                        match change {
                            0 => {
                                evidence.entries.pop();
                            }
                            1 => {
                                evidence.entries.remove(0);
                            }
                            2 => {
                                evidence.entries.swap(0, 1);
                            }
                            _ => {
                                evidence.entries[0].value = vec![42].into();
                            }
                        }
                        let mut altered = proof.clone();
                        altered.proof = evidence.encode().into();
                        assert!(
                            altered
                                .verify(root, module, b"p/", RECORD_PROOF_BYTES)
                                .is_err()
                        );
                    }
                    let mut altered = proof.clone();
                    let mut bytes = altered.proof.to_vec();
                    bytes.push(0);
                    altered.proof = bytes.into();
                    assert!(
                        altered
                            .verify(root, module, b"p/", RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    retained.push(proof);
                }
                assert!(
                    prefix_proof_at(
                        [&a, &b, &h, &n],
                        root,
                        ModuleId::Acp,
                        &vec![0; MAX_KEY_BYTES + 1]
                    )
                    .await
                    .is_err()
                );
                retained
            };
            let next = apply(&set, std::array::from_fn(|_| vec![(b"p/a".to_vec(), None)])).await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            for proof in retained {
                assert!(
                    proof
                        .verify(next, proof.module, b"p/", RECORD_PROOF_BYTES)
                        .is_err()
                );
                assert!(
                    prefix_proof_at([&a, &b, &h, &n], root, proof.module, b"p/")
                        .await
                        .is_err()
                );
                let missing = prefix_proof_at([&a, &b, &h, &n], next, proof.module, b"p/a")
                    .await
                    .unwrap();
                assert!(
                    missing
                        .verify(next, proof.module, b"p/a", RECORD_PROOF_BYTES)
                        .unwrap()
                        .entries
                        .is_empty()
                );
            }
        },
    );
}

mod page;

mod policy;

mod objects;
