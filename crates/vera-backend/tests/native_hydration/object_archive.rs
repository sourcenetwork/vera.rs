use super::*;
use vera_modules::{
    acp::{
        object_state, relationship_index,
        types::{
            AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyCmdResult, RelationshipRecord,
        },
    },
    kv_store::ModuleKvStore as _,
    types::{BlockExecCtx, Timestamp},
};
use zanzibar::{Did, Relationship};

const POLICY: &str = "name: hydration\nresources:\n  - name: file\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n";
const OLD_GRANTS: usize = 257;
const CLEANUP_ITEMS_PER_BLOCK: usize = 128;
const OBJECT_QUEUE: &[u8] = b"object_cleanup/queue/";

struct Expected {
    stores: [Vec<u8>; 4],
    policy: String,
    old_keys: Vec<Vec<u8>>,
    fresh: RelationshipRecord,
    revoked: Did,
}

fn reader(index: usize) -> Did {
    Did::new(format!("did:key:reader-{index:04}")).unwrap()
}

fn primary(row: &RelationshipRecord) -> Vec<u8> {
    acp_keys::relationship_generation_key(
        &row.policy_id,
        row.generations,
        &acp_keys::relationship_storage_key(&row.relationship, row.incarnation),
    )
}

fn can_read(modules: &ModuleState, policy: &str, actor: Did) -> bool {
    modules
        .acp
        .query_verify_access_request(
            policy,
            &AccessRequest {
                actor: Actor(actor),
                operations: vec![Operation {
                    object: Object {
                        resource: "file".into(),
                        id: "report".into(),
                    },
                    permission: "read".into(),
                }],
            },
        )
        .unwrap()
}

fn old_remaining(modules: &ModuleState, keys: &[Vec<u8>]) -> usize {
    keys.iter()
        .filter(|key| modules.acp.store().has(key))
        .count()
}

fn assert_current(modules: &ModuleState, expected: &Expected) {
    modules.acp.validate_restored_state().unwrap();
    let store = modules.acp.store();
    assert_eq!(
        object_state::read(store, &expected.policy, "file", "report").unwrap(),
        1
    );
    assert_eq!(expected.fresh.incarnation, 1);
    assert!(store.has(&primary(&expected.fresh)));
    assert_eq!(
        relationship_index::read_logical_count(store, &expected.policy, expected.fresh.generations)
            .unwrap(),
        1
    );
    assert_eq!(
        relationship_index::read_pair_count(store, &expected.policy, expected.fresh.generations)
            .unwrap(),
        u64::try_from(old_remaining(modules, &expected.old_keys) + 1).unwrap()
    );
    assert!(can_read(modules, &expected.policy, reader(0)));
    assert!(!can_read(
        modules,
        &expected.policy,
        expected.revoked.clone()
    ));
}

fn clean_once(modules: &mut ModuleState, height: u64) {
    modules
        .acp
        .end_blocker(&BlockExecCtx {
            timestamp: Timestamp {
                block_height: height,
                seconds: height,
            },
            ..Default::default()
        })
        .unwrap();
}

async fn persist(set: &NativeStateSet, before: &ModuleState, after: &ModuleState) {
    let sealed = native::prepare(set.new_batches().await, after.diff_from(before))
        .await
        .unwrap();
    set.apply(sealed).await;
    assert!(set.finalize().await.durable().await);
}

#[test]
fn object_incarnation_cleanup_survives_native_reopen_without_reviving_grants() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    let (expected, target, committed_root) =
        tokio::Runner::new(config.clone()).start(|context| async move {
            let set = open(&context).await;
            let owner = Did::new("did:key:owner").unwrap();
            let object = Object {
                resource: "file".into(),
                id: "report".into(),
            };
            let mut modules = ModuleState::default();
            let policy = modules
                .acp
                .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .policy
                .id;
            modules
                .acp
                .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
                .unwrap();
            let mut old_keys = Vec::new();
            for index in 0..OLD_GRANTS {
                let PolicyCmdResult::SetRelationship { record, .. } = modules
                    .acp
                    .direct_policy_cmd(
                        &owner,
                        &policy,
                        PolicyCmd::SetRelationship(Relationship::with_entity(
                            "file",
                            "report",
                            "reader",
                            reader(index),
                        )),
                    )
                    .unwrap()
                else {
                    panic!("expected grant")
                };
                assert_eq!(record.incarnation, 0);
                old_keys.push(primary(&record));
                if index == 1 {
                    assert!(can_read(&modules, &policy, reader(0)));
                    assert!(can_read(&modules, &policy, reader(1)));
                }
            }
            persist(&set, &ModuleState::default(), &modules).await;
            let before = modules.clone();
            let archived = modules
                .acp
                .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(object.clone()))
                .unwrap();
            assert!(matches!(archived, PolicyCmdResult::ArchiveObject {
                found: true, relationships_removed,
            } if relationships_removed == u64::try_from(OLD_GRANTS + 1).unwrap()));
            modules
                .acp
                .direct_policy_cmd(&owner, &policy, PolicyCmd::UnarchiveObject(object))
                .unwrap();
            assert!(!can_read(&modules, &policy, reader(0)));
            assert!(!can_read(&modules, &policy, reader(1)));
            let PolicyCmdResult::SetRelationship { record: fresh, .. } = modules
                .acp
                .direct_policy_cmd(
                    &owner,
                    &policy,
                    PolicyCmd::SetRelationship(Relationship::with_entity(
                        "file",
                        "report",
                        "reader",
                        reader(0),
                    )),
                )
                .unwrap()
            else {
                panic!("expected current grant")
            };
            persist(&set, &before, &modules).await;
            let before = modules.clone();
            clean_once(&mut modules, 1);
            let remaining = old_remaining(&modules, &old_keys);
            assert!(remaining < OLD_GRANTS, "cleanup must make progress");
            assert!(
                remaining > CLEANUP_ITEMS_PER_BLOCK,
                "more than one cleanup block remains"
            );
            assert!(OLD_GRANTS - remaining <= CLEANUP_ITEMS_PER_BLOCK);
            // Denial must hold even for an actor whose obsolete row is still on disk.
            let revoked_index = old_keys
                .iter()
                .enumerate()
                .find(|(index, key)| *index != 0 && modules.acp.store().has(key))
                .unwrap()
                .0;
            let expected = Expected {
                stores: modules.serialize_stores(),
                policy,
                old_keys,
                fresh,
                revoked: reader(revoked_index),
            };
            assert_current(&modules, &expected);
            assert!(
                modules
                    .acp
                    .store()
                    .prefix_iter(OBJECT_QUEUE)
                    .next()
                    .is_some()
            );
            persist(&set, &before, &modules).await;
            (expected, set.committed_targets().await, root(&set).await)
        });

    // A fresh runtime reopens the journals and reconstructs the complete module maps.
    tokio::Runner::new(config).start(|context| async move {
        let set = open(&context).await;
        assert_eq!(set.committed_targets().await, target);
        assert_eq!(root(&set).await, committed_root);
        let mut modules = native::load_modules(&set).await.unwrap();
        assert_eq!(modules.serialize_stores(), expected.stores);
        assert_current(&modules, &expected);
        assert!(old_remaining(&modules, &expected.old_keys) > CLEANUP_ITEMS_PER_BLOCK);
        for height in 2..=8 {
            let before = modules.clone();
            let remaining = old_remaining(&before, &expected.old_keys);
            clean_once(&mut modules, height);
            let after = old_remaining(&modules, &expected.old_keys);
            assert!(after <= remaining);
            assert!(remaining - after <= CLEANUP_ITEMS_PER_BLOCK);
            assert_current(&modules, &expected);
            persist(&set, &before, &modules).await;
            let loaded = native::load_modules(&set).await.unwrap();
            assert_eq!(loaded.serialize_stores(), modules.serialize_stores());
            modules = loaded;
        }
        assert_eq!(old_remaining(&modules, &expected.old_keys), 0);
        assert!(
            modules
                .acp
                .store()
                .prefix_iter(OBJECT_QUEUE)
                .next()
                .is_none()
        );
        assert_current(&modules, &expected);
        // A stable next sweep also covers retirement-marker and queue completion.
        let settled = modules.serialize_stores();
        clean_once(&mut modules, 9);
        assert_eq!(modules.serialize_stores(), settled);
    });
}
