//! Raw-record hydration across activity changes and physical log pruning.

use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    merkle::Location,
    qmdb::sync::{Request, Source as _},
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use std::collections::BTreeMap;
use vera_backend::{
    BackendError,
    native::{self, NativeStateSet},
};
use vera_modules::{
    ModuleState,
    acp::{keys as acp_keys, types::PolicyMarshalingType},
    kv_store::InMemoryKvStore,
    module_state::{ModuleChanges, combine_module_roots},
};

async fn open(context: &tokio::Context) -> NativeStateSet {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(64));
    NativeStateSet::init(
        context.child("native"),
        native::state_config("hydrate", cache),
        None,
    )
    .await
}

async fn root(set: &NativeStateSet) -> alloy_primitives::B256 {
    combine_module_roots(&[
        set.0.read().await.root().0,
        set.1.read().await.root().0,
        set.2.read().await.root().0,
        set.3.read().await.root().0,
    ])
}

fn expected(records: &[BTreeMap<Vec<u8>, Vec<u8>>; 4]) -> [Vec<u8>; 4] {
    ModuleState::from_stores(std::array::from_fn(|i| {
        InMemoryKvStore::from_pairs(
            records[i]
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }))
    .serialize_stores()
}

#[test]
fn hydration_ignores_inactive_records_after_prune_delete_and_rewind() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Config::new().with_storage_directory(directory.path());
    let (records, target) = tokio::Runner::new(runtime.clone()).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("native"),
            native::state_config("hydrate", cache),
            None,
        )
        .await;
        let mut records: [BTreeMap<Vec<u8>, Vec<u8>>; 4] = std::array::from_fn(|_| BTreeMap::new());
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );
        for revision in 0..8 {
            let changes: ModuleChanges = std::array::from_fn(|module| {
                (0u16..256)
                    .map(|index| {
                        let mut key = vec![b'x'; native::INDEX_PREFIX_BYTES];
                        key.extend_from_slice(&index.to_be_bytes());
                        let value = if revision > 0 && index % 4 == 0 {
                            records[module].remove(&key);
                            None
                        } else {
                            let value = vec![revision ^ u8::try_from(module).unwrap(); 64];
                            records[module].insert(key.clone(), value.clone());
                            Some(value)
                        };
                        (key, value)
                    })
                    .collect()
            });
            let batch = native::prepare(set.new_batches().await, changes)
                .await
                .unwrap();
            set.apply(batch).await;
            assert!(set.finalize().await.durable().await);
        }
        let target = set.committed_targets().await;
        set.prune(&target).await;
        for (db, target) in [
            (&set.0, &target.0),
            (&set.1, &target.1),
            (&set.2, &target.2),
            (&set.3, &target.3),
        ] {
            assert!(*target.range.start() > 0);
            assert!(
                db.serve(Request::Operations {
                    size: target.range.end(),
                    start: Location::new(0),
                    max_ops: NZU64!(1)
                })
                .await
                .is_err()
            );
        }
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );

        let deletions =
            std::array::from_fn(|i| records[i].keys().cloned().map(|key| (key, None)).collect());
        let batch = native::prepare(set.new_batches().await, deletions)
            .await
            .unwrap();
        set.apply(batch).await;
        assert!(set.finalize().await.durable().await);
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            ModuleState::default().serialize_stores()
        );
        drop(set);
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("recovered"),
            native::state_config("hydrate", cache),
            Some(target.clone()),
        )
        .await;
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );
        (records, target)
    });
    tokio::Runner::new(runtime).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("native"),
            native::state_config("hydrate", cache),
            None,
        )
        .await;
        assert_eq!(set.committed_targets().await, target);
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );
    });
}

#[test]
fn hydration_rejects_orphaned_token_indexes() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(runtime).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("native"),
            native::state_config("token-index", cache), None,)
        .await;
        let key = vera_modules::vera::keys::jws_token_by_did_key("did:key:issuer", "missing");
        let mut changes: ModuleChanges = std::array::from_fn(|_| Vec::new());
        changes[2].push((key, Some(vec![1])));
        let batch = native::prepare(set.new_batches().await, changes).await.unwrap();
        set.apply(batch).await;
        assert!(set.finalize().await.durable().await);
        assert!(matches!(
            native::load_modules(&set).await,
            Err(vera_backend::BackendError::Storage(message)) if message.contains("token index has no record")
        ));
    });
}

#[test]
fn native_recovery_rejects_corrupt_policy_records_before_publication() {
    const POLICY: &str = "\
name: original
spec: defra
resources:
  - name: document
    permissions:
      - name: read
        expr: owner
      - name: write
        expr: owner
";
    const EDITED: &str = "\
name: edited
resources:
  - name: document
    permissions:
      - name: read
        expr: owner
      - name: write
        expr: owner
";
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    let (corrupt_target, corrupt_root) =
        tokio::Runner::new(config.clone()).start(|context| async move {
            let set = open(&context).await;
            let owner = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                .parse()
                .unwrap();
            let mut modules = ModuleState::default();
            modules
                .acp
                .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
                .unwrap();
            let policy_id = modules.acp.query_policy_ids().unwrap().remove(0);
            // The edited definition omits the original Defra specification; restoration supplies it.
            modules
                .acp
                .edit_policy(&owner, &policy_id, EDITED, PolicyMarshalingType::ShortYaml)
                .unwrap();
            let policy_key = acp_keys::policy_key(&policy_id);
            let changes = modules.diff_from(&ModuleState::default());
            let record = changes[0]
                .iter()
                .find(|(key, _)| *key == policy_key)
                .unwrap()
                .1
                .clone()
                .unwrap();
            let sealed = native::prepare(set.new_batches().await, changes)
                .await
                .unwrap();
            set.apply(sealed).await;
            assert!(set.finalize().await.durable().await);
            let loaded = native::load_modules(&set).await.unwrap();
            assert_eq!(
                loaded.acp.query_policy_ids().unwrap(),
                vec![policy_id.clone()]
            );
            assert_eq!(loaded.serialize_stores(), modules.serialize_stores());

            let mut truncated = record.clone();
            truncated.truncate(record.len() - 8);
            let mut mismatched: serde_json::Value = serde_json::from_slice(&record).unwrap();
            mismatched["raw_policy"] =
                serde_json::Value::String(mismatched["raw_policy"].as_str().unwrap().replacen(
                    "name: edited",
                    "name: another",
                    1,
                ));
            let corrupt = serde_json::to_vec(&mismatched).unwrap();
            for (value, expected) in [
                (truncated, "invalid policy record"),
                (corrupt, "restored policy differs from its definition"),
            ] {
                let mut changes: ModuleChanges = Default::default();
                changes[0].push((policy_key.clone(), Some(value)));
                let sealed = native::prepare(set.new_batches().await, changes)
                    .await
                    .unwrap();
                set.apply(sealed).await;
                assert!(set.finalize().await.durable().await);
                let before = set.committed_targets().await;
                let before_root = root(&set).await;
                let error = native::load_modules(&set).await.unwrap_err();
                assert!(
                    matches!(&error, BackendError::Storage(message) if message.contains(expected)),
                    "{error}"
                );
                assert_eq!(set.committed_targets().await, before);
                assert_eq!(root(&set).await, before_root);
            }
            (set.committed_targets().await, root(&set).await)
        });
    tokio::Runner::new(config).start(|context| async move {
        let set = open(&context).await;
        let error = native::load_modules(&set).await.unwrap_err();
        assert!(
            matches!(error, BackendError::Storage(message) if message.contains("restored policy differs from its definition"))
        );
        assert_eq!(set.committed_targets().await, corrupt_target);
        assert_eq!(root(&set).await, corrupt_root);
    });
}
