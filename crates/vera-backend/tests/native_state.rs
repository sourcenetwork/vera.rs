//! Native module deltas through Commonware's pending, durable and recovery lifecycle.

#![recursion_limit = "256"]

use commonware_cryptography::Sha256;
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use vera_backend::{
    BackendError,
    native::{self, NativeStateSet},
};
use vera_modules::{
    ModuleState,
    acp::{
        keys,
        types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
    },
    bulletin::keys as bulletin_keys,
    kv_store::{InMemoryKvStore, ModuleKvStore},
    module_state::{ModuleChanges, combine_module_roots},
    types::{BlockExecCtx, TxExecCtx},
    vera::types::ChainConfig,
};
use zanzibar::{Relationship, Subject};

const OWNER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const READER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
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

async fn open(context: &tokio::Context) -> NativeStateSet {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(64));
    NativeStateSet::init(
        context.child("native"),
        native::state_config("test", cache),
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

fn can_read(modules: &ModuleState, policy: &str) -> bool {
    modules
        .acp
        .query_verify_access_request(
            policy,
            &AccessRequest {
                actor: Actor(READER.parse().unwrap()),
                operations: vec![Operation {
                    object: Object {
                        resource: "document".into(),
                        id: "report".into(),
                    },
                    permission: "read".into(),
                }],
            },
        )
        .unwrap()
}

#[test]
fn authorization_survives_forks_restart_and_rewind() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    let (first_state, first_root, first_target, second_state, second_root, policy) =
        tokio::Runner::new(config.clone()).start(|context| async move {
            let set = open(&context).await;
            let empty = ModuleState::default();
            let mut first_state = empty.clone();
            let owner = OWNER.parse().unwrap();
            let policy = first_state
                .acp
                .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .policy
                .id;
            first_state
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
            for relationship in [
                Relationship::with_entity("document", "report", "reader", READER.parse().unwrap()),
                blocked.clone(),
            ] {
                first_state
                    .acp
                    .direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(relationship))
                    .unwrap();
            }
            first_state
                .bulletin
                .register_namespace(
                    &mut first_state.acp,
                    &BlockExecCtx::default(),
                    &TxExecCtx {
                        sequence: 0,
                        tx_hash: vec![1; 32],
                        signer: OWNER.into(),
                    },
                    &owner,
                    "reports",
                )
                .unwrap();
            first_state
                .vera
                .set_chain_config(ChainConfig {
                    allow_zero_fee_txs: true,
                    ignore_bearer_auth: false,
                })
                .unwrap();
            first_state.nonces.check_and_increment(OWNER, 0).unwrap();
            // Clone resets dirty tracking; the delta must still include the policy and namespace.
            let first_state = first_state.clone();
            let first = native::prepare(set.new_batches().await, first_state.diff_from(&empty))
                .await
                .unwrap();
            let first_root = native::state_root(&first);

            let mut second_state = first_state.clone();
            second_state
                .acp
                .direct_policy_cmd(&owner, &policy, PolicyCmd::DeleteRelationship(blocked))
                .unwrap();
            second_state.nonces.check_and_increment(OWNER, 1).unwrap();
            let second = native::prepare(
                NativeStateSet::fork_batches(&first),
                second_state.diff_from(&first_state),
            )
            .await
            .unwrap();
            let second_root = native::state_root(&second);
            let mut rejected_state = first_state.clone();
            rejected_state
                .nonces
                .check_and_increment(READER, 0)
                .unwrap();
            let rejected = native::prepare(
                NativeStateSet::fork_batches(&first),
                rejected_state.diff_from(&first_state),
            )
            .await
            .unwrap();
            assert_ne!(native::state_root(&rejected), second_root);
            assert_eq!(
                native::load_modules(&set).await.unwrap().serialize_stores(),
                empty.serialize_stores()
            );

            set.apply(first).await;
            assert!(set.finalize().await.durable().await);
            let first_target = set.committed_targets().await;
            let loaded = native::load_modules(&set).await.unwrap();
            assert_eq!(loaded.serialize_stores(), first_state.serialize_stores());
            assert!(!can_read(&loaded, &policy));
            assert_eq!(root(&set).await, first_root);

            set.apply(second).await;
            assert!(set.finalize().await.durable().await);
            drop(rejected);
            let loaded = native::load_modules(&set).await.unwrap();
            assert_eq!(loaded.serialize_stores(), second_state.serialize_stores());
            assert!(can_read(&loaded, &policy));
            assert_eq!(loaded.nonces.get_nonce(READER).unwrap(), 0);
            assert_eq!(root(&set).await, second_root);

            let target = set.committed_targets().await;
            let db = set.0.read().await;
            let key = keys::policy_key(&policy);
            let value = db.get(&key).await.unwrap().unwrap();
            let proof = db.key_value_proof(key.clone()).await.unwrap();
            assert!(proof.verify::<Sha256, _>(key.clone(), value.clone(), &db.root()));
            assert!(!proof.verify::<Sha256, _>(key, value, &target.0.root));
            (
                first_state,
                first_root,
                first_target,
                second_state,
                second_root,
                policy,
            )
        });

    tokio::Runner::new(config.clone()).start(|context| async move {
        let set = open(&context).await;
        let loaded = native::load_modules(&set).await.unwrap();
        assert_eq!(loaded.serialize_stores(), second_state.serialize_stores());
        assert!(can_read(&loaded, &policy));
        assert_eq!(root(&set).await, second_root);
        drop(set);
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("recovered"),
            native::state_config("test", cache),
            Some(first_target),
        )
        .await;
        let loaded = native::load_modules(&set).await.unwrap();
        assert_eq!(loaded.serialize_stores(), first_state.serialize_stores());
        assert!(!can_read(&loaded, &policy));
        assert_eq!(root(&set).await, first_root);
    });
    tokio::Runner::new(config).start(|context| async move {
        assert_eq!(root(&open(&context).await).await, first_root);
    });
}

#[test]
fn record_limits_and_colliding_prefixes_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    let expected = tokio::Runner::new(config.clone()).start(|context| async move {
        let set = open(&context).await;
        let before = set.committed_targets().await;
        for module in 0..4 {
            for invalid in [
                vec![(vec![1; native::MAX_KEY_BYTES + 1], None)],
                vec![(b"key".to_vec(), Some(vec![1; native::MAX_VALUE_BYTES + 1]))],
                vec![(b"b".to_vec(), None), (b"a".to_vec(), None)],
                vec![(b"a".to_vec(), None), (b"a".to_vec(), None)],
            ] {
                let mut changes: ModuleChanges =
                    std::array::from_fn(|_| vec![(b"valid".to_vec(), Some(vec![1]))]);
                changes[module] = invalid;
                assert!(matches!(
                    native::prepare(set.new_batches().await, changes).await,
                    Err(BackendError::InvalidModuleChange(_))
                ));
                assert_eq!(set.committed_targets().await, before);
            }
        }
        let modules = ModuleState::from_stores(std::array::from_fn(|module| {
            let mut store = InMemoryKvStore::default();
            // 0xFF keys avoid module-owned prefixes; recovery structurally validates those records.
            for key in [
                vec![],
                vec![0],
                vec![0xFF; native::INDEX_PREFIX_BYTES],
                vec![0xFF; native::INDEX_PREFIX_BYTES + 1],
                vec![0xFF; native::MAX_KEY_BYTES],
            ] {
                store.put(&key, vec![u8::try_from(module).unwrap(); 8]);
            }
            store.put(b"large-value", vec![2; native::MAX_VALUE_BYTES]);
            store
        }));
        let sealed = native::prepare(
            set.new_batches().await,
            modules.diff_from(&ModuleState::default()),
        )
        .await
        .unwrap();
        set.apply(sealed).await;
        assert!(set.finalize().await.durable().await);
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            modules.serialize_stores()
        );
        modules.serialize_stores()
    });
    tokio::Runner::new(config).start(|context| async move {
        let set = open(&context).await;
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected
        );
    });
}

#[test]
fn native_hydration_rejects_invalid_bulletin_keys_without_modifying_state() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(|context| async move {
        let set = open(&context).await;
        let owner = OWNER.parse().unwrap();
        let tx_ctx = TxExecCtx {
            sequence: 0,
            tx_hash: vec![1; 32],
            signer: OWNER.into(),
        };
        let mut modules = ModuleState::default();
        modules
            .bulletin
            .register_namespace(
                &mut modules.acp,
                &BlockExecCtx::default(),
                &tx_ctx,
                &owner,
                "reports",
            )
            .unwrap();
        let post_id = modules
            .bulletin
            .create_post(
                &modules.acp,
                &tx_ctx,
                &owner,
                "reports",
                b"payload",
                &[],
                "",
            )
            .unwrap();
        let post_key = bulletin_keys::post_key("bulletin/reports", &post_id);
        let changes = modules.diff_from(&ModuleState::default());
        let post_value = changes[1]
            .iter()
            .find(|(key, _)| *key == post_key)
            .unwrap()
            .1
            .clone()
            .unwrap();
        let mut changes: ModuleChanges = Default::default();
        // A valid record under a mismatched key fails its identity check like a legacy alias.
        changes[1].push((b"post/legacy/id".to_vec(), Some(post_value)));
        let sealed = native::prepare(set.new_batches().await, changes)
            .await
            .unwrap();
        set.apply(sealed).await;
        assert!(set.finalize().await.durable().await);
        let before = set.committed_targets().await;
        let before_root = root(&set).await;
        let error = native::load_modules(&set).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bulletin key does not match its record")
        );
        assert_eq!(set.committed_targets().await, before);
        assert_eq!(root(&set).await, before_root);
    });
}
