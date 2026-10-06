use super::*;
use commonware_runtime::Runner as _;
use commonware_utils::{NZU16, NZUsize};
use vera_modules::vera::administration::OperatorPolicy;

fn configured_genesis() -> VeraGenesis {
    let mut genesis = VeraGenesis::devnet();
    genesis.operators = Some(OperatorPolicy {
        threshold: 1,
        keys: vec!["0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into()],
    });
    genesis
}

#[test]
fn native_genesis_recovers_partial_initialization_and_binds_configuration() {
    let mut expected = None;
    for stage in 0..=2 {
        let directory = tempfile::tempdir().unwrap();
        let directory = directory.path();
        let runtime = tokio::Config::new().with_storage_directory(directory.join("commonware"));
        let genesis = configured_genesis();
        let genesis = &genesis;
        if stage > 0 {
            tokio::Runner::new(runtime.clone()).start(|context| async move {
                persist(
                    &directory.join("native-genesis.intent"),
                    crate::native_genesis::fingerprint(genesis)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
                let execution = VeraStateSet::init(
                    context.child("partial_execution"),
                    state_set_config(crate::node::PARTITION_PREFIX, cache.clone()),
                    None,
                )
                .await;
                vera_app::apply_genesis(&execution, &genesis.to_genesis_state().unwrap())
                    .await
                    .unwrap();
                if stage == 2 {
                    let modules = NativeStateSet::init(
                        context.child("partial_modules"),
                        native::state_config(crate::node::PARTITION_PREFIX, cache),
                        None,
                    )
                    .await;
                    let changes = [
                        vec![(b"partial".to_vec(), Some(vec![9]))],
                        vec![],
                        vec![],
                        vec![],
                    ];
                    modules
                        .apply(
                            native::prepare(modules.new_batches().await, changes)
                                .await
                                .unwrap(),
                        )
                        .await;
                    assert!(modules.finalize().await.durable().await);
                }
            });
        }
        let block = tokio::Runner::new(runtime.clone()).start(|context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let block = load_or_create(&context, directory, genesis, &cache)
                .await
                .unwrap();
            assert!(block.native_targets.is_some());
            assert_eq!(block.prevrandao, fingerprint(genesis).unwrap());
            assert!(!directory.join("native-genesis.intent").exists());
            let modules = NativeStateSet::init(
                context.child("check_modules"),
                native::state_config(crate::node::PARTITION_PREFIX, cache.clone()),
                None,
            )
            .await;
            let state = native::load_modules(&modules).await.unwrap();
            assert_eq!(
                Some(state.vera.administration().unwrap().unwrap().policy),
                genesis.operators
            );
            assert!(state.acp.store().is_empty());
            assert!(
                native::SyncProof::capture(&modules, block.module_state_root)
                    .await
                    .is_ok()
            );
            block
        });
        if let Some(expected) = &expected {
            assert_eq!(&block, expected);
        } else {
            expected = Some(block.clone());
        }
        tokio::Runner::new(runtime).start(|context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            assert_eq!(
                load_or_create(&context, directory, genesis, &cache)
                    .await
                    .unwrap(),
                block
            );
            let mut changed = (*genesis).clone();
            changed.operators = None;
            assert!(
                load_or_create(&context, directory, &changed, &cache)
                    .await
                    .is_err()
            );
            changed = (*genesis).clone();
            changed.allocations[0].balance = "1".into();
            assert!(
                load_or_create(&context, directory, &changed, &cache)
                    .await
                    .is_err()
            );
            let mut legacy = keccak256(serde_json::to_vec(genesis).unwrap()).to_vec();
            legacy.extend_from_slice(&block.encode());
            persist(&directory.join("native-genesis.bin"), &legacy).unwrap();
            assert!(
                load_or_create(&context, directory, genesis, &cache)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("explicit migration")
            );
            assert_eq!(
                fs::read(directory.join("native-genesis.bin")).unwrap(),
                legacy
            );
            let mut old = block;
            old.receipt_commitment = None;
            let mut record = crate::native_genesis::fingerprint(genesis)
                .unwrap()
                .to_vec();
            record.extend_from_slice(&old.encode());
            persist(&directory.join("native-genesis.bin"), &record).unwrap();
            assert!(
                load_or_create(&context, directory, genesis, &cache)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("explicit migration")
            );
            assert_eq!(
                fs::read(directory.join("native-genesis.bin")).unwrap(),
                record
            );
        });
    }
}

#[test]
fn journals_without_initialization_intent_are_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path();
    let runtime = tokio::Config::new().with_storage_directory(directory.join("commonware"));
    let expected = tokio::Runner::new(runtime.clone()).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let modules = NativeStateSet::init(
            context.child("existing"),
            native::state_config(crate::node::PARTITION_PREFIX, cache),
            None,
        )
        .await;
        modules
            .apply(
                native::prepare(
                    modules.new_batches().await,
                    [
                        vec![(b"existing".to_vec(), Some(vec![1]))],
                        vec![],
                        vec![],
                        vec![],
                    ],
                )
                .await
                .unwrap(),
            )
            .await;
        assert!(modules.finalize().await.durable().await);
        modules.committed_targets().await
    });
    tokio::Runner::new(runtime).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        assert!(
            load_or_create(&context, directory, &configured_genesis(), &cache)
                .await
                .is_err()
        );
        let modules = NativeStateSet::init(
            context.child("check_existing"),
            native::state_config(crate::node::PARTITION_PREFIX, cache),
            None,
        )
        .await;
        assert_eq!(modules.committed_targets().await, expected);
        assert!(!directory.join("native-genesis.bin").exists());
    });
}

#[test]
fn legacy_state_and_missing_genesis_with_history_require_recovery() {
    for marker in ["genesis_block.bin", "state", "history"] {
        let directory = tempfile::tempdir().unwrap();
        let directory = directory.path();
        if marker.ends_with(".bin") {
            fs::write(directory.join(marker), b"preserve").unwrap();
        } else {
            fs::create_dir(directory.join(marker)).unwrap();
        }
        let genesis = configured_genesis();
        let genesis = &genesis;
        persist(
            &directory.join("native-genesis.intent"),
            crate::native_genesis::fingerprint(genesis)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        tokio::Runner::new(
            tokio::Config::new().with_storage_directory(directory.join("commonware")),
        )
        .start(|context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            assert!(
                load_or_create(&context, directory, genesis, &cache)
                    .await
                    .is_err()
            );
            assert!(directory.join(marker).exists());
            assert!(!directory.join("native-genesis.bin").exists());
        });
    }
}

#[cfg(unix)]
#[test]
fn inaccessible_genesis_markers_fail_before_initializing_journals() {
    for marker in [
        "native-genesis.bin",
        "native-genesis.intent",
        "genesis_block.bin",
        "state",
        "history",
    ] {
        for target in [marker, "missing-target"] {
            let directory = tempfile::tempdir().unwrap();
            let directory = directory.path();
            let path = directory.join(marker);
            std::os::unix::fs::symlink(target, &path).unwrap();
            let storage = directory.join("commonware");
            tokio::Runner::new(tokio::Config::new().with_storage_directory(&storage)).start(
                |context| async move {
                    let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
                    let entries = || {
                        let mut names: Vec<_> = fs::read_dir(&storage)
                            .unwrap()
                            .map(|entry| entry.unwrap().file_name())
                            .collect();
                        names.sort();
                        names
                    };
                    let before = entries();
                    assert!(
                        load_or_create(&context, directory, &configured_genesis(), &cache)
                            .await
                            .is_err()
                    );
                    assert_eq!(
                        fs::read_link(&path).unwrap(),
                        std::path::PathBuf::from(target)
                    );
                    assert_eq!(
                        entries(),
                        before,
                        "failed initialization created journal entries"
                    );
                    for other in ["native-genesis.bin", "native-genesis.intent"] {
                        if other != marker {
                            assert!(!directory.join(other).exists());
                        }
                    }
                },
            );
        }
    }
}

#[test]
fn pipeline_parameters_bind_the_genesis_identity_and_restart() {
    let mut identities = Vec::new();
    for term_length in [8, 16] {
        let directory = tempfile::tempdir().unwrap();
        let mut genesis = configured_genesis();
        genesis.simplex = Some(vera_domain::SimplexParameters {
            term_length,
            ..Default::default()
        });
        let runtime =
            tokio::Config::new().with_storage_directory(directory.path().join("commonware"));
        let path = directory.path();
        let configured = &genesis;
        let block = tokio::Runner::new(runtime.clone()).start(|context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            load_or_create(&context, path, configured, &cache)
                .await
                .unwrap()
        });
        assert_eq!(block.prevrandao, fingerprint(&genesis).unwrap());
        identities.push(block.id());
        genesis.simplex.as_mut().unwrap().term_length += 1;
        let configured = &genesis;
        tokio::Runner::new(runtime).start(|context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            assert!(
                load_or_create(&context, path, configured, &cache)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("migration")
            );
        });
    }
    assert_ne!(identities[0], identities[1]);
}

#[test]
fn pre_pet_genesis_and_interrupted_initialization_are_rejected_unchanged() {
    let genesis = configured_genesis();
    let mut bytes = b"vera/native-genesis/v2\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&genesis).unwrap());
    let old_fingerprint = keccak256(bytes);
    assert_ne!(old_fingerprint, fingerprint(&genesis).unwrap());
    for marker in ["native-genesis.bin", "native-genesis.intent"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        persist(&path.join(marker), old_fingerprint.as_slice()).unwrap();
        let runtime = tokio::Config::new().with_storage_directory(path.join("commonware"));
        let genesis = &genesis;
        tokio::Runner::new(runtime).start(|context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let error = load_or_create(&context, path, genesis, &cache)
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("different") || error.to_string().contains("differs")
            );
        });
        assert_eq!(
            fs::read(path.join(marker)).unwrap(),
            old_fingerprint.as_slice()
        );
    }
}
