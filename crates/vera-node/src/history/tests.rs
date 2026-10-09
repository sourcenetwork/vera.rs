use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use vera_domain::{DbTargets, StateRoot, Tx};

#[path = "physical_tests.rs"]
mod physical_tests;

pub(super) fn block(height: u64, parent: BlockId) -> Block {
    Block {
        context: Block::genesis_context(),
        parent,
        height,
        timestamp: height,
        prevrandao: B256::ZERO,
        state_root: StateRoot(B256::ZERO),
        module_state_root: B256::ZERO,
        txs: Vec::new(),
        payload: None,
        native_targets: None,
        receipt_commitment: None,
        db_targets: DbTargets::default(),
    }
}

fn artifacts(height: u64) -> FinalizationArtifacts {
    FinalizationArtifacts {
        epoch: 0,
        finalization: height.to_be_bytes().to_vec(),
        certificate: Vec::new(),
    }
}

#[tokio::test]
async fn failed_finalized_write_preserves_head_and_recovers_visible_batch() {
    for visible in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let first = block(1, genesis.id());
        let second = block(2, first.id());
        {
            let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
            history.append_finalized(&first, &[], 100, None).unwrap();
            let error = history
                .append_batch_with_write(
                    &second,
                    &[],
                    100,
                    FinalizedHistory::finalization_batch(2, Some(&artifacts(2))).unwrap(),
                    |db, batch| {
                        if visible {
                            write(db, batch)?;
                        }
                        Err(std::io::Error::other("injected history write failure").into())
                    },
                )
                .unwrap_err();
            assert!(error.to_string().contains("injected history write failure"));
            assert_eq!(*history.head.lock(), (1, first.id()));
            for prefix in [RECORD, CERTIFICATE] {
                assert_eq!(history.db.get(key(prefix, 2)).unwrap().is_some(), visible);
            }
            let expected = if visible { &second } else { &first };
            let head = borsh::to_vec(&(expected.height, expected.id().0.0)).unwrap();
            assert_eq!(history.db.get(HEAD).unwrap().unwrap(), head);
            assert_eq!(history.db.get(QUERY_HEAD).unwrap().unwrap(), head);
            if visible {
                assert!(history.append_finalized(&second, &[], 100, None).is_err());
            }
        }
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        let selected = if visible { &second } else { &first };
        let index = BlockIndex::new();
        let light = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
        let lookup: FinalizationLookup =
            Arc::new(|_| panic!("persisted certificate lookup must not be repeated"));
        history
            .recover(&genesis, selected, &index, &light, &lookup)
            .await
            .unwrap();
        assert_eq!(index.head_block_number(), selected.height);
        if visible {
            assert_eq!(
                light.get_finalization(&second.digest().0).unwrap().bytes,
                artifacts(2).finalization
            );
        }
        let next = block(selected.height + 1, selected.id());
        history.append_finalized(&next, &[], 100, None).unwrap();
        assert_eq!(*history.head.lock(), (next.height, next.id()));
    }
}

#[tokio::test]
async fn finalized_batch_preserves_execution_and_certificate_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let first = block(1, genesis.id());
    let second = block(2, first.id());
    let skipped = block(4, second.id());
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        history.append(&first, &[], 100).unwrap();
        assert!(
            history
                .append_finalized(&first, &[], 101, Some(&artifacts(1)))
                .is_err()
        );
        assert!(history.db.get(key(CERTIFICATE, 1)).unwrap().is_none());
        history
            .append_finalized(&first, &[], 100, Some(&artifacts(1)))
            .unwrap();
        history.append_finalized(&second, &[], 100, None).unwrap();
        assert!(
            history
                .append_finalized(&skipped, &[], 100, Some(&artifacts(4)))
                .is_err()
        );
        assert!(history.db.get(key(RECORD, 4)).unwrap().is_none());
        assert!(history.db.get(key(CERTIFICATE, 4)).unwrap().is_none());
    }
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    let index = BlockIndex::new();
    let light = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
    let lookup: FinalizationLookup = Arc::new(|_| panic!("persisted lookup must not be repeated"));
    history
        .recover(&genesis, &second, &index, &light, &lookup)
        .await
        .unwrap();
    assert_eq!(index.head_block_number(), 2);
    assert_eq!(
        light.get_finalization(&first.digest().0).unwrap().bytes,
        artifacts(1).finalization
    );
    assert!(light.get_finalization(&second.digest().0).is_none());
}

#[tokio::test]
async fn restart_restores_history_and_replaces_the_unprocessed_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let first = block(1, genesis.id());
    let second = block(2, first.id());
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        assert!(history.append(&second, &[], 100).is_err());
        history.append(&first, &[], 100).unwrap();
        history.append(&first, &[], 100).unwrap();
        assert!(history.append(&first, &[], 101).is_err());
        history.append(&second, &[], 100).unwrap();
        history.store_finalization(2, Some(&artifacts(2))).unwrap();
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let lookup: FinalizationLookup = {
        let calls = calls.clone();
        Arc::new(move |height| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { Some(artifacts(height)) })
        })
    };
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        let index = BlockIndex::new();
        let light = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
        history
            .recover(&genesis, &first, &index, &light, &lookup)
            .await
            .unwrap();
        assert_eq!(index.head_block_number(), 1);
        assert_eq!(index.get_block_by_number(1).unwrap().hash, first.id().0);
        assert!(index.get_block_by_number(2).is_none());
        assert_eq!(
            light.get_finalization(&first.digest().0).unwrap().bytes,
            artifacts(1).finalization
        );
        assert!(history.db.get(key(CERTIFICATE, 2)).unwrap().is_none());
        let mut replacement = second.clone();
        replacement.timestamp += 1;
        history.append(&replacement, &[], 100).unwrap();
    }
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        history
            .recover(
                &genesis,
                &first,
                &BlockIndex::new(),
                &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                &lookup,
            )
            .await
            .unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "stored certificates should survive restart"
        );
        let mut wrong = first.clone();
        wrong.timestamp += 1;
        assert!(
            history
                .recover(
                    &genesis,
                    &wrong,
                    &BlockIndex::new(),
                    &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                    &lookup
                )
                .await
                .is_err()
        );
        history.db.delete(key(RECORD, 1)).unwrap();
        assert!(
            history
                .recover(
                    &genesis,
                    &first,
                    &BlockIndex::new(),
                    &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                    &lookup
                )
                .await
                .is_err()
        );
    }
    let mut other_genesis = genesis.clone();
    other_genesis.timestamp += 1;
    assert!(FinalizedHistory::open(dir.path(), &other_genesis).is_err());
}

#[test]
fn execution_record_preserves_receipt_fields_and_rejects_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let mut first = block(1, genesis.id());
    first.txs.push(Tx::new(vec![1, 2, 3].into()));
    let log = Log::new_unchecked(
        Address::repeat_byte(7),
        vec![B256::repeat_byte(8)],
        vec![9, 10].into(),
    );
    let receipt = ExecutionReceipt::new(
        B256::repeat_byte(4),
        false,
        17,
        29,
        vec![log.clone()],
        Some(Address::repeat_byte(5)),
    );
    first.native_targets = Some([vera_domain::DbTarget::default(); 4]);
    first.receipt_commitment = Some(vera_executor::receipt_commitment(
        31,
        std::slice::from_ref(&receipt),
    ));
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    assert!(
        history
            .append(&first, std::slice::from_ref(&receipt), 32)
            .is_err()
    );
    history
        .append(&first, std::slice::from_ref(&receipt), 31)
        .unwrap();
    let bytes = history.db.get(key(RECORD, 1)).unwrap().unwrap();
    let mut record: Record = borsh::from_slice(&bytes).unwrap();
    let (restored, receipts) = record.decode().unwrap();
    assert_eq!(restored, first);
    let actual = &receipts[0];
    assert_eq!(actual.tx_hash, receipt.tx_hash);
    assert_eq!(actual.contract_address, receipt.contract_address);
    assert_eq!(actual.gas_used, 17);
    assert_eq!(actual.cumulative_gas_used(), 29);
    assert!(!actual.success());
    assert_eq!(actual.logs(), &[log]);
    assert_eq!(record.gas_limit, 31);
    for mutation in 0..9 {
        let mut altered: Record = borsh::from_slice(&bytes).unwrap();
        match mutation {
            0 => altered.receipts[0].hash[0] ^= 1,
            1 => altered.receipts[0].success = true,
            2 => altered.receipts[0].gas_used += 1,
            3 => altered.receipts[0].cumulative_gas_used += 1,
            4 => altered.receipts[0].contract = None,
            5 => altered.receipts[0].logs.clear(),
            6 => altered.gas_limit += 1,
            7 => altered.receipts.clear(),
            8 => {
                let mut missing = first.clone();
                missing.receipt_commitment = None;
                altered.block = missing.encode().to_vec();
            }
            _ => unreachable!(),
        }
        assert!(
            altered.decode().is_err(),
            "accepted receipt mutation {mutation}"
        );
    }
    record.receipts[0].logs[0].push(0);
    assert!(record.decode().is_err());
    assert!(borsh::from_slice::<Record>(&bytes[..bytes.len() - 1]).is_err());
}

#[tokio::test]
async fn receipt_corruption_is_rejected_before_recovery_publishes_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let mut first = block(1, genesis.id());
    first.native_targets = Some([vera_domain::DbTarget::default(); 4]);
    first.receipt_commitment = Some(vera_executor::receipt_commitment(100, &[]));
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    history.append(&first, &[], 100).unwrap();
    let bytes = history.db.get(key(RECORD, 1)).unwrap().unwrap();
    let mut record: Record = borsh::from_slice(&bytes).unwrap();
    record.gas_limit = 101;
    history
        .db
        .put(key(RECORD, 1), borsh::to_vec(&record).unwrap())
        .unwrap();
    let index = BlockIndex::new();
    let light = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
    let lookup: FinalizationLookup =
        Arc::new(|_| panic!("invalid record must not reach certificate lookup"));
    let error = history
        .recover(&genesis, &first, &index, &light, &lookup)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("receipt commitment mismatch"));
    assert!(index.get_block_by_number(1).is_none());
    assert_eq!(*history.head.lock(), (1, first.id()));
}

#[tokio::test]
async fn ancestor_without_a_direct_certificate_remains_queryable() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let first = block(1, genesis.id());
    let unavailable: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        history.append(&first, &[], 100).unwrap();
        history
            .recover(
                &genesis,
                &first,
                &BlockIndex::new(),
                &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                &unavailable,
            )
            .await
            .unwrap();
    }
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    let index = BlockIndex::new();
    let light = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
    let unexpected: FinalizationLookup = Arc::new(|_| panic!("lookup result must be retained"));
    history
        .recover(&genesis, &first, &index, &light, &unexpected)
        .await
        .unwrap();
    assert_eq!(index.get_block_by_number(1).unwrap().hash, first.id().0);
    assert!(light.get_finalization(&first.digest().0).is_none());
}

#[tokio::test]
async fn indirect_proof_survives_reopen_and_uses_the_rpc_history_lookup() {
    use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_parallel::Sequential;
    use commonware_utils::non_empty;
    use vera_app::ConsensusScheme;
    use vera_domain::{ConsensusDigest, verify_light_block};
    use vera_jsonrpc::{NodeState, VeraApiImpl, VeraApiServer};

    let public = ed25519::PrivateKey::from_seed(7).public_key();
    let (mut info, shares) = crate::trusted_setup(7, [public.clone()]).unwrap();
    let material = EpochMaterial::new(info.output.players().clone(), info.output.public().clone());
    let trusted = *material.sharing.public();
    let signer = ConsensusScheme::signer(
        crate::NAMESPACE,
        material.participants.clone(),
        material.sharing.clone(),
        shares.get_value(&public).unwrap().clone(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    info.epoch = commonware_consensus::types::Epoch::new(1);
    let mut first = block(1, genesis.id());
    first.payload = Some(Payload::EpochInfo(info));
    first.txs.push(Tx::new(vec![1].into()));
    let receipt = ExecutionReceipt::new(B256::repeat_byte(42), false, 3, 3, vec![], None);
    first.receipt_commitment = Some(vera_executor::receipt_commitment(
        100,
        std::slice::from_ref(&receipt),
    ));

    let mut second = block(2, first.id());
    second.context.round = commonware_consensus::types::Round::new(
        commonware_consensus::types::Epoch::new(1),
        second.context.round.view(),
    );
    let mut third = block(3, second.id());
    third.context.round = second.context.round;
    let proposal = Proposal::new(third.context.round, third.context.parent.0, third.digest());
    let vote = Finalize::sign(&signer, proposal).unwrap();
    let finalization: Finalization<ConsensusScheme, ConsensusDigest> =
        Finalization::from_finalizes(&signer, non_empty![&vote], &Sequential).unwrap();
    let certificate = FinalizationArtifacts {
        epoch: 1,
        finalization: finalization.encode().to_vec(),
        certificate: finalization.certificate.encode().to_vec(),
    };
    let epochs = Arc::new(LightBlockIndex::new(std::num::NonZeroU64::new(2).unwrap()));
    epochs.insert_epoch_material(
        1,
        StoredEpochMaterial {
            bytes: material.encode().to_vec(),
        },
    );
    let expected;
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        for block in [&first, &second, &third] {
            let receipts = if block.height == 1 {
                std::slice::from_ref(&receipt)
            } else {
                &[]
            };
            history.append(block, receipts, 100).unwrap();
            history.store_finalization(block.height, None).unwrap();
        }
        assert!(history.light_block(1, &epochs).is_err());
        history.store_finalization(3, Some(&certificate)).unwrap();
        expected = history.light_block(1, &epochs).unwrap();
        assert_eq!(expected.height, 1);
        assert_eq!(expected.descendants.len(), 2);
        verify_light_block(&expected, &trusted).unwrap();
        assert!(
            history
                .light_block(3, &epochs)
                .unwrap()
                .descendants
                .is_empty()
        );
        assert!(history.light_block(0, &epochs).is_err());
        assert!(history.light_block(4, &epochs).is_err());
    }
    let history = Arc::new(FinalizedHistory::open(dir.path(), &genesis).unwrap());
    let lookup: FinalizationLookup = Arc::new(|_| panic!("persisted artifacts must be reused"));
    let index = Arc::new(BlockIndex::new());
    history
        .recover(&genesis, &third, &index, &epochs, &lookup)
        .await
        .unwrap();
    assert!(epochs.get_finalization(&first.digest().0).is_none());
    let calls = Arc::new(AtomicUsize::new(0));
    let api = VeraApiImpl::new(Arc::new(NodeState::new(1, 0, 1)), None)
        .with_index_and_modules(
            index.clone(),
            Arc::new(std::sync::RwLock::new(vera_modules::ModuleState::default())),
        )
        .with_light_block_index(epochs.clone())
        .with_light_block_lookup({
            let history = history.clone();
            let epochs = epochs.clone();
            let calls = calls.clone();
            Arc::new(move |height| {
                calls.fetch_add(1, Ordering::Relaxed);
                history
                    .light_block(height, &epochs)
                    .map_err(|error| error.to_string())
            })
        });
    let restored = api
        .get_light_block(alloy_primitives::U64::from(1))
        .await
        .unwrap();
    assert_eq!(restored, expected);
    verify_light_block(&restored, &trusted).unwrap();
    let direct = api
        .get_light_block(alloy_primitives::U64::from(3))
        .await
        .unwrap();
    assert!(direct.descendants.is_empty());
    verify_light_block(&direct, &trusted).unwrap();
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "direct proofs must use the existing index"
    );
    for epoch in 2..=vera_indexer::MAX_CACHED_EPOCHS as u64 + 1 {
        epochs.insert_epoch_material(epoch, StoredEpochMaterial { bytes: vec![] });
    }
    assert!(epochs.get_epoch_material(1).is_none());
    let uncached_epoch = api
        .get_light_block(alloy_primitives::U64::from(3))
        .await
        .unwrap();
    assert_eq!(uncached_epoch, direct);
    verify_light_block(&uncached_epoch, &trusted).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    for number in 0..vera_indexer::MAX_CACHED_FINALIZATIONS {
        let mut digest = [0; 32];
        digest[..8].copy_from_slice(&(number as u64).to_be_bytes());
        assert_ne!(digest, third.digest().0);
        epochs.insert_finalization(
            digest,
            StoredFinalization {
                epoch: 0,
                bytes: vec![],
                block: vec![],
            },
        );
    }
    assert!(epochs.get_finalization(&third.digest().0).is_none());
    let evicted = api
        .get_light_block(alloy_primitives::U64::from(3))
        .await
        .unwrap();
    assert_eq!(evicted, direct);
    verify_light_block(&evicted, &trusted).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    // Archived reads share the node's recovered index; the publication gate drops
    // proofs ahead of its head while still routing unindexed receipts to history.
    let archive_api = VeraApiImpl::new(Arc::new(NodeState::new(1, 0, 1)), None)
        .with_index_and_modules(
            index.clone(),
            Arc::new(std::sync::RwLock::new(vera_modules::ModuleState::default())),
        )
        .with_receipt_proof_lookup({
            let history = history.clone();
            let epochs = epochs.clone();
            Arc::new(move |hash| {
                history
                    .receipt_proof(hash, &epochs)
                    .map_err(|error| error.to_string())
            })
        });
    let archived = archive_api
        .get_receipt_proof(receipt.tx_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !archived
            .verify(receipt.tx_hash, &trusted)
            .unwrap()
            .success()
    );
    assert!(archived.verify(B256::ZERO, &trusted).is_err());
    assert!(
        archive_api
            .get_receipt_proof(B256::ZERO)
            .await
            .unwrap()
            .is_none()
    );

    assert!(
        api.get_light_block(alloy_primitives::U64::from(4))
            .await
            .is_err()
    );
    let original = history.db.get(key(RECORD, 1)).unwrap().unwrap();
    let mut record: Record = borsh::from_slice(&original).unwrap();
    let mut boundary = first.clone();
    let Some(Payload::EpochInfo(info)) = &mut boundary.payload else {
        unreachable!()
    };
    info.epoch = commonware_consensus::types::Epoch::new(2);
    record.block = boundary.encode().to_vec();
    history
        .db
        .put(key(RECORD, 1), borsh::to_vec(&record).unwrap())
        .unwrap();
    assert!(
        api.get_light_block(alloy_primitives::U64::from(3))
            .await
            .unwrap_err()
            .message()
            .contains("epoch boundary material mismatch")
    );
    history.db.put(key(RECORD, 1), original).unwrap();
    history.db.delete(key(RECORD, 2)).unwrap();
    assert!(
        api.get_light_block(alloy_primitives::U64::from(1))
            .await
            .is_err()
    );
}

#[test]
fn history_proofs_reject_gaps_corruption_and_excessive_work() {
    use vera_domain::{LIGHT_BLOCK_MAX_ARTIFACT_BYTES, LIGHT_BLOCK_MAX_DESCENDANTS};
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    let epochs = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
    epochs.insert_epoch_material(0, StoredEpochMaterial { bytes: vec![1] });
    let mut parent = genesis.id();
    for height in 1..=LIGHT_BLOCK_MAX_DESCENDANTS as u64 + 2 {
        let next = block(height, parent);
        history.append(&next, &[], 100).unwrap();
        parent = next.id();
    }
    let last = LIGHT_BLOCK_MAX_DESCENDANTS as u64 + 2;
    history
        .store_finalization(last, Some(&artifacts(last)))
        .unwrap();
    assert!(history.light_block(1, &epochs).is_err());
    assert_eq!(
        history.light_block(2, &epochs).unwrap().descendants.len(),
        LIGHT_BLOCK_MAX_DESCENDANTS
    );
    let bytes = history.db.get(key(RECORD, 3)).unwrap().unwrap();
    let mut record: Record = borsh::from_slice(&bytes).unwrap();
    let mut disconnected = block(3, BlockId(B256::repeat_byte(99)));
    record.block = disconnected.encode().to_vec();
    history
        .db
        .put(key(RECORD, 3), borsh::to_vec(&record).unwrap())
        .unwrap();
    assert!(history.light_block(2, &epochs).is_err());
    disconnected.height = 4;
    record.block = disconnected.encode().to_vec();
    history
        .db
        .put(key(RECORD, 3), borsh::to_vec(&record).unwrap())
        .unwrap();
    assert!(history.light_block(3, &epochs).is_err());
    history
        .db
        .put(
            key(RECORD, 3),
            ((LIGHT_BLOCK_MAX_ARTIFACT_BYTES + 1) as u32).to_le_bytes(),
        )
        .unwrap();
    assert!(
        history
            .light_block(3, &epochs)
            .unwrap_err()
            .to_string()
            .contains("artifact limits")
    );
    history.db.put(key(RECORD, 3), [1, 0, 0, 0]).unwrap();
    assert!(
        history
            .light_block(3, &epochs)
            .unwrap_err()
            .to_string()
            .contains("truncated")
    );
}

#[tokio::test]
async fn pruned_roster_selection_survives_history_and_module_reopen() {
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_glue::dkg::ParticipantsProvider as _;
    use commonware_utils::ordered::Set;
    use std::{num::NonZeroU64, sync::RwLock};
    use vera_modules::{ModuleState, kv_store::InMemoryKvStore, vera::VeraModule};

    let genesis_key = ed25519::PrivateKey::from_seed(7).public_key();
    let selected = ed25519::PrivateKey::from_seed(8).public_key();
    let newer = ed25519::PrivateKey::from_seed(9).public_key();
    let genesis_players = Set::from_iter_dedup([genesis_key.clone()]);
    let (mut info, _) = crate::trusted_setup(7, [genesis_key]).unwrap();
    info.epoch = Epoch::new(2);
    info.next_players = Set::from_iter_dedup([selected.clone()]);
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let mut last = genesis.clone();
    let encoded_store;
    {
        let history = Arc::new(FinalizedHistory::open(directory.path(), &genesis).unwrap());
        for height in 1..=7 {
            let mut next = block(height, last.id());
            if height == 7 {
                next.payload = Some(Payload::EpochInfo(info.clone()));
            }
            history.append(&next, &[], 100).unwrap();
            last = next;
        }
        let mut modules = ModuleState::default();
        let selected_bytes: [u8; 32] = selected.encode().as_ref().try_into().unwrap();
        modules
            .vera
            .record_consensus_roster(3, &[selected_bytes])
            .unwrap();
        let newer_bytes: [u8; 32] = newer.encode().as_ref().try_into().unwrap();
        for epoch in 4..=100 {
            modules = modules.clone();
            modules
                .vera
                .record_consensus_roster(epoch, &[newer_bytes])
                .unwrap();
        }
        assert!(modules.vera.consensus_roster(3).is_none());
        encoded_store = modules.vera.store().serialize();
        let mut provider = crate::RegistryParticipants::new(
            Arc::new(RwLock::new(modules)),
            genesis_players.clone(),
            history,
            NonZeroU64::new(4).unwrap(),
        );
        assert_eq!(
            provider.participants(Epoch::new(3)).await,
            Set::from_iter_dedup([selected.clone()])
        );
    }
    let history = Arc::new(FinalizedHistory::open(directory.path(), &genesis).unwrap());
    let lookup: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
    history
        .recover(
            &genesis,
            &last,
            &BlockIndex::new(),
            &LightBlockIndex::new(std::num::NonZeroU64::new(4).unwrap()),
            &lookup,
        )
        .await
        .unwrap();
    let modules = ModuleState {
        vera: VeraModule::from_store(InMemoryKvStore::deserialize(&encoded_store).unwrap()),
        ..Default::default()
    };
    let mut restarted = crate::RegistryParticipants::new(
        Arc::new(RwLock::new(modules)),
        genesis_players,
        history.clone(),
        NonZeroU64::new(4).unwrap(),
    );
    assert_eq!(
        restarted.participants(Epoch::new(3)).await,
        Set::from_iter_dedup([selected])
    );
    assert_eq!(
        restarted.participants(Epoch::new(100)).await,
        Set::from_iter_dedup([newer])
    );
    assert!(
        history
            .consensus_roster(Epoch::new(4), NonZeroU64::new(4).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        history
            .consensus_roster(Epoch::new(3), NonZeroU64::new(3).unwrap())
            .is_err()
    );
}

#[cfg(not(feature = "regolith-history"))]
#[test]
fn regolith_directory_is_rejected_before_rocksdb_initialization() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("regolith")).unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    assert!(FinalizedHistory::open(directory.path(), &genesis).is_err());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
