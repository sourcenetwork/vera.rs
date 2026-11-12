use super::*;
use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
use commonware_cryptography::{Signer as _, ed25519};
use commonware_parallel::Sequential;
use commonware_utils::non_empty;
use std::sync::Arc;
use vera_app::ConsensusScheme;
use vera_domain::{DbTarget, Tx};

pub(in crate::history) fn certify(block: &Block, seed: u64) -> (LightBlock, ConsensusPublicKey) {
    let public = ed25519::PrivateKey::from_seed(seed).public_key();
    let (info, shares) = crate::trusted_setup(seed, [public.clone()]).unwrap();
    let material = EpochMaterial::new(info.output.players().clone(), info.output.public().clone());
    let signer = ConsensusScheme::signer(
        crate::NAMESPACE,
        material.participants.clone(),
        material.sharing.clone(),
        shares.get_value(&public).unwrap().clone(),
    )
    .unwrap();
    let vote = Finalize::sign(
        &signer,
        Proposal::new(block.context.round, block.context.parent.0, block.digest()),
    )
    .unwrap();
    let finalization =
        Finalization::from_finalizes(&signer, non_empty![&vote], &Sequential).unwrap();
    (
        LightBlock::from_parts(block, &finalization.encode(), &material.encode()),
        *material.sharing.public(),
    )
}

pub(in crate::history) fn revision(height: u64, parent: BlockId) -> (Block, Vec<ExecutionReceipt>) {
    let mut block = super::super::tests::block(height, parent);
    let receipts = if height == 0 {
        vec![]
    } else {
        block
            .txs
            .push(Tx::new(vec![height as u8; HISTORY_CHUNK_BYTES].into()));
        vec![ExecutionReceipt::new(
            block.txs[0].id().0,
            true,
            10,
            10,
            vec![Log::new_unchecked(
                Address::ZERO,
                vec![B256::ZERO],
                vec![7; HISTORY_CHUNK_BYTES + 1].into(),
            )],
            None,
        )]
    };
    block.native_targets = Some([DbTarget::default(); 4]);
    block.receipt_commitment = Some(vera_executor::receipt_commitment(100, &receipts));
    (block, receipts)
}

fn collect(history: &FinalizedHistory, height: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let chunk = history
            .record_chunk(height, bytes.len() as u64, HISTORY_CHUNK_BYTES)
            .unwrap();
        assert_eq!(chunk.offset, bytes.len() as u64);
        assert!(chunk.bytes.len() <= HISTORY_CHUNK_BYTES);
        bytes.extend(chunk.bytes);
        if bytes.len() as u64 == chunk.total {
            return bytes;
        }
    }
}

#[tokio::test]
async fn authenticated_reverse_import_resumes_and_requires_matching_state_recovery() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let (genesis, _) = revision(0, BlockId(B256::ZERO));
    let (first, first_receipts) = revision(1, genesis.id());
    let (second, second_receipts) = revision(2, first.id());
    let (third, third_receipts) = revision(3, second.id());
    let source = FinalizedHistory::open(source_dir.path(), &genesis).unwrap();
    for (block, receipts) in [
        (&first, &first_receipts),
        (&second, &second_receipts),
        (&third, &third_receipts),
    ] {
        source.append(block, receipts, 100).unwrap();
    }
    let third_bytes = collect(&source, 3);
    let second_bytes = collect(&source, 2);
    assert!(third_bytes.len() > HISTORY_CHUNK_BYTES);
    assert!(source.record_chunk(0, 0, 1).is_err());
    assert!(source.record_chunk(4, 0, 1).is_err());
    assert!(source.record_chunk(1, u64::MAX, 1).is_err());
    assert!(source.record_chunk(1, 0, 0).is_err());
    assert!(source.record_chunk(1, 0, HISTORY_CHUNK_BYTES + 1).is_err());
    let limits = HistoryLimits {
        record_bytes: third_bytes.len(),
        logs: 1,
    };
    let (light, trusted) = certify(&third, 7);
    let (_, wrong_key) = certify(&third, 8);
    {
        let target = FinalizedHistory::open(target_dir.path(), &genesis).unwrap();
        target.append(&first, &first_receipts, 100).unwrap();
        assert!(target.begin_import(&light, &wrong_key).is_err());
        assert!(target.db.get(IMPORT).unwrap().is_none());
        target.begin_import(&light, &trusted).unwrap();
        assert_eq!(target.db.get(FORMAT).unwrap().unwrap(), [3]);
        assert!(target.append(&second, &second_receipts, 100).is_err());
        let mut changed: Record = borsh::from_slice(&third_bytes).unwrap();
        changed.gas_limit += 1;
        assert!(
            target
                .import_record(&borsh::to_vec(&changed).unwrap(), limits, &light)
                .is_err()
        );
        assert_eq!(target.import_next().unwrap(), Some((3, third.id())));
        assert!(
            target
                .import_record(
                    &third_bytes,
                    HistoryLimits {
                        record_bytes: third_bytes.len() - 1,
                        ..limits
                    },
                    &light,
                )
                .is_err()
        );
        assert!(
            target
                .import_record(&third_bytes, HistoryLimits { logs: 0, ..limits }, &light)
                .is_err()
        );
        for end in [0, 4, third_bytes.len() / 2, third_bytes.len() - 1] {
            assert!(
                target
                    .import_record(&third_bytes[..end], limits, &light)
                    .is_err()
            );
        }
        target.import_record(&third_bytes, limits, &light).unwrap();
        assert_eq!(*target.head.lock(), (1, first.id()));
        assert!(target.record_chunk(3, 0, 1).is_err());
    }
    let target = FinalizedHistory::open(target_dir.path(), &genesis).unwrap();
    assert_eq!(target.import_anchor().unwrap(), Some(third.clone()));
    target.begin_import(&light, &trusted).unwrap();
    assert_eq!(target.import_next().unwrap(), Some((2, second.id())));
    assert!(
        target
            .begin_import(&certify(&second, 7).0, &trusted)
            .is_err()
    );
    assert!(target.import_record(&third_bytes, limits, &light).is_err());
    let index = BlockIndex::new();
    let epochs = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
    let lookup: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
    assert!(
        target
            .recover(&genesis, &third, &index, &epochs, &lookup)
            .await
            .is_err()
    );
    target
        .import_record(&second_bytes, limits, &certify(&second, 7).0)
        .unwrap();
    assert_eq!(target.import_next().unwrap(), None);
    assert!(target.record_chunk(3, 0, 1).is_err());
    assert!(target.light_block(3, &epochs).is_err());
    assert!(
        target
            .recover(&genesis, &first, &index, &epochs, &lookup)
            .await
            .is_err()
    );
    assert_eq!(index.head_block_number(), 0);
    drop(target);
    let target = FinalizedHistory::open(target_dir.path(), &genesis).unwrap();
    target
        .recover(&genesis, &third, &index, &epochs, &lookup)
        .await
        .unwrap();
    assert_eq!(index.head_block_number(), 3);
    assert_eq!(collect(&target, 3), third_bytes);
    assert_eq!(collect(&target, 2), second_bytes);
    assert!(target.db.get(IMPORT).unwrap().is_none());
    assert_eq!(target.import_anchor().unwrap(), None);
    let (fourth, receipts) = revision(4, third.id());
    target.append(&fourth, &receipts, 100).unwrap();
}

#[test]
fn record_decoder_rejects_forged_counts_and_unconnected_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    let (genesis, _) = revision(0, BlockId(B256::ZERO));
    let (wrong, receipts) = revision(1, BlockId(B256::repeat_byte(9)));
    let (light, trusted) = certify(&wrong, 7);
    let source = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    source.begin_import(&light, &trusted).unwrap();
    let record = Record {
        block: wrong.encode().to_vec(),
        gas_limit: 100,
        receipts: receipts
            .iter()
            .map(|r| StoredReceipt {
                hash: r.tx_hash.0,
                gas_used: r.gas_used,
                contract: None,
                success: r.success(),
                cumulative_gas_used: r.cumulative_gas_used(),
                logs: r.logs().iter().map(alloy_rlp::encode).collect(),
            })
            .collect(),
    };
    let bytes = borsh::to_vec(&record).unwrap();
    let limits = HistoryLimits {
        record_bytes: bytes.len() + 1,
        logs: 1,
    };
    assert!(
        source
            .import_record(&bytes, limits, &light)
            .unwrap_err()
            .to_string()
            .contains("committed prefix")
    );
    assert!(source.db.get(key(RECORD, 1)).unwrap().is_none());
    let mut count = bytes.clone();
    let offset = 4 + record.block.len() + 8;
    count[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_record(&count, limits).is_err());
    let mut logs = bytes.clone();
    let log_count = offset + 4 + 32 + 8 + 1 + 1 + 8;
    logs[log_count..log_count + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_record(&logs, limits).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_record(&trailing, limits).is_err());
}

#[tokio::test]
async fn imported_descendant_finality_survives_restart_without_advancing_execution() {
    use commonware_consensus::types::{Epoch, Round, View};
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let (genesis, _) = revision(0, BlockId(B256::ZERO));
    let (first, first_receipts) = revision(1, genesis.id());
    let (second, second_receipts) = revision(2, first.id());
    let (mut third, third_receipts) = revision(3, second.id());
    third.context.round = Round::new(Epoch::new(1), View::new(1));
    let source = FinalizedHistory::open(source_dir.path(), &genesis).unwrap();
    for (block, receipts) in [(&first, &first_receipts), (&second, &second_receipts)] {
        source.append(block, receipts, 100).unwrap();
    }
    let (direct, trusted) = certify(&third, 7);
    let mut anchor = LightBlock::from_parts(
        &second,
        &hex::decode(direct.finalization.trim_start_matches("0x")).unwrap(),
        &hex::decode(direct.epoch_material.trim_start_matches("0x")).unwrap(),
    );
    anchor.descendants.push(direct.block.clone());
    let mut earlier = LightBlock::from_parts(
        &first,
        &hex::decode(direct.finalization.trim_start_matches("0x")).unwrap(),
        &hex::decode(direct.epoch_material.trim_start_matches("0x")).unwrap(),
    );
    earlier.descendants = vec![anchor.block.clone(), direct.block.clone()];
    let bytes = collect(&source, 2);
    let limits = HistoryLimits {
        record_bytes: bytes.len(),
        logs: 1,
    };
    {
        let target = FinalizedHistory::open(target_dir.path(), &genesis).unwrap();
        target.begin_import(&anchor, &trusted).unwrap();
        for invalid in [certify(&second, 8).0, direct.clone(), {
            let mut changed = anchor.clone();
            changed.finalization = "00".into();
            changed
        }] {
            assert!(target.import_record(&bytes, limits, &invalid).is_err());
            assert_eq!(target.import_next().unwrap(), Some((2, second.id())));
            assert!(target.db.get(key(RECORD, 2)).unwrap().is_none());
            assert!(target.db.get(key(IMPORTED_FINALITY, 3)).unwrap().is_none());
            assert!(target.db.get(key(PROOF_BLOCK, 3)).unwrap().is_none());
        }
        target.import_record(&bytes, limits, &anchor).unwrap();
    }
    let lookup: FinalizationLookup = Arc::new(|_| panic!("import must retain finality evidence"));
    let epochs = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
    {
        let target = FinalizedHistory::open(target_dir.path(), &genesis).unwrap();
        assert_eq!(target.import_next().unwrap(), Some((1, first.id())));
        target
            .import_record(&collect(&source, 1), limits, &earlier)
            .unwrap();
        target
            .recover(&genesis, &second, &BlockIndex::new(), &epochs, &lookup)
            .await
            .unwrap();
    }
    let target = FinalizedHistory::open(target_dir.path(), &genesis).unwrap();
    let index = BlockIndex::new();
    target
        .recover(&genesis, &second, &index, &epochs, &lookup)
        .await
        .unwrap();
    assert_eq!(index.head_block_number(), 2);
    assert!(index.get_block_by_number(3).is_none());
    assert!(target.record_chunk(3, 0, 1).is_err());
    assert!(target.light_block(3, &epochs).is_err());
    for (height, expected) in [(1, &first), (2, &second)] {
        let proof = target.light_block(height, &epochs).unwrap();
        assert_eq!(verify_finalized_block(&proof, &trusted).unwrap(), *expected);
    }
    assert!(
        epochs.get_epoch_material(0).is_none(),
        "proof material must not establish membership"
    );
    target
        .recover(&genesis, &first, &BlockIndex::new(), &epochs, &lookup)
        .await
        .unwrap();
    assert_eq!(
        verify_finalized_block(&target.light_block(1, &epochs).unwrap(), &trusted).unwrap(),
        first
    );
    assert!(target.light_block(2, &epochs).is_err());
    target.append(&second, &second_receipts, 100).unwrap();
    let mut conflicting = third.clone();
    conflicting.timestamp += 1;
    assert!(target.append(&conflicting, &third_receipts, 100).is_err());
    target.append(&third, &third_receipts, 100).unwrap();
    assert!(target.db.get(key(PROOF_BLOCK, 3)).unwrap().is_none());
    assert_eq!(
        verify_finalized_block(&target.light_block(3, &epochs).unwrap(), &trusted).unwrap(),
        third
    );
}

#[test]
fn previous_format_imports_are_rejected_without_modification() {
    let dir = tempfile::tempdir().unwrap();
    let (genesis, _) = revision(0, BlockId(B256::ZERO));
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        history.db.put(FORMAT, [2]).unwrap();
        history.db.put(IMPORT, b"old cursor").unwrap();
    }
    assert!(
        FinalizedHistory::open(dir.path(), &genesis)
            .unwrap_err()
            .to_string()
            .contains("previous binary")
    );
    {
        let db = DB::open_default(dir.path(), None).unwrap();
        assert_eq!(db.get(IMPORT).unwrap().unwrap(), b"old cursor");
        db.delete(IMPORT).unwrap();
    }
    FinalizedHistory::open(dir.path(), &genesis).unwrap();
}

#[tokio::test]
async fn resumed_snapshot_can_advance_an_unpublished_history_selection() {
    let (genesis, _) = revision(0, BlockId(B256::ZERO));
    let (first, first_receipts) = revision(1, genesis.id());
    let (second, second_receipts) = revision(2, first.id());
    let (third, third_receipts) = revision(3, second.id());
    let source_dir = tempfile::tempdir().unwrap();
    let source = FinalizedHistory::open(source_dir.path(), &genesis).unwrap();
    for (block, receipts) in [
        (&first, &first_receipts),
        (&second, &second_receipts),
        (&third, &third_receipts),
    ] {
        source.append(block, receipts, 100).unwrap();
    }
    let proofs = [&first, &second, &third].map(|block| certify(block, 7).0);
    let (_, trusted) = certify(&second, 7);
    let limits = HistoryLimits {
        record_bytes: collect(&source, 3).len(),
        logs: 1,
    };
    for complete in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        {
            let target = FinalizedHistory::open(directory.path(), &genesis).unwrap();
            target.begin_import(&proofs[1], &trusted).unwrap();
            target
                .import_record(&collect(&source, 2), limits, &proofs[1])
                .unwrap();
            if complete {
                target
                    .import_record(&collect(&source, 1), limits, &proofs[0])
                    .unwrap();
            }
            target.begin_import(&proofs[2], &trusted).unwrap();
            assert_eq!(target.import_anchor().unwrap(), Some(third.clone()));
            assert!(target.record_chunk(1, 0, 1).is_err());
        }
        let target = FinalizedHistory::open(directory.path(), &genesis).unwrap();
        for height in [3, 2, 1] {
            assert_eq!(target.import_next().unwrap().unwrap().0, height);
            target
                .import_record(
                    &collect(&source, height),
                    limits,
                    &proofs[height as usize - 1],
                )
                .unwrap();
        }
        let index = BlockIndex::new();
        let lookup: FinalizationLookup =
            Arc::new(|_| panic!("imported certificates must be retained"));
        target
            .recover(
                &genesis,
                &third,
                &index,
                &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                &lookup,
            )
            .await
            .unwrap();
        assert_eq!(index.head_block_number(), 3);
    }
}
