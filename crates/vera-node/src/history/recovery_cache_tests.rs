use super::*;
use std::{num::NonZeroU64, time::Instant};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::NativeTx;

struct Fixture {
    history: FinalizedHistory,
    genesis: Block,
    executions: Vec<(Block, Vec<ExecutionReceipt>)>,
    _directory: tempfile::TempDir,
}

fn fixture(revisions: usize, submissions_per_revision: usize) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
    let mut seed = [0; 32];
    seed[0] = 1;
    let signer = BlsSigner::from_secret_bytes(&seed, 1, 0).unwrap();
    let mut parent = genesis.id();
    let mut executions = Vec::with_capacity(revisions);
    for height in 1..=revisions {
        let mut next = block(height as u64, parent);
        let submissions = if submissions_per_revision == 0 {
            usize::from(height == 1 || height == revisions)
        } else {
            submissions_per_revision
        };
        let mut receipts = Vec::with_capacity(submissions);
        for position in 0..submissions {
            let wire = signer
                .sign_native_tx(ACP_ADDRESS, vec![0xab; 128].into())
                .unwrap();
            let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
            next.txs.push(Tx::new(wire.into()));
            receipts.push(ExecutionReceipt::new(
                id,
                false,
                1,
                position as u64 + 1,
                vec![],
                None,
            ));
        }
        next.native_targets = Some([vera_domain::DbTarget::default(); 4]);
        next.receipt_commitment = Some(vera_executor::receipt_commitment(100, &receipts));
        history
            .append_finalized(&next, &receipts, 100, Some(&artifacts(height as u64)))
            .unwrap();
        parent = next.id();
        executions.push((next, receipts));
    }
    Fixture {
        history,
        genesis,
        executions,
        _directory: directory,
    }
}

fn light() -> LightBlockIndex {
    LightBlockIndex::new(NonZeroU64::new(20).unwrap())
}

fn no_lookup() -> FinalizationLookup {
    Arc::new(|_| panic!("persisted certificates must not invoke network lookup"))
}

#[tokio::test]
async fn recent_cache_recovery_matches_full_replay_and_preserves_archived_submissions() {
    let fixture = fixture(MAX_CACHED_REVISIONS + 32, 0);
    let index = BlockIndex::new();
    let expected = BlockIndex::new();
    for (block, receipts) in &fixture.executions {
        index_finalized_block(&expected, block, 100, receipts, receipts.len() as u64);
    }
    fixture
        .history
        .recover(
            &fixture.genesis,
            &fixture.executions.last().unwrap().0,
            &index,
            &light(),
            &no_lookup(),
        )
        .await
        .unwrap();
    assert_eq!(index.stats(), expected.stats());
    let header = |index: &BlockIndex, height| {
        index.get_block_by_number(height).map(|block| {
            (
                block.hash,
                block.number,
                block.parent_hash,
                block.state_root,
                block.module_state_root,
                block.timestamp,
                block.gas_limit,
                block.gas_used,
                block.base_fee_per_gas,
                block.prevrandao,
                block.transaction_hashes,
            )
        })
    };
    for (block, _) in &fixture.executions {
        assert_eq!(
            header(&index, block.height),
            header(&expected, block.height)
        );
    }
    let (oldest, receipts) = &fixture.executions[0];
    assert!(index.get_block_by_number(oldest.height).is_none());
    assert!(index.get_receipt(&receipts[0].tx_hash).is_none());
    let archived = fixture
        .history
        .execution_by_submission(receipts[0].tx_hash)
        .unwrap()
        .unwrap();
    assert_eq!(archived.block, *oldest);
    assert_eq!(archived.receipts[0].tx_hash, receipts[0].tx_hash);
}

#[tokio::test]
async fn recent_cache_recovery_still_rejects_damage_in_uncached_history() {
    let fixture = fixture(MAX_CACHED_REVISIONS + 32, 0);
    let original = fixture.history.db.get(key(RECORD, 1)).unwrap().unwrap();
    for damage in ["missing", "ancestry", "receipt"] {
        let mut record: Record = borsh::from_slice(&original).unwrap();
        match damage {
            "missing" => fixture.history.db.delete(key(RECORD, 1)).unwrap(),
            "ancestry" => {
                let mut block = record.decode().unwrap().0;
                block.parent = BlockId(B256::repeat_byte(99));
                record.block = block.encode().to_vec();
                fixture
                    .history
                    .db
                    .put(key(RECORD, 1), borsh::to_vec(&record).unwrap())
                    .unwrap();
            }
            "receipt" => {
                record.receipts[0].success = true;
                fixture
                    .history
                    .db
                    .put(key(RECORD, 1), borsh::to_vec(&record).unwrap())
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let index = BlockIndex::new();
        let error = fixture
            .history
            .recover(
                &fixture.genesis,
                &fixture.executions.last().unwrap().0,
                &index,
                &light(),
                &no_lookup(),
            )
            .await
            .unwrap_err();
        let expected = match damage {
            "missing" => "missing finalized execution history",
            "ancestry" => "finalized history ancestry mismatch",
            "receipt" => "execution receipt commitment mismatch",
            _ => unreachable!(),
        };
        assert!(error.to_string().contains(expected), "{damage}: {error}");
        assert!(index.is_empty());
        fixture.history.db.put(key(RECORD, 1), &original).unwrap();
    }
}

#[tokio::test]
#[ignore = "history component timing is run by focused release qualification"]
async fn retained_native_history_recovery_timing() {
    let fixture = fixture(MAX_CACHED_REVISIONS * 5, 4);
    let index = BlockIndex::new();
    let started = Instant::now();
    fixture
        .history
        .recover(
            &fixture.genesis,
            &fixture.executions.last().unwrap().0,
            &index,
            &light(),
            &no_lookup(),
        )
        .await
        .unwrap();
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(index.block_count(), MAX_CACHED_REVISIONS);
    let first = fixture
        .history
        .execution_by_submission(fixture.executions[0].1[0].tx_hash)
        .unwrap()
        .unwrap();
    assert_eq!(first.block, fixture.executions[0].0);
    println!(
        "history_recovery_component={}",
        serde_json::json!({"revisions": fixture.executions.len(),
            "native_submissions": fixture.executions.len() * 4,
            "cached_revisions": index.block_count(), "elapsed_ms": elapsed_ms,
            "scope": "Persisted history validation and index reconstruction; synthetic signed reverted native records, not consensus or ACP throughput"})
    );
}
