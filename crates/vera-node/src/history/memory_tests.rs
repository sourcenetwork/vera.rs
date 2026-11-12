use super::*;
use commonware_codec::EncodeSize as _;
use regolith_store::HistoryDb;
use vera_executor::ExecutionReceipt;

const TINY: HistoryMemory = HistoryMemory {
    block_cache_bytes: 0,
    write_buffer_bytes: 4096,
};

/// Bytes that do not compress, so the store handles the record at its full size.
fn noise(length: usize, mut state: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length + 8);
    while bytes.len() < length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(length);
    bytes
}

/// A block at the transaction byte limit: the largest record execution appends.
fn largest(parent: &Block) -> (Block, Vec<ExecutionReceipt>) {
    let mut next = block(parent.height + 1, parent.id());
    let rest = vera_domain::MAX_BLOCK_TX_BYTES - vera_domain::MAX_TX_BYTES - 64;
    next.txs
        .push(Tx::new(noise(vera_domain::MAX_TX_BYTES, 1).into()));
    next.txs.push(Tx::new(noise(rest, 2).into()));
    assert!(next.fits_wire_limits());
    assert!(next.txs.encode_size() > vera_domain::MAX_BLOCK_TX_BYTES - 128);
    let receipts = next
        .txs
        .iter()
        .map(|tx| ExecutionReceipt::new(tx.id().0, true, 1, 1, vec![], None))
        .collect();
    (next, receipts)
}

fn stored_block(history: &FinalizedHistory, height: u64) -> Vec<u8> {
    let bytes = history.db.get(key(RECORD, height)).unwrap().unwrap();
    borsh::from_slice::<Record>(&bytes).unwrap().block
}

#[test]
fn daemon_store_keeps_regolith_sizes_and_embedded_budgets_change_only_those() {
    let regolith = regolith::Options::default();
    let daemon = HistoryDb::options(None, None);
    assert_eq!(daemon.get_block_cache_size(), 512 << 20);
    assert_eq!(daemon.get_write_buffer_size(), 64 << 20);
    assert_eq!(
        daemon.get_block_cache_size(),
        regolith.get_block_cache_size()
    );
    assert_eq!(
        daemon.get_write_buffer_size(),
        regolith.get_write_buffer_size()
    );

    let embedded = HistoryDb::options(Some(HistoryMemory::EMBEDDED), None);
    assert_eq!(embedded.get_block_cache_size(), 8 << 20);
    assert_eq!(embedded.get_write_buffer_size(), 4 << 20);

    for options in [&daemon, &embedded] {
        assert_eq!(options.get_max_background_compactions(), BACKGROUND_THREADS);
        assert_eq!(options.get_max_value_size(), regolith.get_max_value_size());
        assert_eq!(options.get_max_key_size(), regolith.get_max_key_size());
        assert_eq!(options.get_arena_profile(), regolith.get_arena_profile());
        assert_eq!(options.get_block_size(), regolith.get_block_size());
        assert_eq!(
            options.get_block_cache_num_shard_bits(),
            regolith.get_block_cache_num_shard_bits()
        );
        assert_eq!(
            options.get_max_write_buffer_number(),
            regolith.get_max_write_buffer_number()
        );
        assert_eq!(
            options.get_target_file_size(),
            regolith.get_target_file_size()
        );
        assert_eq!(
            options.get_level_base_bytes(),
            regolith.get_level_base_bytes()
        );
        assert_eq!(options.get_durability(), regolith.get_durability());
        assert!(!options.get_log_writeback());
    }
}

#[test]
fn rejected_budgets_are_the_ones_regolith_rejects() {
    for (block_cache_bytes, write_buffer_bytes) in [(0, 0), (8 << 20, 0), (0, 1), (0, 4096)] {
        let memory = HistoryMemory {
            block_cache_bytes,
            write_buffer_bytes,
        };
        assert_eq!(
            memory.rejection().is_some(),
            HistoryDb::options(Some(memory), None).validate().is_err(),
            "{memory:?}"
        );
    }
    assert!(HistoryMemory::EMBEDDED.rejection().is_none());
}

#[test]
fn largest_record_round_trips_and_reopens_within_small_budgets() {
    for memory in [HistoryMemory::EMBEDDED, TINY] {
        let directory = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let (large, receipts) = largest(&genesis);
        assert!(large.encode().len() > memory.write_buffer_bytes);
        let mut head = large.clone();
        {
            let history =
                FinalizedHistory::open_with(directory.path(), &genesis, Some(memory)).unwrap();
            history.append(&large, &receipts, 100).unwrap();
            assert_eq!(stored_block(&history, 1), large.encode().to_vec());
            // Under the tiny budget these rotate the write buffer repeatedly.
            for _ in 0..200 {
                head = block(head.height + 1, head.id());
                history.append(&head, &[], 100).unwrap();
            }
        }
        let history =
            FinalizedHistory::open_with(directory.path(), &genesis, Some(memory)).unwrap();
        assert_eq!(history.head_height(), head.height);
        assert_eq!(stored_block(&history, 1), large.encode().to_vec());
        assert_eq!(stored_block(&history, head.height), head.encode().to_vec());
        let next = block(head.height + 1, head.id());
        history.append(&next, &[], 100).unwrap();
    }
}

#[test]
fn a_store_reopens_under_other_budgets() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let mut head = genesis.clone();
    for memory in [None, Some(HistoryMemory::EMBEDDED), Some(TINY), None] {
        let history = FinalizedHistory::open_with(directory.path(), &genesis, memory).unwrap();
        assert_eq!(history.head_height(), head.height);
        for _ in 0..20 {
            head = block(head.height + 1, head.id());
            history.append(&head, &[], 100).unwrap();
        }
        assert_eq!(
            stored_block(&history, 1).len(),
            block(1, genesis.id()).encode().len()
        );
    }
}
