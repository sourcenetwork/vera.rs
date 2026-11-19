//! Log ranges that reach below the history a node retains.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use alloy_primitives::B256;
use jsonrpsee::types::ErrorObjectOwned;
use vera_indexer::{BlockIndex, IndexQuery, IndexedBlock, LogFilter};

use super::*;
use crate::error::codes;

const FLOOR: u64 = 6;
const HEAD: u64 = 10;

fn revision(number: u64) -> IndexedBlock {
    IndexedBlock {
        hash: B256::with_last_byte(number as u8),
        number,
        parent_hash: B256::with_last_byte(number.saturating_sub(1) as u8),
        state_root: B256::ZERO,
        module_state_root: B256::ZERO,
        timestamp: number,
        gas_limit: 30_000_000,
        gas_used: 0,
        base_fee_per_gas: None,
        prevrandao: B256::ZERO,
        transaction_hashes: vec![],
    }
}

#[tokio::test]
async fn a_log_range_reaching_below_the_retained_floor_fails_instead_of_skipping() {
    let resident = Arc::new(BlockIndex::new());
    resident.insert_block(revision(HEAD), vec![], vec![]);
    let retained = Arc::new(BlockIndex::new());
    for number in FLOOR..HEAD {
        retained.insert_block(revision(number), vec![], vec![]);
    }
    let lookups = Arc::new(AtomicUsize::new(0));
    let archive = ArchiveReader::new(NodeState::new(1, 0, 1), {
        let lookups = lookups.clone();
        Arc::new(move |query, _| {
            lookups.fetch_add(1, Ordering::Relaxed);
            match query {
                IndexQuery::Revision(height) if height < FLOOR => Err(RpcError::HistoryPruned {
                    height,
                    floor: FLOOR,
                }),
                IndexQuery::Revision(_) => Ok(Some(retained.clone())),
                _ => Ok(None),
            }
        })
    });

    let within = LogFilter::new().from_block(FLOOR).to_block(HEAD);
    assert!(
        archive
            .logs(resident.clone(), within)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(lookups.load(Ordering::Relaxed), (HEAD - FLOOR) as usize);

    let below = LogFilter::new().from_block(2).to_block(HEAD);
    let error = archive.logs(resident, below).await.unwrap_err();
    assert!(matches!(
        error,
        RpcError::HistoryPruned {
            height: 2,
            floor: FLOOR
        }
    ));
    // The scan stops at the first pruned revision.
    assert_eq!(lookups.load(Ordering::Relaxed), (HEAD - FLOOR) as usize + 1);
    let error = ErrorObjectOwned::from(error);
    assert_eq!(error.code(), codes::HISTORY_PRUNED);
    assert!(error.data().unwrap().get().contains(r#""retryable":false"#));
}
