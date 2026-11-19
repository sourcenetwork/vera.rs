//! The search for a shared block in a history pruned below a floor.

use alloy_primitives::B256;
use futures::executor::block_on;
use vera_domain::TermCut;

use super::{TermRefusal, UnreadBlock, answer, search};

const HEAD: u64 = 10;
/// The newest height at which both histories hold the same block.
const SHARED: u64 = 5;

/// A history of blocks up to `HEAD` that holds `fork`'s blocks above
/// `SHARED` and has removed those below `floor`.
fn history(fork: u8, floor: u64) -> impl Fn(u64) -> Result<Option<B256>, UnreadBlock> {
    move |height| {
        if height > 0 && height < floor {
            return Err(UnreadBlock {
                height,
                reason: crate::HistoryPruned { height, floor }.into(),
            });
        }
        let block = B256::with_last_byte(height as u8);
        Ok(if height <= SHARED {
            Some(block)
        } else if height <= HEAD {
            Some(B256::repeat_byte(fork) ^ block)
        } else {
            None
        })
    }
}

/// Search from this device's history, pruned below `floor`, with the
/// holder answering from its complete history.
fn locate(at: u64, floor: u64) -> Result<Option<TermCut>, TermRefusal> {
    let holder = history(2, 1);
    let ask = |heights: Vec<u64>| {
        let blocks = answer(&heights, &holder).ok();
        async move { blocks }
    };
    block_on(search(at, HEAD, floor, history(1, floor), ask))
}

#[test]
fn a_shared_block_above_the_floor_is_found() {
    for floor in 1..=SHARED {
        assert_eq!(
            locate(HEAD, floor).unwrap(),
            Some(TermCut {
                height: SHARED,
                block: B256::with_last_byte(SHARED as u8),
            }),
            "floor {floor}"
        );
    }
}

#[test]
fn a_fork_below_the_floor_is_refused_and_not_reported() {
    for floor in SHARED + 1..=HEAD {
        let refusal = locate(HEAD, floor).unwrap_err();
        assert!(
            matches!(refusal, TermRefusal::Pruned { floor: refused } if refused == floor),
            "floor {floor}: {refusal}"
        );
    }
}

#[test]
fn a_search_from_below_the_floor_is_refused() {
    let refusal = locate(SHARED - 1, SHARED).unwrap_err();
    assert!(
        matches!(refusal, TermRefusal::Pruned { floor: SHARED }),
        "{refusal}"
    );
}

#[test]
fn a_pruned_block_that_fails_to_read_is_refused_as_pruned() {
    let refusal: TermRefusal = UnreadBlock {
        height: 3,
        reason: crate::HistoryPruned {
            height: 3,
            floor: 4,
        }
        .into(),
    }
    .into();
    assert!(
        matches!(refusal, TermRefusal::Pruned { floor: 4 }),
        "{refusal}"
    );
}
