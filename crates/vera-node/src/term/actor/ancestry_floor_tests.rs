//! The search for a shared block between histories pruned below floors.

use alloy_primitives::B256;
use futures::executor::block_on;
use vera_domain::TermCut;

use super::{TermRefusal, UnreadBlock, answer, search};

const HEAD: u64 = 20;
/// The newest height at which both histories hold the same block.
const SHARED: u64 = 10;

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

/// Search from this device's history, pruned below `own`, with the holder
/// answering from its history pruned below `holders`.
fn locate(at: u64, own: u64, holders: u64) -> Result<Option<TermCut>, TermRefusal> {
    let holder = history(2, holders);
    let ask = |heights: Vec<u64>| {
        let blocks = answer(&heights, holders, &holder).ok();
        async move { blocks }
    };
    block_on(search(at, HEAD, own, history(1, own), ask))
}

fn shared() -> Option<TermCut> {
    Some(TermCut {
        height: SHARED,
        block: B256::with_last_byte(SHARED as u8),
    })
}

fn refused_at(result: Result<Option<TermCut>, TermRefusal>, expected: u64) {
    let refusal = result.unwrap_err();
    assert!(
        matches!(refusal, TermRefusal::Pruned { floor } if floor == expected),
        "{refusal}"
    );
}

#[test]
fn the_holder_leaves_out_heights_below_its_floor_and_names_it() {
    let (floor, blocks) = answer(&[2, 6, 12], 6, history(2, 6)).unwrap();
    assert_eq!(floor, 6);
    assert_eq!(
        blocks.iter().map(|(height, _)| *height).collect::<Vec<_>>(),
        [6, 12]
    );
}

#[test]
fn a_shared_block_above_both_floors_is_found() {
    for (own, holders) in [
        (1, 1),
        (4, 1),
        (1, 4),
        (4, 8),
        (8, 4),
        (SHARED, 1),
        (1, SHARED),
    ] {
        assert_eq!(
            locate(HEAD, own, holders).unwrap(),
            shared(),
            "{own} {holders}"
        );
    }
}

#[test]
fn a_fork_below_this_devices_floor_is_refused_and_not_reported() {
    for own in SHARED + 1..=HEAD {
        refused_at(locate(HEAD, own, 1), own);
    }
}

#[test]
fn a_fork_below_the_holders_floor_is_refused_and_not_reported() {
    for holders in SHARED + 1..=HEAD {
        refused_at(locate(HEAD, 1, holders), holders);
        refused_at(locate(HEAD, 4, holders), holders);
    }
}

#[test]
fn a_search_from_below_either_floor_is_refused() {
    refused_at(locate(SHARED - 1, SHARED, 1), SHARED);
    refused_at(locate(SHARED - 1, 1, SHARED), SHARED);
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
