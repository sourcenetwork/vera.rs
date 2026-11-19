use alloy_primitives::B256;
use futures::executor::block_on;
use vera_domain::TermCut;

use super::{TermRefusal, UnreadBlock, answer, search};

const HEAD: u64 = 10;
/// The newest height at which both histories hold the same block.
const SHARED: u64 = 5;

/// A history of blocks up to `HEAD` that holds `fork`'s blocks above
/// `SHARED`, and fails to read the block at `unreadable`.
fn history(fork: u8, unreadable: Option<u64>) -> impl Fn(u64) -> Result<Option<B256>, UnreadBlock> {
    move |height| {
        if Some(height) == unreadable {
            return Err(UnreadBlock {
                height,
                reason: anyhow::anyhow!("record does not decode"),
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

/// Search from this device's history with the holder answering from its own.
fn locate(
    own: impl Fn(u64) -> Result<Option<B256>, UnreadBlock>,
    holder: impl Fn(u64) -> Result<Option<B256>, UnreadBlock>,
) -> Result<Option<TermCut>, TermRefusal> {
    let ask = |heights: Vec<u64>| {
        let blocks = answer(&heights, &holder).ok();
        async move { blocks }
    };
    block_on(search(HEAD, HEAD, 1, own, ask))
}

#[test]
fn the_holder_answers_with_the_blocks_it_holds() {
    let blocks = answer(&[4, 7, HEAD + 1], history(1, None)).unwrap();
    assert_eq!(
        blocks.iter().map(|(height, _)| *height).collect::<Vec<_>>(),
        [4, 7]
    );
}

#[test]
fn a_holder_that_fails_to_read_a_requested_block_does_not_answer() {
    let unanswered = answer(&[2, 4, 6], history(1, Some(4))).unwrap_err();
    assert_eq!(unanswered.height, 4);
}

#[test]
fn the_search_finds_the_newest_shared_block() {
    let common = locate(history(1, None), history(2, None)).unwrap();
    assert_eq!(
        common,
        Some(TermCut {
            height: SHARED,
            block: B256::with_last_byte(SHARED as u8),
        })
    );
}

#[test]
fn a_block_the_holder_fails_to_read_records_no_shared_block() {
    for unreadable in 1..HEAD {
        let common = locate(history(1, None), history(2, Some(unreadable))).unwrap();
        assert_eq!(common, None, "holder failed to read block {unreadable}");
    }
}

#[test]
fn a_block_this_device_fails_to_read_refuses_without_a_shared_block() {
    // The search reads this device's blocks up to the first that differs.
    for unreadable in 1..=SHARED + 1 {
        let refusal = locate(history(1, Some(unreadable)), history(2, None)).unwrap_err();
        assert!(
            matches!(&refusal, TermRefusal::History(reason) if reason.contains(&format!("block {unreadable} "))),
            "{refusal}"
        );
    }
}
