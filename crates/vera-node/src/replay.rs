//! Holding a start until the node has applied the finalized blocks it stores.
//!
//! Marshal's processed height is recorded behind the blocks it archives, so
//! a restarted node delivers its newest archived blocks again after its state
//! has opened. A start that returned before them would report a height below
//! blocks this device already finalized and served.

use std::time::Duration;

use commonware_consensus::{
    marshal::{
        Identifier,
        core::{Mailbox, Variant},
    },
    simplex::scheme::Scheme,
};
use vera_indexer::BlockIndex;

use crate::term::{Archived, archived};

const POLL: Duration = Duration::from_millis(20);

/// Longest a start waits for its stored blocks; the node goes on applying them afterwards.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);

/// The newest finalized block marshal stores together with its certificate.
///
/// A certificate stored without its block is never delivered, so the block
/// below it is the newest one the node replays.
pub(crate) async fn stored_tip<S, V>(marshal: Mailbox<S, V>) -> u64
where
    V: Variant,
    S: Scheme<V::Commitment>,
{
    let Some((latest, _)) = marshal.get_info(Identifier::Latest).await else {
        return 0;
    };
    let latest = latest.get();
    match archived(marshal.clone(), latest).await {
        Archived::Block => latest,
        Archived::Certificate if latest > 0 => {
            if archived(marshal, latest - 1).await == Archived::Block {
                latest - 1
            } else {
                0
            }
        }
        Archived::Certificate | Archived::Nothing => 0,
    }
}

/// Resolves once `index` reaches `tip`, or after `limit`.
pub(crate) async fn replayed(index: &BlockIndex, tip: u64, limit: Duration) {
    let deadline = tokio::time::Instant::now() + limit;
    while index.head_block_number() < tip && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(POLL).await;
    }
}
