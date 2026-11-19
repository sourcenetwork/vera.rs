//! Finding where this device's history left the holder's.

use std::future::Future;

use alloy_primitives::B256;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Supervisor as _;
use vera_domain::{PublicKey, TermChange, TermCut};

use super::{Actor, TermRefusal, device_id};
use crate::term::wire::{MAX_HEIGHTS, Message};

/// A finalized block that history failed to read.
#[derive(Debug, thiserror::Error)]
#[error("finalized block {height} could not be read: {reason:#}")]
pub(crate) struct UnreadBlock {
    pub height: u64,
    pub reason: anyhow::Error,
}

impl From<UnreadBlock> for TermRefusal {
    fn from(error: UnreadBlock) -> Self {
        error
            .reason
            .downcast_ref::<crate::HistoryPruned>()
            .map_or_else(
                || Self::History(error.to_string()),
                |pruned| Self::Pruned {
                    floor: pruned.floor,
                },
            )
    }
}

/// What a device answers about its blocks: the oldest block its history
/// retains, 1 until it is pruned, and its blocks at the heights asked.
pub(super) type Answer = (u64, Vec<(u64, B256)>);

/// This device's blocks at `heights`, for a device that looks for where its
/// history left this one's. A height above this device's head, or below its
/// `floor`, is left out; the floor tells the asking device which. A block
/// that fails to read fails the whole answer: a height left out above the
/// floor reads as a difference to the asking device.
pub(super) fn answer(
    heights: &[u64],
    floor: u64,
    held: impl Fn(u64) -> Result<Option<B256>, UnreadBlock>,
) -> Result<Answer, UnreadBlock> {
    let mut blocks = Vec::new();
    for &height in heights.iter().take(MAX_HEIGHTS) {
        if height > 0 && height < floor {
            continue;
        }
        if let Some(block) = held(height)? {
            blocks.push((height, block));
        }
    }
    Ok((floor, blocks))
}

/// The lowest height whose block a history with `floor` can compare:
/// genesis, which every history shares, until it is pruned.
const fn comparable_from(floor: u64) -> u64 {
    if floor > 1 { floor } else { 0 }
}

fn block_at(blocks: &[(u64, B256)], height: u64) -> Option<B256> {
    blocks
        .iter()
        .find(|(answered, _)| *answered == height)
        .map(|(_, block)| *block)
}

/// The newest block this device shares with the holder, when its block at
/// `at` is not the holder's. `at` is at or below the cut's height, and
/// `ask` returns the holder's [`Answer`] for the heights it is given.
///
/// `floor` is the oldest block this device's history retains, 1 until it
/// is pruned; the holder's comes with its first answer. Below the higher
/// of the two neither device can compare blocks: the search starts from the
/// block there, and refuses with [`TermRefusal::Pruned`] when the histories
/// differ at it or `at` is below it. A shared block below it is never
/// reported.
///
/// `None` when the histories agree at `at`, or the holder does not answer.
/// A block of this device's that fails to read ends the search with a
/// refusal; it is never taken for a difference.
pub(super) async fn search<A, F>(
    at: u64,
    cut_height: u64,
    floor: u64,
    held: impl Fn(u64) -> Result<Option<B256>, UnreadBlock>,
    ask: A,
) -> Result<Option<TermCut>, TermRefusal>
where
    A: Fn(Vec<u64>) -> F,
    F: Future<Output = Option<Answer>>,
{
    if at < comparable_from(floor) {
        return Err(TermRefusal::Pruned { floor });
    }
    let Some((holders_floor, theirs)) = ask(vec![at]).await else {
        return Ok(None);
    };
    let lowest = comparable_from(floor).max(comparable_from(holders_floor));
    let pruned = TermRefusal::Pruned { floor: lowest };
    if at < lowest {
        return Err(pruned);
    }
    if at < cut_height && block_at(&theirs, at) == held(at)? {
        return Ok(None);
    }
    // The block at `at` is not shared.
    if lowest > 0 {
        if at == lowest {
            return Err(pruned);
        }
        let Some((_, theirs)) = ask(vec![lowest]).await else {
            return Ok(None);
        };
        let holders = block_at(&theirs, lowest);
        if holders.is_none() || holders != held(lowest)? {
            return Err(pruned);
        }
    }
    // Histories that agree at a height agree below it.
    let (mut shared, mut differs) = (lowest, at);
    while differs - shared > 1 {
        let span = differs - shared - 1;
        let samples = span.min(MAX_HEIGHTS as u64);
        let heights: Vec<u64> = (1..=samples)
            .map(|sample| shared + (sample * (span + 1)) / (samples + 1))
            .collect();
        let Some((_, theirs)) = ask(heights.clone()).await else {
            return Ok(None);
        };
        for height in heights {
            let holders = block_at(&theirs, height);
            if holders.is_some() && holders == held(height)? {
                shared = shared.max(height);
            } else {
                differs = height;
                break;
            }
        }
    }
    let block = held(shared)?
        .ok_or_else(|| TermRefusal::History(format!("missing finalized block {shared}")))?;
    Ok(Some(TermCut {
        height: shared,
        block,
    }))
}

impl<S, R> Actor<S, R>
where
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    /// The identifier of this device's finalized block at `height`, or
    /// `None` when history holds no block there.
    fn held_block(&self, height: u64) -> Result<Option<B256>, UnreadBlock> {
        match height {
            0 => Ok(Some(self.genesis_id)),
            height => (self.blocks)(height).map_err(|reason| UnreadBlock { height, reason }),
        }
    }

    /// This device's answer for `heights`, or the block that failed to read.
    pub(super) fn held_blocks(&self, heights: &[u64]) -> Result<Answer, UnreadBlock> {
        let floor = (self.history_floor)().map_err(|reason| UnreadBlock { height: 0, reason })?;
        answer(heights, floor, |height| self.held_block(height))
    }

    /// Record the newest block this device shares with the holder of
    /// `change`, when its history left the holder's below the cut.
    ///
    /// The rewind that follows cuts history back to that block, reports
    /// what this device finalized above it, and imports the holder's blocks
    /// from there. Without the holder's answer nothing is recorded, and a
    /// history that left the holder's is found out by the rewind. A block
    /// of this device's that fails to read refuses with
    /// [`TermRefusal::History`] and records nothing. A shared block that
    /// cannot be found above the oldest block its history retains refuses
    /// with [`TermRefusal::Pruned`].
    pub(super) async fn locate(&mut self, change: &TermChange) -> Result<(), TermRefusal> {
        if self.backup {
            return Ok(());
        }
        let head = self.head().height;
        let at = head.min(change.cut.height);
        if at == change.cut.height && self.held_block(at)? == Some(change.cut.block) {
            return Ok(());
        }
        let (Some(probe), Some(switching)) = (self.probe.clone(), self.switching.as_ref()) else {
            return Ok(());
        };
        let Some(holder) = switching
            .devices
            .iter()
            .find(|device| device_id(&device.key) == change.holder)
        else {
            return Ok(());
        };
        let address = holder.address;
        let floor = (self.history_floor)().map_err(|error| TermRefusal::history(&error))?;
        let context = self.context.child("term_probes");
        let ask = |heights: Vec<u64>| {
            let (probe, context) = (probe.clone(), context.child("term_ancestry"));
            async move {
                probe
                    .exchange(
                        context,
                        address,
                        &Message::Ancestry { heights },
                        |message| match message {
                            Message::Blocks { floor, blocks } => Some((floor, blocks)),
                            _ => None,
                        },
                    )
                    .await
            }
        };
        let found = search(
            at,
            change.cut.height,
            floor,
            |height| self.held_block(height),
            ask,
        )
        .await?;
        let Some(common) = found else {
            return Ok(());
        };
        tracing::warn!(
            height = common.height,
            cut = change.cut.height,
            "this device's history left the holder's below the cut"
        );
        let mut record = self.record.clone();
        record.common = Some(common);
        record.store(&self.data_dir)?;
        self.record = record;
        Ok(())
    }
}

#[cfg(test)]
#[path = "ancestry_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ancestry_floor_tests.rs"]
mod floor_tests;
