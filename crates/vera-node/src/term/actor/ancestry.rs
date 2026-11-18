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
        Self::History(error.to_string())
    }
}

/// This device's blocks at `heights`, for a device that looks for where its
/// history left this one's. A height above this device's head is left out.
/// A block that fails to read fails the whole answer: a height left out
/// reads as a difference to the asking device.
pub(super) fn answer(
    heights: &[u64],
    held: impl Fn(u64) -> Result<Option<B256>, UnreadBlock>,
) -> Result<Vec<(u64, B256)>, UnreadBlock> {
    let mut blocks = Vec::new();
    for height in heights.iter().take(MAX_HEIGHTS) {
        if let Some(block) = held(*height)? {
            blocks.push((*height, block));
        }
    }
    Ok(blocks)
}

/// The newest block this device shares with the holder, when its block at
/// `at` is not the holder's. `at` is at or below the cut's height, and
/// `ask` returns the holder's blocks at the heights it is given.
///
/// `None` when the histories agree at `at`, or the holder does not answer.
/// A block of this device's that fails to read ends the search with a
/// refusal; it is never taken for a difference.
pub(super) async fn search<A, F>(
    at: u64,
    cut_height: u64,
    held: impl Fn(u64) -> Result<Option<B256>, UnreadBlock>,
    ask: A,
) -> Result<Option<TermCut>, TermRefusal>
where
    A: Fn(Vec<u64>) -> F,
    F: Future<Output = Option<Vec<(u64, B256)>>>,
{
    if at < cut_height {
        let Some(theirs) = ask(vec![at]).await else {
            return Ok(None);
        };
        if theirs.first().map(|(_, block)| *block) == held(at)? {
            return Ok(None);
        }
    }
    // Genesis is shared, and the block at `at` is not. Histories that agree
    // at a height agree below it.
    let (mut shared, mut differs) = (0, at);
    while differs - shared > 1 {
        let span = differs - shared - 1;
        let samples = span.min(MAX_HEIGHTS as u64);
        let heights: Vec<u64> = (1..=samples)
            .map(|sample| shared + (sample * (span + 1)) / (samples + 1))
            .collect();
        let Some(theirs) = ask(heights.clone()).await else {
            return Ok(None);
        };
        for height in heights {
            let holders = theirs
                .iter()
                .find(|(answered, _)| *answered == height)
                .map(|(_, block)| *block);
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

    /// This device's blocks at `heights`, or the block that failed to read.
    pub(super) fn held_blocks(&self, heights: &[u64]) -> Result<Vec<(u64, B256)>, UnreadBlock> {
        answer(heights, |height| self.held_block(height))
    }

    /// Record the newest block this device shares with the holder of
    /// `change`, when its history left the holder's below the cut.
    ///
    /// The rewind that follows cuts history back to that block, reports
    /// what this device finalized above it, and imports the holder's blocks
    /// from there. Without the holder's answer nothing is recorded, and a
    /// history that left the holder's is found out by the rewind. A block
    /// of this device's that fails to read refuses with
    /// [`TermRefusal::History`] and records nothing.
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
                            Message::Blocks { blocks } => Some(blocks),
                            _ => None,
                        },
                    )
                    .await
            }
        };
        let found = search(at, change.cut.height, |height| self.held_block(height), ask).await?;
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
