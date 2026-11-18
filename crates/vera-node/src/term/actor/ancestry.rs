//! Finding where this device's history left the holder's.

use alloy_primitives::B256;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Supervisor as _;
use vera_domain::{PublicKey, TermChange, TermCut};

use super::{Actor, TermRefusal, device_id};
use crate::term::wire::{MAX_HEIGHTS, Message};

impl<S, R> Actor<S, R>
where
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    /// The identifier of this device's finalized block at `height`.
    fn held_block(&self, height: u64) -> Option<B256> {
        match height {
            0 => Some(self.genesis_id),
            height => (self.blocks)(height),
        }
    }

    /// This device's blocks at `heights`, for a device that looks for where
    /// its history left this one's.
    pub(super) fn held_blocks(&self, heights: &[u64]) -> Vec<(u64, B256)> {
        heights
            .iter()
            .take(MAX_HEIGHTS)
            .filter_map(|height| Some((*height, self.held_block(*height)?)))
            .collect()
    }

    /// Record the newest block this device shares with the holder of
    /// `change`, when its history left the holder's below the cut.
    ///
    /// The rewind that follows cuts history back to that block, reports
    /// what this device finalized above it, and imports the holder's blocks
    /// from there. Without the holder's answer nothing is recorded, and a
    /// history that left the holder's is found out by the rewind.
    pub(super) async fn locate(&mut self, change: &TermChange) -> Result<(), TermRefusal> {
        if self.backup {
            return Ok(());
        }
        let head = self.head().height;
        let at = head.min(change.cut.height);
        if at == change.cut.height && self.held_block(at) == Some(change.cut.block) {
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
        if at < change.cut.height {
            let Some(theirs) = ask(vec![at]).await else {
                return Ok(());
            };
            if theirs.first().map(|(_, block)| *block) == self.held_block(at) {
                return Ok(());
            }
        }
        // Genesis is shared, and the block at `at` is not. Histories that
        // agree at a height agree below it.
        let (mut shared, mut differs) = (0, at);
        while differs - shared > 1 {
            let span = differs - shared - 1;
            let samples = span.min(MAX_HEIGHTS as u64);
            let heights: Vec<u64> = (1..=samples)
                .map(|sample| shared + (sample * (span + 1)) / (samples + 1))
                .collect();
            let Some(theirs) = ask(heights.clone()).await else {
                return Ok(());
            };
            for height in heights {
                let held = theirs
                    .iter()
                    .find(|(answered, _)| *answered == height)
                    .map(|(_, block)| *block);
                if held.is_some() && held == self.held_block(height) {
                    shared = shared.max(height);
                } else {
                    differs = height;
                    break;
                }
            }
        }
        let block = self
            .held_block(shared)
            .ok_or_else(|| TermRefusal::History(format!("missing finalized block {shared}")))?;
        tracing::warn!(
            height = shared,
            cut = change.cut.height,
            "this device's history left the holder's below the cut"
        );
        let mut record = self.record.clone();
        record.common = Some(TermCut {
            height: shared,
            block,
        });
        record.store(&self.data_dir)?;
        self.record = record;
        Ok(())
    }
}
