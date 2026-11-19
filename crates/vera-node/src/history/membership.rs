//! Historical membership selections embedded in finalized epoch artifacts.

use super::*;
use commonware_consensus::types::Epoch;
use commonware_utils::ordered::Set;
use std::num::NonZeroU64;
use vera_domain::PublicKey;

impl FinalizedHistory {
    /// Read an older selection after history has been reconciled with execution.
    ///
    /// The participant provider asks for epoch `E + 2` while the last block
    /// of the current epoch `E` is derived, so the boundary it reads is that
    /// block, inside any retained window. A boundary below the floor's
    /// parent fails with [`HistoryPruned`].
    pub(crate) fn consensus_roster(
        &self,
        epoch: Epoch,
        length: NonZeroU64,
    ) -> Result<Option<Set<PublicKey>>> {
        let Some(boundary_epoch) = epoch.get().checked_sub(1) else {
            return Ok(None);
        };
        let height = boundary_epoch
            .checked_mul(length.get())
            .and_then(|height| height.checked_sub(1))
            .context("consensus roster boundary overflow")?;
        let snapshot = self.db.snapshot();
        ensure!(
            snapshot.get(transfer::IMPORT)?.is_none(),
            "history import is not published"
        );
        let (head, _): (u64, [u8; 32]) =
            borsh::from_slice(&snapshot.get(HEAD)?.context("missing history head")?)?;
        if height > head {
            return Ok(None);
        }
        let floor = floor::floor_height(snapshot.get(FLOOR)?.as_deref())?;
        // The floor's parent is the oldest boundary the store holds.
        if floor > 1 && height < floor - 1 {
            return Err(HistoryPruned { height, floor }.into());
        }
        let record = snapshot
            .get_pinned(key(RECORD, height))?
            .context("missing finalized roster boundary")?;
        let mut encoded = record.as_ref();
        let size = u32::deserialize(&mut encoded)? as usize;
        ensure!(
            size <= vera_domain::MAX_BLOCK_BYTES,
            "oversized roster boundary block"
        );
        let block = Block::decode_cfg(
            commonware_codec::Copying(
                encoded
                    .get(..size)
                    .context("truncated roster boundary block")?,
            ),
            &crate::node::block_cfg(),
        )?;
        roster_from_boundary(&block, epoch, height).map(Some)
    }
}

pub(crate) fn roster_from_boundary(
    block: &Block,
    epoch: Epoch,
    height: u64,
) -> Result<Set<PublicKey>> {
    ensure!(block.height == height, "roster boundary height mismatch");
    let Some(Payload::EpochInfo(info)) = &block.payload else {
        anyhow::bail!("roster boundary is missing its epoch artifact");
    };
    ensure!(
        info.epoch.get().checked_add(1) == Some(epoch.get()),
        "roster artifact epoch mismatch"
    );
    ensure!(
        !info.next_players.is_empty(),
        "empty historical consensus roster"
    );
    Ok(info.next_players.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};

    #[test]
    fn boundary_roster_rejects_wrong_epoch_height_and_missing_selection() {
        let key = ed25519::PrivateKey::from_seed(7).public_key();
        let (mut info, _) = crate::trusted_setup(7, [key.clone()]).unwrap();
        info.epoch = Epoch::new(2);
        info.next_players = Set::from_iter_dedup([key.clone()]);
        let mut block = vera_app::genesis_block(
            vera_domain::StateRoot(B256::ZERO),
            Default::default(),
            B256::ZERO,
        );
        block.height = 39;
        block.payload = Some(Payload::EpochInfo(info.clone()));
        assert_eq!(
            roster_from_boundary(&block, Epoch::new(3), 39).unwrap(),
            Set::from_iter_dedup([key]),
        );
        assert!(roster_from_boundary(&block, Epoch::new(4), 39).is_err());
        assert!(roster_from_boundary(&block, Epoch::new(3), 40).is_err());
        info.next_players = Set::default();
        block.payload = Some(Payload::EpochInfo(info));
        assert!(roster_from_boundary(&block, Epoch::new(3), 39).is_err());
        block.payload = None;
        assert!(roster_from_boundary(&block, Epoch::new(3), 39).is_err());
    }
}
