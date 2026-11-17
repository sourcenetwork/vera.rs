//! What consensus is seated on when a device starts: a finalized block's
//! certificate, and the epoch artifact of the block before its epoch.

use super::*;

impl FinalizedHistory {
    /// The finalization of the block at `height`, as marshal encoded it:
    /// the one this node stored when it applied the block, or else the one
    /// an imported record was certified by. `None` when the store holds
    /// neither.
    pub(crate) fn finalization(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let stored = self
            .db
            .get(key(CERTIFICATE, height))?
            .map(|bytes| borsh::from_slice::<Option<(u64, Vec<u8>)>>(&bytes))
            .transpose()?
            .flatten();
        if let Some((_, finalization)) = stored {
            return Ok(Some(finalization));
        }
        Ok(self
            .db
            .get(key(IMPORTED_FINALITY, height))?
            .map(|bytes| borsh::from_slice::<proof::ImportedFinality>(&bytes))
            .transpose()?
            .map(|imported| imported.certificate))
    }

    /// The block at `height`, or `None` when the store does not hold it.
    pub(crate) fn stored_block(&self, height: u64) -> Result<Option<Block>> {
        let Some(bytes) = self.db.get(key(RECORD, height))? else {
            return Ok(None);
        };
        let record: Record = borsh::from_slice(&bytes)?;
        Ok(Some(Block::decode_cfg(
            commonware_codec::Copying(record.block.as_slice()),
            &crate::node::block_cfg(),
        )?))
    }
}
