//! The finalized block consensus starts on.
//!
//! Simplex keeps an epoch's position only in its vote journal. A voter that
//! opens an empty one starts the epoch at its first view, on the last block
//! of the epoch before, and execution, which is past that block, refuses
//! every proposal. So every start hands Simplex the finalization of the
//! node's newest block as its floor. A journal that already reaches further
//! is not rolled back by it.

use std::num::NonZeroU64;

use commonware_codec::Decode as _;
use commonware_consensus::Epochable as _;
use commonware_cryptography::Digestible as _;
use commonware_glue::dkg::{state_sync::StateSync, types::Payload};
use commonware_storage::archive::{Archive, Identifier};
use commonware_utils::sequence::Unit;
use vera_app::ConsensusScheme;
use vera_domain::{ConsensusDigest, DkgVariant};

use super::seating::{Certificate, Finalizations};
use crate::{FinalizedHistory, bootstrap::GenesisEpochInfo};

/// What the orchestrator starts an epoch's consensus from.
pub(crate) type Seat = StateSync<ConsensusScheme, ConsensusDigest, DkgVariant, Unit>;

/// The floor for consensus on a node whose finalized history ends at its
/// newest executed block, or the block marshal is about to deliver again.
///
/// `None` when the newest block is the genesis block or the last of its
/// epoch: the next epoch starts from that block without a certificate. Also
/// `None` when no certificate of the block is stored, or the block that
/// opened its epoch is not: consensus then starts as Commonware recovers it.
pub(crate) async fn seat(
    history: &FinalizedHistory,
    finalizations: &Finalizations,
    blocks: &impl Archive,
    genesis: &GenesisEpochInfo,
    blocks_per_epoch: NonZeroU64,
) -> anyhow::Result<Option<Seat>> {
    let mut height = history.head_height();
    if height == 0 {
        return Ok(None);
    }
    // Marshal delivers the finalized blocks it archived above the newest
    // executed one before consensus proposes.
    while blocks.has(Identifier::Index(height + 1)).await?
        && finalizations.has(Identifier::Index(height + 1)).await?
    {
        height += 1;
    }
    let certificate = match finalizations.get(Identifier::Index(height)).await? {
        Some(certificate) => Some(certificate),
        None => history
            .finalization(height)?
            .map(|bytes| Certificate::decode_cfg(commonware_codec::Copying(bytes.as_slice()), &()))
            .transpose()?,
    };
    let Some(floor) = certificate else {
        return Ok(None);
    };
    if height == history.head_height()
        && history
            .stored_block(height)?
            .is_none_or(|block| block.digest() != floor.proposal.payload)
    {
        return Ok(None);
    }
    let epoch = floor.epoch().get();
    let length = blocks_per_epoch.get();
    if height / length != epoch || (height + 1) / length != epoch {
        return Ok(None);
    }
    let info = match (epoch * length).checked_sub(1) {
        None => Some(genesis.clone()),
        Some(boundary) => history
            .stored_block(boundary)?
            .and_then(|block| match block.payload {
                Some(Payload::EpochInfo(info)) if info.epoch.get() == epoch => Some(info),
                _ => None,
            }),
    };
    Ok(info.map(|info| Seat { info, floor }))
}
