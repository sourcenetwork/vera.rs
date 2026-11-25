//! Conversions between block-carried targets and glue sync targets.

use commonware_storage::{
    merkle::{Location, mmr},
    qmdb::sync::Target,
};
use commonware_utils::non_empty_range;
use vera_domain::{Block, ConsensusDigest, DbTarget};

type SyncTarget = Target<mmr::Family, ConsensusDigest>;

pub(crate) fn target_from_sync(target: &SyncTarget) -> DbTarget {
    DbTarget {
        root: target.root,
        floor: *target.range.start(),
        tip: *target.range.end(),
    }
}

/// Whether a block-carried target names a non-empty range of valid locations.
const fn well_formed(target: &DbTarget) -> bool {
    target.floor < target.tip && Location::<mmr::Family>::new(target.tip).is_valid()
}

/// Whether every target a block carries can be turned into a sync target.
pub(crate) fn block_targets_well_formed(block: &Block) -> bool {
    block.native_targets.iter().all(well_formed)
}

pub(crate) fn sync_from_target(target: &DbTarget) -> SyncTarget {
    Target::new(
        target.root,
        non_empty_range!(Location::new(target.floor), Location::new(target.tip)),
    )
}
