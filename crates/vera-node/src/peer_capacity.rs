//! Network capacity for genesis-bound DKG participant sets.

use std::num::{NonZeroU64, NonZeroUsize};

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[error(
    "epoch length {blocks_per_epoch} and leader term {term_length} support no DKG participants"
)]
pub(crate) struct PeerCapacityError {
    blocks_per_epoch: NonZeroU64,
    term_length: NonZeroU64,
}

pub(crate) struct PeerCapacity {
    participants: NonZeroUsize,
}

impl PeerCapacity {
    pub(crate) fn new(
        blocks_per_epoch: NonZeroU64,
        term_length: NonZeroU64,
    ) -> Result<Self, PeerCapacityError> {
        let participants = NonZeroUsize::new(vera_domain::max_epoch_participants(
            blocks_per_epoch,
            term_length,
        ) as usize)
        .ok_or(PeerCapacityError {
            blocks_per_epoch,
            term_length,
        })?;
        Ok(Self { participants })
    }

    pub(crate) const fn participants(&self) -> usize {
        self.participants.get()
    }

    pub(crate) fn tracked(&self) -> NonZeroUsize {
        // Dealers, players and next players may be disjoint; the local identity
        // also counts when it is outside every committee.
        NonZeroUsize::new(3 * self.participants.get() + 1)
            .expect("the bounded DKG participant count fits in usize")
    }
}

#[cfg(test)]
#[path = "peer_capacity_tests.rs"]
mod tests;
