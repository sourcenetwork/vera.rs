//! Membership bounds imposed by the configured DKG inclusion window.

use crate::MAX_DKG_PARTICIPANTS;
use std::num::NonZeroU64;

/// Maximum active committee supported by the epoch inclusion window.
///
/// Commonware reserves the first half for dealing and the final block for the
/// epoch artifact. Epochs shorter than four blocks have no usable inclusion slot.
/// Leader terms must leave a proposer opportunity for every dealer, including
/// dealers that may withhold logs: each proposer can supply only its own log.
///
/// The bound assumes contiguous successful views and ready logs.
/// Skipped terms and delayed dealing can still cause a ceremony to fail; the
/// previous committee and sharing remain effective until a ceremony succeeds.
pub fn max_epoch_participants(length: NonZeroU64, term_length: NonZeroU64) -> u32 {
    let blocks = length.get();
    let slots = if blocks < 4 {
        0
    } else {
        blocks - (blocks / 2 + 1)
    };
    slots
        .div_ceil(term_length.get())
        .min(u64::from(MAX_DKG_PARTICIPANTS.get())) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_terms_reserve_opportunities_for_the_entire_dealer_roster() {
        for (length, term, expected) in [
            (1, 16, 0),
            (3, 16, 0),
            (4, 16, 1),
            (20, 16, 1),
            (98, 16, 3),
            (99, 16, 4),
            (130, 16, 4),
            (131, 16, 5),
            (192, 16, 6),
            (192, 64, 2),
            (2018, 16, 63),
            (2019, 16, 64),
            (u64::MAX, 64, 64),
        ] {
            assert_eq!(
                max_epoch_participants(
                    NonZeroU64::new(length).unwrap(),
                    NonZeroU64::new(term).unwrap()
                ),
                expected,
                "epoch {length}, term {term}",
            );
        }
    }
}
