//! Up-front allocations a host may size for its deployment.

use std::num::{NonZeroU32, NonZeroUsize};

use commonware_runtime::Quota;
use commonware_utils::{NZU32, NZUsize};

use crate::consts::{MESSAGE_RATE, PAGE_CACHE_SIZE};

/// Requests a state transfer keeps outstanding for each database.
pub(crate) const TRANSFER_REQUESTS: NonZeroU32 = NZU32!(8);

/// Sizes of the allocations a node makes when it starts, before any request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeSizing {
    /// Burst of each peer channel's rate limit.
    ///
    /// Commonware allocates every channel's inbound queue at tracked peers
    /// times this burst, and the router's at their sum, whether or not a peer
    /// ever connects.
    pub channel_burst: NonZeroU32,
    /// Pages of the cache shared by the state and consensus journals, 4 KiB each, allocated at start.
    pub page_cache_pages: NonZeroUsize,
}

impl NodeSizing {
    /// The standalone daemon's sizes.
    pub const DAEMON: Self = Self {
        channel_burst: MESSAGE_RATE.burst_size(),
        page_cache_pages: PAGE_CACHE_SIZE,
    };

    /// Sizes for a validator with no peers. A deployment that gains validators needs [`Self::DAEMON`].
    pub const EMBEDDED: Self = Self {
        channel_burst: NZU32!(1),
        page_cache_pages: NZUsize!(256),
    };

    pub(crate) const fn channel_rate(self) -> Quota {
        MESSAGE_RATE.allow_burst(self.channel_burst)
    }

    /// The rate of the channel marshal fetches finalized blocks and
    /// certificates on, for a node with peers.
    ///
    /// A device catching up asks for many heights at once, and a burst of one
    /// drops all but one of the answers, so it advances by one fetch timeout
    /// per block. This channel keeps the daemon's burst at least.
    pub(crate) fn backfill_rate(self) -> Quota {
        MESSAGE_RATE.allow_burst(self.channel_burst.max(MESSAGE_RATE.burst_size()))
    }

    /// The rate of the channels a device catching up transfers state and
    /// history on, for a node with peers.
    ///
    /// A state transfer keeps [`TRANSFER_REQUESTS`] requests outstanding per
    /// database, and a burst below that drops the requests and answers past
    /// it, each of which then waits out a fetch timeout.
    pub(crate) fn transfer_rate(self) -> Quota {
        MESSAGE_RATE.allow_burst(self.channel_burst.max(TRANSFER_REQUESTS))
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeSizing, TRANSFER_REQUESTS};

    #[test]
    fn a_transfer_burst_covers_the_requests_a_transfer_keeps_outstanding() {
        assert_eq!(
            NodeSizing::EMBEDDED.transfer_rate().burst_size(),
            TRANSFER_REQUESTS
        );
        assert_eq!(
            NodeSizing::DAEMON.transfer_rate().burst_size(),
            NodeSizing::DAEMON.channel_burst
        );
    }
}
