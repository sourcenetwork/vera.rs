//! Up-front allocations a host may size for its deployment.

use std::num::{NonZeroU32, NonZeroUsize};

use commonware_runtime::Quota;
use commonware_utils::{NZU32, NZUsize};

use crate::consts::{MESSAGE_RATE, PAGE_CACHE_SIZE};

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
}
