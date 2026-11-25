//! Tunables shared by every actor in the node.

use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};

use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::Reveal,
    primitives::sharing::{Mode, ModeVersion},
};
use commonware_runtime::Quota;
use commonware_utils::{NZU16, NZU32, NZUsize};

/// Namespace for every consensus signature; light clients verify against it.
pub const NAMESPACE: &[u8] = b"_COMMONWARE_VERA_SIMPLEX";
/// Namespace suffix for the authenticated transport handshake.
pub const P2P_SUFFIX: &[u8] = b"_P2P";
/// Maximum entries accepted in each DKG participant set.
pub const MAX_PARTICIPANTS: NonZeroU32 = NZU32!(64);
/// Share derivation mode used by DKG and reshare ceremonies.
pub const SHARING_MODE: Mode = Mode::NonZeroCounter;
/// Revealed-share calculation used by DKG and reshare ceremonies.
pub const REVEAL: Reveal = Reveal::V1;
/// Newest sharing mode version this binary accepts.
pub const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v0();
/// Logical page size that keeps physical pages 4096-byte aligned.
pub const PAGE_SIZE: NonZeroU16 = NZU16!(4084);
/// Pages held by the shared page cache.
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(4096);
/// Buffer size for journal replay and writes.
pub const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024 * 1024);
/// Mailbox capacity for every actor.
pub const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
/// Per-peer channel rate. Burst size also bounds Commonware's preallocated mailboxes.
pub const MESSAGE_RATE: Quota = Quota::per_second(NZU32!(1000)).allow_burst(NZU32!(64));
pub use vera_domain::{MAX_BLOCK_TXS, MAX_MESSAGE_BYTES as MAX_MESSAGE_SIZE, MAX_TX_BYTES};

/// P2P channel carrying simplex votes.
pub const VOTE_CHANNEL: u64 = 0;
/// P2P channel carrying simplex certificates.
pub const CERTIFICATE_CHANNEL: u64 = 1;
/// P2P channel for orchestrator resolver traffic.
pub const RESOLVER_CHANNEL: u64 = 2;
/// P2P channel for marshal block backfill.
pub const BACKFILL_CHANNEL: u64 = 3;
/// P2P channel for proposed block broadcast.
pub const BROADCAST_CHANNEL: u64 = 4;
/// State-transfer channels in ACP, bulletin, vera and sequence order.
pub const QMDB_CHANNELS: [u64; 4] = [9, 10, 11, 12];
/// P2P channel for retained execution-history chunks.
pub const HISTORY_CHANNEL: u64 = 13;
/// P2P channel on which an account's devices ask each other for the term.
pub const TERM_CHANNEL: u64 = 14;
/// P2P channel for private reshare dealings and acks.
pub const DKG_CHANNEL: u64 = 6;
/// P2P channel for the DKG probe.
pub const DKG_PROBE_CHANNEL: u64 = 7;
/// P2P channel for transaction gossip.
pub const MEMPOOL_CHANNEL: u64 = 8;
