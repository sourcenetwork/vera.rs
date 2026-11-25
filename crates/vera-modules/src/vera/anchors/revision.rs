//! A revision of another deployment whose finality the caller has verified.

use alloy_primitives::B256;

/// The fields of a finalized block of another deployment that an anchor records.
///
/// The module does not verify finality: it holds no consensus types. The
/// caller verifies the block's finalization against the deployment's
/// consensus key and builds this from the verified block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedRevision {
    /// Height of the block.
    pub height: u64,
    /// Identifier of the block.
    pub block_hash: B256,
    /// Term of the block.
    pub term: u64,
    /// Timestamp of the block.
    pub timestamp: u64,
    /// Native module state root of the block.
    pub module_state_root: B256,
    /// Height and identifier of a block that the caller verified, against the
    /// block's commitment to its ancestors, to be an ancestor of it.
    pub ancestor: Option<(u64, B256)>,
}
