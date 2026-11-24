#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Wall-clock timestamp paired with block height.
///
/// The proposer's wall-clock reading (unix seconds) becomes authoritative
/// once validators sign the block. `block_height` replaces protobuf's
/// `nanos` — nanosecond precision is meaningless in consensus, while
/// block height gives total ordering. Both values come from
/// `BlockContext.header` (timestamp + number).
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Timestamp {
    pub seconds: u64,
    pub block_height: u64,
}

/// Block-level execution context, set once at the start of block execution.
///
/// Available to begin_block, end_block, and all tx processing within the block.
/// Derived from the executor's `BlockContext`.
#[derive(Clone, Debug, Default)]
pub struct BlockExecCtx {
    /// Authenticated genesis record identifier; zero disables administrative writes.
    pub genesis_id: [u8; 32],
    /// Configured deployment identifier shared by all execution transports.
    pub deployment_id: u64,
    pub timestamp: Timestamp,
}

/// Per-transaction execution context, set before each tx dispatch.
///
/// Not available during begin_block/end_block. The dispatch that runs a
/// native request, a dry run or a view call populates it.
#[derive(Clone, Debug)]
pub struct TxExecCtx {
    /// Sequence authenticated by the submitting operation.
    pub sequence: u64,
    pub tx_hash: Vec<u8>,
    pub signer: String,
}

/// A duration expressed either as wall-clock seconds or a block count.
///
/// Matches Go's `sourcehub.acp.Duration` oneof: modules that use
/// time-based expiration can express it in either unit.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum Duration {
    Seconds(u64),
    Blocks(u64),
}

impl Default for Duration {
    fn default() -> Self {
        Self::Seconds(0)
    }
}
