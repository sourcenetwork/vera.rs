//! The deployment and head block a simulation runs under.

use vera_modules::types::{BlockExecCtx, Timestamp};
use vera_modules::validator_registry::MembershipLimits;

use crate::ExecutionConfig;

/// What a simulated call observes of its deployment and of the block it runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationContext {
    /// Chain ID of the deployment.
    pub chain_id: u64,
    /// Genesis record identifier administrative approvals are bound to.
    pub genesis_id: [u8; 32],
    /// Bounds membership commands keep the registry within.
    pub limits: MembershipLimits,
    /// Gas allowance of a signerless view call: the gas limit of a block.
    pub view_gas_limit: u64,
    /// Height the call observes.
    pub block_number: u64,
    /// Block time the call observes, in Unix seconds.
    pub timestamp: u64,
}

impl SimulationContext {
    /// The context of a call simulated at the block with this height and time.
    #[must_use]
    pub fn at_block(
        config: &ExecutionConfig,
        view_gas_limit: u64,
        block_number: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            chain_id: config.chain_id,
            genesis_id: config.genesis_id,
            limits: config.membership_limits(),
            view_gas_limit,
            block_number,
            timestamp,
        }
    }

    pub(super) const fn block(&self) -> BlockExecCtx {
        BlockExecCtx {
            genesis_id: self.genesis_id,
            deployment_id: self.chain_id,
            timestamp: Timestamp {
                seconds: self.timestamp,
                block_height: self.block_number,
            },
        }
    }
}
