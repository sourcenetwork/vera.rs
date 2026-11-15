//! The deployment and head block a simulation runs under.

use alloy_primitives::U256;
use revm::{
    Context, Journal,
    context::{CfgEnv, TxEnv, block::BlockEnv},
    database::{State, WrapDatabaseRef},
    primitives::hardfork::SpecId,
};
use vera_modules::ModuleState;
use vera_modules::types::{BlockExecCtx, Timestamp};
use vera_traits::StateDbRead;

use crate::{ExecutionConfig, StateDbAdapter, precompiles::VeraPrecompiles};

pub(super) type Db<S> = State<WrapDatabaseRef<StateDbAdapter<S>>>;
pub(super) type Evm<S> = Context<BlockEnv, TxEnv, CfgEnv, Db<S>, Journal<Db<S>>, ()>;

/// What a simulated call observes of its deployment and of the block it runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationContext {
    /// Chain ID of the deployment.
    pub chain_id: u64,
    /// Hardfork specification.
    pub spec_id: SpecId,
    /// Genesis record identifier administrative approvals are bound to.
    pub genesis_id: [u8; 32],
    /// Largest active committee membership commands may reach.
    pub max_active_members: u32,
    /// Gas limit of a block.
    pub block_gas_limit: u64,
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
        block_gas_limit: u64,
        block_number: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            chain_id: config.chain_id,
            spec_id: config.spec_id,
            genesis_id: config.genesis_id,
            max_active_members: config.max_active_members(),
            block_gas_limit,
            block_number,
            timestamp,
        }
    }

    pub(super) fn evm<S: StateDbRead>(&self, state: &S) -> Evm<S> {
        let adapter = StateDbAdapter::new(state.clone());
        let db = State::builder().with_database_ref(adapter).build();
        let ctx: Evm<S> = Context::new(db, self.spec_id);
        ctx.modify_cfg_chained(|cfg| {
            cfg.chain_id = self.chain_id;
            cfg.disable_nonce_check = true;
            cfg.disable_balance_check = true;
        })
        .modify_block_chained(|blk: &mut BlockEnv| {
            blk.number = U256::from(self.block_number);
            blk.timestamp = U256::from(self.timestamp);
            blk.gas_limit = self.block_gas_limit;
        })
    }

    pub(super) fn precompiles(&self, modules: Option<&ModuleState>) -> VeraPrecompiles {
        modules
            .map_or_else(
                || VeraPrecompiles::new(self.spec_id),
                |m| {
                    VeraPrecompiles::with_modules(
                        self.spec_id,
                        m.acp.clone(),
                        m.bulletin.clone(),
                        m.vera.clone(),
                    )
                },
            )
            .with_genesis_id(self.genesis_id)
            .with_membership_limit(self.max_active_members)
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
