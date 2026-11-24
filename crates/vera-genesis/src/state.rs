//! EVM genesis state produced from a [`VeraGenesis`](crate::VeraGenesis).

use alloy_evm::revm::primitives::{Address, U256};

/// Accounts, storage, and code to install at genesis.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenesisState {
    /// Initial balances.
    pub genesis_alloc: Vec<(Address, U256)>,
    /// Storage slots per address.
    pub genesis_storage: Vec<(Address, Vec<(U256, U256)>)>,
    /// Bytecode per address.
    pub genesis_code: Vec<(Address, Vec<u8>)>,
}
