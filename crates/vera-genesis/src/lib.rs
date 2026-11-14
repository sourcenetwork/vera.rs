//! Extended genesis configuration for vera.
//!
//! Produces the EVM [`GenesisState`] with vera-specific fields
//! (operators, seeded policies, validators, consensus parameters).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(test, allow(unused_crate_dependencies))]

mod config;
mod error;
mod state;
mod validators;
pub use config::{
    GenesisAllocation, GenesisContract, GenesisStorage, ValidatorConfig, VeraGenesis,
};
pub use error::VeraGenesisError;
pub use state::GenesisState;
