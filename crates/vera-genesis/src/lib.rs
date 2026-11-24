//! Genesis configuration for vera: operators, seeded policies, validators and
//! consensus parameters.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(test, allow(unused_crate_dependencies))]

mod config;
mod error;
mod validators;
pub use config::{ValidatorConfig, VeraGenesis};
pub use error::VeraGenesisError;
