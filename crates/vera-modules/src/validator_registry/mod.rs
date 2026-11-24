//! Validator registry: the deployment's members, kept in the vera module's
//! store and called through module address `0x0813`.

use alloy_primitives::Address;

/// Solidity ABI of the registry's calls.
pub mod abi;
mod address_update;
mod commands;
/// Registry error types.
pub mod error;
mod record;
/// Registry domain types.
pub mod types;

pub use address_update::address_update_digest;
pub use record::{MAX_P2P_ADDRESS_LEN, MemberRecord, validate_p2p_address};

/// Module address the registry is called at.
pub const ADDRESS: Address = {
    let mut bytes = [0u8; 20];
    bytes[18] = 0x08;
    bytes[19] = 0x13;
    Address::new(bytes)
};

/// Limits on the registry that depend on the deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipLimits {
    /// Most members, active or not, the registry holds.
    pub members: u32,
    /// Most active members an epoch has capacity for.
    pub active: u32,
}
