//! ValidatorRegistry domain types.

use serde::{Deserialize, Serialize};

/// A validator entry stored in the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Address of the validator (hex string with 0x prefix).
    pub address: String,
    /// Ed25519 consensus public key (hex string, 64 chars).
    pub consensus_pubkey: String,
    /// P2P network address (e.g., "127.0.0.1:30300").
    pub p2p_address: String,
    /// Whether the validator is currently active.
    pub active: bool,
    /// Admission the validator's record was created by; its address updates
    /// sign it.
    pub admission: u64,
    /// Sequence the validator's next signed address update must carry.
    pub address_sequence: u64,
}
