//! Wire types of `vera_simulateNativeCall`.

use alloy_primitives::{Address, B256, Bytes, U64};
use serde::{Deserialize, Serialize};

/// A native module call to dry-run as `signer`.
///
/// The node does not authenticate the signer: the answer says what that DID
/// could do at the head revision and authorizes nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCallRequest {
    /// The DID the call acts as.
    pub signer: String,
    /// Module address.
    pub target: Address,
    /// ABI-encoded module call.
    pub calldata: Bytes,
}

/// An event a simulated call would emit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedLog {
    /// Emitting module address.
    pub address: Address,
    /// Indexed topics.
    pub topics: Vec<B256>,
    /// Non-indexed data.
    pub data: Bytes,
}

/// The outcome of a dry run. It is not evidence: no revision records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeCallSimulation {
    /// Whether the call ran to completion.
    pub success: bool,
    /// Why the call was refused; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Gas a receipt would record: the whole allowance for a refused call.
    pub gas_used: U64,
    /// Return data of a successful call.
    pub output: Bytes,
    /// Events a successful call would emit.
    pub logs: Vec<SimulatedLog>,
    /// Height of the head revision the call was evaluated at.
    pub block_number: U64,
    /// Time of that revision in Unix seconds.
    pub timestamp: U64,
}
