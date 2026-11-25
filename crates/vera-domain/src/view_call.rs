//! Wire type of `vera_call`.

use alloy_primitives::{Bytes, U64};
use serde::{Deserialize, Serialize};

/// What a module answered a signerless, read-only call with.
///
/// Unauthenticated: this is the serving node's word about its head revision.
/// It carries no finality certificate and no state proof, so it must not
/// decide access or be recorded as a decision. The verified readers
/// (`vera_getCurrentRecordProof`, `vera_getCurrentPrefixProof`,
/// `vera_getCurrentPermissionProof` and their paged and policy forms) are the
/// authenticated path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewCallResult {
    /// Return data of a call that ran to completion; empty when refused.
    pub output: Bytes,
    /// Why the module refused the call; absent when it ran to completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<crate::Refusal>,
    /// Height of the head revision the call was evaluated at.
    pub block_number: U64,
    /// Time of that revision in Unix seconds.
    pub timestamp: U64,
}
