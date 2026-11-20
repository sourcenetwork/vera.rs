//! The id a policy gets, known before it is created.

use vera_modules::acp::AcpModule;
use vera_modules::acp::error::AcpError;
pub use vera_modules::acp::types::{PolicyMarshalingType, PolicyNonce};

/// The id `creator` gets for `policy` created with `nonce`: SHA-256 over
/// the policy hash, the nonce and the creator's canonical DID. Any
/// spelling of the creator's key gives the same id. Creating the same
/// policy, nonce and creator again is refused.
///
/// # Errors
/// The definition does not compile.
pub fn predict_policy_id(
    policy: &str,
    marshal_type: &PolicyMarshalingType,
    nonce: &PolicyNonce,
    creator: &str,
) -> Result<String, AcpError> {
    AcpModule::predict_policy_id(policy, marshal_type, nonce, creator)
}

/// A nonce drawn from the operating system's randomness, for a creator that
/// does not need to know a policy's id before creating it.
pub fn random_policy_nonce() -> PolicyNonce {
    PolicyNonce(rand::random())
}
