//! Authenticated caller operation identities with immutable expiry.

use serde::{Deserialize, Serialize};

use crate::jwt::JwtError;

/// Longest lead, in seconds, between execution time and an operation identity's
/// deadline, unless a deployment allows more for policy commands.
pub const DEFAULT_OPERATION_LEAD: u64 = 600;
/// Ceiling on any lead a deployment may allow, in seconds (30 days). An identity's
/// outcome is retained until its deadline, so this also bounds how long a retained
/// outcome can occupy the deployment's outcome budget.
pub const MAX_OPERATION_LEAD: u64 = 30 * 24 * 60 * 60;

/// Eight-byte big-endian expiry followed by 24 bytes of caller-generated entropy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(pub [u8; 32]);

impl OperationId {
    /// An identity with an exclusive deadline and caller-generated entropy.
    pub fn new(expires_at: u64, entropy: [u8; 24]) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&expires_at.to_be_bytes());
        bytes[8..].copy_from_slice(&entropy);
        Self(bytes)
    }

    /// Exclusive execution deadline in Unix seconds.
    pub fn expires_at(self) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.0[..8]);
        u64::from_be_bytes(bytes)
    }

    /// Reject expired or empty identities and those whose deadline lies more
    /// than `max_lead` seconds after `now`.
    pub fn validate(self, now: u64, max_lead: u64) -> Result<(), JwtError> {
        let expiry = self.expires_at();
        if now >= expiry || expiry - now > max_lead || self.0[8..] == [0; 24] {
            return Err(JwtError::InvalidClaims(
                "invalid operation identity or deadline".into(),
            ));
        }
        Ok(())
    }
}

/// Exact request bound to an actor's signed delegation or relay assertion.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationClaim {
    /// Stable caller identity retained across workers and retries.
    pub id: OperationId,
    /// Digest of the typed semantic operation.
    pub digest: [u8; 32],
    /// Exact genesis identity, independently provisioned by the caller.
    pub genesis_id: [u8; 32],
}
