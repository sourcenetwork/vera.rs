use serde::{Deserialize, Serialize};
use vera_domain::{FinalityTrust, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock};

use crate::{
    AccessRequest, PERMISSION_LIMITS, PermissionError, PermissionLimits, PermissionProof,
    encoded_size, verify_permission_proof,
};

/// Transport budget for revision artifacts, permission evidence and the RPC envelope.
pub const PERMISSION_RESPONSE_BYTES: usize =
    LIGHT_BLOCK_RESPONSE_BYTES + PERMISSION_LIMITS.proof_bytes + 1024;

/// Permission evidence paired with the finalized revision from which it was captured.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionResponse {
    /// Canonical revision and its independently verifiable finalization artifacts.
    pub revision: LightBlock,
    /// Policy and relationship evidence at this revision's module root.
    pub proof: PermissionProof,
}

impl PermissionResponse {
    /// Authenticate the revision, enforce the caller's minimum, and evaluate its request.
    /// The caller provisions the consensus key and any additional freshness requirements.
    pub fn verify(
        &self,
        policy: &str,
        request: &AccessRequest,
        minimum_height: u64,
        trusted: &impl FinalityTrust,
        limits: PermissionLimits,
    ) -> Result<bool, PermissionError> {
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        let root = trusted.finalized_block(&self.revision)?.module_state_root;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        verify_permission_proof(root, policy, request, &self.proof, limits)
    }
}
