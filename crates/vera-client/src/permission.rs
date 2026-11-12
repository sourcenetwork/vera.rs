use crate::{ClientError, VeraClient};
use vera_domain::{ConsensusPublicKey, LightBlock, verify_light_block};
use vera_permission::{
    AccessRequest, PermissionLimits, PermissionProof, PermissionResponse, validate_request,
    verify_permission_proof,
};

impl VeraClient {
    /// Fetch one bounded finality proof and authenticate its exact requested revision.
    pub async fn read_finalized_revision(
        &self,
        height: u64,
        trusted_key: &ConsensusPublicKey,
    ) -> Result<LightBlock, ClientError> {
        if height == 0 {
            return Err(ClientError::InvalidResponse("revision must be positive"));
        }
        let revision: LightBlock = self
            .rpc_call_bounded(
                "vera_getLightBlock",
                serde_json::json!([format!("0x{height:x}")]),
                vera_domain::LIGHT_BLOCK_RESPONSE_BYTES,
            )
            .await?;
        if revision.height != height {
            return Err(ClientError::InvalidResponse("finality revision mismatch"));
        }
        verify_light_block(&revision, trusted_key)?;
        Ok(revision)
    }

    /// Fetch and verify current permission evidence and its revision in one bounded response.
    /// Returns the authenticated revision and local decision. The caller supplies the
    /// trusted consensus key, minimum revision and any additional timestamp/age policy.
    pub async fn verify_current_access(
        &self,
        policy: &str,
        request: &AccessRequest,
        minimum_height: u64,
        trusted_key: &ConsensusPublicKey,
        limits: PermissionLimits,
    ) -> Result<(LightBlock, bool), ClientError> {
        validate_request(policy, request, limits)?;
        let response: PermissionResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPermissionProof",
                serde_json::json!([policy, request, minimum_height]),
                vera_domain::LIGHT_BLOCK_RESPONSE_BYTES
                    .saturating_add(limits.proof_bytes)
                    .saturating_add(1024),
            )
            .await?;
        let allowed = response.verify(policy, request, minimum_height, trusted_key, limits)?;
        Ok((response.revision, allowed))
    }

    /// Fetch current permission evidence paired with its revision, without verifying it.
    /// Callers that need to capture a bundle now and verify it later (offline, no further
    /// RPC) should use this instead of `verify_current_access`, which verifies and discards
    /// the bundle immediately.
    pub async fn current_permission_response(
        &self,
        policy: &str,
        request: &AccessRequest,
        minimum_height: u64,
        limits: PermissionLimits,
    ) -> Result<PermissionResponse, ClientError> {
        validate_request(policy, request, limits)?;
        self.rpc_call_bounded(
            "vera_getCurrentPermissionProof",
            serde_json::json!([policy, request, minimum_height]),
            vera_domain::LIGHT_BLOCK_RESPONSE_BYTES
                .saturating_add(limits.proof_bytes)
                .saturating_add(1024),
        )
        .await
    }

    /// Verify permission evidence at the caller's selected finalized revision.
    ///
    /// The consensus key must come from authenticated configuration. The caller
    /// selects revision freshness; this method never falls back to an older revision.
    /// This method fetches evidence over RPC. A successful historical check does
    /// not authorize later offline writes or establish absence of later revocation.
    pub async fn verify_access_at(
        &self,
        policy: &str,
        request: &AccessRequest,
        revision: &LightBlock,
        trusted_key: &ConsensusPublicKey,
        limits: PermissionLimits,
    ) -> Result<bool, ClientError> {
        validate_request(policy, request, limits)?;
        let (_, root) = verify_light_block(revision, trusted_key)?;
        let proof: PermissionProof = self
            .rpc_call_bounded(
                "vera_getPermissionProof",
                serde_json::json!([policy, request, revision.height]),
                limits.proof_bytes.saturating_add(1024),
            )
            .await?;
        Ok(verify_permission_proof(
            root,
            revision.height,
            policy,
            request,
            &proof,
            limits,
        )?)
    }
}
