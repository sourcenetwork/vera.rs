use alloy_primitives::Bytes;
use vera_domain::{ConsensusPublicKey, LIGHT_BLOCK_RESPONSE_BYTES};
use vera_permission::{
    ModuleId, PAGE_PROOF_BYTES, PermissionError, PolicyPrefixPageResponse, PolicyPrefixResponse,
    PrefixPageRequest, RECORD_PROOF_BYTES, validate_policy_prefix,
};

use crate::{ClientError, VeraClient};

impl VeraClient {
    /// Read complete relationship evidence together with policy liveness at one revision.
    /// Raw records remain physical evidence when the policy is absent; use the response's
    /// verification methods to obtain current relationships or ownership.
    pub async fn read_current_policy_prefix(
        &self,
        policy: &str,
        prefix: &[u8],
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<PolicyPrefixResponse, ClientError> {
        validate_policy_prefix(policy, prefix)?;
        let maximum_bytes = maximum_bytes.min(RECORD_PROOF_BYTES);
        let response: PolicyPrefixResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPolicyPrefixProof",
                serde_json::json!([policy, Bytes::copy_from_slice(prefix), minimum_height]),
                LIGHT_BLOCK_RESPONSE_BYTES + maximum_bytes + 1024,
            )
            .await?;
        response.verify(policy, prefix, minimum_height, trusted, maximum_bytes)?;
        Ok(response)
    }

    /// Read one relationship page with same-revision policy liveness.
    /// A continuation selects a lower bound, not a historical snapshot.
    pub async fn read_current_policy_prefix_page(
        &self,
        policy: &str,
        request: &PrefixPageRequest,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<PolicyPrefixPageResponse, ClientError> {
        validate_policy_prefix(policy, &request.prefix)?;
        request.validate()?;
        if request.module != ModuleId::Acp {
            return Err(PermissionError::Invalid("relationships belong to another module").into());
        }
        let maximum_bytes = maximum_bytes.min(PAGE_PROOF_BYTES);
        let response: PolicyPrefixPageResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPolicyPrefixPageProof",
                serde_json::json!([policy, request, minimum_height]),
                LIGHT_BLOCK_RESPONSE_BYTES + maximum_bytes + 1024,
            )
            .await?;
        response.verify(policy, request, minimum_height, trusted, maximum_bytes)?;
        Ok(response)
    }
}
