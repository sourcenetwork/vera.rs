use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use vera_domain::{ConsensusPublicKey, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, verify_light_block};

use crate::{
    ModuleId, PAGE_PROOF_BYTES, PermissionError, PrefixPageProof, PrefixPageRequest, RecordProof,
    VerifiedPrefixPage, encoded_size, policy::verify_policy, validate_policy_prefix,
};

/// Policy liveness and a relationship page at one native root.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPrefixPageProof {
    /// The live policy record or certified absence.
    pub policy: RecordProof,
    /// A bounded physical relationship page at the same root.
    pub page: PrefixPageProof,
}

impl PolicyPrefixPageProof {
    /// Verify complete page coverage and expose records only for a live policy.
    pub fn verify(
        &self,
        root: B256,
        policy: &str,
        request: &PrefixPageRequest,
        maximum_bytes: usize,
    ) -> Result<Option<VerifiedPrefixPage>, PermissionError> {
        validate_policy_prefix(policy, &request.prefix)?;
        request.validate()?;
        if request.module != ModuleId::Acp {
            return Err(PermissionError::Invalid(
                "relationships belong to another module",
            ));
        }
        let maximum_bytes = maximum_bytes.min(PAGE_PROOF_BYTES);
        encoded_size(self, maximum_bytes)?;
        if self.policy.roots != self.page.roots {
            return Err(PermissionError::Invalid(
                "policy and relationships have different roots",
            ));
        }
        let live = verify_policy(&self.policy, root, policy, maximum_bytes)?;
        let page = self.page.verify(root, request, maximum_bytes)?;
        Ok(live.then_some(page))
    }
}

/// Policy-scoped relationship page at one finalized revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPrefixPageResponse {
    /// Canonical revision and independently verifiable finalization artifacts.
    pub revision: LightBlock,
    /// Policy and relationship proofs captured together.
    pub proof: PolicyPrefixPageProof,
}

impl PolicyPrefixPageResponse {
    /// Authenticate this page's policy liveness, request, revision and consensus trust.
    pub fn verify(
        &self,
        policy: &str,
        request: &PrefixPageRequest,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<Option<VerifiedPrefixPage>, PermissionError> {
        validate_policy_prefix(policy, &request.prefix)?;
        request.validate()?;
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        encoded_size(&self.proof, maximum_bytes.min(PAGE_PROOF_BYTES))?;
        let (_, root) = verify_light_block(&self.revision, trusted)?;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        self.proof.verify(root, policy, request, maximum_bytes)
    }
}
