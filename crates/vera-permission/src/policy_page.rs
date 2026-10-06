use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use vera_domain::{ConsensusPublicKey, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, verify_light_block};

use crate::{
    ModuleId, PAGE_DATA_BYTES, PAGE_PROOF_BYTES, PERMISSION_LIMITS, PermissionError,
    PrefixPageProof, PrefixPageRequest, ReadLimits, RecordProof, VerifiedPrefixPage, encoded_size,
    object_evidence::ObjectEvidence,
    policy::{current_relationship, relationship_record, verify_policy},
    validate_policy_prefix,
};

/// Policy liveness and a relationship page at one native root.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPrefixPageProof {
    /// The live policy record or certified absence.
    pub policy: RecordProof,
    /// Same-root incarnation membership or absence for every non-owner target object.
    pub objects: Vec<RecordProof>,
    /// A bounded physical relationship page at the same root.
    pub page: PrefixPageProof,
}

impl PolicyPrefixPageProof {
    /// Verify physical page coverage and expose only current generation records.
    /// The physical continuation is preserved even when every row is retired.
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
        let policy_record = verify_policy(&self.policy, root, policy, maximum_bytes)?;
        let mut page = self.page.verify(root, request, maximum_bytes)?;
        let objects = ObjectEvidence::verify(
            root,
            &self.policy,
            policy,
            &self.objects,
            &page.entries,
            ReadLimits {
                bytes: PAGE_DATA_BYTES
                    .checked_sub(request.prefix.len() + request.start.len())
                    .ok_or(PermissionError::Limit)?,
                ..PERMISSION_LIMITS.reads
            },
            maximum_bytes,
        )?;
        let Some(policy_record) = policy_record else {
            return Ok(None);
        };
        let mut entries = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let record = relationship_record(policy, &entry.key, &entry.value)?;
            if current_relationship(&policy_record, &record, objects.incarnation(&record)?)? {
                entries.push(entry);
            }
        }
        page.entries = entries;
        Ok(Some(page))
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
