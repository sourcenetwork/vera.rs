use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use vera_domain::{ConsensusPublicKey, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, verify_light_block};

use crate::{
    ModuleId, PERMISSION_LIMITS, PermissionError, PrefixProof, RECORD_PROOF_BYTES, ReadLimits,
    RecordProof,
    current::PrefixEvidence,
    encoded_size,
    object_evidence::ObjectEvidence,
    policy::{current_relationship, relationship_record, verify_policy},
    validate_policy_prefix,
};

/// Policy liveness and complete relationship evidence at one native root.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPrefixProof {
    /// The live policy record or certified absence.
    pub policy: RecordProof,
    /// Same-root incarnation membership or absence for every non-owner target object.
    pub objects: Vec<RecordProof>,
    /// Complete physical relationship prefix at the same root.
    pub prefix: PrefixProof,
}

impl PolicyPrefixProof {
    /// Verify both proofs and expose a complete prefix only when every row is current.
    /// Retired generations require paged enumeration or the generic physical-prefix API.
    pub fn verify(
        &self,
        root: B256,
        policy: &str,
        prefix: &[u8],
        maximum_bytes: usize,
    ) -> Result<Option<PrefixEvidence>, PermissionError> {
        validate_policy_prefix(policy, prefix)?;
        let maximum_bytes = maximum_bytes.min(RECORD_PROOF_BYTES);
        encoded_size(self, maximum_bytes)?;
        if self.policy.roots != self.prefix.roots {
            return Err(PermissionError::Invalid(
                "policy and relationships have different roots",
            ));
        }
        let policy_record = verify_policy(&self.policy, root, policy, maximum_bytes)?;
        let evidence = self
            .prefix
            .verify(root, ModuleId::Acp, prefix, maximum_bytes)?;
        let objects = ObjectEvidence::verify(
            root,
            &self.policy,
            policy,
            &self.objects,
            &evidence.entries,
            ReadLimits {
                bytes: PERMISSION_LIMITS
                    .reads
                    .bytes
                    .checked_sub(prefix.len())
                    .ok_or(PermissionError::Limit)?,
                ..PERMISSION_LIMITS.reads
            },
            maximum_bytes,
        )?;
        let Some(policy_record) = policy_record else {
            return Ok(None);
        };
        for entry in &evidence.entries {
            let record = relationship_record(policy, &entry.key, &entry.value)?;
            if !current_relationship(&policy_record, &record, objects.incarnation(&record)?)? {
                return Err(PermissionError::Invalid(
                    "relationship generation or incarnation is inactive",
                ));
            }
        }
        Ok(Some(evidence))
    }
}

/// Policy-scoped complete relationship evidence at one finalized revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPrefixResponse {
    /// Canonical revision and independently verifiable finalization artifacts.
    pub revision: LightBlock,
    /// Policy and relationship proofs captured together.
    pub proof: PolicyPrefixProof,
}

impl PolicyPrefixResponse {
    /// Authenticate liveness and relationships with caller-provided trust and freshness.
    pub fn verify(
        &self,
        policy: &str,
        prefix: &[u8],
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<Option<PrefixEvidence>, PermissionError> {
        validate_policy_prefix(policy, prefix)?;
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        encoded_size(&self.proof, maximum_bytes.min(RECORD_PROOF_BYTES))?;
        let (_, root) = verify_light_block(&self.revision, trusted)?;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        self.proof.verify(root, policy, prefix, maximum_bytes)
    }
}
