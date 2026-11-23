//! Certified discovery of direct relationship assignments.

use alloy_primitives::B256;
use vera_domain::ConsensusPublicKey;
use vera_modules::acp::{
    keys,
    types::{PolicyRecord, RelationshipRecord},
};
use vera_permission::{AssignmentSelector, PolicyPrefixResponse, RECORD_PROOF_BYTES};

use crate::{ClientError, VeraClient};

/// Complete evidence and matching direct assignments at the certified revision.
#[derive(Clone, Debug)]
pub struct CertifiedAssignments {
    /// Policy and complete relationship evidence with its finalization certificate.
    pub evidence: PolicyPrefixResponse,
    /// Active relationships to the selected actor, issued by the selected actor.
    pub records: Vec<RelationshipRecord>,
}

impl VeraClient {
    /// Read all direct assignments in one relation generation.
    ///
    /// The proof contains every relationship in the selected generation. A missing
    /// policy, retired relation, oversized proof or unavailable authority is an error.
    pub async fn read_certified_assignments(
        &self,
        policy: B256,
        selector: &AssignmentSelector<'_>,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<CertifiedAssignments, ClientError> {
        if selector.subject.0.is_wildcard() || selector.issuer.0.is_wildcard() {
            return Err(ClientError::InvalidResponse(
                "assignment actors must be concrete",
            ));
        }
        let selected = self.read_policy(policy, minimum, trusted).await?;
        let policy_record = selected
            .value
            .ok_or(ClientError::InvalidResponse("policy is absent"))?;
        let generation = policy_record
            .relations
            .generation(selector.resource, selector.relation)
            .ok_or(ClientError::InvalidResponse(
                "relation is absent from the authenticated policy",
            ))?;
        if generation == 0 {
            return Err(ClientError::InvalidResponse(
                "owner relation requires object-scoped evidence",
            ));
        }
        let policy_id = policy;
        let policy = hex::encode(policy_id);
        let prefix = keys::relationship_target_prefix(&policy, generation);
        let evidence = match self
            .read_current_policy_prefix(
                &policy,
                &prefix,
                selected.revision.max(minimum),
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await
        {
            Ok(evidence) => evidence,
            Err(error) => {
                if let Ok(current) = self
                    .read_policy(policy_id, selected.revision.max(minimum), trusted)
                    .await
                    && current.value.as_ref().and_then(|record| {
                        record
                            .relations
                            .generation(selector.resource, selector.relation)
                    }) != Some(generation)
                {
                    return Err(ClientError::AssignmentRevisionChanged);
                }
                return Err(error);
            }
        };
        let current: PolicyRecord = serde_json::from_slice(
            evidence
                .proof
                .policy
                .value
                .as_ref()
                .ok_or(ClientError::InvalidResponse("policy is absent"))?,
        )?;
        if current
            .relations
            .generation(selector.resource, selector.relation)
            != Some(generation)
        {
            return Err(ClientError::AssignmentRevisionChanged);
        }
        let records = evidence.verify_assignments(
            &policy,
            selector,
            selected.revision.max(minimum),
            &self.established(trusted),
            RECORD_PROOF_BYTES,
        )?;
        Ok(CertifiedAssignments { evidence, records })
    }
}
