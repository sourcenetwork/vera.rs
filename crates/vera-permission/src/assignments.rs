use alloy_primitives::B256;
use vera_domain::{ConsensusPublicKey, LIGHT_BLOCK_RESPONSE_BYTES, verify_light_block};
use vera_modules::acp::types::RelationshipRecord;
use vera_zanzibar::Subject;

use crate::{Actor, PermissionError, PolicyPrefixProof, PolicyPrefixResponse, encoded_size};

/// Select direct assignments to one actor issued by another actor.
#[derive(Clone, Debug)]
pub struct AssignmentSelector<'a> {
    /// Target resource name.
    pub resource: &'a str,
    /// Target relation name.
    pub relation: &'a str,
    /// Actor receiving the relationship.
    pub subject: &'a Actor,
    /// Actor that issued the relationship.
    pub issuer: &'a Actor,
}

impl PolicyPrefixProof {
    /// Verify all direct assignments matching the selector.
    pub fn verify_assignments(
        &self,
        root: B256,
        policy: &str,
        selector: &AssignmentSelector<'_>,
        maximum_bytes: usize,
    ) -> Result<Vec<RelationshipRecord>, PermissionError> {
        if selector.subject.0.is_wildcard() || selector.issuer.0.is_wildcard() {
            return Err(PermissionError::Invalid(
                "assignment actors must be concrete",
            ));
        }
        let evidence = self.verify_relation(
            root,
            policy,
            selector.resource,
            selector.relation,
            maximum_bytes,
        )?;
        let subject = vera_modules::actor::canonical(&selector.subject.0);
        let issuer = vera_modules::actor::canonical(&selector.issuer.0);
        let mut records = Vec::new();
        for entry in evidence.entries {
            let record: RelationshipRecord = serde_json::from_slice(&entry.value)
                .map_err(|_| PermissionError::Invalid("relationship record encoding"))?;
            if !record.archived
                && record.relationship.resource == selector.resource
                && record.relationship.relation == selector.relation
                && record.relationship.subject == Subject::Entity(subject.clone())
                && record.metadata.owner_did == issuer.as_str()
            {
                records.push(record);
            }
        }
        Ok(records)
    }
}

impl PolicyPrefixResponse {
    /// Verify matching direct assignments and their finalized revision.
    pub fn verify_assignments(
        &self,
        policy: &str,
        selector: &AssignmentSelector<'_>,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<Vec<RelationshipRecord>, PermissionError> {
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        let (_, root) = verify_light_block(&self.revision, trusted)?;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        self.proof
            .verify_assignments(root, policy, selector, maximum_bytes)
    }
}
