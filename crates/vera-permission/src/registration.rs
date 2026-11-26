use alloy_primitives::B256;
use vera_domain::FinalityTrust;

use crate::{
    Actor, Object, PermissionError, PolicyPrefixProof, PolicyPrefixResponse, RECORD_PROOF_BYTES,
    current::PrefixEvidence,
    owner::{object_owner_prefix, registration},
};

/// One object's registration under a live policy at a certified revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectRegistration {
    /// The object is registered and this actor owns it.
    Live(Actor),
    /// The object was registered and its owner record is archived. Nobody owns it,
    /// and it cannot be registered again unless its previous owner unarchives it.
    Archived,
    /// The object has no owner record, or the policy is absent.
    Absent,
}

impl PolicyPrefixProof {
    /// Classify one object's registration from complete owner-prefix evidence at `root`.
    pub fn verify_object_registration(
        &self,
        root: B256,
        policy: &str,
        object: &Object,
    ) -> Result<ObjectRegistration, PermissionError> {
        let prefix = object_owner_prefix(policy, object)?;
        classify(
            self.verify(root, policy, &prefix, RECORD_PROOF_BYTES)?,
            policy,
            object,
        )
    }
}

impl PolicyPrefixResponse {
    /// Classify one object's registration from complete, finalized owner-prefix evidence.
    pub fn verify_object_registration(
        &self,
        policy: &str,
        object: &Object,
        minimum_height: u64,
        trusted: &impl FinalityTrust,
    ) -> Result<ObjectRegistration, PermissionError> {
        let prefix = object_owner_prefix(policy, object)?;
        classify(
            self.verify(policy, &prefix, minimum_height, trusted, RECORD_PROOF_BYTES)?,
            policy,
            object,
        )
    }
}

fn classify(
    evidence: Option<PrefixEvidence>,
    policy: &str,
    object: &Object,
) -> Result<ObjectRegistration, PermissionError> {
    let Some(evidence) = evidence else {
        return Ok(ObjectRegistration::Absent);
    };
    registration(
        evidence
            .entries
            .iter()
            .map(|entry| (entry.key.as_slice(), entry.value.as_ref())),
        policy,
        object,
    )
}
