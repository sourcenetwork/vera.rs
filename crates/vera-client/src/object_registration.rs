//! Certified registration state of one object.

use vera_domain::ConsensusPublicKey;
use vera_permission::{
    Object, ObjectRegistration, PolicyPrefixResponse, RECORD_PROOF_BYTES, object_owner_prefix,
};

use crate::{ClientError, VeraClient};

/// An object's registration together with the evidence that establishes it.
#[derive(Clone, Debug)]
pub struct CertifiedRegistration {
    /// Policy liveness and the object's complete owner prefix with its finalization certificate.
    pub evidence: PolicyPrefixResponse,
    /// Live with its owner, archived, or absent at the evidence's revision.
    pub registration: ObjectRegistration,
}

impl VeraClient {
    /// Read whether an object is live, archived or absent at a certified revision.
    ///
    /// An archived object has no owner. A missing policy reads as absent.
    pub async fn read_object_registration(
        &self,
        policy: &str,
        object: &Object,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<CertifiedRegistration, ClientError> {
        let prefix = object_owner_prefix(policy, object)?;
        let evidence = self
            .read_current_policy_prefix(
                policy,
                &prefix,
                minimum_height,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let registration = evidence.verify_object_registration(
            policy,
            object,
            minimum_height,
            &self.established(trusted),
        )?;
        Ok(CertifiedRegistration {
            evidence,
            registration,
        })
    }
}
