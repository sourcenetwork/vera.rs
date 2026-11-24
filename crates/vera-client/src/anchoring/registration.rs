//! Reading what an anchoring deployment's operators registered for a deployment.

use alloy_primitives::B256;
use vera_domain::{ConsensusPublicKey, ModuleId};
use vera_modules::vera::anchors::{
    DeploymentRecord, SubmitterRecord, deployment_key, submitter_key,
};
use vera_permission::RECORD_PROOF_BYTES;

use super::AnchoringError;
use crate::{ClientError, VeraClient};

impl VeraClient {
    /// Read the registration of `deployment` from this deployment, verified
    /// against its `trusted` key at a revision of at least `minimum_height`.
    /// `None` when its operators have not registered the deployment.
    pub async fn read_registered_deployment(
        &self,
        deployment: &B256,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<DeploymentRecord>, ClientError> {
        let evidence = self
            .read_current_record(
                ModuleId::Vera,
                &deployment_key(deployment),
                minimum_height,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        Ok(evidence
            .record
            .value
            .as_ref()
            .map(|value| DeploymentRecord::decode(deployment, value))
            .transpose()
            .map_err(AnchoringError::from)?)
    }

    /// Read the grant of the native signer `submitter` for `deployment`, with
    /// the submissions counted against it, verified like
    /// [`Self::read_registered_deployment`]. `None` when it has no grant.
    pub async fn read_anchor_submitter(
        &self,
        deployment: &B256,
        submitter: &str,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<SubmitterRecord>, ClientError> {
        let evidence = self
            .read_current_record(
                ModuleId::Vera,
                &submitter_key(deployment, submitter),
                minimum_height,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        Ok(evidence
            .record
            .value
            .as_ref()
            .map(|value| SubmitterRecord::decode(deployment, submitter, value))
            .transpose()
            .map_err(AnchoringError::from)?)
    }
}
