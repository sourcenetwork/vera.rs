//! Reporting and reading the forks an anchoring deployment recorded.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall as _;
use vera_domain::{AncestryProof, ConsensusPublicKey, LightBlock, ModuleId};
use vera_modules::vera::anchors::{
    ForkRecord, MAX_ANCHOR_ARTIFACT_BYTES, abi::IAnchor, fork_prefix,
};
use vera_permission::RECORD_PROOF_BYTES;

use super::AnchoringError;
use crate::{BlsSigner, ClientError, VeraClient, client::ANCHOR_ADDRESS};

/// Encode the fork report of `revision`, a revision of the deployment whose
/// consensus key is `key`. `ancestor` is the revision's ancestor at the height
/// of the tip of the deployment's anchors, shown by `proof`; a revision at that
/// height is its own ancestor and needs no proof.
pub fn encode_fork_report(
    revision: &LightBlock,
    key: &ConsensusPublicKey,
    ancestor: B256,
    proof: Option<&AncestryProof>,
) -> Result<Bytes, ClientError> {
    let artifacts = revision.artifacts()?;
    if artifacts.encoded_len() > MAX_ANCHOR_ARTIFACT_BYTES {
        return Err(AnchoringError::TooLarge.into());
    }
    Ok(IAnchor::reportForkCall {
        deployment: super::deployment_id(key),
        block: artifacts.block.into(),
        descendants: artifacts.descendants.into_iter().map(Into::into).collect(),
        finalization: artifacts.finalization.into(),
        epochMaterial: artifacts.epoch_material.into(),
        ancestor: ancestor.0.into(),
        ancestryProof: proof.map(AncestryProof::encode).unwrap_or_default().into(),
    }
    .abi_encode()
    .into())
}

impl VeraClient {
    /// On a device of the deployment with consensus key `own_key` (this
    /// client), report its revision at `height` to `anchoring` as a fork of
    /// `tip`, the tip of the deployment's anchors there
    /// ([`super::Lineage::tip`]). Returns the submission identifier;
    /// [`Self::await_anchor`] waits for its receipt.
    ///
    /// The report is refused unless this device's history differs from the
    /// anchored one at the tip's height.
    pub async fn report_fork(
        &self,
        anchoring: &Self,
        submitter: &BlsSigner,
        height: u64,
        own_key: &ConsensusPublicKey,
        tip: (u64, B256),
    ) -> Result<B256, ClientError> {
        let revision = self.read_finalized_revision(height, own_key).await?;
        let (ancestor, proof) = if height > tip.0 {
            let ancestor = self
                .read_finalized_revision(tip.0, own_key)
                .await?
                .block_hash
                .parse()
                .map_err(|_| ClientError::InvalidResponse("block hash"))?;
            let proof = self.ancestry_proof(tip.0, height).await?;
            (ancestor, Some(proof))
        } else {
            let own = revision
                .block_hash
                .parse()
                .map_err(|_| ClientError::InvalidResponse("block hash"))?;
            (own, None)
        };
        let call = encode_fork_report(&revision, own_key, ancestor, proof.as_ref())?;
        anchoring
            .submit_native(submitter, ANCHOR_ADDRESS, call)
            .await
    }

    /// Read every fork of `deployment` this deployment recorded, verified
    /// against its `trusted` key at a revision of at least `minimum_height`.
    pub async fn read_forks(
        &self,
        deployment: &B256,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Vec<ForkRecord>, ClientError> {
        let prefix = fork_prefix(deployment);
        let response = self
            .read_current_prefix(
                ModuleId::Vera,
                &prefix,
                minimum_height,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let evidence = response.verify(
            ModuleId::Vera,
            &prefix,
            minimum_height,
            &self.established(trusted),
            RECORD_PROOF_BYTES,
        )?;
        evidence
            .entries
            .iter()
            .map(|entry| {
                ForkRecord::decode(deployment, &entry.value)
                    .map_err(|error| AnchoringError::from(error).into())
            })
            .collect()
    }
}
